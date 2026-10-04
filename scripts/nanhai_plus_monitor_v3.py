#!/usr/bin/env python3
"""30s local observer and delivery of explicit outer releases to the existing Kimi.

No model call on an ordinary tick; no business scheduling or goal creation.
Delivery intent is persisted BEFORE calling Herdr. Unknown outcomes never retry
automatically, including after a process restart.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

from nanhai_plus_tool_records_v2 import poll_source
from nanhai_plus_api_health_refresh_v2 import poll_health

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs/nanhai-plus'
PRIVATE = ROOT / '.nanhai-plus-runtime'
EVENTS = DOCS / 'evidence/bootstrap/native-events.jsonl'
SESSION = 'oracle-kimi:local:nanhai-plus#inner'
HERDR = ['herdr', '--session', 'nanhai-plus', 'agent', 'prompt', 'octos-inner']


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def write(path, data):
    temp = path.with_name(path.name + f'.{os.getpid()}.tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    os.replace(temp, path)


def observe(state):
    goal, turn, last_evidence = {}, {}, None
    for line in EVENTS.read_text().splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get('params', {}).get('session_id') != SESSION:
            continue
        if event['method'] == 'session/goal/updated':
            goal = event['params']['goal']
        if event['method'] in ('turn/started', 'turn/completed', 'turn/error'):
            turn = event
        last_evidence = event['at']
    receipts = []
    for claim in state.get('claims', []):
        directory = (ROOT / claim.get('scope', '')).resolve()
        if not directory.is_relative_to(DOCS.resolve()) or not directory.is_dir():
            continue
        for name in ('result.json', 'environment-review.json', 'CURRENT.md'):
            p = directory / name
            if p.is_file():
                receipts.append({'path': str(p.relative_to(ROOT)),
                                 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()})
    semantic = {'receipts': receipts, 'claims': [{k: c.get(k) for k in
                ('claim_id', 'status', 'receipt_sha256')} for c in state.get('claims', [])],
                'environment_revision': state.get('environment_gate', {}).get('revision'),
                'goal_status': goal.get('status')}
    return goal, turn, last_evidence, semantic


def deliver(release, state, store, runner=subprocess.run):
    key = release['event_id']
    if key in store['deliveries']:
        return 'already-recorded'
    if release.get('run_id') != state['run_id'] or release.get('authorized_by') != 'outer':
        return 'invalid-authorization'
    if release.get('target') != 'octos-inner' or release.get('session') != SESSION:
        return 'invalid-target'
    if release.get('goal_id') != 'goal_01':
        return 'invalid-goal'
    container_policy = state.get('container_policy', {})
    if container_policy.get('status') == 'forbidden' and (
        release.get('container_policy_revision') != container_policy.get('revision') or
        release.get('container_execution') is not False
    ):
        return 'stale-container-policy'
    claim = next((c for c in state['claims'] if c['claim_id'] == release.get('claim_id')), None)
    if not claim or claim.get('status') != 'ready':
        return 'claim-not-ready'
    gate = state.get('environment_gate', {})
    if release.get('environment_revision') != gate.get('revision'):
        return 'stale-environment-revision'
    if release.get('scope') not in ('environment-readonly', 'environment-control-repair') and not gate.get('business_development_allowed'):
        return 'environment-HOLD'
    message = release.get('message', '')
    if not message or len(message) > 6000 or digest(message) != release.get('message_sha256'):
        return 'invalid-message'
    store['deliveries'][key] = {'at': now(), 'status': 'intent-persisted',
                                'claim_id': claim['claim_id'], 'message_sha256': digest(message)}
    write(PRIVATE / 'monitor-state.json', store)
    try:
        result = runner(HERDR + [message], text=True, capture_output=True, timeout=15)
        row = store['deliveries'][key]
        row.update(return_code=result.returncode,
                   status='queued-awaiting-native-ACK' if result.returncode == 0 else 'delivery-failed',
                   transport_output=(result.stdout + result.stderr)[-3000:])
    except (subprocess.TimeoutExpired, OSError) as error:
        store['deliveries'][key].update(status='delivery-unknown-no-retry', error=type(error).__name__)
    write(PRIVATE / 'monitor-state.json', store)
    return store['deliveries'][key]['status']


def tick(store):
    state = json.loads((DOCS / 'OUTER-STATE.json').read_text())
    goal, turn, evidence, semantic = observe(state)
    signature = digest(semantic)
    changed = signature != store.get('last_digest')
    if changed:
        write(DOCS / 'evidence/bootstrap/monitor-delta.json',
              {'at': now(), 'run_id': state['run_id'], 'before_digest': store.get('last_digest'),
               'after_digest': signature, 'delta': semantic,
               'next': 'Kimi reads this only upon a unique outer-authorized release; no automatic model wake'})
    busy = turn.get('method') == 'turn/started'
    delivery = 'none'
    outbox = DOCS / 'workpackages/kimi-outbox.json'
    if not busy and goal.get('goal_id') == 'goal_01' and outbox.is_file():
        releases = json.loads(outbox.read_text()).get('releases', [])
        for release in releases:
            delivery = deliver(release, state, store)
            if delivery in ('queued-awaiting-native-ACK', 'delivery-unknown-no-retry', 'delivery-failed'):
                break
    store.update(last_digest=signature, last_tick=now(), ticks=store.get('ticks', 0) + 1)
    write(PRIVATE / 'monitor-state.json', store)
    reference_observation = poll_source()
    # Read the limit actually supplied to the current backend, not an old
    # default or a future local_env value. Metadata only; no transcript/model IO.
    backend = json.loads((DOCS / 'evidence/bootstrap/backend-process.json').read_text())
    limit = int(backend.get('session_file_limit_bytes', 10 * 1024 * 1024))
    session_root = ROOT / '.octos/oracle-kimi'
    storage = []
    for relative in ('sessions/oracle-kimi%3Alocal%3Ananhai-plus%23inner.jsonl',
                     'users/oracle-kimi%3Alocal%3Ananhai-plus/sessions/inner.jsonl'):
        path = session_root / relative
        if path.is_file():
            size = path.stat().st_size
            storage.append({'path': str(path.relative_to(ROOT)), 'bytes': size,
                            'limit_bytes': limit, 'near_limit': size >= limit * 4 // 5,
                            'at_limit': size >= limit, 'backend_pid': backend['pid']})
    health = poll_health()
    write(DOCS / 'evidence/bootstrap/monitor-heartbeat.json',
          {'at': now(), 'pid': os.getpid(), 'interval_seconds': 30,
           'run_id': state['run_id'], 'heartbeat': '发现变化' if changed else '无变化', 'api_health': health,
           'last_evidence_at': evidence, 'goal_id': goal.get('goal_id'),
           'goal_status': goal.get('status'), 'tokens_used': goal.get('tokens_used'),
           'token_budget': goal.get('token_budget'), 'turn_running': busy,
           'routine_model': 'Kimi (existing octos-inner), only on authorized new work',
           'unchanged_tick_model_calls': 0, 'codex_routine_polling': False,
           'delivery': delivery, 'ticks': store['ticks'],
           'tool_reference_observation': reference_observation,
           'session_storage': storage})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    PRIVATE.mkdir(exist_ok=True)
    lock = (PRIVATE / 'monitor.lock').open('a+')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit('An observer already owns this Run; refusing a duplicate')
    p = PRIVATE / 'monitor-state.json'
    store = json.loads(p.read_text()) if p.exists() else {'deliveries': {}, 'ticks': 0}
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    while not stop.is_set():
        tick_started = time.monotonic()
        try:
            tick(store)
        except Exception as error:
            write(DOCS / 'evidence/bootstrap/monitor-fault.json',
                  {'at': now(), 'error_type': type(error).__name__, 'error': str(error),
                   'dispatch': 'HOLD until state readable; no model call'})
        if args.once:
            break
        stop.wait(max(0, 30 - (time.monotonic() - tick_started)))


if __name__ == '__main__':
    main()
