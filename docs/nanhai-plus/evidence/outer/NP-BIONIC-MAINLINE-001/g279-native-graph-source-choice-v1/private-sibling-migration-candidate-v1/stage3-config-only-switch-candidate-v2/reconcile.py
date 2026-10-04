#!/usr/bin/env python3
"""Read-only G279 local-env switch reconciliation; never rolls back or retries."""
import argparse
import json
from pathlib import Path

import switch


def inspect(root, receipts, nonce):
    active = root / 'local_env.md'
    current_sha = switch.sha(switch.stable_read(active)[0])
    start = receipts / (nonce + '.START.json')
    terminal = receipts / (nonce + '.TERMINAL.json')
    quarantine = receipts / (nonce + '.QUARANTINE.json')
    backup = receipts / ('local_env.old.' + switch.OLD_SHA + '.md')
    artifact_sha = {}
    for name, path in [('start', start), ('terminal', terminal),
                       ('quarantine', quarantine), ('backup', backup)]:
        artifact_sha[name] = switch.sha(switch.stable_read(path)[0]) if path.exists() else None
    start_obj = json.loads(switch.stable_read(start)[0]) if start.exists() else None
    terminal_obj = json.loads(switch.stable_read(terminal)[0]) if terminal.exists() else None
    if start_obj and (start_obj.get('nonce') != nonce or
                      start_obj.get('active_sha256') != switch.OLD_SHA or
                      start_obj.get('future_sha256') != switch.NEW_SHA):
        state = 'EVIDENCE_CONFLICT'
    elif terminal_obj and (not start_obj or terminal_obj.get('nonce') != nonce or
                           terminal_obj.get('start_sha256') != artifact_sha['start'] or
                           terminal_obj.get('active_sha256') != switch.NEW_SHA):
        state = 'EVIDENCE_CONFLICT'
    elif current_sha == switch.OLD_SHA and not start_obj:
        state = 'NOT_STARTED_OLD_ACTIVE'
    elif current_sha == switch.OLD_SHA and start_obj and not terminal_obj:
        state = 'STARTED_OLD_ACTIVE_REVIEW_BEFORE_ANY_NEW_ACTION'
    elif current_sha == switch.NEW_SHA and start_obj and terminal_obj and not quarantine.exists():
        state = 'SWITCHED_TERMINAL_READBACK'
    elif current_sha == switch.NEW_SHA and start_obj and not terminal_obj:
        state = 'NEW_ACTIVE_WITHOUT_TERMINAL_QUARANTINE'
    else:
        state = 'EVIDENCE_CONFLICT'
    if start_obj and artifact_sha['backup'] not in (None, switch.OLD_SHA):
        state = 'EVIDENCE_CONFLICT'
    return {'schema': 'g279-stage3-config-only-reconciliation-v2', 'nonce': nonce,
            'state': state, 'active_file_sha256': current_sha,
            'artifact_sha256': artifact_sha,
            'mutation': False, 'automatic_rollback': False, 'replay_allowed': False}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, default=switch.ROOT)
    ap.add_argument('--receipts', type=Path, default=switch.HERE / 'receipts')
    ap.add_argument('--nonce', default='12e89d715c414c92ba8998a7eea48f43')
    args = ap.parse_args()
    print(json.dumps(inspect(args.root, args.receipts, args.nonce), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
