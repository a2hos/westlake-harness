#!/usr/bin/env python3
"""Read-only, sanitized alternate-node selection. Never writes a proxy config."""
import datetime
import importlib.util
import json
import pathlib
import urllib.parse

HERE = pathlib.Path(__file__).resolve().parent
UP = HERE.parent / 'g279-private-mihomo-v2a-syntax-candidate-v3/runner.py'
EXPECTED_UP_SHA = 'a17afa0de9b3efa68a7ba9601a6b6fa4dc71394d39cb76b4e803f1c5035da61c'
MAX_AGE_SECONDS = 7200
MAX_DELAY_MS = 2000
EXPECTED_COUNT = 15
CHOSEN_INDEX = 1


def import_upstream():
    import hashlib
    if hashlib.sha256(UP.read_bytes()).hexdigest() != EXPECTED_UP_SHA:
        raise ValueError('upstream_runner_drift')
    spec = importlib.util.spec_from_file_location('g279_upstream', UP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def history_metric(history, now):
    if not isinstance(history, list) or len(history) > 256:
        raise ValueError('history_shape')
    valid = []
    for item in history:
        if not isinstance(item, dict) or type(item.get('delay')) is not int:
            continue
        delay = item['delay']
        try:
            when = datetime.datetime.fromisoformat(item['time'].replace('Z', '+00:00'))
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
        if when.tzinfo is None:
            continue
        age = (now - when).total_seconds()
        if 0 < delay <= MAX_DELAY_MS and -120 <= age <= MAX_AGE_SECONDS:
            valid.append((delay, age))
    if not valid:
        return None
    return {'best_delay_ms': min(v[0] for v in valid),
            'freshest_age_seconds': min(v[1] for v in valid),
            'valid_samples': len(valid)}


def choose(metrics, current_index):
    if len(metrics) != EXPECTED_COUNT or type(current_index) is not int or not 0 <= current_index < EXPECTED_COUNT:
        raise ValueError('inventory_shape')
    eligible = [(m['best_delay_ms'], m['freshest_age_seconds'], i)
                for i, m in enumerate(metrics) if i != current_index and m is not None]
    if not eligible or min(eligible)[2] != CHOSEN_INDEX:
        raise ValueError('alternate_choice_drift')
    return CHOSEN_INDEX


def controller_history(up, path, pid, name):
    conn = up.UnixHTTP(path, pid)
    try:
        conn.request('GET', '/proxies/' + urllib.parse.quote(name, safe=''),
                     headers={'Accept': 'application/json'})
        response = conn.getresponse()
        body = response.read(1 << 20)
        if response.status != 200 or len(body) >= 1 << 20:
            raise ValueError('controller_response')
        value = json.loads(body)
        if not isinstance(value, dict) or value.get('name') != name:
            raise ValueError('controller_node_identity')
        return value.get('history')
    finally:
        conn.close()


def observe():
    """Local controller GET only; expose indices and aggregate delay, no names/credentials."""
    up = import_upstream()
    raw = up.stable_read(up.SOURCE)
    if up.sha(raw) != up.SOURCE_SHA:
        raise ValueError('source_drift')
    pid = up.active_process()
    source = up.yaml.safe_load(raw)
    nodes, groups = up.source_structure(source)
    names = list(nodes)
    if len(names) != EXPECTED_COUNT:
        raise ValueError('node_count_drift')
    for node in nodes.values():
        up.selected_node_schema(node)
    path = pathlib.Path(source.get('external-controller-unix') or '')
    socket_identity = up.verify_socket_path(path)
    current = up.current_leaf(source, pid, nodes, groups)
    current_index = names.index(current)
    now = datetime.datetime.now(datetime.timezone.utc)
    metrics = [history_metric(controller_history(up, path, pid, name), now) for name in names]
    chosen = choose(metrics, current_index)
    # Repeat source, process, socket and current selection after the read-only inventory.
    if up.sha(up.stable_read(up.SOURCE)) != up.SOURCE_SHA or up.active_process() != pid:
        raise ValueError('source_or_process_changed')
    if up.verify_socket_path(path) != socket_identity or up.current_leaf(source, pid, nodes, groups) != current:
        raise ValueError('socket_or_selection_changed')
    return {
        'schema': 'g279-private-alternate-observation-v1',
        'at_utc': now.isoformat(),
        'source_sha256': up.SOURCE_SHA,
        'upstream_runner_sha256': EXPECTED_UP_SHA,
        'controller_root_owned': True,
        'controller_peer_pid_matched_process': True,
        'node_count': len(names),
        'eligible_non_current_count': sum(m is not None for i, m in enumerate(metrics) if i != current_index),
        'current_index': current_index,
        'current_type': nodes[current]['type'],
        'alternate_index': chosen,
        'alternate_type': nodes[names[chosen]]['type'],
        'alternate_recent_metric': metrics[chosen],
        'selection_only': True,
        'gz02_reachability_proven': False,
        'global_selection_writes': 0,
        'proxy_instance_starts': 0,
        'gz02_connections': 0,
    }


if __name__ == '__main__':
    print(json.dumps(observe(), sort_keys=True, indent=2))
