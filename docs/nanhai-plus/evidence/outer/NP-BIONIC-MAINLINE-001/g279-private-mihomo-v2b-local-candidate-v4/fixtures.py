#!/usr/bin/env python3
"""Offline byte-only route evidence fixtures; no Mihomo or socket calls."""
import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('v2b_v4', HERE / 'runner.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
checks = {}


def rejects(raw):
    try:
        runner.normalized_route_event(raw)
    except ValueError:
        return True
    return False


mock = (HERE / 'MOCK-STDOUT.raw').read_bytes()
line = [x for x in mock.splitlines() if b'[TCP]' in x and b' --> ' in x]
checks['one_mock_route_line'] = len(line) == 1
event, event_sha = runner.normalized_route_event(mock)
checks['safe_exact_whitelist_fields'] = set(event) == {
    'schema', 'source_ip', 'source_port', 'target_ip', 'target_port',
    'rule', 'action', 'raw_line', 'raw_line_sha256'
}
checks['exact_raw_round_trip'] = event['raw_line'].encode('ascii') == line[0]
checks['raw_sha_round_trip'] = runner.sha(event['raw_line'].encode('ascii')) == event['raw_line_sha256']
checks['normalized_sha_round_trip'] = runner.sha(
    json.dumps(event, sort_keys=True, separators=(',', ':')).encode()
) == event_sha

# Mirror the real TERMINAL projection through JSON, then independently
# recompute both digests from retained, non-secret fields alone.
terminal = json.loads(json.dumps({'negative': {
    'normalized_route_event': event,
    'route_event_sha256': event_sha,
}}, sort_keys=True))
record = terminal['negative']['normalized_route_event']
checks['terminal_raw_sha_independent'] = runner.sha(record['raw_line'].encode('ascii')) == record['raw_line_sha256']
checks['terminal_event_sha_independent'] = runner.sha(
    json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
) == terminal['negative']['route_event_sha256']
checks['terminal_line_exact_original'] = record['raw_line'].encode('ascii') == line[0]

checks['generic_route_words_rejected'] = rejects(b'config rules: MATCH,REJECT\n')
checks['forged_prefix_rejected'] = rejects(b'noise ' + line[0] + b'\n')
checks['forged_suffix_rejected'] = rejects(line[0] + b' tail\n')
checks['duplicate_lines_rejected'] = rejects(mock + mock)
checks['sensitive_password_suffix_rejected'] = rejects(line[0] + b' password=secret\n')
checks['sensitive_node_suffix_rejected'] = rejects(line[0] + b' node=private\n')
checks['sensitive_embedded_name_rejected'] = rejects(
    line[0].replace(b' match Match', b' node=private match Match') + b'\n'
)
checks['wrong_target_rejected'] = rejects(
    line[0].replace(b'203.0.113.1', b'192.0.2.1') + b'\n'
)
checks['proxy_action_rejected'] = rejects(
    line[0].replace(b'using REJECT', b'using PROXY') + b'\n'
)
checks['out_of_range_source_port_rejected'] = rejects(
    line[0].replace(b':64500 ', b':99 ') + b'\n'
)

result = {'schema': 'g279-v2b-offline-fixtures-v4', 'checks': checks,
          'pass': all(checks.values()), 'actual_proxy_started': False,
          'real_network_commands': 0, 'gz02_requests': 0,
          'device_commands': 0, 'container_commands': 0}
print(json.dumps(result, sort_keys=True))
sys.exit(0 if result['pass'] else 2)
