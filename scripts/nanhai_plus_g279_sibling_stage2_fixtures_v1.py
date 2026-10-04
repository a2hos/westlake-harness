#!/usr/bin/env python3
"""Local-only stage-2 identity and denial fixtures; never invokes SSH."""
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    local = load('nanhai_plus_g279_sibling_stage2_candidate_v1')
    remote = load('nanhai_plus_g279_sibling_stage2_remote_v1')
    checks = []
    p, future, binding = local.packet('0123456789abcdef0123456789abcdef')
    checks.append(('46 distinct ordered links', len(p['links']) == 46 and
                   len({r['relative'] for r in p['links']}) == 46))
    checks.append(('proposal binds three new paths',
                   p['new_root'].encode() in future and
                   json.loads(binding)['paths']['NANHAI_GZ02_NATIVE_SOURCE_VIEW'] ==
                   p['new_root'] + '/source-view'))
    checks.append(('binding and packet hashes', local.sha(binding) == p['binding_sha256'] and
                   local.sha(local.encoded({k: v for k, v in p.items()
                                            if k != 'packet_sha256'})) == p['packet_sha256']))
    try:
        local.packet('not-a-nonce')
        checks.append(('bad nonce denied', False))
    except ValueError:
        checks.append(('bad nonce denied', True))
    try:
        remote.run({'schema': 'g279-sibling-stage2-packet-v1', 'packet_sha256': '0'})
        checks.append(('unsigned remote packet denied', False))
    except ValueError:
        checks.append(('unsigned remote packet denied', True))
    with tempfile.TemporaryDirectory() as td:
        with mock.patch.object(local, 'OUT', Path(td)):
            local.freeze('0123456789abcdef0123456789abcdef')
            try:
                local.freeze('0123456789abcdef0123456789abcdef')
                checks.append(('O_EXCL freeze replay denied', False))
            except FileExistsError:
                checks.append(('O_EXCL freeze replay denied', True))
            bogus = Path(td) / 'bogus-review.json'
            bogus.write_text('{}')
            with mock.patch.object(local, 'host_identity', return_value=None):
                try:
                    local.execute(bogus)
                    checks.append(('unreleased execute denied before SSH', False))
                except ValueError as e:
                    checks.append(('unreleased execute denied before SSH',
                                   'release absent' in str(e)))
            checks.append(('no local START from denied execute',
                           not (Path(td) / 'receipts').exists()))
    result = {'schema': 'g279-stage2-local-fixtures-v1',
              'status': 'PASS' if all(ok for _, ok in checks) else 'FAIL',
              'checks': [{'name': name, 'pass': ok} for name, ok in checks],
              'remote_writes': 0, 'network': 0, 'graph': 0,
              'device': 0, 'container': 0}
    print(json.dumps(result, sort_keys=True, indent=2))
    if result['status'] != 'PASS':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
