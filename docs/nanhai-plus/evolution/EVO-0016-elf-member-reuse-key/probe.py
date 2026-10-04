"""Read-only candidate key trial over already sealed batch12 member receipts."""
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[4]
EVID = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001'
BASE = EVID / 'harness-stock-inventory-batch12-v3-candidate'
INPUTS = json.loads((EVID / 'harness-stock-inventory-batch12-v2/INPUTS.json').read_text())
PROBE = json.loads((BASE / 'PROBE.json').read_text())


def key(member_sha, name, abi, scanner_sha, readelf_sha, venv_sha, environment_sha):
    fields = ['elf-member-readelf-v1', member_sha, name, abi, scanner_sha,
              readelf_sha, venv_sha, environment_sha]
    return hashlib.sha256(json.dumps(fields, separators=(',', ':')).encode()).hexdigest()


def main():
    scanner_sha = INPUTS['source_sha256']['harness/westlake_gap/scanner.py']
    readelf_sha = INPUTS['tool_mapping']['tool_sha256']
    venv_sha = INPUTS['venv_manifest']['sha256']
    environment_sha = INPUTS['environment_sha256']
    rows = []
    for package in PROBE['rows']:
        for member in package['entries']:
            if member['kind'] != 'ELF':
                continue
            abi = member['name'].split('/')[1]
            receipt = next((p for p in (BASE / 'member-trials').glob('*/RESULT.json')
                            if (lambda r: r.get('package') == package['package'] and
                                r.get('member') == member['name'])(json.loads(p.read_text()))), None)
            assert receipt is not None
            result = json.loads(receipt.read_text())
            assert result['rc'] == 0 and result['postguard']
            assert result['input']['member_sha256'] == member['sha256']
            assert result['input']['tool_sha256'] == readelf_sha
            rows.append({'package': package['package'], 'member': member['name'],
                         'member_sha256': member['sha256'], 'key': key(member['sha256'], member['name'], abi,
                           scanner_sha, readelf_sha, venv_sha, environment_sha),
                         'receipt': str(receipt.relative_to(ROOT))})
    assert len(rows) == 14
    keys = [r['key'] for r in rows]
    base = rows[0]
    abi = base['member'].split('/')[1]
    def k(sha=base['member_sha256'], name=base['member'], target_abi=abi,
          scanner=scanner_sha, tool=readelf_sha, venv=venv_sha, env=environment_sha):
        return key(sha, name, target_abi, scanner, tool, venv, env)
    controls = {
        'same_content_renamed_archive_stable': k() == base['key'],
        'member_content_change_invalidates': k(sha='0'*64) != base['key'],
        'label_change_invalidates': k(name='lib/arm64-v8a/other.so') != base['key'],
        'abi_change_invalidates': k(target_abi='x86') != base['key'],
        'scanner_change_invalidates': k(scanner='0'*64) != base['key'],
        'readelf_change_invalidates': k(tool='0'*64) != base['key'],
        'venv_change_invalidates': k(venv='0'*64) != base['key'],
        'environment_change_invalidates': k(env='0'*64) != base['key'],
        'observed_keys_unique': len(keys) == len(set(keys)),
        'source_pin_current': hashlib.sha256((ROOT / 'harness/westlake_gap/scanner.py').read_bytes()).hexdigest() == scanner_sha,
        'tool_pin_current': hashlib.sha256(pathlib.Path(INPUTS['tool_mapping']['target']).read_bytes()).hexdigest() == readelf_sha,
    }
    print(json.dumps({'schema': 'evo16-elf-member-reuse-key-trial-v1', 'candidate_only': True,
                      'scanner_sha256': scanner_sha, 'readelf_sha256': readelf_sha,
                      'rows': rows, 'controls': controls, 'all_pass': all(controls.values()),
                      'runtime_reuse_performed': False, 'device_commands': 0}, indent=2))
    return 0 if all(controls.values()) else 2


if __name__ == '__main__':
    raise SystemExit(main())
