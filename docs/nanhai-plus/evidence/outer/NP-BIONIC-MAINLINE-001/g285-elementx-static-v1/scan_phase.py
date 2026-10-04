import hashlib
import json
import os
import pathlib
import struct
import sys
import traceback
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from common import I, L, Q, R, guard, now, put, sha

phase = sys.argv[1]
assert phase in {'zip', 'metadata', 'elf', 'dex'}
out = L / 'phases' / phase
assert out.is_dir()
apk = L / 'apk-view' / 'io.element.android.x.apk'
result = {'phase': phase, 'started_at': now(), 'rc': 2, 'device_commands': 0}

def encode(v):
    if isinstance(v, (set, frozenset)):
        return sorted((encode(x) for x in v), key=str)
    if isinstance(v, dict):
        if all(isinstance(k, str) for k in v):
            return {k: encode(x) for k, x in v.items()}
        return [{'key': encode(k), 'value': encode(x)} for k, x in sorted(v.items(), key=lambda item: str(item[0]))]
    if isinstance(v, (list, tuple)):
        return [encode(x) for x in v]
    return v

try:
    guard('io.element.android.x')
    sys.path.insert(0, str(R / 'harness'))
    from westlake_gap import scanner
    if phase == 'zip':
        def member_sha(z, e):
            h = hashlib.sha256()
            with z.open(e) as stream:
                for chunk in iter(lambda: stream.read(1048576), b''):
                    h.update(chunk)
            return h.hexdigest()
        with zipfile.ZipFile(apk) as z:
            entries = z.infolist()
            names = [e.filename for e in entries]
            assert len(names) == len(set(names)) == 1411
            assert z.testzip() is None
            kinds = {'dex': [], 'elf': [], 'zip_in_so': [], 'other_so': []}
            for e in entries:
                n = e.filename
                if n.startswith('lib/') and n.endswith('.so'):
                    with z.open(e) as f:
                        header = f.read(64)
                    if header.startswith(b'\x7fELF') and len(header) >= 20:
                        cls, machine = header[4], struct.unpack_from('<H', header, 18)[0]
                        abi = n.split('/')[1]
                        assert (abi, cls, machine) in {('arm64-v8a', 2, 183), ('armeabi-v7a', 1, 40), ('x86_64', 2, 62)}
                        kinds['elf'].append({'name': n, 'bytes': e.file_size, 'class': cls, 'machine': machine, 'abi': abi, 'sha256': member_sha(z, e)})
                    elif header.startswith(b'PK\x03\x04'):
                        kinds['zip_in_so'].append({'name': n, 'bytes': e.file_size})
                    else:
                        kinds['other_so'].append({'name': n, 'bytes': e.file_size, 'header_hex': header[:16].hex()})
                if n == 'classes.dex' or (n.startswith('classes') and n.endswith('.dex') and n[7:-4].isdigit()):
                    with z.open(e) as f:
                        header = f.read(112)
                    assert header.startswith(b'dex\n') and len(header) == 112 and struct.unpack_from('<I', header, 32)[0] == e.file_size
                    kinds['dex'].append({'name': n, 'bytes': e.file_size, 'sha256': member_sha(z, e)})
            assert len(kinds['dex']) == 3 and len(kinds['elf']) == 13 and not kinds['other_so']
            put(out / 'ZIP-FACTS.json', {'entries_scanned': len(entries), 'crc_all_ok': True, 'uncompressed_bytes': sum(e.file_size for e in entries), 'compressed_bytes': sum(e.compress_size for e in entries), 'manifest_count': names.count('AndroidManifest.xml'), 'kinds': kinds})
    elif phase == 'metadata':
        m = scanner.apk_metadata(apk)
        put(out / 'MANIFEST.json', m)
        assert m.get('manifest_available') is True and m.get('package') == 'io.element.android.x'
        assert m.get('version_name') == '26.09.1'
        assert m.get('sha256') == I['apks'][0]['sha256'] and m.get('bytes') == I['apks'][0]['bytes']
    elif phase == 'elf':
        records = scanner.apk_elf_inventory(apk)
        put(out / 'ELF-INVENTORY.json', records)
        assert len(records) == 13 and all(x.get('readelf_ok') is True and x.get('abi_matches_machine') is True and not x.get('error') and not x.get('registration_scan_error') for x in records)
    elif phase == 'dex':
        inv = scanner.inventory_dex(apk)
        put(out / 'DEX-INVENTORY.json', encode(vars(inv)))
        assert {x['name'] for x in inv.dex_entries} == {'classes.dex', *(f'classes{i}.dex' for i in range(2, 4))}
    result['rc'] = 0
except BaseException as e:
    result.update(error=repr(e), traceback=traceback.format_exc())
finally:
    try:
        guard('io.element.android.x')
        result['source_apk_tool_postguard'] = True
    except BaseException as e:
        result.update(rc=2, source_apk_tool_postguard=False, guard_error=repr(e))
    result['finished_at'] = now()
    put(out / 'RESULT.json', result)
print(json.dumps({k: v for k, v in result.items() if k != 'traceback'}), flush=True)
sys.exit(result['rc'])
