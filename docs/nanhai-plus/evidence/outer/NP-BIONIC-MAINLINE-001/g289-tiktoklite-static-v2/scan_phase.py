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
apk = L / 'apk-view' / 'com.tiktok.lite.go.apk'
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
    guard('com.tiktok.lite.go')
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
            assert len(names) == len(set(names)) == I['inventory_expectations']['zip_entries']
            assert z.testzip() is None
            kinds = {'dex': [], 'elf': [], 'packed_so': [], 'zip_in_so': [], 'other_so': []}
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
                    elif header.startswith(b'\x7fKOM'):
                        kinds['packed_so'].append({'name': n, 'bytes': e.file_size,
                                                   'abi': n.split('/')[1], 'sha256': member_sha(z, e),
                                                   'header_hex': header[:16].hex()})
                    else:
                        kinds['other_so'].append({'name': n, 'bytes': e.file_size, 'header_hex': header[:16].hex()})
                if n == 'classes.dex' or (n.startswith('classes') and n.endswith('.dex') and n[7:-4].isdigit()):
                    with z.open(e) as f:
                        header = f.read(112)
                    assert header.startswith(b'dex\n') and len(header) == 112 and struct.unpack_from('<I', header, 32)[0] == e.file_size
                    kinds['dex'].append({'name': n, 'bytes': e.file_size, 'sha256': member_sha(z, e)})
            assert kinds['dex'] and len(kinds['elf']) == I['inventory_expectations']['true_elf_entries']
            assert len(kinds['packed_so']) == I['inventory_expectations']['packed_non_elf_so_entries']
            assert not kinds['other_so'] and not kinds['zip_in_so']
            assert sorted({x['abi'] for x in kinds['elf'] + kinds['packed_so']}) == I['inventory_expectations']['native_abis']
            put(out / 'ZIP-FACTS.json', {'entries_scanned': len(entries), 'crc_all_ok': True, 'uncompressed_bytes': sum(e.file_size for e in entries), 'compressed_bytes': sum(e.compress_size for e in entries), 'manifest_count': names.count('AndroidManifest.xml'), 'kinds': kinds})
    elif phase == 'metadata':
        m = scanner.apk_metadata(apk)
        put(out / 'MANIFEST.json', m)
        assert m.get('manifest_available') is True and m.get('package') == 'com.tiktok.lite.go'
        assert str(m.get('version_code')) == str(I['apks'][0]['version_code'])
        assert m.get('version_name') == I['apks'][0]['version_name']
        assert m.get('abis') == I['inventory_expectations']['native_abis']
        assert m.get('sha256') == I['apks'][0]['sha256'] and m.get('bytes') == I['apks'][0]['bytes']
    elif phase == 'elf':
        zipfacts = json.loads((L/'phases/zip/ZIP-FACTS.json').read_text())
        true_entries = zipfacts['kinds']['elf']
        packed_names = {x['name'] for x in zipfacts['kinds']['packed_so']}
        records = []
        with zipfile.ZipFile(apk) as archive:
            for entry in true_entries:
                name = entry['name']
                record = scanner.read_elf(data=archive.read(name), label=name, abi=entry['abi'])
                record.update(archive_entry=name, split_apk=None)
                records.append(record)
        put(out / 'ELF-INVENTORY.json', records)
        true_elf_names = {x['name'] for x in true_entries}
        assert {x.get('archive_entry') for x in records} == true_elf_names
        assert len(records) == len(true_elf_names)
        assert all(x.get('readelf_ok') is True and x.get('abi_matches_machine') is True and
                   not x.get('error') and not x.get('registration_scan_error')
                   for x in records)
        # The four packed .so entries remain explicit opaque inputs in ZIP-FACTS.
        assert len(packed_names) == I['inventory_expectations']['packed_non_elf_so_entries']
    elif phase == 'dex':
        inv = scanner.inventory_dex(apk)
        put(out / 'DEX-INVENTORY.json', encode(vars(inv)))
        expected = {x['name'] for x in json.loads((L/'phases/zip/ZIP-FACTS.json').read_text())['kinds']['dex']}
        assert {x['name'] for x in inv.dex_entries} == expected
    result['rc'] = 0
except BaseException as e:
    result.update(error=repr(e), traceback=traceback.format_exc())
finally:
    try:
        guard('com.tiktok.lite.go')
        result['source_apk_tool_postguard'] = True
    except BaseException as e:
        result.update(rc=2, source_apk_tool_postguard=False, guard_error=repr(e))
    result['finished_at'] = now()
    put(out / 'RESULT.json', result)
print(json.dumps({k: v for k, v in result.items() if k != 'traceback'}), flush=True)
sys.exit(result['rc'])
