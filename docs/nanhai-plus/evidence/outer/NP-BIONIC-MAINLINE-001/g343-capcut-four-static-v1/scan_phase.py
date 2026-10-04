#!/usr/bin/env python3
"""Host-only four-phase scan of the exact root-admitted CapCut APK."""
import hashlib, json, os, pathlib, struct, sys, traceback, zipfile

ROOT = pathlib.Path(os.environ['NANHAI_PROJECT_ROOT'])
HERE = pathlib.Path(__file__).parent
APK = pathlib.Path(os.environ['NANHAI_STAGING_ROOT']) / 'g316-capcut-official-v1/CapCut.apk'
RAW = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g316-capcut-official-raw-candidate-v2/root-raw-admission-v1/ROOT-RAW-ADMISSION.json'
SCANNER = ROOT / 'harness/westlake_gap/scanner.py'
EXPECTED_APK = 'f2d5cf017bc4bf5a2d3e500a1a8c13cf0c83e3fa1bc707c6603e91af9b77612a'
EXPECTED_SIZE = 319992455

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1048576), b''):
            h.update(block)
    return h.hexdigest()

def guard():
    actual = {'apk': sha(APK), 'raw_admission': sha(RAW), 'scanner': sha(SCANNER)}
    admission = json.loads(RAW.read_text())
    if APK.suffix != '.apk' or APK.stat().st_size != EXPECTED_SIZE or actual['apk'] != EXPECTED_APK:
        raise ValueError('APK identity drift')
    if admission['apk_sha256'] != EXPECTED_APK or admission['decision'] != 'ACCEPT_EXACT_CAPCUT_13_6_0_HOST_RAW_ONLY_WITH_ARM64_PATH_EXCEPTION':
        raise ValueError('raw admission drift')
    return actual

def put(path, obj):
    with path.open('x') as f:
        json.dump(obj, f, sort_keys=True, indent=2, ensure_ascii=False)
        f.write('\n')

def encode(obj):
    if isinstance(obj, (set, frozenset)):
        return sorted((encode(x) for x in obj), key=str)
    if isinstance(obj, dict):
        return {str(k): encode(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [encode(x) for x in obj]
    if hasattr(obj, '__dict__'):
        return encode(vars(obj))
    return obj

def classify(data):
    if not data.startswith(b'\x7fELF'):
        return {'kind': 'non_elf', 'magic': data[:8].hex()}
    if len(data) < 20:
        raise ValueError('truncated ELF header')
    endian = data[5]
    if endian not in (1, 2):
        raise ValueError('unknown ELF endian')
    machine = struct.unpack('<H' if endian == 1 else '>H', data[18:20])[0]
    return {'kind': 'elf', 'class': data[4], 'endian': endian, 'machine': machine}

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('zip', 'metadata', 'dex', 'elf'):
        return 2
    phase = sys.argv[1]
    out = HERE / 'phases' / phase
    out.mkdir(parents=True, exist_ok=False)
    result = {'phase': phase, 'rc': 2, 'apk_sha256': EXPECTED_APK, 'network_commands': 0, 'device_commands': 0, 'container_commands': 0}
    before = None
    try:
        before = guard()
        result['input_sha256_before'] = before
        sys.path.insert(0, str(ROOT / 'harness'))
        from westlake_gap import scanner
        if phase == 'zip':
            with zipfile.ZipFile(APK) as z:
                names = z.namelist()
                bad = z.testzip()
                facts = {'entries': len(names), 'unique_names': len(set(names)), 'crc_first_bad': bad,
                         'manifest_entries': names.count('AndroidManifest.xml'),
                         'root_dex_names': [n for n in names if n.startswith('classes') and n.endswith('.dex')],
                         'so_entries': sum(n.startswith('lib/') and n.endswith('.so') for n in names)}
                put(out / 'ZIP-FACTS.json', facts)
                assert bad is None and len(names) == len(set(names)) and facts['manifest_entries'] == 1
        elif phase == 'metadata':
            meta = scanner.apk_metadata(APK)
            put(out / 'MANIFEST.json', meta)
            assert meta.get('manifest_available') is True
            assert meta.get('package') == 'com.lemon.lvoverseas'
            assert meta.get('version_name') == '13.6.0' and str(meta.get('version_code')) == '13601600'
            assert meta.get('sha256') == EXPECTED_APK and meta.get('bytes') == EXPECTED_SIZE
        elif phase == 'dex':
            inv = scanner.inventory_dex(APK)
            put(out / 'DEX-INVENTORY.json', encode(inv))
            result['dex_entries'] = len(inv.dex_entries)
            assert len(inv.dex_entries) > 0
        else:
            true_arm64, misplaced_arm32, other_arm32, other, non_elf = [], [], [], [], []
            records = []
            with zipfile.ZipFile(APK) as z:
                names = [n for n in z.namelist() if n.startswith('lib/') and n.endswith('.so')]
                for n in names:
                    data = z.read(n)
                    hdr = classify(data)
                    row = {'name': n, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), **hdr}
                    abi = n.split('/')[1]
                    if hdr['kind'] == 'non_elf':
                        non_elf.append(row)
                    elif hdr['class'] == 2 and hdr['machine'] == 183 and abi == 'arm64-v8a':
                        true_arm64.append(row)
                        record = scanner.read_elf(data=data, label=n, abi=abi)
                        record['archive_entry'] = n
                        records.append(record)
                    elif hdr['class'] == 1 and hdr['machine'] == 40 and abi == 'arm64-v8a':
                        misplaced_arm32.append(row)
                    elif hdr['class'] == 1 and hdr['machine'] == 40:
                        other_arm32.append(row)
                    else:
                        other.append(row)
            classification = {'archive_so_count': len(names), 'true_arm64_elf': true_arm64,
                              'arm64_path_misplaced_arm32_elf': misplaced_arm32,
                              'other_arm32_elf': other_arm32, 'other_elf': other,
                              'non_elf_so': non_elf}
            put(out / 'ELF-CLASSIFICATION.json', classification)
            put(out / 'ELF-INVENTORY.json', records)
            result['elf_counts'] = {k: len(v) for k, v in classification.items() if isinstance(v, list)}
            assert len(true_arm64) == 146 and len(misplaced_arm32) == 1 and len(other_arm32) == 145
            assert len(other) == 0 and len(non_elf) == 0
            assert misplaced_arm32[0]['name'] == 'lib/arm64-v8a/libcvt.so'
            assert misplaced_arm32[0]['sha256'] == '336c9807054a2f88703509b6f27edd9d7c82acdbc7f2a50d6b0e2d5c79697153'
            assert all(r.get('readelf_ok') is True and r.get('abi_matches_machine') is True for r in records)
        result['rc'] = 0
    except BaseException as e:
        result['error'] = repr(e)
        result['traceback'] = traceback.format_exc()
    finally:
        try:
            after = guard()
            result['input_sha256_after'] = after
            result['input_guard_equal'] = after == before
            if after != before:
                result['rc'] = 2
        except BaseException as e:
            result['post_guard_error'] = repr(e)
            result['rc'] = 2
        put(out / 'RESULT.json', result)
    print(json.dumps({k: v for k, v in result.items() if k != 'traceback'}, sort_keys=True), flush=True)
    return result['rc']

if __name__ == '__main__':
    sys.exit(main())
