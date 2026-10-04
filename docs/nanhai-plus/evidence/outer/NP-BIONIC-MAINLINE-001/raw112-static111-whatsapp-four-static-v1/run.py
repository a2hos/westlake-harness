#!/usr/bin/env python3
"""One execution of the four WhatsApp host static phases, preserving every return code."""
import datetime, hashlib, json, os, pathlib, secrets, signal, subprocess, sys, time

ROOT = pathlib.Path(os.environ['NANHAI_PROJECT_ROOT'])
HERE = pathlib.Path(__file__).parent
LIMITS = {'zip': 300, 'metadata': 300, 'dex': 1800, 'elf': 1800}

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1048576), b''):
            h.update(block)
    return h.hexdigest()

def put(path, obj):
    with path.open('x') as f:
        json.dump(obj, f, sort_keys=True, indent=2, ensure_ascii=False)
        f.write('\n')

def main():
    if sys.argv[1:] != ['--execute'] or (HERE / 'START.json').exists():
        return 2
    apk = HERE / 'WhatsApp.apk'
    raw = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/mainstream-whatsapp-official-supplement-v1/root-intake-v1/ROOT-ACCEPTANCE.json'
    scanner = ROOT / 'harness/westlake_gap/scanner.py'
    python = ROOT / '.nanhai-plus-runtime/bionic-oh7-aosp16/venvs/harness-python-v1/bin/python3'
    readelf = ROOT / '.nanhai-plus-runtime/bionic-oh7-aosp16/inputs-view/harness-native-hosttool-v1/bin/readelf'
    assert readelf.is_symlink() and readelf.resolve() == pathlib.Path(os.environ['NANHAI_OH_SDK_ROOT']) / 'llvm/bin/llvm-readelf'
    expected = 'c4260c7c569c19267fd33ee33b6241fadbee55e3bcfceb3ee151012801368dbb'
    assert sha(apk) == expected and apk.stat().st_size == 148660262
    assert json.loads(raw.read_text())['body']['sha256'] == expected
    nonce = secrets.token_hex(16)
    put(HERE / 'START.json', {'at_utc': now(), 'nonce': nonce, 'apk_sha256': expected,
        'raw_admission_sha256': sha(raw), 'scanner_sha256': sha(scanner),
        'readelf_sha256': sha(readelf), 'phase_script_sha256': sha(HERE / 'scan_phase.py'),
        'runner_sha256': sha(HERE / 'run.py'), 'limits_seconds': LIMITS,
        'scope': 'native Mac host static only; no device/container/SSH'})
    rows = []
    tmp = HERE / 'tmp'
    tmp.mkdir(exist_ok=True)
    for phase, limit in LIMITS.items():
        argv = [str(python), '-I', '-B', str(HERE / 'scan_phase.py'), phase]
        env = {k: v for k, v in os.environ.items() if not k.startswith(('PYTHON', 'PIP_')) and 'proxy' not in k.lower()}
        env.update(PATH=str(readelf.parent) + ':' + str(python.parent) + ':/usr/bin:/bin:/usr/sbin:/sbin',
                   TMPDIR=str(tmp), LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
        row = {'nonce': nonce, 'phase': phase, 'argv': argv, 'started_at': now(),
               'timeout_seconds': limit, 'cwd': str(ROOT),
               'environment': {k: env[k] for k in ('PATH', 'TMPDIR', 'LC_ALL', 'PYTHONDONTWRITEBYTECODE')}}
        out = HERE / (phase + '-stdout.raw')
        err = HERE / (phase + '-stderr.raw')
        t = time.monotonic()
        with out.open('xb') as a, err.open('xb') as b:
            process = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=a, stderr=b, start_new_session=True)
            try:
                row['rc'] = process.wait(timeout=limit)
                row['timed_out'] = False
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                row['rc'] = process.wait()
                row['timed_out'] = True
        row.update(finished_at=now(), elapsed_seconds=round(time.monotonic() - t, 3),
                   stdout_sha256=sha(out), stderr_sha256=sha(err))
        put(HERE / (phase + '-COMMAND.json'), row)
        rows.append(row)
        print(json.dumps({'phase': phase, 'rc': row['rc'], 'elapsed_seconds': row['elapsed_seconds']}), flush=True)
    complete = len(rows) == 4 and all(row['rc'] == 0 and not row['timed_out'] for row in rows)
    result = {'schema': 'raw112-static111-whatsapp-four-static-terminal-v1', 'at_utc': now(), 'nonce': nonce,
              'apk_sha256': expected, 'rows': rows, 'all_four_phases_rc0': complete,
              'candidate_decision': 'READY_FOR_INDEPENDENT_HOST_STATIC_REVIEW' if complete else 'NO_GO_INCOMPLETE_HOST_STATIC',
              'authoritative_count_changed': False, 'cold_start_delta': 0,
              'device_commands': 0, 'container_commands': 0, 'ssh_commands': 0}
    result['rc'] = 0 if complete else 2
    put(HERE / 'RESULT.json', result)
    return result['rc']

if __name__ == '__main__':
    sys.exit(main())
