#!/usr/bin/env python3
"""One-shot offline validation of the exact retained v2 Element APK."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
V2 = HERE.parent / 'apk-arm64-next-vector-v2'
PACKAGE = 'im.vector.app'
VERSION_CODE = '40106622'
VERSION_NAME = '1.6.62'
BYTES = 72422482
DIGEST = 'ff73751599211c709c1e691d1a2b7412df0bab979ffbe8ff0d4b7f31c6a444c9'
DEADLINE_SECONDS = 180
DEADLINE_AT = None

def need(condition, why):
    if not condition:
        raise RuntimeError(why)

def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()

def stamp():
    return datetime.now(timezone.utc).isoformat()

def exclusive_json(path, obj):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(obj, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())

def parse_badging(output):
    lines = [line for line in output.splitlines() if line.startswith('package: ')]
    need(len(lines) == 1, 'exactly one package line required')
    # A field starts after whitespace. This excludes compileSdkVersionCodename.
    matches = re.findall(r"(?<!\S)(name|versionCode|versionName)='([^']*)'", lines[0])
    fields = {}
    for key, value in matches:
        need(key not in fields, 'duplicate package field: ' + key)
        fields[key] = value
    need(fields == {'name': PACKAGE, 'versionCode': VERSION_CODE,
                    'versionName': VERSION_NAME}, 'manifest package/version drift')
    native = [line for line in output.splitlines() if line.startswith('native-code:')]
    need(len(native) == 1 and native[0].strip() == "native-code: 'arm64-v8a'",
         'badging ABI drift')
    return {'package': fields['name'], 'version_code': fields['versionCode'],
            'version_name': fields['versionName'], 'native_code': native[0]}

def run_command(name, args, env, result):
    remaining = DEADLINE_AT - time.monotonic()
    need(remaining > 2, 'deadline reached before ' + name)
    start = time.monotonic()
    try:
        process = subprocess.run(args, cwd=HERE, env=env, capture_output=True,
                                 timeout=min(90, remaining - 1), check=False)
        rc, out, err, timed = process.returncode, process.stdout, process.stderr, False
    except subprocess.TimeoutExpired as error:
        rc, out, err, timed = None, error.stdout or b'', error.stderr or b'', True
    (HERE / (name + '.stdout.raw')).write_bytes(out)
    (HERE / (name + '.stderr.raw')).write_bytes(err)
    result['commands'].append({'name': name, 'argv': args, 'rc': rc, 'timed_out': timed,
        'seconds': round(time.monotonic() - start, 3),
        'stdout_sha256': hashlib.sha256(out).hexdigest(),
        'stderr_sha256': hashlib.sha256(err).hexdigest()})
    need(rc == 0 and not timed, name + ' failed')
    return out.decode('utf-8', errors='replace')

def preflight():
    release = HERE / 'ROOT-RELEASE.json'
    prepare = HERE / 'PREPARE.json'
    candidate = HERE / 'CANDIDATE.json'
    need(release.is_file() and prepare.is_file() and candidate.is_file(), 'review/release missing')
    approval = json.loads(release.read_text())
    need(approval.get('decision') == 'GO_ONE_OFFLINE_VALIDATION', 'root release absent')
    for key, path in [('script_sha256', Path(__file__)), ('prepare_sha256', prepare),
                      ('candidate_sha256', candidate)]:
        need(approval.get(key) == sha(path), key + ' release drift')
    frozen = json.loads(prepare.read_text())
    need(frozen.get('fixture_sha256') == sha(HERE / 'fixture.py') and
         frozen.get('fixture_receipt_sha256') == sha(HERE / 'FIXTURE.json') and
         frozen.get('retained_apk_sha256') == DIGEST, 'frozen offline packet drift')
    need(not (HERE / 'START.json').exists() and not (HERE / 'RESULT.json').exists(),
         'this v3 generation already started; never replay')
    spec = importlib.util.spec_from_file_location('nanhai_env', ROOT / 'scripts/nanhai_plus_env.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    bindings, envinfo = module.load_environment(ROOT / 'local_env.md')
    need(envinfo['config_sha256'] == approval.get('env_sha256') and
         bindings['NANHAI_PROJECT_ROOT'] == str(ROOT) and
         bindings['NANHAI_CONTAINER_POLICY'] == 'forbidden', 'environment drift')
    for key, value in bindings.items():
        need(os.environ.get(key) == value, 'inherited environment drift: ' + key)
    result_file = V2 / 'RESULT.json'
    need(sha(result_file) == approval.get('v2_result_sha256'), 'v2 receipt drift')
    old = json.loads(result_file.read_text())
    need(old.get('status') == 'TERMINAL_FAILED_NO_RETRY' and
         old.get('error') == "RuntimeError('manifest identity drift')", 'unexpected v2 terminal')
    apk = Path(bindings['NANHAI_STAGING_ROOT']) / 'apk-arm64-next-vector-v2/im.vector.app_40106622.apk'
    need(old.get('apk', {}).get('path') == str(apk), 'v2 receipt path drift')
    need(stat.S_ISREG(apk.lstat().st_mode) and apk.stat().st_size == BYTES and
         old['apk']['bytes'] == BYTES and old['apk']['sha256'] == DIGEST,
         'APK type/size/receipt drift')
    pool = Path(bindings['NANHAI_SOURCE_POOL_ROOT'])
    aapt2 = pool / 'AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/bin/aapt2'
    signer = pool / 'AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/lib/apksigner.jar'
    java = Path('/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home/bin/java')
    for name, path in {'aapt2': aapt2, 'apksigner': signer, 'java': java}.items():
        need(sha(path) == approval.get('tool_sha256', {}).get(name), name + ' tool drift')
    return apk, aapt2, signer, java, Path(bindings['NANHAI_TMP_ROOT'])

def execute():
    global DEADLINE_AT
    apk, aapt2, signer, java, tmp_root = preflight()
    result = {'schema': 'nanhai.vector.offline_validation_result.v3',
              'began_utc': stamp(), 'status': 'IN_PROGRESS', 'commands': [],
              'network_requests': 0, 'apk_get': 0, 'device_commands': 0,
              'container_commands': 0, 'count_delta': 0}
    exclusive_json(HERE / 'START.json', {'schema': 'nanhai.vector.offline_start.v3',
        'at_utc': stamp(), 'script_sha256': sha(__file__), 'apk_sha256': DIGEST,
        'state': 'UNKNOWN_IF_RESULT_ABSENT_DO_NOT_REPLAY'})
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_signum, _frame):
        raise TimeoutError('offline global deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    DEADLINE_AT = time.monotonic() + DEADLINE_SECONDS
    signal.setitimer(signal.ITIMER_REAL, DEADLINE_SECONDS)
    try:
        need(sha(apk) == DIGEST, 'APK SHA drift')
        with zipfile.ZipFile(apk) as archive:
            names = archive.namelist()
            abis = sorted({match.group(1) for name in names if
                           (match := re.fullmatch(r'lib/([^/]+)/[^/]+\.so', name))})
            need(archive.testzip() is None and names.count('AndroidManifest.xml') == 1,
                 'ZIP CRC/manifest invalid')
            need(abis == ['arm64-v8a'], 'ZIP ABI drift')
            result['zip'] = {'entries': len(names), 'manifest_count': 1, 'abis': abis}
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC', 'TMPDIR': str(tmp_root)}
        badging = run_command('offline-badging', [str(aapt2), 'dump', 'badging', str(apk)], env, result)
        result['manifest'] = parse_badging(badging)
        signature = run_command('offline-signature', [str(java), '-XX:-UsePerfData', '-Xmx512m',
            '-Djava.awt.headless=true', '-Djava.io.tmpdir=' + str(tmp_root), '-jar', str(signer),
            'verify', '--verbose', '--print-certs', str(apk)], env, result)
        need('Verified using v2 scheme (APK Signature Scheme v2): true' in signature or
             'Verified using v3 scheme (APK Signature Scheme v3): true' in signature,
             'modern APK signature scheme absent')
        cert = re.findall(r'(?m)^Signer #1 certificate SHA-256 digest: ([0-9a-f]+)$', signature)
        need(len(cert) == 1, 'signer certificate digest missing')
        result['signature'] = {'observed_cert_sha256': cert[0], 'publisher_anchor': None}
        need(sha(apk) == DIGEST, 'postguard APK drift')
        result['apk'] = {'path': str(apk), 'bytes': BYTES, 'sha256': DIGEST}
        result['status'] = 'OFFLINE_VALIDATION_CANDIDATE_PENDING_PEER_ROOT_RAW_ADMISSION'
    except Exception as error:
        result['status'] = 'TERMINAL_FAILED_NO_REPLAY'
        result['error'] = repr(error)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    result['ended_utc'] = stamp()
    exclusive_json(HERE / 'RESULT.json', result)
    return 0 if result['status'].startswith('OFFLINE_VALIDATION_CANDIDATE') else 2

if __name__ == '__main__':
    if sys.argv[1:] != ['--execute']:
        print('PREPARED_ONLY: offline execution requires --execute and ROOT-RELEASE.json', file=sys.stderr)
        raise SystemExit(3)
    raise SystemExit(execute())
