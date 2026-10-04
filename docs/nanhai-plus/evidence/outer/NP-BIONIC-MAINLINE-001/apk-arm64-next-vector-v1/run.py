#!/usr/bin/env python3
"""One-shot exact F-Droid Element APK intake; execution requires root release."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
URL = 'https://f-droid.org/repo/im.vector.app_40106622.apk'
PACKAGE = 'im.vector.app'
VERSION_CODE = '40106622'
VERSION_NAME = '1.6.62'
BYTES = 72422482
DIGEST = 'ff73751599211c709c1e691d1a2b7412df0bab979ffbe8ff0d4b7f31c6a444c9'
REGISTRY_DIGEST = '289dcdb499d5ff37e58a8e7d4fbd3d30e3fe9f77d4e7e8ba7139c927c890c1eb'

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def need(condition, message):
    if not condition:
        raise RuntimeError(message)

def stamp():
    return datetime.now(timezone.utc).isoformat()

def exclusive_json(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())

def run_command(name, args, timeout, env, result):
    start = time.monotonic()
    try:
        p = subprocess.run(args, cwd=HERE, env=env, capture_output=True, timeout=timeout, check=False)
        rc, stdout, stderr, timed_out = p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, stdout, stderr, timed_out = None, e.stdout or b'', e.stderr or b'', True
    (HERE / (name + '.stdout.raw')).write_bytes(stdout)
    (HERE / (name + '.stderr.raw')).write_bytes(stderr)
    entry = {'name': name, 'argv': args, 'rc': rc, 'timed_out': timed_out,
             'seconds': round(time.monotonic() - start, 3),
             'stdout_sha256': hashlib.sha256(stdout).hexdigest(),
             'stderr_sha256': hashlib.sha256(stderr).hexdigest()}
    result['commands'].append(entry)
    need(rc == 0 and not timed_out, name + ' failed')
    return stdout.decode('utf-8', errors='replace')

def transfer_fields(output):
    fields = dict(re.findall(r'(http|tls|bytes|redirects|effective)=([^\s]+)', output))
    need(set(fields) == {'http', 'tls', 'bytes', 'redirects', 'effective'}, 'curl fields incomplete')
    need(fields['http'] == '200' and fields['tls'] == '0' and fields['redirects'] == '0'
         and fields['effective'] == URL, 'HTTP/TLS/URL drift')
    return fields

def head_length(raw):
    text = raw.decode('latin1')
    length = re.findall(r'(?im)^content-length:\s*(\d+)\s*$', text)
    mime = re.findall(r'(?im)^content-type:\s*([^\r\n]+)', text)
    need(len(length) == 1 and len(mime) == 1, 'HEAD header multiplicity')
    need(mime[0].strip().lower() == 'application/vnd.android.package-archive', 'HEAD MIME drift')
    need(int(length[0]) == BYTES, 'HEAD length drift')
    return int(length[0])

def identity(badging):
    line = next((s for s in badging.splitlines() if s.startswith('package: ')), '')
    fields = dict(re.findall(r"(name|versionCode|versionName)='([^']+)'", line))
    need(fields.get('name') == PACKAGE and fields.get('versionCode') == VERSION_CODE
         and fields.get('versionName') == VERSION_NAME, 'manifest identity drift')
    native = next((s for s in badging.splitlines() if s.startswith('native-code:')), '')
    need("'arm64-v8a'" in native and "'armeabi-v7a'" not in native, 'badging ABI drift')
    return {'fields': fields, 'native_code': native}

def preflight():
    release = HERE / 'ROOT-RELEASE.json'
    prepare = HERE / 'PREPARE.json'
    candidate = HERE / 'CANDIDATE.json'
    need(release.is_file() and prepare.is_file() and candidate.is_file(), 'missing review/release')
    approval = json.loads(release.read_text())
    need(approval.get('decision') == 'GO_ONE_BOUNDED_GET', 'root has not released GET')
    need(approval.get('script_sha256') == sha(__file__) and
         approval.get('prepare_sha256') == sha(prepare) and
         approval.get('candidate_sha256') == sha(candidate), 'release input hash drift')
    need(not (HERE / 'START.json').exists() and not (HERE / 'RESULT.json').exists(),
         'this generation already started; never replay')
    from importlib.util import module_from_spec, spec_from_file_location
    spec = spec_from_file_location('nanhai_env', ROOT / 'scripts/nanhai_plus_env.py')
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    bindings, envinfo = module.load_environment(ROOT / 'local_env.md')
    need(bindings['NANHAI_PROJECT_ROOT'] == str(ROOT) and
         bindings['NANHAI_CONTAINER_POLICY'] == 'forbidden', 'project/container binding drift')
    need(envinfo['config_sha256'] == approval.get('env_sha256'), 'env lock drift')
    for key, value in bindings.items():
        need(os.environ.get(key) == value, 'inherited environment drift: ' + key)
    registry = Path(bindings['NANHAI_EVIDENCE_ROOT']) / 'outer/NP-BIONIC-MAINLINE-001/upstream-apk-registry-v1/REGISTRY.json'
    need(sha(registry) == REGISTRY_DIGEST, 'registry drift')
    record = [r for r in json.loads(registry.read_text())['records'] if r['id'] == 'r-570841c0ce268cd2ac69']
    need(len(record) == 1 and record[0]['package'] == PACKAGE and
         record[0]['fields']['artifact_sha256']['value'] == DIGEST, 'upstream lock drift')
    staging = Path(bindings['NANHAI_STAGING_ROOT']) / 'apk-arm64-next-vector-v1'
    need(not staging.exists(), 'staging exists; no replay')
    curl = Path(bindings['NANHAI_CURL'])
    aapt2 = Path(bindings['NANHAI_SOURCE_POOL_ROOT']) / 'AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/bin/aapt2'
    signer = Path(bindings['NANHAI_SOURCE_POOL_ROOT']) / 'AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/lib/apksigner.jar'
    java = Path('/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home/bin/java')
    for name, path in {'curl': curl, 'aapt2': aapt2, 'apksigner': signer, 'java': java}.items():
        need(sha(path) == approval.get('tool_sha256', {}).get(name), name + ' tool drift')
    return staging, curl, aapt2, signer, java

def execute():
    stage, curl, aapt2, signer, java = preflight()
    result = {'schema': 'nanhai.vector.raw_get_result.v1', 'began_utc': stamp(),
              'status': 'IN_PROGRESS', 'commands': [], 'apk_get_max': 1,
              'device_commands': 0, 'container_commands': 0, 'count_delta': 0}
    exclusive_json(HERE / 'START.json', {'schema': 'nanhai.vector.raw_get_start.v1',
                                        'at_utc': stamp(), 'script_sha256': sha(__file__),
                                        'url': URL, 'bytes': BYTES, 'sha256': DIGEST,
                                        'state': 'UNKNOWN_IF_RESULT_ABSENT_DO_NOT_REPLAY'})
    try:
        stage.mkdir(parents=True, exist_ok=False)
        part = stage / 'im.vector.app_40106622.apk.part'
        apk = stage / 'im.vector.app_40106622.apk'
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC', 'TMPDIR': str(stage)}
        for key in ('HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'NO_PROXY',
                    'https_proxy', 'http_proxy', 'all_proxy', 'no_proxy'):
            if key in os.environ:
                env[key] = os.environ[key]
        base = [str(curl), '-q', '--fail', '--silent', '--show-error', '--proto', '=https',
                '--proto-redir', '=https', '--retry', '0', '--connect-timeout', '15', '--max-redirs', '0']
        fmt = 'http=%{http_code} tls=%{ssl_verify_result} bytes=%{size_download} redirects=%{num_redirects} effective=%{url_effective}'
        head = HERE / 'runtime-head.headers.raw'
        output = run_command('runtime-head', base + ['--head', '--max-time', '20',
                             '--dump-header', str(head), '--output', '/dev/null',
                             '--write-out', fmt, URL], 25, env, result)
        transfer_fields(output)
        head_length(head.read_bytes())
        result['runtime_head_sha256'] = sha(head)
        output = run_command('runtime-download', base + ['--max-time', '240', '--max-filesize',
                             str(BYTES), '--output', str(part), '--write-out', fmt, URL],
                             250, env, result)
        fields = transfer_fields(output)
        need(int(fields['bytes']) == BYTES and part.stat().st_size == BYTES, 'received bytes drift')
        need(sha(part) == DIGEST, 'artifact SHA drift')
        part.rename(apk)
        result['apk'] = {'path': str(apk), 'bytes': BYTES, 'sha256': DIGEST}
        with zipfile.ZipFile(apk) as z:
            names = z.namelist()
            abis = sorted({m.group(1) for name in names if
                           (m := re.fullmatch(r'lib/([^/]+)/[^/]+\.so', name))})
            need(z.testzip() is None and names.count('AndroidManifest.xml') == 1, 'ZIP/manifest invalid')
            need(abis == ['arm64-v8a'], 'ZIP ABI drift')
            result['zip'] = {'entries': len(names), 'abis': abis, 'manifest_count': 1}
        badging = run_command('runtime-badging', [str(aapt2), 'dump', 'badging', str(apk)],
                              60, env, result)
        result['manifest'] = identity(badging)
        signature = run_command('runtime-signature', [str(java), '-XX:-UsePerfData', '-Xmx512m',
                                '-Djava.awt.headless=true', '-Djava.io.tmpdir=' + str(stage),
                                '-jar', str(signer), 'verify', '--verbose', '--print-certs', str(apk)],
                                120, env, result)
        need('Verified using v2 scheme (APK Signature Scheme v2): true' in signature or
             'Verified using v3 scheme (APK Signature Scheme v3): true' in signature,
             'modern APK signature scheme absent')
        cert = re.findall(r'(?m)^Signer #1 certificate SHA-256 digest: ([0-9a-f]+)$', signature)
        need(len(cert) == 1, 'signer certificate digest missing')
        result['signature'] = {'observed_cert_sha256': cert[0], 'publisher_anchor': None}
        need(sha(apk) == DIGEST, 'postguard APK drift')
        result['status'] = 'CANDIDATE_BYTES_VERIFIED_PENDING_PEER_ROOT_RAW_ADMISSION'
    except Exception as error:
        result['status'] = 'TERMINAL_FAILED_NO_RETRY'
        result['error'] = repr(error)
    result['ended_utc'] = stamp()
    exclusive_json(HERE / 'RESULT.json', result)
    return 0 if result['status'].startswith('CANDIDATE_BYTES_VERIFIED') else 2

if __name__ == '__main__':
    if sys.argv[1:] != ['--execute']:
        print('PREPARED_ONLY: requires --execute and matching ROOT-RELEASE.json', file=sys.stderr)
        raise SystemExit(3)
    raise SystemExit(execute())
