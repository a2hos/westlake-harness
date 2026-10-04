#!/usr/bin/env python3
"""Local fixture only; importing run.py cannot make network requests."""
import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'run.py'
SOURCE = SCRIPT.read_text()
ast.parse(SOURCE)
spec = importlib.util.spec_from_file_location('vector_intake', SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
checks = []

def check(name, value):
    if not value:
        raise RuntimeError(name)
    checks.append(name)

def rejects(name, call):
    try:
        call()
    except RuntimeError:
        checks.append(name)
    else:
        raise RuntimeError(name + ' accepted')

candidate = json.loads((HERE / 'CANDIDATE.json').read_text())
check('frozen URL', candidate['candidate']['source_url'] == runner.URL)
check('frozen length', candidate['candidate']['expected_bytes'] == runner.BYTES)
check('frozen SHA', candidate['candidate']['expected_sha256'] == runner.DIGEST)
check('frozen package', candidate['candidate']['package'] == runner.PACKAGE)
check('frozen ARM64', candidate['candidate']['registered_abis'] == ['arm64-v8a'])
check('v2 staging generation', "'apk-arm64-next-vector-v2'" in SOURCE)
check('global execution deadline', runner.GLOBAL_DEADLINE_SECONDS == 600)
check('HEAD length and MIME', runner.head_length((HERE / 'head.headers.raw').read_bytes()) == runner.BYTES)
rejects('duplicate length rejected', lambda: runner.head_length(
    (HERE / 'head.headers.raw').read_bytes() + b'Content-Length: 1\r\n'))
good = "package: name='im.vector.app' versionCode='40106622' versionName='1.6.62'\nnative-code: 'arm64-v8a'\n"
check('manifest identity and ABI', runner.identity(good)['fields']['name'] == runner.PACKAGE)
rejects('wrong package rejected', lambda: runner.identity(good.replace('im.vector.app', 'wrong.app')))
rejects('ARM32-only rejected', lambda: runner.identity(good.replace('arm64-v8a', 'armeabi-v7a')))
rejects('extra ARM32 rejected', lambda: runner.identity(good.replace("'arm64-v8a'", "'arm64-v8a' 'armeabi-v7a'")))
with tempfile.TemporaryDirectory(prefix='vector-fixture-') as temp:
    path = Path(temp) / 'START.json'
    runner.exclusive_json(path, {'once': True})
    try:
        runner.exclusive_json(path, {'twice': True})
    except FileExistsError:
        checks.append('exclusive START')
    else:
        raise RuntimeError('START overwrite accepted')
runner.DEADLINE_AT = time.monotonic() - 1
rejects('expired deadline prevents subprocess', lambda: runner.run_command(
    'must-not-run', ['/usr/bin/false'], 10, {}, {'commands': []}))
process = subprocess.run([sys.executable, '-B', str(SCRIPT)], capture_output=True, text=True)
check('noarg refuses GET', process.returncode == 3 and 'PREPARED_ONLY' in process.stderr)
check('no execution receipts', not (HERE / 'START.json').exists() and not (HERE / 'RESULT.json').exists())
check('one APK GET site', SOURCE.count("run_command('runtime-download'") == 1)
check('no shell/device/container', all(x not in SOURCE for x in ('shell=True', 'adb ', 'hdc ', 'docker ', 'podman ', 'nsjail ')))
print('FIXTURE_PASS', len(checks), ','.join(checks))
