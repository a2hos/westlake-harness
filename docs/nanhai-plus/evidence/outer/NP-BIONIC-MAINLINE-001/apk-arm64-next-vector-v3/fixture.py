#!/usr/bin/env python3
"""Local parser and guard fixture; never validates APK or starts v3 executor."""
import ast
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
RUNNER = HERE / 'run.py'
SOURCE = RUNNER.read_text()
ast.parse(SOURCE)
spec = importlib.util.spec_from_file_location('vector_v3_offline', RUNNER)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
checks = []

def check(name, condition):
    if not condition:
        raise RuntimeError(name)
    checks.append(name)

def reject(name, function):
    try:
        function()
    except RuntimeError:
        checks.append(name)
    else:
        raise RuntimeError(name + ' accepted')

v2 = HERE.parent / 'apk-arm64-next-vector-v2'
receipt = json.loads((v2 / 'RESULT.json').read_text())
badging = (v2 / 'runtime-badging.stdout.raw').read_text(errors='replace')
check('v2 terminal receipt', receipt['status'] == 'TERMINAL_FAILED_NO_RETRY' and
      receipt['error'] == "RuntimeError('manifest identity drift')")
check('v2 badging output present', badging.startswith("package: name='im.vector.app' "))
old_line = badging.splitlines()[0]
old_fields = dict(re.findall(r"(name|versionCode|versionName)='([^']*)'", old_line))
check('old unanchored regex reproduces wrong package',
      old_fields['name'] == '15' and old_fields['versionCode'] == '40106622')
parsed = module.parse_badging(badging)
check('anchored fields parse exact v2 output', parsed['package'] == module.PACKAGE and
      parsed['version_code'] == module.VERSION_CODE and parsed['version_name'] == module.VERSION_NAME)
check('ARM64 parsed', parsed['native_code'] == "native-code: 'arm64-v8a'")
reject('wrong exact version rejected', lambda: module.parse_badging(
    badging.replace("versionCode='40106622'", "versionCode='35'", 1)))
reject('duplicate exact version rejected', lambda: module.parse_badging(
    badging.replace("versionCode='40106622'", "versionCode='40106622' versionCode='35'", 1)))
reject('ARM32-only rejected', lambda: module.parse_badging(
    badging.replace("native-code: 'arm64-v8a'", "native-code: 'armeabi-v7a'", 1)))
reject('duplicate package line rejected', lambda: module.parse_badging(old_line + '\n' + badging))
with tempfile.TemporaryDirectory(prefix='vector-v3-fixture-') as temp:
    path = Path(temp) / 'START.json'
    module.exclusive_json(path, {'once': True})
    try:
        module.exclusive_json(path, {'twice': True})
    except FileExistsError:
        checks.append('exclusive START')
    else:
        raise RuntimeError('START overwrite accepted')
module.DEADLINE_AT = time.monotonic() - 1
reject('expired deadline prevents subprocess', lambda: module.run_command(
    'must-not-run', ['/usr/bin/false'], {}, {'commands': []}))
process = subprocess.run([sys.executable, '-B', str(RUNNER)], capture_output=True, text=True)
check('noarg refuses execution', process.returncode == 3 and 'PREPARED_ONLY' in process.stderr)
check('v3 no execution receipts', not (HERE / 'START.json').exists() and not (HERE / 'RESULT.json').exists())
check('offline-only command sites', SOURCE.count("run_command('offline-badging'") == 1 and
      SOURCE.count("run_command('offline-signature'") == 1 and
      all(term not in SOURCE for term in ('curl', 'http.client', 'urllib', 'requests.', 'socket.', 'shell=True', 'adb ', 'hdc ', 'docker ', 'podman ')))
print('FIXTURE_PASS', len(checks), ','.join(checks))
