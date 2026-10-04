#!/usr/bin/env python3
"""Local parser-contract replay only; imports runners but never calls their main()."""
import importlib.util
import json
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001'

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

start = time.monotonic()
v2 = load('element_v2', BASE/'apk-arm64-next-vector-v2/run.py')
v3 = load('element_v3', BASE/'apk-arm64-next-vector-v3/run.py')
real = (BASE/'apk-arm64-next-vector-v2/runtime-badging.stdout.raw').read_text(errors='replace')
minimal = "package: name='im.vector.app' versionCode='40106622' versionName='1.6.62'\nnative-code: 'arm64-v8a'\n"
suffix = " platformBuildVersionName='15' platformBuildVersionCode='35' compileSdkVersion='35' compileSdkVersionCodename='15'"
adversarial = minimal.replace("versionName='1.6.62'", "versionName='1.6.62'"+suffix)

def accept(fn, text):
    try:
        fn(text)
        return True
    except RuntimeError:
        return False

rows = {
    'v2_minimal_accept': accept(v2.identity, minimal),
    'v2_suffix_accept': accept(v2.identity, adversarial),
    'v2_actual_accept': accept(v2.identity, real),
    'v3_suffix_accept': accept(v3.parse_badging, adversarial),
    'v3_actual_accept': accept(v3.parse_badging, real),
    'verbatim_actual_package_line': real.splitlines()[0],
}
ok = rows['v2_minimal_accept'] and not rows['v2_suffix_accept'] and not rows['v2_actual_accept'] and rows['v3_suffix_accept'] and rows['v3_actual_accept']
print(json.dumps({'schema':'nanhai.evo24.local_pilot.v1','status':'PASS' if ok else 'FAIL','rc':0 if ok else 2,'seconds':round(time.monotonic()-start,6),'rows':rows,'network_requests':0,'device_commands':0,'container_commands':0,'canonical_count_delta':0},sort_keys=True))
raise SystemExit(0 if ok else 2)
