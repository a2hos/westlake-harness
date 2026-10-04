#!/usr/bin/env python3
"""Local-only fault fixtures for dormant v5 helpers; never starts a graph."""
import importlib.util
import json
from pathlib import Path
import signal
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
script = Path(__file__).resolve().parents[7] / 'scripts/nanhai_plus_native_graph_v5.py'
spec = importlib.util.spec_from_file_location('nanhai_native_v4', script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
checks = {}

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    receipt = module.write_once(root, 'RESULT.json', {'status': 'failed-preflight'})
    original = module.digest(receipt)
    try:
        module.write_once(root, 'RESULT.json', {'status': 'rewritten'})
    except FileExistsError:
        checks['immutable_receipt_excl'] = module.digest(receipt) == original
    else:
        checks['immutable_receipt_excl'] = False

    out = root / 'out'
    (out / 'soong').mkdir(parents=True)
    (out / '.module_paths').mkdir()
    ninja = out / 'soong/build.aosp_arm64.ninja'
    bp = out / '.module_paths/Android.bp.list'
    ninja.write_text('rule inert\n  command = true\n')
    bp.write_text('Android.bp\n')
    positive = module.graph_artifact_audit({'out': out, 'source': root}, [])
    checks['exact_artifact_positive_fixture'] = bool(positive['graph_evidence_pass'])
    checks['no_target_authorization'] = (positive['generated_action_audit_status'] ==
                                         'LEXICAL_SCREEN_ONLY_NO_TARGET_AUTHORIZATION' and
                                         positive['target_ninja_execution_authorized'] is False)
    ninja.rename(out / 'soong/build.other_product.ninja')
    negative = module.graph_artifact_audit({'out': out, 'source': root}, [])
    checks['wrong_product_artifact_rejected'] = negative['graph_evidence_pass'] is False

    argv, environment = module.graph_command({'source': root, 'goroot': root / 'prebuilts/go/linux-x86',
                                              'tmp': root / 'tmp', 'out': out, 'ui': root / 'soong_ui',
                                              'guard': root / 'no-namespace-exec'})
    checks['goroot_explicit_binding'] = (environment.get('GOROOT') == str(root / 'prebuilts/go/linux-x86') and
                                        ('GOROOT=' + environment['GOROOT']) in argv)

    control = root / 'control'
    control.mkdir()
    before_term = signal.getsignal(signal.SIGTERM)
    before_int = signal.getsignal(signal.SIGINT)
    for signum, label in ((signal.SIGTERM, 'sigterm'), (signal.SIGINT, 'sigint')):
        def fake_wait(timeout):
            signal.raise_signal(signum)
        child = SimpleNamespace(pid=999999, wait=fake_wait, returncode=None)
        with mock.patch.object(module.ctypes, 'CDLL', return_value=SimpleNamespace(prctl=lambda *args: 0)), \
             mock.patch.object(module, 'graph_command', return_value=(['inert-not-executed'], {})), \
             mock.patch.object(module.subprocess, 'Popen', return_value=child), \
             mock.patch.object(module, 'reap_tree', return_value={'remaining': [], 'terminated': [999999], 'process_returncode': None}) as cleanup:
            result = module.execute_graph_candidate({'control': control, 'source': root,
                                                     'source_alias': root, 'out': out})
        checks[label + '_calls_cleanup'] = (result['cancelled_signal'] == signum and
                                            result['process_tree_clear'] and cleanup.call_count == 1)
    checks['signal_handlers_restored'] = (signal.getsignal(signal.SIGTERM) == before_term and
                                          signal.getsignal(signal.SIGINT) == before_int)

assert all(checks.values()), checks
print(json.dumps({'status': 'LOCAL_FIXTURES_ONLY', 'checks': checks,
                  'graph_commands': 0, 'remote_commands': 0, 'device_commands': 0,
                  'limits': 'Mocked signal and cleanup; no real detached descendant or seccomp inheritance proof'},
                 sort_keys=True))
