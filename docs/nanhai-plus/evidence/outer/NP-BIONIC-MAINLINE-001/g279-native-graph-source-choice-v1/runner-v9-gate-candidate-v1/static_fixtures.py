#!/usr/bin/env python3
"""Injected transport only; no SSH or graph execution."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode=True
root=Path(__file__).resolve().parents[7]
path=root/'scripts/nanhai_plus_native_graph_v9_gate.py'
spec=importlib.util.spec_from_file_location('v9_gate',path)
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
checks={}
ssh=gate.identity(gate.HOST_SSH)
checks['host_ssh_exact']=(ssh['path'],ssh['sha256'],ssh['bytes'],ssh['mode'])==(str(gate.HOST_SSH),gate.HOST_SSH_SHA,gate.HOST_SSH_BYTES,gate.HOST_SSH_MODE)
rows=[{'name':name,'path':str(value[0]),'sha256':value[1],
       'bytes':gate.RUNNER_BYTES if name=='runner' else gate.INTERPRETER_BYTES if name=='interpreter' else 1,
       'mode':gate.RUNNER_MODE if name=='runner' else gate.INTERPRETER_MODE if name=='interpreter' else 0o444}
      for name,value in sorted(gate.REMOTE_FILES.items())]
base={'schema':gate.SCHEMA,'goal_id':'goal_01','claim':'NP-MUSL16-ART-024',
      'env_config_sha256':gate.CONFIG_SHA,'local_env_sha256':'a'*64,
      'wrapper':gate.identity(path),'remote_host':'gz02','remote_interpreter':gate.INTERPRETER,
      'remote_inputs':rows,'intended_remote_argv':[gate.INTERPRETER,'-B',str(gate.REMOTE_FILES['runner'][0]),'--run'],
      'receipt_path':str(gate.RECEIPT_ROOT/'EVO19-GATE.json')}
gate.validate_spec(base)
checks['v7_exact_spec_accepted_locally']=True
def rejects(spec):
    try:gate.validate_spec(spec)
    except ValueError:return True
    return False
v6=copy.deepcopy(base)
next(row for row in v6['remote_inputs'] if row['name']=='runner')['path']=str(gate.REMOTE_PROJECT/'control/nanhai_plus_native_graph_v6.py')
v6['intended_remote_argv'][2]=str(gate.REMOTE_PROJECT/'control/nanhai_plus_native_graph_v6.py')
checks['v6_runner_rejected']=rejects(v6)
size=copy.deepcopy(base)
next(row for row in size['remote_inputs'] if row['name']=='runner')['bytes']-=1
checks['v7_size_rejected']=rejects(size)
inject=copy.deepcopy(base);inject['remote_interpreter']='/usr/bin/python3.12; false #'
inject['intended_remote_argv'][0]=inject['remote_interpreter']
next(row for row in inject['remote_inputs'] if row['name']=='interpreter')['path']=inject['remote_interpreter']
checks['shell_interpreter_rejected']=rejects(inject)
program=gate.remote_probe_program(rows);ast.parse(program)
checks['full_remote_fd_readback']=all(token in program for token in ('dir_fd=fds[-1]','os.O_NOFOLLOW','st_ctime_ns','st_mode'))
remote={'schema':'nanhai-g279-remote-input-readback-v2','remote_rc':0,
        'rows':[dict(row,stable=True,match=True) for row in rows]}
calls=[]
def transport(argv,program):
    calls.append(argv)
    return SimpleNamespace(returncode=0,stdout=json.dumps(remote).encode(),stderr=b'')
result=gate.evaluate(base,transport,local_wrapper=path,local_env_sha256='a'*64,local_config_sha256=gate.CONFIG_SHA)
checks['injected_readback_only']=result['status']=='STATIC_PREFLIGHT_MATCH_UNRELEASED' and result['outer_ssh_rc']==0 and result['remote_rc']==0 and calls==[gate.SSH_ARGV]
remote['rows'][0]['sha256']='0'*64
bad=gate.evaluate(base,transport,local_wrapper=path,local_env_sha256='a'*64,local_config_sha256=gate.CONFIG_SHA)
checks['remote_byte_drift_rejected']=bad['status']=='FAIL_CLOSED'
calls.clear()
with mock.patch.object(gate,'HOST_SSH_SHA','0'*64):
    stopped=gate.evaluate(base,transport,local_wrapper=path,local_env_sha256='a'*64,local_config_sha256=gate.CONFIG_SHA)
checks['host_ssh_drift_pre_transport']=stopped['status']=='FAIL_CLOSED' and not calls
with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as td:
    destination=Path(td)/'EVO19-GATE.json'
    with mock.patch.object(gate.os,'fsync',side_effect=OSError('injected fsync failure')):
        try:gate.atomic_receipt(destination,{'status':'STATIC_PREFLIGHT_MATCH_UNRELEASED'})
        except OSError:pass
    checks['receipt_failure_no_path_cleanup']=destination.is_file() and not any(Path(td).glob('*.partial-*'))
assert all(checks.values()),checks
print(json.dumps({'status':'LOCAL_STATIC_FIXTURES_ONLY','checks':checks,
                  'ssh_commands':0,'graph_commands':0,'device_commands':0},sort_keys=True))
