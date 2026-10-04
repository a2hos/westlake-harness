#!/usr/bin/env python3
"""Local synthetic release packets only; never call Soong or a remote host."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from unittest import mock

sys.dont_write_bytecode=True
root=Path(__file__).resolve().parents[7]
source=root/'scripts/nanhai_plus_native_graph_v7.py'
spec=importlib.util.spec_from_file_location('graph_v7',source)
graph=importlib.util.module_from_spec(spec);spec.loader.exec_module(graph)
checks={}
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def write444(path,obj):
    if path.exists():path.chmod(0o644)
    path.write_text(json.dumps(obj,sort_keys=True)+'\n')
    path.chmod(0o444)
def rejects(control,runner):
    try:graph.validate_release_packet(control,runner)
    except (ValueError, OSError, KeyError, TypeError):return True
    return False
with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as td:
    control=Path(td)/'project/control';control.mkdir(parents=True)
    runner=control/'nanhai_plus_native_graph_v7.py';shutil.copyfile(source,runner);runner.chmod(0o444)
    gate_path=control/'g279-native-graph-v7-EVO19-GATE.json'
    outer_path=control/'g279-native-graph-v7-outer-release.json'
    owner_path=control/'g279-native-graph-v7-owner-ack.json'
    rows=[{'name':'runner','path':str(runner),'sha256':digest(runner),'bytes':runner.stat().st_size,'mode':0o444}]
    rows += [{'name':name,'path':path,'sha256':sha,'bytes':8020928 if name=='interpreter' else 1,
              'mode':0o755 if name=='interpreter' else 0o444}
             for name,(path,sha) in sorted(graph.pinned_remote(control.parent).items())]
    gate={'status':'STATIC_PREFLIGHT_MATCH_UNRELEASED','outer_ssh_rc':0,'remote_rc':0,
          'remote_host':'gz02','env_config_sha256':graph.CONFIG_SHA,'local_env_sha256':'a'*64,
          'remote_interpreter':'/usr/bin/python3.12',
          'intended_remote_argv':['/usr/bin/python3.12','-B',str(runner),'--run'],
          'wrapper':{'path':'/reviewed/wrapper','sha256':'b'*64,'bytes':1,'mode':0o444},
          'expected_wrapper':{'path':'/reviewed/wrapper','sha256':'b'*64,'bytes':1,'mode':0o444},
          'spec_sha256':'c'*64,'remote_probe_sha256':'d'*64,
          'graph_executed':False,'target_compiled':False,
          'expected_remote_inputs':rows,'remote_rows':[dict(row,stable=True,match=True) for row in rows]}
    outer={'schema':'nanhai-g279-graph-v7-outer-release-v1','run_id':graph.RELEASE_RUN_ID,
           'goal_id':'goal_01','claim':'NP-MUSL16-ART-024','host':'gz02',
           'runner_path':str(runner),'runner_sha256':digest(runner),'runner_bytes':runner.stat().st_size,
           'runner_mode':0o444,'env_config_sha256':graph.CONFIG_SHA,'binding_sha256':graph.BINDING_SHA,
           'local_env_sha256':'a'*64,'evo19_gate_sha256':'',
           'evo19_wrapper_sha256':'b'*64,'evo19_spec_sha256':'c'*64,
           'intended_remote_argv':['/usr/bin/python3.12','-B',str(runner),'--run'],
           'graph_only':True,'target_compile_authorized':False,'device_authorized':False}
    owner={'schema':'nanhai-g279-graph-v7-original-owner-ack-v1','run_id':graph.RELEASE_RUN_ID,
           'goal_id':'goal_01','claim':'NP-MUSL16-ART-024','runner_sha256':digest(runner),
           'outer_release_sha256':'','graph_only_ack':True,'target_compile_ack':False}
    def commit():
        write444(gate_path,gate);outer['evo19_gate_sha256']=digest(gate_path)
        write444(outer_path,outer);owner['outer_release_sha256']=digest(outer_path)
        write444(owner_path,owner)
    commit()
    accepted=graph.validate_release_packet(control,runner)
    checks['three_frozen_documents_bind']=accepted['graph_only'] is True and accepted['runner_sha256']==digest(runner)
    owner['graph_only_ack']=False;write444(owner_path,owner)
    checks['owner_ack_required']=rejects(control,runner)
    owner['graph_only_ack']=True;commit()
    gate['outer_ssh_rc']=255;commit()
    checks['evo19_outer_ssh_rc_required']=rejects(control,runner)
    gate['outer_ssh_rc']=0;commit()
    outer['target_compile_authorized']=True;write444(outer_path,outer)
    checks['target_compile_release_rejected']=rejects(control,runner)
    outer['target_compile_authorized']=False;commit()
    runner.chmod(0o644);runner.write_bytes(b'tampered');runner.chmod(0o444)
    checks['runner_byte_drift_rejected']=rejects(control,runner)
    # Main dispatch is mocked: proves gate calls graph path without running it.
    called=[]
    with mock.patch.object(graph,'release_gate',return_value={'graph_only':True}), \
         mock.patch.object(graph,'reviewed_execution_candidate',side_effect=lambda release:called.append(release) or 42), \
         mock.patch.object(sys,'argv',['graph_v7.py','--run']):
        result=graph.main()
    checks['run_routes_only_after_gate']=result==42 and len(called)==1
    called.clear()
    with mock.patch.object(graph,'release_gate',side_effect=ValueError('gate missing')), \
         mock.patch.object(graph,'reviewed_execution_candidate',side_effect=lambda release:called.append(release)), \
         mock.patch.object(sys,'argv',['graph_v7.py','--run']):
        result=graph.main()
    checks['gate_failure_no_graph_call']=result==3 and not called
assert all(checks.values()),checks
print(json.dumps({'status':'LOCAL_SYNTHETIC_FIXTURES_ONLY','checks':checks,
                  'ssh_commands':0,'graph_commands':0,'target_compiles':0,'device_commands':0},sort_keys=True))
