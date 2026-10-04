#!/usr/bin/env python3
"""Local v7 staging semantics; no SSH, runner, graph or device calls."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode=True
root=Path(__file__).resolve().parents[7]
sys.path.insert(0,str(root/'scripts'))
path=root/'scripts/nanhai_plus_stage_runner_v7_candidate_v3.py'
spec=importlib.util.spec_from_file_location('stage_v3',path)
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
checks={}
data=stage.source_bytes();binding=stage.authority()
checks['exact_v7_authority']=binding['config_sha256']==stage.ENV_CONFIG_SHA and binding['destination'].endswith('/control/nanhai_plus_native_graph_v7.py') and stage.digest(data)==stage.SOURCE_SHA and len(data)==41813

def run_local(program):
    return subprocess.run([sys.executable,'-B','-'],input=program.encode(),capture_output=True,check=False)

with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as td:
    work=Path(td);project=work/'project';control=project/'control';control.mkdir(parents=True)
    program=stage.remote_program(data,project=str(project));dest=control/stage.DEST_NAME
    first=run_local(program);one=json.loads(first.stdout)
    checks['create_readback_uid']=first.returncode==0 and one['status']=='CREATED_READBACK_VERIFIED' and one['row']['sha256']==stage.SOURCE_SHA and one['row']['bytes']==41813 and one['row']['mode']==0o444 and one['row']['uid']==stage.os.getuid() and dest.read_bytes()==data
    second=run_local(program);two=json.loads(second.stdout)
    checks['exact_existing_read_only']=second.returncode==0 and two['status']=='ALREADY_PRESENT_VERIFIED' and two['created'] is False
    dest.chmod(0o644);dest.write_bytes(b'changed')
    third=run_local(program);three=json.loads(third.stdout)
    checks['mismatch_preserved']=third.returncode==23 and three['state_uncertain'] is True and dest.read_bytes()==b'changed'
    dest.unlink()
    needle='stream.write(payload);stream.flush();os.fchmod(stream.fileno(),P[\'mode\']);os.fsync(stream.fileno())'
    assert program.count(needle)==1
    partial=run_local(program.replace(needle,"stream.write(payload[:10]);stream.flush();raise OSError('injected write failure')"))
    part=json.loads(partial.stdout)
    checks['partial_failure_preserved_for_reconcile']=partial.returncode==23 and part['state_uncertain'] is True and dest.read_bytes()==data[:10]
    dest.chmod(0o644);dest.unlink()
    needle='  os.fsync(directory)\n  check_chain(parts,parents)\n  read_fd=os.open(P[\'name\']'
    injected="  os.fsync(directory)\n  os.unlink(P['name'],dir_fd=directory)\n  replacement=os.open(P['name'],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=directory)\n  os.write(replacement,b'concurrent');os.close(replacement)\n  check_chain(parts,parents)\n  read_fd=os.open(P['name']"
    assert program.count(needle)==1
    swapped=run_local(program.replace(needle,injected));swap=json.loads(swapped.stdout)
    checks['concurrent_replacement_preserved']=swapped.returncode==23 and swap['state_uncertain'] is True and dest.read_bytes()==b'concurrent'
    dest.unlink();control.rmdir()
    elsewhere=work/'elsewhere';elsewhere.mkdir();control.symlink_to(elsewhere,target_is_directory=True)
    symlink=run_local(program);sym=json.loads(symlink.stdout)
    checks['symlink_control_rejected']=symlink.returncode==23 and sym['state_uncertain'] is True and not (elsewhere/stage.DEST_NAME).exists()
    release=work/'one_shot';release.mkdir();calls=[]
    remote={'schema':stage.REMOTE_SCHEMA,'remote_rc':0,'path':binding['destination'],
            'status':'CREATED_READBACK_VERIFIED','created':True,'state_uncertain':False,
            'row':{'sha256':stage.SOURCE_SHA,'bytes':stage.SOURCE_BYTES,'mode':stage.DEST_MODE,
                   'uid':stage.os.getuid(),'stable':True,'dev':1,'ino':2},
            'runner_executed':False,'graph_executed':False}
    def fake_transport(argv,program):
        calls.append(argv)
        assert (release/'UNKNOWN.json').is_file()
        return SimpleNamespace(returncode=0,stdout=json.dumps(remote).encode(),stderr=b'')
    with mock.patch.object(stage,'RELEASE_DIR',release):
        terminal=stage.stage_once(fake_transport)
        repeat=stage.stage_once(fake_transport)
    checks['durable_unknown_before_transport']=terminal['status']=='STAGED_HASH_VERIFIED_NOT_EXECUTED' and (release/'TERMINAL.json').is_file()
    checks['one_shot_rejects_retry']=repeat['status']=='FAIL_CLOSED_BEFORE_SSH' and len(calls)==1
    timeout_dir=work/'timeout';timeout_dir.mkdir()
    with mock.patch.object(stage,'RELEASE_DIR',timeout_dir):
        timeout=stage.stage_once(lambda argv,program:(_ for _ in ()).throw(TimeoutError('injected')))
    checks['timeout_unknown_requires_reconcile']=timeout['status']=='REMOTE_STATE_UNKNOWN_RECONCILE_READ_ONLY' and (timeout_dir/'UNKNOWN.json').is_file()
assert all(checks.values()),checks
print(json.dumps({'status':'LOCAL_FIXTURES_ONLY','checks':checks,'ssh_commands':0,'staging_commands':0,'runner_commands':0,'graph_commands':0,'device_commands':0},sort_keys=True))
