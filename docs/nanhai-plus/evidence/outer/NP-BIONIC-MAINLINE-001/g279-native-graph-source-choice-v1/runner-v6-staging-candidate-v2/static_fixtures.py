#!/usr/bin/env python3
"""Bounded local-only v2 staging semantics; no SSH or runner execution."""
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
path=root/'scripts/nanhai_plus_stage_runner_v6_candidate_v2.py'
spec=importlib.util.spec_from_file_location('stage_v2',path)
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
checks={}
data=stage.source_bytes();binding=stage.authority()
checks['authority_exact']=binding['config_sha256']==stage.ENV_CONFIG_SHA and binding['destination']==stage.PROJECT+'/control/'+stage.DEST_NAME

def run_local(program):
    return subprocess.run([sys.executable,'-B','-'],input=program.encode(),capture_output=True,check=False)

with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as td:
    work=Path(td)
    project=work/'project';control=project/'control';control.mkdir(parents=True)
    program=stage.remote_program(data,project=str(project))
    first=run_local(program);one=json.loads(first.stdout)
    dest=control/stage.DEST_NAME
    checks['create_uid_chain_readback']=first.returncode==0 and one['remote_rc']==0 and one['status']=='CREATED_READBACK_VERIFIED' and one['row']['uid']==stage.os.getuid() and one['row']['sha256']==stage.SOURCE_SHA and dest.read_bytes()==data
    second=run_local(program);two=json.loads(second.stdout)
    checks['exact_existing_idempotent']=second.returncode==0 and two['status']=='ALREADY_PRESENT_VERIFIED' and two['created'] is False
    dest.chmod(0o644);dest.write_bytes(b'changed')
    third=run_local(program);three=json.loads(third.stdout)
    checks['mismatch_no_overwrite']=third.returncode==23 and three['status']=='FAIL_CLOSED_RECONCILE_READ_ONLY' and dest.read_bytes()==b'changed'
    dest.unlink()
    # Swap another inode into the final name after link. Cleanup must preserve it.
    needle="   os.fsync(directory)\n   check_chain(parts,parents)\n   fd=os.open(P['name']"
    injected="   os.fsync(directory)\n   os.unlink(P['name'],dir_fd=directory)\n   replacement=os.open(P['name'],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=directory)\n   os.write(replacement,b'concurrent');os.close(replacement)\n   check_chain(parts,parents)\n   fd=os.open(P['name']"
    assert program.count(needle)==1
    fourth=run_local(program.replace(needle,injected))
    four=json.loads(fourth.stdout)
    checks['concurrent_replacement_not_deleted']=fourth.returncode==23 and four['state_uncertain'] is True and dest.read_bytes()==b'concurrent'
    dest.unlink();control.rmdir()
    elsewhere=work/'elsewhere';elsewhere.mkdir();control.symlink_to(elsewhere,target_is_directory=True)
    fifth=run_local(program);five=json.loads(fifth.stdout)
    checks['symlink_control_rejected']=fifth.returncode==23 and not (elsewhere/stage.DEST_NAME).exists()
    # The durable UNKNOWN receipt exists when injected transport is entered.
    release=work/'one_shot';release.mkdir()
    calls=[]
    remote={'schema':stage.REMOTE_SCHEMA,'remote_rc':0,'path':binding['destination'],
            'status':'CREATED_READBACK_VERIFIED','created':True,'state_uncertain':False,
            'row':{'sha256':stage.SOURCE_SHA,'bytes':stage.SOURCE_BYTES,'mode':stage.DEST_MODE,
                   'uid':stage.os.getuid(),'stable':True,'dev':1,'ino':2},
            'runner_executed':False,'graph_executed':False}
    def transport(argv,program):
        calls.append(argv)
        assert (release/'UNKNOWN.json').is_file()
        assert not (release/'TERMINAL.json').exists()
        return SimpleNamespace(returncode=0,stdout=json.dumps(remote).encode(),stderr=b'')
    with mock.patch.object(stage,'RELEASE_DIR',release):
        result=stage.stage_once(transport)
    checks['unknown_before_transport_terminal_after']=result['status']=='STAGED_HASH_VERIFIED_NOT_EXECUTED' and len(calls)==1 and (release/'TERMINAL.json').is_file()
    with mock.patch.object(stage,'RELEASE_DIR',release):
        repeat=stage.stage_once(transport)
    checks['one_shot_no_retry']=repeat['status']=='FAIL_CLOSED_BEFORE_SSH' and len(calls)==1
    blocked=work/'timeout';blocked.mkdir()
    def timeout(argv,program):
        assert (blocked/'UNKNOWN.json').is_file()
        raise TimeoutError('injected')
    with mock.patch.object(stage,'RELEASE_DIR',blocked):
        uncertain=stage.stage_once(timeout)
    checks['timeout_durable_unknown']=uncertain['status']=='REMOTE_STATE_UNKNOWN_RECONCILE_READ_ONLY' and json.loads((blocked/'TERMINAL.json').read_text())['status']=='REMOTE_STATE_UNKNOWN_RECONCILE_READ_ONLY'
    no_term=work/'no_terminal';no_term.mkdir()
    original=stage.exclusive_json
    def fail_terminal(directory,name,body):
        if name=='TERMINAL.json':raise OSError('injected terminal write failure')
        return original(directory,name,body)
    with mock.patch.object(stage,'exclusive_json',side_effect=fail_terminal), mock.patch.object(stage,'RELEASE_DIR',no_term):
        missing=stage.stage_once(transport)
    checks['terminal_failure_unknown_persists']=missing['status']=='REMOTE_STATE_UNKNOWN_NO_TERMINAL_RECEIPT' and (no_term/'UNKNOWN.json').is_file() and not (no_term/'TERMINAL.json').exists()
assert all(checks.values()),checks
print(json.dumps({'status':'LOCAL_FIXTURES_ONLY','checks':checks,'ssh_commands':0,'staging_commands':0,'runner_commands':0,'graph_commands':0,'device_commands':0},sort_keys=True))
