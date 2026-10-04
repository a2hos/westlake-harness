#!/usr/bin/env python3
"""G279 v2b candidate. One native private mihomo; loopback negative only.

DO NOT EXECUTE without an independent peer review and exact root release.
"""
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
UP = HERE.parent / 'g279-private-mihomo-v2a-syntax-candidate-v3'
UP_RUNNER_SHA = 'a17afa0de9b3efa68a7ba9601a6b6fa4dc71394d39cb76b4e803f1c5035da61c'
UP_ACCEPT_SHA = '6eb6519c08035d3511dbc482ad0ef89276924011580822132105a1f0ad1d7766'
UP_TERMINAL_SHA = '6c52be4ac3115d56716def80d958cbe3a41602a62f7dad0a45f2ce9adbcd563e'
PEER = HERE / 'peer-review-v1/REVIEW.json'
RELEASE = HERE / 'root-release-v1/ROOT-RELEASE.json'
START = HERE / 'START.json'
TERMINAL = HERE / 'TERMINAL.json'
POLICY = '(version 1)(allow default)(deny process-fork)'
PRIVATE_ROOT_SUFFIX = '.nanhai-plus-runtime/bionic-oh7-aosp16/proxy-pilot-g279-v2b-v3'
NEGATIVE_IP = '203.0.113.1'  # TEST-NET-3: must be rejected by MATCH,REJECT.
NEGATIVE_PORT = 9

def sha(b):
    return hashlib.sha256(b).hexdigest()

def load_upstream():
    p = UP / 'runner.py'
    if sha(p.read_bytes()) != UP_RUNNER_SHA:
        raise ValueError('upstream_runner_drift')
    spec = importlib.util.spec_from_file_location('g279_v2a_verified', p)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def accepted_upstream(up):
    a = up.stable_read(UP / 'ROOT-POSTRUN-ACCEPTANCE.json')
    t = up.stable_read(UP / 'TERMINAL.json')
    if sha(a) != UP_ACCEPT_SHA or sha(t) != UP_TERMINAL_SHA:
        raise ValueError('upstream_receipt_drift')
    x, y = json.loads(a), json.loads(t)
    if x.get('decision') != 'ACCEPT_BOUNDED_LOCAL_SYNTAX_ONLY' or x.get('terminal_sha256') != sha(t) or x.get('private_proxy_process_started') is not False or x.get('gz02_connected') is not False:
        raise ValueError('upstream_not_accepted')
    if y.get('decision') != 'GO_V2A_LOCAL_SYNTAX_ONLY' or y.get('syntax_rc') != 0 or y.get('private_dir_removed') is not True:
        raise ValueError('upstream_not_clean')
    return x, y

def exact_release(up):
    if START.exists() or TERMINAL.exists():
        raise ValueError('one_shot_consumed')
    peer_raw = up.stable_read(PEER)
    release_raw = up.stable_read(RELEASE)
    peer, release = json.loads(peer_raw), json.loads(release_raw)
    candidate_sha = up.file_sha(HERE / 'CANDIDATE.json')
    runner_sha = up.file_sha(pathlib.Path(__file__))
    wanted = {'schema','decision','candidate_sha256','runner_sha256','peer_review_sha256','upstream_postrun_sha256','upstream_terminal_sha256','source_sha256','binary_sha256','sandbox_sha256','sandbox_policy_sha256','port','scope','one_shot','no_gz02_ssh','no_graph','no_device','no_container','no_namespace','no_global_proxy_write'}
    if set(release) != wanted or release.get('schema') != 'g279-private-mihomo-v2b-root-release-v3' or release.get('decision') != 'ISSUE_EXACT_V2B_V3_LOCAL_TESTNET_REJECT_LOG_ONCE':
        raise ValueError('release_shape')
    if peer.get('decision') != 'GO_V2B_V3_CODE_ONLY' or peer.get('candidate_sha256') != candidate_sha or peer.get('runner_sha256') != runner_sha:
        raise ValueError('peer_gate')
    expected = {'candidate_sha256':candidate_sha,'runner_sha256':runner_sha,'peer_review_sha256':sha(peer_raw),'upstream_postrun_sha256':UP_ACCEPT_SHA,'upstream_terminal_sha256':UP_TERMINAL_SHA,'source_sha256':up.SOURCE_SHA,'binary_sha256':up.BIN_SHA,'sandbox_sha256':up.SANDBOX_SHA,'sandbox_policy_sha256':sha(POLICY.encode()),'scope':'private_native_local_listener_and_testnet_reject_log_only'}
    if any(release.get(k) != v for k,v in expected.items()) or any(release.get(k) is not True for k in ('one_shot','no_gz02_ssh','no_graph','no_device','no_container','no_namespace','no_global_proxy_write')):
        raise ValueError('release_binding')
    if type(release.get('port')) is not int or not 20000 <= release['port'] <= 60999:
        raise ValueError('release_port')
    return release, sha(release_raw)

def parse_lsof_fields(raw):
    """Parse -Fpcfn records; never infer address from human lsof table columns."""
    rows=[]; pid=None; fd=None
    for line in raw.splitlines():
        if not line:
            continue
        tag, value = line[:1], line[1:]
        if tag == 'p':
            if not value.isdecimal(): raise ValueError('lsof_pid')
            pid=int(value);fd=None
        elif tag == 'f':
            if pid is None or not value: raise ValueError('lsof_fd')
            fd=value
        elif tag == 'n':
            if pid is None or fd is None: raise ValueError('lsof_address_order')
            rows.append((pid,fd,value));fd=None
    return rows

def listener_rows(port):
    p=subprocess.run(['/usr/sbin/lsof','-nP','-iTCP:'+str(port),'-sTCP:LISTEN','-Fpcfn'],capture_output=True,text=True,timeout=4)
    if p.returncode not in (0,1) or p.stderr:
        raise ValueError('lsof_failed')
    rows=parse_lsof_fields(p.stdout)
    if p.returncode==1 and rows: raise ValueError('lsof_rc_shape')
    return rows

def listener_gate(port,pid):
    rows=listener_rows(port)
    if len(rows)!=1 or rows[0][0]!=pid or rows[0][2]!=f'127.0.0.1:{port}':
        raise ValueError('listener_owner_or_bind')
    return rows[0]

def process_gate(proc,up):
    if proc.poll() is not None or os.getpgid(proc.pid)!=proc.pid:
        raise ValueError('process_dead_or_group')
    raw=subprocess.check_output(['/bin/ps','-p',str(proc.pid),'-o','uid=','-o','pgid=','-o','command='],text=True,timeout=3).strip()
    parts=raw.split(None,2)
    if len(parts)!=3 or int(parts[0])!=os.getuid() or int(parts[1])!=proc.pid or str(up.BIN) not in parts[2]:
        raise ValueError('process_identity')
    if up.group_members(proc.pid)!=[proc.pid]:
        raise ValueError('unexpected_descendant')
    return True

def recv_exact(s,n):
    chunks=[];remaining=n
    while remaining:
        chunk=s.recv(remaining)
        if not chunk:raise ValueError('socks_reply_truncated')
        chunks.append(chunk);remaining-=len(chunk)
    return b''.join(chunks)

def complete_reply(s):
    head=recv_exact(s,4)
    if head[0]!=5 or head[2]!=0:raise ValueError('socks_reply_header')
    atyp=head[3]
    if atyp==1: address=recv_exact(s,4)
    elif atyp==4: address=recv_exact(s,16)
    elif atyp==3:
        length=recv_exact(s,1)[0]
        if length==0:raise ValueError('socks_reply_domain_length')
        address=bytes([length])+recv_exact(s,length)
    else:raise ValueError('socks_reply_atyp')
    return head+address+recv_exact(s,2)

def socks_negative(port):
    # Never request gz02, its neighbor, or another real destination.
    with socket.create_connection(('127.0.0.1',port),timeout=3) as s:
        s.settimeout(3)
        s.sendall(b'\x05\x01\x00')
        if recv_exact(s,2)!=b'\x05\x00': raise ValueError('socks_handshake')
        request=b'\x05\x01\x00\x01'+socket.inet_aton(NEGATIVE_IP)+NEGATIVE_PORT.to_bytes(2,'big')
        s.sendall(request)
        reply=complete_reply(s)
        # This bundled Mihomo emits a complete REP=0 before MATCH,REJECT
        # closes the stream in a credential-free mock. That is NOT a route
        # proof for a real node. Only record bounded connection closure.
        if len(reply)!=10 or reply[:4]!=b'\x05\x00\x00\x01' or reply[4:8]!=socket.inet_aton('127.0.0.1') or int.from_bytes(reply[8:10],'big')==0:
            raise ValueError('testnet_reply_not_mock_shape')
        try:post=s.recv(1)
        except socket.timeout as e:raise ValueError('testnet_not_closed') from e
        if post!=b'':raise ValueError('testnet_data_after_reply')
        return {'testnet_target':NEGATIVE_IP,'socks_reply_hex':reply.hex(),'connection_closed':True,'route_reject_proven':False,'oracle':'exact_binary_mock_connection_closure_only'}

def cleaned_stop(proc,up):
    if proc is None:return True
    # Seatbelt fork denial is separately tested; group check still fails closed.
    return up.stop_group(proc)

def normalized_route_event(logs):
    """A complete whitelisted line only; other TCP route lines are ambiguous."""
    lines=[line for line in logs.splitlines() if b'[TCP]' in line and b' --> ' in line]
    if len(lines)!=1:raise ValueError('route_line_missing_or_ambiguous')
    line=lines[0]
    pattern=(rb'time="[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{1,9}'
             rb'(?:Z|[+-][0-9]{2}:[0-9]{2})" level=info msg="\[TCP\] 127\.0\.0\.1:([0-9]{1,5})'
             rb' --> 203\.0\.113\.1:9 match Match using REJECT"')
    match=re.fullmatch(pattern,line)
    if match is None:raise ValueError('route_line_not_exact_whitelist')
    port=int(match.group(1))
    if not 1024<=port<=65535:raise ValueError('source_port_not_ephemeral')
    event={'schema':'g279-v2b-v3-normalized-route-event','source_ip':'127.0.0.1','source_port':port,
           'target_ip':'203.0.113.1','target_port':9,'rule':'Match','action':'REJECT',
           'raw_line_sha256':sha(line)}
    event_sha=sha(json.dumps(event,sort_keys=True,separators=(',',':')).encode())
    return event,event_sha

class InstanceFailure(Exception):
    def __init__(self,clean):
        super().__init__('instance_failed')
        self.clean=clean

def run_instance(d,port,up):
    env={**os.environ,'HOME':str(d),'XDG_CONFIG_HOME':str(d),'XDG_CACHE_HOME':str(d),'TMPDIR':str(d)}
    for k in list(env):
        if 'proxy' in k.lower():env.pop(k)
    cmd=[str(up.SANDBOX),'-p',POLICY,str(up.BIN),'-d',str(d),'-f',str(d/'private.yaml')]
    out=d/'mihomo-stdout.raw';err=d/'mihomo-stderr.raw'
    fo=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    fe=os.open(err,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    proc=None;result=None;group_clean=False;failure=None
    try:
        proc=subprocess.Popen(cmd,cwd=up.ROOT,env=env,stdout=fo,stderr=fe,start_new_session=True)
        for _ in range(40):
            if proc.poll() is not None:raise ValueError('mihomo_exited')
            rows=listener_rows(port)
            if rows:
                process_gate(proc,up);listener_gate(port,proc.pid)
                break
            time.sleep(.1)
        else:raise ValueError('listener_timeout')
        before=up.file_sha(d/'private.yaml')
        result=socks_negative(port)
        time.sleep(.1)  # Let the private debug route event reach its raw log.
        process_gate(proc,up);listener_gate(port,proc.pid)
        if up.file_sha(d/'private.yaml')!=before:raise ValueError('config_changed_while_running')
        result.update({'listener_pid_matches_process':True,'loopback_only':True,'config_sha256':before})
    except BaseException as e:
        failure=e
    finally:
        os.close(fo);os.close(fe)
        group_clean=cleaned_stop(proc,up)
    if not group_clean:raise InstanceFailure(False) from failure
    if listener_rows(port):raise InstanceFailure(False) from failure
    if failure is not None:raise InstanceFailure(True) from failure
    logs=out.read_bytes()+b'\n'+err.read_bytes()
    # Exact binary mock independently showed REP=0+EOF for MATCH,REJECT.
    # The route event, not the SOCKS reply, is the rule-selection oracle.
    try:event,event_sha=normalized_route_event(logs)
    except ValueError as e:raise InstanceFailure(True) from e
    result['route_reject_proven']=True
    result['normalized_route_event']=event
    result['route_event_sha256']=event_sha
    return result,{'stdout_sha256':up.file_sha(out),'stderr_sha256':up.file_sha(err),'stdout_bytes':out.stat().st_size,'stderr_bytes':err.stat().st_size,'process_group_clean':True}

def execute():
    up=load_upstream();accepted_upstream(up);release,release_sha=exact_release(up)
    token=secrets.token_hex(16)
    up.json_once(START,{'schema':'g279-private-v2b-start-v3','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'nonce':token,'release_sha256':release_sha,'runner_sha256':up.file_sha(pathlib.Path(__file__)),'upstream_postrun_sha256':UP_ACCEPT_SHA,'scope':'local_private_native_testnet_reject_log_only'})
    d=None;stage='binary';decision='NO_GO';negative=None;logs=None;config_sha=None;cleanup_ok=False;process_clean=True
    try:
        if up.file_sha(up.BIN)!=up.BIN_SHA or up.file_sha(up.SANDBOX)!=up.SANDBOX_SHA:raise ValueError('binary_drift')
        # This policy allows local/native sockets and the selected node but forbids
        # fork/exec escape. Local no-credential probe is mandatory before secret write.
        stage='fork_denial'
        for code in ('import os; p=os.fork();\nif p==0:\n os.setsid(); print("ESCAPED",flush=True); os._exit(0)\nos.waitpid(p,0)',"import os,sys; os.posix_spawn(sys.executable,[sys.executable,'-c','print(12345)'],os.environ)"):
            p=subprocess.run([str(up.SANDBOX),'-p',POLICY,sys.executable,'-I','-B','-c',code],capture_output=True,timeout=5)
            if p.returncode==0 or b'Operation not permitted' not in p.stderr:raise ValueError('fork_denial_not_proven')
        stage='source'
        raw=up.stable_read(up.SOURCE)
        if sha(raw)!=up.SOURCE_SHA:raise ValueError('source_drift')
        pid=up.active_process();x=up.yaml.safe_load(raw);nodes,groups=up.source_structure(x)
        stage='controller_leaf'
        sockid=up.verify_socket_path(pathlib.Path(x.get('external-controller-unix') or ''))
        leaf=up.current_leaf(x,pid,nodes,groups);up.selected_node_schema(nodes[leaf])
        stage='port_preflight'
        if listener_rows(release['port']):raise ValueError('port_occupied')
        stage='private_config'
        up.PRIVATE_ROOT=up.ROOT/PRIVATE_ROOT_SUFFIX
        d=up.private_dir(token)
        node=up.fresh_selected_node(pid,sockid,leaf)
        config=up.minimal_config(node,release['port']);up.config_gate(config)
        config['log-level']='debug'  # 0600 private log; route event only leaves as SHA.
        b=up.yaml.safe_dump(config,sort_keys=False,allow_unicode=True).encode()
        up.write_once(d/'private.yaml',b,0o600)
        if stat.S_IMODE((d/'private.yaml').stat().st_mode)!=0o600 or up.file_sha(d/'private.yaml')!=sha(b):raise ValueError('config_readback')
        config_sha=sha(b)
        stage='private_listener_and_negative'
        process_clean=False
        negative,logs=run_instance(d,release['port'],up)
        process_clean=True
        decision='GO_V2B_LOCAL_TESTNET_REJECT_LOG_ONLY'
    except BaseException as e:
        if isinstance(e,InstanceFailure):process_clean=e.clean
        decision='NO_GO_'+stage.upper();failure_class=type(e).__name__
    finally:
        if process_clean:
            try:cleanup_ok=up.cleanup(d)
            except BaseException:cleanup_ok=False
            if not cleanup_ok:decision='NO_GO_CLEANUP'
        else:decision='NO_GO_PROCESS_UNPROVEN_PRIVATE_RETAINED'
        terminal={'schema':'g279-private-v2b-terminal-v3','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'nonce':token,'decision':decision,'failed_stage':None if decision=='GO_V2B_LOCAL_TESTNET_REJECT_LOG_ONLY' else stage,'failure_class':None if decision=='GO_V2B_LOCAL_TESTNET_REJECT_LOG_ONLY' else locals().get('failure_class'),'release_sha256':release_sha,'upstream_postrun_sha256':UP_ACCEPT_SHA,'config_sha256':config_sha,'negative':negative,'private_log_metadata':logs,'process_group_clean':process_clean,'private_dir_removed':cleanup_ok,'gz02_ssh_commands':0,'graph_commands':0,'device_commands':0,'container_commands':0,'namespace_commands':0,'global_proxy_writes':0,'startup_delta':0}
        up.json_once(TERMINAL,terminal)
    print(json.dumps({'decision':decision,'terminal_sha256':up.file_sha(TERMINAL),'nonce':token}))
    return 0 if decision=='GO_V2B_LOCAL_TESTNET_REJECT_LOG_ONLY' else 2

if __name__=='__main__':
    if sys.argv[1:]!=['--execute']:
        raise SystemExit('usage: runner.py --execute')
    try:sys.exit(execute())
    except BaseException as e:
        print(json.dumps({'decision':'NO_GO_BEFORE_START','failure_class':type(e).__name__}))
        sys.exit(2)
