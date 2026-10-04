#!/usr/bin/env python3
"""G279 v2c v3 candidate: bounded, replayable failure diagnostics.

DO NOT EXECUTE without an independent peer review and exact root release.
"""
import datetime
import base64
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
V2B = HERE.parent / 'g279-private-mihomo-v2b-local-candidate-v4'
V2B_ROOT_SHA = '369462a2e1b4d051739ce3347b3bbb0af25eafa74f7f23f1044d66fc957e5030'
V2B_TERMINAL_SHA = '7dac082c049a4db44e68e558f87d349e7ff7f198a5a34687c33bbcd0e51e24b0'
V2 = HERE.parent / 'g279-private-mihomo-v2c-gz02-candidate-v2'
V2_TERMINAL_SHA = '88010674dcfba761b3e816383fc35effbd3e45adfc482782241abca5230968e7'
V2_POSTRUN_PEER_SHA = '3010164a188ddeb11c26211f3cd41861230a2a883011685842bc55c70ab19362'
V2_ROOT_NOGO_SHA = '9409e940333c50b2e6d700c7ced33f172a860bc75a53d88c89a85b035824879d'
UP = HERE.parent / 'g279-private-mihomo-v2a-syntax-candidate-v3'
UP_RUNNER_SHA = 'a17afa0de9b3efa68a7ba9601a6b6fa4dc71394d39cb76b4e803f1c5035da61c'
UP_ACCEPT_SHA = '6eb6519c08035d3511dbc482ad0ef89276924011580822132105a1f0ad1d7766'
UP_TERMINAL_SHA = '6c52be4ac3115d56716def80d958cbe3a41602a62f7dad0a45f2ce9adbcd563e'
PEER = HERE / 'peer-review-v3/REVIEW.json'
RELEASE = HERE / 'root-release-v3/ROOT-RELEASE.json'
START = HERE / 'START.json'
TERMINAL = HERE / 'TERMINAL.json'
POLICY = '(version 1)(allow default)(deny process-fork)'
PRIVATE_ROOT_SUFFIX = '.nanhai-plus-runtime/bionic-oh7-aosp16/proxy-pilot-g279-v2c-v3'
SAFE_NODE_ALIAS = 'g279-v2c-selected'
NEGATIVE_IP = '203.0.113.1'  # TEST-NET-3: must be rejected by MATCH,REJECT.
NEGATIVE_PORT = 9
TARGET_IP = '1.95.90.207'
TARGET_PORT = 58222
HOST_ALIAS = '[1.95.90.207]:58222'
HOST_FP = 'SHA256:RuAqHWgFJEIEcb4hC+WXULCRfV3uCsayP4Iw4aJvwzg'
SSH_SHA = '17542914a3fb55e7efeb35a90d594a21c84bf6a4cfe1fc8ddff5606dc2658fc3'
NC_SHA = '5735aaf2f80ffa7f28a8026f1fae6cffd6673d578c5618e302d8b591ad5c12c5'

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

def accepted_v2b(up):
    root_raw=up.stable_read(V2B/'ROOT-POSTRUN-ACCEPTANCE.json')
    term_raw=up.stable_read(V2B/'TERMINAL.json')
    if sha(root_raw)!=V2B_ROOT_SHA or sha(term_raw)!=V2B_TERMINAL_SHA:
        raise ValueError('v2b_fact_chain_drift')
    root,term=json.loads(root_raw),json.loads(term_raw)
    if root.get('decision')!='ACCEPT_BOUNDED_LOCAL_REJECT_FACTS_NOT_COMMAND_PASS' or \
       root.get('terminal_sha256')!=V2B_TERMINAL_SHA or \
       root.get('command_pass') is not False or \
       root.get('replay_allowed') is not False or \
       term.get('decision')!='GO_V2B_LOCAL_TESTNET_REJECT_LOG_ONLY' or \
       term.get('private_dir_removed') is not True or \
       term.get('gz02_ssh_commands')!=0:
        raise ValueError('v2b_not_bounded_accepted')
    return root,term

def accepted_v2_failure(up):
    paths={'terminal':V2/'TERMINAL.json',
           'peer':V2/'peer-postrun-v2/REVIEW.json',
           'root':V2/'ROOT-POSTRUN-NO-GO.json'}
    expected={'terminal':V2_TERMINAL_SHA,'peer':V2_POSTRUN_PEER_SHA,
              'root':V2_ROOT_NOGO_SHA}
    docs={name:json.loads(up.stable_read(path)) for name,path in paths.items()}
    if any(up.file_sha(paths[name])!=expected[name] for name in paths):
        raise ValueError('v2_failure_chain_drift')
    terminal,peer,root=(docs[k] for k in ('terminal','peer','root'))
    if terminal.get('decision')!='NO_GO_PRIVATE_LISTENER_AND_GZ02_IDENTITY' or \
       terminal.get('gz02_ssh_commands')!=1 or terminal.get('negative') is not None or \
       terminal.get('private_dir_removed') is not True or \
       peer.get('decision')!='ACCEPT_TERMINAL_FAILURE_AND_CLEANUP_ONLY_NO_GZ02_IDENTITY_OR_ROUTE_PROOF' or \
       root.get('decision')!=peer['decision'] or root.get('replay_allowed') is not False or \
       root.get('failure_substage')!='UNKNOWN_AFTER_LOCAL_SSH_PROCESS_LAUNCH':
        raise ValueError('v2_failure_not_bounded')
    return docs

def exact_release(up):
    if START.exists() or TERMINAL.exists():
        raise ValueError('one_shot_consumed')
    peer_raw = up.stable_read(PEER)
    release_raw = up.stable_read(RELEASE)
    peer, release = json.loads(peer_raw), json.loads(release_raw)
    candidate_sha = up.file_sha(HERE / 'CANDIDATE.json')
    runner_sha = up.file_sha(pathlib.Path(__file__))
    wanted = {'schema','decision','candidate_sha256','runner_sha256','peer_review_sha256','upstream_postrun_sha256','upstream_terminal_sha256','v2b_postrun_sha256','v2b_terminal_sha256','v2_terminal_sha256','v2_postrun_peer_sha256','v2_root_nogo_sha256','source_sha256','binary_sha256','sandbox_sha256','sandbox_policy_sha256','ssh_sha256','nc_sha256','host_fingerprint','host_alias','port','scope','one_shot','read_only_ssh','no_hk01','no_graph','no_device','no_container','no_namespace','no_global_proxy_write'}
    if set(release) != wanted or release.get('schema') != 'g279-private-mihomo-v2c-root-release-v3' or release.get('decision') != 'ISSUE_EXACT_V2C_V3_GZ02_READONLY_IDENTITY_ONCE':
        raise ValueError('release_shape')
    if peer.get('decision') != 'GO_V2C_V3_CODE_ONLY' or peer.get('candidate_sha256') != candidate_sha or peer.get('runner_sha256') != runner_sha:
        raise ValueError('peer_gate')
    expected = {'candidate_sha256':candidate_sha,'runner_sha256':runner_sha,'peer_review_sha256':sha(peer_raw),'upstream_postrun_sha256':UP_ACCEPT_SHA,'upstream_terminal_sha256':UP_TERMINAL_SHA,'v2b_postrun_sha256':V2B_ROOT_SHA,'v2b_terminal_sha256':V2B_TERMINAL_SHA,'v2_terminal_sha256':V2_TERMINAL_SHA,'v2_postrun_peer_sha256':V2_POSTRUN_PEER_SHA,'v2_root_nogo_sha256':V2_ROOT_NOGO_SHA,'source_sha256':up.SOURCE_SHA,'binary_sha256':up.BIN_SHA,'sandbox_sha256':up.SANDBOX_SHA,'sandbox_policy_sha256':sha(POLICY.encode()),'ssh_sha256':SSH_SHA,'nc_sha256':NC_SHA,'host_fingerprint':HOST_FP,'host_alias':HOST_ALIAS,'scope':'private_native_exact_gz02_32_proxy_readonly_ssh_bounded_diagnostics_only'}
    if any(release.get(k) != v for k,v in expected.items()) or any(release.get(k) is not True for k in ('one_shot','read_only_ssh','no_hk01','no_graph','no_device','no_container','no_namespace','no_global_proxy_write')):
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
    # Export this entire line only after anchored fullmatch succeeds. The
    # whitelist permits timestamp, fixed addresses/rule/action, and port only.
    raw_line=line.decode('ascii')
    event={'schema':'g279-v2b-v4-normalized-route-event','source_ip':'127.0.0.1','source_port':port,
           'target_ip':'203.0.113.1','target_port':9,'rule':'Match','action':'REJECT',
           'raw_line':raw_line,'raw_line_sha256':sha(line)}
    event_sha=sha(json.dumps(event,sort_keys=True,separators=(',',':')).encode())
    return event,event_sha

def positive_route_event(logs):
    """Export a full line only after matching the fixed credential-free alias."""
    lines=[line for line in logs.splitlines() if b'[TCP]' in line and b' --> 1.95.90.207:58222 ' in line]
    if len(lines)!=1:raise ValueError('positive_route_missing_or_ambiguous')
    line=lines[0]
    pattern=(rb'time="[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{1,9}'
             rb'(?:Z|[+-][0-9]{2}:[0-9]{2})" level=info msg="\[TCP\] 127\.0\.0\.1:([0-9]{1,5})'
             rb' --> 1\.95\.90\.207:58222 match IPCIDR\(1\.95\.90\.207/32\) using PROXY\['
             +re.escape(SAFE_NODE_ALIAS.encode('ascii'))+rb'\]"')
    match=re.fullmatch(pattern,line)
    if match is None:raise ValueError('positive_route_not_exact')
    port=int(match.group(1))
    if not 1024<=port<=65535:raise ValueError('positive_source_port')
    raw_line=line.decode('ascii')
    return {'schema':'g279-v2c-v2-positive-route-event','source_ip':'127.0.0.1',
            'source_port':port,'target_ip':TARGET_IP,'target_port':TARGET_PORT,
            'rule':'IPCIDR(1.95.90.207/32)','action':'PROXY','node_alias':SAFE_NODE_ALIAS,
            'raw_line':raw_line,'raw_line_sha256':sha(line)}

def replay_positive_event(event):
    line=event['raw_line'].encode('ascii')
    if positive_route_event(line+b'\n')!=event:
        raise ValueError('positive_event_not_replayable')
    return True

def private_alias(node):
    """Rename only the copied, selected leaf; keep its real label out of logs."""
    if not isinstance(node,dict) or not node.get('name') or node['name']==SAFE_NODE_ALIAS:
        raise ValueError('selected_node_name_ambiguous')
    renamed=dict(node)
    renamed['name']=SAFE_NODE_ALIAS
    return renamed

def known_host_gate():
    for path,digest in ((pathlib.Path('/usr/bin/ssh'),SSH_SHA),(pathlib.Path('/usr/bin/nc'),NC_SHA)):
        if sha(path.read_bytes())!=digest:raise ValueError('ssh_or_nc_binary_drift')
    known=pathlib.Path.home()/'.ssh/known_hosts'
    if known.is_symlink() or known.resolve(strict=True)!=known or not known.is_file():
        raise ValueError('known_hosts_path')
    rows=[row.split() for row in known.read_text().splitlines() if row.startswith(HOST_ALIAS+' ')]
    keys=[row[2] for row in rows if len(row)==3 and row[1]=='ssh-ed25519']
    if len(keys)!=1:raise ValueError('pinned_host_key_missing_or_ambiguous')
    key=base64.b64decode(keys[0],validate=True)
    fp='SHA256:'+base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip('=')
    if fp!=HOST_FP:raise ValueError('pinned_host_key_drift')
    return known

def ssh_argv(port,known):
    if type(port) is not int or not 20000<=port<=60999:raise ValueError('ssh_port_scope')
    proxy=f'/usr/bin/nc -X 5 -x 127.0.0.1:{port} -w 8 %h %p'
    opts=['-F','/dev/null','-vv',
          '-o','User=AlexYang','-o','HostName='+TARGET_IP,'-o','Port='+str(TARGET_PORT),
          '-o','ProxyCommand='+proxy,'-o','ProxyJump=none','-o','BatchMode=yes',
          '-o','StrictHostKeyChecking=yes','-o','HostKeyAlgorithms=ssh-ed25519',
          '-o','ConnectTimeout=10','-o','ConnectionAttempts=1',
          '-o','UserKnownHostsFile='+str(known),'-o','GlobalKnownHostsFile=/dev/null',
          '-o','HostKeyAlias='+HOST_ALIAS,'-o','CheckHostIP=no',
          '-o','CanonicalizeHostname=no','-o','UpdateHostKeys=no',
          '-o','ControlMaster=no','-o','ControlPath=none','-o','ControlPersist=no',
          '-o','RequestTTY=no','-o','ClearAllForwardings=yes',
          '-o','PermitLocalCommand=no','-o','NumberOfPasswordPrompts=0']
    return ['/usr/bin/ssh',*opts,'gz02','LC_ALL=C /usr/bin/id -u'],proxy

def ssh_config_gate(argv,proxy,known):
    # -G is local configuration expansion only; no connection or credentials.
    p=subprocess.run(['/usr/bin/ssh','-G',*argv[1:-2],'gz02'],capture_output=True,text=True,timeout=5)
    if p.returncode!=0:raise ValueError('ssh_G_failed')
    values=dict(line.split(' ',1) for line in p.stdout.splitlines() if ' ' in line)
    wanted={'user':'AlexYang','hostname':TARGET_IP,'port':str(TARGET_PORT),
            'proxycommand':proxy,'proxyjump':'none','batchmode':'yes',
            'stricthostkeychecking':'true','hostkeyalgorithms':'ssh-ed25519',
            'hostkeyalias':HOST_ALIAS,'userknownhostsfile':str(known),
            'globalknownhostsfile':'/dev/null','checkhostip':'no',
            'canonicalizehostname':'false','updatehostkeys':'false',
            'controlmaster':'false','controlpath':'none','controlpersist':'no',
            'requesttty':'false','clearallforwardings':'yes',
            'permitlocalcommand':'no'}
    if any(values.get(k,'none' if k in ('proxyjump','controlpath') else '')!=v
           for k,v in wanted.items()):raise ValueError('ssh_G_route_drift')
    return True

def parse_ssh_proof(stdout,stderr,rc):
    if rc!=0:raise ValueError('ssh_nonzero_exit')
    fingerprint=HOST_FP.encode('ascii')
    key_lines=[x for x in stderr.splitlines() if re.fullmatch(rb'debug1: Server host key: ssh-ed25519 '+re.escape(fingerprint),x)]
    auth_lines=[x for x in stderr.splitlines() if x==b'Authenticated to 1.95.90.207 (via proxy) using "publickey".']
    if len(key_lines)!=1:raise ValueError('ssh_hostkey_debug_absent_or_ambiguous')
    if len(auth_lines)!=1:raise ValueError('ssh_auth_debug_absent_or_ambiguous')
    if re.fullmatch(rb'[0-9]{1,10}\n',stdout) is None:
        raise ValueError('ssh_remote_uid_absent_or_invalid')
    # These three complete witnesses contain only a public fingerprint,
    # fixed destination/auth method, and numeric UID; no SSH debug transcript.
    witness={'host_key_line':key_lines[0].decode('ascii'),
             'auth_line':auth_lines[0].decode('ascii'),
             'uid_stdout':stdout.decode('ascii')}
    return {'ssh_rc':0,'remote_uid':int(stdout.strip()),'host_fingerprint':HOST_FP,
            'host_key_pinned':True,'publickey_authenticated':True,
            'remote_command':'LC_ALL=C /usr/bin/id -u','remote_write_commands':0,
            'ssh_stdout_sha256':sha(stdout),'ssh_stderr_sha256':sha(stderr),
            'witness':witness,'host_key_line_sha256':sha(key_lines[0]),
            'auth_line_sha256':sha(auth_lines[0])}

def replay_ssh_proof(proof):
    w=proof['witness']
    if set(w)!={'host_key_line','auth_line','uid_stdout'}:
        raise ValueError('ssh_witness_shape')
    key=w['host_key_line'].encode('ascii');auth=w['auth_line'].encode('ascii')
    stdout=w['uid_stdout'].encode('ascii')
    replay=parse_ssh_proof(stdout,key+b'\n'+auth+b'\n',0)
    for field in ('ssh_rc','remote_uid','host_fingerprint','host_key_pinned',
                  'publickey_authenticated','remote_command','remote_write_commands',
                  'ssh_stdout_sha256','host_key_line_sha256','auth_line_sha256','witness'):
        if proof[field]!=replay[field]:raise ValueError('ssh_witness_not_replayable')
    return True

SSH_STAGES=('UNKNOWN','BANNER_LINE_SEEN','PINNED_KEY_LINE_SEEN',
            'PUBLICKEY_AUTH_LINE_SEEN','NUMERIC_UID_STDOUT_SEEN')

def ssh_observed_stage(stdout,stderr):
    lines=stderr.splitlines()
    banner=any(re.fullmatch(
        rb'debug1: Remote protocol version 2\.0, remote software version OpenSSH_[0-9A-Za-z._-]{1,40}',x)
        for x in lines)
    key=(b'debug1: Server host key: ssh-ed25519 '+HOST_FP.encode('ascii')) in lines
    auth=b'Authenticated to 1.95.90.207 (via proxy) using "publickey".' in lines
    uid=re.fullmatch(rb'[0-9]{1,10}\n',stdout) is not None
    if auth and key and uid:return 'NUMERIC_UID_STDOUT_SEEN'
    if auth and key:return 'PUBLICKEY_AUTH_LINE_SEEN'
    if key:return 'PINNED_KEY_LINE_SEEN'
    if banner:return 'BANNER_LINE_SEEN'
    return 'UNKNOWN'

def ssh_diagnostic_lengths(stdout_bytes,stderr_bytes,rc,timed_out,observed_stage='UNKNOWN'):
    d={'schema':'g279-v2c-v3-ssh-diagnostic','child_rc':rc,
       'timed_out':bool(timed_out),'stdout_bytes':stdout_bytes,
       'stderr_bytes':stderr_bytes,'last_ssh_stage':observed_stage,
       'category':'TIMEOUT' if timed_out else ('NONZERO_EXIT' if rc!=0 else 'RC0_PROOF_PENDING')}
    replay_ssh_diagnostic(d)
    return d

def replay_ssh_diagnostic(d):
    if set(d)!={'schema','child_rc','timed_out','stdout_bytes','stderr_bytes','last_ssh_stage','category'} or \
       d['schema']!='g279-v2c-v3-ssh-diagnostic' or \
       type(d['stdout_bytes']) is not int or d['stdout_bytes']<0 or \
       type(d['stderr_bytes']) is not int or d['stderr_bytes']<0 or \
       type(d['timed_out']) is not bool or \
       (d['child_rc'] is not None and type(d['child_rc']) is not int) or \
       d['last_ssh_stage'] not in SSH_STAGES:
        raise ValueError('ssh_diagnostic_shape')
    if d['timed_out']:
        if d['category']!='TIMEOUT':raise ValueError('ssh_timeout_category')
    elif d['child_rc']!=0:
        if d['category']!='NONZERO_EXIT':raise ValueError('ssh_nonzero_category')
    elif d['category'] not in ('RC0_PROOF_PENDING','HOSTKEY_WITNESS_UNPROVEN',
                              'AUTH_WITNESS_UNPROVEN','UID_WITNESS_UNPROVEN',
                              'PROOF_REJECTED_UNKNOWN','PROOF_VERIFIED'):
        raise ValueError('ssh_rc0_category')
    return True

def classify_ssh_proof_reject(error):
    return {
        'ssh_hostkey_debug_absent_or_ambiguous':'HOSTKEY_WITNESS_UNPROVEN',
        'ssh_auth_debug_absent_or_ambiguous':'AUTH_WITNESS_UNPROVEN',
        'ssh_remote_uid_absent_or_invalid':'UID_WITNESS_UNPROVEN',
    }.get(str(error),'PROOF_REJECTED_UNKNOWN')

def ssh_probe(port,on_launch=lambda:None,on_observe=lambda x:None):
    known=known_host_gate();argv,proxy=ssh_argv(port,known)
    ssh_config_gate(argv,proxy,known)
    proc=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          start_new_session=True)
    stdout=b'';stderr=b'';timed_out=False
    try:
        on_launch()
        stdout,stderr=proc.communicate(timeout=25)
    except subprocess.TimeoutExpired:
        timed_out=True
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid,signal.SIGKILL)
            stdout,stderr=proc.communicate(timeout=3)
    diagnostic=ssh_diagnostic_lengths(len(stdout),len(stderr),proc.returncode,timed_out,
                                      ssh_observed_stage(stdout,stderr))
    on_observe(diagnostic)
    if timed_out:raise ValueError('ssh_probe_timeout')
    try:proof=parse_ssh_proof(stdout,stderr,proc.returncode)
    except ValueError as e:
        if diagnostic['category']=='RC0_PROOF_PENDING':
            diagnostic['category']=classify_ssh_proof_reject(e)
        raise
    diagnostic['category']='PROOF_VERIFIED'
    proof['ssh_stdout_bytes']=len(stdout);proof['ssh_stderr_bytes']=len(stderr)
    return proof

class InstanceFailure(Exception):
    def __init__(self,clean,ssh_commands=0,diagnostic=None,safe_result=None):
        super().__init__('instance_failed')
        self.clean=clean
        self.ssh_commands=ssh_commands
        self.diagnostic=diagnostic
        self.safe_result=safe_result

INSTANCE_STAGES=('NONE','PRIVATE_LOOPBACK_LISTENER','LOCAL_TESTNET_CLOSED',
                 'LOCAL_REJECT_WITNESS','SSH_LOCAL_PROCESS_LAUNCHED',
                 'SSH_IDENTITY_WITNESS','POST_SSH_LOCAL_GUARDS',
                 'POSITIVE_ROUTE_WITNESS','WITNESSES_REPLAYED')
FAILURE_CATEGORIES=('UNKNOWN','INSTANCE_GUARD_UNKNOWN','PROCESS_CLEANUP_UNPROVEN',
                    'LISTENER_CLEANUP_UNPROVEN','SSH_TIMEOUT','SSH_NONZERO_EXIT',
                    'SSH_HOSTKEY_WITNESS_UNPROVEN','SSH_AUTH_WITNESS_UNPROVEN',
                    'SSH_UID_WITNESS_UNPROVEN','SSH_PROOF_REJECTED_UNKNOWN',
                    'SSH_RC0_PROOF_PENDING','POSITIVE_ROUTE_UNPROVEN',
                    'WITNESS_REPLAY_REJECTED')

def validate_instance_diagnostic(d):
    if set(d)!={'schema','last_complete_stage','failure_category','ssh_outcome',
                'positive_route_status','local_reject_status'} or \
       d['schema']!='g279-v2c-v3-instance-diagnostic' or \
       d['last_complete_stage'] not in INSTANCE_STAGES or \
       d['failure_category'] not in FAILURE_CATEGORIES or \
       d['positive_route_status'] not in ('UNKNOWN','PROVEN') or \
       d['local_reject_status'] not in ('UNKNOWN','PROVEN'):
        raise ValueError('instance_diagnostic_shape')
    if d['ssh_outcome'] is not None:replay_ssh_diagnostic(d['ssh_outcome'])
    return True

def run_instance(d,port,up):
    env={**os.environ,'HOME':str(d),'XDG_CONFIG_HOME':str(d),'XDG_CACHE_HOME':str(d),'TMPDIR':str(d)}
    for k in list(env):
        if 'proxy' in k.lower():env.pop(k)
    cmd=[str(up.SANDBOX),'-p',POLICY,str(up.BIN),'-d',str(d),'-f',str(d/'private.yaml')]
    out=d/'mihomo-stdout.raw';err=d/'mihomo-stderr.raw'
    fo=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    fe=os.open(err,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    proc=None;result=None;group_clean=False;failure=None;ssh_launched=[0]
    diagnostic={'schema':'g279-v2c-v3-instance-diagnostic',
                'last_complete_stage':'NONE','failure_category':'UNKNOWN',
                'ssh_outcome':None,'positive_route_status':'UNKNOWN',
                'local_reject_status':'UNKNOWN'}
    try:
        proc=subprocess.Popen(cmd,cwd=up.ROOT,env=env,stdout=fo,stderr=fe,start_new_session=True)
        for _ in range(40):
            if proc.poll() is not None:raise ValueError('mihomo_exited')
            rows=listener_rows(port)
            if rows:
                process_gate(proc,up);listener_gate(port,proc.pid)
                diagnostic['last_complete_stage']='PRIVATE_LOOPBACK_LISTENER'
                break
            time.sleep(.1)
        else:raise ValueError('listener_timeout')
        before=up.file_sha(d/'private.yaml')
        result=socks_negative(port)
        diagnostic['last_complete_stage']='LOCAL_TESTNET_CLOSED'
        time.sleep(.1)  # Let the private debug route event reach its raw log.
        process_gate(proc,up);listener_gate(port,proc.pid)
        if up.file_sha(d/'private.yaml')!=before:raise ValueError('config_changed_while_running')
        result.update({'listener_pid_matches_process':True,'loopback_only':True,'config_sha256':before})
        # Prove the bounded local REJECT again within this new private instance,
        # before any allowed gz02 request. No v2b process or credential survives.
        local_log=out.read_bytes()+b'\n'+err.read_bytes()
        event,event_sha=normalized_route_event(local_log)
        result.update({'route_reject_proven':True,'normalized_route_event':event,
                       'route_event_sha256':event_sha})
        diagnostic['local_reject_status']='PROVEN'
        diagnostic['last_complete_stage']='LOCAL_REJECT_WITNESS'
        def launched():
            ssh_launched[0]+=1
            diagnostic['last_complete_stage']='SSH_LOCAL_PROCESS_LAUNCHED'
        result['ssh_identity']=ssh_probe(port,launched,
            lambda x:diagnostic.__setitem__('ssh_outcome',x))
        diagnostic['last_complete_stage']='SSH_IDENTITY_WITNESS'
        time.sleep(.1)
        process_gate(proc,up);listener_gate(port,proc.pid)
        if up.file_sha(d/'private.yaml')!=before:raise ValueError('config_changed_after_ssh')
        diagnostic['last_complete_stage']='POST_SSH_LOCAL_GUARDS'
    except BaseException as e:
        failure=e
        ssh_outcome=diagnostic['ssh_outcome']
        diagnostic['failure_category']=('SSH_'+ssh_outcome['category'] if ssh_outcome and
                                        ssh_outcome['category']!='PROOF_VERIFIED'
                                        else 'INSTANCE_GUARD_UNKNOWN')
    finally:
        os.close(fo);os.close(fe)
        try:group_clean=cleaned_stop(proc,up)
        except BaseException as e:
            diagnostic['failure_category']='PROCESS_CLEANUP_UNPROVEN'
            group_clean=False
    if not group_clean:raise InstanceFailure(False,ssh_launched[0],diagnostic,result) from failure
    try:remaining=listener_rows(port)
    except BaseException as e:
        diagnostic['failure_category']='LISTENER_CLEANUP_UNPROVEN'
        raise InstanceFailure(False,ssh_launched[0],diagnostic,result) from e
    if remaining:raise InstanceFailure(False,ssh_launched[0],diagnostic,result) from failure
    logs=out.read_bytes()+b'\n'+err.read_bytes()
    # A strict safe-line witness can be retained even if the SSH probe failed.
    # Its absence means UNKNOWN, not evidence of a specific transport failure.
    try:positive=positive_route_event(logs)
    except ValueError:positive=None
    if failure is not None:raise InstanceFailure(True,ssh_launched[0],diagnostic,result) from failure
    if positive is None:
        diagnostic['failure_category']='POSITIVE_ROUTE_UNPROVEN'
        raise InstanceFailure(True,ssh_launched[0],diagnostic,result)
    diagnostic['positive_route_status']='PROVEN'
    diagnostic['last_complete_stage']='POSITIVE_ROUTE_WITNESS'
    result['positive_route_event']=positive
    try:
        replay_positive_event(positive)
        replay_ssh_proof(result['ssh_identity'])
    except ValueError as e:
        diagnostic['failure_category']='WITNESS_REPLAY_REJECTED'
        raise InstanceFailure(True,ssh_launched[0],diagnostic,result) from e
    diagnostic['last_complete_stage']='WITNESSES_REPLAYED'
    result['positive_route_proven']=True
    result['ssh_commands']=ssh_launched[0]
    return result,{'stdout_sha256':up.file_sha(out),'stderr_sha256':up.file_sha(err),'stdout_bytes':out.stat().st_size,'stderr_bytes':err.stat().st_size,'process_group_clean':True},diagnostic

def execute():
    up=load_upstream();accepted_upstream(up);accepted_v2b(up);accepted_v2_failure(up)
    release,release_sha=exact_release(up)
    known_host_gate()  # Local immutable identity gate; no network or secret write.
    token=secrets.token_hex(16)
    up.json_once(START,{'schema':'g279-private-v2c-start-v3','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'nonce':token,'release_sha256':release_sha,'runner_sha256':up.file_sha(pathlib.Path(__file__)),'upstream_postrun_sha256':UP_ACCEPT_SHA,'v2b_postrun_sha256':V2B_ROOT_SHA,'v2_root_nogo_sha256':V2_ROOT_NOGO_SHA,'scope':'private_native_gz02_32_proxy_readonly_ssh_bounded_diagnostics_only'})
    d=None;stage='binary';decision='NO_GO';negative=None;logs=None;diagnostic=None;config_sha=None;cleanup_ok=False;process_clean=True;ssh_commands=0
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
        node=private_alias(up.fresh_selected_node(pid,sockid,leaf))
        config=up.minimal_config(node,release['port']);up.config_gate(config)
        config['log-level']='debug'  # 0600 private log; only whitelisted route line may leave.
        b=up.yaml.safe_dump(config,sort_keys=False,allow_unicode=True).encode()
        up.write_once(d/'private.yaml',b,0o600)
        if stat.S_IMODE((d/'private.yaml').stat().st_mode)!=0o600 or up.file_sha(d/'private.yaml')!=sha(b):raise ValueError('config_readback')
        config_sha=sha(b)
        stage='private_listener_and_gz02_identity'
        process_clean=False
        negative,logs,diagnostic=run_instance(d,release['port'],up)
        ssh_commands=negative['ssh_commands']
        process_clean=True
        decision='GO_V2C_GZ02_32_PROXY_SSH_IDENTITY_ONLY'
    except BaseException as e:
        if isinstance(e,InstanceFailure):
            process_clean=e.clean;ssh_commands=e.ssh_commands
            diagnostic=e.diagnostic;negative=e.safe_result
        decision='NO_GO_'+stage.upper();failure_class=type(e).__name__
    finally:
        if diagnostic is not None:
            try:validate_instance_diagnostic(diagnostic)
            except BaseException:
                diagnostic=None
                decision='NO_GO_DIAGNOSTIC_INVALID'
        if process_clean:
            try:cleanup_ok=up.cleanup(d)
            except BaseException:cleanup_ok=False
            if not cleanup_ok:decision='NO_GO_CLEANUP'
        else:decision='NO_GO_PROCESS_UNPROVEN_PRIVATE_RETAINED'
        terminal={'schema':'g279-private-v2c-terminal-v3','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'nonce':token,'decision':decision,'failed_stage':None if decision=='GO_V2C_GZ02_32_PROXY_SSH_IDENTITY_ONLY' else stage,'failure_class':None if decision=='GO_V2C_GZ02_32_PROXY_SSH_IDENTITY_ONLY' else locals().get('failure_class'),'release_sha256':release_sha,'upstream_postrun_sha256':UP_ACCEPT_SHA,'v2b_postrun_sha256':V2B_ROOT_SHA,'v2_root_nogo_sha256':V2_ROOT_NOGO_SHA,'config_sha256':config_sha,'negative':negative,'private_log_metadata':logs,'diagnostic':diagnostic,'process_group_clean':process_clean,'private_dir_removed':cleanup_ok,'gz02_ssh_commands':ssh_commands,'remote_write_commands':0,'hk01_hops':0,'graph_commands':0,'device_commands':0,'container_commands':0,'namespace_commands':0,'global_proxy_writes':0,'startup_delta':0}
        up.json_once(TERMINAL,terminal)
    print(json.dumps({'decision':decision,'terminal_sha256':up.file_sha(TERMINAL),'nonce':token}))
    return 0 if decision=='GO_V2C_GZ02_32_PROXY_SSH_IDENTITY_ONLY' else 2

def main(argv,run=execute):
    if argv!=['--execute']:return 2
    try:return run()
    except Exception as e:
        print(json.dumps({'decision':'NO_GO_BEFORE_START','failure_class':type(e).__name__}))
        return 2

if __name__=='__main__':
    sys.exit(main(sys.argv[1:]))
