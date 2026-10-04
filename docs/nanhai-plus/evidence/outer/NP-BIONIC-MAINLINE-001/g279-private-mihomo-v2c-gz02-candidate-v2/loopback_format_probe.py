#!/usr/bin/env python3
"""One-shot, no-credential loopback fake-node Mihomo log-format probe.

The fake SOCKS node only listens on 127.0.0.1 and never dials its requested
destination. This probe does not use the actual selected node or SSH.
"""
import hashlib
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

import runner as v

HERE=pathlib.Path(__file__).resolve().parent
RECEIPT=HERE/'LOOPBACK-FORMAT-PROBE.json'

def sha(b):return hashlib.sha256(b).hexdigest()

def reserve():
    s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close();return port

def recvn(s,n):
    out=b''
    while len(out)<n:
        b=s.recv(n-len(out))
        if not b:raise ValueError('mock_truncated')
        out+=b
    return out

def fake_node(listener,received):
    try:
        listener.settimeout(8)
        conn,_=listener.accept()
        with conn:
            conn.settimeout(4)
            if recvn(conn,3)!=b'\x05\x01\x00':raise ValueError('mock_method')
            conn.sendall(b'\x05\x00')
            head=recvn(conn,4)
            if head!=b'\x05\x01\x00\x01':raise ValueError('mock_connect_shape')
            target=recvn(conn,6)
            received['target_requested_to_fake_node']=socket.inet_ntoa(target[:4])
            received['target_port_requested_to_fake_node']=int.from_bytes(target[4:],'big')
            conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01')
    except Exception as e:received['error_class']=type(e).__name__
    finally:listener.close()

def main():
    if sys.argv[1:]!=['--execute'] or RECEIPT.exists():return 2
    up=v.load_upstream()
    if up.file_sha(up.BIN)!=up.BIN_SHA or up.file_sha(up.SANDBOX)!=up.SANDBOX_SHA:raise ValueError('binary_drift')
    mock=socket.socket();mock.bind(('127.0.0.1',0));mock.listen(1)
    fake_port=mock.getsockname()[1];mihomo_port=reserve()
    received={};thread=threading.Thread(target=fake_node,args=(mock,received),daemon=True);thread.start()
    proc=None;stdout=b'';stderr=b'';socks_reply=None
    with tempfile.TemporaryDirectory(prefix='g279-v2c-v2-format-',dir=str(up.ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16')) as t:
        d=pathlib.Path(t);os.chmod(d,0o700)
        config=(f'mode: rule\nallow-lan: false\nbind-address: 127.0.0.1\n'
                f'mixed-port: {mihomo_port}\nipv6: false\nlog-level: debug\n'
                'dns:\n  enable: false\ntun:\n  enable: false\n'
                'profile:\n  store-selected: false\n'
                'proxies:\n  - name: g279-v2c-selected\n    type: socks5\n'
                f'    server: 127.0.0.1\n    port: {fake_port}\n'
                'proxy-groups:\n  - name: PROXY\n    type: select\n'
                '    proxies:\n      - g279-v2c-selected\n'
                'rules:\n  - IP-CIDR,1.95.90.207/32,PROXY,no-resolve\n'
                '  - MATCH,REJECT\n')
        cfg=d/'fake.yaml';cfg.write_text(config);os.chmod(cfg,0o600)
        env={**os.environ,'HOME':str(d),'XDG_CONFIG_HOME':str(d),'XDG_CACHE_HOME':str(d),'TMPDIR':str(d)}
        for k in list(env):
            if 'proxy' in k.lower():env.pop(k)
        cmd=[str(up.SANDBOX),'-p',v.POLICY,str(up.BIN),'-d',str(d),'-f',str(cfg)]
        try:
            proc=subprocess.Popen(cmd,cwd=up.ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            for _ in range(40):
                if proc.poll() is not None:raise ValueError('mihomo_exited')
                try:
                    with socket.create_connection(('127.0.0.1',mihomo_port),timeout=.1) as s:
                        s.settimeout(3)
                        s.sendall(b'\x05\x01\x00')
                        if recvn(s,2)!=b'\x05\x00':raise ValueError('mihomo_method')
                        s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(v.TARGET_IP)+v.TARGET_PORT.to_bytes(2,'big'))
                        socks_reply=recvn(s,10).hex()
                    break
                except (ConnectionRefusedError,TimeoutError):time.sleep(.1)
            else:raise ValueError('mihomo_listener_timeout')
            time.sleep(.3)
        finally:
            if proc is not None:
                if proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM)
                try:stdout,stderr=proc.communicate(timeout=4)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid,signal.SIGKILL);stdout,stderr=proc.communicate(timeout=3)
        thread.join(timeout=1)
    logs=stdout+b'\n'+stderr
    route_lines=[line for line in logs.splitlines() if b'[TCP]' in line and b' --> 1.95.90.207:58222 ' in line]
    try:event=v.positive_route_event(logs);format_matches=True
    except ValueError:event=None;format_matches=False
    outcome={'schema':'g279-v2c-v2-loopback-format-probe-v1','binary_sha256':up.BIN_SHA,
             'sandbox_sha256':up.SANDBOX_SHA,'fake_node_loopback_only':True,
             'fake_node_requested_target':received.get('target_requested_to_fake_node'),
             'fake_node_requested_port':received.get('target_port_requested_to_fake_node'),
             'fake_node_error_class':received.get('error_class'),'real_gz02_connects':0,
             'real_node_credentials_loaded':False,'real_ssh_connections':0,
             'mihomo_process_stopped':proc.poll() is not None,'private_dir_removed':True,
             'socks_reply_hex':socks_reply,'route_line_count':len(route_lines),
             'route_lines_ascii':[x.decode('ascii','replace') for x in route_lines],
             'format_matches_candidate':format_matches,'replayable_event':event,
             'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr),
             'device_commands':0,'container_commands':0,'graph_commands':0}
    RECEIPT.write_text(json.dumps(outcome,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'format_matches_candidate':format_matches,'route_line_count':len(route_lines),'receipt_sha256':sha(RECEIPT.read_bytes())}))
    return 0 if format_matches and received.get('target_requested_to_fake_node')==v.TARGET_IP and received.get('target_port_requested_to_fake_node')==v.TARGET_PORT else 2

if __name__=='__main__':sys.exit(main())
