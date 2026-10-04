#!/usr/bin/env python3
"""One local fake SOCKS5 pre-banner close; no remote dial or credentials."""
import datetime,hashlib,json,pathlib,socket,subprocess,threading,time

HERE=pathlib.Path(__file__).resolve().parent
TARGET='192.0.2.2'  # TEST-NET-1; fake server never dials it.
TARGET_PORT=2222
observed={}
with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
 listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(6)
 port=listener.getsockname()[1]
 def serve():
  try:
   conn,addr=listener.accept();observed['accepts']=1
   with conn:
    conn.settimeout(3)
    greeting=conn.recv(16);observed['greeting_hex']=greeting.hex()
    if greeting!=b'\x05\x01\x00':raise ValueError('unexpected greeting')
    conn.sendall(b'\x05\x00')
    request=conn.recv(32);observed['request_hex']=request.hex()
    if request!=b'\x05\x01\x00\x01'+socket.inet_aton(TARGET)+TARGET_PORT.to_bytes(2,'big'):
     raise ValueError('unexpected destination')
    observed['requested_target']=TARGET;observed['requested_port']=TARGET_PORT
    conn.sendall(b'\x05\x00\x00\x01'+socket.inet_aton('127.0.0.1')+port.to_bytes(2,'big'))
    time.sleep(.08)
  except BaseException as e:observed['server_error_class']=type(e).__name__
 t=threading.Thread(target=serve);t.start()
 proxy=f'/usr/bin/nc -X 5 -x 127.0.0.1:{port} -w 3 %h %p'
 argv=['/usr/bin/ssh','-F','/dev/null','-vv','-o','ProxyCommand='+proxy,
       '-o','HostName='+TARGET,'-o','Port='+str(TARGET_PORT),'-o','User=fake',
       '-o','BatchMode=yes','-o','ConnectTimeout=3','-o','ConnectionAttempts=1',
       '-o','IdentityAgent=none','-o','IdentityFile=/dev/null',
       '-o','PubkeyAuthentication=no','-o','PasswordAuthentication=no',
       '-o','KbdInteractiveAuthentication=no','-o','PreferredAuthentications=none',
       '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/dev/null',
       '-o','GlobalKnownHostsFile=/dev/null','-o','RequestTTY=no',
       'fake-local-target','LC_ALL=C /usr/bin/id -u']
 try:p=subprocess.run(argv,capture_output=True,timeout=8,check=False)
 finally:t.join(timeout=7)

out=HERE/'FAKE-SSH-STDOUT.raw';err=HERE/'FAKE-SSH-STDERR.raw'
out.write_bytes(p.stdout);err.write_bytes(p.stderr)
fixed=(b'kex_exchange_identification: Connection closed by remote host',
       b'Connection closed by UNKNOWN port 65535')
matches=[line.decode('ascii') for line in p.stderr.splitlines() if line in fixed]
receipt={'schema':'g279-v2c-v6-fake-socks-counterexample-v1',
 'at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'decision':'LOCAL_FAKE_ONLY','ssh_rc':p.returncode,
 'ssh_stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),
 'ssh_stderr_sha256':hashlib.sha256(p.stderr).hexdigest(),
 'ssh_stdout_bytes':len(p.stdout),'ssh_stderr_bytes':len(p.stderr),
 'pre_banner_marker_full_lines':matches,
 'fake_server':observed,'fake_server_outbound_socket_calls':0,
 'real_gz02_connections':0,'credential_auth_attempts':0,
 'device_commands':0,'container_commands':0,'namespace_commands':0}
(HERE/'FAKE-SOCKS-RESULT.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
print(json.dumps({'ssh_rc':p.returncode,'markers':matches,'server':observed},sort_keys=True))
raise SystemExit(0 if p.returncode!=0 and matches and observed.get('requested_target')==TARGET and 'server_error_class' not in observed else 2)
