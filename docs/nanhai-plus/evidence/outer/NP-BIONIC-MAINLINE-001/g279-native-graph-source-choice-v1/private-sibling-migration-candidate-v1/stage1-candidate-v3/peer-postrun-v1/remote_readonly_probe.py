#!/usr/bin/env python3
"""Independent G279 stage-1 readback: only Python reads over SSH."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
NONCE = '02add3542f7f57bff960919f7cd3ce55'
TERMINAL = BASE / 'receipts' / (NONCE + '.TERMINAL.json')
PLAN = BASE.parent / 'MIGRATION-PLAN.json'
SSH = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ConnectTimeout=10',
       '-o', 'UserKnownHostsFile=/Users/alexyang/.ssh/known_hosts',
       'gz02', '/usr/bin/python3.12 -']

terminal = json.loads(TERMINAL.read_text())
remote_receipt = json.loads(terminal['stdout'])
plan = json.loads(PLAN.read_text())
items = []
for row in remote_receipt['copied']:
    item = next((x for x in plan['control_old_observed']
                 if row['source'] == 'control/' + x['name']), None)
    if item is None:
        item = next(x for x in plan['host_tool_inputs']['observed_old_outputs']
                    if row['source'] == x['relative'])
    items.append({'source': row['source'], 'kind': row['kind'], 'dest': row['dest'],
                  'sha256': item['sha256'], 'bytes': item['bytes'],
                  'new_ino': row['new_id']['ino'],
                  'new_mode': row['new_id']['mode']})
packet = {'nonce': NONCE, 'old': plan['old_root'], 'new': plan['proposed_new_root'],
          'items': items}
remote_program = 'P = ' + repr(packet) + '\n' + r'''
import hashlib,json,os,stat,sys
def row(path,do_hash=False):
    st=os.lstat(path)
    if stat.S_ISLNK(st.st_mode):raise ValueError('symlink: '+path)
    r={'path':path,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),
       'dev':st.st_dev,'ino':st.st_ino,'type':'directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'other',
       'acl_xattrs':[x for x in os.listxattr(path,follow_symlinks=False) if x.startswith('system.posix_acl_')]}
    if do_hash:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            h=hashlib.sha256();n=0
            while True:
                b=os.read(fd,1048576)
                if not b:break
                h.update(b);n+=len(b)
            r['sha256']=h.hexdigest();r['bytes']=n
        finally:os.close(fd)
    return r
old=P['old'];new=P['new']
dirs={key:row(path) for key,path in {
 'parent':'/data/source','old_root':old,'old_control':old+'/control',
 'new_root':new,'control':new+'/control','out':new+'/out','tmp':new+'/tmp','staging':new+'/staging',
 'out_soong':new+'/out/soong-ui-v1','out_guard':new+'/out/no-namespace-guard-v1'}.items()}
files=[]
for item in P['items']:
    target=new+('/control/' if item['kind']=='control' else '/out/')+item['dest']
    source=old+'/'+item['source']
    files.append({'expected':item,'new':row(target,True),'old':row(source,True)})
receipts={name:row(new+'/control/'+name,True) for name in ('STAGE1-LEASE.json','STAGE1-RECEIPT.json')}
remote_receipt=json.loads(open(new+'/control/STAGE1-RECEIPT.json').read())
lease=json.loads(open(new+'/control/STAGE1-LEASE.json').read())
listing={name:sorted(os.listdir(path)) for name,path in {'root':new,'control':new+'/control','out':new+'/out','tmp':new+'/tmp','staging':new+'/staging'}.items()}
print(json.dumps({'schema':'g279-stage1-independent-remote-readback-v1','host':os.uname().nodename,
 'uid':os.getuid(),'dirs':dirs,'files':files,'receipts':receipts,
 'receipt_content':remote_receipt,'lease_content':lease,'listing':listing,
 'quarantine_exists':os.path.lexists(new+'/control/QUARANTINE.json')},sort_keys=True))
'''
run = subprocess.run(SSH, input=remote_program.encode(), capture_output=True, timeout=60)
(HERE / 'remote.stdout.raw').write_bytes(run.stdout)
(HERE / 'remote.stderr.raw').write_bytes(run.stderr)
summary = {'ssh_rc': run.returncode, 'stdout_sha256': hashlib.sha256(run.stdout).hexdigest(),
           'stderr_sha256': hashlib.sha256(run.stderr).hexdigest(),
           'stdout_bytes': len(run.stdout), 'stderr_bytes': len(run.stderr)}
(HERE / 'probe-command.json').write_text(json.dumps({'ssh_argv':SSH,'remote_program_sha256':hashlib.sha256(remote_program.encode()).hexdigest(),
                                                     'result':summary},indent=2)+'\n')
print(json.dumps(summary,sort_keys=True))
sys.exit(0 if run.returncode==0 else 1)
