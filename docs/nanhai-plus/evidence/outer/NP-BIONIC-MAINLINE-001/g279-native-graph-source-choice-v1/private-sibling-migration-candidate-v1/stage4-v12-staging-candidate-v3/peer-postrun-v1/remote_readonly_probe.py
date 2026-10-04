"""Independent, read-only G279 Stage4 v12 staged-byte probe on gz02."""
import hashlib
import json
import os
import stat
import sys


def identity(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('not regular: ' + path)
        digest = hashlib.sha256()
        content = bytearray()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            content.extend(block)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns, before.st_mode) != (after.st_dev, after.st_ino,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode):
            raise ValueError('changed during read: ' + path)
        row = {'dev': after.st_dev, 'ino': after.st_ino, 'uid': after.st_uid,
               'gid': after.st_gid, 'mode': stat.S_IMODE(after.st_mode),
               'bytes': len(content), 'sha256': digest.hexdigest()}
        if [x for x in os.listxattr(fd) if x.startswith('system.posix_acl_')]:
            raise ValueError('ACL present: ' + path)
        return row, bytes(content)
    finally:
        os.close(fd)


def directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if [x for x in os.listxattr(fd) if x.startswith('system.posix_acl_')]:
            raise ValueError('directory ACL: ' + path)
        return {'dev': s.st_dev, 'ino': s.st_ino, 'uid': s.st_uid,
                'mode': stat.S_IMODE(s.st_mode)}
    finally:
        os.close(fd)


def main():
    p = PACKET
    if sys.platform != 'linux' or os.uname().nodename.split('.')[0].casefold() != 'gz02' or os.uname().machine != 'x86_64' or os.getuid() != 1000 or os.geteuid() != 1000:
        raise ValueError('wrong host/UID')
    root = p['root']
    if os.path.realpath(root) != root or os.path.realpath(p['old_root']) != p['old_root']:
        raise ValueError('root symlink')
    dirs = {name: directory(path) for name, path in (
        ('root', root), ('control', root + '/control'),
        ('old_root', p['old_root']), ('source_view', root + '/source-view'))}
    for name, key in [('root','root_id'), ('control','control_id'),
                      ('old_root','old_root_id'), ('source_view','source_view_id')]:
        if dirs[name] != p[key]:
            raise ValueError('directory identity drift: ' + name)
    root_entries = sorted(os.listdir(root))
    if root_entries != ['control', 'out', 'source-view', 'staging', 'tmp']:
        raise ValueError('root inventory drift')
    files = []
    for spec in p['unchanged_files']:
        row, _ = identity(root + '/' + spec['path'])
        if row != spec['identity']:
            raise ValueError('old input identity drift: ' + spec['path'])
        files.append({'path': spec['path'], **row})
    if len(files) != 17:
        raise ValueError('old input count')
    runner, _ = identity(root + '/control/' + p['runner']['name'])
    if runner['bytes'] != p['runner']['bytes'] or runner['sha256'] != p['runner']['sha256'] or runner['mode'] != 0o444 or runner['uid'] != 1000:
        raise ValueError('v12 runner drift')
    lease, lease_raw = identity(root + '/control/STAGE4-V12-LEASE.json')
    receipt, receipt_raw = identity(root + '/control/STAGE4-V12-RECEIPT.json')
    lease_value = json.loads(lease_raw)
    receipt_value = json.loads(receipt_raw)
    if lease_value != {'schema':'g279-stage4-v12-lease-v1','nonce':p['nonce'],
                       'packet_sha256':p['packet_sha256']}:
        raise ValueError('lease drift')
    expected_receipt = {'schema':'g279-stage4-v12-remote-receipt-v1',
                        'status':'STAGED_READBACK_ONLY','nonce':p['nonce'],
                        'packet_sha256':p['packet_sha256'],'runner':runner,
                        'root_id':p['root_id'],'control_id':p['control_id'],
                        'old_root_id':p['old_root_id'],'source_view_id':p['source_view_id'],
                        'binding_changed':False,'graph':False,'target':False,
                        'device':False,'container':False,'namespace':False}
    if receipt_value != expected_receipt:
        raise ValueError('remote receipt drift')
    controls = sorted(os.listdir(root + '/control'))
    expected_controls = sorted(p['control_entries_before'] +
                               ['STAGE4-V12-LEASE.json','STAGE4-V12-RECEIPT.json',p['runner']['name']])
    if controls != expected_controls or os.path.lexists(root + '/control/STAGE4-V12-QUARANTINE.json'):
        raise ValueError('control inventory or quarantine drift')
    out = {'':sorted(os.listdir(root + '/out')),
           'soong-ui-v1':sorted(os.listdir(root + '/out/soong-ui-v1')),
           'no-namespace-guard-v1':sorted(os.listdir(root + '/out/no-namespace-guard-v1'))}
    if out != {'':['no-namespace-guard-v1','soong-ui-v1'],
               'soong-ui-v1':['soong_ui'],'no-namespace-guard-v1':['no-namespace-exec']}:
        raise ValueError('out inventory drift')
    if os.listdir(root + '/staging') or os.listdir(root + '/tmp'):
        raise ValueError('staging/tmp inventory drift')
    print(json.dumps({'schema':'g279-stage4-v12-independent-readonly-postrun-probe-v1',
                      'status':'PASS','host':os.uname().nodename,'uid':os.getuid(),
                      'directories':dirs,'root_entries':root_entries,'old_files':files,
                      'runner':runner,'lease':lease,'lease_value':lease_value,
                      'receipt':receipt,'receipt_value':receipt_value,
                      'control_entries':controls,'out':out,'staging_empty':True,
                      'tmp_empty':True,'quarantine_absent':True,
                      'remote_writes':0,'graph':False,'target':False,'device':False,
                      'container':False,'namespace':False},sort_keys=True))


if __name__ == '__main__':
    main()
