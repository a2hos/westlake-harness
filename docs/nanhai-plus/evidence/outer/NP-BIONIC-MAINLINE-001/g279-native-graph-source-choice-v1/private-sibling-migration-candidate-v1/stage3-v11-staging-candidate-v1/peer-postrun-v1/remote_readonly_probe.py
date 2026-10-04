"""Independent read-only G279 Stage3 v11 postrun probe on gz02."""
import hashlib
import json
import os
import stat
import subprocess
import sys


def file_row(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        a = os.fstat(fd)
        if not stat.S_ISREG(a.st_mode):
            raise ValueError('not regular: ' + path)
        h = hashlib.sha256()
        chunks = []
        while True:
            block = os.read(fd, 1048576)
            if not block:
                break
            h.update(block)
            chunks.append(block)
        b = os.fstat(fd)
        if (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns, a.st_mode) != \
           (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns, b.st_mode):
            raise ValueError('file changed during read: ' + path)
        data = b''.join(chunks)
        return {'dev': b.st_dev, 'ino': b.st_ino, 'uid': b.st_uid,
                'gid': b.st_gid, 'mode': stat.S_IMODE(b.st_mode),
                'bytes': len(data), 'sha256': h.hexdigest(),
                'acl': [x for x in os.listxattr(fd) if x.startswith('system.posix_acl_')]}, data
    finally:
        os.close(fd)


def dir_row(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        return {'dev': s.st_dev, 'ino': s.st_ino, 'uid': s.st_uid,
                'mode': stat.S_IMODE(s.st_mode),
                'acl': [x for x in os.listxattr(fd) if x.startswith('system.posix_acl_')]}
    finally:
        os.close(fd)


def head(target):
    p = subprocess.run(['/usr/bin/git', '-C', target, 'rev-parse', 'HEAD'],
                       capture_output=True, text=True, timeout=12)
    if p.returncode or p.stderr:
        raise ValueError('Git HEAD probe failed: ' + target)
    return p.stdout.strip()


def main():
    p = PACKET
    s2 = STAGE2_PACKET
    root = p['root']
    if sys.platform != 'linux' or os.uname().nodename.split('.')[0].casefold() != 'gz02' or \
       os.getuid() != 1000 or os.geteuid() != 1000:
        raise ValueError('wrong host or UID')
    if os.path.realpath(root) != root or os.path.realpath(p['old_root']) != p['old_root']:
        raise ValueError('root symlink')
    directories = {name: dir_row(path) for name, path in (
        ('root', root), ('control', root + '/control'),
        ('old_root', p['old_root']), ('source_view', root + '/source-view'))}
    for key, expected in [('root', p['root_id']), ('control', p['control_id']),
                          ('old_root', p['old_root_id']), ('source_view', p['source_view_id'])]:
        if {k: directories[key][k] for k in ('dev', 'ino', 'uid', 'mode')} != expected or \
           directories[key]['acl']:
            raise ValueError('accepted directory changed: ' + key)
    if sorted(os.listdir(root)) != ['control', 'out', 'source-view', 'staging', 'tmp']:
        raise ValueError('sibling root inventory changed')
    files = []
    for spec in p['unchanged_files']:
        current, _ = file_row(root + '/' + spec['path'])
        if {k: current[k] for k in ('dev', 'ino', 'uid', 'gid', 'mode', 'bytes', 'sha256')} != spec['identity'] or current['acl']:
            raise ValueError('Stage1/2 input changed: ' + spec['path'])
        files.append({'path': spec['path'], **current})
    if len(files) != 14:
        raise ValueError('Stage1/2 file count')
    runner_path = root + '/control/' + p['runner']['name']
    runner, _ = file_row(runner_path)
    if runner['sha256'] != p['runner']['sha256'] or runner['bytes'] != p['runner']['bytes'] or \
       runner['mode'] != 0o444 or runner['uid'] != 1000 or runner['acl']:
        raise ValueError('v11 runner identity drift')
    lease, lease_bytes = file_row(root + '/control/STAGE3-V11-LEASE.json')
    receipt, receipt_bytes = file_row(root + '/control/STAGE3-V11-RECEIPT.json')
    lease_value, receipt_value = json.loads(lease_bytes), json.loads(receipt_bytes)
    if lease_value != {'schema': 'g279-stage3-v11-lease-v1',
                       'nonce': p['nonce'], 'packet_sha256': p['packet_sha256']} or \
       receipt_value.get('schema') != 'g279-stage3-v11-remote-receipt-v1' or \
       receipt_value.get('status') != 'STAGED_READBACK_ONLY' or \
       receipt_value.get('nonce') != p['nonce'] or \
       receipt_value.get('packet_sha256') != p['packet_sha256'] or \
       receipt_value.get('runner') != {k: runner[k] for k in ('dev','ino','uid','gid','mode','bytes','sha256')} or \
       any(receipt_value.get(k) is not False for k in ('graph','target','device','container','namespace','binding_changed')):
        raise ValueError('Stage3 lease/receipt drift')
    expected_control = sorted([x['path'].split('/',1)[1] for x in p['unchanged_files']
                               if x['path'].startswith('control/')] +
                              [p['runner']['name'], 'STAGE3-V11-LEASE.json',
                               'STAGE3-V11-RECEIPT.json'])
    if sorted(os.listdir(root + '/control')) != expected_control or \
       os.path.lexists(root + '/control/STAGE3-V11-QUARANTINE.json'):
        raise ValueError('control inventory or quarantine drift')
    links = []
    observed_dirs = []
    observed_links = []
    for base, dirs, names in os.walk(root + '/source-view', followlinks=False):
        for name in dirs + names:
            path = os.path.join(base, name)
            rel = os.path.relpath(path, root + '/source-view')
            if os.path.islink(path):
                observed_links.append(rel)
            elif os.path.isdir(path):
                observed_dirs.append(rel)
            else:
                raise ValueError('unexpected source-view file')
    expected_dirs = sorted({prefix for row in s2['links'] for prefix in (
        '/'.join(row['relative'].split('/')[:i])
        for i in range(1, len(row['relative'].split('/'))))})
    if sorted(observed_links) != [x['relative'] for x in s2['links']] or \
       sorted(observed_dirs) != expected_dirs:
        raise ValueError('source-view inventory drift')
    for row in s2['links']:
        path = root + '/source-view/' + row['relative']
        literal, resolved, commit = os.readlink(path), os.path.realpath(path), head(row['symlink_target'])
        if literal != row['symlink_target'] or resolved != row['resolved_target'] or \
           commit != row['expected_head'] or not os.path.isdir(path):
            raise ValueError('source-view link drift: ' + row['relative'])
        links.append({'relative': row['relative'], 'literal': literal,
                      'resolved': resolved, 'head': commit})
    out = {'': sorted(os.listdir(root + '/out')),
           'soong-ui-v1': sorted(os.listdir(root + '/out/soong-ui-v1')),
           'no-namespace-guard-v1': sorted(os.listdir(root + '/out/no-namespace-guard-v1'))}
    if out != {'': ['no-namespace-guard-v1','soong-ui-v1'],
               'soong-ui-v1': ['soong_ui'],
               'no-namespace-guard-v1': ['no-namespace-exec']} or \
       os.listdir(root + '/tmp') or os.listdir(root + '/staging'):
        raise ValueError('out/tmp/staging inventory drift')
    print(json.dumps({'schema':'g279-stage3-v11-independent-readonly-probe-v1',
                      'status':'PASS','host':os.uname().nodename,'uid':os.getuid(),
                      'directories':directories,'files':files,'runner':runner,
                      'lease':lease,'receipt':receipt,'lease_value':lease_value,
                      'receipt_value':receipt_value,'control_entries':expected_control,
                      'links':links,'link_count':len(links),'parent_dirs':observed_dirs,
                      'out':out,'quarantine_exists':False,'remote_writes':0,
                      'graph':False,'device':False,'container':False,'namespace':False},
                     sort_keys=True))


if __name__ == '__main__':
    main()
