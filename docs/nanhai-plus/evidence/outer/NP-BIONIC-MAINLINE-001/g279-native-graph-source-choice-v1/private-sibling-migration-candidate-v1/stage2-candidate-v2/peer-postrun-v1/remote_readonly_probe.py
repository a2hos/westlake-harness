"""Independent G279 stage-2 readback. The injected PACKET is frozen local data."""
import hashlib
import json
import os
import stat
import subprocess
import sys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_row(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('not a regular file: ' + path)
        digest = hashlib.sha256()
        count = 0
        while True:
            part = os.read(fd, 1048576)
            if not part:
                break
            digest.update(part)
            count += len(part)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns, before.st_mode) != (after.st_dev, after.st_ino,
            after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode):
            raise ValueError('file changed while reading: ' + path)
        return {'dev': after.st_dev, 'ino': after.st_ino, 'uid': after.st_uid,
                'gid': after.st_gid, 'mode': stat.S_IMODE(after.st_mode),
                'bytes': count, 'sha256': digest.hexdigest(),
                'acl': [x for x in os.listxattr(fd) if x.startswith('system.posix_acl_')]}
    finally:
        os.close(fd)


def dir_row(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        return {'dev': s.st_dev, 'ino': s.st_ino, 'uid': s.st_uid,
                'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode),
                'acl': [x for x in os.listxattr(fd) if x.startswith('system.posix_acl_')]}
    finally:
        os.close(fd)


def git_head(path):
    result = subprocess.run(['/usr/bin/git', '-C', path, 'rev-parse', 'HEAD'],
                            capture_output=True, text=True, timeout=15)
    if result.returncode or result.stderr:
        raise ValueError('git HEAD probe failed: ' + path)
    return result.stdout.strip()


def main():
    packet = PACKET
    root = packet['new_root']
    old = packet['old_root']
    if sys.platform != 'linux' or os.uname().nodename.split('.')[0].casefold() != 'gz02' or \
       os.getuid() != 1000 or os.geteuid() != 1000:
        raise ValueError('wrong host or UID')
    if os.path.realpath(root) != root or os.path.realpath(old) != old:
        raise ValueError('root ancestor symlink')
    accepted = packet['accepted_stage1']
    directories = {'root': dir_row(root), 'control': dir_row(root + '/control'),
                   'old_root': dir_row(old), 'source_view': dir_row(root + '/source-view')}
    for key in ('root', 'control', 'old_root'):
        if {k: directories[key][k] for k in ('dev', 'ino', 'uid', 'mode')} != accepted[key] or \
           directories[key]['acl']:
            raise ValueError('stage1 directory drift: ' + key)
    if directories['source_view']['uid'] != 1000 or directories['source_view']['mode'] != 0o755 or \
       directories['source_view']['acl']:
        raise ValueError('source view directory drift')
    if sorted(os.listdir(root)) != ['control', 'out', 'source-view', 'staging', 'tmp']:
        raise ValueError('root inventory drift')
    files = []
    for expected in accepted['files']:
        current = file_row(root + '/' + expected['path'])
        if {k: current[k] for k in ('dev', 'ino', 'uid', 'gid', 'mode', 'bytes', 'sha256')} != \
           {k: expected[k] for k in ('dev', 'ino', 'uid', 'gid', 'mode', 'bytes', 'sha256')} or current['acl']:
            raise ValueError('stage1 staged file drift: ' + expected['path'])
        files.append({'path': expected['path'], **current})
    observed_links = []
    observed_dirs = []
    for base, dirs, names in os.walk(root + '/source-view', followlinks=False):
        for name in dirs + names:
            path = os.path.join(base, name)
            rel = os.path.relpath(path, root + '/source-view')
            if os.path.islink(path):
                observed_links.append(rel)
            elif os.path.isdir(path):
                observed_dirs.append(rel)
            else:
                raise ValueError('unexpected source-view entry: ' + rel)
    expected_dirs = sorted({prefix for row in packet['links'] for prefix in (
        '/'.join(row['relative'].split('/')[:i])
        for i in range(1, len(row['relative'].split('/'))))})
    if sorted(observed_links) != [row['relative'] for row in packet['links']] or \
       sorted(observed_dirs) != expected_dirs:
        raise ValueError('source view inventory drift')
    links = []
    for row in packet['links']:
        path = root + '/source-view/' + row['relative']
        literal = os.readlink(path)
        resolved = os.path.realpath(path)
        head = git_head(literal)
        if literal != row['symlink_target'] or resolved != row['resolved_target'] or \
           head != row['expected_head'] or not os.path.isdir(path):
            raise ValueError('source link drift: ' + row['relative'])
        links.append({'relative': row['relative'], 'literal': literal,
                      'resolved': resolved, 'head': head})
    binding = file_row(root + '/control/g279-native-graph-env.json')
    if binding['sha256'] != packet['binding_sha256'] or binding['uid'] != 1000 or \
       binding['mode'] != 0o400 or binding['acl']:
        raise ValueError('binding identity drift')
    with open(root + '/control/g279-native-graph-env.json', 'rb') as f:
        binding_content = json.load(f)
    if binding_content['env_config_sha256'] != packet['new_config_sha256'] or \
       binding_content['local_env_file_sha256'] != packet['new_local_env_sha256'] or \
       binding_content['paths']['NANHAI_GZ02_NATIVE_PROJECT_ROOT'] != root:
        raise ValueError('binding contents drift')
    stage1_receipt = file_row(root + '/control/STAGE1-RECEIPT.json')
    if stage1_receipt['sha256'] != packet['stage1_receipt_sha256']:
        raise ValueError('stage1 receipt drift')
    lease = file_row(root + '/control/STAGE2-LEASE.json')
    receipt = file_row(root + '/control/STAGE2-RECEIPT.json')
    with open(root + '/control/STAGE2-LEASE.json') as f:
        lease_content = json.load(f)
    with open(root + '/control/STAGE2-RECEIPT.json') as f:
        receipt_content = json.load(f)
    if lease_content != {'schema': 'g279-stage2-lease-v1', 'nonce': packet['nonce'],
                         'packet_sha256': packet['packet_sha256']} or \
       receipt_content['status'] != 'STAGED_READBACK_ONLY' or \
       receipt_content['nonce'] != packet['nonce'] or \
       receipt_content['packet_sha256'] != packet['packet_sha256'] or \
       receipt_content['binding_sha256'] != packet['binding_sha256']:
        raise ValueError('lease or receipt content drift')
    expected_control = sorted([row['path'].split('/', 1)[1] for row in accepted['files']
                               if row['path'].startswith('control/')] +
                              ['STAGE1-LEASE.json', 'STAGE1-RECEIPT.json',
                               'STAGE2-LEASE.json', 'STAGE2-RECEIPT.json',
                               'g279-native-graph-env.json'])
    if sorted(os.listdir(root + '/control')) != expected_control or \
       os.path.lexists(root + '/control/STAGE2-QUARANTINE.json') or \
       os.listdir(root + '/staging') or os.listdir(root + '/tmp'):
        raise ValueError('control/staging/tmp inventory drift')
    result = {'schema': 'g279-stage2-independent-readonly-probe-v1',
              'status': 'PASS', 'host': os.uname().nodename, 'uid': os.getuid(),
              'nonce': packet['nonce'], 'directories': directories,
              'stage1_files': files, 'links': links, 'link_count': len(links),
              'parent_dirs': observed_dirs, 'binding': binding,
              'stage1_receipt': stage1_receipt, 'stage2_lease': lease,
              'stage2_receipt': receipt, 'lease_content': lease_content,
              'receipt_content': receipt_content, 'control_entries': expected_control,
              'quarantine_exists': False, 'remote_writes': 0, 'graph': False,
              'device': False, 'container': False, 'namespace': False}
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
