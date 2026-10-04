"""One-shot G279 stage-2 source-view writer; stdin program has a frozen PACKET."""
import hashlib
import json
import os
import stat
import subprocess
import sys


def sha(b):
    return hashlib.sha256(b).hexdigest()


def encoded(x):
    return (json.dumps(x, sort_keys=True, separators=(',', ':')) + '\n').encode()


def checked_dir(path, uid, mode):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    s = os.fstat(fd)
    if s.st_uid != uid or stat.S_IMODE(s.st_mode) != mode or any(
        n.startswith('system.posix_acl_') for n in os.listxattr(fd)
    ):
        os.close(fd)
        raise ValueError('directory identity/ACL drift: ' + path)
    return fd, (s.st_dev, s.st_ino, s.st_uid, stat.S_IMODE(s.st_mode))


def exclusive(fd, name, data):
    child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o400, dir_fd=fd)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(child, data[offset:])
        os.fsync(child)
        os.fchmod(child, 0o400)
    finally:
        os.close(child)
    os.fsync(fd)


def source_check(row):
    target = row['symlink_target']
    if not target.startswith('/opt/19.SourceCode/AOSP-16.0.0_r4/'):
        raise ValueError('source alias outside registered R4')
    if os.path.realpath(target) != row['resolved_target'] or not os.path.isdir(target):
        raise ValueError('source path drift: ' + row['relative'])
    proc = subprocess.run(['/usr/bin/git', '-C', target, 'rev-parse', 'HEAD'],
                          capture_output=True, text=True, timeout=12)
    if proc.returncode or proc.stdout.strip() != row['expected_head']:
        raise ValueError('source HEAD drift: ' + row['relative'])


def run(packet):
    unsigned = dict(packet)
    claimed = unsigned.pop('packet_sha256')
    if sha(encoded(unsigned)) != claimed or packet['schema'] != 'g279-sibling-stage2-packet-v1':
        raise ValueError('packet identity')
    if sys.platform != 'linux' or os.uname().nodename.split('.')[0].casefold() != 'gz02' or \
       os.getuid() != 1000 or os.geteuid() != 1000:
        raise ValueError('host/UID')
    root = packet['new_root']
    old = packet['old_root']
    if root != '/data/source/.nanhai-plus-opaleye-native-v7' or \
       old != '/data/source/.nanhai-plus-opaleye-native':
        raise ValueError('root path')
    root_fd, root_id = checked_dir(root, 1000, 0o755)
    ctl_fd, ctl_id = checked_dir(root + '/control', 1000, 0o700)
    old_fd, old_id = checked_dir(old, 1000, 0o775)
    created = False
    try:
        if os.path.realpath(root) != root or os.path.realpath(old) != old:
            raise ValueError('project root ancestor symlink')
        if list(sorted(os.listdir(root))) != ['control', 'out', 'staging', 'tmp']:
            raise ValueError('stage1 tree shape drift')
        if os.path.lexists(root + '/source-view') or os.path.lexists(root + '/control/g279-native-graph-env.json') or \
           os.path.lexists(root + '/control/STAGE2-LEASE.json') or os.path.lexists(root + '/control/STAGE2-RECEIPT.json'):
            raise FileExistsError('stage2 already started or unexpected output')
        stage1_fd = os.open('STAGE1-RECEIPT.json', os.O_RDONLY | os.O_NOFOLLOW,
                            dir_fd=ctl_fd)
        try:
            if sha(os.read(stage1_fd, 1048576)) != packet['stage1_receipt_sha256']:
                raise ValueError('stage1 receipt drift')
        finally:
            os.close(stage1_fd)
        rows = packet['links']
        if len(rows) != 46 or len({r['relative'] for r in rows}) != 46:
            raise ValueError('link count/uniqueness')
        if [r['relative'] for r in rows] != sorted(r['relative'] for r in rows):
            raise ValueError('mapping order')
        for r in rows:
            rel = r['relative']
            if rel.startswith('/') or any(x in ('', '.', '..') for x in rel.split('/')):
                raise ValueError('relative path')
            source_check(r)
        created = True
        exclusive(ctl_fd, 'STAGE2-LEASE.json', encoded({'schema': 'g279-stage2-lease-v1',
                  'nonce': packet['nonce'], 'packet_sha256': claimed}))
        os.mkdir('source-view', 0o755, dir_fd=root_fd)
        new_view = os.open('source-view', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                           dir_fd=root_fd)
        os.fchmod(new_view, 0o755)
        os.close(new_view)
        os.fsync(root_fd)
        view_fd, _ = checked_dir(root + '/source-view', 1000, 0o755)
        try:
            made = set()
            for row in rows:
                parts = row['relative'].split('/')
                parent = view_fd
                opened = []
                try:
                    for index, part in enumerate(parts[:-1]):
                        key = '/'.join(parts[:index+1])
                        if key not in made:
                            os.mkdir(part, 0o755, dir_fd=parent)
                            made.add(key)
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                        dir_fd=parent)
                        os.fchmod(child, 0o755)
                        os.fsync(parent)
                        opened.append(child)
                        parent = child
                    os.symlink(row['symlink_target'], parts[-1], dir_fd=parent)
                    os.fsync(parent)
                finally:
                    for fd in reversed(opened):
                        os.close(fd)
            for row in rows:
                path = root + '/source-view/' + row['relative']
                if not os.path.islink(path) or os.readlink(path) != row['symlink_target']:
                    raise ValueError('link literal readback')
                source_check(row)
            observed = []
            observed_dirs = []
            for base, dirs, files in os.walk(root + '/source-view', followlinks=False):
                for name in files + dirs:
                    path = os.path.join(base, name)
                    if os.path.islink(path):
                        observed.append(os.path.relpath(path, root + '/source-view'))
                    elif os.path.isdir(path):
                        observed_dirs.append(os.path.relpath(path, root + '/source-view'))
                    else:
                        raise ValueError('non-link source-view file')
            expected_dirs = sorted({prefix for row in rows for prefix in (
                '/'.join(row['relative'].split('/')[:i])
                for i in range(1, len(row['relative'].split('/'))))})
            if sorted(observed) != [r['relative'] for r in rows]:
                raise ValueError('view link inventory drift')
            if sorted(observed_dirs) != expected_dirs:
                raise ValueError('view directory inventory drift')
        finally:
            os.close(view_fd)
        payload = bytes.fromhex(packet['binding_hex'])
        if sha(payload) != packet['binding_sha256']:
            raise ValueError('binding digest')
        binding = json.loads(payload)
        if binding['paths']['NANHAI_GZ02_NATIVE_PROJECT_ROOT'] != root or \
           binding['paths']['NANHAI_GZ02_NATIVE_SOURCE_VIEW'] != root + '/source-view' or \
           binding['paths']['NANHAI_GZ02_SOONG_UI'] != root + '/out/soong-ui-v1/soong_ui':
            raise ValueError('binding paths')
        exclusive(ctl_fd, 'g279-native-graph-env.json', payload)
        now_root, now_root_id = checked_dir(root, 1000, 0o755)
        now_old, now_old_id = checked_dir(old, 1000, 0o775)
        os.close(now_root)
        os.close(now_old)
        if now_root_id != root_id or now_old_id != old_id:
            raise ValueError('root identity drift')
        receipt = {'schema': 'g279-sibling-stage2-remote-receipt-v1',
                   'status': 'STAGED_READBACK_ONLY', 'nonce': packet['nonce'],
                   'packet_sha256': claimed, 'links': 46, 'root_id': root_id,
                   'control_id': ctl_id, 'old_id': old_id,
                   'binding_sha256': packet['binding_sha256'],
                   'binding_changed': False, 'graph': False, 'device': False,
                   'container': False, 'namespace': False}
        exclusive(ctl_fd, 'STAGE2-RECEIPT.json', encoded(receipt))
        return receipt
    except BaseException as e:
        if created:
            try:
                exclusive(ctl_fd, 'STAGE2-QUARANTINE.json', encoded({
                    'schema': 'g279-stage2-quarantine-v1', 'nonce': packet['nonce'],
                    'error': type(e).__name__ + ': ' + str(e),
                    'rollback': 'preserve partial tree; no automatic deletion',
                    'binding_changed': False}))
            except BaseException:
                pass
        raise
    finally:
        os.close(old_fd)
        os.close(ctl_fd)
        os.close(root_fd)


if __name__ == '__main__':
    print(json.dumps(run(PACKET), sort_keys=True))
