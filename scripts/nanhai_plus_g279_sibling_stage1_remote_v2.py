"""G279 stage-1 remote body. Sent over SSH stdin; never imports project code.

Stage 1 copies seven pinned control files and two pinned ELF files into a new
private sibling. It does not change bindings, run tools, or touch the graph.
"""
import hashlib
import json
import os
import stat
import sys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def mode(fd):
    return stat.S_IMODE(os.fstat(fd).st_mode)


def identity(fd):
    s = os.fstat(fd)
    return {'dev': s.st_dev, 'ino': s.st_ino, 'uid': s.st_uid,
            'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode)}


def no_acl(fd):
    names = os.listxattr(fd)
    if any(n in ('system.posix_acl_access', 'system.posix_acl_default') for n in names):
        raise ValueError('POSIX ACL present')


def open_chain(path):
    if not path.startswith('/') or '//' in path or '/./' in path or '/../' in path:
        raise ValueError('noncanonical absolute path')
    parts = path.split('/')[1:]
    if any(not p or p in ('.', '..') for p in parts):
        raise ValueError('bad path component')
    fds = [os.open('/', os.O_RDONLY | os.O_DIRECTORY)]
    try:
        for part in parts:
            fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=fds[-1]))
        return fds
    except BaseException:
        for fd in reversed(fds):
            os.close(fd)
        raise


def close_chain(fds):
    for fd in reversed(fds):
        os.close(fd)


def read_fixed(directory, name, expected):
    if '/' in name or name in ('', '.', '..'):
        raise ValueError('bad file name')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        a = os.fstat(fd)
        if not stat.S_ISREG(a.st_mode) or a.st_uid != expected['uid'] or \
           stat.S_IMODE(a.st_mode) != expected['source_mode']:
            raise ValueError('source type/owner mismatch: ' + name)
        chunks = []
        while True:
            block = os.read(fd, 1048576)
            if not block:
                break
            chunks.append(block)
        b = os.fstat(fd)
        if (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns, a.st_mode) != \
           (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns, b.st_mode):
            raise ValueError('source changed during read: ' + name)
        data = b''.join(chunks)
        if len(data) != expected['bytes'] or sha(data) != expected['sha256']:
            raise ValueError('source bytes drift: ' + name)
        return data, identity(fd)
    finally:
        os.close(fd)


def exclusive_bytes(directory, name, data, file_mode):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 file_mode, dir_fd=directory)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        os.fchmod(fd, file_mode)
    finally:
        os.close(fd)
    os.fsync(directory)
    check = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        row = identity(check)
        if row['uid'] != os.getuid() or row['mode'] != file_mode:
            raise ValueError('new file identity mismatch: ' + name)
        chunks = []
        while True:
            block = os.read(check, 1048576)
            if not block:
                break
            chunks.append(block)
        if b''.join(chunks) != data:
            raise ValueError('new file readback mismatch: ' + name)
        row['sha256'] = sha(data)
        row['bytes'] = len(data)
        return row
    finally:
        os.close(check)


def mkdir_fixed(parent, name, required_mode, uid):
    os.mkdir(name, required_mode, dir_fd=parent)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    os.fchmod(fd, required_mode)
    row = identity(fd)
    no_acl(fd)
    if row['uid'] != uid or row['mode'] != required_mode:
        os.close(fd)
        raise ValueError('new directory identity mismatch: ' + name)
    os.fsync(parent)
    return fd


def json_bytes(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':')) + '\n').encode()


def stage(packet):
    unsigned = dict(packet)
    claimed = unsigned.pop('packet_sha256')
    if sha(json_bytes(unsigned)) != claimed:
        raise ValueError('packet digest mismatch')
    observed_host = os.uname().nodename.split('.')[0]
    if sys.platform != 'linux' or observed_host.casefold() != packet['host'].casefold():
        raise ValueError('wrong host')
    if os.getuid() != packet['uid'] or os.geteuid() != packet['uid'] or packet['uid'] == 0:
        raise ValueError('wrong UID')
    old = packet['old_root']
    new = packet['new_root']
    if old.rsplit('/', 1)[0] != new.rsplit('/', 1)[0] or old == new:
        raise ValueError('not a sibling')
    parent_path, new_name = new.rsplit('/', 1)
    if not new_name.startswith('.nanhai-plus-opaleye-native-v7'):
        raise ValueError('new root name not pinned')
    parents = open_chain(parent_path)
    old_chain = open_chain(old)
    root = None
    control = None
    out = None
    tmp = None
    staging = None
    created = False
    try:
        parent = parents[-1]
        parent_before = identity(parent)
        no_acl(parent)
        if parent_before['uid'] != packet['uid'] or parent_before['mode'] != 0o755:
            raise ValueError('parent owner/mode mismatch')
        old_before = identity(old_chain[-1])
        if old_before['uid'] != packet['uid']:
            raise ValueError('old root owner drift')
        try:
            os.stat(new_name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError('new root already exists; no replay')
        prepared = []
        for item in packet['files']:
            source_parts = item['source'].split('/')
            source_fds = [old_chain[-1]]
            try:
                for part in source_parts[:-1]:
                    source_fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                              dir_fd=source_fds[-1]))
                data, source_id = read_fixed(source_fds[-1], source_parts[-1], item)
            finally:
                for fd in reversed(source_fds[1:]):
                    os.close(fd)
            prepared.append((item, data, source_id))
        os.mkdir(new_name, 0o755, dir_fd=parent)
        created = True
        root = os.open(new_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                       dir_fd=parent)
        os.fchmod(root, 0o755)
        no_acl(root)
        if identity(root)['uid'] != packet['uid'] or mode(root) != 0o755:
            raise ValueError('new root identity mismatch')
        os.fsync(parent)
        control = mkdir_fixed(root, 'control', 0o700, packet['uid'])
        out = mkdir_fixed(root, 'out', 0o755, packet['uid'])
        tmp = mkdir_fixed(root, 'tmp', 0o755, packet['uid'])
        staging = mkdir_fixed(root, 'staging', 0o700, packet['uid'])
        lease = {'schema': 'g279-sibling-stage1-lease-v1', 'nonce': packet['nonce'],
                 'old_root': old, 'new_root': new, 'packet_sha256': packet['packet_sha256']}
        exclusive_bytes(control, 'STAGE1-LEASE.json', json_bytes(lease), 0o400)
        copied = []
        for item, data, source_id in prepared:
            dest = control if item['kind'] == 'control' else out
            dest_parts = item['dest'].split('/')
            child = dest
            children = []
            try:
                for part in dest_parts[:-1]:
                    child = mkdir_fixed(child, part, 0o755, packet['uid'])
                    children.append(child)
                new_id = exclusive_bytes(child, dest_parts[-1], data, item['dest_mode'])
            finally:
                for fd in reversed(children):
                    os.close(fd)
            copied.append({'source': item['source'], 'dest': item['dest'],
                           'kind': item['kind'], 'source_id': source_id, 'new_id': new_id})
        for item, data, source_id in prepared:
            source_parts = item['source'].split('/')
            source_fds = [old_chain[-1]]
            try:
                for part in source_parts[:-1]:
                    source_fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                              dir_fd=source_fds[-1]))
                later_data, later_id = read_fixed(source_fds[-1], source_parts[-1], item)
            finally:
                for fd in reversed(source_fds[1:]):
                    os.close(fd)
            if later_data != data or later_id != source_id:
                raise ValueError('source changed after copy: ' + item['source'])
        fresh_old = open_chain(old)
        try:
            old_named_same = identity(fresh_old[-1]) == old_before
        finally:
            close_chain(fresh_old)
        named_new = os.open(new_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
        try:
            new_named_same = identity(named_new) == identity(root)
        finally:
            os.close(named_new)
        if not old_named_same or not new_named_same or \
           identity(old_chain[-1]) != old_before or identity(parent) != parent_before:
            raise ValueError('old root or parent identity drift')
        receipt = {'schema': 'g279-sibling-stage1-remote-receipt-v1', 'status': 'STAGED_READBACK',
                   'nonce': packet['nonce'], 'new_root': new, 'new_root_id': identity(root),
                   'observed_host': observed_host,
                   'old_root_id': old_before, 'parent_id': parent_before, 'copied': copied,
                   'binding_changed': False, 'graph': False, 'device': False,
                   'container': False, 'namespace': False}
        exclusive_bytes(control, 'STAGE1-RECEIPT.json', json_bytes(receipt), 0o400)
        return receipt
    except BaseException as error:
        if created:
            marker = {'schema': 'g279-sibling-stage1-quarantine-v1', 'nonce': packet['nonce'],
                      'error': type(error).__name__ + ': ' + str(error),
                      'new_root': new, 'preserve_old_root': True,
                      'binding_changed': False, 'delete_automatically': False}
            target = control if control is not None else root
            try:
                exclusive_bytes(target, 'QUARANTINE.json', json_bytes(marker), 0o400)
            except BaseException:
                pass
        raise
    finally:
        for fd in (staging, tmp, out, control, root):
            if fd is not None:
                os.close(fd)
        close_chain(old_chain)
        close_chain(parents)


if __name__ == '__main__':
    # Launcher appends one pinned PACKET assignment before this call.
    try:
        result = stage(PACKET)
        print(json.dumps(result, sort_keys=True))
    except BaseException as error:
        print(json.dumps({'schema': 'g279-sibling-stage1-remote-error-v1',
                          'status': 'QUARANTINE_OR_PRECREATE_ABORT',
                          'error': type(error).__name__ + ': ' + str(error),
                          'graph': False, 'device': False, 'container': False}, sort_keys=True))
        sys.exit(23)
