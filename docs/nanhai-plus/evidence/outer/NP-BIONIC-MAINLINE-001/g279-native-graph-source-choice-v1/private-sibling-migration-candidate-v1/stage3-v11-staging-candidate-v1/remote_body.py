"""One-shot exact v11 file staging under accepted G279 sibling; no graph."""
import hashlib
import json
import os
import stat
import sys

EXPECTED_UID = 1000


def sha(data):
    return hashlib.sha256(data).hexdigest()


def enc(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def directory(path, mode):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    s = os.fstat(fd)
    ident = {'dev': s.st_dev, 'ino': s.st_ino, 'uid': s.st_uid,
             'mode': stat.S_IMODE(s.st_mode)}
    if ident['uid'] != EXPECTED_UID or ident['mode'] != mode or any(
            n.startswith('system.posix_acl_') for n in os.listxattr(fd)):
        os.close(fd)
        raise ValueError('directory identity/ACL drift: ' + path)
    return fd, ident


def regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or any(
                n.startswith('system.posix_acl_') for n in os.listxattr(fd)):
            raise ValueError('input type/ACL drift: ' + path)
        h = hashlib.sha256()
        size = 0
        while True:
            part = os.read(fd, 1048576)
            if not part:
                break
            h.update(part)
            size += len(part)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns, before.st_mode) != \
           (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns, after.st_mode):
            raise ValueError('input changed during hash: ' + path)
        return {'dev': after.st_dev, 'ino': after.st_ino, 'uid': after.st_uid,
                'gid': after.st_gid, 'mode': stat.S_IMODE(after.st_mode),
                'bytes': size, 'sha256': h.hexdigest()}
    finally:
        os.close(fd)


def exclusive(fd, name, data, mode):
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                  mode, dir_fd=fd)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(out, data[offset:])
        os.fchmod(out, mode)
        os.fsync(out)
    finally:
        os.close(out)
    os.fsync(fd)


def host_guard():
    if sys.platform != 'linux' or os.uname().nodename.split('.')[0].casefold() != 'gz02' or \
       os.uname().machine != 'x86_64' or os.getuid() != 1000 or os.geteuid() != 1000:
        raise ValueError('wrong host/UID')


ROOT = '/data/source/.nanhai-plus-opaleye-native-v7'
OLD = '/data/source/.nanhai-plus-opaleye-native'


def stage(packet, runner_bytes):
    unsigned = dict(packet)
    claimed = unsigned.pop('packet_sha256')
    if packet.get('schema') != 'g279-stage3-v11-staging-packet-v1' or \
       sha(enc(unsigned)) != claimed or \
       sha(runner_bytes) != packet['runner']['sha256'] or \
       len(runner_bytes) != packet['runner']['bytes']:
        raise ValueError('packet/runner identity drift')
    host_guard()
    if packet['root'] != ROOT or packet['old_root'] != OLD or \
       packet['runner']['name'] != 'nanhai_plus_native_graph_v11.py' or \
       packet['runner']['mode'] != 0o444:
        raise ValueError('root/runner path drift')
    root_fd, root_id = directory(ROOT, 0o755)
    control_fd, control_id = directory(ROOT + '/control', 0o700)
    old_fd, old_id = directory(OLD, 0o775)
    created = False
    try:
        if os.path.realpath(ROOT) != ROOT or os.path.realpath(OLD) != OLD or \
           root_id != packet['root_id'] or control_id != packet['control_id'] or \
           old_id != packet['old_root_id']:
            raise ValueError('accepted directory inode drift')
        if sorted(os.listdir(ROOT)) != ['control', 'out', 'source-view', 'staging', 'tmp']:
            raise ValueError('sibling shape drift')
        if os.path.lexists(ROOT + '/control/' + packet['runner']['name']) or \
           os.path.lexists(ROOT + '/control/STAGE3-V11-LEASE.json') or \
           os.path.lexists(ROOT + '/control/STAGE3-V11-RECEIPT.json'):
            raise FileExistsError('v11 staging already attempted')
        for spec in packet['unchanged_files']:
            if regular(ROOT + '/' + spec['path']) != spec['identity']:
                raise ValueError('stage1/2 staged input drift: ' + spec['path'])
        view_fd, view_id = directory(ROOT + '/source-view', 0o755)
        os.close(view_fd)
        if view_id != packet['source_view_id']:
            raise ValueError('accepted source-view inode drift')
        if len(packet['unchanged_files']) != 14:
            raise ValueError('stage1/2 input inventory count')
        created = True
        exclusive(control_fd, 'STAGE3-V11-LEASE.json', enc({
            'schema': 'g279-stage3-v11-lease-v1', 'nonce': packet['nonce'],
            'packet_sha256': claimed}), 0o400)
        exclusive(control_fd, packet['runner']['name'], runner_bytes, 0o444)
        runner_id = regular(ROOT + '/control/' + packet['runner']['name'])
        if runner_id['sha256'] != packet['runner']['sha256'] or \
           runner_id['bytes'] != packet['runner']['bytes'] or \
           runner_id['mode'] != 0o444 or runner_id['uid'] != EXPECTED_UID:
            raise ValueError('v11 runner readback drift')
        later = []
        try:
            later = [directory(ROOT, 0o755), directory(ROOT + '/control', 0o700),
                     directory(OLD, 0o775)]
            stable = [item[1] for item in later] == [root_id, control_id, old_id]
        finally:
            for item in later:
                os.close(item[0])
        if not stable:
            raise ValueError('directory replaced after stage')
        for spec in packet['unchanged_files']:
            if regular(ROOT + '/' + spec['path']) != spec['identity']:
                raise ValueError('stage1/2 input changed after stage')
        receipt = {'schema': 'g279-stage3-v11-remote-receipt-v1',
                   'status': 'STAGED_READBACK_ONLY', 'nonce': packet['nonce'],
                   'packet_sha256': claimed, 'runner': runner_id,
                   'root_id': root_id, 'control_id': control_id,
                   'old_root_id': old_id, 'source_view_id': view_id,
                   'binding_changed': False, 'graph': False, 'target': False,
                   'device': False, 'container': False, 'namespace': False}
        exclusive(control_fd, 'STAGE3-V11-RECEIPT.json', enc(receipt), 0o400)
        return receipt
    except BaseException as error:
        if created:
            try:
                exclusive(control_fd, 'STAGE3-V11-QUARANTINE.json', enc({
                    'schema': 'g279-stage3-v11-quarantine-v1', 'nonce': packet['nonce'],
                    'error': type(error).__name__ + ': ' + str(error),
                    'no_auto_delete': True, 'replay_allowed': False}), 0o400)
            except BaseException:
                pass
        raise
    finally:
        os.close(old_fd)
        os.close(control_fd)
        os.close(root_fd)


if __name__ == '__main__':
    print(json.dumps(stage(PACKET, RUNNER_BYTES), sort_keys=True))
