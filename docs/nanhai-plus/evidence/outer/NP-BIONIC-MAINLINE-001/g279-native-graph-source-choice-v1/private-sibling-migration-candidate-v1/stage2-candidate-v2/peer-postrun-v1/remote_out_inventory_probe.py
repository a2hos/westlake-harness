"""Read-only check that stage-2 left the pre-existing tool out tree intact."""
import json
import os
import stat
import sys

ROOT = '/data/source/.nanhai-plus-opaleye-native-v7'
if sys.platform != 'linux' or os.uname().nodename.split('.')[0].casefold() != 'gz02' or \
   os.getuid() != 1000:
    raise ValueError('wrong host')
if os.path.realpath(ROOT) != ROOT:
    raise ValueError('project root symlink')
expected = {'': ['no-namespace-guard-v1', 'soong-ui-v1'],
            'no-namespace-guard-v1': ['no-namespace-exec'],
            'soong-ui-v1': ['soong_ui']}
actual = {}
for relative, names in expected.items():
    path = ROOT + '/out' + ('/' + relative if relative else '')
    actual[relative] = sorted(os.listdir(path))
    if actual[relative] != names:
        raise ValueError('out inventory drift: ' + relative)
    mode = os.stat(path, follow_symlinks=False).st_mode
    if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) != 0o755:
        raise ValueError('out directory mode drift')
for relative in ('no-namespace-guard-v1/no-namespace-exec', 'soong-ui-v1/soong_ui'):
    path = ROOT + '/out/' + relative
    mode = os.stat(path, follow_symlinks=False).st_mode
    if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o555:
        raise ValueError('out tool mode drift')
print(json.dumps({'schema': 'g279-stage2-out-inventory-v1', 'status': 'PASS',
                  'actual': actual, 'remote_writes': 0, 'graph': False,
                  'device': False, 'container': False, 'namespace': False}, sort_keys=True))
