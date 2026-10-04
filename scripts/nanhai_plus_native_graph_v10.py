#!/usr/bin/env python3
"""G279 native Soong graph v10 isolated sibling candidate. Static check is safe.

No container or namespace sandbox is used. The separate seccomp guard is only
host-tool smoke-tested. --run requires external EVO19 and original-owner gates.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

CONFIG_SHA = 'a4e742576589390209188cddf8d3278c294d9e87e8e9c4733e15eee0a951ddba'
BINDING_SHA = '9157f7d3e719c2fe1d2186bb79095500572049c4b7a3bc8d3befbdb98d47ae2f'
INDEX_SHA = '039f72bb0f25b6c611bd85874e0c3446449faaac2790cc9a6b56585f43f98d79'
BINARY_SHA = '92d62e59e154846535684d339657b7305ad7186aaa795bfee89a81b500901624'
GENERATOR_SHA = 'dafbc416c2b036ea8816591f408b24a8a99974827302968041474d54ef550634'
LEDGER_SHA = 'fe22e645511647b6b34dd83f5c0573ef1f8d45eaf380ac08b12c5120d1e13356'
MANIFEST_SHA = '19db4af44aa74ea4ed07bf602f5805476bab1c821d59ba818031022280ae055f'
GUARD_SHA = '04c24a88e2eb292b669a7c1fae0b42e9e9e3b0d66fa6dd0bf6e901ec7367df20'
GO_VERSION_SHA = '4407ffecd5b7e06b4f47ac38e68dcca9fc13dd173cc71a5cb228605f328af988'
GO_EXEC_SHA = '467614dc12ce73e28cc9aa8d28bdef259ada3bcc4392f205aaaed6fff44d8cab'
GO_VERSION_TEXT = 'go1.24.1\ntime 2025-02-27T17:57:18Z\n'
SMOKE_V3_SHA = '4068efdc4e516849223eae8ab6b7f94c71e889ebcbc9099592b134b36de34e9f'
SMOKE_V4_SHA = '1d9b5aad75f8847b6013a3cb39d1a3f81da5ea8a3ce03b4c705cedc14a1faec6'
SMOKE_PAIR_SHA = '65e1f034ac1d1cc98cd8e6ec08ba5012e4b27f2c16ed52ad79993434bbbfe071'
SOURCE_TARGET = Path('/data/source/aosp-16.0.0-r4')
# On gz02 this file is admitted under the project control directory. Bind that
# derived root to the frozen NANHAI_GZ02_NATIVE_PROJECT_ROOT before execution.
PROJECT_ROOT = Path(__file__).absolute().parents[1]
RUNNER_FILE = PROJECT_ROOT / 'control/nanhai_plus_native_graph_v10.py'
RELEASE_RUN_ID = 'g279-native-graph-v10-once'
def pinned_remote(project: Path) -> dict:
    source = Path('/opt/19.SourceCode/AOSP-16.0.0_r4/android-source')
    return {
        'interpreter': ('/usr/bin/python3.12', '8295ee25cfdb239f3e165afceda7f46de73e2b606ff0e2e3d8623e3facd30acc'),
        'binding': (str(project / 'control/g279-native-graph-env.json'), BINDING_SHA),
        'index': ('/opt/19.SourceCode/SOURCES.json', INDEX_SHA),
        'ui': (str(project / 'out/soong-ui-v1/soong_ui'), BINARY_SHA),
        'guard': (str(project / 'out/no-namespace-guard-v1/no-namespace-exec'), GUARD_SHA),
        'generator': (str(project / 'control/generate_manifest_heads.py'), GENERATOR_SHA),
        'ledger': (str(project / 'control/MANIFEST-HEADS.tsv'), LEDGER_SHA),
        'manifest': (str(source / '.repo/manifests/default.xml'), MANIFEST_SHA),
        'go_version': (str(source / 'prebuilts/go/linux-x86/VERSION'), GO_VERSION_SHA),
        'go_executable': (str(source / 'prebuilts/go/linux-x86/bin/go'), GO_EXEC_SHA),
    }
REQUIRED_BINDINGS = {'NANHAI_SOURCE_POOL_ROOT', 'NANHAI_GZ02_AOSP_SOURCE_ROOT',
                     'NANHAI_GZ02_SOONG_WORKTREE', 'NANHAI_GZ02_NATIVE_PROJECT_ROOT',
                     'NANHAI_GZ02_SOONG_UI', 'NANHAI_GZ02_NATIVE_SOURCE_VIEW'}
FORBIDDEN = {'docker', 'podman', 'nerdctl', 'buildah', 'runc', 'crun', 'nsjail',
             'proot', 'chroot', 'unshare', 'bwrap', 'bubblewrap', 'firejail', 'systemd-nspawn'}
GOALS = ['libc', 'libm', 'libdl', 'linker']
TRACE_SYSCALLS = 'execve,execveat,clone,clone3,unshare,setns,mount,umount2,pivot_root,chroot,open_tree,move_mount,fsopen,fsconfig,fsmount,mount_setattr'


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, **kw)


def load_bindings() -> dict:
    # The only immutable path seed is the project-owned staged control directory.
    # It must agree with the one authoritative frozen local_env binding.
    seed = Path('/data/source/.nanhai-plus-opaleye-native-v7/control/g279-native-graph-env.json')
    if not seed.is_file() or seed.is_symlink() or digest(seed) != BINDING_SHA:
        raise ValueError('frozen environment binding missing or drifted')
    binding = json.loads(seed.read_text())
    if binding.get('schema') != 'nanhai-g279-native-graph-env-v1' or binding.get('env_config_sha256') != CONFIG_SHA:
        raise ValueError('frozen environment schema/config drift')
    paths = binding.get('paths')
    if not isinstance(paths, dict) or set(paths) != REQUIRED_BINDINGS:
        raise ValueError('frozen environment variable set drift')
    if Path(paths['NANHAI_GZ02_NATIVE_PROJECT_ROOT']) / 'control/g279-native-graph-env.json' != seed:
        raise ValueError('project control binding mismatch')
    if os.uname().nodename.split('.')[0].casefold() != 'gz02' or sys.platform != 'linux' or os.uname().machine != 'x86_64':
        raise ValueError('wrong native host')
    return paths


def paths_from_binding(b: dict) -> dict:
    project = Path(b['NANHAI_GZ02_NATIVE_PROJECT_ROOT'])
    source = Path(b['NANHAI_GZ02_AOSP_SOURCE_ROOT'])
    pool = Path(b['NANHAI_SOURCE_POOL_ROOT'])
    worktree = Path(b['NANHAI_GZ02_SOONG_WORKTREE'])
    ui = Path(b['NANHAI_GZ02_SOONG_UI'])
    view = Path(b['NANHAI_GZ02_NATIVE_SOURCE_VIEW'])
    if source != pool / 'AOSP-16.0.0_r4/android-source' or source.resolve(strict=True) != SOURCE_TARGET:
        raise ValueError('source pool alias drift')
    if worktree != pool / 'AOSP-16.0.0_r4/worktrees/opaleye-soong-no-container':
        raise ValueError('Soong worktree binding drift')
    if project.resolve(strict=True) != project or ui != project / 'out/soong-ui-v1/soong_ui' or view != project / 'source-view':
        raise ValueError('project/UI output binding drift')
    if project == SOURCE_TARGET or SOURCE_TARGET in project.parents or project in SOURCE_TARGET.parents:
        raise ValueError('project and shared checkout overlap')
    return {'project': project, 'source': SOURCE_TARGET, 'source_view_diagnostic': view, 'source_alias': source, 'index': pool / 'SOURCES.json',
            'worktree': worktree, 'ui': ui, 'control_inputs': project / 'control',
            'out': project / 'out/g279-native-graph-v10', 'tmp': project / 'tmp/g279-native-graph-v10',
            'control': project / 'control/g279-native-graph-v10',
            'goroot': source / 'prebuilts/go/linux-x86',
            'guard': project / 'out/no-namespace-guard-v1/no-namespace-exec'}


def file_identity(p: dict) -> list[str]:
    checks = [(p['index'], INDEX_SHA), (p['ui'], BINARY_SHA),
              (p['control_inputs'] / 'generate_manifest_heads.py', GENERATOR_SHA),
              (p['control_inputs'] / 'MANIFEST-HEADS.tsv', LEDGER_SHA),
              (p['control_inputs'] / 'g279-native-graph-env.json', BINDING_SHA),
              (p['guard'], GUARD_SHA), (p['source'] / '.repo/manifests/default.xml', MANIFEST_SHA),
              (p['goroot'] / 'VERSION', GO_VERSION_SHA), (p['goroot'] / 'bin/go', GO_EXEC_SHA)]
    result = []
    for path, expected in checks:
        if not path.is_file() or path.is_symlink() or digest(path) != expected:
            raise ValueError('required input drift: ' + str(path))
        result.append(str(path))
    if p['goroot'].resolve(strict=True) != p['source'] / 'prebuilts/go/linux-x86':
        raise ValueError('GOROOT source alias target drift')
    if (p['goroot'] / 'VERSION').stat().st_size != 35 or (p['goroot'] / 'bin/go').stat().st_size != 14314606:
        raise ValueError('Go prebuilt size drift')
    if (p['goroot'] / 'VERSION').read_text() != GO_VERSION_TEXT:
        raise ValueError('Go VERSION content drift')
    for name in ('generate_manifest_heads.py', 'MANIFEST-HEADS.tsv', 'g279-native-graph-env.json'):
        path = p['control_inputs'] / name
        if path.stat().st_mode & 0o222:
            raise ValueError('staged input is writable: ' + name)
    stage2_identity(p)
    return result


def validate_stage2_records(records: dict) -> None:
    """Pure content gate used by remote preflight and local negative fixtures."""
    nonce = '6f324a6cb4e1a5fe8ec594334c61d079'
    packet_sha = 'e8581d9366477911cb9da05ccff6d60e32beaa3cddc6bc60c7a556a758fea371'
    lease, receipt = records['STAGE2-LEASE.json'], records['STAGE2-RECEIPT.json']
    if lease != {'schema': 'g279-stage2-lease-v1', 'nonce': nonce, 'packet_sha256': packet_sha} or \
       receipt.get('schema') != 'g279-sibling-stage2-remote-receipt-v1' or \
       receipt.get('nonce') != nonce or receipt.get('packet_sha256') != packet_sha or \
       receipt.get('status') != 'STAGED_READBACK_ONLY' or receipt.get('links') != 46 or \
       receipt.get('binding_sha256') != BINDING_SHA or receipt.get('graph') is not False or \
       receipt.get('container') is not False or receipt.get('namespace') is not False:
        raise ValueError('stage2 receipt content drift')


def stage2_identity(p: dict) -> dict:
    """Verify the already-staged stage-2 records without changing graph TOP."""
    root, control = p['project'], p['project'] / 'control'
    for path, expected in ((root, (64785, 47185921, 1000, 0o755)),
                           (control, (64785, 47185922, 1000, 0o700)),
                           (root / 'source-view', (64785, 47185940, 1000, 0o755))):
        st = path.lstat()
        if not stat.S_ISDIR(st.st_mode) or (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode)) != expected:
            raise ValueError('stage2 directory identity drift: ' + str(path))
    files = {
        'STAGE1-RECEIPT.json': (47185938, '5ad4c321bf68bd50d84642684736dba4c345de3906720d31a92be6032e2d4b20'),
        'STAGE2-LEASE.json': (47185939, '35e10f6aee932465a8976633455db5e2a78792edb9c659f925d35a364cda9aa6'),
        'STAGE2-RECEIPT.json': (47186009, '31c491700ad81e464666794f451e087594629d16b472e6af143dcde19f71a259'),
        'g279-native-graph-env.json': (47186008, BINDING_SHA),
    }
    records = {}
    for name, (inode, expected_sha) in files.items():
        path = control / name
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode)) != (64785, inode, 1000, 0o400) or digest(path) != expected_sha:
            raise ValueError('stage2 control identity drift: ' + name)
        records[name] = json.loads(path.read_text())
    validate_stage2_records(records)
    # Stage2's source-view is a migration diagnostic. Native Soong TOP stays
    # the complete, separately guarded R4 checkout bound by source_alias.
    return {'stage2_receipt_sha256': files['STAGE2-RECEIPT.json'][1],
            'source_view_diagnostic_only': True, 'graph_top': str(p['source_alias'])}


def ledger_projects(p: dict) -> list[str]:
    with (p['control_inputs'] / 'MANIFEST-HEADS.tsv').open(newline='') as f:
        rows = list(csv.DictReader(f, delimiter='\t'))
    if len(rows) != 1013 or len({r['path'] for r in rows}) != 1013:
        raise ValueError('manifest ledger cardinality drift')
    present = [r['path'] for r in rows if r['state'] == 'present_clean_r4']
    absent = [r['path'] for r in rows if r['state'] == 'absent_manifest_project']
    if len(present) != 1011 or sorted(absent) != ['prebuilts/clang/host/darwin-x86', 'prebuilts/go/darwin-x86']:
        raise ValueError('manifest ledger state drift')
    return present


def ownership(path: Path) -> dict:
    info = path.stat()
    # Build UID/GID 65534 must not write shared paths. Others have no authority here.
    writable = bool(info.st_mode & stat.S_IWOTH or info.st_gid == 65534 and info.st_mode & stat.S_IWGRP or info.st_uid == 65534 and info.st_mode & stat.S_IWUSR)
    return {'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode), 'nobody_writable': writable}


def root_guard(p: dict, projects: list[str]) -> dict:
    root = p['source']
    manifest = ET.parse(root / '.repo/manifests/default.xml').getroot()
    links = []
    for project in manifest.findall('project'):
        base = project.get('path', project.get('name'))
        for item in project.findall('linkfile'):
            src, dest = item.get('src'), item.get('dest')
            if not src or not dest or Path(src).is_absolute() or Path(dest).is_absolute() or '..' in Path(dest).parts:
                raise ValueError('unsafe manifest linkfile entry')
            destination = root / dest
            target = root / base / src
            if not destination.is_symlink() or destination.resolve(strict=True) != target.resolve(strict=True):
                raise ValueError('manifest linkfile target drift: ' + dest)
            links.append({'destination': dest, 'readlink': os.readlink(destination), 'target': str(target.relative_to(root)), 'sha256': digest(destination)})
    if len(links) != 10 or len({x['destination'] for x in links}) != 10:
        raise ValueError('manifest linkfile count drift')
    expected_top = {x.split('/')[0] for x in projects} | {x['destination'].split('/')[0] for x in links} | {'.repo', 'out', '.repo.failed-google-20260808T003450Z'}
    actual_top = {x.name for x in root.iterdir()}
    if actual_top != expected_top:
        raise ValueError('root topology drift: ' + repr(sorted(actual_top ^ expected_top)))
    exclusions = {}
    for name in ('out', '.repo.failed-google-20260808T003450Z'):
        path = root / name
        if not path.is_dir() or path.is_symlink():
            raise ValueError('root exclusion changed: ' + name)
        exclusions[name] = ownership(path)
        if exclusions[name]['nobody_writable']:
            raise ValueError('build UID could write excluded root: ' + name)
    marker = root / 'out/.out-dir'
    if not marker.is_file() or marker.is_symlink():
        raise ValueError('legacy out prune marker absent')
    root_owner = ownership(root)
    if root_owner['nobody_writable']:
        raise ValueError('build UID could write shared root')
    return {'links': sorted(links, key=lambda x: x['destination']), 'top_names': sorted(actual_top),
            'root_ownership': root_owner, 'exclusions': exclusions, 'out_prune_marker_sha256': digest(marker)}


def untracked_guard(p: dict, projects: list[str]) -> dict:
    def one(rel: str):
        path = p['source'] / rel
        if ownership(path)['nobody_writable']:
            raise ValueError('build UID could write shared project: ' + rel)
        ordinary = run(['git', '-C', str(path), 'ls-files', '--others', '--exclude-standard', '-z'])
        ignored = run(['git', '-C', str(path), 'ls-files', '--others', '--ignored', '--exclude-standard', '-z'])
        if ordinary.returncode or ignored.returncode:
            raise ValueError('untracked scan failed: ' + rel)
        if ordinary.stdout or ignored.stdout:
            raise ValueError('untracked source paths present: ' + rel)
        return rel
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        checked = list(executor.map(one, projects))
    return {'checked_projects': len(checked), 'ordinary': 0, 'ignored': 0, 'clean': True}


def source_guard(label: str, p: dict, projects: list[str]) -> dict:
    proc = run([sys.executable, str(p['control_inputs'] / 'generate_manifest_heads.py')], cwd=p['source'], timeout=360)
    (p['control'] / (label + '-ledger.tsv')).write_bytes(proc.stdout)
    (p['control'] / (label + '-ledger.stderr')).write_bytes(proc.stderr)
    root = root_guard(p, projects)
    untracked = untracked_guard(p, projects)
    actual = hashlib.sha256(proc.stdout).hexdigest()
    return {'generator_rc': proc.returncode, 'ledger_sha256': actual, 'root': root, 'untracked': untracked,
            'accepted': proc.returncode == 0 and actual == LEDGER_SHA and untracked['clean']}


def child_tree() -> set[int]:
    """Find every current descendant, including orphans adopted by the subreaper."""
    parents = {}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            raw = (entry / 'stat').read_text()
            # The second field may contain spaces or ')'; use its final terminator.
            fields = raw[raw.rfind(')') + 2:].split()
            parents[int(entry.name)] = int(fields[1])
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError):
            continue
    found = set()
    frontier = {os.getpid()}
    while frontier:
        next_level = {pid for pid, parent in parents.items() if parent in frontier and pid not in found}
        found |= next_level
        frontier = next_level
    return found


def reap_tree(process: subprocess.Popen | None, abnormal: bool) -> dict:
    """Bounded kill/reap on every path; refuse post-guard while children survive."""
    if process is None:
        return {'remaining': [], 'terminated': [], 'process_returncode': None}
    killed = set()
    if abnormal:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + (10 if abnormal else 3)
    while True:
        descendants = child_tree()
        if not descendants:
            break
        if time.monotonic() >= deadline:
            for pid in descendants:
                try:
                    os.kill(pid, signal.SIGKILL)
                    killed.add(pid)
                except ProcessLookupError:
                    pass
            break
        if abnormal:
            for pid in descendants:
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed.add(pid)
                except ProcessLookupError:
                    pass
        time.sleep(0.1)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.wait(timeout=3)
    # Reap any adopted zombies and repeat until process-table proof is empty.
    for _ in range(30):
        try:
            while True:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
        except ChildProcessError:
            pass
        if not child_tree():
            break
        time.sleep(0.1)
    remaining = sorted(child_tree())
    return {'remaining': remaining, 'terminated': sorted(killed), 'process_returncode': process.returncode}


def graph_command(p: dict) -> tuple[list[str], dict]:
    """Exact Soong-only route. Seccomp is installed before the UI exec."""
    ui_argv = [str(p['ui']), '--make-mode', '--soong-only', '--skip-ninja', '--skip-soong-tests', *GOALS]
    if [Path(x).name for x in ui_argv if Path(x).name in FORBIDDEN]:
        raise ValueError('forbidden direct launcher')
    env = {
        'PATH': ':'.join((str(p['source'] / 'prebuilts/build-tools/linux-x86/bin'),
                          str(p['source'] / 'prebuilts/go/linux-x86/bin'), '/usr/bin', '/bin')),
        'HOME': str(p['tmp']), 'TMPDIR': str(p['tmp']), 'OUT_DIR': str(p['out']),
        'GOCACHE': str(p['tmp'] / 'go-cache'), 'GOPATH': str(p['tmp'] / 'gopath'),
        'LANG': 'C.UTF-8', 'USER': 'nobody', 'LOGNAME': 'nobody', 'SHELL': '/bin/bash',
        'TARGET_PRODUCT': 'aosp_arm64', 'TARGET_RELEASE': 'trunk_staging',
        'TARGET_BUILD_VARIANT': 'userdebug',
        'GOROOT': str(p['goroot']),
    }
    if any('\n' in k + v or '=' in k for k, v in env.items()):
        raise ValueError('invalid fixed build environment')
    argv = ['sudo', '-n', '-u', 'nobody', '--', '/usr/bin/env', '-i',
            *(k + '=' + v for k, v in env.items()), '/usr/bin/timeout',
            '--signal=TERM', '--kill-after=5s', '900s', '/usr/bin/strace',
            '-f', '-qq', '-e', 'trace=' + TRACE_SYSCALLS, '-o', str(p['out'] / 'syscalls.log'),
            str(p['guard']), *ui_argv]
    return argv, env


def execute_graph_candidate(p: dict) -> dict:
    """Dormant until independent review; always reap before source post-guard."""
    if ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise RuntimeError('cannot enable child subreaper')
    argv, environment = graph_command(p)
    child = None
    abnormal = True
    rc = None
    timed_out = False
    cleanup = None
    execution_error = None
    cancelled_signal = None
    previous = {}

    class CancelledBySignal(BaseException):
        pass

    def on_cancel(signum, _frame):
        nonlocal cancelled_signal
        cancelled_signal = signum
        raise CancelledBySignal(signum)

    # Python's default SIGTERM action bypasses finally. Intercept both normal
    # operator cancellation signals before a child exists, then restore them.
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, on_cancel)
    try:
        with (p['control'] / 'stdout.log').open('wb') as stdout, (p['control'] / 'stderr.log').open('wb') as stderr:
            child = subprocess.Popen(argv, cwd=p['source_alias'], stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                rc = child.wait(timeout=930)
                timed_out = rc in (124, 137)
                abnormal = timed_out or rc != 0
            except subprocess.TimeoutExpired:
                timed_out = True
                rc = 124
                abnormal = True
    except BaseException as error:
        execution_error = {'type': type(error).__name__, 'message': str(error)}
        abnormal = True
    finally:
        # A second TERM/INT during cleanup must not interrupt child reaping.
        for signum in previous:
            signal.signal(signum, signal.SIG_IGN)
        try:
            cleanup = reap_tree(child, abnormal=abnormal)
        except BaseException as error:
            cleanup = {'remaining': None, 'terminated': [], 'process_returncode': None,
                       'cleanup_error': {'type': type(error).__name__, 'message': str(error)}}
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    return {'argv': argv, 'environment': environment, 'rc': rc, 'timed_out': timed_out,
            'cleanup': cleanup, 'cancelled_signal': cancelled_signal,
            'execution_error': execution_error,
            'process_tree_clear': cleanup['remaining'] == [],
            'trace_path': str(p['out'] / 'syscalls.log')}


def trace_audit(p: dict) -> dict:
    path = p['out'] / 'syscalls.log'
    if not path.is_file() or path.stat().st_size == 0:
        return {'complete': False, 'reason': 'missing or empty strace log'}
    text = path.read_text(errors='replace')
    execs = re.findall(r'\bexecve(?:at)?\([^\n]*?"([^"\n]+)"', text)
    forbidden = [x for x in execs if Path(x).name in FORBIDDEN or Path(x).name.startswith('lxc-')]
    # A denied syscall attempt is still evidence of a generated or bootstrap route
    # that must be investigated; namespace creation may never be accepted.
    namespace = [line for line in text.splitlines() if re.search(r'\b(?:unshare|setns|mount|umount2|pivot_root|chroot|open_tree|move_mount|fsopen|fsconfig|fsmount|mount_setattr)\(', line)
                 or re.search(r'\bclone(?:3)?\([^\n]*CLONE_NEW', line)]
    target_tools = [x for x in execs if Path(x).name in {'clang', 'clang++', 'ld.lld', 'lld'}]
    return {'complete': bool(execs and str(p['ui']) in execs and not re.search(r'\bstrace:\s*(?:Process|ptrace|detach|error)', text)),
            'sha256': digest(path), 'exec_calls': len(execs), 'ui_observed': str(p['ui']) in execs,
            'forbidden_launchers': forbidden, 'namespace_attempt_lines': len(namespace),
            'namespace_attempt_digest': hashlib.sha256('\n'.join(namespace).encode()).hexdigest(),
            'target_tool_execs_observed': target_tools}


def graph_artifact_audit(p: dict, projects: list[str]) -> dict:
    ninja = p['out'] / 'soong/build.aosp_arm64.ninja'
    bp_list = p['out'] / '.module_paths/Android.bp.list'
    if not ninja.is_file() or ninja.stat().st_size == 0 or not bp_list.is_file() or bp_list.stat().st_size == 0:
        return {'graph_evidence_pass': False, 'reason': 'exact product Ninja or BP list absent/empty'}
    lines = [x.strip().removeprefix('./') for x in bp_list.read_text().splitlines() if x.strip()]
    if not lines or len(lines) != len(set(lines)) or any(x.startswith('/') or '..' in Path(x).parts for x in lines):
        return {'graph_evidence_pass': False, 'reason': 'BP list invalid'}
    actual = set(lines)
    expected = {'Android.bp'}
    for project in projects:
        cmd = run(['git', '-C', str(p['source'] / project), 'ls-files', '-z', '--', '*Android.bp'])
        if cmd.returncode:
            raise RuntimeError('BP coverage inventory failed: ' + project)
        for item in cmd.stdout.split(b'\0'):
            if item and (item == b'Android.bp' or item.endswith(b'/Android.bp')):
                expected.add(project + '/' + os.fsdecode(item))
    missing = sorted(expected - actual)
    suspicious = []
    with ninja.open(errors='replace') as f:
        for line_no, line in enumerate(f, 1):
            if re.search(r'(?<![A-Za-z0-9_])(?:nsjail|bwrap|bubblewrap|unshare|docker|podman|runc)(?![A-Za-z0-9_])', line):
                suspicious.append(line_no)
                if len(suspicious) >= 100:
                    break
    return {'graph_evidence_pass': not missing, 'ninja_sha256': digest(ninja), 'ninja_bytes': ninja.stat().st_size,
            'bp_list_sha256': digest(bp_list), 'bp_list_rows': len(lines), 'expected_tracked_bp': len(expected),
            'missing_tracked_bp_count': len(missing), 'missing_tracked_bp_sample': missing[:20],
            'generated_action_audit_status': 'LEXICAL_SCREEN_ONLY_NO_TARGET_AUTHORIZATION',
            'suspicious_ninja_lines': suspicious, 'target_ninja_execution_authorized': False}


def write_once(directory: Path, name: str, obj: dict) -> Path:
    """Persist a one-shot receipt without following a final symlink or replacing bytes."""
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError('receipt directory missing or symlinked')
    data = (json.dumps(obj, sort_keys=True, indent=2) + '\n').encode()
    fd_dir = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=fd_dir)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            # A partial receipt is itself a failed immutable artifact; never rewrite it.
            raise
        os.fsync(fd_dir)
    finally:
        os.close(fd_dir)
    return directory / name


def immutable_control_file(path: Path) -> tuple[bytes, dict]:
    """Read a project-control input through one fd; reject mutable identities."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o444 or before.st_uid != os.getuid():
            raise ValueError('control input type/mode/owner drift: ' + str(path))
        chunks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid')
        if any(getattr(before, key) != getattr(after, key) for key in fields):
            raise ValueError('control input changed during read: ' + str(path))
        data = b''.join(chunks)
        return data, {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(),
                      'bytes': len(data), 'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid}
    finally:
        os.close(fd)


def validate_release_packet(control: Path, runner: Path) -> dict:
    """Pure read-only dual-gate validation, also used by local fixtures."""
    if not control.is_absolute() or control.is_symlink() or control.resolve(strict=True) != control or \
       runner != control / 'nanhai_plus_native_graph_v10.py':
        raise ValueError('project control path binding drift')
    paths = {'runner': runner, 'outer': control / 'g279-native-graph-v10-outer-release.json',
             'owner': control / 'g279-native-graph-v10-owner-ack.json',
             'evo19': control / 'g279-native-graph-v10-EVO19-GATE.json'}
    raw, identities = {}, {}
    for name, path in paths.items():
        raw[name], identities[name] = immutable_control_file(path)
    outer, owner, gate = (json.loads(raw[name]) for name in ('outer', 'owner', 'evo19'))
    if set(outer) != {'schema', 'run_id', 'goal_id', 'claim', 'host', 'runner_path',
                      'runner_sha256', 'runner_bytes', 'runner_mode', 'env_config_sha256',
                      'binding_sha256', 'local_env_sha256', 'evo19_gate_sha256',
                      'evo19_wrapper_sha256', 'evo19_spec_sha256',
                      'intended_remote_argv', 'graph_only', 'target_compile_authorized',
                      'device_authorized'} or \
       outer['schema'] != 'nanhai-g279-graph-v7-outer-release-v1' or \
       outer['run_id'] != RELEASE_RUN_ID or outer['goal_id'] != 'goal_01' or \
       outer['claim'] != 'NP-MUSL16-ART-024' or outer['host'] != 'gz02' or \
       outer['runner_path'] != str(runner) or outer['runner_sha256'] != identities['runner']['sha256'] or \
       outer['runner_bytes'] != identities['runner']['bytes'] or outer['runner_mode'] != 0o444 or \
       outer['env_config_sha256'] != CONFIG_SHA or outer['binding_sha256'] != BINDING_SHA or \
       outer['evo19_gate_sha256'] != identities['evo19']['sha256'] or \
       not isinstance(outer['evo19_wrapper_sha256'], str) or len(outer['evo19_wrapper_sha256']) != 64 or \
       not isinstance(outer['evo19_spec_sha256'], str) or len(outer['evo19_spec_sha256']) != 64 or \
       outer['intended_remote_argv'] != ['/usr/bin/python3.12', '-B', str(runner), '--run'] or \
       outer['graph_only'] is not True or outer['target_compile_authorized'] is not False or \
       outer['device_authorized'] is not False:
        raise ValueError('outer graph release identity/intent drift')
    if set(owner) != {'schema', 'run_id', 'goal_id', 'claim', 'runner_sha256',
                      'outer_release_sha256', 'graph_only_ack', 'target_compile_ack'} or \
       owner['schema'] != 'nanhai-g279-graph-v7-original-owner-ack-v1' or \
       owner['run_id'] != RELEASE_RUN_ID or owner['goal_id'] != 'goal_01' or \
       owner['claim'] != 'NP-MUSL16-ART-024' or owner['runner_sha256'] != identities['runner']['sha256'] or \
       owner['outer_release_sha256'] != identities['outer']['sha256'] or \
       owner['graph_only_ack'] is not True or owner['target_compile_ack'] is not False:
        raise ValueError('original-owner graph ACK missing or mismatched')
    required = {'runner', 'interpreter', 'binding', 'index', 'ui', 'guard', 'generator',
                'ledger', 'manifest', 'go_version', 'go_executable'}
    pinned = pinned_remote(runner.parent.parent)
    expected, observed = gate.get('expected_remote_inputs'), gate.get('remote_rows')
    if gate.get('status') != 'STATIC_PREFLIGHT_MATCH_UNRELEASED' or \
       gate.get('outer_ssh_rc') != 0 or gate.get('remote_rc') != 0 or \
       gate.get('remote_host') != 'gz02' or gate.get('env_config_sha256') != CONFIG_SHA or \
       gate.get('local_env_sha256') != outer['local_env_sha256'] or \
       gate.get('remote_interpreter') != '/usr/bin/python3.12' or \
       gate.get('intended_remote_argv') != outer['intended_remote_argv'] or \
       gate.get('wrapper') != gate.get('expected_wrapper') or \
       not isinstance(gate.get('wrapper'), dict) or gate['wrapper'].get('sha256') != outer['evo19_wrapper_sha256'] or \
       gate.get('spec_sha256') != outer['evo19_spec_sha256'] or \
       not isinstance(gate.get('spec_sha256'), str) or len(gate['spec_sha256']) != 64 or \
       not isinstance(gate.get('remote_probe_sha256'), str) or len(gate['remote_probe_sha256']) != 64 or \
       gate.get('graph_executed') is not False or gate.get('target_compiled') is not False or \
       not isinstance(expected, list) or not isinstance(observed, list) or \
       len(expected) != len(observed) or {r.get('name') for r in expected} != required:
        raise ValueError('EVO19 receipt status or identity incomplete')
    for want, got in zip(expected, observed, strict=True):
        if any(got.get(k) != want.get(k) for k in ('name', 'path', 'sha256', 'bytes', 'mode')) or \
           got.get('stable') is not True or got.get('match') is not True:
            raise ValueError('EVO19 remote input readback mismatch')
        if want['name'] != 'runner' and (want['path'], want['sha256']) != pinned[want['name']]:
            raise ValueError('EVO19 remote input path/digest not independently pinned')
    row = next(r for r in observed if r['name'] == 'runner')
    if row['path'] != str(runner) or row['sha256'] != identities['runner']['sha256'] or \
       row['bytes'] != identities['runner']['bytes'] or row['mode'] != 0o444:
        raise ValueError('execution-adjacent runner identity mismatch')
    return {'schema': 'nanhai-g279-graph-v7-release-gate-v1', 'run_id': RELEASE_RUN_ID,
            'outer_sha256': identities['outer']['sha256'],
            'owner_ack_sha256': identities['owner']['sha256'],
            'evo19_gate_sha256': identities['evo19']['sha256'],
            'runner_sha256': identities['runner']['sha256'], 'graph_only': True}


def release_gate() -> dict:
    if sys.platform != 'linux' or os.uname().machine != 'x86_64' or os.uname().nodename.split('.')[0].casefold() != 'gz02':
        raise ValueError('wrong native host for graph release')
    if PROJECT_ROOT.resolve(strict=True) != PROJECT_ROOT or RUNNER_FILE != PROJECT_ROOT / 'control/nanhai_plus_native_graph_v10.py' or \
       Path(__file__).absolute() != RUNNER_FILE:
        raise ValueError('native project/runner path drift')
    if Path(load_bindings()['NANHAI_GZ02_NATIVE_PROJECT_ROOT']) != PROJECT_ROOT:
        raise ValueError('runner root differs from frozen project binding')
    return validate_release_packet(PROJECT_ROOT / 'control', RUNNER_FILE)


def reviewed_execution_candidate(release: dict) -> int:
    """Graph-only one-shot path after two independent release inputs validate."""
    result = {'schema': 'nanhai-native-graph-v7-result-candidate-v1',
              'at': datetime.now(timezone.utc).isoformat(), 'goal_id': 'goal_01',
              'claim': 'NP-MUSL16-ART-024', 'status': 'PREFLIGHT_FAILED',
              'graph_command_pass': False, 'graph_evidence_pass': False,
              'generated_action_audit_status': 'NOT_RUN', 'target_compile_pass': False,
              'device_commands': 0, 'container_commands': 0,
              'release_gate': release}
    p = None
    projects = None
    pre = None
    code = 4
    precontrol = None
    process_tree_clear = True  # No child exists before execute_graph_candidate.
    try:
        if sys.platform != 'linux' or os.uname().machine != 'x86_64' or os.uname().nodename.split('.')[0].casefold() != 'gz02':
            raise ValueError('wrong native host')
        precontrol = PROJECT_ROOT / 'control/g279-native-graph-v10-preflight'
        precontrol.mkdir(mode=0o700)  # Fixed fresh path; no reuse after any attempt.
        p = paths_from_binding(load_bindings())
        if any(x.exists() for x in (p['control'], p['out'], p['tmp'])):
            raise ValueError('fixed one-shot path already exists')
        p['control'].mkdir(mode=0o700)
        try:
            inputs = file_identity(p)
            projects = ledger_projects(p)
            result['preflight'] = {'passed': True, 'input_files': inputs, 'projects': len(projects)}
        except BaseException as error:
            result['preflight'] = {'passed': False, 'type': type(error).__name__, 'message': str(error)}
            raise
        for key in ('out', 'tmp'):
            setup = run(['sudo', '-n', 'install', '-d', '-o', 'nobody', '-g', 'nogroup', '-m', '0755', str(p[key])])
            if setup.returncode or ownership(p[key])['uid'] != 65534:
                raise RuntimeError('project output setup failed: ' + key)
        pre = source_guard('pre', p, projects)
        result['pre_guard'] = pre
        if not pre['accepted']:
            result['status'] = 'BLOCK_PRE_SOURCE_GUARD'
            code = 3
        else:
            if release_gate() != release:
                raise ValueError('release identity drift immediately before graph command')
            graph = execute_graph_candidate(p)
            process_tree_clear = graph['process_tree_clear']
            result['graph'] = graph
            if not process_tree_clear:
                raise RuntimeError('build process tree not proven empty')
            trace = trace_audit(p)
            artifacts = graph_artifact_audit(p, projects)
            result['trace'] = trace
            result['artifacts'] = artifacts
            result['graph_command_pass'] = graph['rc'] == 0 and not graph['timed_out'] and not graph['execution_error']
            result['graph_evidence_pass'] = bool(artifacts['graph_evidence_pass'] and trace['complete'] and
                                                 trace['ui_observed'] and not trace['forbidden_launchers'] and
                                                 trace['namespace_attempt_lines'] == 0 and
                                                 not trace['target_tool_execs_observed'])
            result['generated_action_audit_status'] = artifacts['generated_action_audit_status']
            result['target_tool_execs_observed'] = trace.get('target_tool_execs_observed', [])
            # This is a graph-only probe. Target compilation and generated Ninja execution
            # require a different, independently reviewed runner and cannot pass here.
            result['target_compile_pass'] = False
            result['status'] = 'GRAPH_TERMINAL'
            code = 0 if result['graph_command_pass'] and result['graph_evidence_pass'] else 2
    except BaseException as error:
        result['exception'] = {'type': type(error).__name__, 'message': str(error)}
        code = 4
    finally:
        if process_tree_clear and p is not None and projects is not None and pre is not None and p['control'].is_dir():
            try:
                post = source_guard('post', p, projects)
                result['post_guard'] = post
                result['guarded_source_unchanged'] = bool(post['accepted'] and post['root'] == pre['root'] and
                                                          post['untracked'] == pre['untracked'])
            except BaseException as error:
                result['guarded_source_unchanged'] = False
                result['post_guard_error'] = {'type': type(error).__name__, 'message': str(error)}
        if code == 0 and result.get('guarded_source_unchanged') is not True:
            code = 5
        result['runner_exit_code'] = code
        # One authoritative terminal receipt only. The outer wrapper must record
        # SSH rc and remote rc in the separate EVO19 gate before this path can run.
        if precontrol is not None and precontrol.is_dir():
            try:
                write_once(precontrol, 'RESULT.json', result)
            except BaseException as error:
                print(json.dumps({'status': 'FAIL_CLOSED_RECEIPT_WRITE',
                                  'error': str(error), 'graph_acceptance': False}), file=sys.stderr)
                code = 7
        else:
            print(json.dumps(result, sort_keys=True), flush=True)
    return code


def static_check() -> int:
    here = Path(__file__).resolve().parents[1]
    candidate = here / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/private-sibling-migration-candidate-v1/stage2-candidate-v2'
    packet = candidate / 'PACKET.json'
    binding = candidate / 'g279-native-graph-env.proposed.json'
    proposed = candidate / 'local_env.proposed.md'
    if digest(packet) != 'f760bf560d2eb3f7aaf8076c24ea866337e3211df7dd1b2bf59d1832737613d7' or \
       digest(binding) != BINDING_SHA or \
       digest(proposed) != '5fefb4ca26c218683df175452495b86a19b53e69168727adccd7eb365b22d35c':
        raise ValueError('stage2 local frozen inputs drift')
    x = json.loads(packet.read_text())
    if x.get('new_root') != str(PROJECT_ROOT) or x.get('new_config_sha256') != CONFIG_SHA or \
       x.get('binding_sha256') != BINDING_SHA or len(x.get('links', [])) != 46:
        # Local candidate runs outside remote root; compare to its declared seed instead.
        if x.get('new_root') != '/data/source/.nanhai-plus-opaleye-native-v7' or \
           x.get('new_config_sha256') != CONFIG_SHA or x.get('binding_sha256') != BINDING_SHA or len(x.get('links', [])) != 46:
            raise ValueError('stage2 packet values drift')
    print(json.dumps({'status': 'STATIC_CANDIDATE_ONLY', 'runner_sha256': digest(Path(__file__)),
                      'source_view': x['new_root'] + '/source-view', 'links': 46,
                      'stage2_packet_sha256': digest(packet), 'graph_execution': False,
                      'remote_write': False, 'device': False, 'container': False, 'namespace': False}, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--static-check', action='store_true')
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    if args.static_check == args.run:
        parser.error('choose exactly one of --static-check or --run')
    if args.static_check:
        return static_check()
    # Candidate code remains unreachable until a separate reviewed release revives it.
    print(json.dumps({'status': 'NO_GO_V10_UNRELEASED', 'graph_execution': False, 'target_compile_commands': 0, 'device_commands': 0}), file=sys.stderr)
    return 3
    try:
        release = release_gate()
    except BaseException as error:
        print(json.dumps({'status': 'NO_GO_GRAPH_RELEASE_GATE',
                          'error': {'type': type(error).__name__, 'message': str(error)},
                          'runner_sha256': digest(Path(__file__)), 'graph_execution': False,
                          'target_compile_commands': 0, 'device_commands': 0}), file=sys.stderr)
        return 3
    return reviewed_execution_candidate(release)


if __name__ == '__main__':
    raise SystemExit(main())
