#!/usr/bin/env python3
"""Exact G276 two-root source guard; this module has no execution entry point."""
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(os.environ['NANHAI_PROJECT_ROOT']).resolve(strict=True)
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
INPUT = BASE / 'g276-two-r4-stock-input-candidate-v1/INPUT-CANDIDATE.json'
INPUT_SHA = 'a7585fae45b956f85db9272175bebe366f1a3e82d1f6959dd13031424751091e'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def candidate():
    need(sha(INPUT) == INPUT_SHA, 'G276 input candidate drift')
    value = json.loads(INPUT.read_bytes())
    need(value['goal_id'] == 'goal_01' and value['claim'] == 'NP-MUSL16-ART-024' and
         value['status'] == 'source-view-candidate-not-executable' and
         value['expected_stock_root_count_if_added_to_g275'] == 42 and
         len(value['roots']) == 2 and value['graph_executed'] is False and
         value['stock_linux_mount_verified'] is False, 'G276 input scope changed')
    predecessor = value['predecessor_g275_result']
    need(sha(ROOT / predecessor['path']) == predecessor['sha256'], 'G275 result drift')
    need([r['stock_root'] for r in value['roots']] == ['system/tools/hidl', 'system/apex'],
         'G276 stock roots changed')
    return value


def records(root):
    receipt = ROOT / root['source_receipt']
    need(sha(receipt) == root['source_receipt_sha256'], 'G276 source receipt drift')
    source = json.loads(receipt.read_bytes())
    manifest = receipt.parent / source['tracked_manifest']
    need(sha(manifest) == source['tracked_manifest_sha256'], 'G276 tracked manifest drift')
    with manifest.open(newline='') as stream:
        rows = list(csv.DictReader(stream, delimiter='\t'))
    need(len(rows) == root['entries'] and source['tracked_entries'] == root['entries'] and
         source['tracked_bytes'] == root['bytes'] and source['symlinks'] == root['symlinks'] and
         source['head'] == root['head'] and source['root_tree'] == root['tree'],
         'G276 source extent/identity drift')
    return rows, source, manifest


def static_plan(prior):
    prior.g275.static_plan(prior.extension)
    roots = candidate()['roots']
    old = json.loads((BASE / 'stock-bionic-target-graph-v19-g275-candidate-v1/MATERIALIZATION.json').read_bytes())
    new = json.loads((HERE / 'MATERIALIZATION.json').read_bytes())
    old_roots = old['readonly_root_mounts']
    added = [r['stock_root'] for r in roots]
    need(len(old_roots) == 40 and new['readonly_root_mounts'] == old_roots + added and
         len(set(new['readonly_root_mounts'])) == 42, 'G276 42-root plan changed')
    need({k: v for k, v in new.items() if k != 'readonly_root_mounts'} ==
         {k: v for k, v in old.items() if k != 'readonly_root_mounts'},
         'G276 private materialization payload changed')
    for root in added:
        need(not any(x == root or x.startswith(root + '/') or root.startswith(x + '/') for x in old_roots),
             'G276 stock root collision')
    prior.extension.module('g276_materializer_metadata', HERE / 'materialize.py').check_plan(new)
    return {'old_roots': 40, 'new_roots': added, 'total_roots': 42,
            'private_entries_unchanged': len(new['entries']), 'docker_commands': 0}


def full_guard(env):
    roots = candidate()['roots']
    pool = Path(env['NANHAI_SOURCE_POOL_ROOT']).resolve(strict=True)
    inputs = Path(env['NANHAI_INPUTS_ROOT']).resolve(strict=True)
    need(inputs.is_relative_to(ROOT), 'G276 input view escaped project')
    summary = []
    paths = set()
    for root in roots:
        rows, source_receipt, _ = records(root)
        source = pool / source_receipt['source_pool_relative_path']
        link = inputs / root['link'].split('/')[-1]
        need(link.is_symlink() and link.resolve(strict=True) == source.resolve(strict=True) and
             source.resolve(strict=True).is_relative_to(pool), 'G276 declared link target changed')
        git = lambda *args: subprocess.check_output(['git', '-C', str(source), *args], stderr=subprocess.DEVNULL).decode().strip()
        need(git('rev-parse', 'HEAD') == root['head'] and
             git('rev-parse', 'HEAD^{tree}') == root['tree'] and
             git('rev-parse', 'refs/tags/android-16.0.0_r4^{}') == root['head'] and
             not git('status', '--porcelain=v1', '--untracked-files=all'), 'G276 Git tag/HEAD/tree/clean drift')
        size = symlinks = 0
        for row in rows:
            name = row['path']
            pure = Path(name)
            need(name and not pure.is_absolute() and '..' not in pure.parts and
                 pure.as_posix() == name and root['stock_root'] + '/' + name not in paths,
                 'G276 unsafe/duplicate path')
            paths.add(root['stock_root'] + '/' + name)
            p = link / name
            if row['mode'] == '120000':
                need(p.is_symlink(), 'G276 symlink absent')
                data = os.readlink(p).encode()
                symlinks += 1
            else:
                need(row['mode'] in ('100644', '100755') and p.is_file() and not p.is_symlink(),
                     'G276 regular file absent')
                data = p.read_bytes()
            need(len(data) == int(row['bytes']) and hashlib.sha256(data).hexdigest() == row['sha256'] and
                 hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == row['git_blob'],
                 'G276 byte/blob mismatch: ' + name)
            size += len(data)
        need(size == root['bytes'] and symlinks == root['symlinks'], 'G276 extent changed')
        summary.append({'root': root['stock_root'], 'entries': len(rows), 'bytes': size,
                        'symlinks': symlinks, 'commit': root['head'], 'tree': root['tree']})
    need(len(paths) == 997, 'G276 exact path count drift')
    return {'repositories': summary, 'exact_paths': len(paths), 'all_bytes_verified': True,
            'input_candidate_sha256': INPUT_SHA, 'docker_commands': 0}


def stock_bind_args(env):
    inputs = Path(env['NANHAI_INPUTS_ROOT']).resolve(strict=True)
    argv = []
    for root in candidate()['roots']:
        link = inputs / root['link'].split('/')[-1]
        need(link.is_symlink(), 'G276 input link absent')
        argv += ['--mount', 'type=bind,src=' + str(link) + ',dst=/src/' + root['stock_root'] + ',readonly']
    return argv


def verify_stock_mounts(mounts, env):
    inputs = Path(env['NANHAI_INPUTS_ROOT']).resolve(strict=True)
    for root in candidate()['roots']:
        destination = '/src/' + root['stock_root']
        matches = [m for m in mounts if m['Destination'] == destination]
        link = inputs / root['link'].split('/')[-1]
        need(len(matches) == 1 and matches[0]['Type'] == 'bind' and matches[0]['RW'] is False and
             Path(matches[0]['Source']).resolve(strict=True) == link.resolve(strict=True),
             'G276 Linux mount identity/RW mismatch: ' + destination)
    return {'new_ro_mounts': 2, 'all_linux_rw_false': True}
