#!/usr/bin/env python3
"""Exact two-repository G275 input guard; no build or Docker entry point."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(os.environ['NANHAI_PROJECT_ROOT']).resolve(strict=True)
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
INPUT = BASE / 'g275-two-r4-stock-input-candidate-v1/INPUT-CANDIDATE.json'
INPUT_SHA = '9cccbd8062aa5215763ae2c45f39d2b1bb9342b9c840b954a5836906963bc995'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def candidate():
    need(sha(INPUT) == INPUT_SHA, 'G275 input candidate drift')
    value = json.loads(INPUT.read_bytes())
    need(value['goal_id'] == 'goal_01' and value['claim'] == 'NP-MUSL16-ART-024', 'G275 control identity drift')
    need(value['expected_stock_root_count'] == 40 and len(value['roots']) == len(value['new_stock_mounts']) == 2,
         'G275 root count drift')
    need(value['graph_executed'] is False and value['owner_new_ACK'] is False, 'G275 input claim expanded')
    for key in ('predecessor_g274_result', 'predecessor_materialization'):
        row = value[key]
        need(sha(ROOT / row['path']) == row['sha256'], 'G275 predecessor drift: ' + key)
    return value


def static_plan(prior_extension):
    prior_extension.verify_static_plan()
    value = candidate()
    prior = json.loads((BASE / 'stock-bionic-target-graph-v18-candidate/MATERIALIZATION.json').read_bytes())
    plan = json.loads((HERE / 'MATERIALIZATION.json').read_bytes())
    new_roots = [row['stock_root'] for row in value['roots']]
    need(len(prior['readonly_root_mounts']) == 38 and
         plan['readonly_root_mounts'] == prior['readonly_root_mounts'] + new_roots and
         len(set(plan['readonly_root_mounts'])) == 40, 'G275 40-root plan changed')
    need({k: v for k, v in plan.items() if k != 'readonly_root_mounts'} ==
         {k: v for k, v in prior.items() if k != 'readonly_root_mounts'},
         'G275 private materialization payload changed')
    for root in new_roots:
        need(not any(old == root or old.startswith(root + '/') or root.startswith(old + '/')
                     for old in prior['readonly_root_mounts']), 'G275 root collision')
    materializer = prior_extension.module('g275_materializer_metadata', HERE / 'materialize.py')
    materializer.check_plan(plan)
    return {'old_roots': 38, 'new_roots': new_roots, 'total_roots': 40,
            'private_entries_unchanged': len(plan['entries']), 'docker_commands': 0}


def full_guard(env):
    value = candidate()
    pool = Path(env['NANHAI_SOURCE_POOL_ROOT']).resolve(strict=True)
    inputs = Path(env['NANHAI_INPUTS_ROOT']).resolve(strict=True)
    need(inputs.is_relative_to(ROOT), 'G275 project input view escaped project')
    summary = []
    all_paths = set()
    for root in value['roots']:
        manifest = ROOT / root['manifest']
        receipt = ROOT / root['source_receipt']
        need(sha(manifest) == root['manifest_sha256'] and
             sha(receipt) == root['source_receipt_sha256'], 'G275 source receipt drift')
        stock = root['stock_root']
        link_name = root['project_input_link'].split('/')[-1]
        link = inputs / link_name
        source = pool / root['pool_relative']
        need(link.is_symlink() and link.resolve(strict=True) == source.resolve(strict=True) and
             source.resolve(strict=True).is_relative_to(pool), 'G275 declared link target changed')
        git = lambda *args: subprocess.check_output(['git', '-C', str(source), *args], stderr=subprocess.DEVNULL).decode().strip()
        need(git('rev-parse', 'HEAD') == root['commit'] and
             git('rev-parse', 'HEAD^{tree}') == root['tree'] and
             git('rev-parse', 'refs/tags/android-16.0.0_r4^{}') == root['commit'] and
             not git('status', '--porcelain=v1', '--untracked-files=all'), 'G275 Git identity/clean status drift')
        count = size = symlinks = 0
        for line in manifest.read_text().splitlines():
            fields = line.split('\t')
            if stock == 'kernel/configs': mode, relative, blob, length, digest = fields
            else: mode, blob, digest, length, relative = fields
            pure = Path(relative)
            need(relative and not pure.is_absolute() and '..' not in pure.parts and
                 pure.as_posix() == relative and stock + '/' + relative not in all_paths,
                 'G275 path unsafe or duplicate')
            all_paths.add(stock + '/' + relative)
            path = link / relative
            if mode == '120000':
                need(path.is_symlink(), 'G275 symlink absent')
                data = os.readlink(path).encode()
                symlinks += 1
            else:
                need(path.is_file() and not path.is_symlink(), 'G275 regular file absent')
                data = path.read_bytes()
            need(len(data) == int(length) and hashlib.sha256(data).hexdigest() == digest and
                 hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob,
                 'G275 tracked byte/blob mismatch: ' + relative)
            count += 1
            size += len(data)
        need(count == root['entries'] and size == root['bytes'] and symlinks == root['symlinks'],
             'G275 manifest extent changed')
        summary.append({'root': stock, 'entries': count, 'bytes': size, 'symlinks': symlinks,
                        'head': root['commit'], 'tree': root['tree'], 'link': link_name})
    need(len(all_paths) == 4587, 'G275 exact path count drift')
    return {'repositories': summary, 'exact_paths': 4587, 'all_bytes_verified': True,
            'input_candidate_sha256': INPUT_SHA, 'docker_commands': 0}


def stock_bind_args(env):
    value = candidate()
    inputs = Path(env['NANHAI_INPUTS_ROOT']).resolve(strict=True)
    pool = Path(env['NANHAI_SOURCE_POOL_ROOT']).resolve(strict=True)
    argv = []
    for row, root in zip(value['new_stock_mounts'], value['roots']):
        link = inputs / root['project_input_link'].split('/')[-1]
        need(row == {'type': 'bind', 'source': root['project_input_link'],
                     'destination': '/src/' + root['stock_root'], 'read_only': True} and
             link.is_symlink() and link.resolve(strict=True) ==
             (pool / root['pool_relative']).resolve(strict=True), 'G275 mount source contract drift')
        argv += ['--mount', 'type=bind,src=' + str(link) + ',dst=' + row['destination'] + ',readonly']
    return argv


def verify_stock_mounts(mounts, env):
    value = candidate()
    inputs = Path(env['NANHAI_INPUTS_ROOT']).resolve(strict=True)
    for row, root in zip(value['new_stock_mounts'], value['roots']):
        matches = [m for m in mounts if m['Destination'] == row['destination']]
        link = inputs / root['project_input_link'].split('/')[-1]
        need(len(matches) == 1 and matches[0]['Type'] == 'bind' and
             matches[0]['RW'] is False and
             Path(matches[0]['Source']).resolve(strict=True) == link.resolve(strict=True),
             'G275 Linux mount identity/RW mismatch: ' + row['destination'])
    return {'new_ro_mounts': 2, 'all_linux_rw_false': True}
