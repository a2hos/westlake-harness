#!/usr/bin/env python3
"""Read-only gz02 R4 repo ledger; run over SSH stdin, never in the checkout."""

import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


TOP = Path('/data/source/aosp-16.0.0-r4')
MANIFEST = TOP / '.repo/manifests/default.xml'
EXPECTED_MANIFEST_SHA256 = '19db4af44aa74ea4ed07bf602f5805476bab1c821d59ba818031022280ae055f'
TAG = 'android-16.0.0_r4'
# Official android.googlesource.com git ls-remote peeled-tag results, queried
# 2026-10-04 for the two unsynced Darwin-host repositories.
ABSENT_TAG_COMMITS = {
    'prebuilts/clang/host/darwin-x86': '269561cf8e3210a60093db99bc665fdfe8262dd3',
    'prebuilts/go/darwin-x86': 'a524afa53ed98979d91d4430a109af65cf06b414',
}


def git(path, *args):
    return subprocess.run(
        ['git', '-C', str(path), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def one(item):
    path, name = item
    root = TOP / path
    revision = 'refs/tags/' + TAG
    if not root.is_dir():
        return [path, name, revision, ABSENT_TAG_COMMITS.get(path, ''), '', '',
                'no', 'n/a', 'n/a', 'absent_manifest_project',
                'official_ls_remote' if path in ABSENT_TAG_COMMITS else 'unresolved']
    identity = git(root, 'rev-parse', 'HEAD', revision + '^{}', 'HEAD^{tree}')
    status = git(root, 'status', '--porcelain', '--untracked-files=no')
    deleted = git(root, 'ls-files', '-d', '-z')
    lines = identity.stdout.decode().splitlines()
    head, tag_commit, tree = lines if identity.returncode == 0 and len(lines) == 3 else ('', '', '')
    clean = status.returncode == 0 and not status.stdout
    missing = deleted.stdout.count(b'\0') if deleted.returncode == 0 else -1
    state = ('present_clean_r4' if head and head == tag_commit and clean and missing == 0
             else 'present_check_failed')
    return [path, name, revision, tag_commit, head, tree, 'yes',
            'yes' if clean else 'no', str(missing), state, 'local_peeled_tag']


def metadata_paths():
    base = TOP / '.repo/projects'
    found = set()
    for directory, subdirs, _ in os.walk(base):
        if directory.endswith('.git'):
            found.add(str(Path(directory).relative_to(base))[:-4])
            subdirs[:] = []
    return found


def verify_absent_tags():
    for path, expected in ABSENT_TAG_COMMITS.items():
        project = ('platform/prebuilts/clang/host/darwin-x86'
                   if path.endswith('clang/host/darwin-x86')
                   else 'platform/prebuilts/go/darwin-x86')
        url = 'https://android.googlesource.com/' + project
        result = subprocess.run(
            ['git', 'ls-remote', url, 'refs/tags/' + TAG + '^{}'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            check=False, timeout=20,
        )
        peeled = result.stdout.split()[0] if result.stdout.split() else ''
        if result.returncode != 0 or peeled != expected:
            raise RuntimeError('official absent-project tag drift: ' + path)


def main():
    actual_sha = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    if actual_sha != EXPECTED_MANIFEST_SHA256:
        raise RuntimeError('manifest SHA drift: ' + actual_sha)
    root = ET.parse(MANIFEST).getroot()
    default = root.find('default')
    if default is None or default.get('revision') != 'refs/tags/' + TAG:
        raise RuntimeError('manifest default revision drift')
    projects = root.findall('project')
    if any(p.get('revision') for p in projects):
        raise RuntimeError('per-project revision override')
    items = [(p.get('path', p.get('name')), p.get('name')) for p in projects]
    paths = {path for path, _ in items}
    if len(items) != 1013 or len(paths) != len(items):
        raise RuntimeError('manifest path count/uniqueness drift')
    metadata = metadata_paths()
    extra = sorted(metadata - paths)
    missing_metadata = sorted(paths - metadata)
    if extra or missing_metadata != sorted(ABSENT_TAG_COMMITS):
        raise RuntimeError(json.dumps({'extra_metadata': extra, 'missing_metadata': missing_metadata}))
    verify_absent_tags()
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        rows = list(pool.map(one, items))
    states = {}
    for row in rows:
        states[row[9]] = states.get(row[9], 0) + 1
    if states != {'present_clean_r4': 1011, 'absent_manifest_project': 2}:
        raise RuntimeError('source state drift: ' + json.dumps(states))
    if {row[0] for row in rows if row[9] == 'absent_manifest_project'} != set(ABSENT_TAG_COMMITS):
        raise RuntimeError('absent project drift')
    header = ['path', 'manifest_name', 'manifest_revision', 'expected_r4_commit',
              'head', 'tree', 'present', 'tracked_clean', 'missing_tracked_count',
              'state', 'tag_source']
    print('\t'.join(header))
    for row in rows:
        print('\t'.join(row))
    print(json.dumps({'manifest_sha256': actual_sha, 'manifest_projects': len(items),
                      'metadata_projects': len(metadata), 'extra_metadata': len(extra),
                      'missing_metadata': missing_metadata, 'states': states},
                     sort_keys=True), file=sys.stderr)


if __name__ == '__main__':
    main()
