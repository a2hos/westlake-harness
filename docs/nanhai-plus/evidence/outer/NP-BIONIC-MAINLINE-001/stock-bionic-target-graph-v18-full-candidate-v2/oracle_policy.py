#!/usr/bin/env python3
"""Exact G274 source-view allowlist for the frozen G273 output oracles.

The original 29-root oracle behavior is retained. Nine source sets are read
from the admitted SHA-bound JSONL manifests, avoiding a second 20 MB copy.
No guessed directory-prefix allow rule is used.
"""
import hashlib
import json
import pathlib
import shlex
import struct

HERE = pathlib.Path(__file__).resolve().parent
BASE = HERE.parent

def need(ok, message):
    if not ok:
        raise ValueError(message)

def sha(path):
    h = hashlib.sha256()
    with pathlib.Path(path).open('rb') as stream:
        for data in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()

def admitted_paths(old, extension):
    input_candidate = extension.candidate()
    source_path = BASE / 'g274-nine-r4-source-candidate-v1/CANDIDATE.json'
    need(sha(source_path) == input_candidate['source_candidate_sha256'], 'nine-repo source candidate drift')
    source = json.loads(source_path.read_bytes())
    need(len(source['repositories']) == len(input_candidate['roots']) == 9, 'new source root count')
    old_manifest = old.read(BASE / 'stock-bionic-target-graph-v17b/SOURCE-MANIFEST.json')
    plan = old.read(HERE / 'MATERIALIZATION.json')
    need(len(old_manifest['repositories']) == 29 and len(plan['readonly_root_mounts']) == 38,
         'old/new root plan changed')
    allowed = {row['path'] for row in plan['entries']}
    for repo in old_manifest['repositories']:
        allowed.update(repo['root'] + '/' + row['path'] for row in repo['files'])
    old_paths = set(allowed)
    extras = set()
    overlaps = set()
    total = 0
    for root, repo in zip(input_candidate['roots'], source['repositories']):
        need(root['pool_relative'] == repo['source_relative_path'] and
             root['commit'] == repo['commit'] and root['tree'] == repo['tree'],
             'new repository identity changed')
        manifest = BASE / 'g274-nine-r4-source-candidate-v1' / repo['manifest']
        need(manifest.parent == BASE / 'g274-nine-r4-source-candidate-v1' and
             sha(manifest) == root['manifest_sha256'] == repo['manifest_sha256'],
             'new source path manifest drift')
        count = 0
        with manifest.open() as stream:
            for line in stream:
                row = json.loads(line)
                relative = row['path']
                pure = pathlib.PurePosixPath(relative)
                need(relative and not relative.startswith('/') and
                     pure.as_posix() == relative and '..' not in pure.parts,
                     'unsafe admitted source path')
                path = root['stock_root'] + '/' + relative
                need(path not in extras and path not in overlaps, 'duplicate new source path')
                (overlaps if path in old_paths else extras).add(path)
                count += 1
        need(count == root['entries'], 'new source manifest count changed')
        total += count
    expected_overlap = {row['path'] for row in input_candidate['identical_overlaps']}
    need(total == 85499 and overlaps == expected_overlap and len(overlaps) == 4 and
         len(extras) == 85495, 'nine-root exact union changed')
    return frozenset(allowed | extras)

def check_paths(names, allowed, role):
    need(bool(names) and len(names) == len(set(names)), role + ' empty or duplicate')
    for name in names:
        require_allowed_path(name, allowed, role)
    return len(names)

def require_allowed_path(name, allowed, role):
    normalized = name.removeprefix('./')
    need(normalized in allowed, 'finder listed unsealed ' + role + ': ' + name)
    return normalized

def verify_static_policy(old, extension):
    allowed = admitted_paths(old, extension)
    input_candidate = extension.candidate()
    first = input_candidate['roots'][0]['stock_root'] + '/Android.bp'
    need(first in allowed, 'known new Blueprint absent')
    need('packages/apps/DocumentsUI/UNLISTED-v18-Android.bp' not in allowed,
         'unlisted Blueprint accidentally admitted')
    return {'roots': 38, 'new_entries': 85499, 'new_exact_paths': 85495,
            'new_overlaps': 4, 'total_allowlisted_paths': len(allowed)}

def install(old, extension):
    """Install copies of both frozen oracles with only the allowlist expanded."""
    admitted_paths(old, extension)
    need(old.sha(old.ROOT / old.LEAF / 'stock_target_graph.sh') ==
         extension.candidate()['v17b_stock_shell_sha256'], 'stock graph shell changed')

    def artifact_oracle(output, materialized):
        allowed = admitted_paths(old, extension)
        steps = output / 'stock-steps'
        names = ('source-pre', 'host-providers', 'mk2rbc', 'rbcrun', 'release-config', 'product-dumpvars', 'source-post')
        for name in names:
            old.need((steps / (name + '.rc')).read_text() == '0\n', 'stock child failed ' + name)
        before = old.read(steps / 'source-pre.stdout')
        after = old.read(steps / 'source-post.stdout')
        old.need(before == after == materialized, 'source volume before/after differs')
        host = old.read(steps / 'host-providers.stdout')
        old.need(host['pass'] is True and len(host['tools']) == 10, 'provider preflight incomplete')
        parsed = old.load_module('stock_vars_oracle', old.ROOT / old.LEAF / 'verify_vars.py').parse(
            (steps / 'product-dumpvars.stdout').read_bytes())
        artifacts = []
        for name in ('mk2rbc', 'rbcrun', 'release-config'):
            path = output / name
            old.need(path.is_file() and not path.is_symlink() and path.stat().st_mode & 0o111,
                     'missing fresh helper ' + name)
            header = path.read_bytes()[:64]
            old.need(len(header) == 64 and header[:6] == b'\x7fELF\x02\x01' and
                     struct.unpack_from('<H', header, 18)[0] == 62, 'helper not x86_64 ELF')
            trace = output / ('.' + name + '.trace')
            old.need(trace.is_file() and trace.stat().st_size > 0, 'microfactory trace missing')
            artifacts.extend([old.file_ref(old.ROOT, path), old.file_ref(old.ROOT, trace)])
        config = output / 'soong/release-config'
        args = config / 'args-aosp_arm64.txt'
        old.need(shlex.split(args.read_text()) == ['--product', 'aosp_arm64', '--release', 'trunk_staging',
                                                  '--variant', 'userdebug', '--maps-file',
                                                  '/out/soong/release-config/maps_list-aosp_arm64.txt'],
                 'generated release arguments mismatch')
        maps = config / 'maps_list-aosp_arm64.txt'
        mapnames = maps.read_text().split()
        old.need('build/release/release_config_map.textproto' in mapnames, 'default release map absent')
        for name in mapnames:
            require_allowed_path(name, allowed, 'release map')
        manifest = old.read(BASE / 'stock-bionic-target-graph-v17b/SOURCE-MANIFEST.json')
        for path in [args, maps, config / 'files_used-aosp_arm64.hash',
                     config / 'release_config-aosp_arm64-trunk_staging.vars',
                     config / 'release_config-aosp_arm64.vars',
                     output / '.module_paths/AndroidProducts.mk.list',
                     output / '.module_paths/configuration.list']:
            old.need(path.is_file() and not path.is_symlink(), 'expected stock generated file absent ' + str(path))
            artifacts.append(old.file_ref(old.ROOT, path))
        for name in ('AndroidProducts.mk.list', 'configuration.list'):
            entries = (output / '.module_paths' / name).read_text().splitlines()
            for path in entries:
                normalized = path.removeprefix('./')
                for link in manifest['configuration_aliases']:
                    prefix = link['path'] + '/'
                    if normalized.startswith(prefix):
                        normalized = str(pathlib.PurePosixPath(link['path']).parent /
                                         pathlib.PurePosixPath(link['target']) / normalized[len(prefix):])
                require_allowed_path(normalized, allowed, 'input')
        stderr = (steps / 'product-dumpvars.stderr').read_text()
        sandbox = ('stock_reported_disabled' if 'Build sandboxing disabled due to nsjail error.' in stderr
                   else 'no_disable_message_observed; inner sandbox success not inferred')
        return {'product_configuration_pass': True, 'variables': parsed['variables'],
                'host_loader_preflight': host, 'source_volume_verified': True,
                'nsjail_observation': sandbox, 'generated_artifacts': artifacts,
                'exact_target_compile_argv_known': False, 'complete_production_dependency_graph': False}

    def graph_oracle(output):
        allowed = admitted_paths(old, extension)
        steps = output / 'stock-steps'
        old.need((steps / 'target-graph.rc').read_text() == '0\n', 'stock graph command failed')
        graph = output / 'soong/build.aosp_arm64.ninja'
        old.need(graph.is_file() and not graph.is_symlink() and graph.stat().st_size > 0,
                 'stock product graph absent')
        bp = output / '.module_paths/Android.bp.list'
        old.need(bp.is_file() and not bp.is_symlink() and bp.stat().st_size > 0,
                 'stock Blueprint finder list absent')
        manifest = old.read(BASE / 'stock-bionic-target-graph-v17b/SOURCE-MANIFEST.json')
        names = bp.read_text().splitlines()
        old.need(bool(names) and len(names) == len(set(names)), 'empty or duplicate Blueprint finder entries')
        for path in names:
            normalized = path.removeprefix('./')
            for link in manifest['configuration_aliases']:
                prefix = link['path'] + '/'
                if normalized.startswith(prefix):
                    normalized = str(pathlib.PurePosixPath(link['path']).parent /
                                     pathlib.PurePosixPath(link['target']) / normalized[len(prefix):])
            require_allowed_path(normalized, allowed, 'Blueprint')
        return {'graph_generation_pass': True,
                'generated_artifacts': [old.file_ref(old.ROOT, graph), old.file_ref(old.ROOT, bp)],
                'target_compile': False, 'target_ninja_executed': False,
                'host_go_bootstrap_may_run': True, 'complete_target_dependency_build_proven': False}

    old.artifact_oracle = artifact_oracle
    old.graph_oracle = graph_oracle
