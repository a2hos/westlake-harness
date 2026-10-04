#!/usr/bin/env python3
"""Retain G275 graph oracles, extending only exact R4 source paths."""
import importlib.util
import os
import posixpath
from pathlib import Path

HERE = Path(__file__).resolve().parent
prior_path = HERE.parent / 'stock-bionic-target-graph-v19-g275-candidate-v1/oracle_policy.py'
spec = importlib.util.spec_from_file_location('g275_exact_oracle_for_g276', prior_path)
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
prior_admitted_paths = prior.admitted_paths


def need(ok, why):
    if not ok:
        raise ValueError(why)


def admitted_paths(old, extension, g276_inputs):
    allowed = set(prior_admitted_paths(old, extension, g276_inputs.prior_g275))
    need(len(allowed) == 197049, 'G275 exact path baseline changed')
    new_paths = set()
    link_destinations = {}
    for root in g276_inputs.candidate()['roots']:
        rows, _, _ = g276_inputs.records(root)
        for row in rows:
            path = root['stock_root'] + '/' + row['path']
            need(path not in allowed and path not in new_paths, 'G276 exact path overlap')
            new_paths.add(path)
            if row['mode'] == '120000':
                link = Path(os.environ['NANHAI_INPUTS_ROOT']) / root['link'].split('/')[-1] / row['path']
                # Resolve the upstream payload lexically in the Linux stock view;
                # Path.resolve() here would inspect the project input view instead.
                target = os.readlink(link)
                virtual = posixpath.normpath(posixpath.join('/src', posixpath.dirname(path), target))
                need(virtual.startswith('/src/') and virtual != '/src', 'G276 stock link escapes /src')
                link_destinations[path] = virtual.removeprefix('/src/')
    need(len(new_paths) == 997, 'G276 exact path count drift')
    all_paths = allowed | new_paths
    need(link_destinations == {
        'system/tools/hidl/.clang-format': 'build/soong/scripts/system-clang-format',
        'system/apex/libs/libapexsupport/.clang-format': 'system/apex/apexd/.clang-format',
        'system/apex/rustfmt.toml': 'build/soong/scripts/rustfmt.toml',
    }, 'G276 stock link target changed')
    need(set(link_destinations.values()).issubset(all_paths), 'G276 stock link target absent')
    return frozenset(all_paths)


def verify_static_policy(old, extension, g276_inputs):
    allowed = admitted_paths(old, extension, g276_inputs)
    need(len(allowed) == 198046 and
         'system/tools/hidl/build/Android.bp' in allowed and
         'system/tools/hidl/build/hidl_interface.go' in allowed and
         'system/tools/hidl/build/hidl_package_root.go' in allowed and
         'system/apex/Android.bp' in allowed,
         'G276 definition/oracle set changed')
    return {'prior_exact_paths': 197049, 'new_exact_paths': 997,
            'total_allowlisted_paths': len(allowed), 'new_overlap_paths': 0,
            'stock_link_targets_present': 3}


def install(old, extension, g276_inputs):
    # G275's parser, artifact, and graph checks remain unchanged; only the
    # admitted exact source-path set gains the two complete R4 roots.
    prior.admitted_paths = lambda old_arg, ext_arg, _g275: admitted_paths(old_arg, ext_arg, g276_inputs)
    prior.install(old, extension, g276_inputs.prior_g275)
