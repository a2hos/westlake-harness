#!/usr/bin/env python3
"""G274 one-shot stock graph candidate. Requires original-owner release.

The accepted G273 executor supplies the unchanged Docker lifecycle and oracles.
This file only extends its source view, guards, and release contract. `run` is
deliberately unusable until a fresh G274 owner ACK and root seal exist.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(os.environ['NANHAI_PROJECT_ROOT']).resolve(strict=True)
REL = 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/stock-bionic-target-graph-v18-full-candidate-v2'
HERE = ROOT / REL
BASE = HERE.parent
OLD = BASE / 'stock-bionic-target-graph-v17b'
EXT = BASE / 'stock-bionic-target-graph-v18-candidate'
CLAIM = 'NP-MUSL16-ART-024'
GOAL = 'goal_01'
SESSION = 'oracle-kimi:local:nanhai-plus#inner'
G273_REVIEW = BASE / 'stock-bionic-target-graph-v17b/root-release-v1/G273-REVIEW.json'
G273_REVIEW_SHA = '9ef63a4e1c9bd6b8a6f944c0d9d52031bab8242a9384a02eedaef7fc07898c93'

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

old = load('g273_accepted_executor', OLD / 'executor.py')
prior = load('g273_independent_contract_validator', OLD / 'executor.py')
extension = load('g274_source_extension', EXT / 'executor_extension.py')
oracle_policy = load('g274_exact_oracle_policy', HERE / 'oracle_policy.py')
need, sha, read = old.need, old.sha, old.read
original_container_argv = old.container_argv
original_verify_container = old.verify_container
guard_before = None

def require_g273():
    need(sha(G273_REVIEW) == G273_REVIEW_SHA, 'G273 root terminal receipt drift')
    review = read(G273_REVIEW)
    need(review['status'] == 'ROOT_ACCEPT_G273_TERMINAL_RC2_NEW_TWELVE_MODULE_WALL' and
         review['execution']['outer_rc'] == 2 and
         review['graph_pass'] is False and review['target_compile_commands'] == 0,
         'G273 terminal scope changed')
    result = BASE / 'stock-bionic-target-graph-v17b/runtime-result/RESULT.json'
    need(sha(result) == review['result']['sha256'], 'G273 result changed')
    return {'review': str(G273_REVIEW.relative_to(ROOT)), 'sha256': G273_REVIEW_SHA,
            'result': str(result.relative_to(ROOT)), 'result_sha256': sha(result)}

def check_candidate(env, candidate):
    need(Path(__file__).resolve() == HERE / 'executor.py', 'wrong executor path')
    # The complete prior release contract, including 29 roots and 17,924 SDK
    # entries, is checked by the unchanged accepted validator on its own bytes.
    prior.validate_candidate(env, read(OLD / 'PACKET-CANDIDATE.json'))
    extension.verify_static_plan()
    oracle_policy.verify_static_policy(old, extension)
    terminal = require_g273()
    need(candidate['kind'] == 'bionic-stock-bionic-target-graph-v18' and
         candidate['status'] == 'candidate-not-released' and
         candidate['goal_id'] == GOAL and candidate['claim'] == CLAIM and
         candidate['target_id'] == old.TARGET and
         candidate['environment_sha256'] == old.ENV_SHA and
         candidate['prior_release_sequence'] == 273 and
         candidate['candidate'] == REL + '/PACKET-CANDIDATE.json' and
         candidate['executor'] == REL + '/executor.py' and
         candidate['executor_sha256'] == sha(__file__) and
         candidate['evidence'] == REL + '/runtime-result' and
         candidate['output_leaf'] == 'bionic-stock-bionic-target-graph-v18-v2',
         'G274 candidate identity/write set changed')
    need(all(candidate[key] is None for key in old.MUTABLE - {'status'}),
         'G274 candidate contains release values')
    need(candidate['g273_terminal'] == terminal, 'G273 predecessor binding changed')
    for reference, digest in candidate['inputs'].items():
        path = Path(env[reference[4:]]) if reference.startswith('env:') else ROOT / old.safe_relative(reference)
        need(sha(path) == digest, 'G274 bound input changed: ' + reference)
    need(candidate['inputs'][candidate['handoff']] == candidate['handoff_sha256'],
         'G274 handoff binding changed')
    return read(OLD / 'SOURCE-MANIFEST.json')

def released(env, candidate, candidate_sha):
    old.g.environment(ROOT)
    need(sha(HERE / 'PACKET-CANDIDATE.json') == candidate_sha, 'candidate changed')
    check_candidate(env, candidate)
    claims = [x for x in read(ROOT / 'docs/nanhai-plus/OUTER-STATE.json')['claims']
              if x['claim_id'] == CLAIM]
    need(len(claims) == 1, 'original claim nonunique')
    claim = claims[0]
    need(claim['goal_id'] == GOAL and claim['native_session'] == SESSION and
         claim['status'] == 'active' and claim['release_state'] == 'released',
         'original claim not released')
    packet_path = old.project_ref(ROOT, claim['release_packet'])
    need(packet_path == HERE / 'root-release-v1/G274-SEALED.json', 'wrong release path')
    packet = read(packet_path)
    need(set(packet) == set(candidate) and
         {k: v for k, v in packet.items() if k not in old.MUTABLE} ==
         {k: v for k, v in candidate.items() if k not in old.MUTABLE},
         'sealed static contract changed')
    need(packet['status'] == 'sealed-for-original-owner' and
         packet['candidate_sha256'] == candidate_sha and
         type(packet['release_sequence']) is int and packet['release_sequence'] == 274,
         'G274 packet is not freshly sealed')
    for key in ('generation', 'nonce', 'owner_ack_nonce'):
        need(isinstance(packet[key], str) and
             re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{7,95}', packet[key]),
             'bad G274 control token')
    need(claim['release_sequence'] == 274 and
         claim['current_generation'] == packet['generation'] and
         claim['handoff_sha256'] == packet['handoff_sha256'],
         'canonical release mismatch')
    ack = read(old.project_ref(ROOT, packet['owner_ack']))
    control = ack['_control']
    need(ack['session'] == SESSION and control['claim'] == CLAIM and
         control['goal_id'] == GOAL and control['return_to_outer'] is True and
         control['nonce'] == packet['owner_ack_nonce'] and
         control['release_sequence'] in (273, 274) and
         ack['consumed'].get(candidate['candidate']) == candidate_sha and
         ack['consumed'].get(candidate['g273_terminal']['review']) == G273_REVIEW_SHA,
         'fresh original-owner ACK is missing or incomplete')
    for reference, digest in candidate['inputs'].items():
        if not reference.startswith('env:'):
            need(ack['consumed'].get(reference) == digest,
                 'owner has not consumed G274 input: ' + reference)
    return packet, sha(packet_path)

def full_source_guard(env, _manifest):
    global guard_before
    result = extension.full_guard(env)
    encoded = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    if guard_before is None:
        guard_before = digest
    else:
        need(digest == guard_before, 'G274 complete source/SDK pre/post mismatch')
    return result

def container_argv(env, packet, phase, volume, output, temp, evidence, manifest):
    args = original_container_argv(env, packet, phase, volume, output, temp, evidence, manifest)
    if phase == 'materialize':
        # The v18 materializer receives the extended metadata, while source
        # payloads remain the original selected/archived inputs.
        return args
    if phase == 'stock':
        extra = extension.stock_bind_args(env)
        mount_point = args.index(old.IMAGE)
        links = EXT / 'NEW-LINKS.json'
        need(sha(links) == sha(HERE / 'NEW-LINKS.json'), 'link table drift')
        args[mount_point:mount_point] = extra + [
            '--mount', 'type=bind,src=' + str(links) + ',dst=/tools/NEW-LINKS.json,readonly']
    return args

def verify_container(info, cid, packet, phase, volume):
    observed = original_verify_container(info, cid, packet, phase, volume)
    if phase == 'stock':
        mounts = observed['Mounts']
        extension.verify_stock_mounts(mounts, old.g.environment(ROOT))
        links = [m for m in mounts if m['Destination'] == '/tools/NEW-LINKS.json']
        need(len(links) == 1 and links[0]['Type'] == 'bind' and
             links[0]['RW'] is False and
             Path(links[0]['Source']).resolve(strict=True) ==
             (EXT / 'NEW-LINKS.json').resolve(strict=True),
             'G274 link table mount identity changed')
    return observed

def main():
    need(sys.argv[1:] in (['check-candidate'], ['run']), 'fixed mode only')
    old.LEAF = REL
    old.validate_candidate = check_candidate
    old.released = released
    old.source_guard = full_source_guard
    old.container_argv = container_argv
    old.verify_container = verify_container
    oracle_policy.install(old, extension)
    return old.main()

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({'refused': type(exc).__name__ + ': ' + str(exc)}), file=sys.stderr)
        raise SystemExit(2)
