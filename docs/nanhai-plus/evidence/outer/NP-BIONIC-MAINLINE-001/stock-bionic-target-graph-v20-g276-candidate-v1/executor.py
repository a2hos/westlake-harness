#!/usr/bin/env python3
"""G276 one-shot stock graph candidate; run requires fresh owner ACK and root seal."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(os.environ['NANHAI_PROJECT_ROOT']).resolve(strict=True)
REL = 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/stock-bionic-target-graph-v20-g276-candidate-v1'
HERE = ROOT / REL
BASE = HERE.parent
PREVIOUS = BASE / 'stock-bionic-target-graph-v19-g275-candidate-v1'
G275_REVIEW = PREVIOUS / 'root-release-v1/G275-REVIEW.json'
G275_REVIEW_SHA = '9b0b8cb961612978b98db36589039e2e670797d39ffcd88672af1ff595a4db4d'
CLAIM = 'NP-MUSL16-ART-024'
GOAL = 'goal_01'
SESSION = 'oracle-kimi:local:nanhai-plus#inner'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


previous = load('g275_terminal_executor', PREVIOUS / 'executor.py')
old = load('g273_frozen_executor_for_g275', BASE / 'stock-bionic-target-graph-v17b/executor.py')
extension = previous.extension
g276 = load('g276_two_input_guard', HERE / 'g276_inputs.py')
g276.prior_g275 = previous.g275
oracle_policy = load('g276_exact_oracle_policy', HERE / 'oracle_policy.py')
need, sha, read = old.need, old.sha, old.read
original_container_argv = previous.container_argv
original_verify_container = previous.verify_container
guard_before = None


def require_g275():
    need(sha(G275_REVIEW) == G275_REVIEW_SHA, 'G275 terminal root review drift')
    review = read(G275_REVIEW)
    result = ROOT / review['result']['path']
    observations = review['observations']
    need(review['decision'] == 'ACCEPT_ACTUAL_TERMINAL_FAILURE_EVIDENCE' and
         review['release_sequence'] == 275 and review['external_execution']['rc'] == 2 and
         observations['stopped_at'] == 'target-graph' and observations['error_lines'] == 182 and
         observations['graph_generation_pass'] is False and
         observations['target_compile_commands'] == 0 and
         sha(result) == review['result']['sha256'], 'G275 predecessor is not accepted terminal evidence')
    return {'review': str(G275_REVIEW.relative_to(ROOT)), 'sha256': G275_REVIEW_SHA,
            'result': str(result.relative_to(ROOT)), 'result_sha256': sha(result)}


def check_candidate(env, candidate):
    need(Path(__file__).resolve(strict=True) == HERE / 'executor.py', 'wrong G276 executor path')
    previous.check_candidate(env, read(PREVIOUS / 'PACKET-CANDIDATE.json'))
    g276.static_plan(previous)
    oracle_policy.verify_static_policy(old, extension, g276)
    terminal = require_g275()
    need(candidate['schema_version'] == 20 and
         candidate['kind'] == 'bionic-stock-bionic-target-graph-v20-g276' and
         candidate['status'] == 'candidate-not-released' and
         candidate['goal_id'] == GOAL and candidate['claim'] == CLAIM and
         candidate['target_id'] == old.TARGET and
         candidate['environment_sha256'] == old.ENV_SHA and
         candidate['prior_release_sequence'] == 275 and
         candidate['candidate'] == REL + '/PACKET-CANDIDATE.json' and
         candidate['executor'] == REL + '/executor.py' and
         candidate['executor_sha256'] == sha(__file__) and
         candidate['evidence'] == REL + '/runtime-result' and
         candidate['output_leaf'] == 'bionic-stock-bionic-target-graph-v20-g276',
         'G276 candidate identity/write set changed')
    need(all(candidate[key] is None for key in old.MUTABLE - {'status'}),
         'G276 candidate contains release values')
    need(candidate['g275_terminal'] == terminal and
         candidate['g276_input']['path'] == str(g276.INPUT.relative_to(ROOT)) and
         candidate['g276_input']['sha256'] == g276.INPUT_SHA,
         'G276 predecessor/input binding changed')
    for reference, digest in candidate['inputs'].items():
        path = Path(env[reference[4:]]) if reference.startswith('env:') else ROOT / old.safe_relative(reference)
        need(sha(path) == digest, 'G276 bound input changed: ' + reference)
    need(candidate['inputs'][candidate['handoff']] == candidate['handoff_sha256'],
         'G276 handoff binding changed')
    return read(BASE / 'stock-bionic-target-graph-v17b/SOURCE-MANIFEST.json')


def released(env, candidate, candidate_sha):
    old.g.environment(ROOT)
    need(sha(HERE / 'PACKET-CANDIDATE.json') == candidate_sha, 'G276 candidate changed')
    check_candidate(env, candidate)
    claims = [row for row in read(ROOT / 'docs/nanhai-plus/OUTER-STATE.json')['claims']
              if row['claim_id'] == CLAIM]
    need(len(claims) == 1, 'original claim nonunique')
    claim = claims[0]
    need(claim['goal_id'] == GOAL and claim['native_session'] == SESSION and
         claim['status'] == 'active' and claim['release_state'] == 'released' and
         claim['release_sequence'] == 276, 'original G276 claim not released')
    packet_path = old.project_ref(ROOT, claim['release_packet'])
    need(packet_path == HERE / 'root-release-v1/G276-SEALED.json', 'wrong G276 release path')
    packet = read(packet_path)
    need(set(packet) == set(candidate) and
         {k: v for k, v in packet.items() if k not in old.MUTABLE} ==
         {k: v for k, v in candidate.items() if k not in old.MUTABLE},
         'G276 sealed static contract changed')
    need(packet['status'] == 'sealed-for-original-owner' and
         packet['candidate_sha256'] == candidate_sha and
         type(packet['release_sequence']) is int and packet['release_sequence'] == 276,
         'G276 packet not freshly sealed')
    for key in ('generation', 'nonce', 'owner_ack_nonce'):
        need(isinstance(packet[key], str) and
             re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{7,95}', packet[key]),
             'bad G276 control token')
    need(claim['current_generation'] == packet['generation'] and
         claim['handoff_sha256'] == packet['handoff_sha256'], 'canonical G276 release mismatch')
    ack_path = old.project_ref(ROOT, packet['owner_ack'])
    need(ack_path == ROOT / 'docs/nanhai-plus/evidence/inner/NP-BIONIC-MAINLINE-001/' /
         'stock-bionic-target-graph-v20-g276-candidate-v1/OWNER-ACK.json', 'wrong G276 ACK path')
    ack = read(ack_path)
    control = ack['_control']
    need(ack['session'] == SESSION and control['claim'] == CLAIM and
         control['goal_id'] == GOAL and control['return_to_outer'] is True and
         control['nonce'] == packet['owner_ack_nonce'] and
         control['release_sequence'] == 276 and
         ack['consumed'].get(candidate['candidate']) == candidate_sha and
         ack['consumed'].get(candidate['g275_terminal']['review']) == G275_REVIEW_SHA,
         'fresh original-owner G276 ACK missing or incomplete')
    for reference, digest in candidate['inputs'].items():
        if not reference.startswith('env:'):
            need(ack['consumed'].get(reference) == digest,
                 'owner has not consumed G276 input: ' + reference)
    seal = read(HERE / 'root-release-v1/ROOT-SEAL.json')
    need(seal['status'] == 'ROOT_SEALED_G276_FOR_ONE_HOST_GRAPH_EXECUTION' and
         seal['candidate_sha256'] == candidate_sha and
         seal['packet_sha256'] == sha(packet_path) and
         seal['owner_ack_sha256'] == sha(ack_path), 'G276 root seal absent or mismatched')
    return packet, sha(packet_path)


def full_source_guard(env, _manifest):
    global guard_before
    result = {'g275_complete_source_and_sdk': previous.full_source_guard(env, _manifest),
              'g276_two_complete_roots': g276.full_guard(env)}
    digest = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if guard_before is None:
        guard_before = digest
    else:
        need(digest == guard_before, 'G276 complete source/SDK pre/post mismatch')
    return result


def container_argv(env, packet, phase, volume, output, temp, evidence, manifest):
    args = original_container_argv(env, packet, phase, volume, output, temp, evidence, manifest)
    if phase == 'stock':
        links = BASE / 'stock-bionic-target-graph-v18-candidate/NEW-LINKS.json'
        need(sha(links) == sha(HERE / 'NEW-LINKS.json'), 'G274 link table drift')
        mount_point = args.index(old.IMAGE)
        args[mount_point:mount_point] = g276.stock_bind_args(env)
    return args


def verify_container(info, cid, packet, phase, volume):
    observed = original_verify_container(info, cid, packet, phase, volume)
    if phase == 'stock':
        mounts = observed['Mounts']
        g276.verify_stock_mounts(mounts, old.g.environment(ROOT))
        links = [m for m in mounts if m['Destination'] == '/tools/NEW-LINKS.json']
        need(len(links) == 1 and links[0]['Type'] == 'bind' and links[0]['RW'] is False and
             Path(links[0]['Source']).resolve(strict=True) ==
             (BASE / 'stock-bionic-target-graph-v18-candidate/NEW-LINKS.json').resolve(strict=True),
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
    oracle_policy.install(old, extension, g276)
    return old.main()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({'refused': type(exc).__name__ + ': ' + str(exc)}), file=sys.stderr)
        raise SystemExit(2)
