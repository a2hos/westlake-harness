#!/usr/bin/env python3
"""Read-only, bounded source-owner probe for known undefined Soong module names.

This is a diagnostic candidate, not a Soong parser or graph-completion oracle.
"""
import argparse
import json
import re
import subprocess
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--command', required=True)
    ap.add_argument('--pool', required=True)
    ap.add_argument('--name', action='append', required=True)
    ap.add_argument('--exclude-source', action='append', default=[])
    ns = ap.parse_args()
    command = json.loads(Path(ns.command).read_text())
    mounts = {}
    for item in command['argv']:
        if item.startswith('type=bind,') and ',dst=/src/' in item:
            fields = dict(field.split('=', 1) for field in item.split(',') if '=' in field)
            mounts[str(Path(fields['src']).resolve())] = fields['dst']
    excluded = {str(Path(x).resolve()) for x in ns.exclude_source}
    rows = []
    pool = Path(ns.pool).resolve()
    for name in ns.name:
        if not re.fullmatch(r'[A-Za-z0-9_.+-]+', name):
            raise SystemExit('invalid module name')
        # Restrict to a lexical definition anchor, never conflate a reference.
        pattern = r'^\s*name\s*:\s*"' + re.escape(name) + r'"\s*,?'
        p = subprocess.run(['rg', '-l', '-g', 'Android.bp', pattern, str(pool)],
                           capture_output=True, text=True, timeout=20)
        if p.returncode not in (0, 1):
            raise SystemExit('rg failed: ' + p.stderr[:300])
        definitions = []
        for filename in p.stdout.splitlines():
            path = Path(filename).resolve()
            owner = next((src for src in mounts if path == Path(src) or Path(src) in path.parents), None)
            definitions.append({'path': str(path), 'mounted_as': mounts.get(owner) if owner not in excluded else None,
                                'source_root': owner, 'excluded_control': owner in excluded})
        rows.append({'name': name, 'definitions': definitions,
                     'candidate_absent_from_bind_view': bool(definitions) and not any(d['mounted_as'] for d in definitions),
                     'unknown_if_no_definition': not bool(definitions)})
    print(json.dumps({'status': 'LEXICAL_CANDIDATE_ONLY', 'command': ns.command,
                      'pool': str(pool), 'rows': rows}, indent=2))


if __name__ == '__main__':
    main()
