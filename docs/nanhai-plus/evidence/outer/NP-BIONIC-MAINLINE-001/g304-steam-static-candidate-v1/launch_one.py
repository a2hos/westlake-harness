import datetime
import hashlib
import json
import pathlib
import signal
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[6]
BASE = pathlib.Path(__file__).parent


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('steam_mobile', 'steam_link'):
        raise SystemExit('one exact package name required')
    d = BASE / sys.argv[1]
    argv = ['python3', '-B', 'scripts/nanhai_plus_env.py', '--run', 'python3', '-B', str(d / 'run.py'), '--execute']
    row = {'argv': argv, 'cwd': str(ROOT), 'started_at': stamp(), 'timeout_seconds': 1400,
           'network_authorized': False, 'device_commands': 0, 'container_commands': 0}
    start = time.monotonic()
    with (d / 'outer.stdout.raw').open('xb') as stdout, (d / 'outer.stderr.raw').open('xb') as stderr:
        proc = subprocess.Popen(argv, cwd=ROOT, stdout=stdout, stderr=stderr, start_new_session=True)
        row['pid'] = proc.pid
        try:
            row['rc'] = proc.wait(timeout=1400)
        except subprocess.TimeoutExpired:
            row['timed_out'] = True
            try:
                import os
                os.killpg(proc.pid, signal.SIGKILL)
            finally:
                row['rc'] = proc.wait()
    row.update(finished_at=stamp(), elapsed_seconds=time.monotonic()-start,
               stdout_sha256=digest(d / 'outer.stdout.raw'), stderr_sha256=digest(d / 'outer.stderr.raw'))
    with (d / 'OUTER-COMMAND.json').open('x') as f:
        json.dump(row, f, indent=2)
        f.write('\n')
    print(json.dumps(row))
    return row['rc']


if __name__ == '__main__':
    sys.exit(main())
