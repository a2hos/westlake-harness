#!/usr/bin/env python3
"""Bounded, local-only entry probe for the two project host leads."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

root = Path(os.environ["NANHAI_PROJECT_ROOT"])
here = Path(__file__).resolve().parent
env_file = root / "local_env.md"
ssh_config = Path.home() / ".ssh/config"
known_hosts = Path.home() / ".ssh/known_hosts"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def run(argv, seconds):
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    tick = time.monotonic()
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=seconds)
        return {"started_utc": started, "elapsed_s": round(time.monotonic()-tick, 3), "rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired as e:
        return {"started_utc": started, "elapsed_s": round(time.monotonic()-tick, 3), "rc": 124, "stdout": (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout,bytes) else (e.stdout or ""), "stderr": "timeout"}

def resolve(name):
    argv = [sys.executable, "-c", "import socket,sys,json;print(json.dumps(sorted({x[4][0] for x in socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM)})))", name]
    return {"argv": ["python3", "-c", "socket.getaddrinfo(<host>)", name], **run(argv, 5)}

env_text = env_file.read_text()
assert '"NANHAI_GZ02_BUILD_HOST": "gz02"' in env_text
hosts = {}
for alias in ("gz02", "alexpc"):
    config = run(["ssh", "-G", alias], 5)
    if config["rc"]:
        hosts[alias] = {"config": config, "decision": "NO_GO_SSH_CONFIG"}
        continue
    fields = dict(line.split(" ",1) for line in config["stdout"].splitlines() if line and " " in line)
    name, port = fields["hostname"], int(fields["port"])
    dns = resolve(name)
    addresses = json.loads(dns["stdout"]) if dns["rc"] == 0 else []
    tcp = {"attempted": False}
    if addresses:
        start = datetime.datetime.now(datetime.timezone.utc).isoformat()
        tick = time.monotonic()
        try:
            with socket.create_connection((addresses[0], port), timeout=3) as sock:
                banner = sock.recv(256)
            tcp = {"attempted": True, "started_utc": start, "elapsed_s": round(time.monotonic()-tick,3), "rc": 0, "address": addresses[0], "port": port, "banner_prefix": banner[:80].decode(errors="replace")}
        except Exception as e:
            tcp = {"attempted": True, "started_utc": start, "elapsed_s": round(time.monotonic()-tick,3), "rc": 2, "address": addresses[0], "port": port, "error": type(e).__name__ + ": " + str(e)}
    key_query = f"[{name}]:{port}" if port != 22 else name
    key = run(["ssh-keygen", "-F", key_query, "-f", str(known_hosts), "-l"], 5)
    fingerprints = [line for line in key["stdout"].splitlines() if line and not line.startswith("#")]
    hosts[alias] = {"effective_config": {k:fields.get(k) for k in ("hostname","port","proxycommand","proxyjump","hostkeyalias","stricthostkeychecking","userknownhostsfile")}, "config_probe": {"argv": ["ssh", "-G", alias], "started_utc": config["started_utc"], "elapsed_s": config["elapsed_s"], "rc": config["rc"]}, "dns": dns, "tcp": tcp, "known_hosts_probe": {"argv": ["ssh-keygen", "-F", key_query, "-f", "~/.ssh/known_hosts", "-l"], "started_utc": key["started_utc"], "elapsed_s": key["elapsed_s"], "rc": key["rc"]}, "known_hosts_fingerprints": fingerprints, "ssh_attempted": False, "remote_commands": 0}

out = {"schema":"peer-native-linux-host-entry-v1", "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "inputs": {"local_env_sha256": sha(env_file), "ssh_config_sha256": sha(ssh_config), "known_hosts_sha256": sha(known_hosts)}, "hosts": hosts, "remote_commands":0,"device_commands":0,"container_commands":0,"bridge_commands":0,"graph_commands":0,"old_nonce_replays":0}
print(json.dumps(out, sort_keys=True, indent=2))
