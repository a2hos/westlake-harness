"""Verify frozen G276 owner request and consumer before read-only SHA consumption."""
import hashlib
import runpy
from pathlib import Path

here = Path(__file__).resolve().parent
expected = {
    'OWNER-REQUEST.json': '2bb550200af0433cda0a0b4ab98e2f568dcf52bef5615a86ced55b38bb549556',
    'consume.py': '1ff563f756f375ad279aafef5d30605ea7b4938bfcfaaa23581cd0ae3a92bc76',
}
for name, digest in expected.items():
    assert hashlib.sha256((here / name).read_bytes()).hexdigest() == digest, name
runpy.run_path(str(here / 'consume.py'), run_name='__main__')
