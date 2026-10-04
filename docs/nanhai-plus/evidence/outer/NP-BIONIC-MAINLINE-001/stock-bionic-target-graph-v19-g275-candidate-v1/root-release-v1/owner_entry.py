"""Verify frozen G275 owner request and consumer before one read-only run."""
import hashlib
import runpy
from pathlib import Path

here = Path(__file__).resolve().parent
expected = {
    'OWNER-REQUEST.json': 'e4fed51c6137d16aa225c1c680555a09489fbb34e0f0a01f617388e8fda3cc1b',
    'consume.py': '973785d299ab0786d3b06c7cde73c9d05c02aca7fa6296ae21e767f390a67ef9',
}
for name, digest in expected.items():
    assert hashlib.sha256((here / name).read_bytes()).hexdigest() == digest, name
runpy.run_path(str(here / 'consume.py'), run_name='__main__')
