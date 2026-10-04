#!/usr/bin/env python3
import hashlib
import runpy
from pathlib import Path
HERE = Path(__file__).resolve().parent
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(HERE / "POLICY-REQUEST.json") == "b1433af635138f9a76b047926532ad0399769379a17ebfc0de51da3785bc0d57"
assert sha(HERE / "consume.py") == "6f819dee1161d5427b63e5330b1a166391d0181838cb5d0eaca9fb0739e54af9"
runpy.run_path(str(HERE / "consume.py"), run_name="__main__")
