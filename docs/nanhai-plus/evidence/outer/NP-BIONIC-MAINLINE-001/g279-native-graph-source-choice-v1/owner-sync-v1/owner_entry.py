#!/usr/bin/env python3
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


assert sha(HERE / "REQUEST.json") == "eeb02ec830106f504a02b1c311d7d4b0416766a0d58e35b8bd702b1110f2814e"
assert sha(HERE / "consume.py") == "0189863fad9f8e42318408895287d05988e47256584b6ffb8ee30af2235378c3"
runpy.run_path(str(HERE / "consume.py"), run_name="__main__")
