#!/usr/bin/env python3
"""No network: synthetic G292 negative and retained G284 positive controls."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
RUNNER = HERE / "range_probe.py"
spec = importlib.util.spec_from_file_location("range_probe", RUNNER)
m = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class LocalRangeTransport:
    def __init__(self, source, etag='"fixture-stable"', fault=None):
        self.source = source
        self.length = len(source) if isinstance(source, bytes) else source.stat().st_size
        self.etag = etag
        self.fault = fault
        self.requests = []

    def read(self, start, length):
        if isinstance(self.source, bytes):
            return self.source[start:start + length]
        with self.source.open("rb") as f:
            f.seek(start)
            return f.read(length)

    def request(self, method, headers, max_read):
        self.requests.append((method, dict(headers)))
        if method == "HEAD":
            return m.Response(200, {"content-length": str(self.length), "etag": self.etag}, b"", 256)
        assert method == "GET" and headers["If-Range"] == self.etag
        start, end = map(int, headers["Range"].removeprefix("bytes=").split("-"))
        body = self.read(start, end - start + 1)
        etag = '"changed"' if self.fault == "etag_changed" and len(self.requests) == 3 else self.etag
        if self.fault == "truncated" and len(self.requests) == 3:
            body = body[:-1]
        status = 200 if self.fault == "range_ignored" else 206
        return m.Response(status, {"content-range": f"bytes {start}-{end}/{self.length}",
                                   "content-length": str(end - start + 1), "etag": etag},
                          body[:max_read + 1] if status == 206 else b"", 256)


def synthetic_arm32():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as z:
        z.writestr("AndroidManifest.xml", b"synthetic fixture; not a real G292 APK")
        z.writestr("lib/armeabi-v7a/libfixture.so", b"fixture")
        z.writestr("assets/padding.bin", bytes(range(256)) * 300)
    return out.getvalue()


def run():
    synthetic = synthetic_arm32()
    assert len(synthetic) > m.TAIL_BYTES
    negative_transport = LocalRangeTransport(synthetic)
    negative = m.preflight(negative_transport, expected_length=len(synthetic), expected_etag=negative_transport.etag)
    assert negative["decision"] == "REJECT_ARM32_ONLY_STRUCTURAL_CANDIDATE", negative
    with zipfile.ZipFile(io.BytesIO(synthetic)) as z:
        malformed_at = z.start_dir
    malformed_bytes = bytearray(synthetic)
    malformed_bytes[malformed_at:malformed_at + 4] = b"BAD!"
    malformed = m.preflight(LocalRangeTransport(bytes(malformed_bytes)), expected_length=len(synthetic),
                            expected_etag='"fixture-stable"')
    assert malformed["decision"] == "UNKNOWN_FALLBACK", malformed

    inputs = json.loads((ROOT / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g285-elementx-static-v1/INPUTS.json").read_text())
    g284 = ROOT / inputs["apks"][0]["path"]
    assert hashlib.sha256(g284.read_bytes()).hexdigest() == inputs["apks"][0]["sha256"]
    positive_transport = LocalRangeTransport(g284)
    positive = m.preflight(positive_transport, expected_length=g284.stat().st_size, expected_etag=positive_transport.etag)
    assert positive["decision"] == "CONTINUE_FULL_GET_CHECKS_ARM64_DIRECTORY_OBSERVED", positive

    changed = m.preflight(LocalRangeTransport(g284, fault="etag_changed"), expected_length=g284.stat().st_size,
                          expected_etag='"fixture-stable"')
    truncated = m.preflight(LocalRangeTransport(g284, fault="truncated"), expected_length=g284.stat().st_size,
                            expected_etag='"fixture-stable"')
    ignored = m.preflight(LocalRangeTransport(g284, fault="range_ignored"), expected_length=g284.stat().st_size,
                          expected_etag='"fixture-stable"')
    assert all(x["decision"] == "UNKNOWN_FALLBACK" for x in (changed, truncated, ignored, malformed))
    assert all(x["remote_body_bytes_read"] + x["remote_header_bytes_accounted"] <= m.MAX_REMOTE_BYTES
               for x in (negative, positive, changed, truncated, ignored, malformed))
    return {"status": "LOCAL_FIXTURE_PASS", "cases": {
        "g292_hypothetical_arm32_only": negative, "g284_retained_arm64": positive,
        "changed_etag": changed, "truncated_range": truncated, "range_ignored_200": ignored,
        "malformed_directory": malformed},
        "g292_fixture_role": "synthetic ZIP under exact future G292 scenario; not downloaded G292 bytes",
        "g284_apk_sha256": inputs["apks"][0]["sha256"], "network_requests": 0,
        "full_apk_get": 0, "device": 0, "container": 0, "canonical_edits": 0}


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
