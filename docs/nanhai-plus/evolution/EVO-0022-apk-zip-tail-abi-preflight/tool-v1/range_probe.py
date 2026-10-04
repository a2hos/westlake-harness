#!/usr/bin/env python3
"""Bounded ZIP-directory ABI probe. Positive results never admit an APK.

The only network entry point is --probe-g292. A server that ignores Range,
changes its strong ETag, or serves malformed ZIP metadata yields UNKNOWN.
"""
from __future__ import annotations

import argparse
import http.client
import json
import re
import ssl
import struct
from dataclasses import dataclass
from urllib.parse import urlsplit

URL = "https://line-android-universal-download.line-scdn.net/line-15.21.3.apk"
EXPECTED_LENGTH = 190235503
EXPECTED_ETAG = '"e1628f42066cb5c669fa96ddaaf618a3"'
MAX_REMOTE_BYTES = 1 << 20
MAX_BODY_BYTES = 786432
MAX_HEADER_BYTES = 65536
TAIL_BYTES = 65557  # Maximum EOCD comment plus fixed EOCD header.
MAX_ENTRIES = 200000


class Unknown(Exception):
    pass


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    header_bytes: int


def _header_map(items: list[tuple[str, str]]) -> dict[str, str]:
    out = {}
    for key, value in items:
        key = key.lower()
        if key in out:
            raise Unknown("duplicate response header: " + key)
        out[key] = value.strip()
    return out


class HTTPSRangeTransport:
    def __init__(self, url: str):
        if url != URL:
            raise Unknown("unexpected URL")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname != "line-android-universal-download.line-scdn.net" or parsed.port is not None:
            raise Unknown("host/scheme drift")
        self.host = parsed.hostname
        self.path = parsed.path

    def request(self, method: str, headers: dict[str, str], max_read: int) -> Response:
        conn = http.client.HTTPSConnection(self.host, timeout=15, context=ssl.create_default_context())
        try:
            conn.request(method, self.path, headers={"Accept-Encoding": "identity", **headers})
            response = conn.getresponse()
            items = response.getheaders()
            header_bytes = 64 + sum(len(k) + len(v) + 4 for k, v in items)
            if header_bytes > MAX_HEADER_BYTES:
                raise Unknown("headers over cap")
            mapped = _header_map(items)
            # Never read a 200 body: a Range-ignoring server cannot trigger a full GET.
            body = response.read(max_read + 1) if response.status == 206 else b""
            return Response(response.status, mapped, body, header_bytes)
        finally:
            conn.close()


def _strong_etag(value: str) -> bool:
    return bool(re.fullmatch(r'"[^"\r\n]{1,128}"', value))


def _range(transport, start: int, end: int, total: int, etag: str, used: dict[str, int]) -> bytes:
    length = end - start + 1
    if start < 0 or end >= total or length <= 0 or length > MAX_BODY_BYTES - used["body"]:
        raise Unknown("range outside byte budget")
    response = transport.request("GET", {"Range": f"bytes={start}-{end}", "If-Range": etag}, length)
    used["body"] += len(response.body)
    used["headers"] += response.header_bytes
    if used["body"] > MAX_BODY_BYTES or used["headers"] > MAX_HEADER_BYTES or used["body"] + used["headers"] > MAX_REMOTE_BYTES:
        raise Unknown("aggregate response cap")
    if response.status != 206:
        raise Unknown("Range not honored")
    expected_range = f"bytes {start}-{end}/{total}"
    if response.headers.get("content-range") != expected_range:
        raise Unknown("Content-Range drift")
    if response.headers.get("etag") != etag or response.headers.get("content-encoding", "identity") != "identity":
        raise Unknown("object validator/encoding drift")
    if response.headers.get("content-length") != str(length) or len(response.body) != length:
        raise Unknown("range length mismatch")
    return response.body


def _eocd(tail: bytes, tail_start: int, total: int) -> tuple[int, int, int]:
    for pos in range(len(tail) - 22, -1, -1):
        if tail[pos:pos + 4] != b"PK\x05\x06":
            continue
        if pos + 22 > len(tail):
            continue
        _, disk, cd_disk, disk_count, count, cd_size, cd_offset, comment = struct.unpack_from("<IHHHHIIH", tail, pos)
        if pos + 22 + comment != len(tail):
            continue
        if disk or cd_disk or disk_count != count or count == 0xffff or cd_size == 0xffffffff or cd_offset == 0xffffffff:
            raise Unknown("multi-disk or ZIP64 metadata")
        if count > MAX_ENTRIES or cd_offset + cd_size != tail_start + pos or cd_offset < 0 or cd_size < 46:
            raise Unknown("central directory bounds")
        return cd_offset, cd_size, count
    raise Unknown("EOCD missing/malformed")


def _abis(cd: bytes, expected_count: int) -> list[str]:
    pos = 0
    abis = set()
    for _ in range(expected_count):
        if pos + 46 > len(cd) or cd[pos:pos + 4] != b"PK\x01\x02":
            raise Unknown("central directory entry missing")
        fields = struct.unpack_from("<IHHHHHHIIIHHHHHII", cd, pos)
        flags, name_len, extra_len, comment_len, disk = fields[3], fields[10], fields[11], fields[12], fields[13]
        if disk or flags & 1:
            raise Unknown("multi-disk/encrypted entry")
        stop = pos + 46 + name_len + extra_len + comment_len
        if name_len == 0 or stop > len(cd):
            raise Unknown("central directory entry bounds")
        raw = cd[pos + 46:pos + 46 + name_len]
        try:
            name = raw.decode("utf-8" if flags & 0x800 else "cp437")
        except UnicodeError as error:
            raise Unknown("filename decode") from error
        if name.startswith("/") or "\\" in name or any(part in ("", ".", "..") for part in name.split("/")[:-1]):
            raise Unknown("unsafe ZIP path")
        match = re.fullmatch(r"lib/([^/]+)/[^/]+\.so", name)
        if match:
            abis.add(match.group(1))
        pos = stop
    if pos != len(cd):
        raise Unknown("central directory trailing bytes")
    return sorted(abis)


def preflight(transport, *, expected_length: int, expected_etag: str) -> dict:
    used = {"body": 0, "headers": 0}
    try:
        if expected_length <= TAIL_BYTES or not _strong_etag(expected_etag):
            raise Unknown("invalid pinned object")
        head = transport.request("HEAD", {}, 0)
        used["headers"] += head.header_bytes
        if head.status != 200 or head.body or head.headers.get("content-length") != str(expected_length) or head.headers.get("etag") != expected_etag:
            raise Unknown("HEAD identity drift")
        if used["headers"] > MAX_HEADER_BYTES:
            raise Unknown("HEAD headers over cap")
        tail_start = expected_length - TAIL_BYTES
        tail = _range(transport, tail_start, expected_length - 1, expected_length, expected_etag, used)
        cd_offset, cd_size, count = _eocd(tail, tail_start, expected_length)
        if cd_size > MAX_BODY_BYTES - used["body"]:
            raise Unknown("directory exceeds byte budget")
        if cd_offset >= tail_start:
            cd = tail[cd_offset - tail_start:cd_offset - tail_start + cd_size]
        else:
            cd = _range(transport, cd_offset, cd_offset + cd_size - 1, expected_length, expected_etag, used)
        abis = _abis(cd, count)
        if not abis:
            decision = "CONTINUE_FULL_GET_CHECKS_NO_LIB_ABI_OBSERVED"
        elif "arm64-v8a" in abis:
            decision = "CONTINUE_FULL_GET_CHECKS_ARM64_DIRECTORY_OBSERVED"
        elif set(abis) <= {"armeabi", "armeabi-v7a"}:
            decision = "REJECT_ARM32_ONLY_STRUCTURAL_CANDIDATE"
        else:
            decision = "UNKNOWN_FALLBACK"
        return {"decision": decision, "observed_abis": abis, "entries": count,
                "remote_body_bytes_read": used["body"], "remote_header_bytes_accounted": used["headers"],
                "raw_admitted": False, "full_apk_get": False}
    except (Unknown, OSError, ValueError, struct.error, http.client.HTTPException) as error:
        return {"decision": "UNKNOWN_FALLBACK", "reason": type(error).__name__ + ": " + str(error),
                "remote_body_bytes_read": used["body"], "remote_header_bytes_accounted": used["headers"],
                "raw_admitted": False, "full_apk_get": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-g292", action="store_true", help="explicit bounded HTTPS Range probe; never a full APK GET")
    args = parser.parse_args()
    if not args.probe_g292:
        parser.error("no network by default; --probe-g292 required")
    result = preflight(HTTPSRangeTransport(URL), expected_length=EXPECTED_LENGTH, expected_etag=EXPECTED_ETAG)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["decision"] != "UNKNOWN_FALLBACK" else 3


if __name__ == "__main__":
    raise SystemExit(main())
