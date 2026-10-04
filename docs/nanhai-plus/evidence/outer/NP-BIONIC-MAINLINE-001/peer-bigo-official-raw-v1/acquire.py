#!/usr/bin/env python3
"""Acquire one exact official BIGO LIVE Android APK on the native host."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(os.environ["NANHAI_PROJECT_ROOT"])
HERE = Path(__file__).parent
STAGING = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-bigo-official-raw-v1"
PAGE = "https://www.bigo.tv/id/blog/bigo-live-apk"
APK_URL = "https://static-web.bigolive.tv/as/bigo-static/apk/bigolive-bigotv.apk"

def sha(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()

def run(name, argv, timeout):
    with (HERE / (name + ".stdout.raw")).open("xb") as out, (HERE / (name + ".stderr.raw")).open("xb") as err:
        p = subprocess.run(argv, stdout=out, stderr=err, timeout=timeout, check=False)
    return {"argv": argv, "rc": p.returncode, "stdout_sha256": sha(HERE / (name + ".stdout.raw")), "stderr_sha256": sha(HERE / (name + ".stderr.raw"))}

def main():
    if sys.argv[1:] != ["--execute"] or (HERE / "RESULT.json").exists(): return 2
    STAGING.mkdir(mode=0o700, parents=True, exist_ok=False)
    curl = os.environ["NANHAI_CURL"]
    page = run("page", [curl,"--fail","--location","--retry","0","--connect-timeout","15","--max-time","45","--output",str(HERE/"publisher-page.raw"),"--dump-header",str(HERE/"publisher-page-headers.raw"),PAGE], 60)
    head = run("head", [curl,"--fail","--location","--head","--retry","0","--connect-timeout","15","--max-time","30","--dump-header",str(HERE/"apk-head-headers.raw"),APK_URL],45)
    part = STAGING/"bigo-official.apk.part"
    get = run("get", [curl,"--fail","--location","--retry","0","--connect-timeout","15","--max-time","240","--output",str(part),"--dump-header",str(HERE/"apk-get-headers.raw"),APK_URL],260)
    page_data = (HERE/"publisher-page.raw").read_text(errors="replace")
    headers = (HERE/"apk-get-headers.raw").read_text(errors="replace").lower()
    result={"schema":"peer-bigo-official-raw-v1","at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"publisher_page":PAGE,"publisher_apk_url":APK_URL,"page":page,"head":head,"get":get,"publisher_page_links_exact_apk":APK_URL in page_data,"apk_mime_seen":"content-type: application/vnd.android.package-archive" in headers,"root_count_changed":False,"device_commands":0,"container_commands":0,"startup_proven":False}
    if part.exists():
        result["apk_bytes"]=part.stat().st_size
        result["apk_sha256"]=sha(part)
        try:
            with zipfile.ZipFile(part) as z:
                names=z.namelist()
                result["zip_entries"]=len(names)
                result["zip_first_bad"]=z.testzip()
                result["zip_duplicate_names"]=len(names)-len(set(names))
                result["manifest_entries"]=names.count("AndroidManifest.xml")
                result["root_dex_entries"]=sum(n.startswith("classes") and n.endswith(".dex") and "/" not in n for n in names)
                result["native_abis"]=sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.endswith(".so") and len(n.split("/"))>2})
                result["arm64_so_entries"]=sum(n.startswith("lib/arm64-v8a/") and n.endswith(".so") for n in names)
        except Exception as e: result["zip_error"]=repr(e)
    result["candidate_pass"]=(page["rc"]==head["rc"]==get["rc"]==0 and result["publisher_page_links_exact_apk"] and result["apk_mime_seen"] and result.get("zip_first_bad","failed") is None and result.get("zip_duplicate_names")==0 and result.get("manifest_entries")==1 and result.get("arm64_so_entries",0)>0)
    if result["candidate_pass"]:
        apk=STAGING/"bigo-official.apk"
        part.rename(apk)
        result["apk_path"]=str(apk.relative_to(ROOT))
    (HERE/"RESULT.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in ("page","head","get")},sort_keys=True))
    return 0 if result["candidate_pass"] else 2

if __name__=="__main__":sys.exit(main())
