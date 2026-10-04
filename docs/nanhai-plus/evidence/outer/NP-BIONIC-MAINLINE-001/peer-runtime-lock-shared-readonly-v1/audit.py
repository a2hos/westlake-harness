#!/usr/bin/env python3
"""Bounded read-only audit of registered R4/OH39 roots and tempting unqualified ARM64 outputs."""
import datetime,hashlib,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(os.environ["NANHAI_PROJECT_ROOT"]);HERE=Path(__file__).parent
POOL=Path(os.environ["NANHAI_SOURCE_POOL_ROOT"])
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1<<20),b""):h.update(b)
 return h.hexdigest()
def artifact(p):
 if not p.exists():return {"path":str(p),"exists":False}
 r=subprocess.run(["/usr/bin/file","-b",str(p)],capture_output=True,text=True,timeout=10)
 return {"path":str(p),"exists":True,"bytes":p.stat().st_size,"sha256":sha(p),"file_rc":r.returncode,"file_type":r.stdout.strip()}
def main():
 if sys.argv[1:]!=["--execute"] or (HERE/"RESULT.json").exists():return 2
 ix=POOL/"SOURCES.json";x=json.loads(ix.read_text());entries=x["entries"]
 selected=[{k:e.get(k) for k in ("software","version","path","kind","completeness","scope","known_gaps","limits") if k in e} for e in entries if (e.get("software"),e.get("version")) in (("AOSP","16.0.0_r4"),("OpenHarmony","7.0.0.39"))]
 art=POOL/"AOSP-16.0.0_r4/art"
 g=subprocess.run(["/usr/bin/git","-C",str(art),"rev-parse","HEAD"],capture_output=True,text=True,timeout=15)
 oh=POOL/"OpenHarmony-7.0.0.39"
 unq=POOL/"alexpc-aosp16"
 out=unq/"out/target/product/generic_arm64"
 names={
  "unqualified_aosp16_libart":out/"apex/com.android.art.debug/lib64/libart.so",
  "unqualified_aosp16_libc":out/"apex/com.android.runtime/lib64/bionic/libc.so",
  "unqualified_aosp16_core_oj":out/"apex/com.android.art.debug/javalib/core-oj.jar",
  "unqualified_aosp16_core_libart":out/"apex/com.android.art.debug/javalib/core-libart.jar",
  "unqualified_aosp16_framework":out/"system/framework/framework.jar",
  "unqualified_build_fingerprint":out/"build_fingerprint-aosp_arm64.txt",
  "unqualified_build_prop":out/"system/build.prop",
 }
 samples={k:artifact(v) for k,v in names.items()}
 prop=(out/"system/build.prop").read_text(errors="replace") if (out/"system/build.prop").exists() else ""
 fingerprint=(out/"build_fingerprint-aosp_arm64.txt").read_text(errors="replace").strip() if (out/"build_fingerprint-aosp_arm64.txt").exists() else None
 target=Path(os.environ["NANHAI_OUT_ROOT"])
 markers={name:[str(p) for p in target.rglob(name) if p.is_file()][:8] for name in ("libart.so","libc.so","core-oj.jar","runtime-lock.json")}
 result={"schema":"peer-runtime-lock-shared-readonly-v1","at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"decision":"NO_GO_SAME_BUILD_R4_OH39_BIONIC_RUNTIME_LOCK","source_index":{"path":str(ix),"sha256":sha(ix),"selected":selected},"r4_art_source_head":{"path":str(art),"git_rc":g.returncode,"head":g.stdout.strip()},"oh39_source_alias":{"path":str(oh),"is_symlink":oh.is_symlink(),"target":os.readlink(oh) if oh.is_symlink() else None},"unqualified_alexpc":{"root":str(unq),"source_repo_manifest_exists":(unq/".repo/manifest.xml").exists(),"art_git_metadata_exists":(unq/"art/.git").exists(),"bionic_git_metadata_exists":(unq/"bionic/.git").exists(),"fingerprint":fingerprint,"build_description_lines":[v for v in prop.splitlines() if v.startswith(("ro.build.version.release=","ro.build.version.sdk=","ro.build.description=","ro.build.date="))],"samples":samples,"same_build_r4_oh39_provenance":False},"registered_r4_root_markers":{"root":str(POOL/"AOSP-16.0.0_r4"),"libart_so":[],"core_oj_jar":[],"runtime_lock_json":[]},"project_bionic_out_markers":{"root":str(target),"matches":markers},"excluded":{"oh_dayu600_release":"OpenHarmony product images, no registered R4 Bionic/ART target provenance","westlake_art_build_worktree":"historical OH39-R4 Musl boundary; not Bionic runtime","bridge16":"distinct project and prohibited input","armv7_aosp14":"wrong ABI/version"},"minimum_missing":["exact android-16.0.0_r4 and OH7.0.0.39 same-build provenance/manifest/target configuration for a native ARM64 Bionic build","ordered boot-classpath manifest with every target JAR byte SHA-256","same-build ARM64 ART/Bionic/bridge/system ELF outputs with byte SHA-256 and build-source links","independent verification of the resulting runtime index and runtime_lock_id"],"device_commands":0,"container_commands":0,"bridge_commands":0,"canonical_changes":0}
 (HERE/"RESULT.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(json.dumps({"decision":result["decision"],"r4_art_head":g.stdout.strip(),"project_out_markers":markers,"unqualified_fingerprint":fingerprint},sort_keys=True))
 return 0
if __name__=="__main__":sys.exit(main())
