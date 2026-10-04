#!/usr/bin/env python3
"""Independent read-only verification of four other-author next4e raw/static candidates."""
import datetime,hashlib,json,os,re,struct,subprocess,sys,zipfile
from pathlib import Path
ROOT=Path(os.environ["NANHAI_PROJECT_ROOT"]);HERE=Path(__file__).parent
B=ROOT/"docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001"
SRC=B/"peer-upstream-next4e-exact-v1"
REG=B/"upstream-apk-registry-v1/REGISTRY.json"
STAGING=Path(os.environ["NANHAI_STAGING_ROOT"])/"peer-upstream-next4e-exact-v1"
TOOLS=Path.home()/"Library/Android/sdk/build-tools/36.1.0"
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for c in iter(lambda:f.read(1<<20),b""):h.update(c)
 return h.hexdigest()
def run(pkg,label,argv):
 p=subprocess.run([str(x) for x in argv],capture_output=True,timeout=120)
 d=HERE/pkg;d.mkdir(exist_ok=True)
 (d/(label+".stdout.raw")).write_bytes(p.stdout);(d/(label+".stderr.raw")).write_bytes(p.stderr)
 return {"argv":[str(x) for x in argv],"rc":p.returncode,"stdout_sha256":sha(d/(label+".stdout.raw")),"stderr_sha256":sha(d/(label+".stderr.raw"))}
def main():
 if sys.argv[1:]!=["--execute"] or (HERE/"RESULT.json").exists():return 2
 sel=json.loads((SRC/"SELECTION.json").read_text());reg=json.loads(REG.read_text());arts={a["id"]:a for a in reg["artifacts"]};hand={r["package"]:r for r in json.loads((SRC/"HANDOFF.json").read_text())["rows"]}
 rows=[]
 for pick in sel["rows"]:
  pkg=pick["package"];d=SRC/pkg;apk=STAGING/pkg/"original.apk"
  raw=json.loads((d/"RAW.json").read_text());sta=json.loads((d/"STATIC.json").read_text());art=arts[pick["artifact_id"]]
  zfacts={};count={"true_arm64":0,"arm32":0,"other_elf":0,"non_elf_so":0,"arm64_path_arm32":0}
  with zipfile.ZipFile(apk) as z:
   names=z.namelist();libs=[n for n in names if n.startswith("lib/") and n.endswith(".so")]
   dexs=[n for n in names if n.endswith(".dex")]
   zfacts={"entries":len(names),"duplicate_names":len(names)-len(set(names)),"crc_first_bad":z.testzip(),"manifest_count":names.count("AndroidManifest.xml"),"dex_names":dexs,"so_names":libs}
   for name in libs:
    data=z.read(name)
    if not data.startswith(b"\x7fELF"):count["non_elf_so"]+=1;continue
    bits=data[4];endian=data[5];mach=struct.unpack("<H" if endian==1 else ">H",data[18:20])[0]
    abi=name.split("/")[1]
    if abi=="arm64-v8a" and bits==2 and mach==183:count["true_arm64"]+=1
    elif abi=="arm64-v8a" and bits==1 and mach==40:count["arm64_path_arm32"]+=1
    elif bits==1 and mach==40:count["arm32"]+=1
    else:count["other_elf"]+=1
  aa=run(pkg,"aapt2",[TOOLS/"aapt2","dump","badging",apk]);ss=run(pkg,"apksigner",[TOOLS/"apksigner","verify","--verbose","--print-certs",apk])
  txt=(HERE/pkg/"aapt2.stdout.raw").read_text(errors="replace");sig=(HERE/pkg/"apksigner.stdout.raw").read_text(errors="replace")
  m=re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'",txt,re.M)
  certs=re.findall(r"Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)",sig)
  phase_checks={k:(v["rc"]==0 and v["input_guard_equal"] and v["apk_sha_before"]==v["apk_sha_after"]==pick["expected_sha256"]) for k,v in sta["phases"].items()}
  checks={"registry_id_package_sha_url_version":art["package"]==pkg and art["sha256"]==pick["expected_sha256"] and pick["source_url"] in art.get("source_urls",[]) and pick["version_code"] in art.get("version_codes",[]) and pick["version_name"] in art.get("versions",[]),"apk_sha_bytes":sha(apk)==pick["expected_sha256"] and apk.stat().st_size==raw["bytes"],"zip_crc_unique_manifest":zfacts["crc_first_bad"] is None and zfacts["duplicate_names"]==0 and zfacts["manifest_count"]==1,"raw_get_aapt_signer_rc":raw["get"]["rc"]==raw["aapt2"]["rc"]==raw["apksigner"]["rc"]==0,"independent_aapt_signer_rc":aa["rc"]==ss["rc"]==0,"identity":bool(m) and m.groups()==(pkg,pick["version_code"],pick["version_name"]),"cert_matches":bool(certs) and certs==[hand[pkg]["signer_cert_sha256"]],"dex_complete":len(zfacts["dex_names"])==sta["phases"]["dex"]["dex_entries"] and zfacts["dex_names"]==sta["phases"]["dex"]["dex_names"],"arm64_elf_matches":count["true_arm64"]==sta["phases"]["elf"]["arm64_elf_entries"]==sta["phases"]["elf"]["readelf_ok"]==sta["phases"]["elf"]["abi_matches_machine"],"all_four_guards":len(phase_checks)==4 and all(phase_checks.values()),"no_wrong_arm64_or_pseudo_so":count["arm64_path_arm32"]==count["non_elf_so"]==0}
  rows.append({"package":pkg,"artifact_id":pick["artifact_id"],"apk_sha256":sha(apk),"apk_bytes":apk.stat().st_size,"source_url":pick["source_url"],"version":m.groups() if m else None,"signer_cert_sha256":certs,"zip":zfacts,"elf":count,"phase_checks":phase_checks,"checks":checks,"all_pass":all(checks.values()),"aapt2":aa,"apksigner":ss,"candidate_raw_sha256":sha(d/"RAW.json"),"candidate_static_sha256":sha(d/"STATIC.json")})
 out={"schema":"peer-review-next4e-exact-v1","at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"reviewer_is_candidate_author":False,"selection_sha256":sha(SRC/"SELECTION.json"),"registry_sha256":sha(REG),"candidate_handoff_sha256":sha(SRC/"HANDOFF.json"),"rows":rows,"all_pass":len(rows)==4 and all(r["all_pass"] for r in rows),"limits":["F-Droid GET URL and registered SHA match; no independent publisher signing-key pin.","Static and signature do not prove installation, runtime or cold start.","Zero packaged native ELF for com.ltrademark.hourly is a Java-only inventory and not an ARM64 runtime proof.","Current anti-join was bounded to prior audit and root receipt filenames; not a full accepted-set reconstruction."],"root_count_changed":False,"container_commands":0,"device_commands":0,"bridge_commands":0,"startup_proven":False}
 (HERE/"RESULT.json").write_text(json.dumps(out,sort_keys=True,indent=2)+"\n")
 print(json.dumps({"all_pass":out["all_pass"],"packages":[[r["package"],r["all_pass"],r["elf"]["true_arm64"]] for r in rows]}));return 0 if out["all_pass"] else 2
if __name__=="__main__":sys.exit(main())
