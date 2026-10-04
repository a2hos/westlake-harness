import os,pathlib,json,hashlib,datetime
P=pathlib.Path;R=P(os.environ["NANHAI_PROJECT_ROOT"]);L=P(__file__).parent;I=json.loads((L/"INPUTS.json").read_text());V=P(I["venv"]);Q=I["tool_mapping"]
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(p):
 h=hashlib.sha256()
 with P(p).open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()
def put(p,v):
 with P(p).open("x") as f:json.dump(v,f,ensure_ascii=False,indent=2);f.write("\n")
def guard(name=None,full=False):
 got={}
 for rel,h in I["source_sha256"].items():
  got[rel]=sha(R/rel);assert got[rel]==h,rel
 assert sha(Q["target"])==Q["tool_sha256"]
 alias=P(Q["alias"]);assert alias.is_symlink() and alias.resolve()==P(Q["target"]).resolve()
 for a in I["apks"]:
  if name and a["registry_package_label"]!=name:continue
  p=R/a["path"];assert sha(p)==a["sha256"] and p.stat().st_size==a["bytes"]
  v=L/"apk-view"/(a["registry_package_label"]+".apk");assert v.is_symlink() and v.resolve()==p.resolve()
 if full:
  mp=P(I["venv_manifest"]["path"]);assert sha(mp)==I["venv_manifest"]["sha256"]==Q["venv_manifest_sha256"]
  m=json.loads(mp.read_text());actual={str(p.relative_to(V)) for p in V.rglob("*") if p.is_file() or p.is_symlink()};assert actual=={x["path"] for x in m["entries"]}
  for x in m["entries"]:
   p=V/x["path"]
   if x["kind"]=="symlink":assert p.is_symlink() and os.readlink(p)==x["link"] and str(p.resolve())==x["resolved"] and sha(p)==x["resolved_sha256"]
   else:assert not p.is_symlink() and p.stat().st_size==x["bytes"] and sha(p)==x["sha256"]
  got["venv_manifest"]={"sha256":sha(mp),"entries_verified":len(m["entries"])}
 got["readelf"]={"sha256":sha(Q["target"]),"alias":str(alias),"resolved":str(alias.resolve())};return got
