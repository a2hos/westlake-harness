#!/usr/bin/env python3
import datetime,hashlib,json,os,re,subprocess,sys
from pathlib import Path
HERE=Path(__file__).parent
PUBLISHER="https://www.teamviewer.com/en/download/portal/android/"
PLAY="https://play.google.com/store/apps/details?id=com.teamviewer.quicksupport.market&hl=en_US"
APK_URL="https://download.teamviewer.com/download/TeamViewerQS.apk"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def get(name,url):
 p=subprocess.run([os.environ["NANHAI_CURL"],"--fail","--location","--retry","0","--connect-timeout","15","--max-time","45","--output",str(HERE/(name+".html")),url],capture_output=True,timeout=60)
 (HERE/(name+".stdout.raw")).write_bytes(p.stdout);(HERE/(name+".stderr.raw")).write_bytes(p.stderr)
 return {"argv":[os.environ["NANHAI_CURL"],"--fail","--location","--retry","0","--connect-timeout","15","--max-time","45","--output",str(HERE/(name+".html")),url],"rc":p.returncode,"stdout_sha256":sha(HERE/(name+".stdout.raw")),"stderr_sha256":sha(HERE/(name+".stderr.raw")),"body_sha256":sha(HERE/(name+".html")) if p.returncode==0 else None}
def main():
 if sys.argv[1:] != ["--execute"] or (HERE/"QUALIFICATION.json").exists():return 2
 p=get("publisher",PUBLISHER);g=get("play",PLAY)
 a=(HERE/"publisher.html").read_text(errors="replace");b=(HERE/"play.html").read_text(errors="replace")
 result={"schema":"peer-teamviewer-qs-qualification-v1","at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"publisher_page":PUBLISHER,"publisher_apk_url":APK_URL,"play_url":PLAY,"fetch":{"publisher":p,"play":g},"publisher_exact_apk_href":APK_URL in a,"play_exact_package_seen":"com.teamviewer.quicksupport.market" in b,"play_50m_seen":"50M+" in b,"play_publisher_seen":"TeamViewer" in b,"source_scope":"Publisher download and same-package Play listing plus bounded project registry check; source-code absence is not globally proved.","root_count_changed":False,"device_commands":0,"container_commands":0,"startup_proven":False}
 result["candidate_pass"]=p["rc"]==g["rc"]==0 and result["publisher_exact_apk_href"] and result["play_exact_package_seen"] and result["play_50m_seen"] and result["play_publisher_seen"]
 (HERE/"QUALIFICATION.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(json.dumps(result,sort_keys=True));return 0 if result["candidate_pass"] else 2
if __name__=="__main__":sys.exit(main())
