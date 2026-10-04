#!/usr/bin/env python3
"""One-shot host-only acquisition via AdGuard VPN's APK link."""
import datetime,hashlib,json,os,pathlib,subprocess,sys,zipfile
ROOT=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT']);HERE=pathlib.Path(__file__).parent
OUT=pathlib.Path(os.environ['NANHAI_STAGING_ROOT'])/'blackbox-adguardvpn-official-intake-candidate-v1'
ENTRY='https://agrd.io/android_vpn_apk';URL='https://static.adtidy.net/android/release/adguard-vpn.apk';BYTES=53867990
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def run(name,args,timeout):
 r=subprocess.run(args,capture_output=True,timeout=timeout,env={**os.environ,'LC_ALL':'C'})
 (OUT/(name+'.stdout.raw')).write_bytes(r.stdout);(OUT/(name+'.stderr.raw')).write_bytes(r.stderr)
 return {'rc':r.returncode,'argv':args,'stdout_sha256':sha(OUT/(name+'.stdout.raw')),'stderr_sha256':sha(OUT/(name+'.stderr.raw'))}
def main():
 if sys.argv[1:]:raise SystemExit(2)
 if OUT.exists():raise RuntimeError('one-shot staging exists')
 OUT.mkdir(parents=True,mode=0o700)
 curl=os.environ['NANHAI_CURL'];common=[curl,'--disable','--silent','--show-error','--proto','=https','--proto-redir','=https','--connect-timeout','10','--retry','0','--no-location','--max-redirs','0']
 entry=run('entry',common+['--head','--max-time','20','--dump-header',str(OUT/'entry.headers.raw'),ENTRY],25)
 eh=(OUT/'entry.headers.raw').read_text(errors='replace').lower()
 if entry['rc']!=0 or 'http/2 301' not in eh or 'location: '+URL.lower() not in eh:raise RuntimeError('publisher link drift')
 fixed=run('fixed',common+['--head','--max-time','20','--dump-header',str(OUT/'fixed.headers.raw'),URL],25)
 fh=(OUT/'fixed.headers.raw').read_text(errors='replace').lower()
 if fixed['rc']!=0 or 'http/1.1 200 ok' not in fh or f'content-length: {BYTES}' not in fh:raise RuntimeError('fixed URL drift')
 body=OUT/'adguard-vpn.apk'
 get=run('get',common+['--fail-with-body','--max-time','120','--max-filesize',str(BYTES),'--dump-header',str(OUT/'get.headers.raw'),'--output',str(body),'--write-out','%{json}',URL],125)
 metrics=json.loads((OUT/'get.stdout.raw').read_text())
 if get['rc']!=0 or metrics['http_code']!=200 or metrics['ssl_verify_result']!=0 or metrics['num_redirects']!=0 or metrics['url_effective']!=URL:raise RuntimeError('GET transport failure')
 if body.stat().st_size!=BYTES or metrics['size_download']!=BYTES:raise RuntimeError('GET size mismatch')
 with zipfile.ZipFile(body) as z:
  bad=z.testzip();names=z.namelist()
  if bad or names.count('AndroidManifest.xml')!=1:raise RuntimeError('ZIP/manifest failure '+str(bad))
  arm64=[n for n in names if n.startswith('lib/arm64-v8a/') and n.endswith('.so')]
 receipt={'schema':'adguardvpn-official-host-raw-candidate-v1','status':'HOST_RAW_CANDIDATE_ONLY','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'official_page':'https://adguard-vpn.com/en/free-vpn/android.html','official_entry':ENTRY,'fixed_url':URL,'bytes':BYTES,'sha256':sha(body),'zip_crc_all':True,'zip_members':len(names),'arm64_so_name_count':len(arm64),'calls':{'entry':entry,'fixed':fixed,'get':get},'get_metrics':{k:metrics.get(k) for k in ('http_code','ssl_verify_result','num_redirects','url_effective','size_download','time_total')},'independent_review':False,'raw_accepted':False,'blackbox_qualified':False,'startup_proven':False,'device_commands':0,'container_commands':0}
 with (OUT/'ACQUISITION.json').open('x') as f:json.dump(receipt,f,indent=2);f.write('\n')
 print(json.dumps({'receipt':str(OUT/'ACQUISITION.json'),'sha256':receipt['sha256'],'bytes':BYTES,'arm64_so_names':len(arm64)}))
if __name__=='__main__':main()
