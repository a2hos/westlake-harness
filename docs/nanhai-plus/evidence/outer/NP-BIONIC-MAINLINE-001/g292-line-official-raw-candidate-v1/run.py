#!/usr/bin/env python3
"""Prepared G292 LINE official CDN one-shot raw candidate; never auto-retry."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
import zipfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[5]
PAGE='https://line-android-universal-download.line-scdn.net/line-apk-download.html'
APK='https://line-android-universal-download.line-scdn.net/line-15.21.3.apk'
BYTES=190235503
HEAD_ETAG='"e1628f42066cb5c669fa96ddaaf618a3"'
HEAD_LAST_MODIFIED='Sat, 20 Dec 2025 04:26:04 GMT'
PACKAGE='jp.naver.line.android'
VERSION='15.21.3'
ENV_SHA='5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718'
REGISTRY_SHA='289dcdb499d5ff37e58a8e7d4fbd3d30e3fe9f77d4e7e8ba7139c927c890c1eb'
TOOLS_SHA={'curl':'b636262803922ee1dd0fbf614818473ffa53c811e44fd3278c2270d3af4759d3',
           'aapt2':'3c5920804724dfe9a43e0dbf1f5b5dcbf08c4a2e829bebdaa04d38bfe7d7ada4',
           'apksigner':'9469c60e5e40fc5c44a2f2338509cb6600cdf065e9b50f9fa3ca6c5be5bae6a9',
           'java':'cd158e1a5328ff42b687b7c2f5c61c7c3be3cfee7f18226ee903169e97336158'}

class GateError(RuntimeError):pass
def need(ok,why):
    if not ok:raise GateError(why)
def utc():return datetime.now(timezone.utc).isoformat()
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()
def exclusive_json(path,obj):
    data=(json.dumps(obj,indent=2,ensure_ascii=False)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    dfd=os.open(Path(path).parent,os.O_RDONLY)
    try:os.fsync(dfd)
    finally:os.close(dfd)
def final_json(path,obj):
    path=Path(path);tmp=path.with_name(path.name+'.pending.'+str(os.getpid()))
    exclusive_json(tmp,obj)
    try:
        os.link(tmp,path)
        dfd=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    finally:tmp.unlink(missing_ok=True)
def command(name,argv,timeout,env):
    began,tick=utc(),time.monotonic()
    try:
        p=subprocess.run(argv,cwd=HERE,env=env,capture_output=True,timeout=timeout,check=False)
        rc,out,err,timed=p.returncode,p.stdout,p.stderr,False
    except subprocess.TimeoutExpired as e:
        rc,out,err,timed=None,e.stdout or b'',e.stderr or b'',True
    (HERE/(name+'.stdout.raw')).write_bytes(out)
    (HERE/(name+'.stderr.raw')).write_bytes(err)
    return {'name':name,'argv':argv,'began_utc':began,'ended_utc':utc(),
            'elapsed_seconds':round(time.monotonic()-tick,3),'rc':rc,'timed_out':timed,
            'stdout_sha256':hashlib.sha256(out).hexdigest(),'stdout_bytes':len(out),
            'stderr_sha256':hashlib.sha256(err).hexdigest(),'stderr_bytes':len(err)}
def transfer(name):
    s=(HERE/(name+'.stdout.raw')).read_text(errors='replace')
    fields=dict(re.findall(r'(http|tls|bytes|redirects|effective)=([^\s]+)',s))
    need(set(fields)=={'http','tls','bytes','redirects','effective'},name+' transfer fields')
    return fields
def official_page_url(raw):
    s=raw.decode('utf-8',errors='replace')
    hrefs=re.findall(r'<a\s+[^>]*apk-auto-download[^>]*href="([^"]+)"',s,re.I)
    refresh=re.findall(r'<meta\s+[^>]*http-equiv="refresh"[^>]*content="[^"]*URL=\'([^\']+)\'"',s,re.I)
    need(hrefs==[APK] and refresh==[APK], 'official page href/refresh exact URL drift')
    return APK
def head_identity(raw):
    s=raw.decode('latin1')
    lengths=re.findall(r'(?im)^content-length:\s*(\d+)\s*$',s)
    types=re.findall(r'(?im)^content-type:\s*([^\r\n]+)',s)
    etags=re.findall(r'(?im)^etag:\s*([^\r\n]+)',s)
    modified=re.findall(r'(?im)^last-modified:\s*([^\r\n]+)',s)
    need(all(len(x)==1 for x in (lengths,types,etags,modified)),
         'HEAD header multiplicity drift')
    return int(lengths[0]),types[0].strip().lower(),etags[0].strip(),modified[0].strip()
def bindings_and_tools(result):
    loader=ROOT/'scripts/nanhai_plus_env.py'
    spec=importlib.util.spec_from_file_location('nanhai_plus_env',loader)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    b,a=m.load_environment(ROOT/'local_env.md')
    need(a['config_sha256']==ENV_SHA and b['NANHAI_PROJECT_ROOT']==str(ROOT) and
         b['NANHAI_EVIDENCE_ROOT']==str(HERE.parents[2]) and
         b['NANHAI_CONTAINER_POLICY']=='forbidden','environment binding drift')
    for key,value in b.items():need(os.environ.get(key)==value,'inherited env drift: '+key)
    pool=Path(b['NANHAI_SOURCE_POOL_ROOT'])
    tools={'curl':Path(b['NANHAI_CURL']),
           'aapt2':pool/'AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/bin/aapt2',
           'apksigner':pool/'AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/lib/apksigner.jar',
           'java':Path('/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home/bin/java')}
    for name,path in tools.items():need(sha(path)==TOOLS_SHA[name],'tool SHA drift: '+name)
    reg=Path(b['NANHAI_EVIDENCE_ROOT'])/'outer/NP-BIONIC-MAINLINE-001/upstream-apk-registry-v1/REGISTRY.json'
    need(sha(reg)==REGISTRY_SHA,'registry SHA drift')
    d=json.loads(reg.read_text())
    need(not any(x.get('package')==PACKAGE for x in d['apps']) and
         not any(x.get('package')==PACKAGE for x in d['records']),'registry duplicate')
    result['environment']={'config_sha256':a['config_sha256'],'registry_sha256':REGISTRY_SHA}
    result['tools_before']=dict(TOOLS_SHA)
    return b,tools
def execute(result):
    b,tools=bindings_and_tools(result)
    stage=Path(b['NANHAI_STAGING_ROOT'])/'g292-line-official-raw-candidate-v1'
    need(not stage.exists(),'staging already exists; one-shot state unknown')
    stage.mkdir(parents=True,exist_ok=False)
    result['staging']=str(stage)
    page=HERE/'runtime-page.body.raw';head=HERE/'runtime-head.headers.raw'
    part=stage/'line-15.21.3.apk.part';apk=stage/'line-15.21.3.apk'
    env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC','TMPDIR':str(stage)}
    for key in ('HTTPS_PROXY','HTTP_PROXY','ALL_PROXY','NO_PROXY','https_proxy','http_proxy','all_proxy','no_proxy'):
        if key in os.environ:env[key]=os.environ[key]
    base=[str(tools['curl']),'-q','--fail','--silent','--show-error','--proto','=https',
          '--proto-redir','=https','--retry','0','--connect-timeout','15']
    fmt='http=%{http_code} tls=%{ssl_verify_result} bytes=%{size_download} redirects=%{num_redirects} effective=%{url_effective}'
    pagecmd=base+['--max-time','20','--max-filesize','100000','--output',str(page),'--write-out',fmt,PAGE]
    rec=command('runtime-page',pagecmd,25,env);result['commands'].append(rec)
    need(rec['rc']==0 and not rec['timed_out'],'official page GET failed')
    pt=transfer('runtime-page');result['page_transfer']=pt
    need(pt['http']=='200' and pt['tls']=='0' and pt['redirects']=='0' and pt['effective']==PAGE,
         'official page HTTP/TLS/URL drift')
    need(page.is_file() and page.stat().st_size<=100000,'page byte cap drift')
    result['page']={'bytes':page.stat().st_size,'sha256':sha(page),'exact_url':official_page_url(page.read_bytes())}
    headcmd=base+['--head','--max-time','20','--dump-header',str(head),'--output','/dev/null','--write-out',fmt,APK]
    rec=command('runtime-head',headcmd,25,env);result['commands'].append(rec)
    need(rec['rc']==0 and not rec['timed_out'],'APK HEAD failed')
    ht=transfer('runtime-head');result['head_transfer']=ht
    need(ht['http']=='200' and ht['tls']=='0' and ht['redirects']=='0' and ht['effective']==APK,
         'APK HEAD HTTP/TLS/URL drift')
    length,mime,etag,last_modified=head_identity(head.read_bytes())
    need(length==BYTES and mime=='application/octet-stream' and
         etag==HEAD_ETAG and last_modified==HEAD_LAST_MODIFIED,
         'APK HEAD size/MIME/ETag/Last-Modified drift')
    result['head']={'sha256':sha(head),'content_length':length,'content_type':mime,
                    'etag_observed_not_sha256':etag,'last_modified':last_modified}
    getcmd=base+['--max-time','300','--max-filesize',str(BYTES),'--output',str(part),'--write-out',fmt,APK]
    rec=command('runtime-download',getcmd,310,env);result['commands'].append(rec)
    if part.exists():result['part']={'bytes':part.stat().st_size,'sha256':sha(part)}
    need(rec['rc']==0 and not rec['timed_out'],'sole APK GET failed; no retry')
    gt=transfer('runtime-download');result['download_transfer']=gt
    need(gt['http']=='200' and gt['tls']=='0' and gt['redirects']=='0' and gt['effective']==APK and
         int(gt['bytes'])==BYTES and part.stat().st_size==BYTES,'APK GET HTTP/TLS/bytes drift')
    part.rename(apk)
    result['apk']={'path':str(apk),'bytes':BYTES,'sha256':sha(apk),
                   'publisher_artifact_digest':None,'sha256_role':'observed received bytes'}
    with zipfile.ZipFile(apk) as z:
        names=z.namelist();result['zip']={'entries':len(names),'bad_entry':z.testzip(),
            'manifest_count':names.count('AndroidManifest.xml'),
            'lib_abis':sorted({m.group(1) for n in names if (m:=re.match(r'lib/([^/]+)/[^/]+\.so$',n))})}
    need(result['zip']['bad_entry'] is None and result['zip']['manifest_count']==1,'ZIP/Manifest invalid')
    for name,argv in [('runtime-badging',[str(tools['aapt2']),'dump','badging',str(apk)]),
        ('runtime-signature',[str(tools['java']),'-XX:-UsePerfData','-Xmx512m','-Djava.awt.headless=true',
                      '-Djava.io.tmpdir='+str(stage),'-jar',str(tools['apksigner']),
                      'verify','--verbose','--print-certs',str(apk)])]:
        rec=command(name,argv,120,env);result['commands'].append(rec)
        need(rec['rc']==0 and not rec['timed_out'],name+' failed')
    badging=(HERE/'runtime-badging.stdout.raw').read_text(errors='replace')
    sig=(HERE/'runtime-signature.stdout.raw').read_text(errors='replace')
    line=next((x for x in badging.splitlines() if x.startswith('package: ')),None)
    native=next((x for x in badging.splitlines() if x.startswith('native-code:')),None)
    min_sdk=next((x for x in badging.splitlines() if x.startswith(('minSdkVersion:','sdkVersion:'))),None)
    target=next((x for x in badging.splitlines() if x.startswith('targetSdkVersion:')),None)
    need(line and min_sdk and target,'manifest fields missing')
    def field(key):
        m=re.search(r'\b'+re.escape(key)+r"='([^']+)'",line)
        need(m is not None,'missing '+key)
        return m.group(1)
    result['manifest']={'package':field('name'),'version_code':field('versionCode'),
                        'version_name':field('versionName'),'min_sdk_line':min_sdk,
                        'target_sdk_line':target,'native_code':native}
    need(result['manifest']['package']==PACKAGE and result['manifest']['version_name']==VERSION,
         'manifest package/version mismatch')
    need(result['zip']['lib_abis'] in ([],['arm64-v8a'],['arm64-v8a','armeabi-v7a']),
         'no ARM64-compatible native variant')
    cert=re.search(r'(?im)^Signer #1 certificate SHA-256 digest:\s*([0-9a-f]{64})\s*$',sig)
    need(cert is not None and 'Number of signers: 1' in sig and
         ('Verified using v2 scheme (APK Signature Scheme v2): true' in sig or
          'Verified using v3 scheme (APK Signature Scheme v3): true' in sig),'APK signature failure')
    result['signature']={'observed_cert_sha256':cert.group(1).lower(),
                         'publisher_certificate_anchor':None,'verified':True}
    result['tools_after']={name:sha(path) for name,path in tools.items()}
    need(result['tools_after']==result['tools_before'] and sha(apk)==result['apk']['sha256'],
         'postguard drift')
def main():
    if sys.argv[1:]!=['--execute']:
        raise SystemExit('PREPARED_ONLY: explicit --execute required')
    start={'schema':'g292-line-raw-start-v1','at_utc':utc(),'status':'REMOTE_STATE_UNKNOWN_IN_PROGRESS',
           'script_sha256':sha(__file__),'page':PAGE,'apk_url':APK,'expected_head_bytes':BYTES,
           'meaning':'If RESULT is absent, inspect; never replay this generation.'}
    exclusive_json(HERE/'START.json',start)
    result={'schema':'g292-line-raw-result-v1','start_sha256':sha(HERE/'START.json'),
            'commands':[],'candidate_only':True,'raw_accepted':False,'blackbox_qualified':False,
            'canonical_delta':0,'device_commands':0,'container_commands':0}
    old=signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(GateError('SIGTERM interrupted')))
    try:
        execute(result);result['status']='OFFICIAL_CHANNEL_RAW_CANDIDATE_STATIC_PASS'
    except BaseException as e:
        result['status']='TERMINAL_FAILED';result['error_type']=type(e).__name__;result['error']=str(e)[:500]
    finally:
        signal.signal(signal.SIGTERM,old);result['ended_utc']=utc();final_json(HERE/'RESULT.json',result)
    print(json.dumps({'status':result['status'],'result':str(HERE/'RESULT.json')}))
if __name__=='__main__':main()
