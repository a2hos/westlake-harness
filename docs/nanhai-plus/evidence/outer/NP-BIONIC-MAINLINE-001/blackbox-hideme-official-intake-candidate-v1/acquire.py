#!/usr/bin/env python3
"""One-shot host-only acquisition of hide.me's officially linked APK."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(os.environ['NANHAI_PROJECT_ROOT'])
OUT = Path(os.environ['NANHAI_STAGING_ROOT']) / 'blackbox-hideme-official-intake-candidate-v1'
ENTRY = 'https://hide.me/download/android/apk'
URL = 'https://hide.me/downloads/Hide.me-6.1.2.apk'
EXPECTED_BYTES = 67834658

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')

def call(name, argv, timeout=130):
    run = subprocess.run(argv, capture_output=True, timeout=timeout, env={**os.environ, 'LC_ALL':'C'})
    (OUT / (name + '.stdout.raw')).write_bytes(run.stdout)
    (OUT / (name + '.stderr.raw')).write_bytes(run.stderr)
    return {'rc':run.returncode, 'argv':argv, 'stdout_sha256':sha(OUT/(name+'.stdout.raw')), 'stderr_sha256':sha(OUT/(name+'.stderr.raw'))}

def main():
    if OUT.exists():
        raise RuntimeError('one-shot staging already exists')
    OUT.mkdir(parents=True, mode=0o700)
    curl = os.environ['NANHAI_CURL']
    common = [curl,'--disable','--silent','--show-error','--proto','=https','--proto-redir','=https','--connect-timeout','10','--retry','0']
    entry = call('entry', common+['--head','--max-time','20','--max-redirs','0','--no-location','--dump-header',str(OUT/'entry.headers.raw'),ENTRY],25)
    head = (OUT/'entry.headers.raw').read_text(errors='replace')
    if entry['rc'] != 0 or 'HTTP/2 302' not in head or 'location: '+URL.lower() not in head.lower():
        raise RuntimeError('official redirect changed')
    fixed = call('fixed',common+['--head','--max-time','20','--max-redirs','0','--no-location','--dump-header',str(OUT/'fixed.headers.raw'),URL],25)
    hdr=(OUT/'fixed.headers.raw').read_text(errors='replace').lower()
    if fixed['rc'] != 0 or 'http/2 200' not in hdr or f'content-length: {EXPECTED_BYTES}' not in hdr:
        raise RuntimeError('fixed artifact HEAD changed')
    body = OUT/'hide-me-6.1.2.apk'
    got = call('get',common+['--fail-with-body','--no-location','--max-redirs','0','--max-time','120','--max-filesize',str(EXPECTED_BYTES),'--dump-header',str(OUT/'get.headers.raw'),'--output',str(body),'--write-out','%{json}',URL],125)
    metrics=json.loads((OUT/'get.stdout.raw').read_text())
    if got['rc'] != 0 or metrics['http_code'] != 200 or metrics['ssl_verify_result'] != 0 or metrics['num_redirects'] != 0 or metrics['url_effective'] != URL:
        raise RuntimeError('GET transport failed')
    if body.stat().st_size != EXPECTED_BYTES or metrics['size_download'] != EXPECTED_BYTES:
        raise RuntimeError('GET size mismatch')
    with zipfile.ZipFile(body) as z:
        bad=z.testzip()
        if bad: raise RuntimeError('ZIP CRC: '+bad)
        members=z.namelist()
        abi=sorted({s.split('/')[1] for s in members if s.startswith('lib/') and len(s.split('/'))>2})
        if 'AndroidManifest.xml' not in members: raise RuntimeError('no manifest')
        native64=[s for s in members if s.startswith('lib/arm64-v8a/') and s.endswith('.so')]
    receipt={'status':'HOST_RAW_CANDIDATE_ONLY','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'official_page':'https://hide.me/en/software/android','official_entry':ENTRY,'fixed_url':URL,'size':body.stat().st_size,'sha256':sha(body),'zip_crc_all':True,'zip_members':len(members),'abi_dirs':abi,'arm64_so_count':len(native64),'manifest_entry':True,'calls':{'entry':entry,'fixed':fixed,'get':got},'get_metrics':{k:metrics.get(k) for k in ('http_code','ssl_verify_result','url_effective','num_redirects','size_download','time_total')},'source_claims':{'publisher':'eVenture Limited','play_package':'hideme.android.vpn','play_downloads':'1M+','webpage':'https://play.google.com/store/apps/details?id=hideme.android.vpn'},'static_accepted':False,'blackbox_qualified':False,'cold_start_accepted':False,'device_commands':0,'container_commands':0}
    write(OUT/'ACQUISITION.json',receipt)
    print(json.dumps({'result':str(OUT/'ACQUISITION.json'),'sha256':receipt['sha256'],'bytes':receipt['size'],'abi_dirs':abi}))

if __name__=='__main__':
    if sys.argv[1:]: raise SystemExit(2)
    main()
