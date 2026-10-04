#!/usr/bin/env python3
import hashlib,json,os,pathlib,subprocess,sys
root=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT']);here=pathlib.Path(__file__).parent
api=json.loads((here/'release-api.raw').read_text());assert api['tag_name']=='5.20.57.0'
name='ProtonVPN-5.20.57.0.605205700.-production-vanilla-direct-release.apk'
asset=next(a for a in api['assets'] if a['name']==name)
assert asset['browser_download_url'].startswith('https://github.com/ProtonVPN/android-app/releases/download/5.20.57.0/')
assert asset['digest']=='sha256:57b06d74cb00fe73e26cc0232dbae98bbeed52738ef5ce5d7c8cafa2a9de20e6' and asset['size']==64238953
stage=pathlib.Path(os.environ['NANHAI_STAGING_ROOT'])/'g332-protonvpn-official-v1';stage.mkdir(exist_ok=False)
out=stage/name
argv=['curl','-fLSsS','--max-time','180','-D',str(here/'apk-get.headers.raw'),asset['browser_download_url'],'-o',str(out)]
run=subprocess.run(argv,cwd=root,stdout=(here/'apk-get.stdout.raw').open('xb'),stderr=(here/'apk-get.stderr.raw').open('xb'))
print(json.dumps({'argv':argv,'rc':run.returncode,'file_exists':out.exists(),'bytes':out.stat().st_size if out.exists() else None,'sha256':hashlib.sha256(out.read_bytes()).hexdigest() if out.exists() else None}))
sys.exit(run.returncode)
