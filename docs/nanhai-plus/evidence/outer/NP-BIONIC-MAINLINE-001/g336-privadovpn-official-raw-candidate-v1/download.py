import hashlib,json,os,pathlib,subprocess,sys
root=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT']);here=pathlib.Path(__file__).parent
url='https://privadovpn.com/apps/android/PrivadoVPN.apk';assert url in (here/'official-software.raw').read_text(errors='replace')
stage=pathlib.Path(os.environ['NANHAI_STAGING_ROOT'])/'g336-privadovpn-official-v1';stage.mkdir(exist_ok=False);out=stage/'PrivadoVPN.apk'
argv=['curl','-fLSsS','--max-time','180','-D',str(here/'apk-get.headers.raw'),url,'-o',str(out)]
with (here/'apk-get.stdout.raw').open('xb') as a,(here/'apk-get.stderr.raw').open('xb') as b:r=subprocess.run(argv,cwd=root,stdout=a,stderr=b)
print(json.dumps({'argv':argv,'rc':r.returncode,'file_exists':out.exists(),'bytes':out.stat().st_size if out.exists() else None,'sha256':hashlib.sha256(out.read_bytes()).hexdigest() if out.exists() else None}))
sys.exit(r.returncode)
