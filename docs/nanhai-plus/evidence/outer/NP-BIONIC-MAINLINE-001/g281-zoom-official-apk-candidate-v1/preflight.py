import hashlib,json,pathlib,subprocess,time,zipfile,struct,sys
root=pathlib.Path(__file__).resolve().parent
apk=pathlib.Path(sys.argv[1]).resolve()
sha=lambda b:hashlib.sha256(b).hexdigest()
expected='ead71709006b62aa6b22e74f39a7058177d7de3dc3449e8f0be82f31f78ee52b'
assert sha(apk.read_bytes())==expected
with zipfile.ZipFile(apk) as z:
    names=z.namelist(); native=[]; dex=[]
    for n in names:
        if n.startswith('lib/') and n.endswith('.so'):
            with z.open(n) as f: head=f.read(20)
            abi=n.split('/')[1]
            valid=(abi=='arm64-v8a' and head[:5]==b'\x7fELF\x02' and head[18:20]==b'\xb7\x00') or (abi=='armeabi-v7a' and head[:5]==b'\x7fELF\x01' and head[18:20]==b'\x28\x00')
            native.append({'name':n,'abi_matches_elf':valid})
        if n.startswith('classes') and n.endswith('.dex') and '/' not in n:
            with z.open(n) as f: head=f.read(8)
            dex.append({'name':n,'magic':head.hex()})
    facts={'entries':len(names),'unique_names':len(names)==len(set(names)),'root_manifest_count':names.count('AndroidManifest.xml'),'dex':dex,'native_abis':sorted({x['name'].split('/')[1] for x in native}),'native_count':len(native),'native_counts_by_abi':{abi:sum(x['name'].split('/')[1]==abi for x in native) for abi in sorted({x['name'].split('/')[1] for x in native})},'invalid_native':[x['name'] for x in native if not x['abi_matches_elf']],'crc_first_failure':z.testzip(),'apk_sha256':expected}
(root/'ZIP-FACTS.json').write_text(json.dumps(facts,indent=2)+'\n')
commands={
 'badging':['/opt/19.SourceCode/AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/bin/aapt2','dump','badging',str(apk)],
 'signature':['/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home/bin/java','-XX:-UsePerfData','-Xmx512m','-Djava.awt.headless=true','-Djava.io.tmpdir='+str(root),'-jar','/opt/19.SourceCode/AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/lib/apksigner.jar','verify','--verbose','--print-certs',str(apk)]}
for name,argv in commands.items():
 t=time.monotonic();p=subprocess.run(argv,capture_output=True,timeout=180)
 (root/(name+'.stdout.raw')).write_bytes(p.stdout);(root/(name+'.stderr.raw')).write_bytes(p.stderr)
 rec={'argv':argv,'rc':p.returncode,'elapsed_seconds':time.monotonic()-t,'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr),'stdout_bytes':len(p.stdout),'stderr_bytes':len(p.stderr)}
 (root/(name+'.COMMAND.json')).write_text(json.dumps(rec,indent=2)+'\n')
 print(name,p.returncode,rec['stdout_sha256'])
