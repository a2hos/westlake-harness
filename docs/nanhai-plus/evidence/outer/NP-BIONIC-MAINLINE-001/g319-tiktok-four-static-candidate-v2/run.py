#!/usr/bin/env python3
"""One exact four-phase local scan, recording each raw stream and terminal rc."""
import datetime,hashlib,json,os,pathlib,signal,subprocess,sys,time
ROOT=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT']); HERE=pathlib.Path(__file__).parent
LIMITS={'zip':180,'metadata':180,'elf':900,'dex':900}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def put(p,x):
 with p.open('x') as f:json.dump(x,f,sort_keys=True,ensure_ascii=False,indent=2);f.write('\n')
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def main():
 if sys.argv[1:]!=['--execute']:raise SystemExit(2)
 if (HERE/'START.json').exists():raise RuntimeError('one-shot already consumed')
 census=json.loads((HERE/'CENSUS.json').read_text());assert census['counts']=={'root_dex':51,'embedded_dex':0,'true_arm64_elf':227,'non_elf_so':4}
 venv=ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16/venvs/harness-python-v1/bin/python3'
 tool=ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16/inputs-view/harness-native-hosttool-v1/bin/readelf'
 assert tool.is_symlink() and tool.resolve()==pathlib.Path('/opt/19.SourceCode/OpenHarmony-SDK-26.0.0.39-mac-arm64/extracted/native/llvm/bin/llvm-readelf')
 put(HERE/'START.json',{'at_utc':now(),'apk_sha256':census['apk_sha256'],'census_sha256':sha(HERE/'CENSUS.json'),'phase_sha256':sha(HERE/'phase.py'),'runner_sha256':sha(HERE/'run.py'),'python':str(venv),'readelf_target':str(tool.resolve()),'readelf_sha256':sha(tool),'limits_seconds':LIMITS,'network':False,'ssh':False,'device':False,'container':False,'namespace':False})
 rows=[]
 for phase,timeout in LIMITS.items():
  d=HERE/'phases'/phase;d.parent.mkdir(exist_ok=True);argv=[str(venv),'-I','-B',str(HERE/'phase.py'),phase]
  env={k:v for k,v in os.environ.items() if not k.startswith(('PYTHON','PIP_')) and 'proxy' not in k.lower()}
  env.update(PATH=str(tool.parent)+':'+str(venv.parent)+':/usr/bin:/bin:/usr/sbin:/sbin',TMPDIR=str(HERE/'tmp'),LC_ALL='C',PYTHONDONTWRITEBYTECODE='1')
  (HERE/'tmp').mkdir(exist_ok=True)
  t=time.monotonic();row={'phase':phase,'argv':argv,'cwd':str(ROOT),'started_at':now(),'timeout_seconds':timeout,'environment':{k:env[k] for k in ('PATH','TMPDIR','LC_ALL','PYTHONDONTWRITEBYTECODE')}}
  stdout=HERE/(phase+'-stdout.raw');stderr=HERE/(phase+'-stderr.raw')
  with stdout.open('xb') as a,stderr.open('xb') as b:
   proc=subprocess.Popen(argv,cwd=ROOT,env=env,stdout=a,stderr=b,start_new_session=True)
   try:row['rc']=proc.wait(timeout=timeout)
   except subprocess.TimeoutExpired:row['timed_out']=True;os.killpg(proc.pid,signal.SIGKILL);row['rc']=proc.wait()
  row.update(finished_at=now(),elapsed_seconds=time.monotonic()-t,stdout_sha256=sha(stdout),stderr_sha256=sha(stderr))
  rows.append(row);put(HERE/(phase+'-COMMAND.json'),row)
  if row['rc']!=0 or row.get('timed_out'):break
 result={'schema':'g319-tiktok-four-static-terminal-candidate-v1','at_utc':now(),'rows':rows,'four_phases_rc0':len(rows)==4 and all(x['rc']==0 for x in rows),'root_dex':51,'embedded_dex':0,'true_arm64_elf':227,'true_arm32_elf':225,'non_elf_so':4,'authoritative_count_changed':False,'startup_proven':False,'device_commands':0,'container_commands':0}
 result['rc']=0 if result['four_phases_rc0'] else 2;put(HERE/'RESULT.json',result);print(json.dumps(result,sort_keys=True));return result['rc']
if __name__=='__main__':sys.exit(main())
