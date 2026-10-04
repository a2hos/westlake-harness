"""Local-only SIGTERM probe against copied main; no network."""
import importlib.util,json,os,pathlib,signal,sys,tempfile,threading,time
HERE=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('g284_peer_copy',HERE/'run.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
with tempfile.TemporaryDirectory(prefix='g284-term-peer-') as td:
 module.HERE=pathlib.Path(td)
 old_argv=sys.argv
 sys.argv=[str(HERE/'run.py'),'--execute']
 module.execute=lambda result:module.run_command('sleep',['/bin/sleep','3'],10,{'PATH':'/usr/bin:/bin'})
 timer=threading.Timer(0.2,lambda:os.kill(os.getpid(),signal.SIGTERM));timer.start()
 began=time.monotonic()
 try:
  module.main()
  result_json=json.loads((module.HERE/'RESULT.json').read_text())
  outcome=result_json['status']
  try:module.main();replay='unexpected_return'
  except FileExistsError:replay='rejected'
 finally:
  elapsed=time.monotonic()-began;timer.join();sys.argv=old_argv
 result={'outcome':outcome,'error_type':result_json.get('error_type'),'replay':replay,'elapsed_seconds':elapsed,'signal_after_seconds':0.2,'child_sleep_seconds':3,'network_requests':0,'apk_get':0,'scope':'local child process only'}
 with (HERE/'SIGTERM-FIXTURE.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
 print(json.dumps(result))
