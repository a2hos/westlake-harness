#!/usr/bin/env python3
"""Local Ninja text fixtures; no build action or remote access."""
import hashlib,json,os,pathlib,subprocess,sys
from ninja_closure import audit
import ninja_closure as scanner

HERE=pathlib.Path(__file__).parent
F=HERE/'fixtures'
F.mkdir(exist_ok=False)
cases=[]
def setup(name,files):
 root=F/name;root.mkdir()
 for path,body in files.items():
  p=root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(body)
 return root
def case(name,files,expected,reason=None,forbidden=None):
 root=setup(name,files)
 result=audit(root,'top.ninja')
 ok=result['status']==expected and (reason is None or result['failure']['reason']==reason) and (forbidden is None or result['first_forbidden']==forbidden)
 cases.append({'name':name,'expected':expected,'observed':result,'pass':ok})

case('benign',{'top.ninja':'include a.ninja\nrule top\n  command = true\n','a.ninja':'subninja nested/b.ninja\n','nested/b.ninja':'rule safe\n  command = true\n'},'PASS_LITERAL_CLOSURE_ONLY')
case('child_forbidden',{'top.ninja':'subninja child.ninja\n','child.ninja':'rule forbidden\n  command = nsjail -- /bin/true\n'},'FORBIDDEN_COMMAND',forbidden={'path':'child.ninja','line':2,'fragment':'nsjail -- /bin/true','token':'nsjail'})
case('continuation',{'top.ninja':'rule split\n  command = ns$\n    jail -- /bin/true\n'},'FORBIDDEN_COMMAND',forbidden={'path':'top.ninja','line':2,'fragment':'nsjail -- /bin/true','token':'nsjail'})
case('variable_edge',{'top.ninja':'include $builddir/child.ninja\n'},'FAIL_CLOSED','VARIABLE_OR_EMPTY_INCLUDE')
case('missing',{'top.ninja':'subninja absent.ninja\n'},'FAIL_CLOSED','MISSING_INCLUDE')
case('cycle',{'top.ninja':'include a.ninja\n','a.ninja':'subninja top.ninja\n'},'FAIL_CLOSED','INCLUDE_CYCLE')
case('escape',{'top.ninja':'include ../outside.ninja\n'},'FAIL_CLOSED','OUT_ESCAPE')
case('malformed',{'top.ninja':'include\n'},'FAIL_CLOSED','VARIABLE_OR_EMPTY_INCLUDE')
case('comment_only',{'top.ninja':'# command = nsjail\nrule safe\n  command = true\n'},'PASS_LITERAL_CLOSURE_ONLY')
case('variable_command',{'top.ninja':'tool = nsjail\nrule x\n  command = $tool -- /bin/true\n'},'FAIL_CLOSED','DYNAMIC_OR_SHELL_COMPOSITION_COMMAND')
case('ordinary_ninja_variables',{'top.ninja':'rule x\n  command = cp $in $out\n'},'FAIL_CLOSED','DYNAMIC_OR_SHELL_COMPOSITION_COMMAND')
case('quoted_join',{'top.ninja':"rule x\n  command = ns'ja'il -- /bin/true\n"},'FAIL_CLOSED','DYNAMIC_OR_SHELL_COMPOSITION_COMMAND')
case('double_quoted_join',{'top.ninja':'rule x\n  command = "ns"jail -- /bin/true\n'},'FAIL_CLOSED','DYNAMIC_OR_SHELL_COMPOSITION_COMMAND')
case('backslash_join',{'top.ninja':'rule x\n  command = n\\sjail -- /bin/true\n'},'FAIL_CLOSED','DYNAMIC_OR_SHELL_COMPOSITION_COMMAND')
case('shell_substitution',{'top.ninja':'rule x\n  command = $(cat launcher.txt) -- /bin/true\n'},'FAIL_CLOSED','DYNAMIC_OR_SHELL_COMPOSITION_COMMAND')
case('shell_glob',{'top.ninja':'rule x\n  command = ns?ail -- /bin/true\n'},'FAIL_CLOSED','DYNAMIC_OR_SHELL_COMPOSITION_COMMAND')
case('shell_bracket_glob',{'top.ninja':'rule x\n  command = n[s]jail -- /bin/true\n'},'FAIL_CLOSED','DYNAMIC_OR_SHELL_COMPOSITION_COMMAND')
root=setup('symlink',{'top.ninja':'include child.ninja\n','actual.ninja':'rule safe\n  command = true\n'})
(root/'child.ninja').symlink_to('actual.ninja')
r=audit(root,'top.ninja');cases.append({'name':'symlink','expected':'FAIL_CLOSED/SYMLINK_PATH','observed':r,'pass':r['status']=='FAIL_CLOSED' and r['failure']['reason']=='SYMLINK_PATH'})

root=setup('changed_during_read',{'top.ninja':'rule safe\n  command = true\n'})
original_read=scanner.os.read;changed=[False]
def mutate_after_read(fd,n):
 data=original_read(fd,n)
 if data and not changed[0]:
  changed[0]=True
  with (root/'top.ninja').open('ab') as f:f.write(b'\n# changed after initial fstat\n')
 return data
scanner.os.read=mutate_after_read
try:r=audit(root,'top.ninja')
finally:scanner.os.read=original_read
cases.append({'name':'changed_during_read','expected':'FAIL_CLOSED/FILE_CHANGED_DURING_READ','observed':r,'pass':r['status']=='FAIL_CLOSED' and r['failure']['reason']=='FILE_CHANGED_DURING_READ'})

root=setup('symlink_swap',{'top.ninja':'include child.ninja\n','child.ninja':'rule safe\n  command = true\n'})
outside=F/'outside.ninja';outside.write_text('rule safe\n  command = true\n')
original_open=scanner.os.open;swapped=[False]
def swap_before_open(path,*args,**kwargs):
 if path=='child.ninja' and not swapped[0]:
  swapped[0]=True
  (root/'child.ninja').unlink()
  (root/'child.ninja').symlink_to(outside)
 return original_open(path,*args,**kwargs)
scanner.os.open=swap_before_open
try:r=audit(root,'top.ninja')
finally:scanner.os.open=original_open
cases.append({'name':'symlink_swap','expected':'FAIL_CLOSED/OPEN_REFUSED','observed':r,'pass':r['status']=='FAIL_CLOSED' and r['failure']['reason'].startswith('OPEN_REFUSED_')})

# Exercise the CLI under a fixed fixture OUT root as well as the pure audit API.
root=F/'child_forbidden';env={**os.environ,'NANHAI_OUT_ROOT':str(root.resolve())}
cli=subprocess.run([sys.executable,'-B',str(HERE/'ninja_closure.py'),'--top','top.ninja'],env=env,capture_output=True)
cli_result=json.loads(cli.stdout)
cases.append({'name':'cli_child_forbidden','expected':'rc2/child.ninja:2','observed':{'rc':cli.returncode,'status':cli_result['status'],'first_forbidden':cli_result['first_forbidden']},'pass':cli.returncode==2 and cli_result['first_forbidden']['path']=='child.ninja' and cli_result['first_forbidden']['line']==2})

receipt={'status':'PASS_LOCAL_FIXTURES' if all(x['pass'] for x in cases) else 'FAIL_LOCAL_FIXTURES','cases':cases,'case_count':len(cases),'passed':sum(x['pass'] for x in cases),'scanner_sha256':hashlib.sha256((HERE/'ninja_closure.py').read_bytes()).hexdigest(),'scope':'local synthetic Ninja text only; no graph action, remote, device or container'}
with (HERE/'TEST-RESULT.json').open('x') as f:json.dump(receipt,f,indent=2,ensure_ascii=False);f.write('\n')
print(json.dumps({'status':receipt['status'],'cases':receipt['case_count'],'passed':receipt['passed']}))
sys.exit(0 if receipt['status']=='PASS_LOCAL_FIXTURES' else 2)
