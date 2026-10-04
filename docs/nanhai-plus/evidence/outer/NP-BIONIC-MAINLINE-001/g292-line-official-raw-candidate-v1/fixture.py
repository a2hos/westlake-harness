#!/usr/bin/env python3
"""Local-only checks for the prepared G292 executor. Never makes a request."""
import ast
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

here=Path(__file__).resolve().parent
runner=here/'run.py'
source=runner.read_text()
tree=ast.parse(source)
spec=importlib.util.spec_from_file_location('g292_line_runner',runner)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

checks=[]
def check(label,condition):
    if not condition:raise RuntimeError(label)
    checks.append(label)

check('project root binding',m.ROOT==here.parents[5])
check('official page exact link',m.official_page_url((here/'page.body.raw').read_bytes())==m.APK)
try:m.official_page_url((here/'page.body.raw').read_bytes().replace(b'line-15.21.3.apk',b'line-15.21.4.apk'))
except m.GateError:check('alternate page link rejected',True)
else:raise RuntimeError('alternate page link accepted')
check('HEAD exact identity',m.head_identity((here/'head.headers.raw').read_bytes())==
      (m.BYTES,'application/octet-stream',m.HEAD_ETAG,m.HEAD_LAST_MODIFIED))
try:m.head_identity((here/'head.headers.raw').read_bytes()+b'Content-Length: 1\r\n')
except m.GateError:check('duplicated HEAD length rejected',True)
else:raise RuntimeError('duplicated HEAD length accepted')
with tempfile.TemporaryDirectory(prefix='g292-fixture-') as tmp:
    p=Path(tmp)/'START.json'
    m.exclusive_json(p,{'a':1})
    try:m.exclusive_json(p,{'a':2})
    except FileExistsError:check('START exclusive',True)
    else:raise RuntimeError('START overwrite accepted')
    q=Path(tmp)/'RESULT.json'
    m.final_json(q,{'status':'fixture'})
    try:m.final_json(q,{'status':'overwrite'})
    except FileExistsError:check('RESULT exclusive',True)
    else:raise RuntimeError('RESULT overwrite accepted')
p=subprocess.run([sys.executable,'-B',str(runner)],capture_output=True,text=True,check=False)
check('noarg refuses execution',p.returncode==1 and 'PREPARED_ONLY' in p.stderr)
check('no execution receipts',not (here/'START.json').exists() and not (here/'RESULT.json').exists())
check('one explicit execute guard',source.count("sys.argv[1:]!=['--execute']")==1)
check('one APK GET argv construction',source.count('getcmd=')==1 and source.count("command('runtime-download'")==1)
check('no shell or device or container command',all(x not in source for x in
      ['shell=True','adb ','hdc ','docker ','podman ','nsjail ']))
check('parsed Python AST',isinstance(tree,ast.Module))
print('FIXTURE_PASS',len(checks),','.join(checks))
