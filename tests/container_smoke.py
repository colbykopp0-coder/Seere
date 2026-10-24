"""CI smoke test: real container execution, network isolation and read-only scopes."""
import json
import os
from pathlib import Path
import subprocess
import sys

base=Path(sys.argv[1]).resolve()
def run(*args, check=True):
    return subprocess.run(args,check=check,capture_output=True,text=True)
run(sys.executable,'-m','seere_sdk.control','init',str(base))
synthetic=''.join(('sk-', 'proj-', 'SYNTHETICONLY1234567890abcdefghij'))
(base/'scope/code/config.py').write_text('API_KEY='+json.dumps(synthetic))
run('git','-C',str(base/'scope/code'),'init')
run('git','-C',str(base/'scope/code'),'add','.')
run('git','-C',str(base/'scope/code'),'-c','user.name=CI','-c','user.email=ci@example.invalid','commit','-m','synthetic fixture')
(base/'scope/local/mcp.json').write_text(json.dumps({'key':synthetic}))
(base/'scope/runtime/content.txt').write_text('ordinary documentation')
import sqlite3
from contextlib import closing
with closing(sqlite3.connect(base/'scope/rag/chunks.db')) as db:
    db.execute('CREATE TABLE chunks(id TEXT,text TEXT,metadata TEXT)')
    db.execute('INSERT INTO chunks VALUES(?,?,?)',('1','ordinary documentation','{}'))
    db.commit()
os.environ['SEERE_RUN_DIR']=str(base)
os.environ['SEERE_UID']=str(os.getuid())
os.environ['SEERE_GID']=str(os.getgid())
run('docker','compose','config','--quiet')
run('docker','compose','build')
for module in ['code','local','rag','runtime']:
    result=run('docker','compose','run','--rm',module,check=False)
    if result.returncode != 0:
        raise RuntimeError(module+': '+result.stderr[-3000:])
run('docker','compose','--profile','coordinate','run','--rm','coordinator')
plan=json.loads((base/'plan/plan.json').read_text())
assert plan['complete'] and len(plan['groups'][0]['layers'])==2
assert all(s['mode']=='deterministic_fallback' for s in plan['specialists'])
# Inspect the running service config, and attempt a write to the mounted scope.
config=json.loads(run('docker','compose','config','--format','json').stdout)
for name in ['code','local','rag','runtime','coordinator']:
    service=config['services'][name]
    assert service['network_mode']=='none' and service['read_only']
blocked=run('docker','compose','run','--rm','--entrypoint','python','code','-c',
    "from pathlib import Path; Path('/scope/unauthorized-write').write_text('must fail')",check=False)
assert blocked.returncode != 0
assert not (base/'scope/code/unauthorized-write').exists()
print(json.dumps({'containers_executed':5,'complete':plan['complete'],'read_only_write_denied':True}))
