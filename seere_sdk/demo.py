"""Run only with synthetic credentials in a newly created demo directory."""
import argparse
import base64
from contextlib import closing
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
from .core import ScanConfig, SeereScanner
from .rag import scan_rag, GuardedRAG
from .orchestration import envelope, correlate
from .response import propose_file_change, approve, execute
from .benchmark import benchmark
from .util import fingerprint

SECRET = ''.join(('sk-', 'proj-', 'SYNTHETICONLY1234567890abcdefghij'))


def demo(directory):
    base = Path(directory).absolute()
    base.mkdir(parents=True, exist_ok=False)
    scope, results = base/'scope', base/'results'
    scope.mkdir(); results.mkdir()
    code, local, rag = scope/'code', scope/'local', scope/'rag'
    for folder in [code,local,rag]:
        folder.mkdir()
    key, human_key = secrets.token_bytes(32), secrets.token_bytes(32)
    (code/'config.py').write_text('API_KEY = "'+SECRET+'"\n')
    (local/'mcp.json').write_text(json.dumps({'env': {'OPENAI_API_KEY': SECRET}}))
    def git(*args):
        subprocess.run(['git', '-C', str(code), *args], check=True, capture_output=True)
    git('init'); git('add','config.py')
    git('-c','user.name=Synthetic Demo','-c','user.email=demo@example.invalid','commit','-m','Synthetic exposure fixture')
    dbpath = rag/'chunks.db'
    with closing(sqlite3.connect(dbpath)) as db:
        db.execute('CREATE TABLE chunks(id TEXT PRIMARY KEY, text TEXT, metadata TEXT)')
        db.execute('INSERT INTO chunks VALUES(?,?,?)', ('1', 'production api key '+SECRET, '{}'))
        db.commit()
    def collect(run_id, runtime_text):
        reports = []
        for module, folder in [('code',code), ('local',local)]:
            reports.append(envelope(module, run_id, key, SeereScanner(ScanConfig(
                fingerprint_key=key, scan_git_history=module=='code', allowed_roots=(folder,))).scan(folder).to_dict()))
        reports.append(envelope('rag', run_id, key, scan_rag(dbpath,key)))
        reports.append(envelope('runtime', run_id, key, GuardedRAG(key).gate(runtime_text,'before_agent')))
        return reports
    before = collect('synthetic-before', SECRET)
    plan = correlate(before, run_id='synthetic-before')
    changes = [propose_file_change(scope,'code/config.py','import os\nAPI_KEY = os.environ["OPENAI_API_KEY"]\n',key),
        propose_file_change(scope,'local/mcp.json',json.dumps({'env':{'OPENAI_API_KEY':'${MANAGED_SECRET}'}}),key)]
    original_db = dbpath.read_bytes()
    with closing(sqlite3.connect(':memory:')) as db:
        db.deserialize(original_db)
        db.execute('UPDATE chunks SET text=? WHERE id=?', ('Credential removed; use managed identity.', '1'))
        db.commit()
        clean_db = db.serialize()
    changes.append({'action':'replace_sqlite','path':'rag/chunks.db',
        'expected_sha256':hashlib.sha256(original_db).hexdigest(),
        'replacement_b64':base64.b64encode(clean_db).decode()})
    class SyntheticProvider:
        def __init__(self): self.revoked = set()
        def revoke(self, credential_id): self.revoked.add(credential_id)
        def is_revoked(self, credential_id): return credential_id in self.revoked
    provider = SyntheticProvider()
    credential_id = fingerprint(SECRET,key)
    changes.append({'action':'revoke_credential','provider':'synthetic-provider','credential_id':credential_id})
    remediation = {'root':str(scope),'changes':changes}
    denied = False
    try:
        execute(remediation, {'signature':''}, human_key,key,scope,base/'audit')
    except PermissionError:
        denied = True
    # Simulation only: the demo acts as a test human. Real deployment uses a separate signing operator.
    approval = approve(remediation,'synthetic-test-human',human_key)
    execution = execute(remediation,approval,human_key,key,scope,base/'audit',providers={'synthetic-provider':provider})
    after = collect('synthetic-after','Credential removed; use managed identity.')
    active = [f for r in after for f in r['findings'] if not f['source'].startswith('git:')]
    historical = [f for r in after for f in r['findings'] if f['source'].startswith('git:')]
    result = {'scenario':'synthetic only; not a customer pilot', 'before':plan,
        'unauthorized_execution_denied':denied, 'approved_execution':execution,
        'verification':{'current_surface_findings':len(active), 'historical_findings':len(historical),
            'historical_exposure_resolved':False, 'requires_provider_rotation':bool(historical) and not provider.is_revoked(credential_id),
            'synthetic_provider_revocation_verified':provider.is_revoked(credential_id),
            'residual_history_requires_retention_review':bool(historical),
            'current_surfaces_clean':not active, 'all_scans_complete':all(r['complete'] for r in after)},
        'after':after, 'benchmark':benchmark(key),
        'approval_mode':'simulated human approval and synthetic-provider revocation; no real operator or provider rotation performed'}
    serialized = json.dumps(result,indent=2)
    if SECRET in serialized:
        raise AssertionError('raw_secret_in_result')
    (results/'demo.json').write_text(serialized)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directory')
    args = parser.parse_args()
    result = demo(args.directory)
    print(json.dumps({'verification':result['verification'],'benchmark':{k:v for k,v in result['benchmark'].items() if k not in {'cases','ranking'}}},indent=2))

if __name__ == '__main__':
    main()
