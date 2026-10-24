"""Execute four real specialist containers plus a separate AI coordinator.

The inference server is a deterministic test double, not loaded model weights.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

base=Path(sys.argv[1]).resolve()
os.environ.update(SEERE_RUN_DIR=str(base),SEERE_UID=str(os.getuid()),SEERE_GID=str(os.getgid()),
    SEERE_MODEL_IMAGE='seere-model-fixture:ci',SEERE_MODEL_DIR=str(base),SEERE_MODEL='protocol-fixture')
compose=['docker','compose','-f','compose.yaml','-f','compose.ai.yaml','-f','tests/compose.model-fixture.yaml','--profile','ai']
def run(*args,check=True):
    result=subprocess.run(args,capture_output=True,text=True)
    if check and result.returncode:
        raise RuntimeError(str(args)+': '+result.stdout[-1000:]+result.stderr[-3000:])
    return result
run('docker','build','-f','tests/Dockerfile.model-fixture','-t','seere-model-fixture:ci','.')
try:
    run(*compose,'up','--build','-d','ai-coordinator')
    run(*compose,'wait','ai-coordinator')
    plan=json.loads((base/'plan/ai-plan.json').read_text())
    assert plan['complete'] and not plan['missing_specialists']
    assert {r['module'] for r in plan['specialists']}=={'code','local','rag','runtime'}
    assert all(r['mode']=='model' for r in plan['specialists'])
    assert plan['coordinator']['mode']=='model'
    config=json.loads(run(*compose,'config','--format','json').stdout)
    assert config['networks']['ai-internal']['internal']
    for module in ['code','local','rag','runtime']:
        service=config['services'][module+'-agent']
        assert service['read_only'] and not service.get('secrets') and not service.get('ports')
        input_mounts=[v for v in service['volumes'] if v['target']=='/input']
        assert len(input_mounts)==1 and input_mounts[0]['read_only']
        assert Path(input_mounts[0]['source'])==base/'reports'/module
        assert not any(v['target'] in {'/scope','/run/secrets','/reports'} for v in service['volumes'])
        assert (base/'reviews'/module/'review.json').exists()
    # The specialist cannot read a sibling module's report or a fingerprint key.
    run(*compose,'run','--rm','--no-deps','--entrypoint','python','code-agent','-c',
        "from pathlib import Path; assert not Path('/reports/local/report.json').exists(); assert not Path('/run/secrets/fingerprint_key').exists()")
    print(json.dumps({'specialist_containers_executed':4,'separate_coordinator_executed':True,
        'shared_model':'protocol fixture','private_network':True,'complete':True}))
finally:
    run(*compose,'down','--remove-orphans',check=False)
