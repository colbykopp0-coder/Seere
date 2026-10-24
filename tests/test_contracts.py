"""Transport, schema and embedding tests beyond the synthetic workflow."""
from contextlib import closing
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import sqlite3
import threading
import pytest
from seere_sdk.agents import LocalModel
from seere_sdk.rag import scan_rag, dense_cosine
from seere_sdk.orchestration import envelope, correlate
from seere_sdk.security import safe_read
from seere_sdk.reviews import review_report, validate_review

KEY=b'0'*32


def test_model_adapter_loopback_protocol():
    requests=[]
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            response={'choices':[{'message':{'content':json.dumps({'risk':'HIGH','reason':'cross_layer_reuse','actions':['identify_owner','verify_all_layers']})}}]}
            self.send_response(200);self.end_headers();self.wfile.write(json.dumps(response).encode())
        def log_message(self,*args):pass
    server=HTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        model=LocalModel(f'http://127.0.0.1:{server.server_port}/v1/chat/completions','protocol-test-double')
        reports=[envelope(module,'run',KEY,{'complete':True,'findings':[]}) for module in ['code','local','rag','runtime']]
        reviews=[review_report(r,r['module'],'run',model) for r in reports]
        result=correlate(reports,run_id='run',model=model,specialist_reviews=reviews)
        assert result['coordinator']['mode']=='model'
        assert len(requests)==5  # four specialists plus coordinator
        assert all(set(json.loads(r['messages'][1]['content'])) <= {'module','count','critical_count','high_count','unique_credentials','credential_groups','cross_layer_groups','missing_module_count','specialist_high_risk_count'} for r in requests)
    finally:
        server.shutdown();server.server_close();thread.join()


def test_stored_embedding_cosine_and_incompatible_dimension(tmp_path):
    path=tmp_path/'chunks.db'
    with closing(sqlite3.connect(path)) as db:
        db.execute('CREATE TABLE chunks(id TEXT,text TEXT,metadata TEXT,embedding TEXT)')
        db.execute('INSERT INTO chunks VALUES(?,?,?,?)',('1','ordinary text','{}','[1,0]'))
        db.commit()
    report=scan_rag(path,KEY,probe_vectors=[[1,0]])
    assert report['complete'] and report['review_candidates'][0]['similarity']==1
    assert report['review_candidates'][0]['method']=='stored_embedding_cosine'
    assert not scan_rag(path,KEY,probe_vectors=[[1,0,0]])['complete']
    with pytest.raises(ValueError):dense_cosine([float('nan')],[1])
    with pytest.raises(ValueError):dense_cosine([0],[1])


def test_schema_envelope(tmp_path):
    import jsonschema
    schema=json.loads(Path('schemas/report.schema.json').read_text())
    report=envelope('local','test-run',KEY,{'complete':True,'findings':[]})
    jsonschema.validate(report,schema)
    report['complete']='false'
    with pytest.raises(jsonschema.ValidationError):jsonschema.validate(report,schema)


def test_posix_parent_link_swap_denied(tmp_path):
    import os
    if os.name!='posix':pytest.skip('POSIX descriptor-bound traversal; exercised in Linux CI')
    outside=tmp_path/'outside';outside.mkdir();(outside/'secret').write_text('must never read')
    scope=tmp_path/'scope';scope.mkdir();(scope/'link').symlink_to(outside,target_is_directory=True)
    with pytest.raises(OSError):safe_read(scope,'link/secret',100)


def test_specialist_reviews_bound_to_reports():
    import copy
    report=envelope('code','run',KEY,{'complete':True,'findings':[]})
    review=review_report(report,'code','run',None)
    validate_review(review,report)
    for field,value in [('run_id','stale'),('module','local'),('key_id','f'*16),('report_digest','0'*64)]:
        altered=copy.deepcopy(review);altered[field]=value
        with pytest.raises(ValueError):validate_review(altered,report)
    changed=copy.deepcopy(report);changed['complete']=False
    with pytest.raises(ValueError):validate_review(review,changed)
    with pytest.raises(ValueError):review_report(report,'local','run',None)
    plan=correlate([report],expected=['code'],run_id='run',specialist_reviews=[])
    assert not plan['complete'] and plan['missing_specialists']==['code']
    assert correlate([report],expected=['code'],run_id='run',specialist_reviews=[review])['complete']
    with pytest.raises(ValueError):correlate([report],expected=['code'],run_id='run',specialist_reviews=[review,review])


def test_coordinator_never_calls_specialist_inference():
    calls=[]
    class Model:
        def interpret(self,payload):
            calls.append(payload['module'])
            return {'risk':'LOW','reason':'cross_layer_reuse','actions':['verify_all_layers']}
    reports=[envelope(m,'run',KEY,{'complete':True,'findings':[]}) for m in ['code','local','rag','runtime']]
    reviews=[review_report(r,r['module'],'run',None) for r in reports]
    correlate(reports,run_id='run',model=Model(),specialist_reviews=reviews)
    assert calls==['coordinator']
