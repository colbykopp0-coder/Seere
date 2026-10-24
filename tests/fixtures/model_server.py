"""Deterministic protocol fixture, never represented as real model inference."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.end_headers();self.wfile.write(b'healthy')

    def do_POST(self):
        body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        payload=json.loads(body['messages'][1]['content'])
        reason={'code':'historical_exposure','local':'stored_credential','rag':'retrieval_exposure','runtime':'tool_exposure','coordinator':'cross_layer_reuse'}[payload['module']]
        interpretation={'risk':'HIGH' if payload.get('count',payload.get('credential_groups',0)) else 'LOW',
            'reason':reason,'actions':['identify_owner','verify_all_layers']}
        response={'choices':[{'message':{'content':json.dumps(interpretation)}}]}
        self.send_response(200);self.end_headers();self.wfile.write(json.dumps(response).encode())

    def log_message(self,*args):pass

HTTPServer(('0.0.0.0',11434),Handler).serve_forever()
