"""Specialist interpretations accept fixed, redacted features only. No action execution."""
import json
import urllib.request
import urllib.parse

DOMAINS = {'code', 'local', 'rag', 'runtime'}
ACTIONS = {'identify_owner', 'request_rotation', 'remove_exposure', 'verify_all_layers'}
RISKS = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}
REASONS = {'historical_exposure', 'stored_credential', 'retrieval_exposure', 'tool_exposure', 'cross_layer_reuse'}


def features(module, findings):
    if module not in DOMAINS:
        raise ValueError('unknown_specialist')
    # Paths, notes, previews and document text cannot become model instructions.
    return {'module': module, 'count': len(findings),
        'critical_count': sum(f['severity'] == 'CRITICAL' for f in findings),
        'high_count': sum(f['severity'] == 'HIGH' for f in findings),
        'unique_credentials': len({f['fingerprint'] for f in findings})}


def validate_interpretation(value):
    if set(value) != {'risk', 'reason', 'actions'} or value['risk'] not in RISKS or value['reason'] not in REASONS:
        raise ValueError('invalid_agent_interpretation')
    if not isinstance(value['actions'], list) or not value['actions'] or not set(value['actions']) <= ACTIONS:
        raise ValueError('invalid_agent_actions')
    return value


class LocalModel:
    """OpenAI-compatible model on loopback or an explicitly trusted container host."""
    def __init__(self, endpoint, model, allowed_hosts=()):
        url = urllib.parse.urlparse(endpoint)
        if url.scheme != 'http' or url.hostname not in {'127.0.0.1', 'localhost', '::1', *allowed_hosts} or url.username or url.password:
            raise ValueError('model_endpoint_not_trusted')
        self.endpoint, self.model = endpoint, model

    def interpret(self, payload):
        instruction = ('Classify these numeric security features. Return only JSON with risk '
            '(CRITICAL,HIGH,MEDIUM,LOW), reason (historical_exposure,stored_credential,retrieval_exposure,'
            'tool_exposure,cross_layer_reuse), actions (array from identify_owner,request_rotation,'
            'remove_exposure,verify_all_layers). Do not invent executable actions.')
        body = {'model': self.model, 'temperature': 0, 'messages': [
            {'role': 'system', 'content': instruction}, {'role': 'user', 'content': json.dumps(payload)}]}
        request = urllib.request.Request(self.endpoint, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
        # Disable redirects and environment proxies: loopback restriction must survive transport.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise ValueError('model_redirect_rejected')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=30) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('model_response_too_large')
        content = json.loads(raw)['choices'][0]['message']['content']
        return validate_interpretation(json.loads(content))


def specialist(module, findings, model=None):
    payload = features(module, findings)
    if model is not None:
        return {'module': module, 'mode': 'model', 'interpretation': model.interpret(payload)}
    reason = {'code': 'historical_exposure', 'local': 'stored_credential',
              'rag': 'retrieval_exposure', 'runtime': 'tool_exposure'}[module]
    risk = 'CRITICAL' if payload['critical_count'] else 'HIGH' if payload['count'] else 'LOW'
    return {'module': module, 'mode': 'deterministic_fallback', 'interpretation': {
        'risk': risk, 'reason': reason, 'actions': ['identify_owner', 'request_rotation', 'remove_exposure', 'verify_all_layers'] if findings else ['verify_all_layers']}}
