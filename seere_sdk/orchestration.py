"""Versioned module envelopes and manifest-checked correlation."""
from collections import defaultdict
import json
import re
from pathlib import Path
from .agents import specialist
from .security import safe_read, key_id

MODULES = {'code', 'local', 'rag', 'runtime'}


def envelope(module, run_id, key, report):
    if module not in MODULES or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', run_id):
        raise ValueError('invalid_module_or_run_id')
    return {'schema_version': 1, 'module': module, 'run_id': run_id, 'key_id': key_id(key),
        'complete': report.get('complete', report.get('stats', {}).get('complete', False)),
        'findings': report['findings'], 'details': {k:v for k,v in report.items() if k != 'findings'}}


def correlate(reports, expected=None, run_id=None, model=None):
    expected = set(expected or MODULES)
    if not expected <= MODULES or not expected:
        raise ValueError('invalid_expected_modules')
    received, groups, reviews, key_ids, run_ids = set(), defaultdict(list), [], set(), set()
    for report in reports:
        module = report['module']
        if report['schema_version'] != 1 or module not in expected or module in received:
            raise ValueError('invalid_duplicate_or_unexpected_module')
        received.add(module)
        key_ids.add(report['key_id'])
        run_ids.add(report['run_id'])
        for finding in report['findings']:
            required = {'kind', 'source', 'path', 'provider', 'severity', 'fingerprint', 'confidence', 'recommended_action'}
            if not required <= finding.keys() or finding['preview'] != '[REDACTED]':
                raise ValueError('invalid_finding')
            if not re.fullmatch(r'[a-f0-9]{24}', finding['fingerprint']):
                raise ValueError('invalid_fingerprint')
            if finding['severity'] not in {'CRITICAL','HIGH','MEDIUM','LOW'} or not 0 <= finding['confidence'] <= 1:
                raise ValueError('invalid_severity_or_confidence')
            groups[finding['fingerprint']].append({'module': module, **finding})
        reviews.append(specialist(module, report['findings'], model))
    if len(key_ids) > 1 or len(run_ids) > 1 or (run_ids and run_id is not None and run_ids != {run_id}):
        raise ValueError('incompatible_key_or_stale_run')
    missing = sorted(expected - received)
    correlated = []
    for fp, findings in groups.items():
        layers = sorted({f['module'] for f in findings})
        priority = max({'LOW':1, 'MEDIUM':2, 'HIGH':3, 'CRITICAL':4}[f['severity']] for f in findings) + len(layers)-1
        correlated.append({'fingerprint': fp, 'layers': layers, 'priority': priority,
            'findings': findings, 'approval_required': True,
            'proposed_actions': ['identify_owner', 'request_rotation', 'remove_exposure', 'verify_all_layers']})
    correlated.sort(key=lambda item: (-item['priority'], item['fingerprint']))
    coordinator_review = model.interpret({'module': 'coordinator', 'credential_groups': len(correlated),
        'cross_layer_groups': sum(len(g['layers']) > 1 for g in correlated),
        'missing_module_count': len(missing)}) if model else None
    return {'schema_version': 1, 'run_id': run_id or next(iter(run_ids), None),
        'complete': not missing and all(r['complete'] for r in reports), 'missing_modules': missing,
        'specialists': reviews, 'groups': correlated, 'execution_enabled': False,
        'coordinator': {'mode': 'model' if model else 'deterministic', 'interpretation': coordinator_review, 'action_plan': 'Review highest-priority credential groups; approve each exact remediation plan; verify every layer.'}}


def load_reports(directory, manifest):
    reports = []
    for module in manifest['expected_modules']:
        path = Path(directory) / module / 'report.json'
        if path.exists():
            reports.append(json.loads(safe_read(directory, str(path.relative_to(directory)), 16_000_000)))
    return reports
