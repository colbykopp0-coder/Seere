"""Bound specialist results: coordinator never runs specialist inference itself."""
import hashlib
import json
import re
from .agents import specialist, validate_interpretation

MODULES = {'code', 'local', 'rag', 'runtime'}


def report_digest(report):
    return hashlib.sha256(json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def validate_report(report, module=None, run_id=None):
    if report.get('schema_version') != 1 or report.get('module') not in MODULES:
        raise ValueError('invalid_scan_report')
    if module is not None and report['module'] != module:
        raise ValueError('specialist_scope_mismatch')
    if run_id is not None and report.get('run_id') != run_id:
        raise ValueError('stale_scan_report')
    if type(report.get('complete')) is not bool or not re.fullmatch(r'[a-f0-9]{16}', report.get('key_id', '')):
        raise ValueError('invalid_report_metadata')
    if not isinstance(report.get('findings'), list):
        raise ValueError('invalid_findings')
    for finding in report['findings']:
        if (finding.get('preview') != '[REDACTED]' or finding.get('severity') not in {'LOW','MEDIUM','HIGH','CRITICAL'}
                or not re.fullmatch(r'[a-f0-9]{24}', finding.get('fingerprint', ''))):
            raise ValueError('invalid_redacted_finding')


def review_report(report, module, run_id, model):
    validate_report(report, module, run_id)
    analysis = specialist(module, report['findings'], model)
    validate_interpretation(analysis['interpretation'])
    return {'schema_version': 1, 'kind': 'specialist_review', 'module': module,
        'run_id': run_id, 'key_id': report['key_id'], 'report_digest': report_digest(report),
        'mode': analysis['mode'], 'interpretation': analysis['interpretation']}


def validate_review(review, report):
    expected = {'schema_version','kind','module','run_id','key_id','report_digest','mode','interpretation'}
    if set(review) != expected or review['schema_version'] != 1 or review['kind'] != 'specialist_review':
        raise ValueError('invalid_specialist_review')
    if any(review[name] != report[name] for name in ['module','run_id','key_id']):
        raise ValueError('stale_or_incompatible_specialist_review')
    if review['report_digest'] != report_digest(report):
        raise ValueError('specialist_report_digest_mismatch')
    if review['mode'] not in {'model','deterministic_fallback'}:
        raise ValueError('invalid_specialist_mode')
    validate_interpretation(review['interpretation'])
