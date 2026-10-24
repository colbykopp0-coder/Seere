"""Approval is signed by a separately held human approval key, never by an AI agent."""
import base64
import sqlite3
from contextlib import closing
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
import secrets
import time
from .security import safe_read, authorize, is_link
from .detection import inspect_text


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def plan_digest(plan):
    return hashlib.sha256(canonical(plan)).hexdigest()


def propose_file_change(root, relative, replacement, fingerprint_key):
    current = safe_read(root, relative, 2_000_000)
    if inspect_text(replacement, 'runtime', 'replacement', fingerprint_key):
        raise ValueError('replacement_contains_detected_credentials')
    return {'action': 'replace_file', 'path': relative,
            'expected_sha256': hashlib.sha256(current).hexdigest(), 'replacement': replacement}


def replacement_bytes(change, fingerprint_key):
    if change['action'] == 'replace_file':
        content = change['replacement']
        if inspect_text(content, 'runtime', 'replacement', fingerprint_key):
            raise PermissionError('unsafe_replacement')
        return content.encode('utf-8')
    if change['action'] == 'replace_sqlite':
        raw = base64.b64decode(change['replacement_b64'], validate=True)
        if len(raw) > 32_000_000:
            raise ValueError('replacement_too_large')
        with closing(sqlite3.connect(':memory:')) as db:
            db.deserialize(raw)
            db.execute('PRAGMA query_only=ON')
            for text, metadata in db.execute('SELECT text, metadata FROM chunks'):
                if text is None or inspect_text(str(text) + '\n' + str(metadata), 'rag', 'replacement', fingerprint_key):
                    raise PermissionError('unsafe_rag_replacement')
        return raw
    raise PermissionError('unsupported_disruptive_action')


def approve(plan, approver, approval_key, ttl_seconds=900):
    if not approver.strip() or len(approval_key) < 32 or not 0 < ttl_seconds <= 3600:
        raise ValueError('invalid_approval')
    payload = {'plan_digest': plan_digest(plan), 'approver': approver,
               'expires': int(time.time()) + ttl_seconds, 'nonce': secrets.token_hex(16)}
    return {**payload, 'signature': hmac.new(approval_key, canonical(payload), hashlib.sha256).hexdigest()}


def execute(plan, approval, approval_key, fingerprint_key, authorized_root, audit_dir, providers=None):
    payload = {k: v for k, v in approval.items() if k != 'signature'}
    signature = hmac.new(approval_key, canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, approval.get('signature', '')):
        raise PermissionError('invalid_human_approval')
    if payload['expires'] < time.time() or payload['plan_digest'] != plan_digest(plan):
        raise PermissionError('expired_or_changed_plan')
    root = authorize(plan['root'], (authorized_root,))
    changes = plan['changes']
    providers = providers or {}
    identities = [c.get('path', str(c.get('provider')) + ':' + str(c.get('credential_id'))) for c in changes]
    if not changes or len(set(identities)) != len(changes):
        raise ValueError('invalid_change_set')
    # Validate the entire set before any mutation. Multi-file application is not transactional.
    for change in changes:
        if change['action'] == 'revoke_credential':
            if change.get('provider') not in providers or not re.fullmatch(r'[a-f0-9]{24}', change.get('credential_id','')):
                raise PermissionError('provider_not_authorized')
            continue
        actual = safe_read(root, change['path'], 32_000_000)
        if hashlib.sha256(actual).hexdigest() != change['expected_sha256']:
            raise PermissionError('stale_plan')
        replacement_bytes(change, fingerprint_key)
    audit = Path(audit_dir)
    audit.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipt = audit / (payload['nonce'] + '.json')
    # Reserve before mutation: an interrupted operation requires a new review and approval.
    with receipt.open('x', encoding='utf-8') as out:
        json.dump({'status': 'started', **payload}, out)
    applied = []
    try:
        for change in changes:
            if change['action'] == 'revoke_credential':
                provider = providers[change['provider']]
                provider.revoke(change['credential_id'])
                if not provider.is_revoked(change['credential_id']):
                    raise RuntimeError('provider_revocation_unverified')
                applied.append(change['provider'] + ':' + change['credential_id'])
                continue
            destination = root / change['path']
            authorize(destination, (root,))
            current = safe_read(root, change['path'], 32_000_000)
            if hashlib.sha256(current).hexdigest() != change['expected_sha256']:
                raise PermissionError('stale_plan')
            # Do not run while other processes can mutate the authorized tree.
            staging = destination.with_name('.seere-' + secrets.token_hex(12))
            try:
                fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as out:
                    out.write(replacement_bytes(change, fingerprint_key))
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(staging, destination)
            finally:
                staging.unlink(missing_ok=True)
            applied.append(change['path'])
    finally:
        receipt.write_text(json.dumps({**payload, 'applied': applied,
            'status': 'completed' if len(applied) == len(changes) else 'partial_failure'}, indent=2))
    return {'status': 'completed', 'applied': applied, 'approval_digest': payload['plan_digest']}
