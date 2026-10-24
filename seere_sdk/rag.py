"""SQLite connector and local cosine prioritization. Similarity is not proof of a secret."""
from contextlib import closing
from collections import Counter
import math
import re
import sqlite3
import json
from pathlib import Path
from .detection import inspect_text
from .security import safe_read, key_id

PROBES = ['api key password token secret credential', 'private key service account authentication',
          'production access authorization bearer login']


def vector(text):
    return Counter(re.findall(r'[a-z]+', text.lower().replace('_', ' ')))


def cosine(a, b):
    denominator = math.sqrt(sum(v*v for v in a.values()) * sum(v*v for v in b.values()))
    return sum(v * b.get(k, 0) for k, v in a.items()) / denominator if denominator else 0.0


def suspicion(text):
    return max(cosine(vector(text), vector(probe)) for probe in PROBES)


def dense_cosine(a, b):
    if not isinstance(a, list) or not isinstance(b, list) or not a or len(a) != len(b):
        raise ValueError('incompatible_embedding_dimensions')
    if not all(isinstance(v, (int,float)) and not isinstance(v,bool) and math.isfinite(v) for v in a+b):
        raise ValueError('invalid_embedding')
    denominator = math.sqrt(sum(v*v for v in a) * sum(v*v for v in b))
    if not denominator:
        raise ValueError('zero_embedding')
    return sum(x*y for x,y in zip(a,b)) / denominator


def scan_rag(database, key, max_bytes=32_000_000, max_rows=10000, probe_vectors=None):
    path = Path(database).absolute()
    # Snapshot bytes into a private in-memory database to avoid SQLite following filesystem links.
    payload = safe_read(path.parent, path.name, max_bytes)
    findings, issues, ranked = [], [], []
    with closing(sqlite3.connect(':memory:')) as db:
        db.deserialize(payload)
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        db.set_progress_handler(lambda: 1 if len(ranked) > max_rows else 0, 1000)
        columns = {row[1] for row in db.execute('PRAGMA table_info(chunks)')}
        has_embeddings = 'embedding' in columns
        query = 'SELECT id, text, metadata' + (', embedding' if has_embeddings else '') + ' FROM chunks ORDER BY id LIMIT ?'
        for index, record in enumerate(db.execute(query, (max_rows+1,))):
            record_id, text, metadata = record[:3]
            if index == max_rows:
                issues.append({'reason': 'rag_row_limit'})
                break
            location = f'chunks/row/{index}'
            if text is None:
                issues.append({'reason': 'original_text_unavailable', 'location': location})
            combined = '\n'.join(str(v) for v in (text, metadata) if v is not None)
            if len(combined.encode()) > 2_000_000:
                issues.append({'reason': 'rag_record_too_large', 'location': location})
                continue
            matches = []
            for content, field in [(text, 'text'), (metadata, 'metadata')]:
                if content is not None:
                    matches.extend(inspect_text(str(content), 'rag', location+'/'+field, key))
            findings.extend(matches)
            score, method = suspicion(combined), 'lexical_cosine'
            if probe_vectors is not None:
                if not has_embeddings or record[3] is None:
                    issues.append({'reason': 'embedding_unavailable', 'location': location})
                else:
                    try:
                        embedding = json.loads(record[3])
                        score = max(dense_cosine(embedding, probe) for probe in probe_vectors)
                        method = 'stored_embedding_cosine'
                    except (ValueError, TypeError, json.JSONDecodeError):
                        issues.append({'reason': 'invalid_or_incompatible_embedding', 'location': location})
            ranked.append({'location': location, 'similarity': round(score, 6), 'method': method,
                           'has_detected_credential': bool(matches), 'original_text_available': text is not None})
    ranked.sort(key=lambda item: item['similarity'], reverse=True)
    return {'findings': findings, 'complete': not issues, 'issues': issues, 'key_id': key_id(key),
            'review_candidates': ranked, 'ranking_method': 'local lexical term-frequency cosine; not semantic embeddings',
            'records_scanned': len(ranked)}


class GuardedRAG:
    """Application-facing gates: rejected input never reaches index, agent, or tool."""
    def __init__(self, key, allowed_tools=()):
        self.key, self.allowed_tools = key, frozenset(allowed_tools)

    def gate(self, text, stage):
        if stage not in {'before_index', 'before_agent', 'tool_call'}:
            raise ValueError('unsupported_runtime_stage')
        if not isinstance(text, str) or len(text.encode()) > 2_000_000:
            return {'allowed': False, 'complete': False, 'findings': [], 'issues': [{'reason': 'invalid_or_oversized_content'}]}
        findings = inspect_text(text, 'runtime', stage, self.key)
        return {'allowed': not findings, 'complete': True, 'findings': findings,
                'issues': [], 'stage': stage, 'key_id': key_id(self.key)}

    def index(self, text, write):
        result = self.gate(text, 'before_index')
        if not result['allowed']:
            raise PermissionError('index_blocked')
        return write(text)

    def retrieve(self, text, deliver):
        result = self.gate(text, 'before_agent')
        if not result['allowed']:
            raise PermissionError('retrieval_blocked')
        return deliver(text)

    def call_tool(self, name, arguments, invoke):
        if name not in self.allowed_tools:
            raise PermissionError('unsupported_tool')
        result = self.gate(json.dumps(arguments, sort_keys=True), 'tool_call')
        if not result['allowed']:
            raise PermissionError('tool_call_blocked')
        return invoke(name, arguments)
