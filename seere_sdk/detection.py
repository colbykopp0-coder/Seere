"""One detector shared by filesystem, Git, RAG and runtime modules."""
import json
import re
from .models import Finding
from .patterns import PATTERNS
from .util import entropy, fingerprint

ASSIGNMENT = re.compile(r'''(?ix)["']?\b(?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|auth[_-]?token|session[_-]?token|secret[_-]?access[_-]?key|secret|client[_-]?secret|password|private[_-]?key)\b["']?\s*[:=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s,}\]\r\n]+))''')
PLACEHOLDERS = {'changeme', 'your_api_key', 'redacted', 'placeholder', 'password', 'example', 'null', 'none'}


def inspect_text(text, source, location, key):
    hits = []
    for pattern in PATTERNS:
        if pattern.name == 'Generic credential assignment':
            continue
        for match in pattern.regex.finditer(text):
            value = match.group(1) if match.lastindex else match.group()
            if pattern.name == "Private key block":
                value = value.replace("\\n", "\n").replace("\r\n", "\n")
            hits.append((match.start(), value, pattern.name, pattern.provider, pattern.severity, .95))
    for match in ASSIGNMENT.finditer(text):
        value = next(g for g in match.groups() if g is not None)
        if len(value) < 12 or value.lower() in PLACEHOLDERS or value.startswith(('${', '{{', '$env:', 'os.environ')):
            continue
        if entropy(value) >= 2.5:
            hits.append((match.start(), value, 'Generic credential assignment', 'generic', 'MEDIUM', .65))
    results, seen = [], set()
    for offset, value, kind, provider, severity, confidence in hits:
        fp = fingerprint(value, key)
        line = text[:offset].count('\n') + 1
        identity = (fp, line)
        if identity in seen:
            continue
        seen.add(identity)
        results.append(Finding(kind, provider, severity, location, line, '[REDACTED]', fp,
            source=source, confidence=confidence).to_dict())
    return results
