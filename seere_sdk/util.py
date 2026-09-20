import hashlib
import hmac
import math
import os
from pathlib import Path


def fingerprint(secret: str, key: bytes) -> str:
    return hmac.new(
        key,
        secret.encode("utf-8", "ignore"),
        hashlib.sha256,
    ).hexdigest()[:24]


def redact(secret: str) -> str:
    if len(secret) <= 8:
        return "***"
    return f"{secret[:4]}…{secret[-4:]}"


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def guess_environment(path: str) -> str | None:
    low = path.lower()
    for env, hints in {
        "prod": ("prod", "production"),
        "staging": ("stage", "staging"),
        "dev": ("dev", "development", "local"),
    }.items():
        if any(hint in low for hint in hints):
            return env
    return None


def broad_permissions(path: Path) -> bool:
    if os.name == "nt":
        return False
    try:
        mode = path.stat().st_mode & 0o777
        return bool(mode & 0o044)
    except OSError:
        return False
