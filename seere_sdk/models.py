from dataclasses import dataclass, asdict, field
from typing import Optional, Any


@dataclass
class Finding:
    kind: str
    provider: str
    severity: str
    path: str
    line: Optional[int]
    preview: str
    fingerprint: str
    source: str = "filesystem"
    environment: Optional[str] = None
    first_seen: Optional[str] = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    root: str
    findings: list[Finding]
    stats: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats,
        }
