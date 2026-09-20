from dataclasses import dataclass, asdict
from typing import Optional, Any


@dataclass
class ExposureRecord:
    organization: str
    provider: str
    kind: str
    fingerprint: str
    severity: str
    source_type: str
    asset: str
    first_seen: str
    last_seen: str
    status: str = "open"
    owner: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OrganizationClaim:
    domain: str
    challenge: str
    method: str
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
