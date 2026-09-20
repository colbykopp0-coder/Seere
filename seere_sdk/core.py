from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict
import datetime as dt
import subprocess

from .models import Finding, ScanReport
from .patterns import PATTERNS, AI_AGENT_FILE_HINTS, SERVICE_ACCOUNT_HINTS
from .util import fingerprint, redact, entropy, guess_environment, broad_permissions


IGNORES = {
    ".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv",
    "__pycache__", "dist", "build", ".next", ".cache"
}

EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".conf", ".env", ".txt", ".md", ".sh", ".ps1",
    ".properties", ".xml", ".go", ".rs", ".java", ".rb", ".php"
}


@dataclass
class ScanConfig:
    fingerprint_key: bytes = b"seere-local-dev-key-change-me"
    max_file_bytes: int = 2_000_000
    scan_git_history: bool = False
    include_hidden: bool = True


class SeereScanner:
    def __init__(self, config: ScanConfig | None = None):
        self.config = config or ScanConfig()

    def scan(self, root: str | Path) -> ScanReport:
        root = Path(root).resolve()
        findings: list[Finding] = []

        for path in self._iter_files(root):
            findings.extend(self._scan_file(path, root))

        if self.config.scan_git_history and (root / ".git").exists():
            findings.extend(self._scan_git_history(root))

        self._annotate_duplicates(findings)
        self._annotate_cross_environment(findings)
        self._annotate_service_account_sprawl(findings)

        stats = {
            "total_findings": len(findings),
            "critical": sum(f.severity == "CRITICAL" for f in findings),
            "high": sum(f.severity == "HIGH" for f in findings),
            "medium": sum(f.severity == "MEDIUM" for f in findings),
            "low": sum(f.severity == "LOW" for f in findings),
            "unique_fingerprints": len({f.fingerprint for f in findings}),
            "providers": sorted({f.provider for f in findings}),
        }
        return ScanReport(str(root), findings, stats)

    def _iter_files(self, root: Path):
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in IGNORES for part in path.parts):
                continue
            if not self.config.include_hidden and any(part.startswith(".") for part in path.parts):
                continue
            try:
                if path.stat().st_size > self.config.max_file_bytes:
                    continue
            except OSError:
                continue

            if (
                path.suffix.lower() in EXTENSIONS
                or path.name.startswith(".env")
                or path.name.lower() in AI_AGENT_FILE_HINTS
            ):
                yield path

    def _scan_file(self, path: Path, root: Path) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        rel = str(path.relative_to(root))
        findings: list[Finding] = []

        is_agent_config = (
            path.name.lower() in AI_AGENT_FILE_HINTS
            or "mcp" in path.name.lower()
        )
        insecure_storage = path.name.startswith(".env") or is_agent_config

        for lineno, line in enumerate(text.splitlines(), 1):
            for pattern in PATTERNS:
                for match in pattern.regex.finditer(line):
                    secret = match.group(1) if match.lastindex else match.group(0)

                    if pattern.provider == "generic" and entropy(secret) < 2.5:
                        continue

                    notes = []
                    severity = pattern.severity

                    if insecure_storage:
                        notes.append("Credential appears in a high-risk local config location.")
                    if is_agent_config:
                        notes.append("Credential appears in an AI-agent / MCP-related configuration file.")
                    if broad_permissions(path):
                        notes.append("File may be readable by group/other users on this host.")
                        if severity == "MEDIUM":
                            severity = "HIGH"

                    try:
                        first_seen = dt.datetime.fromtimestamp(
                            path.stat().st_mtime,
                            dt.timezone.utc,
                        ).isoformat()
                    except OSError:
                        first_seen = None

                    findings.append(
                        Finding(
                            kind=pattern.name,
                            provider=pattern.provider,
                            severity=severity,
                            path=rel,
                            line=lineno,
                            preview=redact(secret),
                            fingerprint=fingerprint(secret, self.config.fingerprint_key),
                            source="filesystem",
                            environment=guess_environment(rel),
                            first_seen=first_seen,
                            notes=notes,
                        )
                    )

        lower_name = path.name.lower()
        if any(hint in lower_name for hint in SERVICE_ACCOUNT_HINTS):
            findings.append(
                Finding(
                    kind="Service-account artifact",
                    provider="machine-identity",
                    severity="MEDIUM",
                    path=rel,
                    line=None,
                    preview="service-account artifact",
                    fingerprint=fingerprint(rel, self.config.fingerprint_key),
                    source="filesystem",
                    environment=guess_environment(rel),
                    notes=["Review ownership, scope, rotation, and retirement policy."],
                )
            )

        return findings

    def _scan_git_history(self, root: Path) -> list[Finding]:
        try:
            proc = subprocess.run(
                [
                    "git", "-C", str(root), "log", "--all", "-p", "--no-color",
                    "--format=commit:%H|%aI",
                ],
                capture_output=True,
                text=True,
                errors="ignore",
                timeout=45,
            )
        except Exception:
            return []

        findings: list[Finding] = []
        current_commit = None
        current_date = None
        current_file = "git-history"

        for line in proc.stdout.splitlines():
            if line.startswith("commit:"):
                payload = line[len("commit:"):]
                parts = payload.split("|", 1)
                current_commit = parts[0]
                current_date = parts[1] if len(parts) > 1 else None
                continue

            if line.startswith("+++ b/"):
                current_file = line[6:]
                continue

            if not line.startswith("+") or line.startswith("+++"):
                continue

            content = line[1:]

            for pattern in PATTERNS:
                for match in pattern.regex.finditer(content):
                    secret = match.group(1) if match.lastindex else match.group(0)

                    if pattern.provider == "generic" and entropy(secret) < 2.5:
                        continue

                    findings.append(
                        Finding(
                            kind=pattern.name,
                            provider=pattern.provider,
                            severity="CRITICAL"
                            if pattern.severity in {"CRITICAL", "HIGH"}
                            else "HIGH",
                            path=current_file,
                            line=None,
                            preview=redact(secret),
                            fingerprint=fingerprint(secret, self.config.fingerprint_key),
                            source=f"git:{current_commit or 'unknown'}",
                            environment=guess_environment(current_file),
                            first_seen=current_date,
                            notes=[
                                "Credential appears in Git history; removing it from HEAD alone may not remove historical exposure."
                            ],
                        )
                    )

        return findings

    def _annotate_duplicates(self, findings: list[Finding]) -> None:
        by_fp = defaultdict(list)
        for finding in findings:
            by_fp[finding.fingerprint].append(finding)

        for group in by_fp.values():
            locations = {(f.source, f.path) for f in group}
            if len(locations) > 1:
                for finding in group:
                    finding.notes.append(
                        f"Same credential fingerprint appears in {len(locations)} locations."
                    )

    def _annotate_cross_environment(self, findings: list[Finding]) -> None:
        by_fp = defaultdict(list)
        for finding in findings:
            by_fp[finding.fingerprint].append(finding)

        for group in by_fp.values():
            envs = {f.environment for f in group if f.environment}
            if len(envs) > 1:
                for finding in group:
                    finding.notes.append(
                        "Credential appears across multiple environments: "
                        + ", ".join(sorted(envs))
                    )
                    if finding.severity == "MEDIUM":
                        finding.severity = "HIGH"

    def _annotate_service_account_sprawl(self, findings: list[Finding]) -> None:
        service_findings = [
            finding
            for finding in findings
            if finding.provider == "machine-identity"
        ]
        if len(service_findings) >= 5:
            for finding in service_findings:
                finding.notes.append(
                    "Service-account sprawl heuristic triggered; review ownership and lifecycle."
                )
