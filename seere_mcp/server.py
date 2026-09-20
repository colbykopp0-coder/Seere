from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from mcp.server import MCPServer

from seere_sdk import ScanConfig, SeereScanner


mcp = MCPServer("SEERE")


def _allowed_roots() -> list[Path]:
    """
    Return the filesystem roots the MCP server is allowed to inspect.

    Configure with SEERE_ALLOWED_ROOTS using the platform path separator:
      macOS/Linux: /repo/a:/repo/b
      Windows: C:\\repo\\a;D:\\repo\\b

    If unset, access is limited to the current working directory.
    """
    raw = os.environ.get("SEERE_ALLOWED_ROOTS", "").strip()
    if not raw:
        return [Path.cwd().resolve()]

    roots: list[Path] = []
    for item in raw.split(os.pathsep):
        item = item.strip()
        if item:
            roots.append(Path(item).expanduser().resolve())
    return roots or [Path.cwd().resolve()]


def _authorize(path: str) -> Path:
    candidate = Path(path).expanduser().resolve()
    for root in _allowed_roots():
        if candidate == root or root in candidate.parents:
            return candidate
    allowed = ", ".join(str(root) for root in _allowed_roots())
    raise ValueError(
        f"Path is outside SEERE_ALLOWED_ROOTS. Allowed roots: {allowed}"
    )


def _scanner(git_history: bool = False) -> SeereScanner:
    key = os.environ.get(
        "SEERE_FINGERPRINT_KEY",
        "seere-local-dev-key-change-me",
    ).encode("utf-8")

    return SeereScanner(
        ScanConfig(
            fingerprint_key=key,
            scan_git_history=git_history,
        )
    )


def _serialize_findings(report, limit: int = 100) -> list[dict[str, Any]]:
    findings = []
    for finding in report.findings[:limit]:
        findings.append(
            {
                "kind": finding.kind,
                "provider": finding.provider,
                "severity": finding.severity,
                "path": finding.path,
                "line": finding.line,
                "preview": finding.preview,
                "fingerprint": finding.fingerprint,
                "source": finding.source,
                "environment": finding.environment,
                "first_seen": finding.first_seen,
                "notes": finding.notes,
            }
        )
    return findings


@mcp.tool()
def seere_status() -> dict[str, Any]:
    """
    Describe the local SEERE MCP server, its allowed filesystem scope, and
    its privacy model. Call this before scanning if you need to understand
    what SEERE is allowed to inspect.
    """
    return {
        "name": "SEERE MCP",
        "purpose": "Local-first machine identity and secret exposure analysis",
        "allowed_roots": [str(root) for root in _allowed_roots()],
        "privacy": {
            "raw_secrets_uploaded": False,
            "credential_validation_against_providers": False,
            "network_required_for_scan": False,
            "secret_output": "redacted preview + local HMAC fingerprint",
        },
    }


@mcp.tool()
def scan_path(
    path: str = ".",
    git_history: bool = False,
    max_findings: int = 100,
) -> dict[str, Any]:
    """
    Scan an authorized local directory for likely API keys, tokens,
    hard-coded credentials, private keys, AI/MCP config exposure,
    duplicated secrets, cross-environment reuse, and machine-identity
    artifacts.

    This tool does not use discovered credentials and does not validate them
    against third-party services. Raw secret values are not returned.
    """
    target = _authorize(path)
    if not target.is_dir():
        raise ValueError("scan_path expects a directory")

    report = _scanner(git_history=git_history).scan(target)
    limit = max(1, min(int(max_findings), 500))

    return {
        "root": report.root,
        "stats": report.stats,
        "findings": _serialize_findings(report, limit=limit),
        "truncated": len(report.findings) > limit,
        "safety": "Local analysis only. No discovered credential was used or validated.",
    }


@mcp.tool()
def scan_agent_configs(
    path: str = ".",
    max_findings: int = 100,
) -> dict[str, Any]:
    """
    Scan an authorized directory and return findings associated with
    AI-agent and MCP configuration surfaces.

    Useful when an agent is being connected to tools, APIs, databases,
    service accounts, or MCP servers and the owner wants to check whether
    machine credentials are being stored unsafely.
    """
    target = _authorize(path)
    if not target.is_dir():
        raise ValueError("scan_agent_configs expects a directory")

    report = _scanner(git_history=False).scan(target)
    relevant = []

    for finding in report.findings:
        low = finding.path.lower()
        notes = " ".join(finding.notes).lower()
        if (
            "mcp" in low
            or "agent" in low
            or "claude" in low
            or "langgraph" in low
            or "ai-agent" in notes
            or "mcp-related" in notes
        ):
            relevant.append(finding)

    limit = max(1, min(int(max_findings), 500))
    fake_report = type("AgentConfigReport", (), {"findings": relevant})()

    return {
        "root": report.root,
        "total_agent_config_findings": len(relevant),
        "findings": _serialize_findings(fake_report, limit=limit),
        "truncated": len(relevant) > limit,
        "safety": "SEERE reports redacted evidence only.",
    }


@mcp.tool()
def machine_identity_summary(
    path: str = ".",
    git_history: bool = False,
) -> dict[str, Any]:
    """
    Produce a compact machine-identity security summary for an authorized
    local directory. This is designed for agents that need a small result
    suitable for explaining risk to their owner.
    """
    target = _authorize(path)
    if not target.is_dir():
        raise ValueError("machine_identity_summary expects a directory")

    report = _scanner(git_history=git_history).scan(target)

    providers: dict[str, int] = {}
    environments: dict[str, int] = {}
    kinds: dict[str, int] = {}

    for finding in report.findings:
        providers[finding.provider] = providers.get(finding.provider, 0) + 1
        kinds[finding.kind] = kinds.get(finding.kind, 0) + 1
        if finding.environment:
            environments[finding.environment] = (
                environments.get(finding.environment, 0) + 1
            )

    urgent = [
        {
            "kind": f.kind,
            "provider": f.provider,
            "severity": f.severity,
            "path": f.path,
            "preview": f.preview,
            "fingerprint": f.fingerprint,
        }
        for f in report.findings
        if f.severity in {"CRITICAL", "HIGH"}
    ][:20]

    return {
        "root": report.root,
        "stats": report.stats,
        "providers": providers,
        "environments": environments,
        "finding_types": kinds,
        "urgent_findings": urgent,
        "message": (
            "If critical or high findings exist, the owner should review and "
            "rotate/remediate affected credentials using their authorized "
            "provider and deployment workflows."
        ),
    }


@mcp.tool()
def explain_finding(
    kind: str,
    provider: str,
    severity: str,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    """
    Explain a SEERE finding and return defensive remediation guidance.
    This does not test or use any credential.
    """
    notes = notes or []

    actions = [
        "Treat an exposed credential as potentially compromised.",
        "Identify the application, service, agent, or workflow that owns it.",
        "Rotate or revoke it through the authorized provider workflow.",
        "Update dependent applications using a managed secret store.",
        "Review authorized audit logs for unexpected use where available.",
        "Remove the credential from source/config history where practical.",
        "Add preventive secret scanning and least-privilege controls.",
    ]

    if "git" in " ".join(notes).lower():
        actions.append(
            "Remember that deleting a secret from the latest commit does not "
            "remove it from Git history."
        )

    return {
        "finding": {
            "kind": kind,
            "provider": provider,
            "severity": severity,
            "notes": notes,
        },
        "recommended_actions": actions,
        "principle": (
            "SEERE helps owners detect and remediate exposure; it does not "
            "use discovered credentials."
        ),
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
