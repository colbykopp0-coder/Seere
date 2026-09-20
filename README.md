# SEERE

**Machine Identity Security**

SEERE is a local-first security agent for discovering and managing machine credentials, non-human identities, and secret exposure across modern software and AI systems.

## Product flow

**SEERE Scan — Free**  
Find the problem.

**SEERE Assessment — Paid**  
Understand the problem.

**SEERE Response — Paid**  
Fix the problem.

**SEERE Sentinel — Subscription**  
Never let it happen again.

## Concept

SEERE runs locally first. It scans only paths and environments the customer authorizes, classifies potential credential exposure, fingerprints findings locally, and can optionally pipeline sanitized metadata to SEERE Sentinel.

The local agent is designed to detect:

- probable API keys and tokens
- hard-coded credentials
- credentials in Git history
- duplicated secrets
- long-lived-secret indicators
- insecure local storage
- overly broad file permissions
- AI-agent / MCP configs containing sensitive credentials
- service-account sprawl
- secrets copied across environments
- unmanaged machine identities

## Security model

SEERE should never become another place where customer secrets accumulate.

The design principles are:

- local processing by default
- no credential validation against third-party services
- raw secrets are not uploaded
- HMAC fingerprints for cross-location correlation
- redacted evidence for reports
- customer-controlled telemetry
- explicit authorization for every monitored environment
- approval gates before high-impact remediation actions
- signed agent builds and secure update channels

## Quick start

```bash
python -m pip install -e .
seere scan ./my-project
seere scan ./my-project --git-history
```

Optional metadata-only Sentinel pipeline:

```bash
export SEERE_ENDPOINT="https://sentinel.example.com/v1/findings"
export SEERE_TOKEN="..."
export SEERE_FINGERPRINT_KEY="replace-with-an-org-specific-random-key"

seere scan ./my-project --push
```

## Status

Early concept prototype. Not production-ready.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the proposed architecture and roadmap.
