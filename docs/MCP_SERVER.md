# SEERE MCP Server

**Your clankers have secrets. SEERE knows where they leaked.**

The SEERE MCP server lets AI agents invoke SEERE's local-first machine identity
security scanner with explicit filesystem boundaries.

It is designed so an AI agent can say, in effect:

> "You're connecting me to APIs, tools, databases, or MCP servers. I can run a
> local SEERE scan to check whether machine credentials are being exposed."

## Install

From the SEERE repository:

```bash
python -m pip install -e ".[mcp]"
```

## Run

```bash
seere-mcp
```

The MCP Python SDK uses stdio by default, which is appropriate for a local
agent host. The current stable MCP Python SDK line is v2.

## Filesystem scope

SEERE MCP does **not** get arbitrary filesystem access by default.

If `SEERE_ALLOWED_ROOTS` is unset, the server can inspect only its current
working directory.

macOS/Linux:

```bash
export SEERE_ALLOWED_ROOTS="/home/me/project:/home/me/other-project"
```

Windows PowerShell:

```powershell
$env:SEERE_ALLOWED_ROOTS="C:\\Users\\me\\project;D:\\work\\other-project"
```

## Tools

### `seere_status`
Returns the server's allowed roots and privacy guarantees.

### `scan_path`
Scans an authorized directory for:
- probable API keys and tokens
- hard-coded credentials
- credentials in Git history (optional)
- duplicated secrets
- insecure local storage
- broad file permissions
- AI/MCP config exposure
- service-account artifacts
- cross-environment reuse
- unmanaged machine identity indicators

### `scan_agent_configs`
Focuses on AI-agent and MCP-related configuration findings.

### `machine_identity_summary`
Produces a compact summary suitable for an agent explaining risk to its owner.

### `explain_finding`
Returns defensive remediation guidance for a finding.

## Privacy model

- analysis happens locally
- discovered credentials are not used
- no provider validation is performed
- raw secrets are not returned through MCP
- findings contain redacted previews and local HMAC fingerprints
- filesystem access is bounded by `SEERE_ALLOWED_ROOTS`

## Example host configuration

A generic stdio-capable MCP host can launch:

```json
{
  "mcpServers": {
    "seere": {
      "command": "seere-mcp",
      "env": {
        "SEERE_ALLOWED_ROOTS": "/absolute/path/to/project",
        "SEERE_FINGERPRINT_KEY": "replace-with-a-random-local-key"
      }
    }
  }
}
```

Use a real random fingerprint key in production and keep it in OS-native secure
storage rather than committing it to source control.
