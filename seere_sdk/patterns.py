import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    name: str
    provider: str
    regex: re.Pattern
    severity: str


PATTERNS = [
    SecretPattern(
        "OpenAI API key",
        "openai",
        re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    SecretPattern(
        "Anthropic API key",
        "anthropic",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    SecretPattern(
        "AWS access key",
        "aws",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "CRITICAL",
    ),
    SecretPattern(
        "GitHub token",
        "github",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"),
        "HIGH",
    ),
    SecretPattern(
        "Stripe secret key",
        "stripe",
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        "CRITICAL",
    ),
    SecretPattern(
        "Google API key",
        "google",
        re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
        "HIGH",
    ),
    SecretPattern(
        "Private key block",
        "generic",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "CRITICAL",
    ),
    SecretPattern(
        "Generic credential assignment",
        "generic",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|secret|client[_-]?secret|password)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:@-]{12,})"
        ),
        "MEDIUM",
    ),
]

AI_AGENT_FILE_HINTS = {
    "mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
    "agent.json",
    "agents.json",
    "langgraph.json",
}

SERVICE_ACCOUNT_HINTS = (
    "service-account",
    "service_account",
    "credentials.json",
    "gcp-key",
    "google-credentials",
)
