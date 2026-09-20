from __future__ import annotations

import secrets
from dataclasses import dataclass


@dataclass
class VerificationChallenge:
    domain: str
    token: str
    dns_name: str
    dns_value: str


def create_dns_challenge(domain: str) -> VerificationChallenge:
    """
    Create a DNS TXT challenge.

    A production verifier would resolve DNS independently and confirm the exact
    TXT record before granting access to organization findings.
    """
    domain = domain.strip().lower().rstrip(".")
    token = secrets.token_urlsafe(24)
    return VerificationChallenge(
        domain=domain,
        token=token,
        dns_name=f"_seere-verify.{domain}",
        dns_value=f"seere-verification={token}",
    )


def verification_instructions(challenge: VerificationChallenge) -> dict:
    return {
        "domain": challenge.domain,
        "record_type": "TXT",
        "name": challenge.dns_name,
        "value": challenge.dns_value,
        "next_step": "After the TXT record is visible, request verification.",
    }
