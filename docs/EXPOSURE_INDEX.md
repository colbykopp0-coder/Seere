# SEERE Exposure Index

## Idea

SEERE can provide the machine-identity equivalent of a breach lookup service:

> **Have your machines been exposed?**

The public-facing product should be useful without publishing exploitable credential material.

## Core flow

1. A company enters its domain.
2. SEERE creates a claim for that organization.
3. Ownership is verified using one of:
   - DNS TXT challenge
   - email challenge to an approved domain mailbox
   - GitHub organization admin OAuth
4. Once verified, the organization can view exposure metadata associated with its domain and connected assets.
5. SEERE Sentinel can be enabled for persistent monitoring.

## Data model

SEERE stores only metadata needed for correlation:

- provider/type
- HMAC fingerprint
- source type
- asset identifier
- first/last seen timestamps
- severity
- remediation status
- ownership metadata
- evidence pointer

**Raw secret values are not stored in the index.**

## Public behavior

An unverified visitor must never receive raw secrets, credential fragments sufficient for reconstruction,
exact exploit paths, or sensitive internal metadata.

The public page can say:

> Verify ownership of example.com to check for machine-credential exposure.

After ownership verification:

> 11 machine identities need review  
> 3 high-risk exposures  
> 2 credentials appear across multiple environments  
> 1 credential appears in public source history

## Product funnel

**SEERE Scan — Free**  
Find the problem.

**SEERE Assessment — Paid**  
Understand the problem.

**SEERE Response — Paid**  
Fix the problem.

**SEERE Sentinel — Subscription**  
Never let it happen again.

## Viral loop

Developer runs SEERE locally -> discovers exposure -> invites security/DevOps ->
organization claims domain -> connects repositories/cloud -> Sentinel remains installed ->
future detections create recurring value.

## Security constraints

- no unauthorized credential validation
- no raw-secret publication
- no public endpoint that allows enumerating exact vulnerabilities for arbitrary third parties
- rate-limit organization lookups
- auditable organization verification
- minimize retained telemetry
- customer-controlled deletion/export
- strong separation between public index and private findings
