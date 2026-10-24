# SEERE modular implementation

This branch implements the software path for the five milestones. A real customer pilot and live model/provider validation require external participants and services; neither is represented as completed.

## 1. Scanner

`security.py` implements explicit root authorization, descriptor-bound POSIX reads, Windows opened-handle verification, reparse/symlink rejection, hardlink rejection, bounded reads and private persistent 32-byte fingerprint keys. The scanner inspects UTF-8 files regardless of extension, including extensionless credentials. It reports unreadable/oversized/binary content, declared excluded directories and truncated history. Git scans complete historical blobs, including deleted files and multiline private keys, with commit/blob/output/time limits. Worktrees with external metadata and object alternates are rejected.

`detection.py` is the common detector for provider tokens, quoted JSON assignments, credential files and complete PEM/OpenSSH private key blocks. Private key material is fingerprinted as a whole. All evidence previews are fully redacted. Confidence is a rule-based score, not a calibrated probability. Format and entropy heuristics cannot prove a credential is valid; no live credential validation occurs.

Persistent keys default to `.seere/fingerprint.key`. The key directory is excluded from scans and Docker build context. Linux permissions are checked. On Windows, protect the key directory using an operator-controlled ACL; Python mode bits do not establish equivalent ACL protection. Key rotation starts a new correlation domain.

## 2. Module contract and containers

The code, local-config, RAG and runtime workers emit v1 envelopes with module, run ID, key ID, completeness, findings and coverage details. The schema is `schemas/report.schema.json`. Each finding includes source/location, type/provider, HMAC fingerprint, heuristic confidence, severity and recommended action. Coordinator rejects duplicated modules, incompatible fingerprint keys and stale run IDs; absent modules make the plan incomplete.

The five Compose workers run as a non-root user with no network, read-only root filesystem, read-only authorized input, dropped capabilities and resource limits. Workers write to individual report directories. Coordinator reads reports but has no fingerprint or approval key. Scanning containers never receive a writable source mount or a human approval key.

Set up an isolated run:

```sh
python -m seere_sdk.control init work/run-001
export SEERE_RUN_DIR="$PWD/work/run-001"
export SEERE_UID="$(id -u)"
export SEERE_GID="$(id -g)"
# Place only authorized snapshots into scope/code, scope/local and scope/rag.
# SQLite snapshot: scope/rag/chunks.db; runtime fixture: scope/runtime/content.txt.
docker compose build
docker compose run --rm code
docker compose run --rm local
docker compose run --rm rag
docker compose run --rm runtime
docker compose --profile coordinate run --rm coordinator
```

On Windows set the environment variables in PowerShell; UID/GID mapping is needed for Linux bind-mount ownership. Exit code 2 means a report was produced with incomplete coverage. Malformed inputs fail without a success report; the coordinator then identifies the missing module. Use a fresh run ID and directory for every run.

## 3. RAG connector and prevention

SQLite schema: `chunks(id TEXT, text TEXT, metadata TEXT)` with optional `embedding TEXT` containing a JSON numeric vector. Supply a consistent SQLite backup, not an active database missing its WAL. The connector opens a scope-checked bounded snapshot and scans a private in-memory copy. NULL original text explicitly makes coverage incomplete; metadata is scanned independently.

Default ranking uses local term-frequency cosine against credential-related probes. It prioritizes review candidates without asserting they contain credentials. `scan_rag(..., probe_vectors=[[...]])` supports cosine ranking against stored embeddings from the same embedding model. Invalid, missing or mismatched embeddings produce coverage issues. Embeddings are not inverted to recover unavailable original text.

`GuardedRAG.index`, `.retrieve` and `.call_tool` are application integration points that invoke deterministic checks before executing callbacks. Unsupported tools, oversized content and detected credentials are blocked. Applications must use these wrappers; containers do not intercept arbitrary processes. Credential-bearing tool arguments require a separate brokered-credential design rather than bypassing the scanner.

## 4. Agent coordination and approved response

Four specialist roles and a coordinator can interpret numeric redacted features through an OpenAI-compatible loopback model. File paths, content, notes and previews are excluded from model prompts. Model outputs accept only enumerated risk/reason/action values and cannot execute actions. Without a configured model, the output explicitly says `deterministic_fallback`.

Optional local inference containers are defined in `compose.ai.yaml`: provide a verified Ollama image via SEERE_MODEL_IMAGE, preloaded weights via SEERE_MODEL_DIR and model name via SEERE_MODEL. The model and AI coordinator share an isolated network namespace, publish no ports and have no external network. Start the model and wait for it to load before invoking ai-coordinator. Actual inference quality requires a loaded model and has not been established by protocol tests.

`response.py` binds a separately held human approval key to the exact plan digest, approver, expiry and single-use nonce. It rejects changed plans, invalid/expired signatures, stale file contents, unapproved roots and unsupported actions. Supported changes are scope-limited file replacement, validated SQLite snapshot replacement and revocation through an explicitly supplied provider adapter. No real credential provider adapter is shipped. Adapter revocation must be verified by `is_revoked` before it is reported successful.

```sh
# Review the complete remediation JSON before signing. Keep the human key outside scanner mounts.
seere-control approve --plan remediation.json --approver operator-name \
  --approval-key /private/operator.key --output approval.json
seere-control apply --plan remediation.json --approval approval.json \
  --approval-key /private/operator.key --fingerprint-key work/run-001/.seere/fingerprint.key \
  --authorized-root /approved/maintenance-snapshot --audit-dir /private/audit
```

Apply to a quiescent maintenance snapshot, not a directory another process can mutate. Multi-file/provider operations are not a transaction; receipts record partial failure and require a new review. Database replacements are for offline snapshots; application owners must control deployment. Native filesystem ACLs, approval-key custody and an immutable external audit store remain deployment responsibilities.

## 5. Reproducible demonstration, benchmark and pilot

```sh
python -m seere_sdk.demo work/demo-001
python -m seere_sdk.control benchmark --output benchmark.json
pytest -q
```

The demo creates a fresh synthetic Git repo, MCP configuration and SQLite corpus containing the same synthetic credential. It correlates all four layers, proves unsigned execution is denied, signs a test approval with a separate test-human key, removes current exposures, revokes the synthetic provider identity and rescans. Current surfaces become clean. Historical findings remain visible even after simulated revocation; the demo never claims Git history has been erased. Approval and provider revocation are simulated, not actual human/provider events.

The synthetic detector corpus has 9 positive and 7 negative cases. The ranking evaluation separately measures top-k relevant passages and incremental review coverage; it does not count relevance as additional confirmed secrets. These fixtures are regression evidence, not a statistically representative estimate of production accuracy.

`tests/container_smoke.py` builds and executes all five real containers, checks correlation, verifies network/read-only configuration and confirms an attempted source write fails. The Linux GitHub Actions job runs it alongside the regression suite. A Docker runtime is not installed on the development host.

The customer pilot runbook is `PILOT.md`. A real pilot requires an identified customer, explicit authorized scope, an operator-owned key and customer-labelled findings. Those external dependencies cannot be replaced with synthetic results.
