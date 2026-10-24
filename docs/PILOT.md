# Small-customer pilot runbook

Status: prepared; no customer pilot has been performed.

1. Customer names an owner and authorizes exact code/config/database snapshots, retention and permitted runtime hooks. Record exclusions and prohibit credential validation. Keep raw content inside the customer's environment.
2. Create a fresh run directory and private fingerprint key. Make snapshot inputs read-only. Keep the separate human approval key with the operator, outside all agent mounts. Review Linux UID mapping or Windows ACLs.
3. Run all four modules and the coordinator. Record run ID, image digest, scanner revision, exclusions, incomplete coverage, elapsed time and resource use. Do not classify an incomplete run as clean.
4. Customer labels findings as confirmed exposure, benign pattern or unresolved, and adds known synthetic planted exposures to a separate evaluation copy. Calculate precision from reviewed findings and recall only against known labelled/planted exposures. Report unresolved and unreviewed counts separately.
5. Review cosine top-k candidates that rule scanning did not identify. Count additional relevant passages and additional confirmed exposures separately; compare with a random review sample of the same size. Do not treat a similarity score as a credential verdict.
6. Select one supported fix. Owner reviews the exact patch and dependencies, signs the approval, applies it to a maintenance snapshot and deploys through their normal change process. Real provider rotation/revocation uses a customer-approved adapter or manual provider workflow; preserve an operator audit receipt.
7. Rescan every affected surface with the same fingerprint key and a fresh run ID. Historical exposure stays open until provider revocation and retention decisions are verified. Run the application smoke tests and confirm runtime hooks block planted exposures without leaking content.
8. Agree acceptance before starting: full declared module coverage, no raw secret in outputs, all planted critical fixtures found, reviewed false-positive budget and scan-time budget, and verified approved remediation. Record defects and customer sign-off. No telemetry leaves the customer environment without their explicit authorization.

Pilot evidence template:

| Field | Value |
|---|---|
| Customer/owner/authorization reference | Pending |
| Approved roots and corpus snapshot | Pending |
| Revision and image digest | Pending |
| Run IDs and key ID (never key material) | Pending |
| Complete modules / incomplete reasons | Pending |
| Reviewed TP / FP / unresolved / unreviewed | Pending |
| Planted TP / FN | Pending |
| Cosine additional relevant / confirmed exposures | Pending |
| Scan duration / peak resource use | Pending |
| Approval receipt / fix / provider verification | Pending |
| Rescan and application verification | Pending |
| Customer acceptance | Pending |
