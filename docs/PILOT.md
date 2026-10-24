# Proposed SEERE pilot



Status: proposal for review. Executing a customer pilot is outside the current code-delivery scope.



## Objective



Evaluate whether SEERE can discover and correlate credential exposure across code/Git, local AI/MCP configuration, RAG storage and supported runtime hooks, then guide one explicitly approved remediation and verify the result.



## Proposed scope



One small design-partner customer, one application owner and one security reviewer. Use one authorized repository with up to 100 commits, up to five configuration files, one consistent SQLite snapshot with up to 1,000 chunks, and one application workflow using indexing, retrieval and one allowlisted tool hook. Larger inputs are a separate scope decision; limits and exclusions must appear in the report.



Begin with an isolated copy containing 20 synthetic exposures across supported credential families and all four layers, including one credential repeated across layers. Add 20 benign fixtures and missing-text cases. Keep these fixtures separate from the customer's unmodified snapshot. Live credentials are never exercised to establish validity.



## Proposed schedule



| Phase | Timing | Work and evidence |

|---|---|---|

| Scope and setup | Days 1–2 | Confirm authorization, snapshots, exclusions, key custody, container revision and review labels. |

| Baseline and integration | Days 3–4 | Run all modules; wire supported runtime hooks; demonstrate missing-module and incomplete-coverage reporting. |

| Detection and ranking review | Days 5–6 | Label findings; evaluate planted exposures; compare cosine top-20 review candidates with 20 randomly selected passages outside detector hits. |

| Approved remediation | Days 7–8 | Review one exact fix, prove unsigned/altered approval rejection, apply signed approval to the maintenance copy and verify current surfaces. |

| Rescan and decision | Days 9–10 | Review historical exposure, app smoke checks, metrics, defects and customer acceptance. |



This is a proposed ten-business-day schedule, starting only after the participant and authorized inputs are available.



## Proposed acceptance criteria



- All four expected modules report the same run ID and fingerprint-key ID; any incomplete coverage is visible and prevents a clean-run conclusion.

- Reports, model inputs and audit receipts contain no raw credential values in the planted test set.

- Detect 100% of planted critical/high exposures supported by the declared rules; report misses by credential family and surface.

- Target at least 90% precision among customer-reviewed findings. Review all findings when there are 50 or fewer; otherwise use a documented random sample of at least 50, report the sample size and keep unresolved cases separate. This is a pilot target, not an existing performance claim.

- Report recall only for known labelled/planted exposures. Do not infer corpus-wide recall from findings alone.

- All planted credential-bearing runtime inputs are blocked, and all benign runtime fixtures pass. The application callback must not run after rejection.

- Cross-layer copies of the planted credential form one correlated group. Missing reports, stale runs and incompatible key IDs are rejected or explicitly incomplete.

- Compare cosine review yield with equal-size random review. Report additional relevant passages separately from additional confirmed exposures; zero incremental exposure discoveries is a valid measured result.

- One unsigned or altered remediation plan is rejected; one reviewed, signed fix succeeds; the rescan verifies the change. Git-history evidence remains visible. Provider containment is counted only after actual provider verification.

- Record duration and peak resources. Proposed scan target: ten minutes for the bounded pilot scope on the agreed customer host; misses become measured findings, not hidden timeouts.



## Responsibilities and deliverables



The Chief Systems Architect owns architecture and scope decisions. The development lead owns build, tests, fixes and evidence. The customer application owner authorizes scope and assesses application impact. The security reviewer labels findings and controls the separate human approval key. An operator executes approved changes through the customer's deployment process.



Deliverables: versioned container configuration, authorized-scope record, module reports, correlated action plan, labelled detection/ranking metrics, approval receipt, verification report, defect backlog and a go/no-go recommendation. The customer retains raw snapshots and key material.



## Boundaries and exit decision



No automatic production changes, provider credential validation, Git-history rewrite, model-driven access enforcement or unapproved telemetry. Real provider adapters and loaded-model inference are separate integration checks before relying on them operationally. The current executable demo uses a synthetic provider and simulated human approval.



Proceed to a broader pilot only when acceptance evidence and owner review support it. Otherwise prioritize the recorded detection, integration or operational defects and repeat the affected checks.



---



## Execution runbook



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

