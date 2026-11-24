# Template audit-report service

This service implements the file-based report fallback for `AI_PROVIDER=none`. It reads existing FAIL and
INCONCLUSIVE findings, resolves their evidence through the Core and Gateway APIs, and exports contract-valid
`AuditReportSubmission` JSON with a readable Markdown companion. Its model identity is `none/template/1.0.0`.
It does not use an LLM, review findings, publish findings, change an election, or relax finalization conditions.

The Rule Engine remains responsible for R1–R5 and the independent pinned-node audit. An audit report is an
explanation of a stored finding and its available references. A COMPLETED report is not an election PASS, a
verified root cause, or proof that an integration scenario succeeded.

## Current mapping provenance

The bundled `config/b1-cause-map.pr10.json` encodes Harits's proposed B1 table from
[PR #10, commit 4e398deb7da0256d849ab0e58bd7ac752f8db2f0](https://github.com/jsm1024/purevoting2/pull/10),
`docs/test-plan.md`. It is marked `proposed`. By default, the service resolves references and produces ESCALATED
reports without using that table to claim a cause.

`AUDIT_ALLOW_PROPOSED_MAPPING=true` explicitly enables that proposed table for advisory development reports.
Every such report includes its proposed status and pinned source. This setting is not acceptance of an evaluation
baseline. Unknown or unmapped causes still produce ESCALATED reports. The synthetic HTTP smoke uses this option
only with its own generated fixtures.

After the team accepts and freezes a B1 table, provide its local machine-readable encoding through
`AUDIT_B1_MAPPING`. An approved encoding must contain `status: approved` and an `approval` object whose
`source_commit` matches `source.commit` and whose `reference` identifies the review. Preserve the exact ordered
rows and source commit. This metadata is operator-supplied provenance; the agent cannot independently verify a
reviewer's approval. Do not relabel the proposed file as approved merely to obtain a COMPLETED report.

## Verify without deployment credentials

From the repository root, with Python 3.11 and the existing locked requirements installed:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -c rules\pytest.ini rules\tests
.\.venv\Scripts\python.exe rules\devtools\audit_report_smoke.py
```

The smoke starts a temporary server on `127.0.0.1`, runs the real agent and reference-validator CLIs, then starts
the agent again. It checks one COMPLETED and one ESCALATED report, schema/reference validation, and identical
report IDs and bytes after restart. Its subprocesses use an allowlisted environment with a synthetic service key;
they do not inherit actual deployment credentials or endpoints. To retain its sample reports, give it a new path:

```powershell
.\.venv\Scripts\python.exe rules\devtools\audit_report_smoke.py --output-dir "$env:USERPROFILE\purevoting-evidence\audit-template-smoke-01"
```

An existing destination is refused. These are synthetic HTTP results; the summary explicitly records no real
Core, Gateway, chain, official T01, E1 finalization, or AI evaluation.

## Run against the agreed Core and Gateway

Use the deployment owner's existing services and their matching `AGENT_KEY`. Obtain the key through the team's
private configuration process. Use HTTP(S) origins for `CORE_URL` and `GATEWAY_URL`, without embedded credentials,
path prefixes, queries, or fragments. No RPC URL or Rule Engine signer key is needed by this service.

For a direct Windows run, configure the following process environment before starting:

| Variable | Value or purpose |
| --- | --- |
| `CORE_URL` | Agreed Core origin, accessible from this machine |
| `GATEWAY_URL` | Agreed Gateway origin, accessible from this machine |
| `AGENT_KEY` | The deployed agent service credential; never include it in a report or screenshot |
| `AI_PROVIDER` | `none` |
| `AUDIT_STATE_DIR` | Private writable directory outside Git for the durable journal |
| `AUDIT_REPORT_DIR` | Export directory outside Git; defaults to `AUDIT_STATE_DIR/reports` |
| `AUDIT_DEPLOYMENT_ID` | Stable identifier for this deployed chain/contract instance |
| `AUDIT_POLL_SECONDS` | 30 by default; permitted 1–300 |
| `AUDIT_MAX_ATTEMPTS` | 3 by default; permitted 1–20 per finding and generation policy |
| `AUDIT_REPORTS_PER_POLL` | 100 by default; permitted 1–1000 |
| `AUDIT_RETRY_SECONDS` | Initial retry delay, 30 by default; permitted 1–600 |
| `AUDIT_B1_MAPPING` | Optional absolute path to the agreed mapping encoding |
| `AUDIT_ALLOW_PROPOSED_MAPPING` | `false` by default; explicit development opt-in only |

Do not reuse one state directory across different deployments. The journal checks its Core/Gateway/deployment
binding and refuses a mismatch. Keep state when restarting the same deployment; a fresh state directory discards
the agent's local knowledge of earlier reports.

From the repository root, run one poll after configuring that environment:

```powershell
Push-Location .\rules
..\.venv\Scripts\python.exe -m purevoting_rules.audit_agent --once
Pop-Location
```

For a continuous process, omit `--once`. An optional `--election-id` limits the scan to one agreed election. A
one-poll run returns nonzero on a read error, immutable-finding conflict, or ABORTED report. ESCALATED reports are
valid outcomes that need review; they are not silently converted into successful diagnoses. If no qualifying
findings exist, zero generated reports is expected and is not proof that a scenario passed.

### Existing Docker integration stack

The `audit-agent` block in `docker-compose.integration.yml` builds the existing rules image, mounts the frozen
contract schemas read-only, and uses separate state/report volumes. It starts after Core and the Gateway are
healthy. On an already bootstrapped and configured team stack, run from its repository root:

```powershell
docker compose -f docker-compose.yml -f docker-compose.integration.yml up -d --build --no-deps audit-agent
docker compose -f docker-compose.yml -f docker-compose.integration.yml ps audit-agent
docker compose -f docker-compose.yml -f docker-compose.integration.yml logs --tail 30 audit-agent
```

`--no-deps` limits this command to the new report service; first confirm the existing Core and Gateway are healthy.
The normal stack bootstrap remains documented at the top of `docker-compose.integration.yml`. This report service
does not need a new chain, new keys, a new contract, or a database reset. Leave shared data volumes intact.

For an external mapping in Docker, bind-mount the approved file read-only through a local Compose override and set
`AUDIT_B1_MAPPING` to its **container** path. A host filesystem path by itself is not visible inside the container.
Copy the exported reports to a new local destination when needed:

```powershell
docker compose -f docker-compose.yml -f docker-compose.integration.yml cp audit-agent:/reports "$env:USERPROFILE\purevoting-evidence\audit-reports-01"
```

The container's healthcheck measures process liveness only. It does not certify evidence availability or an
election result. The service logs aggregate counters and sanitized error categories, not credentials or raw
response bodies. Review the report status and limitations as well as the health indicator.

## Outputs, validation and recovery

Each attempt exports `rpt_*.json` and `rpt_*.md`; its operational provenance is under `metadata/rpt_*.json`. The
metadata is separate because it is not a field of the frozen report-submission schema. Reports keep the required
evidence references, but do not copy source summaries, raw ballot bodies, private keys, or arbitrary evidence notes
into their explanations.

| Report status | Meaning |
| --- | --- |
| COMPLETED | An enabled mapping row matched, and the finding and all of its cited references resolved |
| ESCALATED | References resolved, but no enabled mapping row gives a supported cause |
| ABORTED | A required lookup, schema, scope, timeout, or step-budget check failed |

Reference lookup checks existence, schema and applicable election/checkpoint scope. It is not an independent
cryptographic re-audit. A resolvable piece of tampered evidence can be valid evidence **of** a failure; the resolver
does not erase that failure by requiring the fault itself to disappear.

Validate exported JSON files from the repository root. Pass the reports directory, not its metadata subdirectory:

```powershell
.\.venv\Scripts\python.exe rules\devtools\validate_audit_reports.py "$env:USERPROFILE\purevoting-evidence\audit-reports-01"
.\.venv\Scripts\python.exe rules\devtools\validate_audit_reports.py "$env:USERPROFILE\purevoting-evidence\audit-reports-01" --live
```

The first command checks the schema only. `--live` uses the configured agent credential and service origins to
resolve the report subject, hypothesis references, and counter-evidence. Its output keeps schema and reference
counts separate. Neither validation mode certifies an official scenario.

The durable SQLite journal is the deduplication authority because Core's current file-report fallback does not
update `has_report`. Reports are deduplicated per immutable finding and generation policy. A new accepted mapping
or explicit change of proposed-map policy can intentionally produce a new report for an existing finding. Review
metadata added by Core does not count as a new immutable finding.

The report body, provenance and retry state are committed before exports. A restart recreates missing exports
with the same IDs and bytes. It refuses a modified export or inconsistent journal instead of silently overwriting
it. One process may write a state directory at a time. Keep a stopped, consistent copy of the state and report
directories together when backing them up. The journal checksum detects corruption; it is not a cryptographic
attestation against an operator who can replace the whole directory.

Retryable transport or availability failures retain the ABORTED attempt and can produce a later attempt after
bounded exponential backoff. The default maximum is three attempts, with delay capped at 600 seconds. Invalid or
cross-election evidence does not receive an automatic retry. Each investigation has at most 20 actual HTTP
fetches, and each fetch has a 10-second wall-clock limit. No request follows redirects or an evidence-provided URL.

## Remaining joint validation and measurements

Use [README_EVALUATION.md](README_EVALUATION.md) to freeze scenario labels, export the agreed checkpoint's real
findings, and generate tables. The report service records `observed_to_report_ms`, measured from its first discovery
of a finding. Core does not currently expose its storage timestamp, so `core_storage_to_report_ms` is null. Do not
use the discovery interval to claim that a storage-to-report latency target has been measured.

Actual Gateway/PureChain runs, report references from those runs, E1 finalization/E2 refusal, and labelled evaluation
data remain necessary. Template outputs do not supply B2/LLM, token-use, or model-performance measurements. The
service adds no Core report-storage route or report UI; JSON/Markdown files are the agreed fallback deliverable.
