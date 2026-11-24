# Collecting integration measurements and evaluating rule results

These tools prepare the remaining joint tests and evaluation tables. They **do not run or certify an election scenario**.
The collector only reads existing Core and Gateway responses. It does not create elections, edit a database, inject
faults, publish a tally, submit findings, review findings, or call finalization.

Use the agreed integration deployment with Harits and Seungmin. Run each labelled scenario using its owner's setup
instructions and a separate test election. In particular, do not run DB-edit scenarios against a shared election.
Keep the actual setup/receipt/finalization evidence with the integration record. T01 does not tally; E1 additionally
needs all R1–R5 PASS at TALLY and successful finalization. E2 additionally needs the expected finalization refusal.
The exporter deliberately leaves those end-to-end claims `NOT_VERIFIED`.

## Before a judged run

Agree on the scenario variant, seed, configuration, exact deployed revision and checkpoint to judge. Record the
run's UTC start time. Freeze Harits's committed `tests/scenarios/<variant>/expected.json` **before** starting the run.
Do not change that label after observing results. A label in an open pull request is not automatically an accepted
baseline; resolve its review with the owner before reporting a confirmatory experiment.

The existing checked-in labels cover T05 and T08 variants. Missing T01/T02/T04/T15 labels are reported as unavailable,
not recreated by this tool. Fetch an agreed label commit before using its full 40-character ID. The `--label-commit`
argument reads Git's immutable file bytes, ignoring any edited working-tree copy. It stores the original UTF-8 bytes,
SHA-256, path, source commit and commit time. A source commit after the stated run start is not accepted for metrics.

Commit the collector and evaluation implementation before the judged runs, and keep that tooling fixed throughout
the cohort. `collector_commit` records the checked-out Git HEAD; it does not attest uncommitted source bytes or
prove which code was deployed. Use the committed checkout and preserve the declared deployment revision and
configuration with the integration record. Do not alter the tooling between seeds to improve observed outcomes.

Use the project virtual environment with `rules/requirements-lock.txt` installed. Provide `AGENT_KEY`, `CORE_URL`
and `GATEWAY_URL` in the process environment through the agreed local configuration. Keys are never command-line
arguments, displayed by the tools, or written into the measurement files. URLs must be HTTP(S) origins, without
embedded credentials, paths, queries or fragments. Redirects are not followed. The collector never follows an RPC
URL advertised by the Gateway.

## Export an existing checkpoint

From the repository root, after the agreed scenario has run, fill the variables below with the actual non-secret
run identifiers. `RUN_STARTED_AT` must describe the original run start, not the time the collector is launched.
For an exploratory mock, use `mock`; for a local development stand-in use `local-development`. `real-declared`
records the operator's description of the environment and does not independently prove it.

PowerShell command (the named variables must already hold the real values):

```powershell
.\.venv\Scripts\python.exe rules\devtools\collect_rule_evidence.py --election-id $electionId --checkpoint $checkpoint --run-id $runId --scenario $scenario --seed $seed --configuration demo --started-at $runStartedAt --source-mode real-declared --deployment-commit $deploymentCommit --label-commit $labelCommit --output $evidencePath
```

For example, a meaningful run ID is `T08b-seed1-20261127`; it does not contain a credential or voter identifier.
The output file must be new. Existing evidence files are preserved. Exit code `0` means the requested responses were
collected; it does not mean the rules passed. Exit code `2` can still accompany a saved **incomplete** bundle when a
service read failed. The completion flag and sanitized error codes record that condition.

The collector reads the election/checkpoint metadata, finding bodies and Gateway finding records. In memory, it
validates the frozen stored-finding and ledger-event schemas and checks the election, rule, result, checkpoint,
checkpoint-event ID, recorded-event ID, payload hash and `Hc(FindingSubmission)` binding. It requires the Gateway's
record to be reported ANCHORED. The file retains only decision metadata, approved numeric counters, a body hash,
an evidence-reference count and an explicit MATCHED/unmatched binding result. It does not retain raw evidence
references, voter event IDs, receipt/token/nullifier values, keys, signatures, descriptions or RPC URLs.

`MATCHED` means the two HTTP services returned consistent finding data. It is **not** an independent signature,
node, confirmation-depth or deployment check. Those remain the Rule Engine's task and the joint test's evidence.
The reduced export is an ordinary measurement record, not a cryptographic attestation of the experiment.

## Optional frozen B1 cause mapping

Rule-result measurements work without a cause mapping. For confirmatory cause measurements, first obtain the
owner-approved mapping and its review reference. Keep its JSON inside this repository and commit that exact
encoding **before the run**, as well as the source table it identifies. After the run, add these two arguments to
the collector command:

```powershell
--b1-mapping $approvedMappingPath --b1-mapping-commit $mappingEncodingCommit
```

Both values must identify the actual agreed baseline. The tool requires `status: approved`, matching approval/source
commit metadata, a locally available source table, and a byte-for-byte match between the supplied JSON and
the repository-relative blob in `--b1-mapping-commit`, allowing only LF/CRLF checkout line-ending conversion.
Other whitespace edits, string changes and mapping changes remain rejected. The original committed bytes and
their SHA-256 remain the authoritative evidence, including when a Windows checkout uses CRLF.
Both Git commit times must precede the stated run start.
It saves the mapping manifest, its canonical SHA-256, exact encoding SHA-256, source/encoding commits and dates,
and the declared review reference. Proposed, stale, unavailable, unpinned, locally edited or post-run mappings
leave cause metrics `NOT_EVALUATED`; they do not erase otherwise valid rule-result measurements.

The supplied approval reference and run start time are declarations. A local Git timestamp does not independently
prove when an experiment occurred or whether a maintainer approved the table. The exact JSON and the source table
must be reviewed together by the owner. The bundled `b1-cause-map.pr10.json` is **proposed** and must not be relabelled
approved just to enable a metric.

Cause selection runs against the full finding in memory before sensitive arrays are discarded. Each reduced finding
keeps only the selected cause, table-row index and mapping hash. The evaluator takes the first matching row across
the selected R1–R5 findings (the smallest row index, with rule order breaking ties). PASS and unmatched findings have
no cause. For example, under PR #10's proposed ordering, T05's R4 `roster_chain_breaks` selects
`UNAUTHORIZED_ADMIN_ACTION` before R5's `DATA_TAMPERING`. Against T05's `DATA_TAMPERING` label this is an error;
the evaluator does not change the mapping or label to improve the score.

## Generate the tables

Pass the saved files explicitly; shell wildcard expansion differs between Windows and Linux. Use a new output
directory for each evaluation, preserving earlier results:

```powershell
.\.venv\Scripts\python.exe rules\devtools\evaluate_rule_runs.py $firstEvidencePath $secondEvidencePath --output-dir $newResultsDirectory
```

The evaluator writes:

- `evaluation.json`: run provenance, per-rule decisions, label-counter checks, partial counts, metrics and coverage;
- `rule_results.csv`: one row per run and rule, suitable for tables;
- `README.md`: run summary and interpretation limits.

It rejects duplicate run IDs and repeated exports of the same election/checkpoint/scenario/seed/revision. A later
export is not an independent experiment. Runs are grouped separately by source mode, configuration and deployment
revision; mock results are never pooled with operator-declared real results.
Within each such group and scenario variant, complete runs must use one unchanged label content hash, and the
label's source commit must precede the **earliest scenario attempt**, including incomplete attempts. Incompatible
label revisions or a label committed between seeds reject the combined evaluation instead of improving its score.

## How missing and repeated findings are handled

Missing findings, unmatched body hashes, malformed summaries, incomplete collection, missing labels and labels
committed after the run produce an `INCOMPLETE` measurement with null metrics. Missing findings are
`NOT_EVALUATED`; they are never filled with PASS. Incomplete runs remain visible in run counts and coverage, but are
excluded from pooled metrics. Report those exclusions and their causes alongside any performance claim.

For multiple findings of one rule at the same fixed checkpoint, the first FAIL is preserved: a later PASS does not
erase it. Repeated same-result findings use the latest timestamp, breaking ties by finding ID. A mixture of PASS and
INCONCLUSIVE is ambiguous unless the Gateway reports every INCONCLUSIVE as SUPERSEDED. If any candidate has an
invalid binding, that rule stays unmeasured rather than choosing a better-looking valid candidate.

The label's `observed_nonzero` keys are checked as an **exact set**, separately from result equality, matching the
scenario owner's judge. Missing and unexpected numeric nonzero keys both cause a mismatch. The owner's numeric
truthiness includes negative numbers and true boolean values; the tool preserves that comparison rather than
reinterpreting it. An unexported numeric nonzero field is counted without exposing its name or value and also
causes a mismatch. A matching FAIL with a missing or additional deciding counter does not satisfy the observation
label. `matches_label` means rule results plus these observation sets; cause accuracy and actual refusal outcomes
are reported separately.

## Metric definitions and remaining measurements

FAIL detection is a binary comparison separate from exact PASS/FAIL/INCONCLUSIVE agreement. Against expected PASS
or FAIL, an actual INCONCLUSIVE means no detected FAIL; it remains INCONCLUSIVE in the table, and an expected FAIL
therefore counts as a missed detection. This never asserts that INCONCLUSIVE is PASS. Expected INCONCLUSIVE labels
are included in exact-result accuracy and excluded from binary FAIL denominators.

Precision is `TP / (TP + FP)`, recall is `TP / (TP + FN)`, and the false-positive rate is `FP / (FP + TN)`.
Zero denominators are null. The output also records exact-result accuracy and the INCONCLUSIVE fraction.
Per-run and per-seed min/median/max use only complete collected measurements. Inspect scenario/seed coverage before
comparing them: missing mandatory families and missing seeds 1–3 for supplied variants are listed explicitly. This
does not prove every required variant was included, so protocol-completion verification remains false.

Root-cause accuracy remains `NOT_EVALUATED_NO_FROZEN_ACCEPTED_MAPPING` until the B1 mapping meets the checks above.
With that mapping, `root_cause_accuracy` explicitly means correct primary causes divided by runs whose frozen
label specifies a non-null injected-fault cause. An unmatched/no-cause prediction counts as wrong for such a run.
The separate `primary_cause_agreement` also includes null/no-fault labels; it is not silently substituted for fault
accuracy. This denominator choice is stated because the test plan does not specify how normal null-label cases
should enter a combined cause score. The output includes both denominators, missing-prediction counts and seed
summaries. Different mapping hashes are kept in separate cause groups.

Evidence validity is measured separately by the audit-report reference validator. A template report is not B2;
no AI accuracy, token or model-performance numbers are generated here. The actual scenario runs, deployment
evidence, refusal outcomes and accepted cause mapping must be supplied before the final evaluation can be
claimed complete.
