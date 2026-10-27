# Local rules simulation

This initial implementation runs synthetic evidence through local rules and a mocked finding publication path. It supplies a reusable starting point for the Rule Engine. It does not run a production worker or connect to a real chain.

## Quick start from the repository root

Use a Python 3.11 virtual environment, then:

```bash
python -m pip install -r rules/requirements-lock.txt
python rules/run_simulation.py
python -m pytest -c rules/pytest.ini rules/tests -q
```

For another output location or different deterministic fixture seeds:

```bash
python rules/run_simulation.py --output ./simulation_runs --seeds 7 11
```

Fixture input data is deterministic for a seed. Each execution creates fresh finding IDs, timestamps, and an ephemeral signing key, so finding hashes and signatures can differ across independent runs. A persisted finding body is immutable within its publication lifecycle and is retried unchanged.

The launcher works both in this standalone handoff (`reference/contracts/`) and within the original repository (`contracts/`). An explicit reference root can be set with `PUREVOTING_REFERENCE_ROOT`; that directory must contain both `contracts/` and `tests/vectors/hash-vectors.json`.

## Code map

| File | Responsibility |
| --- | --- |
| `run_simulation.py` | One command for vector checks, all local cases, publication, and reports |
| `purevoting_rules/hashing.py` | Independent frozen hash formulas and canonicalization |
| `purevoting_rules/signing.py` | Ephemeral EIP-191 signer and signature verification |
| `purevoting_rules/vector_check.py` | Compare independent calculations with all shared vectors |
| `purevoting_rules/engine.py` | R1-R5 evaluators over explicit local evidence |
| `purevoting_rules/fixtures.py` | Synthetic developer cases with declared expectations |
| `purevoting_rules/findings.py` | FindingSubmission builder and frozen-schema validation |
| `purevoting_rules/storage.py` | Exact-body SQLite queue and publication state |
| `purevoting_rules/publication.py` | In-process HTTP Gateway/Core mocks and publication exercise |
| `purevoting_rules/scheduler.py` | Pure readiness and anchor-timeout decisions |
| `purevoting_rules/reporting.py` | HTML, JSON, CSV, and SVG development reports |
| `tests/` | Unit, boundary, and mock integration tests |

## Input boundary and rule scope

The evaluator consumes a local snapshot containing `election_id`, the selected `checkpoint`, `checkpoint_event_id`, `ledger_last_seq`, `views`, cumulative accepted `events`, cumulative `rejections`, historical snapshots, and declared mock node availability. Rows and events in the supplied fixtures are checked against the frozen contract definitions in the tests.

The adapter that will obtain real evidence is still required. It must read all pages, enforce the requested election and checkpoint, detect retrieval failures, validate payloads, and supply complete accepted/rejected evidence. A list alone cannot prove that a remote server supplied every record. The simulation assumes the fixture provider is explicit about availability; it does not establish remote completeness. Guards prevent PASS when relevant row fields refer to future checkpoints or when known historical checkpoint evidence is visibly missing from the event stream.

R1-R3 are local implementations of the frozen rule predicates on the supplied evidence. This is not a claim that the live service or formal evaluation is complete. R4/R5 include only selected checks. Their `coverage` and `unimplemented_checks` fields are development report metadata; they are not added to the frozen FindingSubmission schema. Each partial rule returns FAIL when an implemented check establishes a violation, or INCONCLUSIVE with an explanation. A partial rule cannot return PASS.

R4 still needs signature/quorum validation from node-read organization keys, exact effect replay, historical row-change checks, and independent governance comparisons. R5 still needs direct pinned-node anchor/proof verification, full state/governance replay, all roster/token/config commitment checks, key derivation, decryption, and independent tally reproduction. See the enumerated pending checks in each generated result.

The scheduler demonstrates the `2 * batch_interval + 60` second anchor deadline. At the default 60-second interval this is 180 seconds. It is not a polling loop, network client, or persisted alert service.

## Publication scope

The SQLite queue stores the exact canonical finding body before publication. The local outbox supports one active writer. It works in private SQLite memory and saves a complete SQLite file with an atomic replacement after each committed change, before the operation returns. This keeps each closed outbox independently readable without SQLite journal or shared-memory sidecars. The prototype rewrites a full snapshot for durability and portability; its storage performance has not been evaluated for production workloads.

The mock path checks the body hash and an EIP-191 signature, registers the record with the mocked Gateway, then submits the body to the mocked Core. Simulated HTTP 503 failures leave the persisted record pending for an unchanged retry. The mock Gateway derives accepted checkpoint fixtures from the initial queued input unless explicit committed checkpoints are supplied.

These checks exercise the local protocol boundaries. They do not establish on-chain authorization, independent node truth, a deployed service's behavior, or recovery from a real network/chain failure. The simulated remote backend exists only in memory. Queue persistence is tested separately from that simulated server state. Direct chain fallback is not implemented.

The test signer is generated in memory. The launcher never writes a private key, uses a real election key, or calls an AI provider. Saved finding files contain synthetic evidence references for inspection; console and publication logs omit voter hashes and raw evidence content.

## Reading the output

- `report.html`: human-readable outcomes, explanations, partial-coverage notes, and scheduling examples.
- `results.json`: full machine-readable run results, provenance, environment, expected developer outcomes, and actual outcomes.
- `rule_outcomes.csv`: one row per rule evaluation, suitable for checking decisions without reading the whole report.
- `progress.svg`: exact summary values from that run for progress reporting.
- `seed_*/<case>/findings.json`: frozen-schema finding submissions.
- `seed_*/<case>/findings.sqlite3`: durable local finding queue.
- `seed_*/<case>/publication.json`: sanitized local mock publication trace and retry evidence.

The fixtures do not use official T01-T16 identifiers. A matched expectation is a development assertion, not an independently measured detection rate, false-positive rate, or research result.

## Optional Docker recipe

The Dockerfile is supplied for review but has not been executed in this environment. Build from `rules/`, then mount a reference root and a writable output directory. The reference root must contain `contracts/` and `tests/vectors/`.

Example from the standalone package root on a POSIX shell:

```bash
docker build -t purevoting-rules-simulation ./rules
mkdir -p docker_output
docker run --rm -v "$PWD/reference:/reference:ro" -v "$PWD/docker_output:/output" purevoting-rules-simulation
```

In the full repository, mount the repository root as `/reference:ro` instead. This container runs the finite simulation and exits; it is not the production Compose Rule Engine service.

## Storage verification note

The initial hosted working directory intermittently showed older SQLite contents after a writer process had exited, including after complete-file atomic saves. The exact cause remains unresolved. The same implementation passed the full 140-test suite and the 57-case persistence checks in a clean local Linux directory. The packaged sample was generated and independently reopened there.

Run the included cross-process persistence test on the team's target filesystem before integration. This handoff is a local simulation milestone; it does not certify persistence in the original execution directory or a deployed service. Do not reuse any failed trial databases. The release contains only the separately verified sample files.

