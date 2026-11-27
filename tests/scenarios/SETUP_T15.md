# T15 setup (Seungmin)

Each variant folder (`T15a-results`, `T15a-aggregate`, `T15b`, `T15c`, `T15d`) has `expected.json` (Harits, basis in
`LABELS_T15.md`) and a `setup.py` that runs the T01 flow (`T01/setup.py`) and then `tally_tamper.py`:

1. wait until the window has ended and the CLOSE_FINAL checkpoint F is settled (`GET .../tally-input` answers 200);
2. check that Core's aggregate is the sum of the N listed ballots (every proof verifies), then send the three
   organizations' honest decryption shares;
3. run the tally (admin) two seconds into a time bucket, and at once change the `TALLY_PUBLISHED` row in
   `credential.outbox` while it is still PENDING (Core releases a system event when its bucket has ended);
4. wait for the Gateway's outcome; the judged checkpoint is the TALLY checkpoint (`credential.checkpoints`, reason
   `TALLY`), or F for T15d.

| Variant | Change in the TALLY_PUBLISHED payload |
|---|---|
| T15a-results | `ballot_count` = N - 1; one vote fewer for the first candidate that has one; `ballot_set_root` and the shares honest |
| T15a-aggregate | the first ballot (by `ballot_hash`) left out of the aggregate: the three organizations' shares over the aggregate of N - 1 ballots replace the stored ones (same transaction), the results are their decryption, `ballot_count` = N - 1; `ballot_set_root` honest |
| T15b | one vote moved from the first candidate that has one to the next; `ballot_count` = N |
| T15c | `ballot_set_root` over the N accepted `ballot_hash` values plus one extra random 32-byte value; nothing else |
| T15d | `final_checkpoint` = F - 1; the contract must refuse `publishTally` |

Every change recomputes `result_hash` = Hc(result) and `payload_hash` = Hc(payload), otherwise the Gateway refuses the
event with VALIDATION_ERROR before the contract sees it. The outbox row and (T15a-aggregate) the three share rows are
changed in one statement, and the shares only if the outbox row was still PENDING.

The script stops with NOT COMPLETED when a condition of `LABELS_T15.md` does not hold:

- the honest payload is not N ballots / F / 0 invalid with the honest root;
- fewer than 10 s are left before the event's release (Core reads a PENDING row without a lock and marks it only when
  the Gateway answers, so a row being delivered still looks PENDING), or the event left before the change;
- T15a to c: the Gateway's outcome is not ACCEPTED / DUPLICATE (DUPLICATE: stored on an earlier RETRY_LATER, Core
  treats it as ACCEPTED), the ledger's `TALLY_PUBLISHED` (Gateway `GET /v1/events`) is not the changed payload, or the
  TALLY checkpoint is not committed;
- T15d: the outcome is not REJECTED `INVALID_STATE_TRANSITION`, or a TALLY checkpoint exists. The Gateway's rejection
  detail (revert name) is recorded.

Known: after T15d, Core keeps the election TALLIED with one TRANSITION_REJECTED alert (`core/app/tally.py`, strict
CLOSED → TALLIED; `outbox.py` STRICT_KEPT); on chain it stays CLOSED and no TALLY checkpoint exists. The variant
declares that one alert as expected, so the T01 judge accepts exactly one (any other number is a problem).

## Run

As T05 / T08 (`SETUP_T05_T08.md`), plus `T15_TRUSTEE_DIR`: the folder with every organization's
`<org_id>.secret.json` (`tools/trustees.sh`), and `T15_GATEWAY_URL` / `T15_AUDITOR_KEY` (the Gateway's host address
and its read-only `AUDITOR_KEY`) for the ledger checks. The secrets and the key are read, never printed or recorded.

```sh
export COMPOSE="docker compose -f docker-compose.yml -f docker-compose.integration.yml"
export T15_TRUSTEE_DIR=/path/to/trustee-keys
export T15_GATEWAY_URL=http://127.0.0.1:8100 T15_AUDITOR_KEY=...
T01_USERNAME=admin1 T01_PASSWORD=... python tests/scenarios/T15b/setup.py --config demo --seed 1
```

The run takes the whole window plus the tally (about two buckets) and the findings at the TALLY checkpoint.
