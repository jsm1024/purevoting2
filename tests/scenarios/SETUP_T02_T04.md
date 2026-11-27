# T02 and T04 setup (Seungmin)

Each variant folder (`T02`, `T04-core`, `T04-lastbucket`, `T04-injected`) has `expected.json` (Harits, basis in
`LABELS_T02_T04.md`) and a `setup.py` that runs the T01 flow (`T01/setup.py`: election, roster, freeze, links, ballots,
receipts ANCHORED, the ballots' checkpoint committed) and adds one step from `tamper.py`.

| Variant | Step | When | Judged checkpoint |
|---|---|---|---|
| T02 | the second redeem of a link that already voted; must be 409 `TOKEN_ALREADY_USED` (else FAIL) | after the last ballot, inside the window, before the judged checkpoint is read | as T01 (its `rejected_attempts` row has checkpoint <= C) |
| T04-core | one redeem before `window_start`; must be 409 `ELECTION_NOT_OPEN` (else FAIL) | links issued, window not open yet | as T01 (the row is at Core's open checkpoint, <= C) |
| T04-lastbucket | the last voter redeems and votes in the window's last bucket (`occurred_at + time_bucket_seconds = effective_end`); the script checks that exactly one `BALLOT_RECEIVED` has that bucket | two seconds into the last bucket | as T01 (the checkpoint that commits that ballot) |
| T04-injected | one `TOKEN_USED` written into `credential.outbox`: bucketed `occurred_at` one bucket before `window_start`, `payload_hash` = Hc(payload), a random `token_hash`, checkpoint = Core's open checkpoint read in the same statement | after the ballots' checkpoint is committed | that checkpoint |

These are the conditions of `LABELS_T02_T04.md`. The script stops with NOT COMPLETED when one does not hold:

- T02: the window ended before the second redeem;
- T04-core: the redeem ran past `window_start`;
- T04-lastbucket: the earlier ballots ran into the last bucket, the last ballot finished after `window_end`, or the
  outbox does not hold exactly one `BALLOT_RECEIVED` in the last bucket;
- T04-injected: the injected event's checkpoint is already committed, or the Gateway's outcome is not `REJECTED
  ELECTION_NOT_OPEN` within 120 s (Core delivers it as its own release unit, since its bucket is the oldest pending).

Core leaves a rejected `TOKEN_USED` alone (no alert, `core/app/outbox.py` `apply_outcome`), so the only trace is the
Gateway rejection that R2 and R3 count. The run record's `injection` holds checkpoint numbers and the Gateway outcome
only; no token, credential or receipt is printed or recorded.

## Run

As T05 / T08 (`SETUP_T05_T08.md`): same stack, same staff account, `COMPOSE` set for the database steps (T04-lastbucket
and T04-injected), one fresh election per run.

```sh
export COMPOSE="docker compose -f docker-compose.yml -f docker-compose.integration.yml"
T01_USERNAME=admin1 T01_PASSWORD=... python tests/scenarios/T02/setup.py --config demo --seed 1
```

Window length: T04-injected needs the judged checkpoint before `window_end` (at least four buckets); T04-lastbucket
waits for the last bucket, so it takes the whole window. Every T01 option applies (`--bucket`, `--buckets`,
`--voters`, `--lead`); changing a preset value records the configuration as `custom`.
