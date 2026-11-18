# Basis of the T02 and T04 labels (written before any run, from the contract text only)

Source: contracts/README.md "Audit rules" (R1 to R5 and their `observed` keys), core/app/views.py (`rejected_attempts`
is a view snapshotted at every checkpoint), docs/test-plan.md (T02, T04), tests/scenarios/README.md and T01/README.md
(the judge compares the set of non-zero numeric `observed` keys of each decided finding with `observed_nonzero`,
exactly, at the judged checkpoint C = the checkpoint that commits the last ballot).
The labels were NOT derived from rules/ (Anik's code) or from any run. Every variant runs the T01 voting flow
(3 voters vote), so the R3 count keys are the same as in T01.

## Variants

| Variant | Fault | Rules | Non-zero keys beyond T01's R3 counts |
|---|---|---|---|
| T02 | the same link redeemed a second time | all PASS | R1 `refused_duplicates` |
| T04-core | redeem / ballot before start (and after end) refused by Core | all PASS | R2 `refused_not_open` |
| T04-lastbucket | a ballot in the last bucket is accepted | all PASS | none (same as T01) |
| T04-injected | a voter event outside the window written into the outbox, bypassing Core | R2 FAIL, R3 FAIL, R1/R4/R5 PASS | R2 `ledger_rejected_window`; R3 `ledger_rejected_voter_events` |

## Conditions the setup (Sumin) must meet, otherwise the label does not apply

- **T02:** the first redeem of the link succeeds (200); the second redeem of the same link happens **inside the voting
  window** and is answered 409 TOKEN_ALREADY_USED. (Core checks the window first, voting.py:26: a second redeem outside
  the window is refused for the window, not as a duplicate, and `refused_duplicates` stays 0.) The attempt is recorded in
  `rejected_attempts` and happens before the judged checkpoint C is committed (otherwise its row has a checkpoint > C and
  `refused_duplicates` is 0 at C). Nothing else is refused in this variant.
- **T04-core:** at least one refused attempt happens **before window_start**, and it must be a **redeem** (409
  ELECTION_NOT_OPEN at Core). A ballot before the start gets CREDENTIAL_UNKNOWN 403, because Core's credential check
  (voting.py:70) runs before the window check (voting.py:71), so it never reaches the window rule. A redeem before the
  start is recorded at Core's open checkpoint (1 after the freeze; 0 only before the freeze), so its checkpoint is <= C
  and it is counted at every C. An attempt after the end may be added, but only as a **redeem with an unused link**: its
  checkpoint is then greater than C, so it does not change the label. (A ballot after the end can leave
  `redeemed_not_voted` behind, and a link that was already used gets CREDENTIAL_ALREADY_USED, not the window refusal.)
  The label rests on the before-start redeem. No other refusal (no duplicate link use) happens in this variant, and no
  event reaches the Gateway outside the window.
- **T04-lastbucket:** one voter's ballot has `occurred_at` in the last bucket of the window
  (`occurred_at + time_bucket_seconds = effective_end` exactly) and is accepted (201). No refusal in this variant.
- **T04-injected:** exactly one voter event (TOKEN_USED or BALLOT_RECEIVED) is written into the Core outbox with
  `time_precision: "bucketed"` and an `occurred_at` that is a multiple of `time_bucket_seconds`, outside the window
  (before `window_start` or at or after `effective_end`; otherwise the Gateway rejects it with VALIDATION_ERROR and R2
  never sees it, gw_engine.py:614-617), a valid `payload_hash`, a key field, and **a checkpoint number <= C and <= the CLOSE_FINAL checkpoint**; the Gateway rejects
  it ELECTION_NOT_OPEN before the rules run at C; no view row is created for it; Core has refused nothing else in this
  variant. If its checkpoint is greater than CLOSE_FINAL, `events_after_close_final` is also non-zero and this label
  does not apply.

## Reasoning per variant

- **T02:** the refusal is made by Core (409), so nothing reaches the Gateway: no accepted duplicate (R1 keys
  `accepted_duplicate_tokens` stay 0), no Gateway rejection (R3 `ledger_rejected_voter_events` stays 0). The contract
  lists refused duplicates as "not a FAIL, reported in `observed`": R1 PASS with `refused_duplicates` non-zero.
  The refused attempt changes no view count, so R3 equals T01.
- **T04-core:** "refused ELECTION_NOT_OPEN attempts at Core (`rejected_attempts`)" is "not a FAIL, reported in
  `observed`" under R2: R2 PASS with `refused_not_open`. Core refused before any event, so R3 equals T01.
- **T04-lastbucket:** R2 FAILs only when `occurred_at + time_bucket_seconds > effective_end`; equality is allowed, so
  an event in the last bucket passes and no key is non-zero. Same label values as T01; it is a separate folder
  because the setup differs.
- **T04-injected:** R2 FAILs on "a Gateway rejection of a voter-side event with reject_code ELECTION_NOT_OPEN (Core
  accepted a request outside the window)": `ledger_rejected_window`. R3 FAILs on "for each voter event type: accepted
  ledger events + Gateway rejections with checkpoint <= k != cumulative view count": the rejection has no view row, so
  the type's sum is one above its view count, and `ledger_rejected_voter_events` is non-zero. The event is rejected, not
  accepted, so R1 (accepted events only) and the row matching of R5 are unchanged. R4 does not look at voter events.
  The rejection is recorded in the rejections root, which R5 compares with the chain: PASS when it is anchored (an
  unanchored root would be INCONCLUSIVE BATCH_NOT_ANCHORED and waits for the Rule Engine's re-run).

## Cause
- T02, T04-core, T04-lastbucket: no fault is accepted, `cause_code` null, as for T01.
- T04-injected: DATA_TAMPERING, from the injection (a voter event written directly into the outbox, bypassing Core's
  window check). This is a judgment call: it follows the same reasoning as T05-db-add (a direct write to stored data).
  A rules-only reading (B1 table: R2 `ledger_rejected_window` -> PROCESSING_BUG, "the voter event passed Core's window
  check") names another cause; that is a legitimate B1 error and stays.

## Not labelled yet
- **T15 (a to d).** Labelled in a separate PR, with the exact key names fixed in contracts/README.md (v1.2.5).
- T03 (concurrent duplicates), not in the mandatory list.

## Known gaps in the current rule engine (B1 will miss these; the labels do not change)
Not checked against rules/ for this document: the labels come from the contract text only.
