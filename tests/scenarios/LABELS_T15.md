# Basis of the T15 labels (written before any run, from the contract text only)

Source: contracts/README.md v1.2.5 "Audit rules" (R3 and R5 rows, exact `tally_*` key names), contracts/ballot-elgamal.md
sections 4 and 6 (ElGamal elections, the default scheme), contracts/hashing.md (`ballot_set_root`, `result_hash`),
ledger/contracts/PureVotingLedger.sol `publishTally` (`finalCheckpoint` must equal the CLOSE_FINAL checkpoint),
docs/test-plan.md (T15 row), tests/scenarios/README.md (the judge compares the set of non-zero numeric `observed` keys of
each decided finding with `observed_nonzero`, exactly). The labels were NOT derived from rules/ (Anik's code) or from
any run.

Common flow: the T01 voting flow (3 voters vote, N = 3 accepted valid ballots, all rules PASS), the election closes,
CLOSE_FINAL is committed at checkpoint F, Core runs the tally with all three organizations' honest decryption shares,
TALLY_PUBLISHED and the TALLY checkpoint follow, and the Rule Engine is judged **at the TALLY checkpoint**. The R3 count
keys are those of T01 (three voters), plus the TALLY keys below.

## Variants

| Variant | Fault | Rules | Non-zero keys beyond T01's R3 counts |
|---|---|---|---|
| T15a-results | one accepted ballot is missing from the published count and results | R3 FAIL, R5 FAIL | R3 `tally_count_mismatches` + the TALLY copies; R5 `tally_result_mismatches` |
| T15a-aggregate | Core's aggregate omits one ballot, the shares follow that aggregate | R3 FAIL, R5 FAIL | R3 `tally_count_mismatches` + the TALLY copies; R5 `tally_share_failures` |
| T15b | one candidate's published total is changed | R5 FAIL (R3 PASS) | the TALLY copies in R3; R5 `tally_result_mismatches` |
| T15c | TALLY `ballot_set_root` covers a ballot with checkpoint > final | R5 FAIL (R3 PASS) | the TALLY copies in R3; R5 `tally_root_mismatches` |
| T15d | `publishTally` with final_checkpoint = F - 1 | refused by the contract, all rules PASS | none (T01 keys only) |

"The TALLY copies" are `tally_final_checkpoint` (= F, non-zero because checkpoint 0 is the freeze), `tally_ballot_count`
and `tally_accepted_ballots`. `tally_invalid_ballots`, `tally_excluded_ballots` and `tally_rejected_ballots` are 0 in
every variant and are not listed.

## Conditions the setup (Sumin) must meet, otherwise the label does not apply

Common: exactly one TALLY_PUBLISHED at the TALLY checkpoint (otherwise R3 is INCONCLUSIVE OTHER and the R3 `tally_*`
keys are absent); `final_checkpoint` = F; `invalid_ballots` 0, `invalid_ballot_hashes` empty, `excluded_ballots` 0;
`result_hash` is recomputed by the injection over the fields it publishes (otherwise `tally_result_hash_mismatches` is
also non-zero); the chain-side checks (R1, R2, R4, the other R5 keys) are untouched; the tampering is made after the
checkpoint that commits the last ballot and does not change a view row that a committed checkpoint covers
(`tables_mismatched` stays 0).

- **T15a-results:** published `ballot_count` = N - 1 and the results total N - 1 votes (the omitted ballot's candidate
  has one vote fewer); `ballot_set_root` is the honest one over all N accepted ballots; the shares are the honest ones
  over the full aggregate of N ballots.
- **T15a-aggregate:** Core's aggregate and the three shares are those of N - 1 ballots (so each share fails against the
  aggregate the Rule Engine recomputes over all N); the published `ballot_count` is N - 1 and the results are the
  decryption of that smaller aggregate; `ballot_set_root` is the honest one over all N ballots. R5 then skips the result
  check (`tally_result_mismatches` is null).
- **T15b:** `ballot_count` = N, one candidate's published votes changed (+1, -1, or a vote moved to another candidate; the
  key set is the same), everything else consistent; the shares are honest.
- **T15c:** only `ballot_set_root` differs (it covers one extra ballot_hash with checkpoint > F); `ballot_count`, results
  and shares are honest and consistent with the N accepted ballots. If the injection also changes the counts or the
  results, this label does not apply.
- **T15d:** the publishTally call carries `final_checkpoint` = F - 1 and is refused: the contract reverts
  InvalidFinalCheckpoint, the Gateway answers REJECTED INVALID_STATE_TRANSITION (revert name in the detail). The election
  stays CLOSED, no TALLY_PUBLISHED exists and no TALLY checkpoint is committed. The rules are judged at the last committed
  checkpoint (F), so R3 has no `tally_*` keys.

## Reasoning per variant

- **T15a-results:** R3 FAILs on "TALLY.ballot_count + invalid_ballots != accepted BALLOT_RECEIVED <= final_checkpoint":
  (N - 1) + 0 != N, so `tally_count_mismatches` is 1 (list entry "tally_counts"). `final_checkpoint` equals F and
  `excluded_ballots` equals the rejected ballots (0), so only that one of the three checks fails. R5: the decrypted sums
  (honest shares over all N ballots) give one more vote than the published results for one candidate:
  `tally_result_mismatches` > 0. The ballot set is complete, so `tally_root_mismatches` and
  `tally_invalid_set_mismatches` are 0, and the shares verify, so `tally_share_failures` is 0.
- **T15a-aggregate:** R3 as above. R5 recomputes the aggregate over all N valid ballots; every organization's share was
  made for another aggregate, so each fails: `tally_share_failures` > 0; the contract text then skips step 4, so
  `tally_result_mismatches` is null, not 0. The test plan row names the same two keys for (a).
- **T15b:** the counts are consistent (ballot_count + invalid_ballots = accepted), so R3 passes, but the three TALLY
  copies are non-zero. R5: the votes decrypted from the honest shares differ from the published ones for the changed
  candidate(s): `tally_result_mismatches` > 0 only (the contract text counts candidates, so one or two, the key set is the
  same).
- **T15c:** R5 recomputes `ballot_set_root` from the accepted BALLOT_RECEIVED with checkpoint <= final and finds a
  different value: `tally_root_mismatches`. The other tally keys are 0 under the stated conditions. The test plan row
  names only R5 for (c).
- **T15d:** the contract text accepts `publishTally` only with the CLOSE_FINAL checkpoint, so nothing reaches the
  ledger and no rule can FAIL on a tally. The refusal is a rejected system event, not a voter event, so R3 is unchanged.

## Cause
T15a-results, T15a-aggregate, T15b, T15c: DATA_TAMPERING, from the injection (the published tally or Core's aggregate is
changed after the fact), as decided for the B1 table (decision 3 of docs/test-plan.md). T15d: no fault is accepted,
`cause_code` null. B1 reaches DATA_TAMPERING for (a) through `tally_count_mismatches` and for (b) to (c) through the R5
tally keys, so it is correct on these variants if the conditions hold.

## Not labelled
- T15d injected (a TALLY_PUBLISHED with final_checkpoint != CLOSE_FINAL that reaches the ledger): the contract refuses it
  while `publishTally` requires the CLOSE_FINAL checkpoint, so such an event cannot exist on this contract.
- T15 with the sealed-box scheme (SEALED_BOX_V1): not in the mandatory runs, the default is ElGamal.

## Open points the setup decides (the label is correct only under the conditions above)
- T15c: the test-plan row says only R5 FAILs; whether the injection can change `ballot_set_root` without touching the
  counts is a question for the setup.
- T15a-aggregate: the honest trustee tool refuses a short ballot list, so the shares of N - 1 ballots need an
  injection after the trustees decrypted, or direct database values.
