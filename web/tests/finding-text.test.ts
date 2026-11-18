// observedKo: the FAIL row lists only the non-zero deciding keys (values as stored by the T05-db-add / T08a runs)
import assert from "node:assert/strict";
import test from "node:test";
import { observedKo } from "../src/admin/findingText.ts";

const f = (rule_id: "R3" | "R4" | "R5", observed: Record<string, unknown>) =>
  ({ finding_id: "x", rule_id, result: "FAIL" as const, checkpoint: 4, summary: "", observed });

test("T05-db-add: R4 roster_chain_breaks, informational counts left out", () => {
  const out = observedKo(f("R4", { roster_chain_breaks: 9, executed_actions: 0, failed_actions: 2, unapproved_changes: 0 }));
  assert.deepEqual(out.map((o) => [o.key, o.count]), [["roster_chain_breaks", 9]]);
});

test("T08a: R5 row and table mismatches; unanchored counts and id lists left out", () => {
  const out = observedKo(f("R5", { tables_mismatched: 2, row_ledger_mismatches: 1, events_unanchored: 3,
    chain_anchor_ids_missing_from_gateway: ["a"], root_mismatches: null, key_mismatch: false }));
  assert.deepEqual(out.map((o) => o.key).sort(), ["row_ledger_mismatches", "tables_mismatched"]);
});

test("R3: each failed count check is one line; tally_count_mismatches not repeated next to tally_counts", () => {
  const out = observedKo(f("R3", { ballots_received: 3, roster_active: 20,
    count_relationship_violations: ["ledger_ballot_outcomes", "tally_counts"], tally_count_mismatches: 1 }));
  assert.deepEqual(out.map((o) => o.key), ["ledger_ballot_outcomes", "tally_counts"]);
});

test("R3: plain rejection count and the checkpoint mismatch count never add a line of their own", () => {
  const out = observedKo(f("R3", { ledger_rejected_voter_events: 1, checkpoint_voter_event_mismatches: 2,
    count_relationship_violations: ["checkpoint_voter_events"] }));
  assert.deepEqual(out.map((o) => o.key), ["checkpoint_voter_events"]);
});

test("lists count their entries; unknown keys are ignored", () => {
  const out = observedKo(f("R5", { tally_share_failures: ["org_observer"], something_new: 5 }));
  assert.deepEqual(out.map((o) => [o.key, o.count]), [["tally_share_failures", 1]]);
});
