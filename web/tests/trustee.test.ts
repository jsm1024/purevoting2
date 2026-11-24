// The browser trustee (src/crypto/trusteeCheck.ts) against the shared ElGamal vectors: the same keys, ballots, sums and
// share bytes as core/app/elgamal.py, and the same refusals as core/app/scripts/trustee.py check().
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { aggregate, decryptionShare, jointKey, ready, toHex, verifyBallot, verifyTrusteeKey, type TrusteeRecord } from "../src/crypto/elgamal.ts";
import { H, hexToBytes } from "../src/crypto/hashing.ts";
import { Refused, checkTallyInput, checkWithFile, readTrusteeFile, remember, type LedgerView, type Memory, type TallyInput } from "../src/crypto/trusteeCheck.ts";

type Trustee = { org_id: string; secret: string; record: TrusteeRecord };
const doc = JSON.parse(readFileSync(new URL("../../tests/vectors/elgamal-vectors.json", import.meta.url), "utf-8")) as {
  election_id: string; candidate_count: number; joint_key: string; trustees: Trustee[];
  ballots: { nullifier_hash: string; sealed_ballot: string }[]; aggregate: { a: string; b: string }[];
  shares: { rng: string[]; share: { org_id: string; shares: { d: string; c: string; z: string }[] } }[];
};
const leToBig = (b: Uint8Array) => b.reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const eid = doc.election_id, n = doc.candidate_count;

async function tallyInput(): Promise<TallyInput> {
  const ballots = await Promise.all(doc.ballots.map(async (b) => {
    const raw = hexToBytes(b.sealed_ballot);
    return { nullifier_hash: b.nullifier_hash, ballot_hash: await H(raw), sealed_ballot: b64(raw) };
  }));
  return {
    election_id: eid, ballot_scheme: "ELGAMAL_ED25519_V1", final_checkpoint: 7, public_key: doc.joint_key,
    trustee_keys: doc.trustees.map((t) => t.record), candidate_ids: Array.from({ length: n }, (_, i) => `cand_${i}`),
    ballots, aggregate: doc.aggregate, valid_ballots: doc.ballots.length, invalid_ballot_hashes: [], missing_shares: [],
  };
}
const ledgerOf = async (inp: TallyInput): Promise<LedgerView> => ({
  ballots: new Set(inp.ballots.map((b) => `${b.nullifier_hash}:${b.ballot_hash}`)),
  public_key_hash: await H(hexToBytes(inp.public_key)),
});
const memory = (): Memory => { const m = new Map<string, string>(); return { get: (k) => m.get(k) ?? null, set: (k, v) => void m.set(k, v) }; };

test("trustee keys, joint key, ballots, aggregate", async () => {
  await ready();
  assert.ok(doc.trustees.every((t) => verifyTrusteeKey(t.record)));
  assert.equal(toHex(jointKey(doc.trustees.map((t) => t.record))), doc.joint_key);
  const Y = hexToBytes(doc.joint_key);
  const cts = doc.ballots.map((b) => verifyBallot(hexToBytes(b.sealed_ballot), Y, eid, b.nullifier_hash, n));
  assert.ok(cts.every((c) => c !== null));
  assert.deepEqual(aggregate(cts as NonNullable<(typeof cts)[0]>[], n).map(([a, b]) => ({ a: toHex(a), b: toHex(b) })), doc.aggregate);
  // one flipped byte of a proof makes the ballot invalid; another election binds differently
  const bad = hexToBytes(doc.ballots[0].sealed_ballot);
  bad[100] ^= 1;
  assert.equal(verifyBallot(bad, Y, eid, doc.ballots[0].nullifier_hash, n), null);
  assert.equal(verifyBallot(hexToBytes(doc.ballots[0].sealed_ballot), Y, eid.replace(/T$/, "X"), doc.ballots[0].nullifier_hash, n), null);
});

test("decryption shares equal Core's bytes", async () => {
  await ready();
  const agg = doc.aggregate.map(({ a, b }) => [hexToBytes(a), hexToBytes(b)] as [Uint8Array, Uint8Array]);
  for (const [i, t] of doc.trustees.entries()) {
    const scalars = doc.shares[i].rng.map((h) => leToBig(hexToBytes(h)));
    const share = decryptionShare(leToBig(hexToBytes(t.secret)), t.org_id, eid, agg, () => scalars.shift()!);
    assert.deepEqual(share, doc.shares[i].share);
    assert.equal(scalars.length, 0);
  }
});

test("the key file is read and checked", async () => {
  const t = doc.trustees[1];
  const { file, x } = await readTrusteeFile(JSON.stringify(t));
  assert.equal(file.org_id, t.org_id);
  assert.equal(x, leToBig(hexToBytes(t.secret)));
  const wrong = { ...t, secret: doc.trustees[0].secret };
  await assert.rejects(readTrusteeFile(JSON.stringify(wrong)), Refused);
  await assert.rejects(readTrusteeFile("not json"), Refused);
});

test("the check passes on honest input, with and without the ledger", async () => {
  const inp = await tallyInput();
  const out = await checkTallyInput(inp, doc.trustees[0].record, eid, await ledgerOf(inp));
  assert.equal(out.valid, doc.ballots.length);
  assert.deepEqual(out.steps.map((s) => s.key), ["keys", "ledger", "ballots", "sum"]);
  const noLedger = await checkTallyInput(inp, doc.trustees[0].record, eid, null);
  assert.deepEqual(noLedger.steps.map((s) => s.key), ["keys", "ballots", "sum"]);
});

test("the check refuses what trustee.py refuses", async () => {
  const mine = doc.trustees[0].record;
  const refuse = async (change: (inp: TallyInput, ledger: LedgerView) => void, msg: RegExp) => {
    const inp = await tallyInput();
    const ledger = await ledgerOf(inp);
    change(inp, ledger);
    await assert.rejects(checkTallyInput(inp, mine, eid, ledger), (e: Error) => e instanceof Refused && msg.test(e.message));
  };
  await refuse((inp) => void (inp.election_id = "elc_other"), /다른 선거/);
  await refuse((inp) => void (inp.trustee_keys = inp.trustee_keys.slice(1)), /이 선거의 기관 열쇠가 아니에요/);
  await refuse((inp) => void (inp.public_key = inp.trustee_keys[0].public_key), /합이 아니에요/);
  // Core leaves a ballot out (to narrow the sum) or lists one twice
  await refuse((inp) => { inp.ballots.pop(); }, /원장에 접수된 투표/);
  await refuse((inp) => { inp.ballots.push(inp.ballots[0]); }, /두 번/);
  await refuse((_inp, ledger) => void (ledger.public_key_hash = "00".repeat(32)), /ELECTION_CREATED/);
  await refuse((inp) => void (inp.ballots[1].sealed_ballot = null), /보여 주지 못하는/);
  await refuse((inp) => void (inp.ballots[1].sealed_ballot = inp.ballots[2].sealed_ballot), /지문/);
  await refuse((inp) => void (inp.valid_ballots = 3), /유효표/);
  await refuse((inp) => void (inp.aggregate = [inp.aggregate[1], inp.aggregate[0], inp.aggregate[2]]), /합계/);
});

test("the screen's check uses the organization's own key record (a key swapped in by Core is refused)", async () => {
  const { file } = await readTrusteeFile(JSON.stringify(doc.trustees[1]));
  const inp = await tallyInput();
  const ledger = await ledgerOf(inp);
  assert.equal((await checkWithFile(inp, file, eid, ledger)).valid, doc.ballots.length);
  // Core lists another valid key under this organization's id (one whose secret it knows): sums and proofs all agree
  const swapped = await tallyInput();
  swapped.trustee_keys = swapped.trustee_keys.map((r) => (r.org_id === file.org_id ? { ...doc.trustees[0].record, org_id: r.org_id } : r));
  await assert.rejects(checkWithFile(swapped, file, eid, ledger), (e: Error) => e instanceof Refused && /이 선거의 기관 열쇠가 아니에요/.test(e.message));
});

test("one sum per election and organization", async () => {
  const mem = memory();
  const inp = await tallyInput();
  const { agg } = await checkTallyInput(inp, doc.trustees[0].record, eid, null);
  await remember(mem, "org_commission", eid, agg);
  await remember(mem, "org_commission", eid, agg);              // the same sum again: fine (a lost answer)
  const other = [agg[1], agg[0], agg[2]];
  await assert.rejects(remember(mem, "org_commission", eid, other), Refused);
  await remember(mem, "org_observer", eid, other);              // another organization's record is separate
});
