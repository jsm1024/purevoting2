// D-30 trustee check of one organization in the browser, the same steps as core/app/scripts/trustee.py check() and
// remember(): Core's tally input must list exactly the ledger's accepted ballots, every ballot is verified here, the sum
// is recomputed here, and only then is this organization's share of that sum computed. Nothing here sends anything.
import { H } from "./hashing.ts";
import {
  aggregate, decryptionShare, jointKey, ready, toHex, trusteeSecret, verifyBallot, verifyTrusteeKey,
  type Ciphertext, type Share, type TrusteeRecord,
} from "./elgamal.ts";

/** GET /v1/public/elections/{id}/tally-input (core/app/tally.py tally_input) */
export interface TallyInput {
  election_id: string;
  ballot_scheme: string;
  final_checkpoint: number;
  public_key: string;
  trustee_keys: TrusteeRecord[];
  candidate_ids: string[];
  ballots: { nullifier_hash: string; ballot_hash: string; sealed_ballot: string | null }[];
  aggregate: { a: string; b: string }[];
  valid_ballots: number;
  invalid_ballot_hashes: string[];
  missing_shares: string[];
}

/** from the Gateway's stored (= ACCEPTED) events up to final_checkpoint */
export interface LedgerView {
  ballots: Set<string>; // `${nullifier_hash}:${ballot_hash}`
  public_key_hash: string | null;
}

/** the organization's key file (python -m app.scripts.trustee keygen), plus the optional read-only Gateway key the
 * demo puts next to it for the web */
export interface TrusteeFile {
  org_id: string;
  secret: string;
  record: TrusteeRecord;
  gateway_auditor_key?: string;
}

export class Refused extends Error {
  override name = "Refused";   // explicit: a minified class name would not match
}

/** one line per step that passed, for the screen */
export type Step = { key: string; text: string };

export interface Checked {
  agg: Ciphertext[];
  steps: Step[];
  listed: number;
  valid: number;
}

const sameRecord = (a: TrusteeRecord, b: TrusteeRecord) =>
  a.org_id === b.org_id && a.public_key === b.public_key && a.proof?.c === b.proof?.c && a.proof?.z === b.proof?.z;

const b64 = (s: string) => {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4) throw new Refused("목록에 있는 투표지 형식이 올바르지 않아요");
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
};

/** parses and checks the picked key file; Refused with a Korean reason */
export async function readTrusteeFile(text: string): Promise<{ file: TrusteeFile; x: bigint }> {
  await ready();
  let file: TrusteeFile;
  try {
    file = JSON.parse(text) as TrusteeFile;
  } catch {
    throw new Refused("기관 열쇠 파일이 아니에요 (JSON 형식이 아님)");
  }
  if (!file || typeof file !== "object" || typeof file.org_id !== "string" || !file.record)
    throw new Refused("기관 열쇠 파일이 아니에요 (org_id, secret, record가 있어야 해요)");
  const x = trusteeSecret(file);
  if (x === null || !verifyTrusteeKey(file.record)) throw new Refused("열쇠 파일이 손상됐어요: 비밀값이 공개 기록과 맞지 않아요");
  return { file, x };
}

/**
 * Every check of the trustee tool. `ledger` null skips the comparison with the Gateway (the screen says so, and then
 * Core could make this organization decrypt a ballot of its choice).
 */
export async function checkTallyInput(inp: TallyInput, mine: TrusteeRecord, electionId: string, ledger: LedgerView | null): Promise<Checked> {
  await ready();
  const steps: Step[] = [];
  if (inp.election_id !== electionId) throw new Refused("Core가 다른 선거의 자료를 보냈어요");
  if (inp.ballot_scheme !== "ELGAMAL_ED25519_V1") throw new Refused("동형 암호(ElGamal) 선거가 아니에요");
  const records = inp.trustee_keys;
  if (!records.some((r) => sameRecord(r, mine))) throw new Refused("이 열쇠는 이 선거의 기관 열쇠가 아니에요");
  if (!records.every(verifyTrusteeKey)) throw new Refused("이 선거의 기관 열쇠 중 검증되지 않는 것이 있어요");
  const Y = jointKey(records);
  if (toHex(Y) !== inp.public_key) throw new Refused("선거 공개키가 기관 열쇠들의 합이 아니에요");
  steps.push({ key: "keys", text: `선거 공개키 = 기관 열쇠 ${records.length}개의 합 (각 열쇠의 증명 확인)` });

  const listed = new Set(inp.ballots.map((b) => `${b.nullifier_hash}:${b.ballot_hash}`));
  if (listed.size !== inp.ballots.length || new Set(inp.ballots.map((b) => b.nullifier_hash)).size !== listed.size)
    throw new Refused("Core가 같은 투표지나 같은 투표권을 두 번 넣었어요");
  if (ledger !== null) {
    if (ledger.public_key_hash !== (await H(Y))) throw new Refused("선거 공개키가 원장(ELECTION_CREATED)에 기록된 것과 달라요");
    // exactly the ledger's ballots, so Core can neither add ballots it made itself nor leave some out
    const same = listed.size === ledger.ballots.size && [...listed].every((k) => ledger.ballots.has(k));
    if (!same) throw new Refused("Core가 준 투표지 목록이 원장에 접수된 투표(BALLOT_RECEIVED)와 달라요");
    steps.push({ key: "ledger", text: `투표지 목록 ${listed.size}장 = 블록체인 원장에 접수된 투표` });
  }

  const n = inp.candidate_ids.length;
  const cts: Ciphertext[][] = [];
  for (const b of inp.ballots) {
    // a ballot whose bytes Core cannot show narrows the sum (all but one left out would decrypt that one): the CLI's
    // --allow-unavailable is a person's decision after checking why, so the web never allows it
    if (b.sealed_ballot === null) throw new Refused("Core가 원장 투표지 중 내용을 보여 주지 못하는 것이 있어요. 명령창 도구로 원인을 확인하세요");
    const raw = b64(b.sealed_ballot);
    if ((await H(raw)) !== b.ballot_hash) throw new Refused("목록의 투표지가 그 지문(ballot_hash)과 맞지 않아요");
    const ct = verifyBallot(raw, Y, electionId, b.nullifier_hash, n);
    if (ct !== null) cts.push(ct);
  }
  if (cts.length !== inp.valid_ballots) throw new Refused(`Core는 유효표를 ${inp.valid_ballots}장이라고 하지만 직접 확인하니 ${cts.length}장이에요`);
  steps.push({ key: "ballots", text: `투표지 ${inp.ballots.length}장 증명 확인: 유효 ${cts.length}장, 무효 ${inp.ballots.length - cts.length}장` });

  const agg = aggregate(cts, n);
  const mineAgg = agg.map(([a, b]) => ({ a: toHex(a), b: toHex(b) }));
  if (mineAgg.length !== inp.aggregate.length || mineAgg.some((x, i) => x.a !== inp.aggregate[i].a || x.b !== inp.aggregate[i].b))
    throw new Refused("Core가 계산한 합계가 투표지들의 합과 달라요");
  steps.push({ key: "sum", text: `후보 ${n}명의 암호문 합계를 직접 다시 계산: Core 값과 같음` });
  return { agg, steps, listed: inp.ballots.length, valid: cts.length };
}

/**
 * What the organization's screen runs: the key record checked against the election is the one in the organization's
 * OWN file (trustee.py passes secret["record"]), never the one Core lists, so a key Core swapped in for this
 * organization is refused here.
 */
export const checkWithFile = (inp: TallyInput, file: TrusteeFile, electionId: string, ledger: LedgerView) =>
  checkTallyInput(inp, file.record, electionId, ledger);

/** digest of a sum, the value remembered per election */
export const sumDigest = (agg: Ciphertext[]) => H(new Uint8Array(agg.flatMap(([a, b]) => [...a, ...b])));

/** storage of this organization's browser; a test passes its own */
export interface Memory {
  get(key: string): string | null;
  set(key: string, value: string): void;
}

/**
 * One sum per election and organization (trustee.py remember): a different one later would let Core subtract two sums.
 * Kept in this browser only; the file-based CLI keeps its own record, so an organization uses one of the two per election.
 */
export async function remember(mem: Memory, orgId: string, electionId: string, agg: Ciphertext[]): Promise<void> {
  const key = `pv_trustee_sum:${orgId}:${electionId}`;
  const digest = await sumDigest(agg);
  const seen = mem.get(key);
  if (seen !== null && seen !== digest) throw new Refused("이 기관은 이 선거에서 이미 다른 합계를 복호화했어요. 제출하지 않아요");
  mem.set(key, digest);
}

/** the share to send, computed only after the checks above passed */
export const shareFor = (x: bigint, orgId: string, electionId: string, agg: Ciphertext[]): Share =>
  decryptionShare(x, orgId, electionId, agg);
