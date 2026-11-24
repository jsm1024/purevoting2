// D-30: exponential ElGamal ballot over the Ed25519 prime-order group, exactly as contracts/ballot-elgamal.md and
// core/app/elgamal.py (shared vectors in tests/vectors/elgamal-vectors.json). The browser only encrypts and proves;
// nobody holds the whole decryption key.
import sodium from "libsodium-wrappers-sumo";

const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const IDENTITY = Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 1 : 0));
const DOMAIN = new TextEncoder().encode("PureVoting/elgamal-ed25519/v1");
const MAGIC = new TextEncoder().encode("PVE1");
export const MAX_CANDIDATES = 15;

export type Rng = () => bigint;

// no import from ./hashing: node --test loads this file directly (tests/elgamal-vectors.test.ts)
const hexToBytes = (hex: string) => Uint8Array.from(hex.match(/../g) ?? [], (b) => parseInt(b, 16));

const mod = (s: bigint) => ((s % L) + L) % L;
const leToBig = (b: Uint8Array) => b.reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);

export function encScalar(s: bigint): Uint8Array {
  let v = mod(s);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++, v >>= 8n) out[i] = Number(v & 0xffn);
  return out;
}

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const base = (s: bigint) => (mod(s) === 0n ? IDENTITY : sodium.crypto_scalarmult_ed25519_base_noclamp(encScalar(s)));
const mul = (s: bigint, p: Uint8Array) =>
  mod(s) === 0n || same(p, IDENTITY) ? IDENTITY : sodium.crypto_scalarmult_ed25519_noclamp(encScalar(s), p);
const add = (p: Uint8Array, q: Uint8Array) => sodium.crypto_core_ed25519_add(p, q);
const sub = (p: Uint8Array, q: Uint8Array) => sodium.crypto_core_ed25519_sub(p, q);
const total = (points: Uint8Array[]) => points.reduce(add, IDENTITY);
const u16 = (n: number) => Uint8Array.of(n >> 8, n & 0xff);

const concat = (parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  parts.reduce((at, p) => (out.set(p, at), at + p.length), 0);
  return out;
};

/** Fiat-Shamir challenge: SHA-512 over length-prefixed parts, read little-endian, reduced mod L */
function hs(label: string, ...parts: Uint8Array[]): bigint {
  const all = [DOMAIN, new TextEncoder().encode(label), ...parts].flatMap((p) => [u16(p.length), p]);
  return mod(leToBig(sodium.crypto_hash_sha512(concat(all))));
}

export function randScalar(): bigint {
  for (;;) {
    const s = mod(leToBig(sodium.randombytes_buf(64)));
    if (s !== 0n) return s;
  }
}

/** the sealed_ballot bytes for candidate index `choice` of n (candidate_id order), bound to the credential */
export async function encryptBallot(publicKey: Uint8Array, electionId: string, nullifierHash: string, n: number,
                                    choice: number, rng: Rng = randScalar): Promise<Uint8Array> {
  await sodium.ready;
  if (n < 1 || n > MAX_CANDIDATES || choice < 0 || choice >= n) throw new Error("후보 번호가 범위를 벗어났어요");
  if (!sodium.crypto_core_ed25519_is_valid_point(publicKey)) throw new Error("선거 공개키 형식이 올바르지 않아요");
  const Y = publicKey;
  const G = base(1n);
  const ctx = [new TextEncoder().encode(electionId), hexToBytes(nullifierHash), Y];
  const out: Uint8Array[] = [MAGIC, u16(n)];
  const As: Uint8Array[] = [], Bs: Uint8Array[] = [];
  let R = 0n;
  for (let j = 0; j < n; j++) {
    const m = j === choice ? 1 : 0, s = 1 - m;
    const r = rng();
    const A = base(r), B = m ? add(mul(r, Y), G) : mul(r, Y);
    const cs = rng(), zs = rng(), w = rng();
    const T: Uint8Array[] = [], U: Uint8Array[] = [];
    T[m] = base(w);
    U[m] = mul(w, Y);
    T[s] = sub(base(zs), mul(cs, A));
    U[s] = sub(mul(zs, Y), mul(cs, s ? sub(B, G) : B));
    const c = hs("bit", ...ctx, u16(j), A, B, T[0], U[0], T[1], U[1]);
    const cc: bigint[] = [], zz: bigint[] = [];
    cc[s] = cs;
    cc[m] = mod(c - cs);
    zz[s] = zs;
    zz[m] = mod(w + cc[m] * r);
    out.push(A, B, encScalar(cc[0]), encScalar(cc[1]), encScalar(zz[0]), encScalar(zz[1]));
    As.push(A);
    Bs.push(B);
    R += r;
  }
  const w = rng();
  const c = hs("sum", ...ctx, total(As), total(Bs), base(w), mul(w, Y));
  out.push(encScalar(c), encScalar(w + c * R));
  return concat(out);
}

// ───────────── trustee side (core/app/elgamal.py + core/app/scripts/trustee.py, contracts/ballot-elgamal.md 4–5) ─────────────
// An organization's browser checks Core's tally input and computes its decryption share of the per-candidate sums.
// The secret is read from a file the organization picks; it never leaves the browser, only the proven share does.

const SCALAR = 32, ENTRY = 2 * 32 + 4 * SCALAR;
const te = (s: string) => new TextEncoder().encode(s);
export const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const validPoint = (p: Uint8Array) => p.length === 32 && sodium.crypto_core_ed25519_is_valid_point(p);

/** canonical scalar (< L), else null */
function decScalar(raw: Uint8Array): bigint | null {
  if (raw.length !== SCALAR) return null;
  const s = leToBig(raw);
  return s < L ? s : null;
}
const hexScalar = (hex: unknown) => (typeof hex === "string" && /^[0-9a-f]{64}$/.test(hex) ? decScalar(hexToBytes(hex)) : null);
const hexPoint = (hex: unknown) => (typeof hex === "string" && /^[0-9a-f]{64}$/.test(hex) ? hexToBytes(hex) : null);

export const ready = () => sodium.ready;

export type TrusteeRecord = { org_id: string; public_key: string; proof: { c: string; z: string } };
export type Ciphertext = [Uint8Array, Uint8Array];
export type Share = { org_id: string; shares: { d: string; c: string; z: string }[] };

/** the proof of knowledge of the organization's secret (stops a rogue-key sum); call after ready() */
export function verifyTrusteeKey(r: TrusteeRecord): boolean {
  try {
    const X = hexPoint(r.public_key), c = hexScalar(r.proof?.c), z = hexScalar(r.proof?.z);
    if (!X || c === null || z === null || typeof r.org_id !== "string" || !validPoint(X)) return false;
    return c === hs("key", te(r.org_id), X, sub(base(z), mul(c, X)));
  } catch {
    return false;
  }
}

/** Y = sum of the trustees' public keys, in org_id order (code-point order, as Python sorts strings) */
export function jointKey(records: TrusteeRecord[]): Uint8Array {
  const sorted = [...records].sort((a, b) => (a.org_id < b.org_id ? -1 : a.org_id > b.org_id ? 1 : 0));
  return total(sorted.map((r) => hexToBytes(r.public_key)));
}

/** the per-candidate ciphertexts of a valid ballot, else null (format, points or any proof wrong) */
export function verifyBallot(raw: Uint8Array, Y: Uint8Array, electionId: string, nullifierHash: string, n: number): Ciphertext[] | null {
  try {
    if (raw.length !== 6 + n * ENTRY + 2 * SCALAR || !same(raw.subarray(0, 4), MAGIC) || ((raw[4] << 8) | raw[5]) !== n) return null;
    const G = base(1n);
    const ctx = [te(electionId), hexToBytes(nullifierHash), Y];
    const out: Ciphertext[] = [];
    let at = 6;
    for (let j = 0; j < n; j++, at += ENTRY) {
      const A = raw.slice(at, at + 32), B = raw.slice(at + 32, at + 64);
      if (!validPoint(A) || !validPoint(B)) return null;
      const [c0, c1, z0, z1] = [0, 1, 2, 3].map((i) => decScalar(raw.slice(at + 64 + 32 * i, at + 96 + 32 * i)));
      if (c0 === null || c1 === null || z0 === null || z1 === null) return null;
      const T0 = sub(base(z0), mul(c0, A)), U0 = sub(mul(z0, Y), mul(c0, B));
      const T1 = sub(base(z1), mul(c1, A)), U1 = sub(mul(z1, Y), mul(c1, sub(B, G)));
      if (mod(c0 + c1) !== hs("bit", ...ctx, u16(j), A, B, T0, U0, T1, U1)) return null;
      out.push([A, B]);
    }
    const c = decScalar(raw.slice(at, at + 32)), z = decScalar(raw.slice(at + 32, at + 64));
    if (c === null || z === null) return null;
    const sA = total(out.map((e) => e[0])), sB = total(out.map((e) => e[1]));
    if (c !== hs("sum", ...ctx, sA, sB, sub(base(z), mul(c, sA)), sub(mul(z, Y), mul(c, sub(sB, G))))) return null;
    return out;
  } catch {
    return null;   // libsodium refuses a degenerate point: an invalid ballot, as in Python
  }
}

/** per-candidate sums of valid ballots' ciphertexts */
export const aggregate = (cts: Ciphertext[][], n: number): Ciphertext[] =>
  Array.from({ length: n }, (_, j) => [total(cts.map((b) => b[j][0])), total(cts.map((b) => b[j][1]))] as Ciphertext);

/** D_j = x * A_j for every aggregate, each with a Chaum-Pedersen proof that log_G X = log_A D */
export function decryptionShare(x: bigint, orgId: string, electionId: string, agg: Ciphertext[], rng: Rng = randScalar): Share {
  const X = base(x);
  return {
    org_id: orgId,
    shares: agg.map(([A], j) => {
      const D = mul(x, A), w = rng();
      const c = hs("share", te(electionId), te(orgId), u16(j), X, A, D, base(w), mul(w, A));
      return { d: toHex(D), c: toHex(encScalar(c)), z: toHex(encScalar(w + c * x)) };
    }),
  };
}

/** the secret of a trustee file, checked against the public record in the same file */
export function trusteeSecret(file: { org_id?: unknown; secret?: unknown; record?: TrusteeRecord }): bigint | null {
  const x = hexScalar(file.secret);
  if (x === null || x === 0n || !file.record || file.record.org_id !== file.org_id) return null;
  return toHex(base(x)) === file.record.public_key ? x : null;
}
