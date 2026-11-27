// Screens of the three organizations (D-30, docs/decisions.md): each one signs in with its own account and sees its own
// tasks. Decryption runs in the organization's browser: the key file is read here and never sent, only the proven share.
import { useEffect, useRef, useState, type ChangeEvent } from "react";
import { api } from "../api";
import type { Account, Election, NodeStatus, ShareStatus } from "../api/types";
import type { Checked, Step, TrusteeFile } from "../crypto/trusteeCheck";
import { Button, Card, Spinner } from "../ui";
import { ORG_KO } from "./findingText";

// libsodium is large: loaded only when an organization uses the decryption card, never on the voter's first page
const trustee = () => import("../crypto/trusteeCheck");
/** a refusal of the checks carries its Korean reason; anything else gets a fallback */
const reason = (x: unknown, fallback: string) => (x instanceof Error && x.name === "Refused" ? x.message : fallback);

export const ROLE_KO: Record<Account["role"], string> = { admin: "운영 담당", approver: "승인 담당", auditor: "감사 담당" };

/** what each organization does in an election (docs/system-design.md 2.3) */
const ORG_TASKS: Record<string, { title: string; tasks: string[] }> = {
  org_commission: {
    title: "선관위: 선거를 만들고 운영해요",
    tasks: ["선거 만들기, 명단 확정, 투표 링크 발급", "마감 뒤 우리 기관의 복호화 조각 제출", "세 기관 조각이 모이면 개표, 감사가 끝나면 결과 확정"],
  },
  org_observer: {
    title: "참관: 운영을 지켜보고 검증해요",
    tasks: ["선거마다 무결성 검사(R1–R5) 결과와 근거 확인", "마감 뒤 투표지·합계·원장을 직접 검사하고 복호화 조각 제출", "선거를 만들거나 명단을 바꿀 수는 없어요"],
  },
  org_neutral: {
    title: "중립: 원장(Gateway)과 노드를 운영해요",
    tasks: ["블록체인 노드 3개와 원장 상태 확인", "마감 뒤 투표지·합계·원장을 직접 검사하고 복호화 조각 제출", "선거를 만들거나 명단을 바꿀 수는 없어요"],
  },
};

export function OrgTasksCard({ account }: { account: Account }) {
  const t = ORG_TASKS[account.org_id];
  if (!t) return null;
  return (
    <Card className="mt-6 p-5">
      <div className="flex flex-wrap items-baseline gap-2">
        <h2 className="text-[16px] font-bold">{t.title}</h2>
        <span className="text-[13px] text-ink-4">{account.name} · {ROLE_KO[account.role]}</span>
      </div>
      <ul className="mt-2 space-y-1 text-[14px] text-ink-3">
        {t.tasks.map((x) => <li key={x}>• {x}</li>)}
      </ul>
    </Card>
  );
}

/** the read-only Gateway key of this tab (api.ledgerKey), entered once; the key file can carry it too */
function LedgerKeyInput({ onSet }: { onSet: (k: string) => void }) {
  const [v, setV] = useState("");
  return (
    <form className="flex gap-2" onSubmit={(ev) => { ev.preventDefault(); api.setLedgerKey(v.trim()); onSet(v.trim()); setV(""); }}>
      <input type="password" autoComplete="off" value={v} onChange={(ev) => setV(ev.target.value)} placeholder="원장 읽기 키 (auditorKey)"
        className="h-10 min-w-0 flex-1 rounded-xl border border-line px-3 text-[14px] outline-none focus:border-primary" />
      <Button type="submit" variant="secondary" disabled={!v.trim()}>저장</Button>
    </form>
  );
}

/** GET /v1/nodes through the web's /ledger/ entry: the organizations' chain nodes, every 10 s */
export function NodesCard({ className = "" }: { className?: string }) {
  const [key, setKey] = useState(api.ledgerKey());
  const [nodes, setNodes] = useState<NodeStatus[]>();
  const [err, setErr] = useState("");
  useEffect(() => {
    if (!key) return;
    let stop = false;
    const tick = () => api.listNodes(key).then(
      (v) => { if (!stop) { setNodes(v); setErr(""); } },
      (e: Error) => { if (!stop) { setNodes(undefined); setErr(e.message); } },
    );
    tick();
    const t = setInterval(tick, 10_000);
    return () => { stop = true; clearInterval(t); };
  }, [key]);

  const top = Math.max(0, ...(nodes ?? []).map((n) => n.block_number ?? 0));
  return (
    <Card className={`p-5 ${className}`}>
      <div className="flex items-baseline justify-between">
        <h2 className="text-[16px] font-bold">블록체인 노드</h2>
        <span className="text-[12px] text-ink-4">기관마다 1개 · 10초마다 갱신</span>
      </div>
      {!key ? (
        <div className="mt-3 space-y-2">
          <p className="text-[13px] text-ink-3">원장 읽기 키를 넣으면 노드 상태를 볼 수 있어요. 이 탭에만 저장돼요.</p>
          <LedgerKeyInput onSet={setKey} />
        </div>
      ) : err ? (
        <div className="mt-3 space-y-2">
          <p className="text-[13px] text-danger">{err}</p>
          <button className="text-[13px] font-semibold text-ink-3 hover:text-ink" onClick={() => { api.setLedgerKey(""); setKey(""); setErr(""); }}>
            키 다시 넣기
          </button>
        </div>
      ) : !nodes ? (
        <p className="mt-3 flex items-center gap-2 text-[13px] text-ink-4"><Spinner className="h-4 w-4" /> 불러오는 중…</p>
      ) : (
        <ul className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-3">
          {nodes.map((n) => {
            const behind = n.reachable && n.block_number !== undefined ? top - n.block_number : 0;
            const ok = n.reachable && behind <= 3;
            return (
              <li key={n.node_id} className={`rounded-xl p-3 ${ok ? "bg-surface" : "bg-danger-soft"}`}>
                <div className="flex items-center justify-between">
                  <span className="text-[14px] font-bold">{ORG_KO[n.org_id] ?? n.org_id} 노드</span>
                  <span className={`text-[12px] font-bold ${ok ? "text-ok" : "text-danger"}`}>{!n.reachable ? "● 연결 안 됨" : ok ? "● 정상" : "● 뒤처짐"}</span>
                </div>
                {n.reachable && (
                  <p className="mt-1 text-[12px] text-ink-3">
                    블록 #{n.block_number?.toLocaleString()}
                    {n.peer_count !== undefined && ` · 연결된 노드 ${n.peer_count}개`}
                    {behind > 3 && ` · ${behind}블록 뒤`}
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

type Phase =
  | { at: "pick" }
  | { at: "checking" }
  | { at: "checked"; out: Checked }
  | { at: "sending"; steps: Step[] }
  | { at: "sent"; steps: Step[]; missing: string[] }
  | { at: "nothing" };

/**
 * One organization's decryption, the same steps as `python -m app.scripts.trustee decrypt`: read the key file (here,
 * never uploaded), read Core's tally input and the Gateway's accepted events, check every ballot and the sum, then
 * send only this organization's proven share of that sum. The comparison with the ledger is not optional here.
 */
export function TrusteeCard({ e, account, onSent }: { e: Election; account: Account; onSent: () => void }) {
  const id = e.election_id;
  const org = account.org_id;
  const secret = useRef<bigint | null>(null);
  const keyFile = useRef<TrusteeFile | null>(null);   // the organization's own record is what the checks compare against
  const [fileName, setFileName] = useState("");
  const [phase, setPhase] = useState<Phase>({ at: "pick" });
  const [err, setErr] = useState("");
  const [status, setStatus] = useState<ShareStatus>();
  const [key, setKey] = useState(api.ledgerKey());

  useEffect(() => {
    api.shareStatus(id).then(setStatus, () => undefined);
    return () => { secret.current = null; keyFile.current = null; };          // the secret lives only while this card is open
  }, [id]);

  const mine = status ? status.orgs.includes(org) : true;
  const alreadySent = status !== undefined && status.valid_ballots > 0 && !status.missing.includes(org) && phase.at !== "sent";
  if (!mine) return null;

  async function pick(ev: ChangeEvent<HTMLInputElement>) {
    const f = ev.target.files?.[0];
    ev.target.value = "";                                // the same file can be picked again
    setErr("");
    setPhase({ at: "pick" });
    secret.current = null;
    keyFile.current = null;
    setFileName("");
    if (!f) return;
    try {
      const t = await trustee();
      if (f.size > 64 * 1024) throw new t.Refused("기관 열쇠 파일이 아니에요 (너무 커요)");
      const { file, x } = await t.readTrusteeFile(await f.text());
      if (file.org_id !== org) throw new t.Refused(`${ORG_KO[file.org_id] ?? file.org_id} 기관의 열쇠 파일이에요. ${ORG_KO[org] ?? org} 기관 열쇠를 고르세요`);
      // the ledger comparison needs the Gateway's read-only key: it comes with the key file (web-key.json); this card has no input for it
      const ledgerKey = file.gateway_auditor_key || api.ledgerKey();
      if (!ledgerKey) throw new t.Refused(`이 파일에는 원장 읽기 키가 없어요. ${org}.web-key.json 파일을 고르세요`);
      secret.current = x;
      keyFile.current = file;
      api.setLedgerKey(ledgerKey);
      setKey(ledgerKey);
      setFileName(f.name);
    } catch (x) {
      setErr(reason(x, "파일을 읽지 못했어요"));
    }
  }

  async function check() {
    setErr("");
    setPhase({ at: "checking" });
    try {
      const t = await trustee();
      const file = keyFile.current;
      if (!file) throw new t.Refused("기관 열쇠 파일을 다시 고르세요");
      const inp = await api.getTallyInput(id);
      const ledger = await api.ledgerView(id, key, inp.final_checkpoint);
      const out = await t.checkWithFile(inp, file, id, ledger);
      // trustee.py: no valid ballot, nothing to decrypt (Core refuses a share then)
      setPhase(out.valid === 0 ? { at: "nothing" } : { at: "checked", out });
    } catch (x) {
      setPhase({ at: "pick" });
      setErr((x as Error).message);
    }
  }

  async function send(out: Checked) {
    const x = secret.current;
    if (x === null) return;
    setErr("");
    setPhase({ at: "sending", steps: out.steps });
    try {
      // one sum per election, remembered BEFORE the share leaves (trustee.py remember)
      const mem = { get: (k: string) => localStorage.getItem(k), set: (k: string, v: string) => localStorage.setItem(k, v) };
      const t = await trustee();
      await t.remember(mem, org, id, out.agg);
      const r = await api.submitShare(id, t.shareFor(x, org, id, out.agg));
      secret.current = null;
      keyFile.current = null;
      setFileName("");
      setPhase({ at: "sent", steps: out.steps, missing: r.missing_shares });
      onSent();
    } catch (x) {
      setPhase({ at: "checked", out });
      setErr(x instanceof DOMException ? "이 브라우저에 기록을 남길 수 없어 제출하지 않았어요 (사생활 보호 모드인지 확인하세요)" : (x as Error).message);
    }
  }

  const orgName = ORG_KO[org] ?? org;
  const steps = phase.at === "checked" ? phase.out.steps : phase.at === "sending" || phase.at === "sent" ? phase.steps : [];
  return (
    <Card className="mt-4 p-6">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-[17px] font-bold">우리 기관 복호화 · {orgName}</h2>
        <span className="text-[13px] text-ink-4">열쇠 파일은 이 컴퓨터 안에서만 읽고, 서버로 보내지 않아요</span>
      </div>

      {alreadySent ? (
        <p className="mt-4 rounded-xl bg-ok-soft p-3 text-[14px] font-semibold text-ok">✓ {orgName} 기관은 이 선거의 복호화 조각을 이미 제출했어요.</p>
      ) : phase.at === "sent" ? (
        <div className="mt-4 space-y-3">
          <StepList steps={[...steps, { key: "sent", text: "복호화 조각 제출: Core가 증명을 확인하고 받았어요" }]} />
          <p className="rounded-xl bg-ok-soft p-3 text-[14px] font-semibold text-ok">
            ✓ 제출했어요. {phase.missing.length ? `남은 기관: ${phase.missing.map((o) => ORG_KO[o] ?? o).join(", ")}` : "세 기관이 모두 제출해서 개표할 수 있어요."}
          </p>
        </div>
      ) : phase.at === "nothing" ? (
        <p className="mt-4 rounded-xl bg-surface p-3 text-[14px] text-ink-3">유효한 표가 없어 복호화할 것이 없어요. 바로 개표할 수 있어요.</p>
      ) : (
        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
          <ol className="space-y-3 text-[14px]">
            <li>
              <span className="font-bold">① 기관 열쇠 파일 고르기</span>
              <label className="mt-2 flex cursor-pointer items-center gap-3 rounded-xl border border-dashed border-line p-3 hover:border-primary">
                <span className="rounded-lg bg-primary-soft px-3 py-1.5 text-[13px] font-bold text-primary">파일 선택</span>
                <span className="truncate text-[13px] text-ink-3">{fileName ? `✓ ${fileName}` : `${org}.web-key.json`}</span>
                <input type="file" accept=".json,application/json" className="hidden" onChange={pick} />
              </label>
            </li>
            <li>
              <span className="font-bold">② 검사 → 제출</span>
              <div className="mt-2 flex gap-2">
                <Button variant="secondary" className="flex-1" disabled={!fileName || !key || phase.at === "checking" || phase.at === "sending"} onClick={check}>
                  {phase.at === "checking" ? <><Spinner className="h-4 w-4" /> 검사 중…</> : "검사하기"}
                </Button>
                <Button className="flex-1" disabled={phase.at !== "checked" || !fileName} onClick={() => phase.at === "checked" && send(phase.out)}>
                  {phase.at === "sending" ? <><Spinner className="h-4 w-4" /> 제출 중…</> : "복호화 조각 제출"}
                </Button>
              </div>
            </li>
          </ol>
          <div className="rounded-xl bg-surface p-4">
            <p className="text-[13px] font-bold text-ink-2">검사 결과</p>
            {steps.length ? (
              <StepList steps={steps} />
            ) : (
              <p className="mt-2 text-[13px] text-ink-4">
                Core가 준 투표지 목록이 블록체인 원장과 같은지, 투표지마다 증명이 맞는지, 합계가 맞는지 이 브라우저가 직접 확인해요. 하나라도 어긋나면 조각을 내지 않아요.
              </p>
            )}
            {phase.at === "checked" && (
              <p className="mt-3 text-[12px] text-ink-4">
                이 합계에 대한 {orgName} 조각만 계산해서 보내요. 같은 선거에 다른 합계가 오면 이 브라우저는 다시 계산하지 않아요.
                이 기록은 이 브라우저에만 남으니, 한 선거는 같은 브라우저에서 내고 시크릿 창은 쓰지 마세요.
              </p>
            )}
          </div>
        </div>
      )}
      {err && <p className="mt-4 rounded-xl bg-danger-soft p-3 text-[14px] font-semibold text-danger">✕ {err}</p>}
    </Card>
  );
}

function StepList({ steps }: { steps: Step[] }) {
  return (
    <ul className="mt-2 space-y-1.5 text-[13px]">
      {steps.map((s) => (
        <li key={s.key} className="flex gap-2 text-ink-2"><span className="font-bold text-ok">✓</span>{s.text}</li>
      ))}
    </ul>
  );
}
