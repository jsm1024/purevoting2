import type { Finding } from "../api/types";

// The Rule Engine writes `summary` in English and signs it into the finding record (its hash is on chain), so the
// stored text never changes; the screen shows a Korean reading of it and keeps the original one click away.

export const RULE_NAME: Record<Finding["rule_id"], string> = {
  R1: "중복·상태",
  R2: "투표 시간",
  R3: "개수 맞춤",
  R4: "관리 작업",
  R5: "기록 무결성",
};

const REASON: Record<string, string> = {
  BATCH_NOT_ANCHORED: "아직 체인에 충분히 확정되지 않은 묶음이 있어 판단을 미뤘어요. 다음 검사에서 다시 봐요.",
  NODE_UNAVAILABLE: "블록체인 노드를 읽지 못해 판단을 미뤘어요. 다음 검사에서 다시 봐요.",
  VIEW_UNAVAILABLE: "Core의 기록을 읽지 못해 판단을 미뤘어요. 다음 검사에서 다시 봐요.",
};

// "Checks not implemented: ..." items of rules/ (R4, R5)
const CHECK: Record<string, string> = {
  "Verify request, approval and review signatures against node-read organization keys and quorum":
    "요청·승인·검토 서명을 노드에서 읽은 기관 키와 정족수로 검증",
  "Replay roster/token effects as exact sets in seq order, including effect windows and roster-hash chains":
    "명단·토큰 변경을 순서대로 다시 적용해 정확히 맞는지 확인",
  "Compare creation organizations/operator and proposal state to independent contract getters":
    "선거 생성 기관·운영 기관·제안 상태를 계약에서 직접 읽어 대조",
  "Detect all row changes between historical checkpoints without matching administrative events":
    "관리 작업 없이 바뀐 과거 기록 찾기",
  "Read pinned-node anchorAt and independently verify event/rejection Merkle proofs and roots":
    "고정 노드에서 앵커를 읽어 이벤트·거부 기록의 머클 증명을 직접 검증",
  "Replay full election state and compare electionStateAtCheckpoint and electionGovernance getters":
    "선거 상태 전체를 다시 계산해 계약의 상태 값과 대조",
  "Recompute all roster/token/config roots and verify revealed key derivation and commitment":
    "명단·토큰·설정 지문을 다시 계산하고 공개된 개인키가 맞는지 확인",
  "Decrypt ledger-accepted sealed ballots, or for ElGamal elections verify every ballot proof, the sums and the decryption shares, and independently reproduce tally results and invalid set":
    "장부에 기록된 표를 직접 열거나(동형 암호 선거는 표 증명·합계·복호화 조각 검증) 개표 결과와 무효표를 다시 계산",
};

export function findingKo(f: Finding): { text: string; missing: string[] } {
  if (f.result === "PASS") return { text: "구현된 검사를 모두 통과했어요.", missing: [] };
  if (f.result === "FAIL") return { text: "이상이 발견됐어요. 원문에서 자세한 내용을 확인하세요.", missing: [] };
  // a reason other than OTHER (anchor not deep, node or view unreadable) is the cause of this INCONCLUSIVE
  if (f.inconclusive_reason && f.inconclusive_reason !== "OTHER" && REASON[f.inconclusive_reason])
    return { text: REASON[f.inconclusive_reason], missing: [] };
  const m = /Checks not implemented: (.*?)\.?$/s.exec(f.summary);
  if (m) {
    const missing = m[1].split("; ").map((c) => CHECK[c.trim().replace(/\.$/, "")] ?? c.trim());
    return { text: "확인한 범위에서는 위반이 없지만, 아직 구현되지 않은 검사가 있어 판단을 보류했어요.", missing };
  }
  return { text: REASON[f.inconclusive_reason ?? ""] ?? "판단을 보류했어요. 원문을 확인하세요.", missing: [] };
}

// Deciding `observed` keys of each rule (contracts/README.md "Audit rules"; rules/purevoting_rules engine.py,
// admin_audit.py, integrity_local.py, chain_audit.py), in Korean.
// Counts and id lists that never decide (R3 counts, tally_* values, refused_*, executed/failed actions, unanchored
// counts, ledger_rejected_voter_events, and checkpoint_voter_event_mismatches which R3 also lists as
// count_relationship_violations "checkpoint_voter_events") are left out: a FAIL row lists only what made it FAIL.
const OBSERVED_KO: Record<string, string> = {
  accepted_duplicate_tokens: "같은 투표 링크가 두 번 이상 사용 처리됐어요",
  accepted_duplicate_nullifiers: "같은 투표권으로 표가 두 번 이상 접수됐어요",
  unknown_tokens: "발급 기록에 없는 투표 링크가 사용됐어요",
  unknown_nullifiers: "발급 기록에 없는 투표권으로 표가 접수됐어요",
  used_then_revoked: "사용과 취소가 함께 기록된 투표 링크가 있어요",
  events_before_start: "투표 시작 전에 기록된 투표가 있어요",
  events_after_end: "투표 종료 뒤에 기록된 투표가 있어요",
  ledger_rejected_window: "투표 기간 밖이라 원장이 거부한 기록이 있어요 (Core가 기간 검사를 통과시킴)",
  events_after_close_final: "최종 마감 뒤에 기록된 투표가 있어요",
  tally_count_mismatches: "개표 집계가 원장과 달라요",
  unapproved_changes: "기관 승인 없이 실행된 관리 작업이 있어요",
  invalid_signatures: "유효하지 않은 승인 서명이 있어요",
  duplicate_executions: "같은 제안이 두 번 이상 실행됐어요",
  missing_effects: "승인된 작업의 효과가 적용되지 않았어요",
  target_mismatches: "승인된 내용과 실제로 실행된 내용이 달라요",
  roster_chain_breaks: "명단 변경 이력 사슬이 끊겼어요 (기록 없이 명단이 바뀜)",
  rejected_checkpoints: "원장이 거부한 체크포인트가 있어요",
  chain_state_mismatch: "블록체인의 선거 상태가 원장 기록과 달라요",
  governance_mismatch: "블록체인의 선거 설정(기관·정족수)이 생성 기록과 달라요",
  checkpoint_cadence_violations: "체크포인트 주기가 어긋났어요",
  row_ledger_mismatches: "투표 기록이 원장의 기록과 달라요",
  key_mismatch: "선거 키(공개된 개인키·기관 키)가 생성 기록과 맞지 않아요",
  tables_mismatched: "체크포인트 이후 바뀐 기록 표가 있어요 (지문 불일치)",
  sealed_hash_mismatches: "암호화된 투표지와 그 지문이 맞지 않아요",
  root_mismatches: "명단·링크 목록의 지문이 원장(ROSTER_*/TOKEN_* 이벤트)에 기록된 값과 달라요",
  config_mismatch: "선거 설정이 생성 기록과 달라요",
  events_hash_mismatch: "원장 이벤트의 지문이 다시 계산한 값과 달라요",
  anchors_mismatch: "블록체인 앵커(머클 루트)가 원장 기록과 달라요",
  tally_root_mismatches: "개표에 쓴 투표지 집합의 지문이 원장과 달라요",
  tally_final_checkpoint_mismatches: "개표 기준 체크포인트가 최종 마감과 달라요",
  tally_result_hash_mismatches: "개표 결과 지문이 다시 계산한 값과 달라요",
  tally_invalid_set_mismatches: "무효표 판정이 다시 검증한 결과와 달라요",
  tally_share_failures: "검증에 실패한 복호화 조각이 있어요",
  tally_result_mismatches: "다시 계산한 개표 결과가 공개된 결과와 달라요",
};

// R3 `count_relationship_violations` entries
const COUNT_CHECK_KO: Record<string, string> = {
  atomic_redemption: "링크 사용 수와 투표권 발급 수가 달라요",
  ballots_within_credentials: "접수된 표가 발급된 투표권보다 많아요",
  credentials_within_roster: "발급된 투표권이 명단 인원보다 많아요",
  tokens_within_roster: "유효 링크가 명단 인원보다 많아요",
  committed_counts: "체크포인트에 기록한 집계가 지금 집계와 달라요",
  ledger_token_outcomes: "원장의 링크 사용 기록이 Core 기록과 달라요",
  ledger_ballot_outcomes: "원장의 투표 접수 기록이 Core 기록과 달라요",
  checkpoint_voter_events: "체크포인트별 투표 기록 수가 다시 센 값과 달라요",
  tally_counts: "개표 집계가 원장과 달라요",
};

/** the non-zero deciding values of a finding, in Korean, with their raw key (shown small, for the record) */
export function observedKo(f: Finding): { key: string; text: string; count?: number }[] {
  const out: { key: string; text: string; count?: number }[] = [];
  for (const [key, v] of Object.entries(f.observed ?? {})) {
    if (key === "count_relationship_violations") {
      if (Array.isArray(v)) for (const c of v) out.push({ key: String(c), text: COUNT_CHECK_KO[String(c)] ?? String(c) });
      continue;
    }
    const label = OBSERVED_KO[key];
    if (!label || v === null || v === undefined || v === false || v === 0) continue;
    if (key === "tally_count_mismatches" && (f.observed?.count_relationship_violations as unknown[] | undefined)?.includes("tally_counts")) continue;
    if (Array.isArray(v)) { if (v.length) out.push({ key, text: label, count: v.length }); continue; }
    out.push({ key, text: label, count: typeof v === "number" ? v : undefined });
  }
  return out;
}

export const EVIDENCE_KIND_KO: Record<string, string> = {
  ledger_event: "원장 이벤트",
  ledger_rejection: "원장 거부 기록",
  anchor: "블록체인 앵커",
  proposal: "관리 작업 제안",
  view_row: "기록 행",
  snapshot: "체크포인트 스냅샷",
  service_log: "서비스 로그",
  finding: "이전 검사 결과",
};

export const ALERT_KO: Record<string, string> = {
  AUDIT_DELAYED: "체크포인트가 아직 원장에 반영되지 않아 감사를 미뤘어요. 반영되면 다시 검사해요.",
  LEDGER_UNAVAILABLE: "원장(Gateway)이나 블록체인 노드에 연결할 수 없어요.",
  ANCHOR_REJECTED: "블록체인 계약이 앵커 기록을 거부했어요.",
  LEDGER_CONFLICT: "원장에 같은 기록이 다른 내용으로 있어요.",
  FIFO_STOPPED: "원장으로 보내는 기록이 멈췄어요.",
  OUTBOX_MISMATCH: "원장에 기록된 내용이 Core가 보낸 내용과 달라요.",
  GOVERNANCE_MISMATCH: "블록체인의 선거 설정이 생성 기록과 달라요.",
  CHAIN_CONFIG_MISMATCH: "Gateway의 체인 설정이 고정된 설정과 달라요.",
  CHECKPOINT_LEDGER_REJECTED: "원장이 체크포인트 기록을 거부했어요.",
  TRANSITION_REJECTED: "원장이 선거 상태 전환을 거부했어요.",
  BALLOT_EXCLUDED: "개표에서 제외된 표가 있어요.",
};

/** kinds that clear when the ledger catches up and the Rule Engine re-runs the checkpoint (core-api raiseAuditAlert) */
export const resolvesItself = (kind: string) => kind === "AUDIT_DELAYED" || kind === "LEDGER_UNAVAILABLE";

export const ALERT_SOURCE_KO: Record<string, string> = {
  "rule-engine": "규칙 엔진",
  "ledger-gateway": "Gateway",
  "core-api": "Core",
};

export const ORG_KO: Record<string, string> = {
  org_commission: "선관위",
  org_observer: "참관",
  org_neutral: "중립",
};
