import { useState, type FormEvent } from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Button } from "../ui";
import { ORG_KO } from "./findingText";

/** the home page's entry per organization (?org=…): its name on the form and an example account */
const ENTRY: Record<string, { title: string; hint: string }> = {
  org_commission: { title: "선관위 담당자 로그인", hint: "admin1" },
  org_observer: { title: "참관 기관 담당자 로그인", hint: "observer1" },
  org_neutral: { title: "중립 기관 담당자 로그인", hint: "neutral1" },
};

export default function Login() {
  const nav = useNavigate();
  const [params] = useSearchParams();
  const org = params.get("org") ?? "";
  const entry = ENTRY[org];
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.login(username, password);
      // an entry names one organization: another organization's account is signed out again, so three windows
      // side by side never end up on the same organization by mistake
      const got = api.currentAccount()?.org_id;
      if (entry && got !== org) {
        api.logout();
        throw new Error(`${ORG_KO[got ?? ""] ?? "다른"} 기관 계정이에요. ${ORG_KO[org]} 기관 계정으로 로그인하세요`);
      }
      nav("/admin");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  // already signed in for this organization: straight to its screen
  if (entry && api.currentAccount()?.org_id === org) return <Navigate to="/admin" replace />;

  const input = "h-12 w-full rounded-xl border border-line px-4 text-[15px] outline-none focus:border-primary";

  return (
    <div className="flex min-h-screen items-center justify-center bg-surface px-6">
      <form onSubmit={submit} className="w-full max-w-sm rounded-3xl bg-white p-8 shadow-[0_8px_32px_rgba(0,27,55,0.08)]">
        <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary text-lg font-black text-white">P</span>
        <h1 className="mt-5 text-[22px] font-bold">{entry?.title ?? "기관 담당자 로그인"}</h1>
        <p className="mt-1 text-[14px] text-ink-3">
          {entry ? `${ORG_KO[org]} 기관의 담당자 계정으로 로그인하세요.` : "선관위·참관·중립 기관의 담당자 계정으로 로그인하세요."}
        </p>
        <div className="mt-6 space-y-3">
          <input className={input} placeholder={entry ? `아이디 (예: ${entry.hint})` : "아이디"} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
          <input
            className={input}
            placeholder="비밀번호"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </div>
        {error && <p className="mt-3 text-[14px] text-danger">{error}</p>}
        <Button type="submit" size="lg" className="mt-6 w-full" disabled={busy}>
          로그인
        </Button>
      </form>
    </div>
  );
}
