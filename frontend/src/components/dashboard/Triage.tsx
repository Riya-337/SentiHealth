import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Eye, EyeOff, ShieldAlert, BellOff, Unlock, FileDown, ThumbsUp, ThumbsDown, Activity, Play } from "lucide-react";
import { apiFetch, apiJson, askTotp, authToken, isDemoMode } from "@/lib/api";

/* ---------------------------------------------------------------- privacy: pseudonymised identifiers */

const PRIVACY_KEY = "sentihealth.privacyMode";
const revealed = new Set<string>();

function privacyOn(): boolean {
  try {
    return localStorage.getItem(PRIVACY_KEY) !== "0";
  } catch {
    return true;
  }
}

function setPrivacy(on: boolean) {
  try {
    localStorage.setItem(PRIVACY_KEY, on ? "1" : "0");
  } catch {
    /* storage unavailable */
  }
  window.dispatchEvent(new Event("sentihealth-privacy"));
}

export function usePrivacyMode(): [boolean, (v: boolean) => void] {
  const [on, setOn] = useState(privacyOn());
  useEffect(() => {
    const h = () => setOn(privacyOn());
    window.addEventListener("sentihealth-privacy", h);
    return () => window.removeEventListener("sentihealth-privacy", h);
  }, []);
  return [on, setPrivacy];
}

function pseudonym(id: string): string {
  let h = 2166136261;
  for (let i = 0; i < id.length; i++) h = Math.imul(h ^ id.charCodeAt(i), 16777619) >>> 0;
  return `id-${h.toString(16).padStart(8, "0").slice(0, 6)}`;
}

/** Shows a pseudonym by default; a click reveals the real identifier and records the reveal in the audit chain. */
export function MaskedIp({ ip, className = "" }: { ip: string; className?: string }) {
  const [on] = usePrivacyMode();
  const [, force] = useState(0);
  const shown = !on || revealed.has(ip) || isDemoMode();
  const reveal = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!isDemoMode()) await apiJson("/api/audit/reveal", { identifier: ip, context: "dashboard" });
    revealed.add(ip);
    force((n) => n + 1);
  };
  if (shown) return <span className={className}>{ip}</span>;
  return (
    <button type="button" onClick={reveal} title="Reveal (recorded in the audit chain)" className={`inline-flex items-center gap-1 ${className}`}>
      <span className="font-mono-sec">{pseudonym(ip)}</span>
      <Eye className="h-3 w-3 opacity-60" />
    </button>
  );
}

export function PrivacyToggle() {
  const [on, set] = usePrivacyMode();
  return (
    <button
      type="button"
      onClick={() => set(!on)}
      title={on ? "Identifiers are pseudonymised; click a value to reveal it (audited)" : "Identifiers shown in clear"}
      className="inline-flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5 text-xs font-medium hover:bg-muted"
    >
      {on ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
      {on ? "Pseudonymised" : "Identifiers visible"}
    </button>
  );
}

/* ---------------------------------------------------------------- API health (sidebar) */

export function ApiHealth() {
  const [state, setState] = useState<"ok" | "down" | "checking">("checking");
  useEffect(() => {
    const check = () =>
      apiFetch("/healthz")
        .then((r) => setState(r.ok ? "ok" : "down"))
        .catch(() => setState("down"));
    check();
    const id = setInterval(check, 15000);
    return () => clearInterval(id);
  }, []);
  if (state === "checking") return <div className="text-muted-foreground">Checking the API…</div>;
  return <div className={state === "ok" ? "text-muted-foreground" : "text-alert"}>{state === "ok" ? "API reachable" : "API unreachable"}</div>;
}

/* ---------------------------------------------------------------- triage queue */

export interface Incident {
  id: string;
  ip: string;
  users: string[];
  start: string;
  end: string;
  n_events: number;
  tiers: { Low: number; Medium: number; High: number };
  peak_tier: "Low" | "Medium" | "High";
  peak_score: number;
  status: string;
  blocked: boolean;
  snoozed: { until: string; reason: string } | null;
  reason: string;
  attack_types: string[];
  shap_url: string;
}

const tierClass: Record<string, string> = {
  High: "text-red-400 bg-red-500/10 border-red-400/40",
  Medium: "text-amber-400 bg-amber-500/10 border-amber-400/40",
  Low: "text-green-400 bg-green-500/10 border-green-400/40",
};

const DEMO_INCIDENTS: Incident[] = [
  { id: "demo1", ip: "185.220.101.5", users: ["anonymous"], start: new Date(Date.now() - 600000).toISOString(), end: new Date().toISOString(), n_events: 12, tiers: { Low: 0, Medium: 2, High: 10 }, peak_tier: "High", peak_score: 0.94, status: "pending", blocked: true, snoozed: null, reason: "High tier, risk score 0.940. Main indicators: failed logins 142 (normal 0-5).", attack_types: ["brute_force"], shap_url: "" },
  { id: "demo2", ip: "10.0.4.22", users: ["U0042"], start: new Date(Date.now() - 7200000).toISOString(), end: new Date(Date.now() - 6900000).toISOString(), n_events: 5, tiers: { Low: 1, Medium: 4, High: 0 }, peak_tier: "Medium", peak_score: 0.61, status: "resolved", blocked: false, snoozed: null, reason: "Medium tier. Main indicators: access-time deviation 0.9 (normal 0-0.3).", attack_types: [], shap_url: "" },
];

export function TriagePanel({ isAdmin, hideLow }: { isAdmin: boolean; hideLow: boolean }) {
  const [incidents, setIncidents] = useState<Incident[]>(isDemoMode() ? DEMO_INCIDENTS : []);
  const [cursor, setCursor] = useState(0);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    if (isDemoMode()) return;
    const { ok, data } = await apiJson<{ incidents: Incident[] }>("/api/incidents?limit=100");
    if (ok && Array.isArray(data.incidents)) setIncidents(data.incidents);
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, [refresh]);

  const rows = useMemo(() => (hideLow ? incidents.filter((i) => i.peak_tier !== "Low" || i.status === "pending") : incidents), [incidents, hideLow]);
  const current = rows[Math.min(cursor, Math.max(rows.length - 1, 0))];

  const act = useCallback(
    async (kind: "approve" | "deny" | "snooze" | "release" | "benign" | "attack" | "report", inc?: Incident) => {
      const target = inc ?? current;
      if (!target || busy) return;
      if (isDemoMode()) return toast.info("Demo mode: actions are disabled.");
      if (!isAdmin && kind !== "report") return toast.error("Admin role required.");
      setBusy(true);
      try {
        if (kind === "approve" || kind === "deny") {
          // the incident's pending challenge is matched by IP on the alerts list
          type Challenge = { incident_id: string; metadata?: { ip?: string } };
          const { data } = await apiJson<{ pending_challenges: Challenge[] }>("/api/alerts");
          const list: Challenge[] = data.pending_challenges ?? [];
          const ch = list.find((c: Challenge) => c.metadata?.ip === target.ip) ?? list[0];
          if (!ch) return toast.error("No pending authorization for this incident.");
          const code = askTotp(`${kind === "approve" ? "APPROVE containment + forensics" : "DENY"} for ${target.ip}`);
          if (!code) return;
          const r = await apiJson(`/api/alerts/${ch.incident_id}/respond`, { decision: kind === "approve" ? "YES" : "DENY", totp_code: code });
          r.ok ? toast.success(kind === "approve" ? "Approved: forensic report generating." : "Denied: defensive posture held.") : toast.error(r.data.message || "Failed.");
        } else if (kind === "snooze") {
          const hours = Number(window.prompt(`Snooze Low/Medium alerts for ${target.ip} for how many hours? (max 72)`, "4"));
          if (!hours) return;
          const reason = window.prompt("Reason (recorded in the audit chain):", "");
          if (!reason) return;
          const r = await apiJson(`/api/entities/${target.ip}/snooze`, { hours, reason });
          r.ok ? toast.success(`Snoozed ${target.ip} for ${hours} h.`) : toast.error(r.data.message || "Failed.");
        } else if (kind === "release") {
          const code = askTotp(`RELEASE the block on ${target.ip}`);
          if (!code) return;
          const reason = window.prompt("Reason for releasing (recorded):", "false positive") ?? "";
          const r = await apiJson(`/api/blocked/${target.ip}/release`, { totp_code: code, reason });
          r.ok ? toast.success(`Block on ${target.ip} released.`) : toast.error(r.data.message || "Failed.");
        } else if (kind === "benign" || kind === "attack") {
          const r = await apiJson("/api/review", { incident_id: target.id, label: kind });
          r.ok ? toast.success(`Labelled ${kind}: queued for retraining review.`) : toast.error(r.data.message || "Failed.");
        } else if (kind === "report") {
          const res = await apiFetch(`/api/incidents/${target.id}/report`, { headers: { Authorization: `Bearer ${authToken()}` } });
          if (!res.ok) return toast.error("Report unavailable.");
          const blob = await res.blob();
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = `sentihealth_incident_${target.id}.html`;
          a.click();
          URL.revokeObjectURL(a.href);
        }
        await refresh();
      } finally {
        setBusy(false);
      }
    },
    [current, busy, isAdmin, refresh],
  );

  // keyboard: j/k move, y approve, n deny, s snooze, u unblock, b benign, a attack, r report
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || e.metaKey || e.ctrlKey) return;
      const map: Record<string, () => void> = {
        j: () => setCursor((c) => Math.min(c + 1, rows.length - 1)),
        k: () => setCursor((c) => Math.max(c - 1, 0)),
        y: () => act("approve"),
        n: () => act("deny"),
        s: () => act("snooze"),
        u: () => act("release"),
        b: () => act("benign"),
        a: () => act("attack"),
        r: () => act("report"),
      };
      const fn = map[e.key.toLowerCase()];
      if (fn) {
        e.preventDefault();
        fn();
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [act, rows.length]);

  const pending = rows.filter((r) => r.status === "pending").length;

  return (
    <section className="card-soft fade-in-up p-6">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
          Triage queue · {rows.length} incident{rows.length === 1 ? "" : "s"}
          {pending > 0 && <span className="ml-2 rounded-full bg-red-500/15 px-2 py-0.5 text-[10px] font-bold text-red-400 ring-1 ring-red-400/30">{pending} awaiting decision</span>}
        </h2>
        <div className="text-[11px] text-muted-foreground">
          keys: <kbd>j</kbd>/<kbd>k</kbd> move · <kbd>y</kbd> approve · <kbd>n</kbd> deny · <kbd>s</kbd> snooze · <kbd>u</kbd> unblock · <kbd>b</kbd>/<kbd>a</kbd> label · <kbd>r</kbd> report
        </div>
      </div>
      {rows.length === 0 ? (
        <div className="rounded-xl border border-border bg-muted/30 px-4 py-3 text-sm text-muted-foreground">No incidents yet.</div>
      ) : (
        <ul className="divide-y divide-border/60">
          {rows.map((inc, i) => (
            <li
              key={inc.id}
              onClick={() => setCursor(i)}
              className={`cursor-pointer px-2 py-3 transition-colors ${i === cursor ? "bg-brand/5 ring-1 ring-brand/30 rounded-xl" : "hover:bg-muted/30"}`}
            >
              <div className="flex flex-wrap items-center gap-3">
                <span className={`rounded-lg border px-2 py-0.5 text-[11px] font-bold ${tierClass[inc.peak_tier]}`}>{inc.peak_tier}</span>
                <MaskedIp ip={inc.ip} className="font-mono-sec text-sm font-semibold" />
                {inc.users.length > 0 && <span className="text-[11px] text-muted-foreground">{inc.users.slice(0, 3).join(", ")}</span>}
                <span className="font-mono-sec text-[11px] text-muted-foreground">{inc.start.slice(11, 16)}–{inc.end.slice(11, 16)} UTC · {inc.n_events} ev · peak {inc.peak_score.toFixed(3)}</span>
                <span className="rounded-md border border-border px-2 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">{inc.status}</span>
                {inc.blocked && <span className="rounded-md bg-red-500/10 px-2 py-0.5 text-[10px] text-red-400">blocked</span>}
                {inc.snoozed && <span className="rounded-md bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-400" title={inc.snoozed.reason}>snoozed until {inc.snoozed.until.slice(11, 16)}</span>}
                {inc.attack_types.map((t) => <span key={t} className="text-[10px] text-muted-foreground">sensor: {t}</span>)}
              </div>
              <p className="mt-1 line-clamp-2 text-[12px] text-foreground/80">{inc.reason || "No explanation."}</p>
              {i === cursor && (
                <div className="mt-2 flex flex-wrap gap-2">
                  {inc.status === "pending" && (
                    <>
                      <Btn onClick={() => act("approve", inc)} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone="green">Approve (y)</Btn>
                      <Btn onClick={() => act("deny", inc)} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone="red">Deny (n)</Btn>
                    </>
                  )}
                  {inc.blocked && <Btn onClick={() => act("release", inc)} icon={<Unlock className="h-3.5 w-3.5" />}>Release block (u)</Btn>}
                  <Btn onClick={() => act("snooze", inc)} icon={<BellOff className="h-3.5 w-3.5" />}>Snooze (s)</Btn>
                  <Btn onClick={() => act("benign", inc)} icon={<ThumbsDown className="h-3.5 w-3.5" />}>Benign (b)</Btn>
                  <Btn onClick={() => act("attack", inc)} icon={<ThumbsUp className="h-3.5 w-3.5" />}>Confirm attack (a)</Btn>
                  <Btn onClick={() => act("report", inc)} icon={<FileDown className="h-3.5 w-3.5" />}>Report (r)</Btn>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Btn({ children, onClick, icon, tone }: { children: React.ReactNode; onClick: () => void; icon?: React.ReactNode; tone?: "green" | "red" }) {
  const cls = tone === "green" ? "bg-status-normal text-white" : tone === "red" ? "bg-status-threat text-white" : "border border-border bg-card hover:bg-muted";
  return (
    <button type="button" onClick={(e) => { e.stopPropagation(); onClick(); }} className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11.5px] font-medium ${cls}`}>
      {icon}
      {children}
    </button>
  );
}

/* ---------------------------------------------------------------- model health + response + tabletop */

interface Health {
  drift: { overall: string; n_recent: number; features: Record<string, { psi: number; status: string }>; model?: { trained_at?: string } };
  anchors: { ok: boolean; anchors: number; chain_length: number; last_anchor?: { ts: string } | null };
  response: { dry_run: boolean; nft_available: boolean; lock_cmd_configured: boolean; actions_total: number };
}

export function ModelHealthCard() {
  const [h, setH] = useState<Health | null>(null);
  const [sim, setSim] = useState<string | null>(null);
  useEffect(() => {
    if (isDemoMode()) return;
    const load = () =>
      apiJson<Health>("/api/ml/health").then((r: { ok: boolean; data: Health }) => {
        if (r.ok) setH(r.data);
      });
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, []);
  const simulate = async (name: string) => {
    if (isDemoMode()) return toast.info("Demo mode: simulations are disabled.");
    setSim(name);
    const r = await apiJson(`/api/admin/simulate/${name}`, {});
    setSim(null);
    r.ok ? toast.success(`Started ${name} simulation. Watch the triage queue.`) : toast.error(r.data.message || "Failed.");
  };
  const tone = (s: string) => (s === "ok" ? "text-green-400" : s === "watch" ? "text-amber-400" : s === "drift" ? "text-red-400" : "text-muted-foreground");
  return (
    <section className="card-soft fade-in-up p-6">
      <h2 className="mb-3 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
        <Activity className="h-4 w-4" /> Model & response health
      </h2>
      {!h ? (
        <p className="text-sm text-muted-foreground">{isDemoMode() ? "Not available in demo mode." : "Loading…"}</p>
      ) : (
        <div className="grid grid-cols-1 gap-4 text-[12.5px] md:grid-cols-3">
          <div>
            <div className="font-semibold">Feature drift <span className={tone(h.drift.overall)}>· {h.drift.overall}</span></div>
            <div className="text-muted-foreground">{h.drift.n_recent} recent events vs. training period{h.drift.model?.trained_at ? ` (trained ${h.drift.model.trained_at.slice(0, 10)})` : ""}</div>
            <ul className="mt-1 space-y-0.5">
              {Object.entries(h.drift.features ?? {}).map(([k, v]) => (
                <li key={k} className="flex justify-between font-mono-sec text-[11px]"><span>{k}</span><span className={tone(v.status)}>PSI {v.psi.toFixed(3)}</span></li>
              ))}
            </ul>
          </div>
          <div>
            <div className="font-semibold">Audit-chain anchors <span className={h.anchors.ok ? "text-green-400" : "text-red-400"}>· {h.anchors.ok ? "consistent" : "MISMATCH"}</span></div>
            <div className="text-muted-foreground">{h.anchors.anchors} anchor(s), chain length {h.anchors.chain_length}{h.anchors.last_anchor ? `, last ${h.anchors.last_anchor.ts.slice(0, 16)}` : ""}</div>
            <div className="mt-3 font-semibold">Response adapters</div>
            <div className="text-muted-foreground">
              {h.response.dry_run ? "DRY RUN: actions are recorded, not applied" : "LIVE: firewall actions are applied"} · nft {h.response.nft_available ? "available" : "absent"} · directory hook {h.response.lock_cmd_configured ? "set" : "not set"} · {h.response.actions_total} actions logged
            </div>
          </div>
          <div>
            <div className="font-semibold">Tabletop exercise</div>
            <div className="text-muted-foreground">Run a bundled attack simulation against this installation (the sentinel must run with SENTIHEALTH_TEST_MODE=1).</div>
            <div className="mt-2 flex flex-wrap gap-2">
              {["brute_force", "exfiltration", "ddos", "port_scan"].map((n) => (
                <button key={n} type="button" disabled={sim !== null} onClick={() => simulate(n)} className="inline-flex items-center gap-1 rounded-lg border border-border px-2.5 py-1 text-[11.5px] hover:bg-muted disabled:opacity-50">
                  <Play className="h-3 w-3" /> {n.replace("_", " ")}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
