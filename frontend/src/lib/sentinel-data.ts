import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch, isDemoMode, openStream } from "@/lib/api";

export type Tier = "High" | "Medium" | "Low";
export type Action = "pending" | "resolved" | "auto-locked" | "forensics_generated" | "denied" | "blocked" | "admin_released";
export type SystemStatus = "NORMAL" | "THREAT" | "LOCKDOWN";

export interface TopFeature {
  feature: string;
  label: string;
  value: number;
  normal_range: [number, number];
  share: number; // 0..1, share of the abnormal signal
}

export interface ThreatEvent {
  id: string;
  timestamp: string;
  ip: string;
  tier: Tier;
  score: number;
  action: Action;
  reason: string;       // plain_english_explanation from ML model
  shap_url: string;     // /api/shap/<filename> — served behind auth gate
  lat: number;
  lng: number;
  country: string;
  city: string;
  topFeatures?: TopFeature[];   // indicators outside their normal range (empty = none)
  attackType?: string;
  modelDisagreement?: number;   // std-dev of the five models' High probabilities
}

type RawThreat = {
  ip: string; tier: string; score: number; timestamp: string; action: string;
  reason?: string; shap_url?: string;
  top_features?: TopFeature[]; attack_type?: string; model_disagreement?: number;
};

/** Small deterministic hash so the same IP always lands on the same map spot. */
function ipHash(ip: string): number {
  let h = 0;
  for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) >>> 0;
  return h;
}

export interface MLMetricRow {
  model: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  auc: number;
  ensemble?: boolean;
}

export interface SentinelSnapshot {
  status: SystemStatus;
  ledger: "INTACT" | "COMPROMISED";
  totalBlockedIPs: number;
  recent: ThreatEvent[];
  feed: ThreatEvent[];
  blocked: ThreatEvent[];
  tierCounts: { High: number; Medium: number; Low: number; total: number };
  riskSeries: { t: string; score: number }[];
  lastHighAt: number;
  totalIPsPlotted: number;
  lastUpdated: string;
}

// IP prefix → approximate geolocation (Option A: offline, no API key needed)
const IP_GEO: { prefix: string; lat: number; lng: number; city: string; country: string }[] = [
  { prefix: "198.51",   lat: 40.71,  lng: -74.00, city: "New York",    country: "USA" },
  { prefix: "203.0",    lat: 35.68,  lng: 139.69, city: "Tokyo",       country: "Japan" },
  { prefix: "185.199",  lat: 52.52,  lng: 13.40,  city: "Berlin",      country: "Germany" },
  { prefix: "185.220",  lat: 55.75,  lng: 37.61,  city: "Moscow",      country: "Russia" },
  { prefix: "45.33",    lat: 37.38,  lng: -122.0, city: "San Jose",    country: "USA" },
  { prefix: "192.0",    lat: 48.86,  lng: 2.35,   city: "Paris",       country: "France" },
  { prefix: "8.8",      lat: 37.42,  lng: -122.08,city: "Mountain View","country": "USA" },
  { prefix: "10.",      lat: 39.90,  lng: 116.40, city: "Beijing",     country: "China" },
  { prefix: "172.",     lat: 1.35,   lng: 103.82, city: "Singapore",   country: "Singapore" },
];

const REASONS: Record<Tier, string[]> = {
  High:   ["Brute Force Login Attempt", "Exploit Attempt Detected", "Privilege Escalation Attempt", "Malicious Payload Detected"],
  Medium: ["Suspicious User-Agent", "Abnormal Request Rate", "Repeated 401 Responses", "Suspicious Payload Pattern"],
  Low:    ["Reconnaissance Activity", "Port Scan Detected", "Header Anomaly", "Slow Probe Detected"],
};

function geoForIP(ip: string): { lat: number; lng: number; city: string; country: string } {
  const match = IP_GEO.find((g) => ip.startsWith(g.prefix));
  if (match) return match;
  // deterministic fallback based on IP sum
  const parts = ip.split(".").map(Number);
  const seed = (parts[0] * 13 + parts[1] * 7 + parts[2]) % IP_GEO.length;
  return IP_GEO[seed] ?? IP_GEO[0];
}

/** Demo mode only: a label for simulated events, chosen by IP so it does not change on re-render. */
function reasonForTier(tier: Tier, ip: string): string {
  const arr = REASONS[tier];
  return arr[ipHash(ip) % arr.length];
}

function mapFlaskEvent(raw: RawThreat, idx: number): ThreatEvent {
  const tier = raw.tier as Tier;
  const geo = geoForIP(raw.ip);
  const h = ipHash(raw.ip);
  return {
    id: `${raw.timestamp}-${idx}`,
    timestamp: raw.timestamp,
    ip: raw.ip,
    tier,
    score: raw.score,
    action: raw.action as Action,
    // Only the model's own explanation; never an invented attack name.
    reason: raw.reason || "",
    shap_url: raw.shap_url || "",
    // Fixed small offset per IP so repeated events from one address stack on one spot.
    lat: geo.lat + (((h % 1000) / 1000) - 0.5) * 0.8,
    lng: geo.lng + ((((h >>> 10) % 1000) / 1000) - 0.5) * 0.8,
    country: geo.country,
    city: geo.city,
    topFeatures: raw.top_features,
    attackType: raw.attack_type,
    modelDisagreement: raw.model_disagreement,
  };
}

/** Derive a full SentinelSnapshot from a flat list of already-mapped ThreatEvents. */
function buildSnapshotFromEvents(
  recent: ThreatEvent[],
  status: SystemStatus,
  ledger: "INTACT" | "COMPROMISED",
  totalBlockedIPs: number,
): SentinelSnapshot {
  const feed    = recent.slice(0, 20);
  const blocked = recent.filter((e) => e.action !== "pending");


  const tierCounts = { High: 0, Medium: 0, Low: 0, total: recent.length };
  for (const e of recent) tierCounts[e.tier]++;

  const riskSeries = recent
    .slice()
    .reverse()
    .slice(-30)            // keep last 30 points so the chart stays readable
    .map((e) => ({ t: e.timestamp.slice(11, 16), score: e.score }));

  const lastHigh = recent.find((e) => e.tier === "High");
  const lastHighAt = lastHigh ? new Date(lastHigh.timestamp).getTime() : 0; // 0 = none yet

  return {
    status,
    ledger,
    totalBlockedIPs,
    recent,
    feed,
    blocked,
    tierCounts,
    riskSeries,
    lastHighAt,
    totalIPsPlotted: recent.length,
    lastUpdated: new Date().toISOString().slice(11, 19),
  };
}

function buildSnapshot(apiData: {
  status: string;
  blockchain_status: string;
  blocked_count: number;
  total_threat_count?: number;
  all_tier_counts?: { High: number; Medium: number; Low: number };
  threats: RawThreat[];
}): SentinelSnapshot {
  const recent = apiData.threats.map(mapFlaskEvent);
  const status: SystemStatus =
    apiData.status === "LOCKDOWN" ? "LOCKDOWN" :
    apiData.status === "THREAT"   ? "THREAT"   : "NORMAL";
  const ledger: "INTACT" | "COMPROMISED" =
    apiData.blockchain_status === "INTACT" ? "INTACT" : "COMPROMISED";

  const snap = buildSnapshotFromEvents(recent, status, ledger, apiData.blocked_count);

  // Override tier counts with the real full-log totals from the backend
  if (apiData.total_threat_count !== undefined && apiData.all_tier_counts) {
    snap.tierCounts = {
      High:   apiData.all_tier_counts.High,
      Medium: apiData.all_tier_counts.Medium,
      Low:    apiData.all_tier_counts.Low,
      total:  apiData.total_threat_count,
    };
  }

  return snap;
}

const INITIAL_DEMO_EVENTS: ThreatEvent[] = [
  {
    id: "evt-001",
    timestamp: new Date(Date.now() - 1000 * 60 * 2).toISOString().replace("T", " ").slice(0, 19),
    ip: "185.220.101.5",
    tier: "High",
    score: 0.942,
    action: "blocked",
    reason: "Brute Force Authentication & SQL Injection payload detected on /api/ehr/patients",
    shap_url: "",
    lat: 55.75,
    lng: 37.61,
    city: "Moscow",
    country: "Russia",
  },
  {
    id: "evt-002",
    timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString().replace("T", " ").slice(0, 19),
    ip: "45.33.32.156",
    tier: "High",
    score: 0.887,
    action: "forensics_generated",
    reason: "Privilege Escalation & unauthorized access to patient record EHR-49201",
    shap_url: "",
    lat: 37.38,
    lng: -122.0,
    city: "San Jose",
    country: "USA",
  },
  {
    id: "evt-003",
    timestamp: new Date(Date.now() - 1000 * 60 * 12).toISOString().replace("T", " ").slice(0, 19),
    ip: "198.51.100.24",
    tier: "Medium",
    score: 0.654,
    action: "resolved",
    reason: "Abnormal Request Burst (480 req/min) — Bandwidth Throttling Applied",
    shap_url: "",
    lat: 40.71,
    lng: -74.0,
    city: "New York",
    country: "USA",
  },
  {
    id: "evt-004",
    timestamp: new Date(Date.now() - 1000 * 60 * 18).toISOString().replace("T", " ").slice(0, 19),
    ip: "203.0.113.88",
    tier: "Medium",
    score: 0.582,
    action: "resolved",
    reason: "Suspicious User-Agent & repeated 401 unauthorized probes",
    shap_url: "",
    lat: 35.68,
    lng: 139.69,
    city: "Tokyo",
    country: "Japan",
  },
  {
    id: "evt-005",
    timestamp: new Date(Date.now() - 1000 * 60 * 25).toISOString().replace("T", " ").slice(0, 19),
    ip: "192.0.2.140",
    tier: "Low",
    score: 0.312,
    action: "resolved",
    reason: "Port Scanning & SSL Cipher renegotiation reconnaissance",
    shap_url: "",
    lat: 48.86,
    lng: 2.35,
    city: "Paris",
    country: "France",
  },
  {
    id: "evt-006",
    timestamp: new Date(Date.now() - 1000 * 60 * 35).toISOString().replace("T", " ").slice(0, 19),
    ip: "10.14.88.19",
    tier: "Low",
    score: 0.220,
    action: "resolved",
    reason: "Header Anomaly detected and recorded in cryptographic ledger",
    shap_url: "",
    lat: 39.9,
    lng: 116.4,
    city: "Beijing",
    country: "China",
  },
];

const FALLBACK: SentinelSnapshot = buildSnapshotFromEvents(
  INITIAL_DEMO_EVENTS,
  "THREAT",
  "INTACT",
  5
);

function authHeaders(): HeadersInit {
  const token = typeof window !== "undefined"
    ? sessionStorage.getItem("auth_token") ?? ""
    : "";
  return token ? { Authorization: `Bearer ${token}` } : {};
}

const EMPTY: SentinelSnapshot = buildSnapshotFromEvents([], "NORMAL", "INTACT", 0);

export function useSentinel(autoRefresh = true): SentinelSnapshot {
  // Simulated events are used only in the explicit demo mode, never as a stand-in for a real session.
  const [snap, setSnap] = useState<SentinelSnapshot>(() => (isDemoMode() ? FALLBACK : EMPTY));

  const snapRef = useRef<SentinelSnapshot>(snap);
  snapRef.current = snap;

  const fetchSnap = useCallback(async () => {
    if (!isDemoMode()) {
      try {
        const res = await apiFetch("/api/status", { headers: authHeaders() });
        if (res.status === 401) {
          if (typeof window !== "undefined") window.location.href = "/";
          return;
        }
        if (!res.ok) return;
        const data = await res.json();
        setSnap(buildSnapshot(data));
      } catch {
        // Backend unreachable: keep the last real snapshot rather than inventing events.
      }
      return;
    }
    {
      // Demo mode: simulated periodic sentinel ticker
      const randomIP = IP_GEO[Math.floor(Math.random() * IP_GEO.length)];
      const isHigh = Math.random() > 0.65;
      const tier: Tier = isHigh ? "High" : Math.random() > 0.5 ? "Medium" : "Low";
      const newEvent: ThreatEvent = {
        id: `evt-${Date.now()}`,
        timestamp: new Date().toISOString().replace("T", " ").slice(0, 19),
        ip: `${randomIP.prefix}.${Math.floor(Math.random() * 200) + 1}`,
        tier,
        score: isHigh ? 0.85 + Math.random() * 0.12 : 0.25 + Math.random() * 0.45,
        action: isHigh ? "blocked" : "resolved",
        reason: reasonForTier(tier, randomIP.prefix),
        shap_url: "",
        lat: randomIP.lat + (Math.random() - 0.5) * 0.5,
        lng: randomIP.lng + (Math.random() - 0.5) * 0.5,
        city: randomIP.city,
        country: randomIP.country,
      };

      setSnap((prev) => {
        const nextRecent = [newEvent, ...prev.recent].slice(0, 30);
        return buildSnapshotFromEvents(nextRecent, isHigh ? "THREAT" : prev.status, "INTACT", prev.totalBlockedIPs + (isHigh ? 1 : 0));
      });
    }
  }, []);

  useEffect(() => {
    fetchSnap();
    if (!autoRefresh) return;
    const id = setInterval(fetchSnap, 6000);
    return () => clearInterval(id);
  }, [autoRefresh, fetchSnap]);

  // ── Real-time push: SSE threat_update events ────────────────────────────
  // When live_sentinel.py writes a new scored threat to threat_log.json the
  // backend tail-follows the file and pushes it here immediately — no poll lag.
  useEffect(() => {
    const token = typeof window !== "undefined"
      ? sessionStorage.getItem("auth_token") ?? ""
      : "";


    if (!token) return;

    const es = openStream();   // one-time ticket; no session token in the URL

    es.addEventListener("threat_update", (e: MessageEvent) => {
      try {
        const raw = JSON.parse(e.data) as {
          ip: string; tier: string; score: number;
          timestamp: string; action: string;
          reason?: string; shap_url?: string;
        };
        const incoming = mapFlaskEvent(raw, Date.now());
        setSnap(prev => {
          // Dedup by ip+timestamp to avoid double-counting
          const key = `${raw.ip}-${raw.timestamp}`;
          if (prev.recent.some(r => `${r.ip}-${r.timestamp}` === key)) return prev;

          const newRecent = [incoming, ...prev.recent].slice(0, 100);

          // Re-derive status: if there's any pending High, it's LOCKDOWN
          const hasPending  = newRecent.some(r => r.action === "pending");
          const hasAnyHigh  = newRecent.some(r => r.tier === "High");
          const newStatus: SystemStatus = hasPending ? "LOCKDOWN" : hasAnyHigh ? "THREAT" : "NORMAL";

          const newSnap = buildSnapshotFromEvents(
            newRecent,
            newStatus,
            prev.ledger,
            prev.totalBlockedIPs,
          );

          // Preserve the real running totals from the backend rather than
          // rebuilding from the in-memory slice (which is capped at 100).
          // Only increment — the next full poll will reconcile if needed.
          newSnap.tierCounts = {
            High:   prev.tierCounts.High   + (incoming.tier === "High"   ? 1 : 0),
            Medium: prev.tierCounts.Medium + (incoming.tier === "Medium" ? 1 : 0),
            Low:    prev.tierCounts.Low    + (incoming.tier === "Low"    ? 1 : 0),
            total:  prev.tierCounts.total  + 1,
          };

          return newSnap;
        });
      } catch {}
    });

    es.onerror = () => {};   // suppress noise; reconnect is automatic
    return () => es.close();
  }, []);

  return snap;
}

export { authHeaders };

// Shown until /api/metrics answers. Copied from evaluation/evaluation_metrics.json as written by
// ml/evaluate.py (macro averages on the synthetic test period, rounded to 4 places). Update both together.
// Rule-only systems have no probabilities, so no ROC-AUC (shown as 0).
const DEMO_ML_METRICS: MLMetricRow[] = [
  { model: "XGBoost (calibrated)", accuracy: 0.9993, precision: 0.9684, recall: 0.9798, f1: 0.974, auc: 0.9922, ensemble: true },
  { model: "XGBoost + cost policy", accuracy: 0.9992, precision: 0.9567, recall: 0.9877, f1: 0.9717, auc: 0.9922 },
  { model: "Random Forest (single, calibrated) + cost policy", accuracy: 0.9992, precision: 0.9579, recall: 0.987, f1: 0.972, auc: 0.9944 },
  { model: "Legacy 5-model ensemble", accuracy: 0.9989, precision: 0.9639, recall: 0.9517, f1: 0.9576, auc: 0.9997 },
  { model: "XGBoost + cost policy + rules (max tier)", accuracy: 0.9991, precision: 0.9525, recall: 0.9813, f1: 0.9665, auc: 0 },
  { model: "Expert rules only (thresholds)", accuracy: 0.7869, precision: 0.5431, recall: 0.8288, f1: 0.5563, auc: 0 },
  { model: "Rules only (deployed: failed logins)", accuracy: 0.9921, precision: 0.9759, recall: 0.5588, f1: 0.6509, auc: 0 },
];

export function useMLMetrics(): MLMetricRow[] {
  const [rows, setRows] = useState<MLMetricRow[]>(DEMO_ML_METRICS);

  const MODEL_LABELS: Record<string, string> = {
    RF: "RF (Random Forest)",
    GB: "GB (Gradient Boosting)",
    SVM: "SVM (Support Vector Machine)",
    LR: "LR (Logistic Regression)",
    XGB: "XGB (XGBoost)",
    "ENSEMBLE (weighted)": "ENSEMBLE (weighted)",
  };

  useEffect(() => {
    apiFetch("/api/metrics", { headers: authHeaders() })
      .then((r) => r.json())
      .then((data: { model: string; accuracy: number; precision: number; recall: number; f1: number; auc_roc: number }[]) => {
        if (Array.isArray(data) && data.length > 0) {
          setRows(
            data.map((m) => ({
              model: MODEL_LABELS[m.model] ?? m.model,
              accuracy: m.accuracy,
              precision: m.precision,
              recall: m.recall,
              f1: m.f1,
              auc: m.auc_roc,
              ensemble: m.model.toLowerCase().includes("ensemble"),
            }))
          );
        }
      })
      .catch(() => {});
  }, []);

  return rows;
}

export function formatMTTR(sinceMs: number): string {
  const total = Math.max(0, Math.floor((Date.now() - sinceMs) / 1000));
  const h = String(Math.floor(total / 3600)).padStart(2, "0");
  const m = String(Math.floor((total % 3600) / 60)).padStart(2, "0");
  const s = String(total % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}