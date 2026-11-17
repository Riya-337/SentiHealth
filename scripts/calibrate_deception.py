#!/usr/bin/env python3
"""
calibrate_deception.py — fit Mirage's deception gate from this installation's own legitimate traffic.

Reads logs/threat_log.json, groups entries into sessions (same IP, gap <= 30 min), keeps sessions that
are known to be legitimate (no High tier, never blocked/confirmed, and not labelled 'attack' by an
analyst; sessions an analyst labelled 'benign' are always kept), and fits the split-conformal gate on
their maximum risk score. Writes models/deception_gate.json, which deception/mirage.py uses.

    python3 scripts/calibrate_deception.py --alpha-noise 0.01 --alpha-full 0.002 [--days 14]
    python3 scripts/calibrate_deception.py --check     # realised rate on recent verified-legit sessions

With too few legitimate sessions for the requested alpha the threshold is infinite and Mirage never
deceives (fail-safe). The bound needs about 1/alpha sessions per role.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_ROOT, os.path.join(_ROOT, "ml")):
    if p not in sys.path:
        sys.path.insert(0, p)
from _paths import MODELS_DIR, THREAT_LOG, RETRAINING_QUEUE  # noqa: E402
from safe_deception import DeceptionGate, monitor, sessionize  # noqa: E402

GATE_PATH = os.path.join(MODELS_DIR, "deception_gate.json")
CONFIRMED = {"forensics_generated", "auto-locked", "blocked"}


def load_sessions(days: int) -> pd.DataFrame:
    rows = []
    if os.path.exists(THREAT_LOG):
        with open(THREAT_LOG, encoding="utf-8") as f:
            for line in f:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    if not rows:
        return pd.DataFrame()
    d = pd.DataFrame(rows)
    d["ts"] = pd.to_datetime(d["timestamp"], utc=True, errors="coerce", format="ISO8601")
    d = d[d["ts"] >= datetime.now(timezone.utc) - timedelta(days=days)].dropna(subset=["ts"])
    d = d.rename(columns={"ip": "entity"}).sort_values(["entity", "ts"]).reset_index(drop=True)
    d["sess"] = sessionize(d)
    labels = {}
    if os.path.exists(RETRAINING_QUEUE):
        try:
            for e in json.load(open(RETRAINING_QUEUE)):
                if e.get("source") == "dashboard":
                    labels[e.get("ip")] = e.get("label")
        except (json.JSONDecodeError, OSError):
            pass
    s = d.groupby("sess").agg(entity=("entity", "first"), m=("score", "max"), high=("tier", lambda x: (x == "High").any()),
                              confirmed=("action", lambda x: bool(set(x) & CONFIRMED)),
                              group=("role", "first") if "role" in d else ("entity", lambda x: "unauthenticated"))
    s["label"] = s["entity"].map(labels)
    s["legit"] = (s["label"] == "benign") | ((s["label"] != "attack") & ~s["high"] & ~s["confirmed"])
    return s


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--alpha-noise", type=float, default=0.01)
    ap.add_argument("--alpha-full", type=float, default=0.002)
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    s = load_sessions(a.days)
    if s.empty:
        print("no sessions in the threat log yet; Mirage stays fail-safe (no gate file means no decoys)")
        return 0
    legit = s[s.legit]
    if a.check:
        if not os.path.exists(GATE_PATH):
            print("no gate fitted yet")
            return 0
        gate = DeceptionGate.from_json(open(GATE_PATH).read())
        ever = np.array([m > gate.thresholds(g if gate.group_tau else None)[0] for m, g in zip(legit.m, legit.group)])
        rep = monitor(ever, gate.alpha_noise)
        print(json.dumps(rep, indent=2))
        return 2 if rep["violated"] else 0
    gate = DeceptionGate(alpha_noise=a.alpha_noise, alpha_full=a.alpha_full).fit(legit.m.to_numpy(), legit.group.to_numpy())
    os.makedirs(MODELS_DIR, exist_ok=True)
    payload = json.loads(gate.to_json())
    payload.update({"score": "threat_log.score (session maximum)", "fitted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "window_days": a.days, "n_legit_sessions": int(len(legit))})
    with open(GATE_PATH, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"fitted on {len(legit)} legitimate sessions: tau_noise={gate.tau_noise} tau_full={gate.tau_full} -> {GATE_PATH}")
    if not np.isfinite(gate.tau_noise):
        print(f"note: need about {int(np.ceil(1 / a.alpha_noise))} legitimate sessions for alpha={a.alpha_noise}; Mirage will not deceive until then")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
