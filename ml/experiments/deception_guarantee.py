"""
deception_guarantee.py — does the conformal deception gate keep its promise, and what does it cost?

For each simulator seed:
  1. simulate 14 days, build windowed features, temporal split (70 / 15 / 15 %);
  2. train two detectors on the training period: XGBoost (supervised) and Isolation Forest
     (normal rows only, unsupervised);
  3. sessionize (entity = user@ip, gap 30 min); a session is legitimate iff it has no attack record;
  4. calibrate the gate on the VALIDATION period's legitimate sessions (pooled and per role);
  5. evaluate on the TEST period: how often is a legitimate session ever deceived (vs alpha), overall
     and per role; how many attack sessions are deceived, how quickly, and what share of the
     attacker's reads/exports after deception are decoys.
Plus: a naive fixed-threshold baseline, calibration contamination, and a drift scenario with and
without recalibration on a recent window.

    python3 ml/experiments/deception_guarantee.py --seeds 5
Writes evaluation/deception_guarantee.json and evaluation/DECEPTION.md.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

_HERE = os.path.dirname(os.path.abspath(__file__))
_ML = os.path.dirname(_HERE)
_ROOT = os.path.dirname(_ML)
for p in (_ML, _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)
import simulate_events as sim  # noqa: E402
from features import FEATURE_NAMES, build_feature_table  # noqa: E402
from safe_deception import DeceptionGate, sessionize  # noqa: E402

ALPHAS = [0.10, 0.05, 0.02, 0.01, 0.005]
NAIVE_THRESHOLDS = [0.5, 0.75, 0.9]
STAFF_ROLES = ["nurse", "doctor", "admin", "billing", "it_staff"]
OUT_DIR = os.path.join(_ROOT, "evaluation")


# --------------------------------------------------------------------------- data
def make_dataset(seed: int, days: int, users: int, drift: float = 1.0) -> pd.DataFrame:
    """drift > 1 multiplies every role's normal read rate (e.g. a new EHR workflow)."""
    saved = dict(sim.ROLES)
    try:
        if drift != 1.0:
            sim.ROLES = {r: (v[0], v[1], v[2] * drift, v[3], v[4], v[5], v[6]) for r, v in saved.items()}
        recs = sim.Simulator(days, users, seed).run()
    finally:
        sim.ROLES = saved
    F = build_feature_table(pd.DataFrame(recs))
    F["ts"] = pd.to_datetime(F["ts"], utc=True)
    F = F.sort_values(["entity", "ts"], kind="stable").reset_index(drop=True)
    F["sess"] = sessionize(F)
    F["group"] = np.where(F["role"].isin(STAFF_ROLES), F["role"], "unauthenticated")
    return F


def split(F: pd.DataFrame, seed: int, train_frac: float = 0.5) -> np.ndarray:
    """Whole sessions, by session START time: the first train_frac of the period trains the detectors.
    The remaining sessions are split at random 50/50 into calibration ('val') and evaluation ('test'),
    which is the exchangeable setting split-conformal prediction assumes. (A time-ordered variant is
    reported separately.)"""
    start = F.groupby("sess")["ts"].transform("min")
    cut = F["ts"].min() + (F["ts"].max() - F["ts"].min()) * train_frac
    post_sessions = np.unique(F.loc[start >= cut, "sess"])
    rng = np.random.default_rng(seed + 17)
    cal = set(rng.choice(post_sessions, size=len(post_sessions) // 2, replace=False).tolist())
    in_cal = F["sess"].isin(cal).to_numpy()
    return np.where(start < cut, "train", np.where(in_cal, "val", "test"))


def temporal_split_post(F: pd.DataFrame, sp: np.ndarray) -> np.ndarray:
    """Time-ordered alternative inside the post-training period: earlier half of sessions calibrate,
    later half evaluate. Not exchangeable when the halves differ (weekday mix, shifts)."""
    start = F.groupby("sess")["ts"].transform("min")
    post = sp != "train"
    mid = start[post].quantile(0.5)
    return np.where(~post, "train", np.where(start < mid, "val", "test"))


def train_detectors(F: pd.DataFrame, tr: np.ndarray, seed: int):
    X, y = F.loc[tr, FEATURE_NAMES].to_numpy(float), F.loc[tr, "tier_label"].to_numpy(int)
    xgb = XGBClassifier(objective="multi:softprob", num_class=3, n_estimators=300, learning_rate=0.08, max_depth=6,
                        subsample=0.8, colsample_bytree=0.8, tree_method="hist", random_state=seed, n_jobs=-1)
    xgb.fit(X, y, sample_weight=compute_sample_weight("balanced", y))
    normal = tr & (F["attack_family"].to_numpy() == "normal")
    iso = IsolationForest(n_estimators=200, max_samples=min(8192, int(normal.sum())), random_state=seed, n_jobs=-1)
    iso.fit(F.loc[normal, FEATURE_NAMES].to_numpy(float))
    return xgb, iso


def scores(F: pd.DataFrame, xgb, iso) -> dict[str, np.ndarray]:
    X = F[FEATURE_NAMES].to_numpy(float)
    p = xgb.predict_proba(X)
    return {"xgb": p[:, 1] + p[:, 2], "iforest": -iso.score_samples(X)}


# --------------------------------------------------------------------------- evaluation
def session_table(F: pd.DataFrame, mask: np.ndarray, score: np.ndarray) -> pd.DataFrame:
    d = F.loc[mask, ["sess", "group", "is_attack", "attack_family", "ehr_reads", "export_kb", "ts"]].copy()
    d["score"] = score[mask]
    return d


def evaluate_gate(gate: DeceptionGate, d: pd.DataFrame, use_groups: bool) -> dict:
    dec = gate.decide_sessions(d["sess"].to_numpy(), d["score"].to_numpy(), d["group"].to_numpy() if use_groups else None)
    d = d.assign(level=dec["level"].to_numpy())
    s = d.groupby("sess").agg(attack=("is_attack", "max"), group=("group", "first"),
                              noise=("level", lambda x: bool((x != "none").any())),
                              full=("level", lambda x: bool((x == "full").any())))
    legit, att = s[~s.attack], s[s.attack]
    out = {
        "legit_sessions": int(len(legit)), "attack_sessions": int(len(att)),
        "legit_ever_noise": float(legit.noise.mean()) if len(legit) else None,
        "legit_ever_full": float(legit.full.mean()) if len(legit) else None,
        "attack_deceived": float(att.noise.mean()) if len(att) else None,
        "attack_full_decoy": float(att.full.mean()) if len(att) else None,
        "per_group_legit_ever_noise": {g: float(v.noise.mean()) for g, v in legit.groupby("group") if len(v) >= 20},
    }
    # share of the attacker's EHR reads / exported KB that happen after the session was put on decoys
    a = d[d.is_attack.astype(bool)]
    reads, kb = a["ehr_reads"].sum(), a["export_kb"].sum()
    out["attacker_reads_decoyed"] = float(a.loc[a.level == "full", "ehr_reads"].sum() / reads) if reads else None
    out["attacker_export_decoyed"] = float(a.loc[a.level == "full", "export_kb"].sum() / kb) if kb else None
    out["attacker_reads_noised_or_decoyed"] = float(a.loc[a.level != "none", "ehr_reads"].sum() / reads) if reads else None
    # per family session detection
    fam = d.groupby("sess").agg(f=("attack_family", lambda x: next((v for v in x if v != "normal"), "normal")),
                                dec=("level", lambda x: bool((x != "none").any())))
    out["per_family_deceived"] = {k: float(v.dec.mean()) for k, v in fam[fam.f != "normal"].groupby("f")}
    return out


def naive_baseline(d: pd.DataFrame, thr: float) -> dict:
    s = d.assign(hit=d.score > thr).groupby("sess").agg(attack=("is_attack", "max"), group=("group", "first"), hit=("hit", "max"))
    legit, att = s[~s.attack], s[s.attack]
    per = {g: float(v.hit.mean()) for g, v in legit.groupby("group") if len(v) >= 20}
    return {"threshold": thr, "legit_ever_deceived": float(legit.hit.mean()), "attack_deceived": float(att.hit.mean()),
            "per_group_legit": per, "worst_group_legit": max(per.values()) if per else None}


def run_seed(seed: int, days: int, users: int, contamination: list[float], drift: float) -> dict:
    t0 = time.time()
    F = make_dataset(seed, days, users)
    sp = split(F, seed)
    tr, va, te = sp == "train", sp == "val", sp == "test"
    spt = temporal_split_post(F, sp)
    xgb, iso = train_detectors(F, tr, seed)
    S = scores(F, xgb, iso)
    res = {"seed": seed, "rows": int(len(F)), "detectors": {}}
    for det, sc in S.items():
        cal = session_table(F, va, sc)
        cs = cal.groupby("sess").agg(m=("score", "max"), a=("is_attack", "max"), g=("group", "first"))
        legit_cal = cs[~cs.a]
        test = session_table(F, te, sc)
        block = {"n_cal_legit_sessions": int(len(legit_cal)), "pooled": {}, "mondrian": {}, "naive": [], "contaminated": {}}
        for alpha in ALPHAS:
            g_pool = DeceptionGate(alpha_noise=alpha, alpha_full=alpha / 5).fit(legit_cal.m.to_numpy())
            g_mond = DeceptionGate(alpha_noise=alpha, alpha_full=alpha / 5).fit(legit_cal.m.to_numpy(), legit_cal.g.to_numpy())
            block["pooled"][str(alpha)] = evaluate_gate(g_pool, test, use_groups=False)
            block["mondrian"][str(alpha)] = evaluate_gate(g_mond, test, use_groups=True)
        for thr in NAIVE_THRESHOLDS:
            if det == "xgb":
                block["naive"].append(naive_baseline(test, thr))
        # contamination: unlabeled attack sessions mixed into the calibration set
        att_cal = cs[cs.a]
        rng = np.random.default_rng(seed)
        for frac in contamination:
            k = int(round(frac * len(legit_cal)))
            extra = att_cal.m.to_numpy()[rng.choice(len(att_cal), size=min(k, len(att_cal)), replace=False)] if k and len(att_cal) else np.array([])
            cal_m = np.concatenate([legit_cal.m.to_numpy(), extra])
            g = DeceptionGate(alpha_noise=0.01, alpha_full=0.002).fit(cal_m)
            block["contaminated"][str(frac)] = evaluate_gate(g, test, use_groups=False) | {"n_attack_sessions_added": int(len(extra))}
        # time-ordered calibration (earlier half of the post period calibrates the later half)
        cal_t = session_table(F, spt == "val", sc).groupby("sess").agg(m=("score", "max"), a=("is_attack", "max"), g=("group", "first"))
        test_t = session_table(F, spt == "test", sc)
        g_t = DeceptionGate(alpha_noise=0.01, alpha_full=0.002).fit(cal_t[~cal_t.a].m.to_numpy(), cal_t[~cal_t.a].g.to_numpy())
        block["temporal_alpha_0.01"] = evaluate_gate(g_t, test_t, use_groups=True)
        res["detectors"][det] = block

    # drift: legitimate behaviour changes after deployment (read rates x drift); same detectors
    if drift != 1.0:
        D = make_dataset(seed + 1000, 14, users, drift=drift)
        SD = scores(D, xgb, iso)
        start_days = (D.groupby("sess")["ts"].transform("min") - D["ts"].min()).dt.total_seconds() / 86400
        recent = start_days < 7          # recalibration window: sessions that start in the first 7 days after the change
        later = start_days >= 7
        res["drift"] = {"factor": drift}
        for det, sc in SD.items():
            cal = session_table(F, va, S[det])
            legit_cal = cal.groupby("sess").agg(m=("score", "max"), a=("is_attack", "max")).query("~a")
            stale = DeceptionGate(alpha_noise=0.01, alpha_full=0.002).fit(legit_cal.m.to_numpy())
            dt = session_table(D, later.to_numpy(), sc)
            rc = session_table(D, recent.to_numpy(), sc).groupby("sess").agg(m=("score", "max"), a=("is_attack", "max")).query("~a")
            fresh = DeceptionGate(alpha_noise=0.01, alpha_full=0.002).fit(rc.m.to_numpy())
            res["drift"][det] = {"stale_calibration": evaluate_gate(stale, dt, False),
                                 "recalibrated_on_recent_window": evaluate_gate(fresh, dt, False),
                                 "n_recal_sessions": int(len(rc))}
    res["seconds"] = round(time.time() - t0, 1)
    return res


# --------------------------------------------------------------------------- report
def summarise(runs: list[dict]) -> dict:
    out: dict = {}
    for det in runs[0]["detectors"]:
        rows = []
        for alpha in ALPHAS:
            a = str(alpha)
            def vals(kind, key):
                v = [r["detectors"][det][kind][a][key] for r in runs if r["detectors"][det][kind][a][key] is not None]
                return (float(np.mean(v)), float(np.max(v))) if v else (None, None)
            def worst_group_mean(kind):
                # average each role's rate over seeds first, then take the worst role (a max over noisy
                # single-seed rates would be biased upwards)
                per = {}
                for r in runs:
                    for g, v in r["detectors"][det][kind][a]["per_group_legit_ever_noise"].items():
                        per.setdefault(g, []).append(v)
                return max((np.mean(v) for v in per.values()), default=0.0)
            worst_role = [worst_group_mean("mondrian")]
            worst_role_pooled = [worst_group_mean("pooled")]
            rows.append({
                "alpha": alpha,
                "pooled_legit_rate_mean_max": vals("pooled", "legit_ever_noise"),
                "pooled_worst_role_mean": float(np.mean(worst_role_pooled)),
                "mondrian_legit_rate_mean_max": vals("mondrian", "legit_ever_noise"),
                "mondrian_worst_role_mean": float(np.mean(worst_role)),
                "attack_sessions_deceived_mean": vals("mondrian", "attack_deceived")[0],
                "attacker_reads_decoyed_mean": vals("mondrian", "attacker_reads_decoyed")[0],
                "attacker_export_decoyed_mean": vals("mondrian", "attacker_export_decoyed")[0],
            })
        out[det] = rows
    return out


def write_report(runs: list[dict], summary: dict, args) -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "deception_guarantee.json"), "w") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "args": vars(args),
                   "summary": summary, "runs": runs}, f, indent=2, default=float)
    fmt = lambda x: "n/a" if x is None else f"{x:.4f}"
    md = ["# Deception with a safety guarantee: measured results", "",
          f"Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}. **Synthetic data** (ml/simulate_events.py), "
          f"{len(runs)} seeds, {args.days} days, {args.users} users per seed. Calibration on the validation period's legitimate sessions, "
          "evaluation on the test period. 'Legit rate' = share of legitimate sessions that were EVER served noise or decoys.", ""]
    for det, rows in summary.items():
        md += [f"## Detector: {det}", "",
               "| alpha | legit rate pooled (mean / max over seeds) | worst role, pooled | legit rate per-role gate (mean / max) | worst role, per-role gate | attack sessions deceived | attacker reads on decoys | attacker export on decoys |",
               "|---|---|---|---|---|---|---|---|"]
        for r in rows:
            pm, px = r["pooled_legit_rate_mean_max"]
            mm, mx = r["mondrian_legit_rate_mean_max"]
            md.append(f"| {r['alpha']} | {fmt(pm)} / {fmt(px)} | {fmt(r['pooled_worst_role_mean'])} | {fmt(mm)} / {fmt(mx)} | {fmt(r['mondrian_worst_role_mean'])} | "
                      f"{fmt(r['attack_sessions_deceived_mean'])} | {fmt(r['attacker_reads_decoyed_mean'])} | {fmt(r['attacker_export_decoyed_mean'])} |")
        md.append("")
    nv = [n for r in runs for n in r["detectors"]["xgb"]["naive"]]
    if nv:
        md += ["## Baseline: fixed threshold on the detector's probability (no guarantee)", "",
               "| threshold | legit rate (mean over seeds) | worst role (mean) | attack sessions deceived |", "|---|---|---|---|"]
        for thr in NAIVE_THRESHOLDS:
            sel = [n for n in nv if n["threshold"] == thr]
            md.append(f"| {thr} | {fmt(np.mean([s['legit_ever_deceived'] for s in sel]))} | {fmt(np.mean([s['worst_group_legit'] or 0 for s in sel]))} | {fmt(np.mean([s['attack_deceived'] for s in sel]))} |")
        md.append("")
    md += ["## Time-ordered calibration (alpha = 0.01, per-role gate)", "",
           "Earlier half of the post-training sessions calibrates, later half is evaluated (not exchangeable if the halves differ).", "",
           "| detector | legit rate (mean / max over seeds) | attack sessions deceived (mean) |", "|---|---|---|"]
    for det in runs[0]["detectors"]:
        sel = [r["detectors"][det]["temporal_alpha_0.01"] for r in runs]
        md.append(f"| {det} | {fmt(np.mean([s['legit_ever_noise'] for s in sel]))} / {fmt(np.max([s['legit_ever_noise'] for s in sel]))} | {fmt(np.mean([s['attack_deceived'] for s in sel]))} |")
    md.append("")
    md += ["## Contaminated calibration (alpha = 0.01, xgb)", "", "| attack sessions added (as share of legit) | legit rate (mean) | attack sessions deceived (mean) |", "|---|---|---|"]
    for frac in args.contamination:
        sel = [r["detectors"]["xgb"]["contaminated"][str(frac)] for r in runs]
        md.append(f"| {frac} | {fmt(np.mean([s['legit_ever_noise'] for s in sel]))} | {fmt(np.mean([s['attack_deceived'] for s in sel]))} |")
    if "drift" in runs[0]:
        md += ["", f"## Drift: legitimate read rates x{args.drift} after deployment (alpha = 0.01)", "",
               "| detector | stale calibration: legit rate | recalibrated on 7 recent days: legit rate | attack deceived (stale / recalibrated) |", "|---|---|---|---|"]
        for det in runs[0]["drift"]:
            if det == "factor":
                continue
            st = [r["drift"][det]["stale_calibration"] for r in runs]
            rc = [r["drift"][det]["recalibrated_on_recent_window"] for r in runs]
            md.append(f"| {det} | {fmt(np.mean([s['legit_ever_noise'] for s in st]))} | {fmt(np.mean([s['legit_ever_noise'] for s in rc]))} | "
                      f"{fmt(np.mean([s['attack_deceived'] for s in st]))} / {fmt(np.mean([s['attack_deceived'] for s in rc]))} |")
    md += ["", "## Reading the table", "",
           "- The guarantee is P(legitimate session ever deceived) <= alpha under exchangeability; the per-role gate makes it hold inside each role.",
           "- 'max over seeds' can exceed alpha by sampling noise because each seed has a finite number of test sessions.",
           "- All numbers are on simulated data written by the same author as the detector; they test the method's mechanics, not real-world performance."]
    with open(os.path.join(OUT_DIR, "DECEPTION.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--days", type=int, default=28)
    ap.add_argument("--users", type=int, default=300)
    ap.add_argument("--contamination", type=float, nargs="*", default=[0.0, 0.01, 0.05])
    ap.add_argument("--drift", type=float, default=1.8)
    args = ap.parse_args()
    runs = []
    for s in range(args.seeds):
        r = run_seed(s, args.days, args.users, args.contamination, args.drift)
        print(f"seed {s}: {r['rows']:,} rows, {r['seconds']} s", flush=True)
        runs.append(r)
    write_report(runs, summarise(runs), args)


if __name__ == "__main__":
    main()
