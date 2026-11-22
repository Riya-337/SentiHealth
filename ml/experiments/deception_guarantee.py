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
from safe_deception import (DeceptionGate, clopper_pearson, conformal_threshold, group_excess, group_excess_clustered,  # noqa: E402
                            np_umbrella_threshold, sessionize)

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


def session_summary(d: pd.DataFrame) -> pd.DataFrame:
    """One row per session: whole-session maximum score, attack flag, group and attack family, and the
    user (column u) when the data has one."""
    fam = d["attack_family"].where(d["attack_family"] != "normal")
    agg = dict(m=("score", "max"), a=("is_attack", "max"), g=("group", "first"), f=("fam", "first"))
    if "user" in d.columns:
        agg["u"] = ("user", "first")
    return (d.assign(fam=fam).groupby("sess").agg(**agg)
            .assign(a=lambda x: x.a.astype(bool), f=lambda x: x.f.fillna("normal")))


def excess(dec_legit: np.ndarray, groups: np.ndarray, alpha: float) -> dict:
    """Per-role rates with 95 % intervals and the number of roles significantly above alpha (Holm)."""
    r = group_excess(dec_legit, groups, alpha, min_n=20)
    return {"per_group": {x["group"]: {k: x[k] for k in ("n", "deceived", "rate", "ci_low", "ci_high", "p_holm")} for x in r["groups"]},
            "n_groups": r["n_groups"], "n_significant": r["n_significant"]}


def excess_users(dec_legit: np.ndarray, groups: np.ndarray, users: np.ndarray, alpha: float) -> dict:
    """Per-role intervals and significance with users as clusters (sessions of one user are dependent)."""
    r = group_excess_clustered(dec_legit, groups, users, alpha, min_n=20)
    return {"per_group": {x["group"]: {k: x[k] for k in ("n", "users", "rate", "ci_low", "ci_high", "top_user_share", "p_holm")} for x in r["groups"]},
            "n_groups": r["n_groups"], "n_significant": r["n_significant"], "too_few_users": r["too_few_users"]}


def evaluate_gate(gate: DeceptionGate, d: pd.DataFrame, use_groups: bool) -> dict:
    dec = gate.decide_sessions(d["sess"].to_numpy(), d["score"].to_numpy(), d["group"].to_numpy() if use_groups else None)
    d = d.assign(noise=(dec["level"] != "none").to_numpy(), full=(dec["level"] == "full").to_numpy())
    s = d.groupby("sess").agg(attack=("is_attack", "max"), group=("group", "first"), noise=("noise", "max"), full=("full", "max"))
    s["attack"] = s["attack"].astype(bool)
    legit, att = s[~s.attack], s[s.attack]
    out = {
        "legit_sessions": int(len(legit)), "attack_sessions": int(len(att)),
        "legit_ever_noise": float(legit.noise.mean()) if len(legit) else None,
        "legit_deceived_count": int(legit.noise.sum()),
        "legit_ever_full": float(legit.full.mean()) if len(legit) else None,
        "attack_deceived": float(att.noise.mean()) if len(att) else None,
        "attack_full_decoy": float(att.full.mean()) if len(att) else None,
        "per_group_legit_ever_noise": {g: float(v.noise.mean()) for g, v in legit.groupby("group") if len(v) >= 20},
        "excess": excess(legit.noise.to_numpy(), legit.group.to_numpy(), gate.alpha_noise),
    }
    # share of the attacker's EHR reads / exported KB that happen after the session was put on decoys
    a = d[d.is_attack.astype(bool)]
    reads, kb = a["ehr_reads"].sum(), a["export_kb"].sum()
    out["attacker_reads_decoyed"] = float(a.loc[a.full, "ehr_reads"].sum() / reads) if reads else None
    out["attacker_export_decoyed"] = float(a.loc[a.full, "export_kb"].sum() / kb) if kb else None
    out["attacker_reads_noised_or_decoyed"] = float(a.loc[a.noise, "ehr_reads"].sum() / reads) if reads else None
    # per family session detection
    fam = d.assign(fam=d["attack_family"].where(d["attack_family"] != "normal")).groupby("sess").agg(f=("fam", "first"), dec=("noise", "max"))
    out["per_family_deceived"] = {k: float(v.dec.mean()) for k, v in fam.dropna(subset=["f"]).groupby("f")}
    return out


# --------------------------------------------------------------------------- baselines
def gate_from_thresholds(alpha: float, pooled_tau: float, group_taus: dict | None) -> DeceptionGate:
    """A gate with given noise thresholds, so baselines go through the same decision rule (running
    maximum, pooled threshold for unauthenticated traffic, never deceive an unseen staff role)."""
    g = DeceptionGate(alpha_noise=alpha, alpha_full=alpha, tau_noise=pooled_tau, tau_full=pooled_tau)
    g.group_tau = {k: {"noise": v, "full": v, "n": 0} for k, v in (group_taus or {}).items()}
    return g


def fast_eval(gate: DeceptionGate, ts: pd.DataFrame, use_groups: bool) -> dict:
    """Session-level evaluation from whole-session maxima: a session is ever deceived iff its maximum
    exceeds its threshold (the running maximum reaches the session maximum)."""
    tau = ts["g"].map(lambda g: gate.thresholds(g if use_groups else None)[0]).to_numpy(float)
    hit = ts["m"].to_numpy() > tau
    legit, att = ~ts["a"].to_numpy(), ts["a"].to_numpy()
    out = {"legit_ever_noise": float(hit[legit].mean()), "legit_deceived_count": int(hit[legit].sum()),
           "legit_sessions": int(legit.sum()), "attack_deceived": float(hit[att].mean()) if att.any() else None,
           "excess": excess(hit[legit], ts["g"].to_numpy()[legit], gate.alpha_noise)}
    if "u" in ts.columns:
        out["excess_users"] = excess_users(hit[legit], ts["g"].to_numpy()[legit], ts["u"].to_numpy()[legit], gate.alpha_noise)
    return out


def baselines(cal_events: pd.DataFrame, legit_cal: pd.DataFrame, ts: pd.DataFrame, alpha: float) -> dict:
    """Thresholding rules a reviewer would compare against, all evaluated on whole sessions."""
    groups = legit_cal.groupby("g")["m"]
    legit_events = cal_events[cal_events["sess"].isin(legit_cal.index)]
    rules = {
        # ConformalGuard-style: conformal on per-event scores, then applied at every event of a session
        "per_event_conformal": gate_from_thresholds(alpha, conformal_threshold(legit_events["score"].to_numpy(), alpha), None),
        # per-role empirical (1 - alpha) quantile of session maxima, no finite-sample correction
        "per_role_quantile": gate_from_thresholds(alpha, float(np.quantile(legit_cal["m"], 1 - alpha)),
                                                  {g: float(np.quantile(v, 1 - alpha)) for g, v in groups}),
        # per-role Neyman-Pearson umbrella: P(rate > alpha) <= 0.05 over the calibration draw
        "per_role_neyman_pearson": gate_from_thresholds(alpha, np_umbrella_threshold(legit_cal["m"].to_numpy(), alpha),
                                                        {g: np_umbrella_threshold(v.to_numpy(), alpha) for g, v in groups}),
    }
    return {name: fast_eval(g, ts, use_groups=name != "per_event_conformal") for name, g in rules.items()}


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
    # main protocol: time-ordered (earlier post-training sessions calibrate, later ones evaluate), as a
    # deployment would run; the random split is the exchangeable setting the theory assumes
    protocols = {"temporal": (spt == "val", spt == "test"), "random": (va, te)}
    for det, sc in S.items():
        block = {}
        for proto, (cmask, tmask) in protocols.items():
            cal = session_table(F, cmask, sc)
            cs = session_summary(cal)
            legit_cal = cs[~cs.a]
            test = session_table(F, tmask, sc)
            ts = session_summary(test)
            pb = {"n_cal_legit_sessions": int(len(legit_cal)), "pooled": {}, "mondrian": {}, "baselines": {}, "naive": []}
            for alpha in ALPHAS:
                g_pool = DeceptionGate(alpha_noise=alpha, alpha_full=alpha / 5).fit(legit_cal.m.to_numpy())
                g_mond = DeceptionGate(alpha_noise=alpha, alpha_full=alpha / 5).fit(legit_cal.m.to_numpy(), legit_cal.g.to_numpy())
                pb["pooled"][str(alpha)] = evaluate_gate(g_pool, test, use_groups=False)
                pb["mondrian"][str(alpha)] = evaluate_gate(g_mond, test, use_groups=True)
                if proto == "temporal":
                    pb["baselines"][str(alpha)] = baselines(cal, legit_cal, ts, alpha)
            if proto == "temporal":
                if det == "xgb":
                    pb["naive"] = [naive_baseline(test, thr) for thr in NAIVE_THRESHOLDS]
                # contamination: attack sessions mislabelled as legitimate in the calibration set.
                # 'random' draws any attack session (mostly high-scoring, i.e. detected ones);
                # 'stealthiest' takes the lowest-scoring ones, the attacks most likely to go unnoticed.
                att_cal = cs[cs.a].sort_values("m")
                rng = np.random.default_rng(seed)
                pb["contaminated"] = {}
                for mode in ("random", "stealthiest"):
                    for frac in contamination:
                        k = min(int(round(frac * len(legit_cal))), len(att_cal))
                        if mode == "random":
                            extra = att_cal.m.to_numpy()[rng.choice(len(att_cal), size=k, replace=False)] if k else np.array([])
                        else:
                            extra = att_cal.m.to_numpy()[:k]
                        g = DeceptionGate(alpha_noise=0.01, alpha_full=0.002).fit(np.concatenate([legit_cal.m.to_numpy(), extra]))
                        pb["contaminated"][f"{mode}_{frac}"] = fast_eval(g, ts, use_groups=False) | {"n_attack_sessions_added": int(k)}
            block[proto] = pb
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
def _pct(x) -> str:
    return "n/a" if x is None else f"{100 * x:.2f} %"


def _pooled_rate(blocks: list[dict]) -> tuple[float, float, float]:
    """Legitimate sessions deceived, pooled over seeds, with a 95 % Clopper-Pearson interval."""
    k = sum(b["legit_deceived_count"] for b in blocks)
    n = sum(b["legit_sessions"] for b in blocks)
    lo, hi = clopper_pearson(k, n)
    return k / n, lo, hi


def _worst_role(blocks: list[dict]) -> float:
    """Average each role's rate over seeds first, then take the worst role (a max over noisy
    single-seed rates would be biased upwards)."""
    per: dict = {}
    for b in blocks:
        for g, v in b["excess"]["per_group"].items():
            per.setdefault(g, []).append(v["rate"])
    return max((float(np.mean(v)) for v in per.values()), default=0.0)


def _significant(blocks: list[dict]) -> str:
    return f"{sum(b['excess']['n_significant'] for b in blocks)} / {sum(b['excess']['n_groups'] for b in blocks)}"


def _mean(blocks: list[dict], key: str):
    v = [b[key] for b in blocks if b.get(key) is not None]
    return float(np.mean(v)) if v else None


def summarise(runs: list[dict]) -> dict:
    out: dict = {}
    for det in runs[0]["detectors"]:
        out[det] = {}
        for proto in ("temporal", "random"):
            rows = []
            for alpha in ALPHAS:
                a = str(alpha)
                mond = [r["detectors"][det][proto]["mondrian"][a] for r in runs]
                pool = [r["detectors"][det][proto]["pooled"][a] for r in runs]
                rate, lo, hi = _pooled_rate(mond)
                rows.append({"alpha": alpha, "per_role_rate": rate, "per_role_ci": [lo, hi],
                             "per_role_worst_role": _worst_role(mond), "per_role_significant_roles": _significant(mond),
                             "shared_rate": _pooled_rate(pool)[0], "shared_worst_role": _worst_role(pool),
                             "shared_significant_roles": _significant(pool),
                             "attack_sessions_deceived": _mean(mond, "attack_deceived"),
                             "attacker_reads_decoyed": _mean(mond, "attacker_reads_decoyed")})
            out[det][proto] = rows
    return out


def write_report(runs: list[dict], summary: dict, args) -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "deception_guarantee.json"), "w") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "args": vars(args),
                   "summary": summary, "runs": runs}, f, indent=2, default=float)
    md = ["# Deception with a safety guarantee: measured results", "",
          f"Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}. **Synthetic data** (ml/simulate_events.py), "
          f"{len(runs)} seeds, {args.days} days, {args.users} users per seed. A session is ever deceived if the gate put it on noise or "
          "decoys at any event. Rates are pooled over seeds with a 95 % Clopper-Pearson interval; 'worst role' averages each role's "
          "rate over seeds, then takes the maximum; 'roles above alpha' counts roles whose rate is significantly above alpha "
          "(one-sided binomial test, Holm-corrected over roles, 5 %), summed over seeds.", "",
          "## Main result: time-ordered calibration", "",
          "Detectors are trained on the first half of the period. Within the rest, earlier sessions calibrate the gate and later "
          "sessions evaluate it, as a deployment would.", ""]
    head = ("| alpha | per-role gate: legit deceived [95 % CI] | worst role | roles above alpha | shared threshold: worst role | "
            "roles above alpha | attack sessions deceived | attacker reads on decoys |")
    for proto, title in (("temporal", None), ("random", "## Random split (exchangeable setting assumed by the theory)")):
        if title:
            md += [title, ""]
        for det, by_proto in summary.items():
            md += [f"**Detector: {det}**", "", head, "|---|---|---|---|---|---|---|---|"]
            for r in by_proto[proto]:
                lo, hi = r["per_role_ci"]
                md.append(f"| {r['alpha']} | {_pct(r['per_role_rate'])} [{_pct(lo)}, {_pct(hi)}] | {_pct(r['per_role_worst_role'])} | "
                          f"{r['per_role_significant_roles']} | {_pct(r['shared_worst_role'])} | {r['shared_significant_roles']} | "
                          f"{_pct(r['attack_sessions_deceived'])} | {_pct(r['attacker_reads_decoyed'])} |")
            md.append("")
    md += ["## Baselines (time-ordered calibration)", "",
           "All rules use the same running-maximum decision; only the threshold differs. *Per-event conformal* calibrates on "
           "individual event scores (as conformal false-positive control for alert gating does) instead of whole-session maxima. "
           "*Per-role quantile* uses each role's empirical (1 - alpha) quantile without the finite-sample correction. "
           "*Per-role Neyman-Pearson* (umbrella algorithm, delta = 0.05) bounds the rate with probability 0.95 over the calibration draw.", "",
           "| detector | alpha | rule | legit deceived | worst role | roles above alpha | attack sessions deceived |", "|---|---|---|---|---|---|---|"]
    for det in summary:
        for alpha in ALPHAS:
            a = str(alpha)
            rules = {"shared conformal": [r["detectors"][det]["temporal"]["pooled"][a] for r in runs],
                     "**per-role conformal (ours)**": [r["detectors"][det]["temporal"]["mondrian"][a] for r in runs]}
            for name in ("per_event_conformal", "per_role_quantile", "per_role_neyman_pearson"):
                rules[name.replace("_", " ")] = [r["detectors"][det]["temporal"]["baselines"][a][name] for r in runs]
            for name, bl in rules.items():
                md.append(f"| {det} | {alpha} | {name} | {_pct(_pooled_rate(bl)[0])} | {_pct(_worst_role(bl))} | {_significant(bl)} | "
                          f"{_pct(_mean(bl, 'attack_deceived'))} |")
    md.append("")
    nv = [n for r in runs for n in r["detectors"]["xgb"]["temporal"]["naive"]]
    if nv:
        md += ["## Fixed threshold on the detector's probability (no guarantee)", "",
               "| threshold | legit deceived | worst role | attack sessions deceived |", "|---|---|---|---|"]
        for thr in NAIVE_THRESHOLDS:
            sel = [n for n in nv if n["threshold"] == thr]
            md.append(f"| {thr} | {_pct(np.mean([s['legit_ever_deceived'] for s in sel]))} | {_pct(np.mean([s['worst_group_legit'] or 0 for s in sel]))} | "
                      f"{_pct(np.mean([s['attack_deceived'] for s in sel]))} |")
        md.append("")
    md += ["## Contaminated calibration (alpha = 0.01, shared threshold, time-ordered)", "",
           "Attack sessions mislabelled as legitimate, as a share of the legitimate calibration sessions. *Random*: any attack "
           "session (mostly detected, high-scoring ones). *Stealthiest*: the lowest-scoring attack sessions, the ones most likely "
           "to go unnoticed and be mislabelled in practice.", "",
           "| detector | contamination | share added | legit deceived [95 % CI] | attack sessions deceived |", "|---|---|---|---|---|"]
    for det in summary:
        for mode in ("random", "stealthiest"):
            for frac in args.contamination:
                bl = [r["detectors"][det]["temporal"]["contaminated"][f"{mode}_{frac}"] for r in runs]
                rate, lo, hi = _pooled_rate(bl)
                md.append(f"| {det} | {mode} | {frac} | {_pct(rate)} [{_pct(lo)}, {_pct(hi)}] | {_pct(_mean(bl, 'attack_deceived'))} |")
    if "drift" in runs[0]:
        md += ["", f"## Drift: legitimate read rates x{args.drift} after deployment (alpha = 0.01)", "",
               "| detector | stale calibration: legit deceived | recalibrated on 7 recent days | attack deceived (stale / recalibrated) |", "|---|---|---|---|"]
        for det in runs[0]["drift"]:
            if det == "factor":
                continue
            st = [r["drift"][det]["stale_calibration"] for r in runs]
            rc = [r["drift"][det]["recalibrated_on_recent_window"] for r in runs]
            md.append(f"| {det} | {_pct(_pooled_rate(st)[0])} | {_pct(_pooled_rate(rc)[0])} | {_pct(_mean(st, 'attack_deceived'))} / {_pct(_mean(rc, 'attack_deceived'))} |")
    md += ["", "## Reading the tables", "",
           "- The guarantee is P(legitimate session ever deceived) <= alpha under exchangeability; the per-role gate makes it hold inside each role.",
           "- The worst role is the maximum over several noisy estimates, so it can sit above alpha by chance; 'roles above alpha' tests whether any role is significantly above it.",
           "- Contamination is conservative only when the mislabelled sessions score above the clean threshold; low-scoring (stealthy) attacks can lower it.",
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
