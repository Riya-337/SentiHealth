"""
cert_sessions.py — the deception gate on real event sequences from CERT Insider Threat r4.2.

ml/datasets/cert_r42.py scores one row per user-day, so it tests a single decision per day. The
method's claim is about sessions: the gate re-decides at every event and must bound the chance that a
legitimate session is EVER deceived. This experiment tests that claim on CERT's own event logs.

Events    logon / logoff, USB connect, file copy and e-mail events (data/external/cert/r4.2, written by
          `cert_r42.py extract`). Web browsing is only kept as daily totals, so it is not part of the
          sessions; this also keeps the scenario-specific web keywords out of the detector.
Sessions  one user's events with no gap longer than SESSION_GAP_MIN (30) minutes.
Scores    at every event, from the session so far (counts of each event type, after-hours events, USB,
          executables and archives copied, external recipients, attachments, PC changes, elapsed time)
          and the user's own previous 30 days (from user_days.csv.gz, past days only).
Labels    an event is positive once its session has contained a malicious event (answer key); a
          session is malicious if it contains one.
Protocol  detectors trained on sessions that start in the first half of the period. Main result:
          time-ordered calibration (earlier half of the remaining sessions calibrates, later half
          evaluates). Secondary: random split of the remaining sessions. Baselines, per-role intervals
          and contamination as in ml/experiments/deception_guarantee.py.

    python3 ml/datasets/cert_r42.py extract && python3 ml/datasets/cert_r42.py features   # once
    python3 ml/datasets/cert_sessions.py [--seeds 5]   -> evaluation/CERT_SESSIONS.md, evaluation/cert_sessions.json
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

_HERE = os.path.dirname(os.path.abspath(__file__))
_ML = os.path.dirname(_HERE)
_ROOT = os.path.dirname(_ML)
for p in (_HERE, _ML, os.path.join(_ML, "experiments"), _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)
import cert_r42 as base  # noqa: E402
from deception_guarantee import baselines, excess, excess_users, fast_eval, session_summary  # noqa: E402
from safe_deception import SESSION_GAP_MIN, DeceptionGate, clopper_pearson  # noqa: E402

ALPHAS = [0.10, 0.05, 0.01, 0.005]
CONTAMINATION = [0.0, 0.01, 0.05]
MIN_GROUP_SESSIONS = 800        # roles with fewer post-training sessions share one group ("other_roles")
RECAL_WINDOW_DAYS = 60          # rolling recalibration: legitimate sessions of the previous 60 days
CACHE = os.path.join(base.DIR, "session_events.pkl")
BASE_COLS = ["logon_n", "logon_after", "usb_n", "file_n", "email_n", "email_ext"]
CUM_COLS = ["is_logon", "is_usb", "is_file", "is_email", "after", "exe", "archive", "ext", "att", "bcc", "pc_change"]


# --------------------------------------------------------------------------- events and features
def load_events() -> pd.DataFrame:
    bad = base.malicious_ids()
    lg = base._read_events("logon.csv", ["id", "date", "user", "pc", "activity"])
    lg["kind"] = np.where(lg["activity"] == "Logon", "logon", "logoff")
    dv = base._read_events("device.csv", ["id", "date", "user", "pc", "activity"])
    dv = dv[dv["activity"] == "Connect"].assign(kind="usb")
    fl = base._read_events("file.csv", ["id", "date", "user", "pc", "filename"])
    ext = fl["filename"].str.extract(r"\.([A-Za-z0-9]+)$")[0].str.lower()
    fl = fl.assign(kind="file", exe=ext.isin(["exe", "dll", "bat"]).astype(int), archive=ext.isin(["zip", "rar", "7z"]).astype(int))
    em = base._read_events("email_headers.csv", ["id", "date", "user", "pc", "to", "cc", "bcc", "attachments"])
    rcpt = em["to"].fillna("") + ";" + em["cc"].fillna("") + ";" + em["bcc"].fillna("")
    em = em.assign(kind="email", ext=rcpt.str.count(r"@(?!dtaa\.com)"), att=(em["attachments"].fillna(0) > 0).astype(int),
                   bcc=em["bcc"].notna().astype(int))
    cols = ["id", "date", "day", "user", "pc", "kind", "after", "exe", "archive", "ext", "att", "bcc"]
    E = pd.concat([d.reindex(columns=cols) for d in (lg, dv, fl, em)], ignore_index=True)
    for c in ["exe", "archive", "ext", "att", "bcc"]:
        E[c] = E[c].fillna(0).astype(np.int32)
    E["mal"] = E["id"].isin(bad)
    return E.drop(columns=["id"]).sort_values(["user", "date"], kind="stable").reset_index(drop=True)


def build_session_table() -> pd.DataFrame:
    if os.path.exists(CACHE):
        return pd.read_pickle(CACHE)
    t0 = time.time()
    E = load_events()
    print(f"[{time.time() - t0:.0f}s] {len(E):,} events, {int(E.mal.sum()):,} malicious", flush=True)

    new = (E["user"] != E["user"].shift()) | (E["date"].diff() > pd.Timedelta(minutes=SESSION_GAP_MIN))
    E["sess"] = new.cumsum().astype(np.int64)
    for k in ("logon", "usb", "file", "email"):
        E[f"is_{k}"] = (E["kind"] == k).astype(np.int32)
    E["pc_change"] = ((E["pc"] != E.groupby("sess")["pc"].shift()) & E.groupby("sess").cumcount().gt(0)).astype(np.int32)
    g = E.groupby("sess")
    cum = g[CUM_COLS].cumsum()
    E[[f"s_{c}" for c in CUM_COLS]] = cum.to_numpy(np.float32)
    E["s_events"] = (g.cumcount() + 1).astype(np.float32)
    E["s_minutes"] = ((E["date"] - g["date"].transform("min")).dt.total_seconds() / 60).astype(np.float32)
    E["hour"] = E["date"].dt.hour.astype(np.float32)
    E["weekend"] = (E["date"].dt.weekday >= 5).astype(np.float32)
    E["label"] = g["mal"].cummax().astype(bool)          # session so far contains a malicious event
    E["sess_mal"] = g["mal"].transform("max").astype(bool)

    # the user's own previous 30 days (past days only) and the role of that day, from user_days
    U = pd.read_csv(os.path.join(base.DIR, "user_days.csv.gz"), usecols=["user", "day", "role", *BASE_COLS], parse_dates=["day"])
    U = U.sort_values(["user", "day"])
    for c in BASE_COLS:
        U[f"base_{c}"] = U.groupby("user")[c].transform(lambda s: s.shift(1).rolling(30, min_periods=5).mean()).astype(np.float32)
    E["day"] = pd.to_datetime(E["day"])
    E = E.merge(U[["user", "day", "role", *[f"base_{c}" for c in BASE_COLS]]], on=["user", "day"], how="left")
    E["role"] = E["role"].fillna("unknown")
    for s, b in (("s_is_logon", "base_logon_n"), ("s_is_usb", "base_usb_n"), ("s_is_file", "base_file_n"),
                 ("s_is_email", "base_email_n"), ("s_ext", "base_email_ext"), ("s_after", "base_logon_after")):
        E[f"r_{s[2:]}"] = (E[s] / (E[b].fillna(0) + 1.0)).astype(np.float32)
    E = E.drop(columns=["pc", "kind", "day"])
    E.to_pickle(CACHE)
    print(f"[{time.time() - t0:.0f}s] {E.sess.nunique():,} sessions ({int(E.groupby('sess').sess_mal.first().sum())} malicious) -> {CACHE}", flush=True)
    return E


def feature_names(E: pd.DataFrame) -> list[str]:
    return ([f"s_{c}" for c in CUM_COLS] + ["s_events", "s_minutes", "hour", "weekend"]
            + [f"base_{c}" for c in BASE_COLS] + [c for c in E.columns if c.startswith("r_")])


# --------------------------------------------------------------------------- experiment
def timing(d: pd.DataFrame, gate: DeceptionGate) -> float | None:
    """Share of insiders' malicious events that happen after their session was put on deception."""
    m = d[d["sess_mal"]]
    if m.empty or not m["mal"].any():
        return None
    run = m.groupby("sess")["score"].cummax().to_numpy()
    tau = m["group"].map(lambda g: gate.thresholds(g)[0]).to_numpy(float)
    deceived = run > tau
    return float(deceived[m["mal"].to_numpy()].mean())


def _decisions(gate: DeceptionGate, ts: pd.DataFrame, use_groups: bool) -> pd.DataFrame:
    tau = ts["g"].map(lambda g: gate.thresholds(g if use_groups else None)[0]).to_numpy(float)
    return pd.DataFrame({"hit": ts["m"].to_numpy() > tau, "a": ts["a"].to_numpy(), "g": ts["g"].to_numpy(), "u": ts["u"].to_numpy()})


def _summarise_decisions(d: pd.DataFrame, alpha: float) -> dict:
    legit = d[~d.a]
    return {"legit_ever_noise": float(legit.hit.mean()), "legit_deceived_count": int(legit.hit.sum()), "legit_sessions": int(len(legit)),
            "attack_deceived": float(d[d.a].hit.mean()) if d.a.any() else None,
            "excess": excess(legit.hit.to_numpy(), legit.g.to_numpy(), alpha),
            "excess_users": excess_users(legit.hit.to_numpy(), legit.g.to_numpy(), legit.u.to_numpy(), alpha)}


def rolling(D: pd.DataFrame, start: pd.Series, tr: np.ndarray, mid, block: dict) -> dict:
    """Drift check and remedy on the time-ordered evaluation period. 'static': the gate calibrated once
    on the first half of the post-training period, evaluated month by month. 'rolling': before each
    evaluation month the gate is recalibrated on the legitimate sessions of the previous
    RECAL_WINDOW_DAYS (post-training data only)."""
    s_start = start.to_numpy()
    month = start.dt.to_period("M").to_numpy()
    eval_months = sorted(set(month[~tr & (s_start >= np.datetime64(mid))]))
    out = {"window_days": RECAL_WINDOW_DAYS, "months": [str(m) for m in eval_months], "static_by_month": {}, "rolling": {}}
    cal_static = session_summary(D[~tr & (s_start < np.datetime64(mid))])
    legit_static = cal_static[~cal_static.a]
    for alpha in ALPHAS:
        a = str(alpha)
        g_static = DeceptionGate(alpha_noise=alpha, alpha_full=alpha).fit(legit_static.m.to_numpy(), legit_static.g.to_numpy())
        static_rates, parts = [], {"per_role": [], "shared": []}
        for m in eval_months:
            m0 = np.datetime64(m.start_time)
            test = (month == m) & (s_start >= np.datetime64(mid))
            ts = session_summary(D[test])
            dl = _decisions(g_static, ts, True)
            static_rates.append(float(dl[~dl.a].hit.mean()))
            cal = ~tr & (s_start >= m0 - np.timedelta64(RECAL_WINDOW_DAYS, "D")) & (s_start < m0)
            cs = session_summary(D[cal])
            legit = cs[~cs.a]
            parts["per_role"].append(_decisions(DeceptionGate(alpha_noise=alpha, alpha_full=alpha).fit(legit.m.to_numpy(), legit.g.to_numpy()), ts, True))
            parts["shared"].append(_decisions(DeceptionGate(alpha_noise=alpha, alpha_full=alpha).fit(legit.m.to_numpy()), ts, False))
        out["static_by_month"][a] = static_rates
        out["rolling"][a] = {k: _summarise_decisions(pd.concat(v, ignore_index=True), alpha) for k, v in parts.items()}
    return out


def run_seed(E: pd.DataFrame, feats: list[str], seed: int) -> dict:
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import average_precision_score, roc_auc_score
    from xgboost import XGBClassifier

    t0 = time.time()
    start = E.groupby("sess")["date"].transform("min")
    cut = E["date"].min() + (E["date"].max() - E["date"].min()) * 0.5
    tr = (start < cut).to_numpy()
    X, y = E[feats].to_numpy(np.float32), E["label"].to_numpy()
    xgb = XGBClassifier(n_estimators=300, learning_rate=0.08, max_depth=6, subsample=0.8, colsample_bytree=0.8,
                        tree_method="hist", random_state=seed, n_jobs=-1,
                        scale_pos_weight=float((~y[tr]).sum() / max(y[tr].sum(), 1)))
    xgb.fit(X[tr], y[tr])
    normal = tr & ~E["sess_mal"].to_numpy()
    iso = IsolationForest(n_estimators=200, max_samples=8192, random_state=seed, n_jobs=-1).fit(X[normal])
    S = {"xgb": xgb.predict_proba(X)[:, 1], "iforest": -iso.score_samples(X)}
    print(f"  seed {seed}: detectors trained in {time.time() - t0:.0f}s", flush=True)

    post_sess = np.unique(E.loc[~tr, "sess"])
    mid = start[~tr].quantile(0.5)
    rng = np.random.default_rng(seed + 17)
    rand_cal = set(rng.choice(post_sess, size=len(post_sess) // 2, replace=False).tolist())
    in_rand_cal = E["sess"].isin(rand_cal).to_numpy()
    protocols = {"temporal": (~tr & (start < mid).to_numpy(), ~tr & (start >= mid).to_numpy()),
                 "random": (~tr & in_rand_cal, ~tr & ~in_rand_cal)}

    res = {"seed": seed, "detectors": {}}
    for det, sc in S.items():
        D = pd.DataFrame({"sess": E["sess"].to_numpy(), "score": sc, "is_attack": E["sess_mal"].to_numpy(),
                          "mal": E["mal"].to_numpy(), "sess_mal": E["sess_mal"].to_numpy(), "group": E["group"].to_numpy(), "user": E["user"].to_numpy(),
                          "attack_family": np.where(E["sess_mal"].to_numpy(), "insider", "normal")})
        post = ~tr
        sess_post = D[post].groupby("sess").agg(m=("score", "max"), a=("is_attack", "max"))
        block = {"session_roc_auc": float(roc_auc_score(sess_post.a, sess_post.m)),
                 "session_pr_auc": float(average_precision_score(sess_post.a, sess_post.m))}
        for proto, (cmask, tmask) in protocols.items():
            cal, test = D[cmask], D[tmask]
            cs, ts = session_summary(cal), session_summary(test)
            legit_cal = cs[~cs.a]
            pb = {"n_cal_legit_sessions": int(len(legit_cal)), "n_test_sessions": int(len(ts)),
                  "n_test_malicious_sessions": int(ts.a.sum()), "shared": {}, "per_role": {}, "baselines": {}}
            for alpha in ALPHAS:
                a = str(alpha)
                g_shared = DeceptionGate(alpha_noise=alpha, alpha_full=alpha).fit(legit_cal.m.to_numpy())
                g_role = DeceptionGate(alpha_noise=alpha, alpha_full=alpha).fit(legit_cal.m.to_numpy(), legit_cal.g.to_numpy())
                pb["shared"][a] = fast_eval(g_shared, ts, use_groups=False)
                pb["per_role"][a] = fast_eval(g_role, ts, use_groups=True) | {"malicious_events_after_deception": timing(test, g_role)}
                if proto == "temporal":
                    pb["baselines"][a] = baselines(cal, legit_cal, ts, alpha)
            if proto == "temporal":
                att_cal = cs[cs.a].sort_values("m")
                pb["contaminated"] = {}
                for mode in ("random", "stealthiest"):
                    for frac in CONTAMINATION:
                        k = min(int(round(frac * len(legit_cal))), len(att_cal))
                        extra = (att_cal.m.to_numpy()[rng.choice(len(att_cal), size=k, replace=False)] if mode == "random"
                                 else att_cal.m.to_numpy()[:k]) if k else np.array([])
                        g = DeceptionGate(alpha_noise=0.01, alpha_full=0.01).fit(np.concatenate([legit_cal.m.to_numpy(), extra]))
                        pb["contaminated"][f"{mode}_{frac}"] = fast_eval(g, ts, use_groups=False) | {"n_attack_sessions_added": int(k)}
            block[proto] = pb
        block["rolling"] = rolling(D, start, tr, mid, block)
        res["detectors"][det] = block
    res["seconds"] = round(time.time() - t0, 1)
    print(f"  seed {seed} done in {res['seconds']}s", flush=True)
    return res


# --------------------------------------------------------------------------- report
def _pct(x) -> str:
    return "n/a" if x is None else f"{100 * x:.2f} %"


def _rate(blocks: list[dict]) -> tuple[float, float, float]:
    k, n = sum(b["legit_deceived_count"] for b in blocks), sum(b["legit_sessions"] for b in blocks)
    return (k / n, *clopper_pearson(k, n))


def _worst(blocks: list[dict]) -> float:
    per: dict = {}
    for b in blocks:
        for g, v in b["excess"]["per_group"].items():
            per.setdefault(g, []).append(v["rate"])
    return max((float(np.mean(v)) for v in per.values()), default=0.0)


def _sig(blocks: list[dict]) -> str:
    """Role-seeds significantly above alpha: treating sessions as independent, and (in brackets) with
    users as clusters."""
    s = f"{sum(b['excess']['n_significant'] for b in blocks)} / {sum(b['excess']['n_groups'] for b in blocks)}"
    if all("excess_users" in b for b in blocks):
        s += f" ({sum(b['excess_users']['n_significant'] for b in blocks)} / {sum(b['excess_users']['n_groups'] for b in blocks)})"
    return s


def _mean(blocks: list[dict], key: str):
    v = [b[key] for b in blocks if b.get(key) is not None]
    return float(np.mean(v)) if v else None


def write_report(runs: list[dict], info: dict) -> None:
    os.makedirs(base.OUT, exist_ok=True)
    with open(os.path.join(base.OUT, "cert_sessions.json"), "w") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "info": info, "runs": runs}, f, separators=(",", ":"), default=float)
    dets = list(runs[0]["detectors"])
    md = ["# CERT r4.2 sessions: the deception gate on real event sequences", "",
          f"Public synthetic benchmark (CMU SEI). {info['events']:,} logon, USB, file and e-mail events from {info['users']:,} users, "
          f"grouped into {info['sessions']:,} sessions (no gap over {SESSION_GAP_MIN} min), {info['malicious_sessions']:,} of them containing "
          f"malicious events; {info['groups']} role groups. The gate re-decides at every event; a session counts as deceived if it was "
          f"deceived at any event. Mean of {len(runs)} seeds. Rates are pooled over seeds with a 95 % Clopper-Pearson interval; 'worst role' "
          "averages each role over seeds, then takes the maximum; 'roles above alpha' counts role-seeds significantly above alpha "
          "(Holm-corrected, 5 %), summed over seeds, first treating sessions as independent (one-sided binomial test) and, in "
          "brackets, with users as clusters (user-level bootstrap over roles with at least 5 users; smaller roles cannot be tested "
          "as roles). Sessions of one person are dependent, so the bracketed count is the one to rely on.", "",
          "Session-level detection on the post-training period (session maximum score): " +
          "; ".join(f"{d} ROC-AUC {np.mean([r['detectors'][d]['session_roc_auc'] for r in runs]):.3f}, "
                    f"PR-AUC {np.mean([r['detectors'][d]['session_pr_auc'] for r in runs]):.3f}" for d in dets) + ".", ""]
    head = ("| alpha | per-role gate: legit sessions deceived [95 % CI] | worst role | roles above alpha | shared threshold: worst role | "
            "roles above alpha | malicious sessions deceived | malicious events after deception |")
    for proto, title in (("temporal", "## Main result: time-ordered calibration"), ("random", "## Random split (exchangeable setting)")):
        md += [title, ""]
        for det in dets:
            md += [f"**Detector: {det}**", "", head, "|---|---|---|---|---|---|---|---|"]
            for alpha in ALPHAS:
                a = str(alpha)
                role = [r["detectors"][det][proto]["per_role"][a] for r in runs]
                shared = [r["detectors"][det][proto]["shared"][a] for r in runs]
                rate, lo, hi = _rate(role)
                md.append(f"| {alpha} | {_pct(rate)} [{_pct(lo)}, {_pct(hi)}] | {_pct(_worst(role))} | {_sig(role)} | {_pct(_worst(shared))} | "
                          f"{_sig(shared)} | {_pct(_mean(role, 'attack_deceived'))} | {_pct(_mean(role, 'malicious_events_after_deception'))} |")
            md.append("")
    md += ["## Drift and rolling recalibration", "",
           f"*Static*: the time-ordered gate above (calibrated once), its legitimate-session rate in each evaluation month. *Rolling*: "
           f"before each evaluation month the gate is recalibrated on the legitimate sessions of the previous {RECAL_WINDOW_DAYS} days.", ""]
    for det in dets:
        months = runs[0]["detectors"][det]["rolling"]["months"]
        md += [f"**Detector: {det}**", "",
               "| alpha | static per-role gate, by month (" + ", ".join(months) + ") | rolling per-role: legit deceived [95 % CI] | worst role | "
               "roles above alpha | rolling shared: worst role | roles above alpha | malicious sessions deceived (rolling per-role) |",
               "|---|---|---|---|---|---|---|---|"]
        for alpha in ALPHAS:
            a = str(alpha)
            by_month = np.mean([r["detectors"][det]["rolling"]["static_by_month"][a] for r in runs], axis=0)
            role = [r["detectors"][det]["rolling"]["rolling"][a]["per_role"] for r in runs]
            shared = [r["detectors"][det]["rolling"]["rolling"][a]["shared"] for r in runs]
            rate, lo, hi = _rate(role)
            md.append(f"| {alpha} | {' / '.join(_pct(x) for x in by_month)} | {_pct(rate)} [{_pct(lo)}, {_pct(hi)}] | {_pct(_worst(role))} | "
                      f"{_sig(role)} | {_pct(_worst(shared))} | {_sig(shared)} | {_pct(_mean(role, 'attack_deceived'))} |")
        md.append("")
    md += ["## Baselines (time-ordered calibration)", "",
           "Same running-maximum decision for every rule; only the threshold differs. *Per-event conformal* calibrates on individual "
           "event scores instead of whole-session maxima. *Per-role quantile*: empirical (1 - alpha) quantile per role, no "
           "finite-sample correction. *Per-role Neyman-Pearson*: umbrella algorithm, delta = 0.05.", "",
           "| detector | alpha | rule | legit sessions deceived | worst role | roles above alpha | malicious sessions deceived |", "|---|---|---|---|---|---|---|"]
    for det in dets:
        for alpha in ALPHAS:
            a = str(alpha)
            rules = {"shared conformal": [r["detectors"][det]["temporal"]["shared"][a] for r in runs],
                     "**per-role conformal (ours)**": [r["detectors"][det]["temporal"]["per_role"][a] for r in runs]}
            for name in ("per_event_conformal", "per_role_quantile", "per_role_neyman_pearson"):
                rules[name.replace("_", " ")] = [r["detectors"][det]["temporal"]["baselines"][a][name] for r in runs]
            for name, bl in rules.items():
                md.append(f"| {det} | {alpha} | {name} | {_pct(_rate(bl)[0])} | {_pct(_worst(bl))} | {_sig(bl)} | {_pct(_mean(bl, 'attack_deceived'))} |")
    md += ["", "## Contaminated calibration (alpha = 0.01, shared threshold, time-ordered)", "",
           "Malicious sessions mislabelled as legitimate, as a share of the legitimate calibration sessions. *Random*: any malicious "
           "session. *Stealthiest*: the lowest-scoring ones, the most likely to go unnoticed.", "",
           "| detector | contamination | share added | legit sessions deceived [95 % CI] | malicious sessions deceived |", "|---|---|---|---|---|"]
    for det in dets:
        for mode in ("random", "stealthiest"):
            for frac in CONTAMINATION:
                bl = [r["detectors"][det]["temporal"]["contaminated"][f"{mode}_{frac}"] for r in runs]
                rate, lo, hi = _rate(bl)
                md.append(f"| {det} | {mode} | {frac} | {_pct(rate)} [{_pct(lo)}, {_pct(hi)}] | {_pct(_mean(bl, 'attack_deceived'))} |")
    md += ["", "## Limits", "",
           "- CERT r4.2 is synthetic (generated enterprise activity), not hospital EHR logs.",
           "- Web browsing is not in the sessions (CERT's event-level web log is not stored here), so scenario steps that happen only on the web are not seen.",
           "- Role groups come from the monthly LDAP snapshots; roles with few sessions share one group."]
    with open(os.path.join(base.OUT, "CERT_SESSIONS.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds", type=int, default=5)
    args = ap.parse_args()
    E = build_session_table()
    feats = feature_names(E)
    start = E.groupby("sess")["date"].transform("min")
    cut = E["date"].min() + (E["date"].max() - E["date"].min()) * 0.5
    counts = E.loc[start >= cut].groupby("role")["sess"].nunique()
    E["group"] = np.where(E["role"].map(counts).fillna(0) >= MIN_GROUP_SESSIONS, E["role"], "other_roles")
    sess = E.groupby("sess").agg(mal=("sess_mal", "first"))
    info = {"events": int(len(E)), "users": int(E["user"].nunique()), "sessions": int(len(sess)),
            "malicious_sessions": int(sess.mal.sum()), "groups": int(E["group"].nunique()), "features": feats}
    print(f"{info['events']:,} events, {info['sessions']:,} sessions, {info['malicious_sessions']} malicious, {info['groups']} groups", flush=True)
    runs = [run_seed(E, feats, s) for s in range(args.seeds)]
    write_report(runs, info)


if __name__ == "__main__":
    main()
