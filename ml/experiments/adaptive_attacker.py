"""
adaptive_attacker.py — what does it cost an attacker who knows the deception gate to avoid it?

The guarantee in docs/theory.md is about legitimate sessions; an attacker who keeps every score at or
below tau is never deceived. This experiment measures how much of the attack survives that constraint.

Mimicry model
-------------
For an attack session with feature rows x_t, the attacker scales its activity towards the normal
profile mu of a legitimate role: x_t(lambda) = mu + lambda * (x_t - mu) on the ACTIVITY features
(logins, failures, EHR reads, export volume, requests, endpoints, internal hosts, CPU, memory, and the
entity's own baselines and ratios). Context it cannot fake is kept as it was: time of day, weekend,
off-shift score, IP reputation, internal or external address. lambda = 1 is the original attack,
lambda = 0 is the role's average behaviour. For each attack session we find the largest lambda on a
grid whose session maximum score stays <= tau: the share of its activity rate the attacker can keep
while never being deceived (the cost of evasion is 1 - lambda*).

Gates (time-ordered calibration, as in deception_guarantee.py)
  shared        one threshold for everyone; the attacker mimics the role of the account it uses.
  per-role      tau of the account's role; the attacker mimics that role.
  role shopping per-role gate, but the attacker uses an account of whichever role has the largest
                tau and mimics that role (e.g. after compromising such an account).
Sessions without an account (external IPs) are judged against the shared threshold in every setting.

Feature interpolation is an approximation: not every interpolated vector is reachable by real
behaviour. It gives the attacker more freedom than reality would, so the costs are lower bounds.

    python3 ml/experiments/adaptive_attacker.py [--seeds 5]   -> evaluation/ADAPTIVE.md, evaluation/adaptive_attacker.json
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
for p in (_HERE, _ML, _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)
from deception_guarantee import STAFF_ROLES, make_dataset, scores, split, temporal_split_post, train_detectors  # noqa: E402
from features import FEATURE_NAMES  # noqa: E402
from safe_deception import DeceptionGate  # noqa: E402

CONTEXT = ["hour_sin", "hour_cos", "is_weekend", "offshift_score", "ip_reputation", "is_internal_ip"]
ACTIVITY = [f for f in FEATURE_NAMES if f not in CONTEXT]
GRID = np.round(np.linspace(0, 1, 21), 2)
ALPHAS = [0.05, 0.01]
OUT_DIR = os.path.join(_ROOT, "evaluation")


def score_fn(det: str, xgb, iso):
    if det == "xgb":
        return lambda X: (lambda p: p[:, 1] + p[:, 2])(xgb.predict_proba(X))
    return lambda X: -iso.score_samples(X)


def max_lambda(X: np.ndarray, sess_idx: np.ndarray, n_sess: int, mu: np.ndarray, tau: np.ndarray, f) -> np.ndarray:
    """Largest grid lambda per session whose session maximum stays <= tau (tau per session).
    0 when even the role's average profile would be deceived."""
    act = np.array([FEATURE_NAMES.index(c) for c in ACTIVITY])
    best = np.zeros(n_sess)
    for lam in GRID:
        Xl = X.copy()
        Xl[:, act] = mu[act] + lam * (X[:, act] - mu[act])
        sc = f(Xl)
        smax = np.full(n_sess, -np.inf)
        np.maximum.at(smax, sess_idx, sc)
        ok = smax <= tau
        best = np.where(ok, lam, best)
    return best


def run_seed(seed: int, days: int, users: int) -> dict:
    t0 = time.time()
    F = make_dataset(seed, days, users)
    sp = split(F, seed)
    spt = temporal_split_post(F, sp)
    xgb, iso = train_detectors(F, sp == "train", seed)
    S = scores(F, xgb, iso)
    cal, test = spt == "val", spt == "test"
    att = test & F["is_attack"].to_numpy(bool)
    sess_codes, sess_idx = np.unique(F.loc[att, "sess"].to_numpy(), return_inverse=True)
    n_sess = len(sess_codes)
    Xa = F.loc[att, FEATURE_NAMES].to_numpy(float)
    groups_att = F.loc[att].groupby("sess")["group"].first().reindex(sess_codes).to_numpy()
    family = F.loc[att].groupby("sess")["attack_family"].agg(lambda x: next((v for v in x if v != "normal"), "normal")).reindex(sess_codes).to_numpy()
    legit_rows = cal & ~F["is_attack"].to_numpy(bool)
    mu = {g: F.loc[legit_rows & (F["group"] == g).to_numpy(), FEATURE_NAMES].to_numpy(float).mean(axis=0)
          for g in np.unique(F.loc[legit_rows, "group"])}
    mu_all = F.loc[legit_rows, FEATURE_NAMES].to_numpy(float).mean(axis=0)
    profile = lambda g: mu.get(g, mu_all)          # a role with no legitimate rows: overall average
    staff = [g for g in STAFF_ROLES if g in mu]

    res = {"seed": seed, "n_attack_sessions": int(n_sess), "families": family.tolist(), "groups": groups_att.tolist(), "detectors": {}}
    for det, sc in S.items():
        f = score_fn(det, xgb, iso)
        cs = pd.DataFrame({"sess": F.loc[cal, "sess"].to_numpy(), "score": sc[cal], "a": F.loc[cal, "is_attack"].to_numpy(bool),
                           "g": F.loc[cal, "group"].to_numpy()}).groupby("sess").agg(m=("score", "max"), a=("a", "max"), g=("g", "first"))
        legit = cs[~cs.a]
        block = {}
        for alpha in ALPHAS:
            shared = DeceptionGate(alpha_noise=alpha, alpha_full=alpha).fit(legit.m.to_numpy())
            per_role = DeceptionGate(alpha_noise=alpha, alpha_full=alpha).fit(legit.m.to_numpy(), legit.g.to_numpy())
            # role an attacker would shop for: the staff role with the largest per-role threshold
            shop = max(staff, key=lambda g: per_role.thresholds(g)[0])
            out = {"shopped_role": shop, "role_thresholds": {g: per_role.thresholds(g)[0] for g in staff}, "shared_threshold": shared.tau_noise}
            for setting in ("shared", "per_role", "role_shopping"):
                lam = np.zeros(n_sess)
                for g in np.unique(groups_att):
                    sel = groups_att == g
                    rows = sel[sess_idx]
                    staff_session = g in STAFF_ROLES
                    if setting == "shared" or not staff_session:
                        target, tau = g, shared.tau_noise if setting == "shared" else per_role.thresholds(g)[0]
                    elif setting == "per_role":
                        target, tau = g, per_role.thresholds(g)[0]
                    else:
                        target, tau = shop, per_role.thresholds(shop)[0]
                    sub_idx = np.unique(sess_idx[rows], return_inverse=True)[1]
                    lam[sel] = max_lambda(Xa[rows], sub_idx, int(sel.sum()), profile(target), np.full(int(sel.sum()), tau), f)
                out[setting] = lam.tolist()
            block[str(alpha)] = out
        res["detectors"][det] = block
    res["seconds"] = round(time.time() - t0, 1)
    print(f"seed {seed}: {n_sess} attack sessions, {res['seconds']} s", flush=True)
    return res


def write_report(runs: list[dict], args) -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "adaptive_attacker.json"), "w") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "args": vars(args), "runs": runs}, f, indent=2, default=float)
    fam = np.concatenate([r["families"] for r in runs])
    md = ["# Adaptive attacker: the cost of avoiding the deception gate", "",
          f"Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}. **Synthetic data**, {len(runs)} seeds, {args.days} days, "
          f"{args.users} users per seed, {len(fam):,} attack sessions in the evaluation period. The attacker knows the gate and its "
          "thresholds and scales its activity towards a legitimate role's average profile until no event is deceived. "
          "lambda* = share of its activity rate it can keep (1 = the original attack, 0 = average legitimate behaviour). "
          "See the docstring of ml/experiments/adaptive_attacker.py for the model and its limits.", ""]
    for det in runs[0]["detectors"]:
        md += [f"## Detector: {det}", "",
               "| alpha | gate | median lambda* | mean lambda* | sessions never deceived as they were (lambda* = 1) | sessions keeping >= 50 % |",
               "|---|---|---|---|---|---|"]
        for alpha in ALPHAS:
            a = str(alpha)
            for setting, label in (("shared", "shared threshold"), ("per_role", "per-role, own role"), ("role_shopping", "per-role, role shopping")):
                lam = np.concatenate([r["detectors"][det][a][setting] for r in runs])
                md.append(f"| {alpha} | {label} | {np.median(lam):.2f} | {lam.mean():.2f} | {100 * np.mean(lam >= 1):.1f} % | {100 * np.mean(lam >= 0.5):.1f} % |")
        md += ["", f"Per attack family, alpha = 0.01, median lambda* (shared / per-role / role shopping):", "",
               "| family | sessions | shared | per-role | role shopping |", "|---|---|---|---|---|"]
        for f_ in sorted(set(fam)):
            sel = fam == f_
            vals = [np.median(np.concatenate([r["detectors"][det]["0.01"][s] for r in runs])[sel]) for s in ("shared", "per_role", "role_shopping")]
            md.append(f"| {f_} | {int(sel.sum())} | {vals[0]:.2f} | {vals[1]:.2f} | {vals[2]:.2f} |")
        shops = [r["detectors"][det]["0.01"]["shopped_role"] for r in runs]
        md += ["", f"Role an attacker would shop for at alpha = 0.01: {', '.join(sorted(set(shops)))} (per seed: {', '.join(shops)})."]
        for alpha in ALPHAS:
            off = sorted({g for r in runs for g, t in r["detectors"][det][str(alpha)]["role_thresholds"].items() if not np.isfinite(t)})
            if off:
                md.append(f"At alpha = {alpha}, roles with too few calibration sessions have deception switched off (tau = infinity), "
                          f"so an attacker using such an account is never deceived: {', '.join(off)}.")
        md.append("")
    md += ["## Reading the tables", "",
           "- A low lambda* means the attacker must slow down to close to normal behaviour to stay undeceived: deception then costs it most of its speed.",
           "- Role shopping shows the price of per-role thresholds: an attacker who controls an account of the most permissive role gets the most room.",
           "- Interpolated feature vectors are not all reachable by real behaviour, so these costs are lower bounds on what a real attacker pays."]
    with open(os.path.join(OUT_DIR, "ADAPTIVE.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--days", type=int, default=28)
    ap.add_argument("--users", type=int, default=300)
    args = ap.parse_args()
    write_report([run_seed(s, args.days, args.users) for s in range(args.seeds)], args)


if __name__ == "__main__":
    main()
