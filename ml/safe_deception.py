"""
safe_deception.py — deciding when to serve decoy data, with a finite-sample bound on how often a
LEGITIMATE session is ever deceived.

Problem
-------
Mirage answers suspected attackers with fake patient records. In a hospital the costly error is the
other one: a clinician who is served fake data can harm a patient. A risk threshold such as "deceive
when P(attack) > 0.75" says nothing about how often that happens to legitimate staff, and the rate
changes with the model, the role and the time of day.

Method (split conformal prediction, applied at session level)
-------------------------------------------------------------
* A session is one user/IP's activity with no gap longer than SESSION_GAP_MIN. Every event in it has
  a risk score r_t from the detector (any detector: calibrated XGBoost, Isolation Forest, ...).
* Decisions are sequential: at event t the session is deceived iff M_t = max_{k<=t} r_k > tau.
  Once deceived it stays deceived.
* tau is calibrated on n legitimate sessions using their WHOLE-SESSION maxima M_T:
      tau = the ceil((n+1)(1-alpha))-th smallest of {M_T(s_1), ..., M_T(s_n)}.
* Guarantee. If the calibration sessions and a new legitimate session are exchangeable,
      P( the new legitimate session is ever deceived ) = P( M_T > tau ) <= alpha,
  because M_t <= M_T for every t (standard split-conformal argument; Vovk et al. 2005,
  Angelopoulos & Bates 2023). The bound covers the whole session, not each event, so the
  repeated per-event decisions do not inflate it.
* Mondrian (group-conditional) version: one tau per group (e.g. role), calibrated on that group's
  sessions only; the bound then holds inside every group separately, so false deceptions cannot be
  concentrated on one role. A group with too few calibration sessions for alpha gets tau = +inf
  (deception disabled for it); an unseen staff group is also never deceived (fail-safe).
* Contamination: some calibration "legitimate" sessions may in fact be attacks. Adding scores that
  are >= the clean tau cannot lower tau (the clean set's k-1 smallest scores stay the k-1 smallest),
  so detected-but-unlabelled attacks only make the gate more conservative. Adding scores BELOW the
  clean tau can lower it: the attacks most likely to be mislabelled as legitimate are the
  undetected ones, which score low, so contamination is NOT conservative in general.
  ml/experiments/deception_guarantee.py measures both cases (random and stealthiest attacks).
* Two levels: noise-only above tau(alpha_noise), full decoys above tau(alpha_full) with
  alpha_full <= alpha_noise. Each level has its own bound.

What is NOT guaranteed: the bound needs future legitimate sessions to resemble the calibration
sessions (exchangeability). Under drift (new staff, new workflows) it can be violated; recalibrate on
a recent window and monitor the realised rate on verified-legitimate sessions (monitor()).
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

SESSION_GAP_MIN = 30
MIN_GROUP_SIZE_FACTOR = 1.0   # a group needs >= ceil(1/alpha) - 1 sessions for a finite tau


def conformal_threshold(cal_scores: np.ndarray, alpha: float) -> float:
    """Smallest tau with the split-conformal guarantee P(new > tau) <= alpha.
    Returns +inf when n is too small for alpha (then nothing can be deceived safely)."""
    s = np.sort(np.asarray(cal_scores, dtype=float))
    n = len(s)
    k = math.ceil((n + 1) * (1 - alpha))
    if n == 0 or k > n:
        return float("inf")
    return float(s[k - 1])


def np_umbrella_threshold(cal_scores: np.ndarray, alpha: float, delta: float = 0.05) -> float:
    """Neyman-Pearson umbrella threshold (Tong, Feng & Li 2018), a baseline with a high-probability
    guarantee: P_cal( P(new > tau) > alpha ) <= delta. tau is the k-th smallest calibration score,
    with k the smallest order for which P(Binomial(n, 1 - alpha) >= k) <= delta; +inf if none exists.
    Stricter than the conformal threshold, whose guarantee is only in expectation over calibration."""
    from scipy.stats import binom
    s = np.sort(np.asarray(cal_scores, dtype=float))
    n = len(s)
    if n == 0:
        return float("inf")
    k = np.arange(1, n + 1)
    viol = binom.sf(k - 1, n, 1 - alpha)          # P(Binomial(n, 1-alpha) >= k)
    ok = np.flatnonzero(viol <= delta)
    return float(s[ok[0]]) if len(ok) else float("inf")


def clopper_pearson(k: int, n: int, conf: float = 0.95) -> tuple[float, float]:
    """Exact two-sided confidence interval for a binomial rate k/n."""
    from scipy.stats import beta
    if n == 0:
        return 0.0, 1.0
    a = 1 - conf
    lo = 0.0 if k == 0 else float(beta.ppf(a / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - a / 2, k + 1, n - k))
    return lo, hi


def group_excess(deceived: np.ndarray, groups: np.ndarray, alpha: float, min_n: int = 1, level: float = 0.05) -> dict:
    """Per-group realised false-deception rates on legitimate sessions, each with a 95 % Clopper-Pearson
    interval and a one-sided binomial p-value for H0: rate <= alpha. Holm's correction across groups
    answers whether ANY group is significantly above alpha, as opposed to the largest of many noisy
    estimates landing above it by chance."""
    from scipy.stats import binom
    x = np.asarray(deceived, dtype=bool)
    g = np.asarray(groups).astype(str)
    rows = []
    for grp in np.unique(g):
        m = g == grp
        n, k = int(m.sum()), int(x[m].sum())
        if n < min_n:
            continue
        lo, hi = clopper_pearson(k, n)
        rows.append({"group": grp, "n": n, "deceived": k, "rate": k / n, "ci_low": lo, "ci_high": hi,
                     "p_value": float(binom.sf(k - 1, n, alpha)) if k else 1.0})
    # Holm step-down over the per-group p-values
    order = sorted(range(len(rows)), key=lambda i: rows[i]["p_value"])
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(rows) - rank) * rows[i]["p_value"]))
        rows[i]["p_holm"] = running
    worst = max(rows, key=lambda r: r["rate"]) if rows else None
    return {"alpha": alpha, "groups": rows, "n_groups": len(rows),
            "n_significant": sum(r["p_holm"] < level for r in rows),
            "worst": worst}


def conformal_pvalue(cal_scores: np.ndarray, score: float) -> float:
    """p = (1 + #{cal >= score}) / (n + 1). Small p = unusual for legitimate sessions."""
    s = np.asarray(cal_scores, dtype=float)
    return float((1 + np.sum(s >= score)) / (len(s) + 1))


def sessionize(df: pd.DataFrame, entity_col: str = "entity", ts_col: str = "ts", gap_min: int = SESSION_GAP_MIN) -> pd.Series:
    """Session id per row: same entity, no gap longer than gap_min. df must be sorted by entity, ts."""
    ts = pd.to_datetime(df[ts_col], utc=True)
    new = (df[entity_col] != df[entity_col].shift()) | (ts.diff() > pd.Timedelta(minutes=gap_min))
    return new.cumsum().astype(int)


def session_maxima(sess: np.ndarray, scores: np.ndarray) -> pd.Series:
    return pd.Series(scores).groupby(sess).max()


@dataclass
class DeceptionGate:
    alpha_noise: float = 0.01
    alpha_full: float = 0.001
    tau_noise: float = float("inf")
    tau_full: float = float("inf")
    group_tau: dict = field(default_factory=dict)       # group -> {"noise": tau, "full": tau, "n": n}
    n_cal: int = 0
    # Groups that contain no clinical staff (e.g. unauthenticated / external sessions). No clinician
    # can be in them, so they use the pooled thresholds instead of being disabled.
    nonclinical_groups: tuple = ("unauthenticated",)

    # ------------------------------------------------------------------ fitting
    def fit(self, cal_max: np.ndarray, cal_groups: np.ndarray | None = None) -> "DeceptionGate":
        cal_max = np.asarray(cal_max, dtype=float)
        self.n_cal = len(cal_max)
        self.tau_noise = conformal_threshold(cal_max, self.alpha_noise)
        self.tau_full = max(conformal_threshold(cal_max, self.alpha_full), self.tau_noise)
        self.group_tau = {}
        if cal_groups is not None:
            g = np.asarray(cal_groups)
            for grp in np.unique(g):
                m = cal_max[g == grp]
                tn = conformal_threshold(m, self.alpha_noise)
                tf = max(conformal_threshold(m, self.alpha_full), tn)
                self.group_tau[str(grp)] = {"noise": tn, "full": tf, "n": int(len(m))}
        return self

    # ------------------------------------------------------------------ decisions
    def thresholds(self, group: str | None = None) -> tuple[float, float]:
        if group is not None and self.group_tau:
            if str(group) in self.nonclinical_groups:
                return self.tau_noise, self.tau_full
            gt = self.group_tau.get(str(group))
            if gt is None:
                return float("inf"), float("inf")   # unseen staff group: fail safe, never deceive
            return gt["noise"], gt["full"]
        return self.tau_noise, self.tau_full

    def level(self, running_max: float, group: str | None = None) -> str:
        """'none' | 'noise_only' | 'full' for a session whose running maximum risk is running_max."""
        tn, tf = self.thresholds(group)
        if running_max > tf:
            return "full"
        if running_max > tn:
            return "noise_only"
        return "none"

    def decide_sessions(self, sess: np.ndarray, scores: np.ndarray, groups: np.ndarray | None = None) -> pd.DataFrame:
        """Sequential decisions for every event. Returns per-event level and the first-deception index."""
        df = pd.DataFrame({"sess": sess, "score": scores})
        df["running_max"] = df.groupby("sess")["score"].cummax()
        if groups is None or not self.group_tau:
            tn, tf = self.tau_noise, self.tau_full
            df["tn"], df["tf"] = tn, tf
        else:
            g = pd.Series(groups).astype(str)
            th = {x: self.thresholds(x) for x in g.unique()}
            df["tn"] = g.map(lambda x: th[x][0]).to_numpy()
            df["tf"] = g.map(lambda x: th[x][1]).to_numpy()
        df["level"] = np.where(df.running_max > df.tf, "full", np.where(df.running_max > df.tn, "noise_only", "none"))
        return df

    # ------------------------------------------------------------------ persistence
    def to_json(self) -> str:
        def f(x):
            return None if not np.isfinite(x) else float(x)
        return json.dumps({"alpha_noise": self.alpha_noise, "alpha_full": self.alpha_full,
                           "tau_noise": f(self.tau_noise), "tau_full": f(self.tau_full), "n_cal": self.n_cal,
                           "group_tau": {k: {"noise": f(v["noise"]), "full": f(v["full"]), "n": v["n"]} for k, v in self.group_tau.items()}},
                          indent=2)

    @classmethod
    def from_json(cls, text: str) -> "DeceptionGate":
        d = json.loads(text)
        inf = float("inf")
        g = cls(alpha_noise=d["alpha_noise"], alpha_full=d["alpha_full"],
                tau_noise=inf if d["tau_noise"] is None else d["tau_noise"],
                tau_full=inf if d["tau_full"] is None else d["tau_full"], n_cal=d.get("n_cal", 0))
        g.group_tau = {k: {"noise": inf if v["noise"] is None else v["noise"], "full": inf if v["full"] is None else v["full"], "n": v["n"]}
                       for k, v in d.get("group_tau", {}).items()}
        return g


def monitor(verified_legit_ever_deceived: np.ndarray, alpha: float, delta: float = 0.01) -> dict:
    """Is the realised false-deception rate on verified-legitimate sessions consistent with alpha?
    One-sided binomial test; 'violated' means the rate is significantly above alpha (recalibrate)."""
    from scipy.stats import binom
    x = np.asarray(verified_legit_ever_deceived, dtype=bool)
    n, k = len(x), int(x.sum())
    p = float(binom.sf(k - 1, n, alpha)) if n else 1.0
    return {"n": n, "deceived": k, "rate": k / n if n else 0.0, "alpha": alpha, "p_value": p, "violated": bool(n and p < delta)}
