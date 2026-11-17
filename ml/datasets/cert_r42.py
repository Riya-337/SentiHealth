"""
cert_r42.py — the CERT Insider Threat Test Dataset r4.2 (CMU SEI / ExactData; DOI 10.1184/R1/12841247)
as a public benchmark for SentiHealth's per-user detection and for the deception safety guarantee.

r4.2: 1,000 synthetic employees, Jan 2010 - May 2011, logon / device / file / email / http logs,
70 insiders acting out three scenarios; the answer key lists every malicious event.

Pipeline
--------
extract   one streaming pass over r4.2.tar.bz2: logon, device, file, email (headers only), LDAP and
          psychometric files are written to data/external/cert/r4.2/; http.csv (~14 GB) is never
          stored: it is aggregated on the fly into per-user-day counts (visits, after-hours visits,
          wikileaks / job-site / cloud-upload hits, upload-like URLs).
features  one row per user-day ("session"): counts, after-hours shares, distinct PCs, removable-media
          use, file copies, email volume / external recipients / attachments, http aggregates, plus each
          feature's deviation from the user's own trailing 30-day mean (computed with past days only).
labels    a user-day is malicious if it contains any event id from the answer key.
groups    the user's role from the monthly LDAP snapshot (Mondrian groups for the guarantee).
experiment  detectors trained on the first half of the period; the later user-days are split at random
          into calibration and evaluation; conformal gate as in ml/safe_deception.py (one decision per
          user-day). Also a time-ordered variant.

    python3 ml/datasets/cert_r42.py extract      # once, ~20-40 min, needs ~3 GB free after deleting the archive
    python3 ml/datasets/cert_r42.py features
    python3 ml/datasets/cert_r42.py experiment   -> evaluation/CERT_R42.md, evaluation/cert_r42.json
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import tarfile
import time
from collections import defaultdict
from datetime import datetime, timezone

import numpy as np
import pandas as pd

_HERE = os.path.dirname(os.path.abspath(__file__))
_ML = os.path.dirname(_HERE)
_ROOT = os.path.dirname(_ML)
for p in (_ML, _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

EXT = os.path.join(_ROOT, "data", "external")
ARCHIVE = os.path.join(EXT, "r4.2.tar.bz2")
DIR = os.path.join(EXT, "cert", "r4.2")
ANSWERS = os.path.join(EXT, "cert", "answers")
OUT = os.path.join(_ROOT, "evaluation")
WORK_START, WORK_END = 8, 18   # after-hours = outside 08:00-18:00 or weekend

KEEP = {"logon.csv", "device.csv", "file.csv", "psychometric.csv"}
HTTP_PATTERNS = {
    "wikileaks": re.compile(r"wikileaks", re.I),
    "jobsite": re.compile(r"(monster|careerbuilder|indeed|jobhunt|linkedin|simplyhired|job|career|hiring|recruit)", re.I),
    "cloud_upload": re.compile(r"(dropbox|box\.com|drive\.google|mega\.|mediafire|upload|sendspace|4shared)", re.I),
    "keylogger": re.compile(r"(keylog|spyware|surveil)", re.I),
}


# --------------------------------------------------------------------------- extract
def _day_and_after(date_str: str) -> tuple[str, bool]:
    # "01/02/2010 07:11:45"
    m, d, rest = date_str.split("/", 2)
    y, hms = rest.split(" ", 1)
    hour = int(hms[:2])
    dt = datetime(int(y), int(m), int(d))
    after = hour < WORK_START or hour >= WORK_END or dt.weekday() >= 5
    return f"{y}-{m}-{d}", after


class _Raw(io.RawIOBase):
    """Adapter: tarfile's streaming member objects lack seekable()/readinto(), which TextIOWrapper needs."""
    def __init__(self, f):
        self.f = f
    def readable(self):
        return True
    def seekable(self):
        return False
    def readinto(self, b):
        data = self.f.read(len(b))
        n = len(data)
        b[:n] = data
        return n


def _text(fobj):
    return io.TextIOWrapper(io.BufferedReader(_Raw(fobj), 1 << 20), encoding="utf-8", errors="ignore", newline="")


def _aggregate_http(fobj, out_path: str) -> int:
    agg: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0, 0, 0, 0, 0])
    text = _text(fobj)
    n = 0
    for row in csv.reader(text):
        if len(row) < 5 or row[0] == "id":
            continue
        day, after = _day_and_after(row[1])
        url = row[4]
        a = agg[(row[2], day)]
        a[0] += 1
        a[1] += after
        for i, key in enumerate(("wikileaks", "jobsite", "cloud_upload", "keylogger"), start=2):
            if HTTP_PATTERNS[key].search(url):
                a[i] += 1
        n += 1
        if n % 5_000_000 == 0:
            print(f"  http: {n:,} rows", flush=True)
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["user", "day", "http_n", "http_after", "http_wikileaks", "http_jobsite", "http_cloud", "http_keylogger"])
        for (user, day), v in agg.items():
            w.writerow([user, day, *v])
    return n


def _email_headers(fobj, out_path: str) -> int:
    """email.csv carries full bodies; keep only id, date, user, pc, to, cc, bcc, from, size, attachments."""
    text = _text(fobj)
    n = 0
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        for i, row in enumerate(csv.reader(text)):
            if i == 0:
                w.writerow(row[:10])
                continue
            w.writerow(row[:10])
            n += 1
    return n


def extract() -> None:
    if not os.path.exists(ARCHIVE):
        raise SystemExit(f"missing {ARCHIVE}: run scripts/fetch_datasets.sh")
    os.makedirs(DIR, exist_ok=True)
    t0 = time.time()
    import bz2
    # the archive is multi-stream bzip2 (parallel compressor); bz2.open reads all streams, while
    # tarfile's own streaming 'r|bz2' mode stops after the first one
    with bz2.open(ARCHIVE, "rb") as raw, tarfile.open(fileobj=raw, mode="r|") as tar:
        for m in tar:
            if not m.isfile():
                continue
            name = os.path.basename(m.name)
            parent = os.path.basename(os.path.dirname(m.name))
            f = tar.extractfile(m)
            if f is None:
                continue
            if name == "http.csv":
                print(f"[{time.time() - t0:.0f}s] aggregating {m.name} ({m.size / 1e9:.1f} GB)", flush=True)
                n = _aggregate_http(f, os.path.join(DIR, "http_daily.csv"))
                print(f"[{time.time() - t0:.0f}s] http rows {n:,}", flush=True)
            elif name == "email.csv":
                print(f"[{time.time() - t0:.0f}s] email headers from {m.name}", flush=True)
                _email_headers(f, os.path.join(DIR, "email_headers.csv"))
            elif name in KEEP or parent == "LDAP":
                dest = os.path.join(DIR, "LDAP", name) if parent == "LDAP" else os.path.join(DIR, name)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as o:
                    while chunk := f.read(1 << 20):
                        o.write(chunk)
                print(f"[{time.time() - t0:.0f}s] wrote {dest}", flush=True)
    print(f"extract done in {time.time() - t0:.0f}s")


# --------------------------------------------------------------------------- features
def _read_events(name: str, cols: list[str]) -> pd.DataFrame:
    d = pd.read_csv(os.path.join(DIR, name), usecols=cols)
    d["date"] = pd.to_datetime(d["date"], format="%m/%d/%Y %H:%M:%S")
    d["day"] = d["date"].dt.strftime("%Y-%m-%d")
    h = d["date"].dt.hour
    d["after"] = ((h < WORK_START) | (h >= WORK_END) | (d["date"].dt.weekday >= 5)).astype(int)
    return d


def malicious_ids() -> set[str]:
    ids: set[str] = set()
    for sub in ("r4.2-1", "r4.2-2", "r4.2-3"):
        folder = os.path.join(ANSWERS, sub)
        if not os.path.isdir(folder):
            continue
        for fn in os.listdir(folder):
            with open(os.path.join(folder, fn), newline="", encoding="utf-8", errors="ignore") as f:
                for row in csv.reader(f):
                    if len(row) > 1:
                        ids.add(row[1])
    return ids


def build_features() -> pd.DataFrame:
    t0 = time.time()
    bad = malicious_ids()
    print(f"malicious event ids in answer key: {len(bad):,}")
    parts = []

    lg = _read_events("logon.csv", ["id", "date", "user", "pc", "activity"])
    lg["mal"] = lg["id"].isin(bad)
    on = lg[lg.activity == "Logon"]
    parts.append(on.groupby(["user", "day"]).agg(logon_n=("id", "size"), logon_after=("after", "sum"),
                                                 logon_pcs=("pc", "nunique"), first_hour=("date", lambda x: x.dt.hour.min()),
                                                 last_hour=("date", lambda x: x.dt.hour.max())))
    mal = [lg.groupby(["user", "day"])["mal"].max()]
    print(f"[{time.time() - t0:.0f}s] logon")

    dv = _read_events("device.csv", ["id", "date", "user", "pc", "activity"])
    dv["mal"] = dv["id"].isin(bad)
    c = dv[dv.activity == "Connect"]
    parts.append(c.groupby(["user", "day"]).agg(usb_n=("id", "size"), usb_after=("after", "sum"), usb_pcs=("pc", "nunique")))
    mal.append(dv.groupby(["user", "day"])["mal"].max())
    print(f"[{time.time() - t0:.0f}s] device")

    fl = _read_events("file.csv", ["id", "date", "user", "pc", "filename"])
    fl["mal"] = fl["id"].isin(bad)
    ext = fl["filename"].str.extract(r"\.([A-Za-z0-9]+)$")[0].str.lower()
    fl["exe"] = ext.isin(["exe", "dll", "bat"]).astype(int)
    fl["archive"] = ext.isin(["zip", "rar", "7z"]).astype(int)
    parts.append(fl.groupby(["user", "day"]).agg(file_n=("id", "size"), file_after=("after", "sum"),
                                                 file_exe=("exe", "sum"), file_zip=("archive", "sum")))
    mal.append(fl.groupby(["user", "day"])["mal"].max())
    print(f"[{time.time() - t0:.0f}s] file")

    em = _read_events("email_headers.csv", ["id", "date", "user", "to", "cc", "bcc", "size", "attachments"])
    em["mal"] = em["id"].isin(bad)
    rcpt = (em["to"].fillna("") + ";" + em["cc"].fillna("") + ";" + em["bcc"].fillna(""))
    em["n_rcpt"] = rcpt.str.count("@")
    em["n_ext"] = rcpt.str.count(r"@(?!dtaa\.com)")
    em["has_bcc"] = em["bcc"].notna().astype(int)
    parts.append(em.groupby(["user", "day"]).agg(email_n=("id", "size"), email_after=("after", "sum"), email_rcpt=("n_rcpt", "sum"),
                                                 email_ext=("n_ext", "sum"), email_bcc=("has_bcc", "sum"),
                                                 email_att=("attachments", "sum"), email_kb=("size", lambda x: x.sum() / 1024)))
    mal.append(em.groupby(["user", "day"])["mal"].max())
    print(f"[{time.time() - t0:.0f}s] email")

    http = pd.read_csv(os.path.join(DIR, "http_daily.csv")).set_index(["user", "day"])
    parts.append(http)
    # http event ids are not kept by the streaming aggregation; malicious http days are already
    # covered because every scenario's day also has logon/device/file/email events in the key, and
    # the http_wikileaks / jobsite counts carry the signal as features.

    F = pd.concat(parts, axis=1).fillna(0.0)
    F["malicious"] = pd.concat(mal, axis=1).max(axis=1).reindex(F.index).fillna(False).astype(bool)
    F = F.reset_index()
    F["day"] = pd.to_datetime(F["day"])
    F = F.sort_values(["user", "day"]).reset_index(drop=True)

    # deviation from the user's own trailing 30-day mean (past days only, so no look-ahead)
    base_cols = ["logon_n", "logon_after", "usb_n", "file_n", "email_n", "email_ext", "http_n", "http_after"]
    g = F.groupby("user")
    for c in base_cols:
        past = g[c].transform(lambda s: s.shift(1).rolling(30, min_periods=5).mean())
        F[f"{c}_dev"] = (F[c] - past.fillna(F[c])) / (past.fillna(0) + 1.0)

    # role from the LDAP snapshot of that month (fallback: most recent known role)
    roles = []
    for fn in sorted(os.listdir(os.path.join(DIR, "LDAP"))):
        m = pd.read_csv(os.path.join(DIR, "LDAP", fn))
        m["month"] = fn.replace(".csv", "")
        roles.append(m[["user_id", "role", "month"]])
    R = pd.concat(roles).rename(columns={"user_id": "user"})
    F["month"] = F["day"].dt.strftime("%Y-%m")
    F = F.merge(R, on=["user", "month"], how="left")
    F["role"] = F.groupby("user")["role"].transform(lambda s: s.ffill().bfill()).fillna("unknown")
    F.drop(columns=["month"], inplace=True)
    out = os.path.join(DIR, "user_days.csv.gz")
    F.to_csv(out, index=False, compression="gzip")
    print(f"[{time.time() - t0:.0f}s] {len(F):,} user-days, {int(F.malicious.sum())} malicious, {F.role.nunique()} roles -> {out}")
    return F


# --------------------------------------------------------------------------- experiment
def experiment(seeds: int = 5) -> None:
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import average_precision_score, roc_auc_score
    from xgboost import XGBClassifier
    from safe_deception import DeceptionGate

    F = pd.read_csv(os.path.join(DIR, "user_days.csv.gz"), parse_dates=["day"])
    feats = [c for c in F.columns if c not in ("user", "day", "malicious", "role")]
    cut = F["day"].min() + (F["day"].max() - F["day"].min()) * 0.5
    tr = (F["day"] < cut).to_numpy()
    y = F["malicious"].to_numpy(bool)
    X = F[feats].to_numpy(float)
    # small roles share one Mondrian group so each group has enough calibration days
    counts = F.loc[~tr, "role"].value_counts()
    F["group"] = np.where(F["role"].map(counts).fillna(0) >= 400, F["role"], "other_roles")
    print(f"user-days {len(F):,}; train {tr.sum():,} ({y[tr].sum()} malicious); post {(~tr).sum():,} ({y[~tr].sum()} malicious); "
          f"groups {F.loc[~tr, 'group'].nunique()}")

    runs = []
    for seed in range(seeds):
        xgb = XGBClassifier(n_estimators=400, learning_rate=0.05, max_depth=5, subsample=0.8, colsample_bytree=0.8,
                            tree_method="hist", random_state=seed, n_jobs=-1,
                            scale_pos_weight=float((~y[tr]).sum() / max(y[tr].sum(), 1)))
        xgb.fit(X[tr], y[tr])
        iso = IsolationForest(n_estimators=300, max_samples=8192, random_state=seed, n_jobs=-1).fit(X[tr & ~y])
        S = {"xgb": xgb.predict_proba(X)[:, 1], "iforest": -iso.score_samples(X)}
        post = np.flatnonzero(~tr)
        rng = np.random.default_rng(seed)
        cal_idx = rng.choice(post, size=len(post) // 2, replace=False)
        is_cal = np.zeros(len(F), bool)
        is_cal[cal_idx] = True
        te = ~tr & ~is_cal
        run = {"seed": seed}
        for det, sc in S.items():
            blk = {"roc_auc": float(roc_auc_score(y[te], sc[te])), "pr_auc": float(average_precision_score(y[te], sc[te])), "gate": {}}
            legit_cal = is_cal & ~y
            for a in (0.10, 0.05, 0.01, 0.005):
                for mode in ("pooled", "mondrian"):
                    gate = DeceptionGate(alpha_noise=a, alpha_full=a / 5).fit(
                        sc[legit_cal], F.loc[legit_cal, "group"].to_numpy() if mode == "mondrian" else None)
                    tn = np.array([gate.thresholds(g)[0] if mode == "mondrian" else gate.tau_noise for g in F.loc[te, "group"]])
                    dec = sc[te] > tn
                    yy, gg = y[te], F.loc[te, "group"].to_numpy()
                    per = {g: float(dec[(gg == g) & ~yy].mean()) for g in np.unique(gg) if ((gg == g) & ~yy).sum() >= 200}
                    blk["gate"][f"{mode}_{a}"] = {"legit_deceived": float(dec[~yy].mean()), "malicious_deceived": float(dec[yy].mean()) if yy.any() else None,
                                                   "per_group_legit": per}
            # time-ordered: earlier post days calibrate, later evaluate
            mid = F.loc[~tr, "day"].quantile(0.5)
            cal_t = ~tr & (F["day"] < mid).to_numpy() & ~y
            te_t = ~tr & (F["day"] >= mid).to_numpy()
            g_t = DeceptionGate(alpha_noise=0.01, alpha_full=0.002).fit(sc[cal_t], F.loc[cal_t, "group"].to_numpy())
            tn = np.array([g_t.thresholds(g)[0] for g in F.loc[te_t, "group"]])
            dec = sc[te_t] > tn
            blk["temporal_0.01"] = {"legit_deceived": float(dec[~y[te_t]].mean()), "malicious_deceived": float(dec[y[te_t]].mean()) if y[te_t].any() else None}
            run[det] = blk
        runs.append(run)
        print(f"seed {seed} done")

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "cert_r42.json"), "w") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "runs": runs}, f, indent=2)
    md = ["# CERT Insider Threat r4.2: measured results", "",
          f"Public synthetic benchmark (CMU SEI). {len(F):,} user-days ({int(y.sum())} malicious, {F.user.nunique()} users). "
          "Detectors trained on the first half of the period; later user-days split at random into calibration and evaluation; "
          f"mean over {seeds} seeds. 'Legit deceived' = share of normal user-days put on deception.", "",
          "| detector | ROC-AUC | PR-AUC |", "|---|---|---|"]
    for det in ("xgb", "iforest"):
        md.append(f"| {det} | {np.mean([r[det]['roc_auc'] for r in runs]):.3f} | {np.mean([r[det]['pr_auc'] for r in runs]):.3f} |")
    for det in ("xgb", "iforest"):
        md += ["", f"## Deception gate, detector {det}", "",
               "| alpha | pooled: legit deceived | pooled: worst role | per-role: legit deceived | per-role: worst role | malicious days deceived (per-role) |",
               "|---|---|---|---|---|---|"]
        for a in (0.10, 0.05, 0.01, 0.005):
            def worst(mode):
                per = {}
                for r in runs:
                    for g, v in r[det]["gate"][f"{mode}_{a}"]["per_group_legit"].items():
                        per.setdefault(g, []).append(v)
                return max((np.mean(v) for v in per.values()), default=0.0)
            pl = np.mean([r[det]["gate"][f"pooled_{a}"]["legit_deceived"] for r in runs])
            ml = np.mean([r[det]["gate"][f"mondrian_{a}"]["legit_deceived"] for r in runs])
            mm = np.mean([r[det]["gate"][f"mondrian_{a}"]["malicious_deceived"] or 0 for r in runs])
            md.append(f"| {a} | {pl:.4f} | {worst('pooled'):.4f} | {ml:.4f} | {worst('mondrian'):.4f} | {mm:.3f} |")
        tl = np.mean([r[det]["temporal_0.01"]["legit_deceived"] for r in runs])
        tm = np.mean([r[det]["temporal_0.01"]["malicious_deceived"] or 0 for r in runs])
        md.append(f"\nTime-ordered calibration, alpha 0.01, per-role: legit deceived {tl:.4f}, malicious days deceived {tm:.3f}.")
    with open(os.path.join(OUT, "CERT_R42.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=["extract", "features", "experiment", "all"])
    ap.add_argument("--seeds", type=int, default=5)
    a = ap.parse_args()
    if a.step in ("extract", "all"):
        extract()
    if a.step in ("features", "all"):
        build_features()
    if a.step in ("experiment", "all"):
        experiment(a.seeds)


if __name__ == "__main__":
    main()
