"""
simulate_events.py — event-level simulator of hospital access/network activity (SYNTHETIC DATA).

Why this exists
---------------
No public dataset of hospital EHR access logs with labelled attacks exists. This simulator produces
raw, minute-level activity records for users and IPs, with normal behaviour driven by role and
shift, and attack campaigns overlaid on top. Labels come from the *campaign* an entity is part of,
never from thresholds on the features, so a model cannot score well by reading the label back
from the inputs. Stealthy variants (low-and-slow brute force, slow exfiltration that stays under
naive volume limits) are included on purpose so the evaluation is not trivial.

Everything is deterministic for a given --seed. Output: gzipped JSON lines, one record per
(user, ip, minute) with non-zero activity.

Record fields
-------------
ts, user_id, role, ip, internal_ip, emergency_status,
logins, login_failures, ehr_reads, export_kb, requests, distinct_endpoints, internal_hosts,
cpu_usage, mem_spike,
campaign_id, attack_family, tier_label (0 Low, 1 Medium, 2 High), is_attack

Usage
-----
    python3 ml/simulate_events.py --days 14 --users 120 --seed 0 --out data/events_sim.jsonl.gz
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# --------------------------------------------------------------------------- roles & shifts
# shift = (start_hour, end_hour); night shifts wrap past midnight.
ROLES = {
    #           share  shifts                          reads/min  kb/read  fail_p  endpoints/min offhours_p
    "nurse":    (0.40, [(7, 19), (19, 7)],              0.45,      12.0,    0.03,   0.25,         0.06),
    "doctor":   (0.20, [(7, 19)],                       0.55,      15.0,    0.03,   0.30,         0.08),
    "admin":    (0.10, [(9, 17)],                       0.15,      25.0,    0.02,   0.20,         0.01),
    "billing":  (0.15, [(9, 17)],                       0.25,      35.0,    0.02,   0.15,         0.01),
    "it_staff": (0.15, [(9, 17), (17, 1)],              0.08,      8.0,     0.04,   0.60,         0.05),
}
ROLE_NAMES = list(ROLES)

# Tier of each attack family. Labels are by campaign, not by feature thresholds.
FAMILY_TIER = {
    "normal": 0,
    "recon": 0,                 # port/endpoint scan: log only
    "brute_force_slow": 1,      # 2-4 failures a minute for hours: under naive limits
    "insider_offhours": 1,      # legitimate account reading records off shift
    "ddos_mild": 1,
    "brute_force": 2,
    "exfiltration": 2,
    "exfiltration_slow": 2,     # stays under 500 KB/h and 60 reads/h
    "ddos_severe": 2,
    "ransomware": 2,
    "credential_stuffing": 2,   # held out of training by default (unknown family)
}
# how many campaigns per family per 14 days at 120 users (scaled with --days)
CAMPAIGNS_PER_14D = {
    "recon": 16, "brute_force": 18, "brute_force_slow": 8, "exfiltration": 12, "exfiltration_slow": 8,
    "ddos_mild": 6, "ddos_severe": 6, "ransomware": 6, "insider_offhours": 10, "credential_stuffing": 6,
}


def _public_ip(rng: np.random.Generator) -> str:
    while True:
        a, b, c, d = int(rng.integers(1, 224)), int(rng.integers(0, 256)), int(rng.integers(0, 256)), int(rng.integers(1, 255))
        if a in (10, 127) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
            continue
        return f"{a}.{b}.{c}.{d}"


def _internal_ip(rng: np.random.Generator) -> str:
    return f"10.0.{int(rng.integers(1, 21))}.{int(rng.integers(2, 251))}"


def _in_shift(hour: float, shifts: list[tuple[int, int]]) -> bool:
    for s, e in shifts:
        if s < e:
            if s <= hour < e:
                return True
        else:  # wraps midnight
            if hour >= s or hour < e:
                return True
    return False


class Simulator:
    def __init__(self, days: int, n_users: int, seed: int, holdout_family: str | None = "credential_stuffing"):
        self.rng = np.random.default_rng(seed)
        self.days = days
        self.n_users = n_users
        self.holdout_family = holdout_family
        self.t0 = datetime(2025, 3, 3, 0, 0, tzinfo=timezone.utc)  # a Monday
        self.minutes = days * 1440
        self.users = self._make_users()
        self.records: list[dict] = []
        self._campaign_seq = 0

    # ------------------------------------------------------------------ users
    def _make_users(self) -> list[dict]:
        users = []
        shares = np.array([ROLES[r][0] for r in ROLE_NAMES])
        roles = self.rng.choice(ROLE_NAMES, size=self.n_users, p=shares / shares.sum())
        for i, role in enumerate(roles):
            spec = ROLES[role]
            shift = spec[1][int(self.rng.integers(len(spec[1])))]
            users.append({
                "user_id": f"U{i + 1:04d}", "role": role, "shift": shift,
                "ip": _internal_ip(self.rng),
                "remote_ip": _public_ip(self.rng),   # home / VPN address used for remote work and on-call
                "activity": float(self.rng.uniform(0.7, 1.3)),  # personal multiplier
            })
        return users

    # ------------------------------------------------------------------ helpers
    def _ts(self, minute: int) -> str:
        return (self.t0 + timedelta(minutes=int(minute))).isoformat(timespec="seconds")

    def _emit(self, minute: int, user: dict, ip: str, *, logins=0, fails=0, reads=0, export_kb=0.0, requests=0,
              endpoints=0, hosts=0, cpu=None, mem_spike=0, family="normal", campaign="", emergency=False):
        if cpu is None:
            cpu = float(np.clip(self.rng.normal(0.28, 0.08) + 0.01 * requests, 0.05, 0.65))
        shift = user.get("shift")
        self.records.append({
            "ts": self._ts(minute), "user_id": user["user_id"], "role": user["role"], "ip": ip,
            "shift": list(shift) if shift and tuple(shift) != (0, 0) else None,  # the user's own shift, as a roster would give it
            "internal_ip": ip.startswith("10."), "emergency_status": bool(emergency),
            "logins": int(logins), "login_failures": int(fails), "ehr_reads": int(reads),
            "export_kb": round(float(export_kb), 1), "requests": int(requests),
            "distinct_endpoints": int(endpoints), "internal_hosts": int(hosts),
            "cpu_usage": round(float(cpu), 3), "mem_spike": int(mem_spike),
            "campaign_id": campaign, "attack_family": family, "tier_label": FAMILY_TIER[family],
            "is_attack": family != "normal",
        })

    def _new_campaign(self, family: str) -> str:
        self._campaign_seq += 1
        return f"C{self._campaign_seq:04d}_{family}"

    # ------------------------------------------------------------------ normal traffic
    def normal_traffic(self) -> None:
        rng = self.rng
        for user in self.users:
            share, shifts, reads_pm, kb_per_read, fail_p, ep_pm, offhours_p = ROLES[user["role"]]
            s, e = user["shift"]
            for day in range(self.days):
                base = day * 1440
                weekday = (self.t0 + timedelta(days=day)).weekday()
                works = rng.random() < (0.85 if weekday < 5 else (0.45 if user["role"] in ("nurse", "doctor") else 0.05))
                if works:
                    start = base + s * 60 + int(rng.integers(-20, 20))
                    length = ((e - s) % 24) * 60
                    # about 8 % of shifts are worked remotely (telehealth, admin from home): external IP, same behaviour
                    ip = user["remote_ip"] if rng.random() < 0.08 else user["ip"]
                    self._session(user, ip, start, length, reads_pm * user["activity"], kb_per_read, fail_p, ep_pm)
                # occasional legitimate off-hours session (emergency / on-call)
                if rng.random() < offhours_p:
                    hour = int(rng.integers(0, 24))
                    if not _in_shift(hour, [user["shift"]]):
                        start = base + hour * 60 + int(rng.integers(0, 60))
                        ip = user["remote_ip"] if rng.random() < 0.5 else user["ip"]   # on-call often from home
                        self._session(user, ip, start, int(rng.integers(10, 45)),
                                      reads_pm * 1.2, kb_per_read, fail_p, ep_pm, emergency=True)

    def _session(self, user, ip, start, length, reads_pm, kb_per_read, fail_p, ep_pm, emergency=False):
        rng = self.rng
        length = max(1, min(length, self.minutes - start - 1))
        if start < 0 or length <= 0:
            return
        # activity intensity follows a smooth curve over the session (busier mid-shift)
        x = np.linspace(0, np.pi, length)
        lam = reads_pm * (0.6 + 0.6 * np.sin(x)) * rng.uniform(0.8, 1.2)
        reads = rng.poisson(lam)
        eps = rng.poisson(ep_pm * (0.6 + 0.6 * np.sin(x)))
        # login at session start (with a few failures sometimes)
        login_fail = int(rng.binomial(3, fail_p))
        for i in np.nonzero((reads > 0) | (eps > 0))[0]:
            m = start + int(i)
            if m >= self.minutes:
                break
            r = int(reads[i])
            self._emit(m, user, ip, logins=1 if i == 0 else 0, fails=login_fail if i == 0 else 0,
                       reads=r, export_kb=r * kb_per_read * rng.uniform(0.6, 1.5),
                       requests=r + int(eps[i]) + (1 if i == 0 else 0),
                       endpoints=min(6, 1 + int(eps[i])), hosts=1, emergency=emergency)

    # ------------------------------------------------------------------ attacks
    def attacks(self) -> None:
        rng = self.rng
        scale = self.days / 14.0
        for family, n14 in CAMPAIGNS_PER_14D.items():
            n = max(1, int(round(n14 * scale)))
            for _ in range(n):
                getattr(self, "_atk_" + family)(self._new_campaign(family))

    def _victim(self):
        return self.users[int(self.rng.integers(len(self.users)))]

    def _start(self, margin: int) -> int:
        return int(self.rng.integers(60, max(61, self.minutes - margin - 1)))

    def _atk_recon(self, cid):
        rng = self.rng
        attacker = {"user_id": "anonymous", "role": "unknown", "shift": (0, 0)}
        ip = _public_ip(rng)
        start = self._start(60)
        for i in range(int(rng.integers(5, 40))):
            m = start + i
            if m >= self.minutes:
                break
            req = int(rng.integers(3, 15))
            self._emit(m, attacker, ip, requests=req, endpoints=min(40, req), reads=0, family="recon", campaign=cid)

    def _atk_brute_force(self, cid):
        rng = self.rng
        attacker = {"user_id": "anonymous", "role": "unknown", "shift": (0, 0)}
        ip = _public_ip(rng)
        start = self._start(30)
        for i in range(int(rng.integers(4, 25))):
            m = start + i
            if m >= self.minutes:
                break
            fails = int(rng.integers(20, 180))
            self._emit(m, attacker, ip, logins=fails, fails=fails, requests=fails, endpoints=1,
                       cpu=float(np.clip(rng.normal(0.45, 0.1), 0.2, 0.9)), family="brute_force", campaign=cid)

    def _atk_brute_force_slow(self, cid):
        rng = self.rng
        attacker = {"user_id": "anonymous", "role": "unknown", "shift": (0, 0)}
        ip = _public_ip(rng)
        start = self._start(400)
        for i in range(int(rng.integers(120, 360))):          # 2-6 hours
            m = start + i
            if m >= self.minutes:
                break
            fails = int(rng.integers(1, 5))                     # 1-4 failures a minute
            if rng.random() < 0.7:
                self._emit(m, attacker, ip, logins=fails, fails=fails, requests=fails, endpoints=1,
                           family="brute_force_slow", campaign=cid)

    def _atk_exfiltration(self, cid):
        rng = self.rng
        victim = self._victim()                                  # compromised account
        ip = _public_ip(rng) if rng.random() < 0.6 else victim["ip"]
        start = self._start(90)
        for i in range(int(rng.integers(10, 60))):
            m = start + i
            if m >= self.minutes:
                break
            reads = int(rng.integers(3, 12))                     # 180-720 reads/h
            self._emit(m, victim, ip, logins=1 if i == 0 else 0, reads=reads,
                       export_kb=reads * rng.uniform(60, 250),   # 10-100 KB per record
                       requests=reads + 1, endpoints=int(rng.integers(2, 5)), hosts=1,
                       family="exfiltration", campaign=cid)

    def _atk_exfiltration_slow(self, cid):
        rng = self.rng
        victim = self._victim()
        ip = victim["ip"] if rng.random() < 0.7 else _public_ip(rng)
        start = self._start(1500)
        hours = int(rng.integers(6, 30))
        for i in range(hours * 60):
            m = start + i
            if m >= self.minutes:
                break
            if rng.random() < 0.016:                             # ~1 read a minute, 40-60 reads/h
                reads = 1
                self._emit(m, victim, ip, reads=reads, export_kb=rng.uniform(5.0, 8.5),  # <= ~450 KB/h
                           requests=reads, endpoints=1, hosts=1, family="exfiltration_slow", campaign=cid)

    def _ddos(self, cid, family, cpu_lo, cpu_hi, minutes):
        rng = self.rng
        attacker = {"user_id": "anonymous", "role": "unknown", "shift": (0, 0)}
        start = self._start(minutes + 5)
        ips = [_public_ip(rng) for _ in range(int(rng.integers(3, 12)))]
        for i in range(minutes):
            m = start + i
            if m >= self.minutes:
                break
            for ip in ips:
                req = int(rng.integers(40, 400))
                self._emit(m, attacker, ip, requests=req, endpoints=int(rng.integers(1, 6)),
                           cpu=float(rng.uniform(cpu_lo, cpu_hi)), mem_spike=int(cpu_lo >= 0.8),
                           family=family, campaign=cid)

    def _atk_ddos_mild(self, cid):
        self._ddos(cid, "ddos_mild", 0.62, 0.78, int(self.rng.integers(3, 12)))

    def _atk_ddos_severe(self, cid):
        self._ddos(cid, "ddos_severe", 0.82, 1.0, int(self.rng.integers(8, 30)))

    def _atk_ransomware(self, cid):
        rng = self.rng
        victim = self._victim()
        start = self._start(60)
        for i in range(int(rng.integers(8, 40))):
            m = start + i
            if m >= self.minutes:
                break
            hosts = min(12, 1 + i // 3)                          # spreads to more hosts over time
            self._emit(m, victim, victim["ip"], reads=int(rng.integers(0, 4)),
                       export_kb=rng.uniform(50, 400), requests=int(rng.integers(10, 60)),
                       endpoints=int(rng.integers(3, 10)), hosts=hosts,
                       cpu=float(rng.uniform(0.8, 1.0)), mem_spike=1, family="ransomware", campaign=cid)

    def _atk_insider_offhours(self, cid):
        rng = self.rng
        victim = self._victim()
        # pick an hour outside the user's shift
        for _ in range(20):
            day = int(rng.integers(0, self.days))
            hour = int(rng.integers(0, 24))
            if not _in_shift(hour, [victim["shift"]]):
                break
        start = day * 1440 + hour * 60 + int(rng.integers(0, 60))
        for i in range(int(rng.integers(15, 70))):
            m = start + i
            if m >= self.minutes:
                break
            if rng.random() < 0.6:
                reads = int(rng.integers(1, 4))
                self._emit(m, victim, victim["ip"], logins=1 if i == 0 else 0, reads=reads,
                           export_kb=reads * rng.uniform(15, 40), requests=reads, endpoints=int(rng.integers(1, 3)),
                           hosts=1, family="insider_offhours", campaign=cid)

    def _atk_credential_stuffing(self, cid):
        """One external IP tries leaked passwords across MANY accounts, succeeds on a few and reads
        records. Different shape from brute force (few failures per account, many accounts)."""
        rng = self.rng
        ip = _public_ip(rng)
        start = self._start(120)
        n_targets = min(len(self.users), int(rng.integers(15, 40)))   # the draw is made before the cap, so large runs are unchanged
        targets = [self.users[int(i)] for i in rng.choice(len(self.users), size=n_targets, replace=False)]
        for k, user in enumerate(targets):
            m = start + k * int(rng.integers(1, 4))
            if m >= self.minutes:
                break
            fails = int(rng.integers(1, 4))
            success = rng.random() < 0.15
            reads = int(rng.integers(5, 20)) if success else 0
            self._emit(m, user, ip, logins=fails + int(success), fails=fails, reads=reads,
                       export_kb=reads * rng.uniform(30, 90), requests=fails + reads + 1,
                       endpoints=int(rng.integers(1, 4)), hosts=1, family="credential_stuffing", campaign=cid)

    # ------------------------------------------------------------------ run
    def run(self) -> list[dict]:
        self.normal_traffic()
        self.attacks()
        self.records.sort(key=lambda r: (r["ts"], r["user_id"], r["ip"]))
        return self.records


def write_jsonl_gz(records: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--users", type=int, default=120)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default=os.path.join(_ROOT, "data", "events_sim.jsonl.gz"))
    a = ap.parse_args()
    sim = Simulator(a.days, a.users, a.seed)
    recs = sim.run()
    write_jsonl_gz(recs, a.out)
    n_att = sum(r["is_attack"] for r in recs)
    fam = {}
    for r in recs:
        fam[r["attack_family"]] = fam.get(r["attack_family"], 0) + 1
    print(f"{len(recs):,} minute-records over {a.days} days, {a.users} users; attack records {n_att:,} "
          f"({100 * n_att / len(recs):.1f}%)")
    for k, v in sorted(fam.items(), key=lambda kv: -kv[1]):
        print(f"  {k:22s} {v:8,d}  tier={FAMILY_TIER[k]}")
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
