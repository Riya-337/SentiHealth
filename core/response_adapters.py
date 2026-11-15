"""
response_adapters.py — the point where SentiHealth touches real infrastructure.

Before this module, block_ip / throttle_bandwidth / lock_account only wrote log lines. Now:

- FirewallAdapter.block_ip / unblock_ip manage an nftables set (inet sentihealth blocked) when
  SENTIHEALTH_DRY_RUN=0 and the `nft` binary is available; otherwise the command is recorded but
  not run (dry run is the DEFAULT, so a fresh install never blocks anything by accident).
- Every action is appended to logs/response_actions.jsonl with an optional TTL; expire_actions()
  reverses blocks whose TTL has passed, so a mistaken block heals itself.
- DirectoryAdapter.lock_account is an integration point: it runs the command template given in
  SENTIHEALTH_LOCK_CMD (for example a PowerShell or ldapmodify wrapper) with {user} substituted.
  Without that variable it is a documented no-op. There is no safe generic way to lock an
  Active Directory account from here, so this is deliberately left to the deployment.
- throttle() records the intended tc/nft rate limit; applying it needs the interface name
  (SENTIHEALTH_THROTTLE_IFACE) and is also gated by DRY_RUN.
"""
from __future__ import annotations

import ipaddress
import json
import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_HERE, _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)
from _paths import LOGS_DIR  # noqa: E402

ACTIONS_LOG = os.path.join(LOGS_DIR, "response_actions.jsonl")
DEFAULT_BLOCK_TTL_MIN = int(os.environ.get("SENTIHEALTH_BLOCK_TTL_MIN", "240"))


def dry_run() -> bool:
    return os.environ.get("SENTIHEALTH_DRY_RUN", "1") != "0"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _record(action: dict) -> dict:
    os.makedirs(LOGS_DIR, exist_ok=True)
    action.setdefault("ts", _now().isoformat(timespec="seconds"))
    action.setdefault("dry_run", dry_run())
    with open(ACTIONS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(action) + "\n")
    return action


def _run(cmd: list[str]) -> tuple[bool, str]:
    """Run a command unless in dry run. Returns (ok, output)."""
    if dry_run():
        return True, "dry-run: " + " ".join(shlex.quote(c) for c in cmd)
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        return res.returncode == 0, (res.stdout + res.stderr).strip()
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)


def load_actions() -> list[dict]:
    if not os.path.exists(ACTIONS_LOG):
        return []
    out = []
    with open(ACTIONS_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out


class FirewallAdapter:
    TABLE, SET = "sentihealth", "blocked"

    def available(self) -> bool:
        return shutil.which("nft") is not None

    def setup(self) -> tuple[bool, str]:
        """Create the table/set/chain once (idempotent)."""
        cmds = [
            ["nft", "add", "table", "inet", self.TABLE],
            ["nft", "add", "set", "inet", self.TABLE, self.SET, "{ type ipv4_addr; flags interval; }"],
            ["nft", "add", "chain", "inet", self.TABLE, "input", "{ type filter hook input priority 0; }"],
            ["nft", "add", "rule", "inet", self.TABLE, "input", "ip", "saddr", f"@{self.SET}", "drop"],
        ]
        out = []
        for c in cmds:
            ok, msg = _run(c)
            out.append(msg)
            if not ok and "exists" not in msg.lower():
                return False, "\n".join(out)
        return True, "\n".join(out)

    def block_ip(self, ip: str, ttl_min: int | None = DEFAULT_BLOCK_TTL_MIN, reason: str = "") -> dict:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return _record({"action": "block_ip", "ip": ip, "ok": False, "detail": "invalid address", "reason": reason})
        if self.available() or dry_run():
            ok, detail = _run(["nft", "add", "element", "inet", self.TABLE, self.SET, f"{{ {ip} }}"])
        else:
            ok, detail = False, "nft not installed"
        expires = (_now() + timedelta(minutes=ttl_min)).isoformat(timespec="seconds") if ttl_min else None
        return _record({"action": "block_ip", "ip": ip, "ok": ok, "detail": detail, "expires_at": expires, "reason": reason})

    def unblock_ip(self, ip: str, reason: str = "") -> dict:
        if self.available() or dry_run():
            ok, detail = _run(["nft", "delete", "element", "inet", self.TABLE, self.SET, f"{{ {ip} }}"])
        else:
            ok, detail = False, "nft not installed"
        return _record({"action": "unblock_ip", "ip": ip, "ok": ok, "detail": detail, "reason": reason})

    def throttle(self, percent: int = 1, reason: str = "") -> dict:
        iface = os.environ.get("SENTIHEALTH_THROTTLE_IFACE", "")
        if not iface:
            return _record({"action": "throttle", "percent": percent, "ok": True,
                            "detail": "recorded only: set SENTIHEALTH_THROTTLE_IFACE to apply", "reason": reason})
        rate = f"{max(1, percent)}mbit"
        ok, detail = _run(["tc", "qdisc", "replace", "dev", iface, "root", "tbf", "rate", rate, "burst", "32kbit", "latency", "400ms"])
        return _record({"action": "throttle", "percent": percent, "iface": iface, "ok": ok, "detail": detail, "reason": reason})

    def unthrottle(self, reason: str = "") -> dict:
        iface = os.environ.get("SENTIHEALTH_THROTTLE_IFACE", "")
        if not iface:
            return _record({"action": "unthrottle", "ok": True, "detail": "recorded only", "reason": reason})
        ok, detail = _run(["tc", "qdisc", "del", "dev", iface, "root"])
        return _record({"action": "unthrottle", "iface": iface, "ok": ok, "detail": detail, "reason": reason})


class DirectoryAdapter:
    def lock_account(self, user_id: str, reason: str = "") -> dict:
        tmpl = os.environ.get("SENTIHEALTH_LOCK_CMD", "").strip()
        if not tmpl:
            return _record({"action": "lock_account", "user": user_id, "ok": True,
                            "detail": "recorded only: set SENTIHEALTH_LOCK_CMD to call the directory", "reason": reason})
        cmd = [part.replace("{user}", user_id) for part in shlex.split(tmpl)]
        ok, detail = _run(cmd)
        return _record({"action": "lock_account", "user": user_id, "ok": ok, "detail": detail, "reason": reason})

    def unlock_account(self, user_id: str, reason: str = "") -> dict:
        tmpl = os.environ.get("SENTIHEALTH_UNLOCK_CMD", "").strip()
        if not tmpl:
            return _record({"action": "unlock_account", "user": user_id, "ok": True, "detail": "recorded only", "reason": reason})
        cmd = [part.replace("{user}", user_id) for part in shlex.split(tmpl)]
        ok, detail = _run(cmd)
        return _record({"action": "unlock_account", "user": user_id, "ok": ok, "detail": detail, "reason": reason})


def expire_actions() -> list[dict]:
    """Reverse blocks whose TTL has passed and that were not already reversed. Returns what was undone."""
    actions = load_actions()
    undone_ips = {a["ip"] for a in actions if a.get("action") == "unblock_ip" and a.get("ip")}
    now = _now()
    fw = FirewallAdapter()
    out = []
    for a in actions:
        if a.get("action") != "block_ip" or not a.get("expires_at") or a.get("ip") in undone_ips:
            continue
        try:
            exp = datetime.fromisoformat(a["expires_at"])
        except ValueError:
            continue
        if exp <= now:
            out.append(fw.unblock_ip(a["ip"], reason=f"TTL expired ({a['expires_at']})"))
            undone_ips.add(a["ip"])
    return out


def status() -> dict:
    acts = load_actions()
    return {
        "dry_run": dry_run(),
        "nft_available": FirewallAdapter().available(),
        "lock_cmd_configured": bool(os.environ.get("SENTIHEALTH_LOCK_CMD")),
        "throttle_iface": os.environ.get("SENTIHEALTH_THROTTLE_IFACE", ""),
        "actions_total": len(acts),
        "recent": acts[-10:],
    }
