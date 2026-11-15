#!/usr/bin/env python3
"""
canary_watch.py — look for minted canary tokens where they should never appear.

Mirage serves decoy records that carry canary tokens (logs/canary_registry.jsonl). A token showing
up anywhere outside that registry — an outbound proxy log, a mail gateway log, a paste-site feed
you mirror locally — proves that decoy data left the hospital and from which session. This script
scans the files listed in config/canary_watch.json, records hits in logs/canary_hits.jsonl, and
raises an alert through the configured (cloud-free) notifier.

    python3 scripts/canary_watch.py --once          # single pass
    python3 scripts/canary_watch.py                 # loop every interval_sec
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from _paths import CANARY_LOG, CONFIG_DIR, LOGS_DIR, p as _p  # noqa: E402

CONFIG = os.path.join(CONFIG_DIR, "canary_watch.json")
HITS = os.path.join(LOGS_DIR, "canary_hits.jsonl")
DEFAULT_CONFIG = {
    "_comment": "Files to scan for canary tokens, relative to the project root or absolute. Add proxy, mail and DLP logs here.",
    "scan_paths": ["logs/events.jsonl", "logs/network_actions.log"],
    "interval_sec": 300,
}


def load_config() -> dict:
    if not os.path.exists(CONFIG):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        return dict(DEFAULT_CONFIG)
    with open(CONFIG, "r", encoding="utf-8") as f:
        return json.load(f)


def load_tokens() -> dict[str, dict]:
    tokens: dict[str, dict] = {}
    if not os.path.exists(CANARY_LOG):
        return tokens
    with open(CANARY_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("canary_id"):
                tokens[e["canary_id"]] = e
    return tokens


def previous_hits() -> set[tuple[str, str]]:
    seen = set()
    if os.path.exists(HITS):
        with open(HITS, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    h = json.loads(line)
                    seen.add((h.get("canary_id", ""), h.get("file", "")))
                except json.JSONDecodeError:
                    continue
    return seen


def scan_once(cfg: dict, notify: bool = True) -> list[dict]:
    tokens = load_tokens()
    if not tokens:
        return []
    seen = previous_hits()
    hits = []
    for rel in cfg.get("scan_paths", []):
        path = rel if os.path.isabs(rel) else _p(*rel.split("/"))
        if not os.path.exists(path) or os.path.abspath(path) == os.path.abspath(CANARY_LOG):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        for tok, meta in tokens.items():
            if tok in text and (tok, rel) not in seen:
                hit = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "canary_id": tok, "file": rel,
                       "minted_at": meta.get("issued_at"), "session_id": meta.get("session_id"), "endpoint": meta.get("endpoint")}
                hits.append(hit)
    if hits:
        os.makedirs(LOGS_DIR, exist_ok=True)
        with open(HITS, "a", encoding="utf-8") as f:
            for h in hits:
                f.write(json.dumps(h) + "\n")
        if notify:
            try:
                from notifications import get_notifier
                for h in hits:
                    get_notifier().send_alert(
                        f"🪤 CANARY TRIGGERED\nToken {h['canary_id']} minted {h['minted_at']} for session {h['session_id']} "
                        f"({h['endpoint']}) was found in {h['file']}. Decoy data has left the system: treat that session as a confirmed breach.")
            except Exception:
                pass
    return hits


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()
    cfg = load_config()
    while True:
        hits = scan_once(cfg)
        print(f"[canary_watch] {datetime.now(timezone.utc).isoformat(timespec='seconds')} scanned {len(cfg.get('scan_paths', []))} files, "
              f"{len(load_tokens())} tokens, {len(hits)} new hit(s)")
        if a.once:
            break
        time.sleep(int(cfg.get("interval_sec", 300)))


if __name__ == "__main__":
    main()
