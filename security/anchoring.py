"""
anchoring.py — pin the audit chain's head to a place an attacker on the host cannot rewrite.

The hash chain in data/audit_chain.json detects edits inside the chain, but someone with root can
rewrite the whole file and its replica consistently. An anchor is the chain head (block index +
entry hash) written somewhere else: by default data/anchors.jsonl (which is only a start), and in
production a path on a WORM share, a second machine, or a printer, through SENTIHEALTH_ANCHOR_FILE.
verify_anchors() checks that every anchored block is still in the chain with the same hash.
Run scripts/anchor_chain.py from a timer (config/systemd has a template).
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_HERE, _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)
from _paths import AUDIT_CHAIN, DATA_DIR  # noqa: E402

ANCHOR_FILE = os.environ.get("SENTIHEALTH_ANCHOR_FILE", os.path.join(DATA_DIR, "anchors.jsonl"))


def _load_chain() -> list:
    if not os.path.exists(AUDIT_CHAIN):
        return []
    with open(AUDIT_CHAIN, "r", encoding="utf-8") as f:
        return json.load(f)


def chain_head() -> dict | None:
    chain = _load_chain()
    if not chain:
        return None
    return {"block_index": len(chain) - 1, "entry_hash": chain[-1].get("entry_hash", "")}


def load_anchors(path: str = ANCHOR_FILE) -> list[dict]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out


def anchor_now(note: str = "", path: str = ANCHOR_FILE) -> dict | None:
    head = chain_head()
    if head is None:
        return None
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **head, "note": note}
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def verify_anchors(path: str = ANCHOR_FILE) -> dict:
    """Every anchor must still match the chain at its block index."""
    chain = _load_chain()
    anchors = load_anchors(path)
    mismatches = []
    for a in anchors:
        idx = int(a.get("block_index", -1))
        if idx < 0 or idx >= len(chain):
            mismatches.append({"anchor": a, "problem": "block missing: chain is shorter than when anchored"})
        elif chain[idx].get("entry_hash") != a.get("entry_hash"):
            mismatches.append({"anchor": a, "problem": "hash differs: chain rewritten at or before this block"})
    return {
        "anchor_file": path,
        "anchors": len(anchors),
        "last_anchor": anchors[-1] if anchors else None,
        "chain_length": len(chain),
        "ok": not mismatches,
        "mismatches": mismatches,
    }
