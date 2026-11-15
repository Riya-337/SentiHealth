#!/usr/bin/env python3
"""
anchor_chain.py — write the audit chain head to the anchor file and verify earlier anchors.

Run from a timer (every hour is reasonable). Point SENTIHEALTH_ANCHOR_FILE at a location the
sentinel host cannot rewrite: a WORM share, an append-only bucket on another machine, or a
line printer. Exit code 2 means a previous anchor no longer matches the chain.

    python3 scripts/anchor_chain.py            # anchor now + verify
    python3 scripts/anchor_chain.py --verify   # verify only
"""
from __future__ import annotations

import argparse
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_ROOT, os.path.join(_ROOT, "security")):
    if p not in sys.path:
        sys.path.insert(0, p)
from anchoring import anchor_now, verify_anchors  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verify", action="store_true", help="verify only, do not write a new anchor")
    ap.add_argument("--note", default="")
    a = ap.parse_args()
    if not a.verify:
        rec = anchor_now(a.note)
        print("anchored:", json.dumps(rec) if rec else "no chain yet")
    rep = verify_anchors()
    print(json.dumps({k: v for k, v in rep.items() if k != "mismatches"}, indent=2))
    if not rep["ok"]:
        for m in rep["mismatches"]:
            print("MISMATCH:", json.dumps(m))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
