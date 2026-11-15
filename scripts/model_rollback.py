#!/usr/bin/env python3
"""
model_rollback.py — go back to an earlier model set.

ml/train.py archives the previous models to models/archive/<version>/ and appends to
models/registry.json before writing new ones. This script copies an archived set back into
models/ (after archiving the current one), so a bad retrain can be undone in seconds.

    python3 scripts/model_rollback.py --list
    python3 scripts/model_rollback.py <version>
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_ROOT, os.path.join(_ROOT, "ml")):
    if p not in sys.path:
        sys.path.insert(0, p)
from _paths import MODELS_DIR  # noqa: E402

ARCHIVE = os.path.join(MODELS_DIR, "archive")


def versions() -> list[str]:
    if not os.path.isdir(ARCHIVE):
        return []
    return sorted(d for d in os.listdir(ARCHIVE) if os.path.isdir(os.path.join(ARCHIVE, d)))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("version", nargs="?")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    reg_path = os.path.join(MODELS_DIR, "registry.json")
    registry = json.load(open(reg_path)) if os.path.exists(reg_path) else []
    if a.list or not a.version:
        print("archived versions:")
        for v in versions():
            meta = next((r for r in registry if r.get("version", "").replace(":", "-") == v), {})
            print(f"  {v}  model={meta.get('supervised_model', '?')}  val_macro_f1={meta.get('val_macro_f1', '?')}")
        return 0
    src = os.path.join(ARCHIVE, a.version.replace(":", "-"))
    if not os.path.isdir(src):
        print(f"no archived version '{a.version}'; use --list", file=sys.stderr)
        return 1
    from train import archive_previous
    current = archive_previous(MODELS_DIR)
    for name in os.listdir(src):
        shutil.copy2(os.path.join(src, name), os.path.join(MODELS_DIR, name))
    registry.append({"version": a.version, "rolled_back": True, "replaced": current})
    with open(reg_path, "w") as f:
        json.dump(registry, f, indent=2)
    print(f"rolled back to {a.version}; the replaced set was archived to {current}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
