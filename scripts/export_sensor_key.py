#!/usr/bin/env python3
"""
export_sensor_key.py — print the event-signing key for a sensor (the EHR web app, a log shipper).

The key is created in config/.secrets_vault.json on first use. Give it to each sensor through its
environment (SENTIHEALTH_EVENT_KEY) over a channel you trust; never commit it. Rotating it means
re-exporting to every sensor.

    python3 scripts/export_sensor_key.py            # prints the hex key
    python3 scripts/export_sensor_key.py --rotate   # new key (sensors must be updated)
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_ROOT, os.path.join(_ROOT, "security")):
    if p not in sys.path:
        sys.path.insert(0, p)
from secrets_vault import get_secret_str, set_secret  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rotate", action="store_true")
    a = ap.parse_args()
    key = get_secret_str("EVENT_SIGNING_KEY", "")
    if a.rotate or not key:
        key = secrets.token_hex(32)
        set_secret("EVENT_SIGNING_KEY", key)
        print("# new key written to the vault" + (" (rotated)" if a.rotate else ""), file=sys.stderr)
    print(f"export SENTIHEALTH_EVENT_KEY={key}")


if __name__ == "__main__":
    main()
