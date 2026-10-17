#!/usr/bin/env python3
"""
Decrypt a captured ``{"data": "<base64>"}`` body (request or response) with the
derived session key.  Handy for inspecting traffic captured from the app.

Usage:
    python tools/decrypt_capture.py '<base64-data-string>'
    echo '{"data":"...."}' | python tools/decrypt_capture.py        # reads stdin JSON
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from jianxun import crypto  # noqa: E402


def main() -> int:
    if len(sys.argv) > 1:
        blob = sys.argv[1].strip()
    else:
        blob = sys.stdin.read().strip()
    # accept either the raw base64 or a full {"data": "..."} envelope
    if blob.startswith("{"):
        blob = json.loads(blob)["data"]
    pt = crypto.decrypt(blob, verify=False)
    try:
        print(json.dumps(json.loads(pt), indent=2, ensure_ascii=False))
    except ValueError:
        print(pt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
