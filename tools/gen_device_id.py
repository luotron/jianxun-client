#!/usr/bin/env python3
"""
Generate a usable ``device_id`` for 简讯 login.

Algorithm (recovered from libapp.so)
------------------------------------
The login payload ``device.device_id`` is an **Android-ID-style** value:
16 lowercase hex chars = a 64-bit id = 8 random bytes hex-encoded.  In the app
this is the real Android ID obtained via the ``device_info_plus`` plugin
(``dev.fluttercommunity.plus/device_info`` -> ``Settings.Secure.ANDROID_ID``).
The server accepts any well-formed value and binds account<->device; a device
it has not seen for the account then requires security-question verification
(which ``JianxunClient.login`` performs automatically).

The app ALSO keeps a separate *install id* in SharedPreferences under the key
``<prefix>_device_id`` generated as ``uuid.v4().replaceAll('-','')`` (32 hex,
see ``sub_FABB48``).  That value is used for device bookkeeping, not for the
login ``device_id``; this tool can emit either form.

Usage
-----
    python tools/gen_device_id.py                 # one android-style id (16 hex)
    python tools/gen_device_id.py -n 5            # five ids
    python tools/gen_device_id.py --style uuid    # app install-id style (32 hex)
    python tools/gen_device_id.py --set-config    # also write it into config.json
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import uuid


def gen_android_id() -> str:
    """16 lowercase hex chars (64-bit), same shape as Android ID."""
    return secrets.token_hex(8)


def gen_uuid_id() -> str:
    """32 lowercase hex chars = uuid4 without dashes (app install-id style)."""
    return uuid.uuid4().hex


def _set_config_device_id(value: str) -> str:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "config.json")
    cfg = {}
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    cfg.setdefault("device", {})["device_id"] = value
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a usable device_id")
    ap.add_argument("--style", choices=["android", "uuid"], default="android",
                    help="android: 16 hex (login device_id); uuid: 32 hex (app install id)")
    ap.add_argument("-n", "--count", type=int, default=1, help="how many to print")
    ap.add_argument("--set-config", action="store_true",
                    help="write the first generated id into config.json device.device_id")
    args = ap.parse_args()

    gen = gen_android_id if args.style == "android" else gen_uuid_id
    ids = [gen() for _ in range(max(1, args.count))]
    for i in ids:
        print(i)

    if args.set_config:
        path = _set_config_device_id(ids[0])
        print(f"[*] wrote device_id={ids[0]} -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
