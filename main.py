#!/usr/bin/env python3
"""
Command-line login for the 简讯 (api.jianxun01.com) app.

Account / device / security Q&A / base-url are read from the global
``config.json`` (see ``jianxun/config.py``).  Any CLI flag overrides the
corresponding config value.

Login supports both a username account (``--username``) and a phone account
(``--phone`` + ``--country-code``).  On an unrecognised device the server asks
for verification (status 110 "新设备需要验证"); the client then automatically
retries with the configured security question + answer.

Examples
--------
    # use everything from config.json (qwe778800 + security Q&A)
    python main.py

    # username account, explicit security answer
    python main.py --username qwe778800 --password qwe778800 \
                   --security-question "儿时养的第一只宠物的名字" --security-answer "小狗赛虎"

    # phone account
    python main.py --phone 15303021909 --password Asdfghjkl123 --country-code 0086

    # force a brand-new device to exercise the strange-device verify path
    python main.py --device-id $(python - <<<'import secrets;print(secrets.token_hex(8))')
"""
import argparse
import json
import sys

from jianxun import JianxunClient, DeviceInfo, NewDeviceVerifyRequired, ApiError
from jianxun.config import Config


def main() -> int:
    ap = argparse.ArgumentParser(description="简讯 password login (reverse-engineered)")
    ap.add_argument("--config", default=None,
                    help="Path to config.json (default: project config.json / $JIANXUN_CONFIG)")
    ap.add_argument("--username", default=None, help="Username account (takes precedence over --phone)")
    ap.add_argument("--phone", default=None, help="Phone account (wire username = country_code + phone)")
    ap.add_argument("--password", default=None)
    ap.add_argument("--country-code", default=None)
    ap.add_argument("--security-question", default=None)
    ap.add_argument("--security-answer", default=None)
    ap.add_argument("--no-verify", action="store_true",
                    help="Do not auto-retry security verification on a new device")
    ap.add_argument("--device-id", default=None,
                    help="Android ID. Unknown devices require security verification (status 110).")
    ap.add_argument("--device-model", default=None)
    ap.add_argument("--device-name", default=None)
    ap.add_argument("--base-url", default=None)
    args = ap.parse_args()

    # Load global config, then let CLI flags override individual fields.
    cfg = Config.load(args.config)
    password = args.password or cfg.account.password
    country_code = args.country_code or cfg.account.country_code
    base_url = args.base_url or cfg.base_url

    # Resolve the account: --username > --phone > config.
    if args.username is not None:
        username, phone = args.username, None
    elif args.phone is not None:
        username, phone = None, args.phone
    else:
        username, phone = (cfg.account.username or None), (cfg.account.phone or None)

    client = JianxunClient(base_url=base_url)
    device = DeviceInfo(
        device_model=args.device_model or cfg.device.device_model,
        device_id=args.device_id or cfg.device.device_id,
        device_name=args.device_name or cfg.device.device_name,
    )
    sec_q = args.security_question if args.security_question is not None else cfg.security.question
    sec_a = args.security_answer if args.security_answer is not None else cfg.security.answer

    wire = username if username else f"{country_code}{phone}"
    if cfg.path:
        print(f"[*] config   : {cfg.path}")
    print(f"[*] account  : {wire}")
    print(f"[*] device_id: {device.device_id}")
    print("[*] logging in ...")
    try:
        result = client.login(
            username=username, phone=phone, password=password, country_code=country_code,
            device=device, security_question=sec_q, security_answer=sec_a,
            verify_on_new_device=not args.no_verify,
        )
    except NewDeviceVerifyRequired as e:
        print(f"[!] {e.msg} (status {e.status}) - security verification needed.")
        print("    Set security.question / security.answer in config.json (or pass --security-answer).")
        return 2
    except ApiError as e:
        print(f"[!] login failed: {e}")
        return 1

    print("[+] LOGIN OK")
    print(f"    uid      : {result.uid}")
    print(f"    name     : {result.name}")
    print(f"    username : {result.username}")
    print(f"    token    : {result.token}")
    print("[*] full profile:")
    print(json.dumps(result.raw, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
