"""Connect once and optionally send/receive messages on that same socket."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from jianxun.config import Config
from jianxun.im import WKIMClient


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config")
    parser.add_argument("--receive", type=float, default=0, metavar="SECONDS")
    parser.add_argument("--channel", help="Destination uid or group_no")
    parser.add_argument("--channel-type", type=int, default=2)
    parser.add_argument("--text")
    parser.add_argument("--device-flag", type=int, default=0)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.text is not None and not args.channel:
        parser.error("--text requires --channel")
    cfg = Config.load(args.config)
    result = {}
    try:
        with WKIMClient(addr=cfg.im_addr, uid=cfg.uid, token=cfg.token,
                        device_id=cfg.device.device_id, device_flag=args.device_flag,
                        qlck=cfg.qlck if cfg.im_transport == "appvest" else None) as im:
            result.update(connected=True, gateway=im.gateway)
            print(json.dumps(result, ensure_ascii=True), flush=True)
            if args.text is not None:
                ack = im.send_text(args.channel, args.text, args.channel_type)
                result["send_ack"] = asdict(ack)
                result["send_succeeded"] = ack.success
                result["send_reason"] = ack.reason_name
            if args.receive:
                result["received"] = asdict(im.recv_message(args.receive))
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True), flush=True)
    return 1 if "error" in result or result.get("send_succeeded") is False else 0


if __name__ == "__main__":
    raise SystemExit(main())
