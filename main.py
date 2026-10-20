#!/usr/bin/env python3
"""
Command-line (interactive) client for the 简讯 (api.jianxun01.com) app.

Startup policy
--------------
* default: reuse the session ``token`` persisted in ``config.json``;
* if the saved token is missing / expired / invalid -> automatically log in
  with ``config.json`` (username+password, or phone+password when ``username``
  is empty), and persist the fresh token back to ``config.json``;
* if the server demands the Aliyun behaviour captcha (status 220) the login
  is cancelled -- this client does not solve captchas;
* on an unrecognised device the client automatically retries with the
  configured security question + answer (status 110 "新设备需要验证").

Runtime menu (all interactive)
------------------------------
* 查询群: fetches ``GET /v1/group/my`` and lets you pick a group by number,
  then view members/profile, send text/images, or show history and keep
  listening for new messages. Ctrl+C stops listening and returns to the menu.

Examples
--------
    python main.py                 # interactive; uses config.json
    JIANXUN_CONFIG=/path/to/other.json python main.py
"""
import json
import sys
from collections import deque
from datetime import datetime

from requests.exceptions import RequestException

from jianxun import (
    JianxunClient, DeviceInfo, ApiError, NewDeviceVerifyRequired, CaptchaRequired,
)
from jianxun.client import image_dimensions
from jianxun.config import Config
from jianxun.im import WKIMClient, WKIMError, WKIMTimeout, DEFAULT_IM_ADDR


def ask(prompt: str, default: str = "") -> str:
    """Read a line; empty input returns ``default``. Ctrl-C / EOF exits."""
    try:
        value = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(0)
    return value if value else default


def choose_image_file() -> str:
    """Open a desktop file picker; cancelling returns an empty selection."""
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError as exc:
        raise ValueError(
            "选图窗口需要 Tkinter。Windows 请安装 Python 的 Tcl/Tk 组件；"
            "Ubuntu/Debian 可运行 sudo apt install python3-tk。"
        ) from exc

    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        root.update()
        return filedialog.askopenfilename(
            parent=root,
            title="选择要发送到当前群的图片",
            filetypes=[
                ("PNG / JPEG 图片", "*.png *.jpg *.jpeg *.PNG *.JPG *.JPEG"),
                ("所有文件", "*"),
            ],
        ) or ""
    except tk.TclError as exc:
        raise ValueError("无法打开选图窗口，请在有图形桌面的终端中运行 main.py。") from exc
    finally:
        if root is not None:
            root.destroy()


def try_saved_token(cfg: Config, client: JianxunClient) -> bool:
    """Validate the token persisted in config.json via ``GET /group/my``."""
    token = (cfg.token or "").strip()
    if not token:
        return False
    client.token = token
    print(f"[*] 使用已保存 token: {token[:8]}...")
    try:
        client.get_group_list()
    except ApiError:
        print("[!] token 已过期/失效，改用账号密码登录。")
        client.token = ""
        cfg.save_token("")
        return False
    print("[+] token 有效")
    return True


def auto_login(cfg: Config, client: JianxunClient) -> bool:
    """Login with config.json credentials (username preferred, else phone)."""
    acc = cfg.account
    password = acc.password
    device = DeviceInfo(
        device_id=cfg.device.device_id,
        device_model=cfg.device.device_model,
        device_name=cfg.device.device_name,
    )
    if acc.username:
        username = acc.username
        phone = None
    elif acc.phone:
        username = None
        phone = acc.phone
    else:
        # no credentials in config.json -> ask interactively (username mode)
        username = ask("用户名: ")
        password = ask(f"密码 [{password}]: ", password)
        phone = None
    if not password:
        password = ask(f"密码 [{acc.password}]: ", acc.password)

    wire = username if username else f"{acc.country_code}{phone}"
    print(f"[*] 设备 device_id: {device.device_id}")
    print(f"[*] 登录中: {wire} ...")
    try:
        result = client.login(
            username=username, phone=phone, password=password,
            country_code=acc.country_code, device=device,
            security_question=cfg.security.question,
            security_answer=cfg.security.answer,
            verify_on_new_device=True,
        )
    except NewDeviceVerifyRequired as e:
        print(f"[!] {e.msg} (status 110) - 陌生设备验证未通过（密保问题/答案缺失或错误）。")
        print("    请检查 config.json 的 security.question / security.answer。")
        return False
    except CaptchaRequired as e:
        print(f"[!] 服务端要求阿里云行为验证码 (status {e.status})，已取消登录。")
        return False
    except ApiError as e:
        print(f"[!] 登录失败: {e}")
        return False

    cfg.save_token(result.token, result.uid)
    print("[+] 登录成功")
    print(f"    uid      : {result.uid}")
    print(f"    name     : {result.name}")
    print(f"    username : {result.username or result.phone}")
    print(f"    token    : {result.token}  (已保存到 config.json)")
    return True


def select_group(client: JianxunClient) -> dict | None:
    """Pull the group list, let the user pick one group by number.

    Returns the chosen group dict, or None when the user wants to go back.
    """
    groups = client.get_group_list()
    if not groups:
        print("[*] 没有加入任何群（/group/my 返回空）。")
        return None
    print(f"[*] 共 {len(groups)} 个群:")
    for i, g in enumerate(groups, 1):
        name = g.get("name") or g.get("group_no")
        print(f"    {i}. {name}  ({g.get('group_no')}) 成员:{g.get('member_count', '?')}")
    while True:
        choice = ask(f"选择群 (1-{len(groups)}，回车返回主菜单): ", "0")
        if choice in ("", "0"):
            return None
        if not choice.isdigit():
            print("[!] 请输入序号")
            continue
        idx = int(choice)
        if 1 <= idx <= len(groups):
            return groups[idx - 1]
        print("[!] 序号超出范围")


def print_group_message(message: dict, source: str) -> None:
    """Display HTTP history and IM pushes using the same terminal format."""
    timestamp = message.get("timestamp", 0)
    try:
        clock = datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError, OverflowError):
        clock = str(timestamp)
    payload = message.get("payload", {})
    sender = message.get("from_uid") or "系统"
    if isinstance(payload, dict):
        if payload.get("type") == 2:
            content = f"[图片] {payload.get('url', '')}"
        else:
            content = payload.get("content")
            if content is None:
                content = json.dumps(payload, ensure_ascii=False)
    else:
        content = str(payload)
    rendered = f"[{source}] {clock} #{message.get('message_seq', '?')} {sender}: {content}"
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    print(rendered.encode(encoding, errors="backslashreplace").decode(encoding), flush=True)


def watch_group_messages(
    client: JianxunClient, im: WKIMClient, group_no: str, history_limit: int = 20,
) -> None:
    """Show recent history, then listen until Ctrl+C without closing IM.

    The caller connects IM before this function so pushes arriving during the
    HTTP request are queued. Message IDs deduplicate history/push overlaps.
    """
    if history_limit < 0:
        raise ValueError("历史条数不能为负数")
    seen: set[str] = set()
    recent: deque[str] = deque()
    window = max(2048, history_limit * 2)

    def remember(identity: str) -> bool:
        if identity in seen:
            return False
        seen.add(identity)
        recent.append(identity)
        while len(recent) > window:
            seen.discard(recent.popleft())
        return True

    try:
        if history_limit:
            print(f"[*] 正在拉取最近 {history_limit} 条群历史（Ctrl+C 返回菜单）...", flush=True)
            try:
                page = client.request("POST", "/message/channel/sync", {
                    "channel_id": group_no, "channel_type": 2,
                    "start_message_seq": 0, "end_message_seq": 0,
                    "limit": history_limit, "pull_mode": 0,
                })
                messages = sorted(page["messages"], key=lambda m: int(m["message_seq"]))
            except (ApiError, RequestException, OSError, ValueError, KeyError, TypeError) as exc:
                print(f"[!] 历史加载失败: {exc}；继续实时监听。", flush=True)
            else:
                print(f"[*] 共 {len(messages)} 条历史消息", flush=True)
                for message in messages:
                    if remember(str(message["message_id"])):
                        print_group_message(message, "历史")

        print("[*] 正在持续监听当前群的新消息，按 Ctrl+C 返回菜单（连接保留）。", flush=True)
        while True:
            try:
                # A bounded wait also keeps Ctrl+C responsive on Windows.
                message = im.recv_message(timeout=1.0)
            except WKIMTimeout:
                continue
            if message.channel_id != group_no or message.channel_type != 2:
                continue
            if not remember(str(message.message_id)):
                continue
            print_group_message({
                "message_id": message.message_id,
                "message_seq": message.message_seq,
                "timestamp": message.message_time,
                "from_uid": message.from_uid,
                "payload": message.content,
            }, "新消息")
    except KeyboardInterrupt:
        print("\n[*] 已停止监听，返回群菜单（连接保留）。", flush=True)


def group_view_menu(client: JianxunClient, group: dict, cfg: Config) -> None:
    """View a group, send messages, or show history and listen on the same IM."""
    group_no = group.get("group_no", "")
    name = group.get("name") or group_no
    im_client: WKIMClient | None = None

    def ensure_im() -> WKIMClient:
        nonlocal im_client
        if im_client is None or not im_client.connected:
            if not (cfg.uid and client.token):
                raise WKIMError("缺少 uid/token（请先重新登录获取）")
            im_client = WKIMClient(
                addr=cfg.im_addr or DEFAULT_IM_ADDR,
                uid=cfg.uid,
                token=client.token,
                device_id=cfg.device.device_id,
                qlck=cfg.qlck if cfg.im_transport == "appvest" else None,
            )
            print(f"[*] 连接悟空IM: {im_client.addr} ...")
            im_client.connect()
            print(f"[+] IM 连接成功（会话密钥已协商，网关: {im_client.gateway or '直连'}）")
        return im_client

    try:
        while True:
            print(f"\n当前群: {name} ({group_no})")
            print("请选择操作:")
            print("  1. 查询群成员列表")
            print("  2. 查询群资料")
            print("  3. 发送文字消息")
            print("  4. 发送图片")
            print("  5. 查看历史并持续监听群消息")
            print("  6. 返回群列表")
            choice = ask("> ", "6")
            try:
                if choice == "1":
                    print(f"[*] 自动翻页拉取群成员列表 ...")
                    members = client.get_all_group_members(group_no)
                    print(json.dumps([m.raw for m in members], indent=2, ensure_ascii=False))
                    print(f"[*] 全部成员共 {len(members)} 名（已自动翻页）")
                elif choice == "2":
                    print(json.dumps(client.get_group(group_no), indent=2, ensure_ascii=False))
                elif choice == "3":
                    text = ask("消息内容: ")
                    if not text:
                        continue
                    ack = ensure_im().send_text(group_no, text)
                    if ack.reason_code == 1:
                        print(f"[+] 已发送: messageID={ack.message_id} "
                              f"messageSeq={ack.message_seq} clientSeq={ack.client_seq}")
                    else:
                        print(f"[!] 发送失败: reasonCode={ack.reason_code} ({ack.reason_name})")
                elif choice == "4":
                    print("[*] 请选择图片（取消可返回群菜单）...", flush=True)
                    file_path = choose_image_file()
                    if not file_path:
                        print("[*] 已取消选择图片。")
                        continue
                    width, height = image_dimensions(file_path)
                    if width <= 0 or height <= 0:
                        raise ValueError("无法读取图片尺寸，请使用完整的 PNG 或 JPEG 图片")
                    print("[*] 上传图片 ...")
                    up = client.upload_file(group_no, file_path)
                    image_path = up.get("path")
                    if not isinstance(image_path, str) or not image_path.strip():
                        raise ValueError("上传响应缺少图片预览 path，未发送图片消息")
                    print(f"[*] 上传成功: {image_path}")
                    ack = ensure_im().send_image(group_no, image_path, width, height)
                    if ack.reason_code == 1:
                        print(f"[+] 已发送图片: messageID={ack.message_id} "
                              f"messageSeq={ack.message_seq} ({width}x{height})")
                    else:
                        print(f"[!] 发送失败: reasonCode={ack.reason_code} ({ack.reason_name})")
                elif choice == "5":
                    history_limit = int(ask("显示最近历史条数 [20，0=只监听新消息]: ", "20"))
                    if history_limit < 0:
                        raise ValueError("历史条数不能为负数")
                    watch_group_messages(client, ensure_im(), group_no, history_limit)
                elif choice == "6":
                    return
                else:
                    print("[!] 无效选项")
            except WKIMTimeout as e:
                print(f"[*] {e}（连接保留，可继续收发）")
            except (ApiError, RequestException, ValueError, WKIMError, OSError) as e:
                print(f"[!] 操作失败: {e}")
                if im_client is not None:
                    im_client.close()
                    im_client = None

    finally:
        if im_client is not None:
            im_client.close()


def main() -> int:
    cfg = Config.load()  # honors $JIANXUN_CONFIG
    print("简讯 (jianxun) 命令行客户端")
    print("-" * 60)
    print(f"[*] config   : {cfg.path or '(使用内置默认值)'}")
    print(f"[*] base_url : {cfg.base_url}")
    if cfg.account.username:
        print(f"[*] 账号     : {cfg.account.username} (用户名账号)")
    else:
        print(f"[*] 账号     : {cfg.account.country_code}{cfg.account.phone} (手机号账号)")

    client = JianxunClient(base_url=cfg.base_url)

    # default: saved token; fallback: login with config.json credentials
    if not try_saved_token(cfg, client):
        if not auto_login(cfg, client):
            return 1

    while True:
        print()
        print("请选择操作:")
        print("  1. 查询群（查看成员/资料、收发消息、历史与实时监听）")
        print("  2. 重新登录")
        print("  3. 退出")
        choice = ask("> ", "3")

        if choice == "1":
            while True:
                try:
                    group = select_group(client)
                except ApiError as e:
                    print(f"[!] 拉取群列表失败: {e}")
                    break
                if group is None:
                    break
                group_view_menu(client, group, cfg)
        elif choice == "2":
            cfg = Config.load()
            client = JianxunClient(base_url=cfg.base_url)
            if not auto_login(cfg, client):
                return 1
        elif choice == "3":
            print("bye")
            return 0
        else:
            print("[!] 无效选项")


if __name__ == "__main__":
    sys.exit(main())
