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
  then view its member list or profile.

Examples
--------
    python main.py                 # interactive; uses config.json
    JIANXUN_CONFIG=/path/to/other.json python main.py
"""
import json
import sys

from jianxun import (
    JianxunClient, DeviceInfo, ApiError, NewDeviceVerifyRequired, CaptchaRequired,
)
from jianxun.client import jpeg_dimensions
from jianxun.config import Config
from jianxun.im import WKIMClient, WKIMError, WKIMNotImplemented, DEFAULT_IM_ADDR


def ask(prompt: str, default: str = "") -> str:
    """Read a line; empty input returns ``default``. Ctrl-C / EOF exits."""
    try:
        value = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(0)
    return value if value else default


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


def group_view_menu(client: JianxunClient, group: dict, cfg: Config) -> None:
    """For the selected group: view members / profile, or send messages."""
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
            )
            print(f"[*] 连接悟空IM: {im_client.addr} ...")
            im_client.connect()
            print("[+] IM 连接成功（会话密钥已协商）")
        return im_client

    while True:
        print(f"\n当前群: {name} ({group_no})")
        print("请选择操作:")
        print("  1. 查询群成员列表")
        print("  2. 查询群资料")
        print("  3. 发送文字消息")
        print("  4. 发送图片")
        print("  5. 返回群列表")
        choice = ask("> ", "5")
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
                if ack.reason_code == 0:
                    print(f"[+] 已发送: messageID={ack.message_id} "
                          f"messageSeq={ack.message_seq} clientSeq={ack.client_seq}")
                else:
                    print(f"[!] 发送失败: reasonCode={ack.reason_code}")
            elif choice == "4":
                file_path = ask("本地图片路径: ")
                if not file_path:
                    continue
                print("[*] 上传图片 ...")
                up = client.upload_file(group_no, file_path)
                width, height = jpeg_dimensions(file_path)
                print(f"[*] 上传成功: {up['url']}")
                ack = ensure_im().send_image(group_no, up["url"], width, height)
                if ack.reason_code == 0:
                    print(f"[+] 已发送图片: messageID={ack.message_id} "
                          f"messageSeq={ack.message_seq} ({width}x{height})")
                else:
                    print(f"[!] 发送失败: reasonCode={ack.reason_code}")
            elif choice == "5":
                return
            else:
                print("[!] 无效选项")
        except (ApiError, ValueError, WKIMError, OSError) as e:
            print(f"[!] 操作失败: {e}")
            if isinstance(e, WKIMNotImplemented):
                print("    提示: IM 消息加密协议尚未完全还原，见 README「线上 IM 协议」。")
            if im_client is not None:
                im_client.close()
                im_client = None


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
        print("  1. 查询群（选择群查看成员/资料，或发消息/图片）")
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
