"""
jianxun.client
==============

High-level client that speaks the 简讯 (api.jianxun01.com) encrypted protocol.

Every request body is ``{"data": base64(AES-256-GCM(json))}`` and carries the
headers ``x-timestamp`` / ``x-nonce`` / ``x-sign`` (=md5 of the raw body) plus
a ``token`` (empty for login, the session token afterwards).  Successful
responses are themselves ``{"data": base64(...)}`` and are transparently
decrypted here.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from . import crypto
from .config import CONFIG

DEFAULT_BASE_URL = CONFIG.base_url
USER_AGENT = "Dart/3.12 (dart:io)"


class ApiError(Exception):
    """Server returned a non-success business status."""

    def __init__(self, status: int, msg: str, raw: Any = None):
        super().__init__(f"[{status}] {msg}")
        self.status = status
        self.msg = msg
        self.raw = raw


class NewDeviceVerifyRequired(ApiError):
    """status 110 - the device_id is unknown and needs captcha/SMS verification."""


class CaptchaRequired(ApiError):
    """status 220 - the server demands the Aliyun/Tencent behaviour captcha.

    The app answers it with ``captcha_verify_param`` / ``need_verify`` /
    ``scene_id`` in the login payload.  This client does not solve captchas;
    callers should cancel the login when this is raised.
    """


CAPTCHA_STATUS = 220


def image_dimensions(path: str) -> tuple[int, int]:
    """Read PNG/JPEG dimensions from file contents; (0, 0) if unrecognised."""
    import struct

    with open(path, "rb") as fh:
        data = fh.read()
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        if len(data) < 33 or data[8:16] != b"\0\0\0\rIHDR":
            return 0, 0
        width, height = struct.unpack(">II", data[16:24])
        return (width, height) if width > 0 and height > 0 else (0, 0)
    if data[:2] != b"\xff\xd8":
        return 0, 0
    i = 2
    # All SOF variants that carry dimensions, excluding DHT/JPG/DAC markers.
    sof = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
           0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
    while i < len(data):
        if data[i] != 0xFF:
            return 0, 0
        while i < len(data) and data[i] == 0xFF:
            i += 1
        if i >= len(data):
            break
        marker = data[i]
        i += 1
        if marker in (0xDA, 0xD9):  # Scan data/end before a recognised SOF.
            break
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            continue
        if i + 2 > len(data):
            break
        length = struct.unpack(">H", data[i:i + 2])[0]
        if length < 2 or i + length > len(data):
            break
        if marker in sof:
            if length < 8:
                break
            height, width = struct.unpack(">HH", data[i + 3:i + 7])
            return (width, height) if width > 0 and height > 0 else (0, 0)
        i += length
    return 0, 0


def jpeg_dimensions(path: str) -> tuple[int, int]:
    """Compatibility alias; also recognises PNG images."""
    return image_dimensions(path)


@dataclass
class DeviceInfo:
    """Device fingerprint sent inside the login payload.

    The server ties accounts to ``device_id`` (Android ID).  Logging in from
    a device that is unknown for the account returns status 110
    ("新设备需要验证"); passing the account's security question + answer in the
    retry clears it (no Aliyun captcha is required on the server side).

    Defaults come from the global config (``config.json``).
    """

    device_model: str = CONFIG.device.device_model
    device_id: str = CONFIG.device.device_id
    device_name: str = CONFIG.device.device_name

    def to_dict(self) -> dict:
        return {
            "device_model": self.device_model,
            "device_id": self.device_id,
            "device_name": self.device_name,
        }


@dataclass
class LoginResult:
    uid: str
    token: str
    username: str
    phone: str
    name: str
    raw: dict = field(repr=False)


@dataclass
class GroupMember:
    """A member of a group (``GET /v1/groups/{groupNo}/members``).

    Field set taken from the decrypted capture in ``tcpdump/cap_http.pcap``::

        [{"id":145382, "uid":"...", "group_no":"...", "name":"...", "remark":"",
          "role":1, "version":..., "is_deleted":0, "status":1, "vercode":"",
          "invite_uid":"...", "robot":0, "forbidden_expir_time":0,
          "friend_remark":"", "created_at":"...", "updated_at":"...",
          "is_white_list":0, "is_member":0, "background_color":1,
          "nickname_color":1, "is_pretty":0}, ...]

    ``role``: 1 = owner/creator, 0 = regular member.
    """

    uid: str
    group_no: str
    name: str
    role: int
    id: int = 0
    remark: str = ""
    friend_remark: str = ""
    status: int = 1
    is_deleted: int = 0
    robot: int = 0
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: dict) -> "GroupMember":
        return cls(
            uid=str(d.get("uid", "")),
            group_no=str(d.get("group_no", "")),
            name=str(d.get("name", "")),
            role=int(d.get("role", 0)),
            id=int(d.get("id", 0)),
            remark=str(d.get("remark", "")),
            friend_remark=str(d.get("friend_remark", "")),
            status=int(d.get("status", 1)),
            is_deleted=int(d.get("is_deleted", 0)),
            robot=int(d.get("robot", 0)),
            raw=d,
        )


class JianxunClient:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: int = 20):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.token = ""
        self.session = requests.Session()

    # ------------------------------------------------------------------ #
    # low level
    # ------------------------------------------------------------------ #
    def _headers(self, body: str) -> dict:
        return {
            "user-agent": USER_AGENT,
            "content-type": "application/json",
            "accept-encoding": "gzip",
            "x-timestamp": str(int(time.time() * 1000)),
            "x-nonce": crypto.gen_nonce(),
            "x-sign": crypto.sign_body(body),
            "token": self.token or "",
        }

    def request(self, method: str, path: str, payload: Optional[dict] = None) -> Any:
        """Send an encrypted request and return the decrypted JSON ``data``.

        ``payload`` (a dict) is JSON-encoded, AES-GCM-encrypted and wrapped as
        ``{"data": ...}``.  The decrypted response ``data`` is returned; a
        business error raises :class:`ApiError`.
        """
        url = f"{self.base_url}{path}"
        if payload is not None:
            inner = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            body = json.dumps({"data": crypto.encrypt(inner)}, separators=(",", ":"))
        else:
            body = ""
        resp = self.session.request(
            method, url, data=body.encode("utf-8"),
            headers=self._headers(body), timeout=self.timeout,
        )
        return self._parse(resp)

    def _parse(self, resp: requests.Response) -> Any:
        # Business error messages are GBK-encoded ("非群成员，不能访问" etc.);
        # try UTF-8 first, then GBK, so ApiError shows the real text.
        raw = resp.content
        try:
            j = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            try:
                j = json.loads(raw.decode("gbk"))
            except ValueError:
                resp.raise_for_status()
                raise ApiError(-1, f"non-json response: {raw[:200]!r}")

        # Success envelope: {"data": "<base64 encrypted>"}
        if isinstance(j, dict) and isinstance(j.get("data"), str):
            return json.loads(crypto.decrypt(j["data"]))

        # Error envelope: {"status": N, "msg": "...", ...}
        status = j.get("status", -1) if isinstance(j, dict) else -1
        msg = j.get("msg", "") if isinstance(j, dict) else str(j)
        if status == 110:
            raise NewDeviceVerifyRequired(status, msg, j)
        if status == CAPTCHA_STATUS or (isinstance(j, dict) and j.get("need_verify")):
            raise CaptchaRequired(status, msg, j)
        raise ApiError(status, msg, j)

    # ------------------------------------------------------------------ #
    # high level
    # ------------------------------------------------------------------ #
    def login(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        device: Optional[DeviceInfo] = None,
        *,
        phone: Optional[str] = None,
        country_code: Optional[str] = None,
        security_question: Optional[str] = None,
        security_answer: Optional[str] = None,
        verify_on_new_device: bool = True,
        flag: int = 0,
    ) -> LoginResult:
        """Password login (username **or** phone), with strange-device verify.

        Account resolution (all fall back to ``config.json``):

        * ``username`` given -> sent verbatim (username account, e.g. qwe778800)
        * else ``phone`` -> wire username becomes ``country_code + phone``

        ``password`` is sent as plaintext inside the GCM-encrypted body.

        If the device is unknown for the account the server replies status 110
        ("新设备需要验证").  When ``verify_on_new_device`` is true and a security
        answer is available, the login is automatically retried with
        ``security_question`` / ``security_answer`` added to the payload (the
        strange-device verification request).  Otherwise
        :class:`NewDeviceVerifyRequired` is raised.
        """
        acc = CONFIG.account
        password = password if password is not None else acc.password
        country_code = country_code if country_code is not None else acc.country_code
        if username is None and phone is None:
            wire_username = acc.wire_username()
        elif username:
            wire_username = username
        else:
            wire_username = f"{country_code}{phone}"

        security_question = (
            security_question if security_question is not None else CONFIG.security.question
        )
        security_answer = (
            security_answer if security_answer is not None else CONFIG.security.answer
        )
        device = device or DeviceInfo()

        base_payload = {
            "username": wire_username,
            "password": password,
            "device": device.to_dict(),
            "flag": flag,
        }

        try:
            data = self.request("POST", "/user/login", base_payload)
        except NewDeviceVerifyRequired:
            if not (verify_on_new_device and security_answer):
                raise
            # Strange-device verification: retry with the security Q/A.
            data = self.verify_security(
                security_answer=security_answer,
                security_question=security_question,
                username=wire_username,
                password=password,
                device=device,
                flag=flag,
            )

        self.token = data.get("token", "")
        return LoginResult(
            uid=data.get("uid", ""),
            token=data.get("token", ""),
            username=data.get("username", ""),
            phone=data.get("phone", ""),
            name=data.get("name", ""),
            raw=data,
        )

    def verify_security(
        self,
        security_answer: Optional[str] = None,
        security_question: Optional[str] = None,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        device: Optional[DeviceInfo] = None,
        flag: int = 0,
    ) -> dict:
        """Strange-device login carrying the security question + answer.

        This is the ``/user/login`` request sent after the server asks for
        verification; it adds ``security_question`` / ``security_answer`` to the
        normal login payload.  Returns the decrypted profile dict.
        """
        acc = CONFIG.account
        username = username if username is not None else acc.wire_username()
        password = password if password is not None else acc.password
        security_question = (
            security_question if security_question is not None else CONFIG.security.question
        )
        security_answer = (
            security_answer if security_answer is not None else CONFIG.security.answer
        )
        device = device or DeviceInfo()
        payload = {
            "username": username,
            "password": password,
            "device": device.to_dict(),
            "flag": flag,
            "security_question": security_question,
            "security_answer": security_answer,
        }
        return self.request("POST", "/user/login", payload)

    # ------------------------------------------------------------------ #
    # groups
    # ------------------------------------------------------------------ #
    def get_group_list(self) -> list[dict]:
        """List the groups the account has joined.

        ``GET /v1/group/my`` — the response is an encrypted JSON **array** of
        group objects (``[]`` when the account is in no group).  Raw dicts are
        returned; use :meth:`get_group` for the full profile of one group.
        """
        return self.request("GET", "/group/my")

    def get_group(self, group_no: str) -> dict:
        """Full profile of one group (``GET /v1/groups/{groupNo}``).

        Returns the decrypted dict, e.g.::

            {"group_no": "...", "group_type": 0, "name": "...", "notice": "",
             "member_count": 2, "online_count": 1, "role": 0, "status": 1,
             "created_at": "...", "version": ..., "Creator": "<uid>", ...}
        """
        return self.request("GET", f"/groups/{group_no}")

    def get_group_members(
        self,
        group_no: str,
        keyword: str = "",
        limit: int = 50,
        page: int = 1,
    ) -> list[GroupMember]:
        """Paged member list of a group.

        ``GET /v1/groups/{groupNo}/members?keyword={kw}&limit={n}&page={p}``
        (as seen in the capture: ``?keyword&limit=20&page=1`` and
        ``?keyword=&limit=50&page=1``).  The decrypted payload is a JSON array
        of member objects (see :class:`GroupMember`).
        """
        data = self.request(
            "GET", f"/groups/{group_no}/members?keyword={keyword}&limit={limit}&page={page}"
        )
        return [GroupMember.from_dict(m) for m in data]

    def get_all_group_members(
        self,
        group_no: str,
        limit: int = 50,
        max_pages: int = 200,
    ) -> list[GroupMember]:
        """Auto-paginated member list: fetch every page until a short page.

        Keeps calling :meth:`get_group_members` with ``page = 1, 2, ...`` and
        stops when a page returns fewer than ``limit`` members (``max_pages``
        is a safety cap against infinite loops).
        """
        members: list[GroupMember] = []
        for page in range(1, max_pages + 1):
            page_members = self.get_group_members(group_no, limit=limit, page=page)
            members.extend(page_members)
            if len(page_members) < limit:
                break
        return members

    # ------------------------------------------------------------------ #
    # file upload (image message flow, verified against cap_http.pcap)
    # ------------------------------------------------------------------ #
    def upload_file(self, channel_id: str, file_path: str, channel_type: int = 2) -> dict:
        """Upload a file for a chat message (``type=chat``).

        Two-step flow captured from the app (``tcpdump/cap_http.pcap``):

        1. presign: ``GET /v1/file/upload?path=<urlencoded>&type=chat`` →
           plain JSON ``{"url": "<upload url>"}``;
        2. upload: ``POST`` that url, multipart field ``file`` (plain JSON
           response, ``x-sign`` is the literal string ``"x-sign"`` as the app
           sends it for FormData bodies).

        Returns the plain JSON dict from step 2, e.g.::

            {"path": "file/preview/chat/2/<groupNo>/<uuid>",
             "url":  "https://zy-jp-prod2.oss-ap-northeast-1.aliyuncs.com/chat/2/<groupNo>/<uuid>"}

        Use ``path`` for the image-message payload's ``url``, matching the app.
        The absolute OSS ``url`` is the uploaded object's storage address.
        """
        import time as _time
        import urllib.parse as _urlparse
        import uuid as _uuid

        path = f"/{channel_type}/{channel_id}/{_uuid.uuid4().hex}"
        quoted = _urlparse.quote(path, safe="")
        presign_url = f"{self.base_url}/file/upload?path={quoted}&type=chat"
        headers = self._headers("")
        headers["content-type"] = "application/json"
        resp = self.session.get(presign_url, headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        presign = resp.json()  # {"url": "..."}

        suffix = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else "jpg"
        mime = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png"}.get(
            suffix, "application/octet-stream"
        )
        with open(file_path, "rb") as fh:
            content = fh.read()
        filename = f"image_{int(_time.time() * 1000)}.{suffix}"

        up_headers = {
            "user-agent": USER_AGENT,
            "accept-encoding": "gzip",
            "x-timestamp": str(int(_time.time() * 1000)),
            "x-nonce": crypto.gen_nonce(),
            "x-sign": "x-sign",  # the app literally sends this for multipart bodies
            "token": self.token or "",
        }
        resp2 = self.session.post(
            presign["url"],
            files={"file": (filename, content, mime)},
            headers=up_headers,
            timeout=self.timeout * 3,
        )
        resp2.raise_for_status()
        return resp2.json()
