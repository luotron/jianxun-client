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
        try:
            j = resp.json()
        except ValueError:
            resp.raise_for_status()
            raise ApiError(-1, f"non-json response: {resp.text[:200]}")

        # Success envelope: {"data": "<base64 encrypted>"}
        if isinstance(j, dict) and isinstance(j.get("data"), str):
            return json.loads(crypto.decrypt(j["data"]))

        # Error envelope: {"status": N, "msg": "...", ...}
        status = j.get("status", -1) if isinstance(j, dict) else -1
        msg = j.get("msg", "") if isinstance(j, dict) else str(j)
        if status == 110:
            raise NewDeviceVerifyRequired(status, msg, j)
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
