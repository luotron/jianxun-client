"""
jianxun.config
==============

Global configuration loader.

Values are read from ``config.json`` at the project root (override the path
with the ``JIANXUN_CONFIG`` environment variable).  Anything missing falls
back to the built-in defaults below, so a partial ``config.json`` is fine.

The file holds:

* ``account``  - login credentials.  Use ``username`` for a username account
  (e.g. ``qwe778800``); leave it empty and set ``phone`` for phone login
  (the wire ``username`` becomes ``country_code + phone``).
* ``device``   - device fingerprint (device_id / model / name).
* ``security`` - security question + answer, used to pass *strange-device*
  verification (status 110 "新设备需要验证").
* ``base_url`` - API base URL.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

# Project root = parent of this package directory.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG_PATH = os.environ.get(
    "JIANXUN_CONFIG", os.path.join(_PROJECT_ROOT, "config.json")
)

# Built-in defaults (used when config.json is absent or incomplete).
_DEFAULTS = {
    "base_url": "https://api.jianxun01.com/v1",
    "account": {
        "username": "qwe778800",   # username account; takes precedence over phone
        "phone": "",               # phone login: wire username = country_code + phone
        "password": "qwe778800",
        "country_code": "0086",
    },
    "device": {
        "device_id": "bdd9c2b81eaf972c",
        "device_model": "OnePlus_PLR110",
        "device_name": "OP6117L1",
    },
    "security": {
        "question": "儿时养的第一只宠物的名字",
        "answer": "小狗赛虎",
    },
}


@dataclass
class Account:
    password: str
    country_code: str = "0086"
    username: str = ""
    phone: str = ""

    def wire_username(self) -> str:
        """The ``username`` value actually sent to the server.

        A username account is used as-is; otherwise it is ``country_code + phone``.
        """
        if self.username:
            return self.username
        return f"{self.country_code}{self.phone}"


@dataclass
class Device:
    device_id: str
    device_model: str
    device_name: str


@dataclass
class Security:
    question: str = ""
    answer: str = ""


@dataclass
class Config:
    base_url: str
    account: Account
    device: Device
    security: Security
    path: str = ""

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        path = path or DEFAULT_CONFIG_PATH
        data = dict(_DEFAULTS)
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                user = json.load(fh)
            data = _merge(data, user)
        return cls(
            base_url=data["base_url"],
            account=Account(**data["account"]),
            device=Device(**data["device"]),
            security=Security(**data.get("security", {})),
            path=path if os.path.isfile(path) else "",
        )


def _merge(base: dict, override: dict) -> dict:
    """Shallow+nested-dict merge of ``override`` onto a copy of ``base``."""
    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = {**out[k], **v}
        else:
            out[k] = v
    return out


# Eagerly-loaded singleton for convenient ``from jianxun.config import CONFIG``.
CONFIG = Config.load()
