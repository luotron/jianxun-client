"""
jianxun.crypto
==============

Session-encryption primitives for the 简讯 (jianxun / api.jianxun01.com)
Flutter app, reverse-engineered from ``libapp.so`` (Dart 3.12.2 AOT snapshot).

All request/response bodies are wrapped as ``{"data": "<base64>"}`` where the
base64 payload is::

    nonce(12 bytes random) || AES-256-GCM-ciphertext || GCM-tag(16 bytes)

The 32-byte GCM key is NOT stored directly in the binary.  It is unwrapped at
runtime (``_FG`` / ``sub_F8D500`` -> ``sub_F8D554``) with the Dart ``encrypt``
package:

    realKey = AES-256/CBC/PKCS7-decrypt(
                  base64decode(CONST_BLOB),
                  key = utf8(A),            # 32-byte string, AES-256
                  iv  = utf8(B))            # 16-byte string

where

    A = "k1"+"k2"+"k3"+"k4"+"x1"+"x2"+"x3"+"x4"   (8 x 4 hex fragments)
    B = "8SCXcHDvxLgHa4yK"                          (fixed 16-byte IV)

This module reproduces that derivation exactly and asserts the result matches
the value proven against captured traffic.
"""
from __future__ import annotations

import base64
import hashlib
import secrets

from Crypto.Cipher import AES

# --------------------------------------------------------------------------- #
# Hard-coded constants recovered from libapp.so (object pool / sub_5CADB4 etc.)
# --------------------------------------------------------------------------- #

# Base64 blob that stores the (encrypted) real AES-GCM key  (pp+0x93b8)
_CONST_BLOB_B64 = "JzoVVt6fJinbtbOLbM8oS+KBljyAjrauPDdWnH1LxveG7JlyoUPWChbjVoVFJx3k"

# 4-hex-char fragments addressed by (type, index) -> value  (sub_5CADB4)
#   type "k" => key fragments, type "x" => aux fragments.
# A is built in the order k1..k4, then x1..x4.
_FRAGMENTS = {
    ("k", 1): "6a1b", ("k", 2): "3c7d", ("k", 3): "9e2f", ("k", 4): "3a4b",
    ("x", 1): "5c6d", ("x", 2): "7e8f", ("x", 3): "9a0b", ("x", 4): "1c2e",
}

# Fixed 16-byte CBC IV used to unwrap the key  (sub_5CA784)
_UNWRAP_IV = b"8SCXcHDvxLgHa4yK"

# The verified 32-byte AES-256-GCM key (self-check target).
_EXPECTED_KEY = b"3a7b8c9d1e2f3a4b5c6d7e8f9a0b1c2d"


def _pkcs7_unpad(data: bytes) -> bytes:
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("bad PKCS7 padding")
    return data[:-n]


def derive_gcm_key() -> bytes:
    """Reproduce the runtime key-unwrap and return the 32-byte AES-GCM key."""
    a = "".join(
        _FRAGMENTS[("k", i)] for i in range(1, 5)
    ) + "".join(
        _FRAGMENTS[("x", i)] for i in range(1, 5)
    )
    key = a.encode("utf-8")          # 32 bytes -> AES-256
    blob = base64.b64decode(_CONST_BLOB_B64)
    real = _pkcs7_unpad(AES.new(key, AES.MODE_CBC, _UNWRAP_IV).decrypt(blob))
    return real


# Resolve once at import time and verify against the captured ground truth.
GCM_KEY = derive_gcm_key()
assert GCM_KEY == _EXPECTED_KEY, (
    f"key derivation mismatch: {GCM_KEY!r} != {_EXPECTED_KEY!r}"
)


# --------------------------------------------------------------------------- #
# Body encryption / decryption
# --------------------------------------------------------------------------- #

def encrypt(plaintext: str, key: bytes = GCM_KEY) -> str:
    """plaintext(str) -> base64(nonce12 || ciphertext || tag16)."""
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return base64.b64encode(nonce + ct + tag).decode("ascii")


def decrypt(data_b64: str, key: bytes = GCM_KEY, verify: bool = True) -> str:
    """base64(nonce12 || ciphertext || tag16) -> plaintext(str)."""
    raw = base64.b64decode(data_b64)
    nonce, body, tag = raw[:12], raw[12:-16], raw[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if verify:
        pt = cipher.decrypt_and_verify(body, tag)
    else:
        pt = cipher.decrypt(body)
    return pt.decode("utf-8")


# --------------------------------------------------------------------------- #
# Request signing
# --------------------------------------------------------------------------- #

def sign_body(body: str) -> str:
    """x-sign = md5(raw request body string).hexdigest()."""
    return hashlib.md5(body.encode("utf-8")).hexdigest()


def gen_nonce() -> str:
    """x-nonce: a fresh 32-hex replay nonce (md5 of random bytes)."""
    return hashlib.md5(secrets.token_bytes(16)).hexdigest()
