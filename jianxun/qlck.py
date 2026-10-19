"""AppVest TCP transport recovered from libcf-msc.so (ARM64).

0x26E7C0 builds the gateway preamble; 0x26DC40 XORs the following
bidirectional byte stream. The destination remains independent of the gateway.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import socket
import struct
import zlib
import json
from dataclasses import dataclass

from Crypto.Cipher import AES


DEFAULT_GATEWAY = "106.53.220.67:80"
DEFAULT_APP_KEY = "910c76bcec1bb4470f010ba24bc8a393"
_KEY_PREFIX = b"ce3487fe393c4f"
_IV = b"1234567812345678"
_MAGIC = bytes.fromhex("cd6a000101e0")
_CONTROL_MASK = bytes.fromhex("23f6bfc1ecf7c398dbc4ea177b1d3289")
_CONTROL_KEY = b"4)d7eX%?jV?BeS"
_CONTROL_IV = b"?zZkQ5+EmMx,]HY)"


def encode_control(message: dict, nonce: bytes | None = None) -> bytes:
    """Native 0x26964C: masked header, AES-CBC payload, SHA1 trailer."""
    from Crypto.Util.Padding import pad
    nonce = secrets.token_bytes(2) if nonce is None else nonce
    if len(nonce) != 2:
        raise ValueError("AppVest control nonce must have length 2")
    payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode()
    ciphertext = AES.new(_CONTROL_KEY + nonce, AES.MODE_CBC, iv=_CONTROL_IV).encrypt(pad(payload, 16))
    header = bytearray(bytes.fromhex("e5c90101") + struct.pack(">H", len(ciphertext) + 36)
                       + nonce + b"\x01" + secrets.token_bytes(3))
    header += struct.pack(">I", zlib.crc32(header))
    wire = bytes(a ^ b for a, b in zip(header, _CONTROL_MASK)) + ciphertext
    return wire + hashlib.sha1(wire).digest()


def decode_control(packet: bytes) -> dict:
    from Crypto.Util.Padding import unpad
    if len(packet) < 52:
        raise ValueError("Truncated AppVest control packet")
    header = bytes(a ^ b for a, b in zip(packet[:16], _CONTROL_MASK))
    if header[:2] != b"\xe5\xc9" or int.from_bytes(header[4:6], "big") != len(packet):
        raise ValueError("Invalid AppVest control header/length")
    if zlib.crc32(header[:12]) != int.from_bytes(header[12:16], "big"):
        raise ValueError("Invalid AppVest control CRC32")
    if not hmac.compare_digest(hashlib.sha1(packet[:-20]).digest(), packet[-20:]):
        raise ValueError("Invalid AppVest control SHA1")
    raw = unpad(AES.new(_CONTROL_KEY + header[6:8], AES.MODE_CBC, iv=_CONTROL_IV).decrypt(packet[16:-20]), 16)
    if header[8] & 2:
        raw = zlib.decompress(raw, 31)
    return json.loads(raw)


def query_gateway_config(options: "QLCKOptions", device_id: str = "", timeout: float = 5) -> dict:
    host, _, _ = options.gateway.rpartition(":")
    request = encode_control({"id": 0, "op": 3, "accesskey": options.app_key,
                              "fingerprint": options.device_fingerprint(device_id),
                              "simulator": 0, "sdk_version": 0, "platform": 0,
                              "rls": 0, "exclude_ips": []})
    with socket.create_connection((host, 8080), timeout) as sock:
        sock.sendall(request)
        raw = bytearray()
        needed = 16
        while len(raw) < needed:
            part = sock.recv(needed - len(raw))
            if not part:
                raise ConnectionError(f"AppVest control EOF after {len(raw)} bytes")
            raw.extend(part)
            if len(raw) == 16:
                header = bytes(a ^ b for a, b in zip(raw, _CONTROL_MASK))
                needed = int.from_bytes(header[4:6], "big")
                if not 52 <= needed <= 65535:
                    raise ValueError("Invalid AppVest control response size")
    return decode_control(bytes(raw))


def murmur2(data: bytes) -> int:
    """Native 0x26CDEC: MurmurHash2, seed zero, little-endian input words."""
    value = len(data)
    end = len(data) & ~3
    for offset in range(0, end, 4):
        word = int.from_bytes(data[offset:offset + 4], "little")
        word = word * 0x5BD1E995 & 0xFFFFFFFF
        word ^= word >> 24
        word = word * 0x5BD1E995 & 0xFFFFFFFF
        value = (value * 0x5BD1E995 & 0xFFFFFFFF) ^ word
    tail = data[end:]
    if tail:
        value ^= int.from_bytes(tail, "little")
        value = value * 0x5BD1E995 & 0xFFFFFFFF
    value ^= value >> 13
    value = value * 0x5BD1E995 & 0xFFFFFFFF
    return value ^ (value >> 15)


def _put_text(buffer: bytearray, offset: int, size: int, text: str) -> None:
    raw = text.encode("utf-8")
    if len(raw) > size:
        raise ValueError(f"AppVest field at {offset} exceeds {size} bytes")
    buffer[offset:offset + len(raw)] = raw


@dataclass(frozen=True)
class QLCKOptions:
    gateway: str = DEFAULT_GATEWAY
    discover: bool = True
    app_key: str = DEFAULT_APP_KEY
    fingerprint: str = ""
    api_level: int = 34
    manufacturer: str = "OnePlus"
    brand: str = "OnePlus"
    model: str = "PLR110"
    package: str = "quya.app"
    network: str = "WIFI"
    session_id: str = ""

    def device_fingerprint(self, device_id: str = "") -> str:
        # Explicit captured fingerprints can be supplied; otherwise keep the
        # handshake and XOR internally consistent using a stable device digest.
        result = self.fingerprint or hashlib.md5(
            (device_id + self.manufacturer + self.brand + self.model).encode()
        ).hexdigest().upper()
        if len(result) != 32 or any(c not in "0123456789abcdefABCDEF" for c in result):
            raise ValueError("AppVest fingerprint must contain 32 hexadecimal characters")
        return result


def gateway_candidates(options: QLCKOptions, device_id: str, timeout: float) -> list[str]:
    """Use dispatch nodes for this network, then the configured fallback."""
    result = []
    if options.discover:
        try:
            config = query_gateway_config(options, device_id, timeout)
            if config.get("status") != 200:
                raise ConnectionError(f"AppVest dispatch status={config.get('status')}")
            _, _, port = options.gateway.rpartition(":")
            for address in config.get("ipset", [])[:6]:
                # Dispatch ipset contains literal addresses, not destinations.
                socket.inet_pton(socket.AF_INET, address)
                result.append(f"{address}:{port}")
        except (OSError, ValueError, TypeError):
            # Dispatch is an optimisation; a manually configured node still
            # works when the control service is temporarily unavailable.
            pass
    result.append(options.gateway)
    return list(dict.fromkeys(result))


def build_handshake(
    host: str,
    port: int,
    options: QLCKOptions,
    fingerprint: str,
    *,
    nonce: bytes | None = None,
    stream_id: int = 1,
) -> bytes:
    """Build the 488-byte preamble; unspecified Android telemetry stays zero."""
    app_key = options.app_key.encode("ascii")
    expected = hashlib.md5(app_key[:16] + b"tjkd_app_salt_oLBAI").hexdigest()[:16]
    if len(app_key) != 32 or options.app_key[16:] != expected:
        raise ValueError("AppVest app key checksum mismatch")
    if len(fingerprint.encode("ascii")) != 32:
        raise ValueError("AppVest fingerprint must have length 32")
    if not 0 < port <= 65535:
        raise ValueError("Invalid AppVest destination port")
    raw = bytearray(480)
    # Named destinations use the HOST:PORT map (0x2703D4/0x26E424).
    # The numeric destination-port slot stays zero in this mode.
    destination = f"{host}:{port}"
    struct.pack_into(">BBHIII", raw, 0, 13, 2, 0, options.api_level, 0, 0)
    struct.pack_into("<I", raw, 16, stream_id)
    _put_text(raw, 36, 32, options.app_key)
    _put_text(raw, 68, 32, fingerprint)
    _put_text(raw, 100, 15, options.manufacturer)
    _put_text(raw, 116, 15, options.brand)
    _put_text(raw, 132, 31, options.model)
    struct.pack_into("<I", raw, 32, 1)  # persisted SDK launch counter
    _put_text(raw, 196, 15, options.network)
    session_id = options.session_id or secrets.token_hex(8)
    if len(session_id) != 16:
        raise ValueError("AppVest session_id must have length 16")
    _put_text(raw, 212, 16, session_id)
    _put_text(raw, 228, 47, options.package)
    _put_text(raw, 276, 63, destination)
    raw[420:428] = b"20240525"
    struct.pack_into(">I", raw, 436, murmur2(destination.encode("utf-8")))
    raw[444:464] = hashlib.sha1(raw[:444]).digest()
    raw[464:] = b"\x10" * 16
    nonce = secrets.token_bytes(2) if nonce is None else nonce
    if len(nonce) != 2:
        raise ValueError("AppVest nonce must have length 2")
    return _MAGIC + nonce + AES.new(
        _KEY_PREFIX + nonce, AES.MODE_CBC, iv=_IV
    ).encrypt(bytes(raw))


def decode_handshake(packet: bytes) -> dict:
    """Decode a captured preamble and validate both padding and SHA1."""
    if len(packet) != 488 or packet[:6] != _MAGIC:
        raise ValueError("Invalid AppVest preamble header/length")
    raw = AES.new(_KEY_PREFIX + packet[6:8], AES.MODE_CBC, iv=_IV).decrypt(packet[8:])
    if raw[464:] != b"\x10" * 16 or not hmac.compare_digest(
        raw[444:464], hashlib.sha1(raw[:444]).digest()
    ):
        raise ValueError("Invalid AppVest preamble padding/SHA1")

    def text_at(offset: int, size: int) -> str:
        return raw[offset:offset + size].split(b"\0", 1)[0].decode("utf-8")

    return {
        "protocol": raw[0], "platform": raw[1],
        "port": int.from_bytes(raw[2:4], "big"),
        "api_level": int.from_bytes(raw[4:8], "big"),
        "stream_id": int.from_bytes(raw[16:20], "little"),
        "app_key": text_at(36, 32), "fingerprint": text_at(68, 32),
        "manufacturer": text_at(100, 16), "brand": text_at(116, 16),
        "model": text_at(132, 32), "host": text_at(276, 64),
        "sdk_version": text_at(420, 8),
        "host_hash": int.from_bytes(raw[436:440], "big"),
    }


class QLCKSocket:
    """Socket-compatible XOR stream; sends the preamble exactly once."""

    def __init__(self, sock: socket.socket, xor_key: int):
        self.socket = sock
        self._table = bytes(value ^ xor_key for value in range(256))

    @classmethod
    def connect(cls, host: str, port: int, options: QLCKOptions,
                timeout: float, device_id: str = "") -> "QLCKSocket":
        gateway_host, _, gateway_port = options.gateway.rpartition(":")
        if not gateway_host:
            raise ValueError("AppVest gateway must use HOST:PORT")
        fingerprint = options.device_fingerprint(device_id)
        handshake = build_handshake(host, port, options, fingerprint)
        sock = socket.create_connection((gateway_host, int(gateway_port)), timeout)
        try:
            sock.sendall(handshake)
        except BaseException:
            sock.close()
            raise
        return cls(sock, ord(fingerprint[0]))

    def sendall(self, data: bytes) -> None:
        self.socket.sendall(data.translate(self._table))

    def recv(self, size: int) -> bytes:
        return self.socket.recv(size).translate(self._table)

    def settimeout(self, value: float | None) -> None:
        self.socket.settimeout(value)

    def fileno(self) -> int:
        return self.socket.fileno()

    def shutdown(self, how: int) -> None:
        self.socket.shutdown(how)

    def close(self) -> None:
        self.socket.close()
