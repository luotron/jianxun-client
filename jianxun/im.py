"""
简讯 App 的 WuKongIM v4 TCP 客户端。

支持直连和 AppVest/QLCK 网关。一个持久 socket 由后台线程统一读取，
发送回执和推送消息分别分发，空闲时持续发送心跳。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import select
import struct
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, replace
from typing import Any

from Crypto.Cipher import AES
from Crypto.Protocol import DH
from Crypto.PublicKey import ECC
from Crypto.Util.Padding import pad, unpad

from .qlck import QLCKOptions, QLCKSocket, gateway_candidates


DEFAULT_IM_ADDR = "tcp.jianxun01.com:15100"
CHANNEL_GROUP = 2

_PROTO_VERSION = 4
_MAX_FRAME_SIZE = 1 << 21
_HEARTBEAT_SECONDS = 30.0

_PACKET_CONNECT = 1
_PACKET_CONNACK = 2
_PACKET_SEND = 3
_PACKET_SENDACK = 4
_PACKET_RECV = 5
_PACKET_RECVACK = 6
_PACKET_PING = 7
_PACKET_PONG = 8
_PACKET_DISCONNECT = 9

_REASON_SUCCESS = 1
_REASON_NAMES = {
    1: "Success", 2: "AuthFail", 3: "SubscriberNotExist", 4: "InBlacklist",
    5: "ChannelNotExist", 7: "SenderOffline", 8: "MsgKeyError",
    9: "PayloadDecodeError", 11: "NotAllowSend", 12: "ConnectKick",
    13: "NotInWhitelist", 14: "QueryTokenError", 15: "SystemError",
    16: "ChannelIDError", 19: "Ban", 22: "RateLimit", 24: "Disband",
    25: "SendBan",
}

# The public DNS names can resolve to Clash fake IPs. These addresses were
# obtained from the App's HTTPDNS response and are also visible in captures.
_FALLBACK_ENDPOINTS = {
    15100: ("123.60.87.106", 15100),
    5100: ("154.23.224.149", 5100),
}


class WKIMError(Exception):
    pass


class WKIMNotImplemented(WKIMError):
    """Kept for callers of older versions; all required IM operations exist."""


class WKIMTimeout(WKIMError):
    """An operation timed out without closing the persistent connection."""


@dataclass(frozen=True)
class SendAck:
    message_id: int
    client_seq: int
    message_seq: int
    reason_code: int

    @property
    def success(self) -> bool:
        return self.reason_code == _REASON_SUCCESS

    @property
    def reason_name(self) -> str:
        return _REASON_NAMES.get(self.reason_code, f"Unknown({self.reason_code})")


@dataclass(frozen=True)
class RecvMessage:
    message_id: int
    message_seq: int
    message_time: int
    client_msg_no: str
    from_uid: str
    channel_id: str
    channel_type: int
    content: Any
    raw_content: str
    expire: int = 0
    topic: str = ""


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def _take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise WKIMError("IM 数据包长度不足")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def u8(self) -> int:
        return self._take(1)[0]

    def u32(self) -> int:
        return struct.unpack(">I", self._take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self._take(8))[0]

    def string(self) -> str:
        size = struct.unpack(">H", self._take(2))[0]
        return self._take(size).decode("utf-8")

    def remaining(self) -> bytes:
        return self._take(len(self.data) - self.offset)


def _pack_string(value: str) -> bytes:
    data = value.encode("utf-8")
    if len(data) > 0xFFFF:
        raise ValueError("IM 字符串字段超过 65535 字节")
    return struct.pack(">H", len(data)) + data


def _encode_remaining_length(length: int) -> bytes:
    if length < 0 or length > _MAX_FRAME_SIZE:
        raise ValueError(f"无效的 IM 帧长度: {length}")
    encoded = bytearray()
    while True:
        digit = length % 0x80
        length //= 0x80
        if length:
            digit |= 0x80
        encoded.append(digit)
        if not length:
            break
    return bytes(encoded)


def _encode_frame(packet_type: int, body: bytes = b"", flags: int = 0) -> bytes:
    first = bytes([(packet_type << 4) | (flags & 0x07)])
    if packet_type in (_PACKET_PING, _PACKET_PONG):
        return first
    return first + _encode_remaining_length(len(body)) + body


@dataclass
class WKIMClient:
    addr: str = DEFAULT_IM_ADDR
    timeout: float = 10.0
    uid: str = ""
    token: str = ""
    device_id: str = ""
    device_flag: int = 0
    qlck: QLCKOptions | None = None

    _sock: socket.socket | QLCKSocket | None = field(default=None, init=False, repr=False)
    _connected: bool = field(default=False, init=False)
    _buffer: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _client_seq: int = field(default=0, init=False)
    _proto_version: int = field(default=_PROTO_VERSION, init=False)
    _aes_key: bytes = field(default=b"", init=False, repr=False)
    _aes_iv: bytes = field(default=b"", init=False, repr=False)
    _dh_private: ECC.EccKey | None = field(default=None, init=False, repr=False)
    _pending_messages: deque[RecvMessage] = field(
        default_factory=deque, init=False, repr=False
    )
    _pending_acks: dict[int, SendAck] = field(default_factory=dict, init=False, repr=False)
    _next_ping: float = field(default=0.0, init=False, repr=False)
    _reader_thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _condition: threading.Condition = field(default_factory=threading.Condition, init=False, repr=False)
    _write_lock: Any = field(default_factory=threading.Lock, init=False, repr=False)
    _request_lock: Any = field(default_factory=threading.Lock, init=False, repr=False)
    _failure: WKIMError | None = field(default=None, init=False, repr=False)
    _gateway: str = field(default="", init=False)

    @property
    def gateway(self) -> str:
        return self._gateway

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> None:
        if not self.uid or not self.token:
            raise WKIMError("缺少 IM uid/token")
        self.close()
        if self.timeout <= 0:
            raise ValueError("IM timeout must be positive")
        if not 0 <= self.device_flag <= 255:
            raise ValueError("Invalid IM device_flag")
        candidates = (gateway_candidates(self.qlck, self.device_id, self.timeout)
                      if self.qlck else [""])
        errors = []
        for gateway in candidates:
            self._gateway = gateway
            try:
                self._connect_once()
                return
            except (OSError, ValueError, WKIMError) as exc:
                self.close()
                errors.append(f"{gateway or self.addr}: {exc}")
                if "reasonCode=" in str(exc):
                    break  # Retrying a rejected credential on other nodes cannot help.
        raise WKIMError("IM 连接未完成: " + "; ".join(errors))

    def _connect_once(self) -> None:
        host, port = self._split_addr(self.addr)
        self._stop.clear()
        self._failure = None
        self._sock = self._dial(host, port)
        self._buffer.clear()
        self._pending_messages.clear()
        self._pending_acks.clear()
        self._client_seq = 0
        self._proto_version = _PROTO_VERSION

        self._dh_private = ECC.generate(curve="Curve25519")
        client_key = base64.b64encode(
            self._dh_private.public_key().export_key(format="raw")
        ).decode("ascii")
        wire_device_id = (self.device_id or uuid.uuid4().hex).replace("-", "")
        if not wire_device_id.endswith("F"):
            wire_device_id += "F"

        body = (
            bytes([_PROTO_VERSION, self.device_flag])
            + _pack_string(wire_device_id)
            + _pack_string(self.uid)
            + _pack_string(self.token)
            + struct.pack(">Q", int(time.time() * 1000))
            + _pack_string(client_key)
        )
        self._send_raw(_encode_frame(_PACKET_CONNECT, body))

        deadline = time.monotonic() + self.timeout
        try:
            while True:
                first, packet_type, packet_body = self._read_frame(deadline)
                if packet_type == _PACKET_CONNACK:
                    self._handle_connack(first, packet_body)
                    break
                if packet_type == _PACKET_PING:
                    self._send_raw(_encode_frame(_PACKET_PONG))
        except Exception:
            self.close()
            raise

        self._connected = True
        self._next_ping = time.monotonic() + _HEARTBEAT_SECONDS
        self._reader_thread = threading.Thread(
            target=self._reader_loop, name="jianxun-im-reader", daemon=True
        )
        self._reader_thread.start()

    @staticmethod
    def _split_addr(addr: str) -> tuple[str, int]:
        value = addr.removeprefix("tcp://")
        host, separator, port_text = value.rpartition(":")
        if not separator or not host:
            raise WKIMError(f"无效的 im_addr: {addr!r}")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise WKIMError(f"无效的 im_addr: {addr!r}") from exc
        if not 0 < port <= 65535:
            raise WKIMError(f"无效的 im_addr: {addr!r}")
        return host.strip("[]"), port

    def _dial(self, host: str, port: int) -> socket.socket | QLCKSocket:
        if self.qlck is not None:
            return QLCKSocket.connect(
                host, port, replace(self.qlck, gateway=self._gateway),
                self.timeout, self.device_id,
            )
        candidates = [(host, port)]
        fallback = _FALLBACK_ENDPOINTS.get(port)
        if fallback and fallback not in candidates:
            candidates.append(fallback)

        errors: list[str] = []
        for candidate_host, candidate_port in candidates:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect((candidate_host, candidate_port))
                return sock
            except OSError as exc:
                errors.append(f"{candidate_host}:{candidate_port}: {exc}")
                sock.close()
        raise WKIMError("无法连接 IM 服务: " + "; ".join(errors))

    def _handle_connack(self, first: int, body: bytes) -> None:
        reader = _Reader(body)
        if first & 0x01:
            self._proto_version = min(reader.u8(), _PROTO_VERSION)
        time_diff = reader.u64()
        reason_code = reader.u8()
        if reason_code != _REASON_SUCCESS:
            raise WKIMError(
                f"IM 鉴权失败: reasonCode={reason_code}, timeDiff={time_diff}"
            )
        server_key_text = reader.string()
        salt = reader.string()
        if self._proto_version >= 4:
            reader.u64()  # node ID
        if self._dh_private is None:
            raise WKIMError("IM X25519 私钥状态丢失")

        try:
            server_key = DH.import_x25519_public_key(
                base64.b64decode(server_key_text, validate=True)
            )
            shared_secret = DH.key_agreement(
                static_priv=self._dh_private,
                static_pub=server_key,
                kdf=lambda secret: secret,
            )
            digest = hashlib.md5(base64.b64encode(shared_secret)).hexdigest()
            self._aes_key = digest[:16].encode("ascii")
            self._aes_iv = salt.encode("utf-8")
        except (ValueError, TypeError) as exc:
            raise WKIMError(f"IM 会话密钥协商失败: {exc}") from exc
        if len(self._aes_iv) != AES.block_size:
            raise WKIMError(f"IM Connack salt 长度错误: {len(self._aes_iv)}")

    def close(self) -> None:
        self._connected = False
        self._stop.set()
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        with self._condition:
            self._condition.notify_all()
        thread = self._reader_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)
        self._reader_thread = None
        self._aes_key = b""
        self._aes_iv = b""
        self._dh_private = None
        self._buffer.clear()

    def _reader_loop(self) -> None:
        try:
            while not self._stop.is_set():
                self._pump_one(None)
        except (WKIMError, OSError, ValueError, UnicodeError) as exc:
            if not self._stop.is_set():
                self._failure = exc if isinstance(exc, WKIMError) else WKIMError(str(exc))
        finally:
            self.close()
            with self._condition:
                self._condition.notify_all()

    def __enter__(self) -> "WKIMClient":
        if not self.connected:
            self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _send_raw(self, data: bytes) -> None:
        try:
            with self._write_lock:
                sock = self._sock
                if sock is None:
                    raise WKIMError("IM socket 未连接")
                sock.sendall(data)
        except OSError as exc:
            self._failure = WKIMError(f"IM socket 发送失败: {exc}")
            self.close()
            raise self._failure from exc

    def _extract_frame(self) -> tuple[int, int, bytes] | None:
        if not self._buffer:
            return None
        first = self._buffer[0]
        packet_type = first >> 4
        if not 1 <= packet_type <= _PACKET_DISCONNECT:
            raise WKIMError(f"未知 IM 包类型: {packet_type}")
        if packet_type in (_PACKET_PING, _PACKET_PONG):
            del self._buffer[:1]
            return first, packet_type, b""

        remaining = 0
        length_size = 0
        for index in range(4):
            position = 1 + index
            if position >= len(self._buffer):
                return None
            value = self._buffer[position]
            remaining |= (value & 0x7F) << (index * 7)
            length_size += 1
            if not value & 0x80:
                break
        else:
            raise WKIMError("IM 帧长度字段无效")
        if remaining > _MAX_FRAME_SIZE:
            raise WKIMError(f"IM 帧过大: {remaining}")

        total = 1 + length_size + remaining
        if len(self._buffer) < total:
            return None
        body = bytes(self._buffer[1 + length_size:total])
        del self._buffer[:total]
        return first, packet_type, body

    def _read_frame(self, deadline: float | None) -> tuple[int, int, bytes]:
        while True:
            frame = self._extract_frame()
            if frame is not None:
                return frame
            if self._sock is None:
                raise WKIMError("IM socket 已断开")

            now = time.monotonic()
            if deadline is not None and now >= deadline:
                raise WKIMTimeout("等待 IM 数据超时")
            wake_at = self._next_ping if self._connected else None
            if deadline is not None:
                wake_at = min(wake_at, deadline) if wake_at else deadline
            wait = None if wake_at is None else max(0.05, wake_at - now)
            sock = self._sock
            try:
                readable, _, _ = select.select([sock], [], [], wait)
                if not readable:
                    raise socket.timeout()
                chunk = sock.recv(65536)
            except socket.timeout:
                now = time.monotonic()
                if self._connected and now >= self._next_ping:
                    self._send_raw(_encode_frame(_PACKET_PING))
                    self._next_ping = now + _HEARTBEAT_SECONDS
                    continue
                raise WKIMTimeout("等待 IM 数据超时")
            except (OSError, ValueError) as exc:
                raise WKIMError(f"IM socket 接收失败: {exc}") from exc
            if not chunk:
                raise WKIMError("IM 服务端已关闭连接")
            self._buffer.extend(chunk)

    def _encrypt(self, plaintext: str) -> str:
        if not self._aes_key or not self._aes_iv:
            raise WKIMError("IM 会话密钥尚未协商")
        cipher = AES.new(self._aes_key, AES.MODE_CBC, iv=self._aes_iv)
        encrypted = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
        return base64.b64encode(encrypted).decode("ascii")

    def _decrypt(self, ciphertext: str) -> str:
        try:
            raw = base64.b64decode(ciphertext, validate=True)
            cipher = AES.new(self._aes_key, AES.MODE_CBC, iv=self._aes_iv)
            return unpad(cipher.decrypt(raw), AES.block_size).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise WKIMError(f"IM 消息解密失败: {exc}") from exc

    def send_text(
        self, channel_id: str, text: str, channel_type: int = CHANNEL_GROUP
    ) -> SendAck:
        payload = json.dumps(
            {"content": text, "type": 1}, separators=(",", ":"), ensure_ascii=False
        )
        return self._send_payload(channel_id, channel_type, payload)

    def send_image(
        self,
        channel_id: str,
        url: str,
        width: int = 0,
        height: int = 0,
        channel_type: int = CHANNEL_GROUP,
    ) -> SendAck:
        payload = json.dumps(
            {"width": width, "height": height, "url": url, "type": 2},
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return self._send_payload(channel_id, channel_type, payload)

    def _send_payload(self, channel_id: str, channel_type: int, payload: str) -> SendAck:
        with self._request_lock:
            return self._send_payload_serial(channel_id, channel_type, payload)

    def _send_payload_serial(self, channel_id: str, channel_type: int, payload: str) -> SendAck:
        self._require_connected()
        if not channel_id or not 0 <= channel_type <= 255:
            raise ValueError("无效的 IM channel_id/channel_type")
        self._client_seq = (self._client_seq + 1) & 0xFFFFFFFF
        if self._client_seq == 0:
            self._client_seq = 1
        client_seq = self._client_seq
        client_msg_no = uuid.uuid4().hex + "5"
        encrypted_payload = self._encrypt(payload)
        verification = (
            f"{client_seq}{client_msg_no}{channel_id}{channel_type}{encrypted_payload}"
        )
        msg_key = hashlib.md5(self._encrypt(verification).encode("utf-8")).hexdigest()

        body = (
            b"\x00"  # Setting: no receipt/topic/stream fields
            + struct.pack(">I", client_seq)
            + _pack_string(client_msg_no)
            + _pack_string(channel_id)
            + bytes([channel_type])
        )
        if self._proto_version >= 3:
            body += struct.pack(">I", 0)  # expire
        body += _pack_string(msg_key) + encrypted_payload.encode("ascii")

        # showUnread is true in WKSendOptions' default MessageHeader.
        self._send_raw(_encode_frame(_PACKET_SEND, body, flags=0x02))
        deadline = time.monotonic() + self.timeout
        with self._condition:
            while True:
                ack = self._pending_acks.pop(client_seq, None)
                if ack is not None:
                    return ack
                self._require_connected()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WKIMTimeout(f"等待 SENDACK 超时: clientSeq={client_seq}（服务端接收状态未知，请勿自动重发）")
                self._condition.wait(remaining)

    def recv_message(self, timeout: float | None = None) -> RecvMessage:
        """Wait for one server-pushed message and send its RecvAck."""
        if timeout is not None and timeout < 0:
            raise ValueError("IM receive timeout must be non-negative")
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while not self._pending_messages:
                self._require_connected()
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise WKIMTimeout("等待 IM 消息超时")
                self._condition.wait(remaining)
            return self._pending_messages.popleft()

    def _pump_one(self, deadline: float | None) -> None:
        first, packet_type, body = self._read_frame(deadline)
        if packet_type == _PACKET_PONG:
            return
        if packet_type == _PACKET_PING:
            self._send_raw(_encode_frame(_PACKET_PONG))
            return
        if packet_type == _PACKET_SENDACK:
            reader = _Reader(body)
            ack = SendAck(
                message_id=reader.u64(),
                client_seq=reader.u32(),
                message_seq=reader.u32(),
                reason_code=reader.u8(),
            )
            with self._condition:
                self._pending_acks[ack.client_seq] = ack
                # Bound unsolicited/late ACK storage on a long-lived connection.
                while len(self._pending_acks) > 128:
                    self._pending_acks.pop(next(iter(self._pending_acks)))
                self._condition.notify_all()
            return
        if packet_type == _PACKET_RECV:
            message = self._decode_recv(first, body)
            with self._condition:
                self._pending_messages.append(message)
                self._condition.notify_all()
            return
        if packet_type == _PACKET_DISCONNECT:
            reader = _Reader(body)
            reason_code = reader.u8()
            reason = reader.string()
            raise WKIMError(
                f"IM 服务端断开连接: reasonCode={reason_code}, reason={reason}"
            )
        if packet_type == _PACKET_CONNACK:
            return
        raise WKIMError(f"未处理的 IM 包类型: {packet_type}")

    def _decode_recv(self, first: int, body: bytes) -> RecvMessage:
        reader = _Reader(body)
        setting = reader.u8()
        msg_key = reader.string()
        from_uid = reader.string()
        channel_id = reader.string()
        channel_type = reader.u8()
        expire = reader.u32() if self._proto_version >= 3 else 0
        client_msg_no = reader.string()
        if setting & 0x04:
            reader.string()  # streamNo
            reader.u32()     # streamSeq
            reader.u8()      # streamFlag
        message_id = reader.u64()
        message_seq = reader.u32()
        message_time = reader.u32()
        topic = reader.string() if setting & 0x08 else ""
        encrypted_payload = reader.remaining().decode("ascii")

        verification = (
            f"{message_id}{message_seq}{client_msg_no}{message_time}"
            f"{from_uid}{channel_id}{channel_type}{encrypted_payload}"
        )
        expected_key = hashlib.md5(
            self._encrypt(verification).encode("utf-8")
        ).hexdigest()

        # Match the SDK: acknowledge persistent messages even if validation fails.
        if not first & 0x01:
            ack_body = struct.pack(">QI", message_id, message_seq)
            self._send_raw(_encode_frame(_PACKET_RECVACK, ack_body, flags=first & 0x07))
        if not hmac.compare_digest(expected_key, msg_key):
            raise WKIMError(
                f"IM 消息校验失败: expected={expected_key}, actual={msg_key}"
            )

        raw_content = self._decrypt(encrypted_payload)
        try:
            content: Any = json.loads(raw_content)
        except ValueError:
            content = raw_content
        return RecvMessage(
            message_id=message_id,
            message_seq=message_seq,
            message_time=message_time,
            client_msg_no=client_msg_no,
            from_uid=from_uid,
            channel_id=channel_id,
            channel_type=channel_type,
            content=content,
            raw_content=raw_content,
            expire=expire,
            topic=topic,
        )

    def _require_connected(self) -> None:
        if self._failure is not None:
            raise self._failure
        if not self.connected or self._sock is None:
            raise WKIMError("IM 尚未连接")
