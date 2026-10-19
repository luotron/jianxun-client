from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Protocol import DH
from Crypto.PublicKey import ECC
from Crypto.Util.Padding import pad, unpad

from jianxun.im import WKIMClient, WKIMError, WKIMTimeout, _Reader
from jianxun.im import _encode_frame, _encode_remaining_length, _pack_string
from jianxun.qlck import QLCKOptions, QLCKSocket, build_handshake, decode_handshake
from jianxun.qlck import decode_control, encode_control, murmur2
from tools.analyze_im_capture import Segment, reassemble, analyze


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError()
        data.extend(part)
    return bytes(data)


def read_frame(sock):
    first = read_exact(sock, 1)[0]
    if first >> 4 in (7, 8):
        return first, b""
    length = 0
    for shift in range(0, 28, 7):
        digit = read_exact(sock, 1)[0]
        length |= (digit & 127) << shift
        if not digit & 128:
            return first, read_exact(sock, length)
    raise AssertionError("Overlong varint")


class GatewayFixture:
    """Independent peer: real TCP + AppVest + X25519 + encrypted IM frames."""

    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.gateway = "127.0.0.1:" + str(self.listener.getsockname()[1])
        self.errors = []
        self.done = threading.Event()
        self.heartbeat = threading.Event()
        self.recv_ack = None
        self.payloads = []
        self.accept_count = 0
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        try:
            with self.listener.accept()[0] as raw:
                self.accept_count += 1
                raw.settimeout(2)
                preamble = decode_handshake(read_exact(raw, 488))
                assert preamble["host"] == "tcp.jianxun01.com:15100"
                assert preamble["host_hash"] == murmur2(preamble["host"].encode())
                stream = QLCKSocket(raw, ord(preamble["fingerprint"][0]))
                first, body = read_frame(stream)
                assert first == 0x10
                reader = _Reader(body)
                assert reader.u8() == 4 and reader.u8() == 0
                reader.string()  # device ID
                assert reader.string() == "test-user"
                assert reader.string() == "test-token"
                reader.u64()
                public = DH.import_x25519_public_key(base64.b64decode(reader.string()))
                private = ECC.generate(curve="Curve25519")
                secret = DH.key_agreement(static_priv=private, static_pub=public, kdf=lambda x: x)
                key = hashlib.md5(base64.b64encode(secret)).hexdigest()[:16].encode()
                iv = b"fixture-salt-123"
                assert len(iv) == 16
                def encrypt(text):
                    return base64.b64encode(AES.new(key, AES.MODE_CBC, iv).encrypt(pad(text.encode(), 16))).decode()
                def non_ping():
                    while True:
                        packet, data = read_frame(stream)
                        if packet >> 4 == 7:
                            stream.sendall(b"\x80")
                            self.heartbeat.set()
                        else:
                            return packet, data
                connack = _encode_frame(2, struct.pack(">QB", 0, 1)
                                        + _pack_string(base64.b64encode(private.public_key().export_key(format="raw")).decode())
                                        + _pack_string(iv.decode()) + struct.pack(">Q", 1))
                # Split fixed header and remaining length over separate writes.
                for part in (connack[:1], connack[1:2], connack[2:]):
                    stream.sendall(part)
                for seq in (1, 2):
                    first, body = non_ping()
                    assert first == 0x32
                    reader = _Reader(body)
                    assert reader.u8() == 0 and reader.u32() == seq
                    client_no, channel = reader.string(), reader.string()
                    channel_type, expire, msg_key = reader.u8(), reader.u32(), reader.string()
                    ciphertext = reader.remaining().decode()
                    verification = f"{seq}{client_no}{channel}{channel_type}{ciphertext}"
                    assert msg_key == hashlib.md5(encrypt(verification).encode()).hexdigest()
                    assert expire == 0
                    payload = json.loads(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(base64.b64decode(ciphertext)), 16))
                    self.payloads.append(payload)
                    ack = _encode_frame(4, struct.pack(">QIIB", 9000 + seq, seq, seq, 1))
                    if seq == 1:
                        content = encrypt(json.dumps({"content": "server push", "type": 1}))
                        verification = f"90007server-no1700000000other-usertest-group2{content}"
                        msg_key = hashlib.md5(encrypt(verification).encode()).hexdigest()
                        recv = _encode_frame(5, b"\0" + _pack_string(msg_key)
                                             + _pack_string("other-user") + _pack_string("test-group")
                                             + b"\x02" + struct.pack(">I", 0) + _pack_string("server-no")
                                             + struct.pack(">QII", 9000, 7, 1700000000)
                                             + content.encode(), flags=2)
                        # RECV arrives before SENDACK in the same TCP write.
                        stream.sendall(recv + ack)
                        first, body = non_ping()
                        assert first == 0x62
                        self.recv_ack = struct.unpack(">QI", body)
                    else:
                        stream.sendall(ack)
                raw.settimeout(0.1)
                while not self.done.is_set():
                    try:
                        first, body = read_frame(stream)
                    except socket.timeout:
                        continue
                    if first == 0x70:
                        stream.sendall(b"\x80")
                        self.heartbeat.set()
                    else:
                        raise AssertionError(f"Unexpected idle frame {first}")
        except (EOFError, OSError) as exc:
            if not self.done.is_set():
                self.errors.append(repr(exc))
        except BaseException as exc:
            self.errors.append(repr(exc))

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.done.set()
        self.listener.close()
        self.thread.join(3)


class IMTests(unittest.TestCase):
    def test_zero_length_and_fragmented_frames(self):
        self.assertEqual(_encode_remaining_length(0), b"\0")
        self.assertEqual(_encode_frame(9), b"\x90\0")
        parser = WKIMClient()
        wire = _encode_frame(3, b"x" * 129) + b"\x70\x80"
        for byte in wire[:-3]:
            parser._buffer.append(byte)
            self.assertIsNone(parser._extract_frame())
        parser._buffer.extend(wire[-3:])
        self.assertEqual(parser._extract_frame(), (0x30, 3, b"x" * 129))
        self.assertEqual(parser._extract_frame(), (0x70, 7, b""))
        self.assertEqual(parser._extract_frame(), (0x80, 8, b""))

    def test_invalid_lengths(self):
        parser = WKIMClient()
        parser._buffer.extend(b"\x30\xff\xff\xff\xff")
        with self.assertRaises(WKIMError):
            parser._extract_frame()
        with self.assertRaises(ValueError):
            _encode_remaining_length(-1)

    def test_handshake_integrity(self):
        options = QLCKOptions(session_id="0123456789abcdef")
        fp = options.device_fingerprint("android-id")
        packet = build_handshake("tcp.jianxun01.com", 15100, options, fp, nonce=b"AB")
        self.assertEqual(len(packet), 488)
        decoded = decode_handshake(packet)
        self.assertEqual(decoded["host"], "tcp.jianxun01.com:15100")
        self.assertEqual(decoded["fingerprint"], fp)
        with self.assertRaises(ValueError):
            decode_handshake(packet[:-1] + bytes([packet[-1] ^ 1]))

    def test_control_integrity(self):
        message = {"id": 1, "op": 3, "request": "hello"}
        packet = encode_control(message, nonce=b"AB")
        self.assertEqual(decode_control(packet), message)
        with self.assertRaises(ValueError):
            decode_control(packet[:-1] + bytes([packet[-1] ^ 1]))

    def test_capture_retransmissions_gaps_and_sequence_wrap(self):
        def part(seq, data):
            return Segment(0, ("A", 1), ("B", 2), seq, 0, data)
        self.assertEqual(reassemble([part(103, b"def"), part(100, b"abcde"), part(100, b"abcde"), part(110, b"gap")]), [b"abcdef", b"gap"])
        self.assertEqual(reassemble([part(0xFFFFFFFE, b"ab"), part(0, b"cd")]), [b"abcd"])

    def test_real_capture_send_and_ack(self):
        path = Path(__file__).resolve().parents[1] / "tcpdump/cap_im4.pcap"
        if not path.is_file():
            self.skipTest("Capture not present")
        flows = analyze(path, "106.53.220.67", 0x45)
        frames = [frame for flow in flows for chunk in flow["chunks"] for frame in chunk.get("frames", [])]
        send = next(frame for frame in frames if frame["type"] == 3)
        ack = next(frame for frame in frames if frame["type"] == 4)
        self.assertEqual(send["client_seq"], ack["client_seq"])
        self.assertEqual(ack["reason_code"], 1)
        controls = [chunk["control"] for flow in flows for chunk in flow["chunks"] if "control" in chunk]
        self.assertEqual(len(controls), 8)  # Includes gzip packets, CRC and SHA1 checks.

    def test_one_socket_full_duplex_heartbeat_and_timeout(self):
        with patch("jianxun.im._HEARTBEAT_SECONDS", 0.05), GatewayFixture() as server:
            im = WKIMClient(uid="test-user", token="test-token", timeout=2,
                            qlck=QLCKOptions(gateway=server.gateway, discover=False))
            try:
                with im, ThreadPoolExecutor(1) as pool:
                    pending = pool.submit(im.recv_message, 2)
                    ack = im.send_text("test-group", "hello")
                    self.assertEqual(ack.reason_code, 1)
                    self.assertEqual(pending.result(2).content["content"], "server push")
                    with self.assertRaises(WKIMTimeout):
                        im.recv_message(0.02)
                    self.assertTrue(im.connected)
                    image_ack = im.send_image("test-group", "https://example.test/image.jpg", 12, 34)
                    self.assertEqual(image_ack.client_seq, 2)
                    self.assertTrue(server.heartbeat.wait(1), server.errors)
                    self.assertEqual(server.recv_ack, (9000, 7))
                    self.assertEqual(server.accept_count, 1)
                    self.assertEqual(server.payloads[1], {"width": 12, "height": 34, "url": "https://example.test/image.jpg", "type": 2})
                    server.done.set()
            finally:
                server.done.set()
                im.close()
            self.assertFalse(server.errors, server.errors)
            self.assertIsNone(im._reader_thread)


if __name__ == "__main__":
    unittest.main()
