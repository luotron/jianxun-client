"""Reassemble classic PCAP TCP flows and inspect AppVest/WuKongIM frames."""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from jianxun.im import WKIMClient, _Reader
from jianxun.qlck import decode_handshake, decode_control


@dataclass(frozen=True)
class Segment:
    timestamp: float
    source: tuple[str, int]
    destination: tuple[str, int]
    sequence: int
    flags: int
    data: bytes


def tcp_segments(path: Path):
    with path.open("rb") as stream:
        header = stream.read(24)
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
                   b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
        if header[:4] not in formats:
            raise ValueError(f"{path}: expected classic PCAP")
        endian, scale = formats[header[:4]]
        linktype = struct.unpack_from(endian + "I", header, 20)[0]
        while record := stream.read(16):
            if len(record) != 16:
                raise ValueError("Truncated PCAP record header")
            sec, sub, captured, _ = struct.unpack(endian + "4I", record)
            packet = stream.read(captured)
            if len(packet) != captured:
                raise ValueError("Truncated PCAP packet")
            if linktype == 1:
                offset = 14
                ethertype = packet[12:14]
                while ethertype in (b"\x81\x00", b"\x88\xa8"):
                    ethertype = packet[offset + 2:offset + 4]
                    offset += 4
                if ethertype != b"\x08\x00":
                    continue
            elif linktype in (101, 228):
                offset = 0
            elif linktype in (0, 108):
                offset = 4
            elif linktype in (113, 276):
                offset = 16 if linktype == 113 else 20
            else:
                raise ValueError(f"Unsupported PCAP linktype {linktype}")
            ip = packet[offset:]
            if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
                continue
            if struct.unpack_from(">H", ip, 6)[0] & 0x3FFF:
                continue  # Fragment reassembly is outside this TCP inspector.
            tcp = ip[(ip[0] & 15) * 4:int.from_bytes(ip[2:4], "big")]
            if len(tcp) < 20:
                continue
            src_port, dst_port, sequence = struct.unpack_from(">HHI", tcp)
            start = (tcp[12] >> 4) * 4
            if start < 20 or start > len(tcp):
                continue
            yield Segment(sec + sub / scale,
                          (socket.inet_ntoa(ip[12:16]), src_port),
                          (socket.inet_ntoa(ip[16:20]), dst_port), sequence,
                          tcp[13], tcp[start:])


def reassemble(segments: list[Segment]) -> list[bytes]:
    """Trim retransmissions/overlaps and split at capture gaps. Preserve wrap."""
    payloads = [part for part in segments if part.data]
    if not payloads:
        return []
    anchor = payloads[0].sequence
    def relative(part: Segment) -> int:
        return ((part.sequence - anchor + (1 << 31)) % (1 << 32)) - (1 << 31)
    ordered = sorted(payloads, key=relative)
    chunks: list[bytearray] = []
    expected: int | None = None
    for part in ordered:
        position = relative(part)
        if expected is None or position > expected:
            chunks.append(bytearray(part.data))
            expected = position + len(part.data)
        elif position + len(part.data) > expected:
            chunks[-1].extend(part.data[expected - position:])
            expected = position + len(part.data)
    return [bytes(chunk) for chunk in chunks]


def frames(data: bytes, xor_key: int) -> list[dict]:
    parser = WKIMClient()
    parser._buffer.extend(bytes(value ^ xor_key for value in data))
    result = []
    while parser._buffer:
        frame = parser._extract_frame()
        if frame is None:
            result.append({"incomplete_bytes": len(parser._buffer)})
            break
        first, packet_type, body = frame
        item = {"type": packet_type, "flags": first & 15, "body_bytes": len(body)}
        reader = _Reader(body)
        if packet_type == 3:
            item.update(setting=reader.u8(), client_seq=reader.u32(),
                        client_msg_no=reader.string(), channel_id=reader.string(),
                        channel_type=reader.u8(), expire=reader.u32(), msg_key=reader.string())
            item["encrypted_payload"] = reader.remaining().decode("ascii")
        elif packet_type == 4:
            item.update(message_id=reader.u64(), client_seq=reader.u32(),
                        message_seq=reader.u32(), reason_code=reader.u8())
        # Never dump CONNECT credentials or plaintext user messages by default.
        result.append(item)
    return result


def analyze(path: Path, peer: str, xor_key: int) -> list[dict]:
    directions = defaultdict(list)
    for part in tcp_segments(path):
        if peer and peer not in (part.source[0], part.destination[0]):
            continue
        directions[(part.source, part.destination)].append(part)
    result = []
    for (source, destination), segments in directions.items():
        item = {"source": source, "destination": destination, "chunks": []}
        for data in reassemble(segments):
            chunk = {"wire_bytes": len(data), "prefix_hex": data[:8].hex()}
            if data.startswith(bytes.fromhex("cd6a000101e0")) and len(data) >= 488:
                try:
                    chunk["handshake"] = decode_handshake(data[:488])
                    data = data[488:]
                except ValueError as exc:
                    chunk["handshake_error"] = str(exc)
            if 80 in (source[1], destination[1]) and data:
                try:
                    chunk["frames"] = frames(data, xor_key)
                except Exception as exc:
                    chunk["frame_error"] = str(exc)
            elif 8080 in (source[1], destination[1]) and data:
                try:
                    chunk["control"] = decode_control(data)
                except ValueError as exc:
                    chunk["control_error"] = str(exc)
            item["chunks"].append(chunk)
        if item["chunks"]:
            result.append(item)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--peer", default="106.53.220.67")
    parser.add_argument("--xor", type=lambda value: int(value, 0), default=0x45)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = analyze(args.capture, args.peer, args.xor)
    output = json.dumps(result, indent=2, ensure_ascii=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output + "\n", encoding="utf-8")
    print(output)
