"""Run the real ARM64 handshake builder with deterministic external stubs.

Captures native plaintext/key/IV and compares the wire bytes to the Python
implementation. No Android device is needed. Requires unicorn + pyelftools.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from Crypto.Cipher import AES
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2
from unicorn.arm64_const import UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_LR
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL0
from jianxun.qlck import QLCKOptions, build_handshake, murmur2


def verify(library: Path = Path("resource/libcf-msc.so")) -> dict:
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            begin = segment["p_vaddr"] & ~0xFFF
            end = (segment["p_vaddr"] + segment["p_memsz"] + 0xFFF) & ~0xFFF
            uc.mem_map(begin, end - begin)
            uc.mem_write(segment["p_vaddr"], segment.data())
        relocs = elf.get_section_by_name(".rela.dyn")
        symbols = elf.get_section(relocs["sh_link"])
        for reloc in relocs.iter_relocations():
            kind = reloc["r_info_type"]
            if kind == 1027:
                value = reloc["r_addend"]
            elif kind in (257, 1025):
                value = symbols.get_symbol(reloc["r_info_sym"])["st_value"] + reloc["r_addend"]
            else:
                continue
            uc.mem_write(reloc["r_offset"], struct.pack("<Q", value))
    work = 0x10000000
    uc.mem_map(work, 0x20000)
    uc.reg_write(UC_ARM64_REG_SP, work + 0x18000)
    uc.reg_write(UC_ARM64_REG_TPIDR_EL0, work + 0x1F000)
    out, ctx = work, work + 0x1000
    key_obj, iv_obj = work + 0x4000, work + 0x4100
    key_str, iv_str = work + 0x5000, work + 0x5100
    uc.mem_write(key_obj + 32, struct.pack("<Q", key_str))
    uc.mem_write(iv_obj + 32, struct.pack("<Q", iv_str))
    uc.mem_write(key_str, b"ce3487fe393c4f\0")
    uc.mem_write(iv_str, b"1234567812345678\0")
    options = QLCKOptions(fingerprint="E6319E11162A94F9236399F5D5AE279E", session_id="c62e75281704da63")
    fp = options.device_fingerprint()
    uc.mem_write(0x61B6C8, options.app_key.encode())
    uc.mem_write(0x61B6E8, fp.encode())
    uc.mem_write(0x61B74A, options.manufacturer.encode())
    uc.mem_write(0x61B75A, options.brand.encode())
    uc.mem_write(0x61B76A, options.model.encode())
    uc.mem_write(0x61B7EC, struct.pack("<I", options.api_level))
    uc.mem_write(0x61D180, struct.pack("<I", 1))
    uc.mem_write(0x61B7DA, options.network.encode())
    uc.mem_write(0x61B6A4, options.session_id.encode())
    uc.mem_write(0x61B7AA, options.package.encode())
    uc.mem_write(0x61B844, struct.pack("<I", 2))
    uc.mem_write(ctx + 4472, struct.pack("<I", 1))
    destination = b"tcp.jianxun01.com:15100"
    registers = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                 UC_ARM64_REG_X3, UC_ARM64_REG_X4]
    captured = {}
    nonce = iter(b"AB")
    def args():
        return [uc.reg_read(reg) for reg in registers]
    def hook(_uc, address, _size, _data):
        a = args()
        result = 0
        if address == 0x26E424:
            uc.mem_write(a[1], struct.pack("<II", 0, murmur2(destination)) + destination + b"\0")
        elif address == 0x597440:
            uc.mem_write(a[0], b"\0" * 16)
        elif address == 0x5971B0:
            uc.mem_write(a[0], bytes(uc.mem_read(a[1], a[2])))
            result = a[0]
        elif address == 0x25BBC0:
            uc.mem_write(a[2], hashlib.sha1(uc.mem_read(a[0], a[1])).digest())
        elif address == 0x26D2D4:
            result = next(nonce)
        elif address == 0x26F874:
            result = key_obj
        elif address == 0x26F8DC:
            result = iv_obj
        elif address == 0x25D8F0:
            captured["key"] = bytes(uc.mem_read(a[1], 16))
            captured["iv"] = bytes(uc.mem_read(a[2], 16))
        elif address == 0x25E05C:
            raw = bytes(uc.mem_read(a[1], a[3]))
            captured["plaintext"] = raw
            uc.mem_write(a[2], AES.new(captured["key"], AES.MODE_CBC, iv=captured["iv"]).encrypt(raw))
        elif address not in (0x25CB2C, 0x263E10, 0x25CB50, 0x2665C8):
            return
        uc.reg_write(UC_ARM64_REG_X0, result)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
    uc.hook_add(UC_HOOK_CODE, hook)
    stop = work + 0x1E000
    uc.reg_write(UC_ARM64_REG_X0, out)
    uc.reg_write(UC_ARM64_REG_X1, 1024)
    uc.reg_write(UC_ARM64_REG_X2, ctx)
    uc.reg_write(UC_ARM64_REG_LR, stop)
    uc.emu_start(0x26E7C0, stop, count=100000)
    native = bytes(uc.mem_read(out, 488))
    python = build_handshake("tcp.jianxun01.com", 15100, options, fp, nonce=b"AB")
    raw_python = AES.new(b"ce3487fe393c4fAB", AES.MODE_CBC, iv=b"1234567812345678").decrypt(python[8:])
    differences = [{"offset": i, "native": x, "python": y}
                   for i, (x, y) in enumerate(zip(captured["plaintext"], raw_python)) if x != y]
    result = {"wire_equal": native == python, "native_return": uc.reg_read(UC_ARM64_REG_X0),
              "native_header": native[:8].hex(), "native_key": captured["key"].hex(),
              "plaintext_differences": differences}
    Path("doc/ida_socket/native_handshake_verification.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
