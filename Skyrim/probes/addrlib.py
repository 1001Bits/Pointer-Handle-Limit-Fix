"""Address Library (meh321 versionlib) reader + PE disassembly helper.

Read-only research tooling for the Skyrim handle-cap investigation. Resolves
CommonLibSSE-NG RELOCATION_IDs to RVAs for a given runtime, and disassembles
arbitrary RVA ranges straight out of SkyrimSE.exe with capstone.

No game or Bethesda data is redistributed: this reads the user's own install.
"""

from __future__ import annotations

import struct
import sys
import os
import csv
from dataclasses import dataclass
from pathlib import Path

import capstone
import pefile

IMAGE_BASE = 0x140000000


# --------------------------------------------------------------------------- #
# Address Library
# --------------------------------------------------------------------------- #


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.d = data
        self.p = 0

    def u8(self) -> int:
        v = self.d[self.p]
        self.p += 1
        return v

    def u16(self) -> int:
        v = struct.unpack_from("<H", self.d, self.p)[0]
        self.p += 2
        return v

    def i32(self) -> int:
        v = struct.unpack_from("<i", self.d, self.p)[0]
        self.p += 4
        return v

    def u32(self) -> int:
        v = struct.unpack_from("<I", self.d, self.p)[0]
        self.p += 4
        return v

    def u64(self) -> int:
        v = struct.unpack_from("<Q", self.d, self.p)[0]
        self.p += 8
        return v

    def raw(self, n: int) -> bytes:
        v = self.d[self.p : self.p + n]
        self.p += n
        return v


@dataclass
class AddressLibrary:
    format: int
    version: tuple[int, int, int, int]
    module: str
    pointer_size: int
    id_to_offset: dict[int, int]

    def rva(self, ident: int) -> int:
        try:
            return self.id_to_offset[ident]
        except KeyError as exc:  # pragma: no cover - diagnostic path
            raise KeyError(f"id {ident} not present in {self.version}") from exc

    def va(self, ident: int) -> int:
        return IMAGE_BASE + self.rva(ident)


def load_binary_addrlib(path: str | Path) -> AddressLibrary:
    r = _Reader(Path(path).read_bytes())
    fmt = r.i32()
    if fmt not in (1, 2):
        raise ValueError(f"unsupported address library format {fmt}")
    version = (r.i32(), r.i32(), r.i32(), r.i32())
    name = r.raw(r.i32()).decode("utf-8", "replace").rstrip("\x00")
    ptr_size = r.i32()
    count = r.i32()

    out: dict[int, int] = {}
    prev_id = 0
    prev_off = 0
    for _ in range(count):
        t = r.u8()
        lo, hi = t & 0x0F, t >> 4

        if lo == 0:
            ident = r.u64()
        elif lo == 1:
            ident = prev_id + 1
        elif lo == 2:
            ident = prev_id + r.u8()
        elif lo == 3:
            ident = prev_id - r.u8()
        elif lo == 4:
            ident = prev_id + r.u16()
        elif lo == 5:
            ident = prev_id - r.u16()
        elif lo == 6:
            ident = r.u16()
        elif lo == 7:
            ident = r.u32()
        else:
            raise ValueError(f"bad id encoding {lo}")

        tmp = prev_off // ptr_size if (hi & 8) else prev_off
        b = hi & 7
        if b == 0:
            off = r.u64()
        elif b == 1:
            off = tmp + 1
        elif b == 2:
            off = tmp + r.u8()
        elif b == 3:
            off = tmp - r.u8()
        elif b == 4:
            off = tmp + r.u16()
        elif b == 5:
            off = tmp - r.u16()
        elif b == 6:
            off = r.u16()
        elif b == 7:
            off = r.u32()
        else:
            raise ValueError(f"bad offset encoding {b}")
        if hi & 8:
            off *= ptr_size

        out[ident] = off
        prev_id, prev_off = ident, off

    return AddressLibrary(fmt, version, name, ptr_size, out)


def load_csv_addrlib(path: str | Path) -> AddressLibrary:
    """Read the VR Address Library's ``id,offset`` export.

    The first data row in the distributed CSV is metadata (its offset is a
    dotted database version), so only strict hexadecimal offsets are accepted.
    """
    out: dict[int, int] = {}
    with Path(path).open(newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            try:
                ident = int(row["id"], 10)
                text = row["offset"].strip()
                if not text or any(ch not in "0123456789abcdefABCDEF" for ch in text):
                    continue
                out[ident] = int(text, 16)
            except (KeyError, TypeError, ValueError):
                continue
    if not out:
        raise ValueError(f"no address mappings in {path}")
    return AddressLibrary(0, (1, 4, 15, 0), "SkyrimVR.exe", 8, out)


def load_addrlib(path: str | Path) -> AddressLibrary:
    path = Path(path)
    return load_csv_addrlib(path) if path.suffix.lower() == ".csv" else load_binary_addrlib(path)


# --------------------------------------------------------------------------- #
# PE image
# --------------------------------------------------------------------------- #


class Image:
    def __init__(self, exe: str | Path) -> None:
        self.path = Path(exe)
        self.pe = pefile.PE(str(exe), fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.data = self.pe.__data__
        self.sections = [
            (
                s.Name.rstrip(b"\x00").decode(),
                s.VirtualAddress,
                max(s.Misc_VirtualSize, s.SizeOfRawData),
                s.PointerToRawData,
                s.SizeOfRawData,
                s.Characteristics,
            )
            for s in self.pe.sections
        ]
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    def section_of(self, rva: int) -> str | None:
        for name, va, vsz, _, _, _ in self.sections:
            if va <= rva < va + vsz:
                return name
        return None

    def read(self, rva: int, size: int) -> bytes:
        for _, va, vsz, praw, rsz, _ in self.sections:
            if va <= rva < va + vsz:
                off = rva - va
                if off >= rsz:  # in virtual-only tail (e.g. .bss); reads as zero
                    return b"\x00" * size
                take = min(size, rsz - off)
                out = self.data[praw + off : praw + off + take]
                return out + b"\x00" * (size - len(out))
        raise ValueError(f"rva {rva:#x} not mapped")

    def disasm(self, rva: int, size: int):
        code = self.read(rva, size)
        return list(self.md.disasm(code, self.base + rva))

    def dump(self, rva: int, size: int = 0x200, stop_at_ret: bool = True) -> str:
        lines = []
        for ins in self.disasm(rva, size):
            raw = ins.bytes.hex()
            lines.append(f"{ins.address:#012x}  {raw:<20}  {ins.mnemonic} {ins.op_str}")
            if stop_at_ret and ins.mnemonic in ("ret", "jmp") and len(lines) > 3:
                # jmp is a common tail call / thunk terminator; keep a little slack
                if ins.mnemonic == "ret":
                    break
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Runtime registry
# --------------------------------------------------------------------------- #

RUNTIMES = {
    "SE": {
        "exe": os.environ.get("SHCR_SE_EXE", r"C:\Games\Skyrim SE\SkyrimSE.exe"),
        "db": os.environ.get("SHCR_SE_ADDRLIB",
                             r"C:\Games\Skyrim SE\Data\SKSE\Plugins\version-1-5-97-0.bin"),
        "version": "1.5.97.0",
    },
    "AE": {
        "exe": os.environ.get("SHCR_AE_EXE", r"C:\Games\Skyrim AE 1.6\SkyrimSE.exe"),
        "db": os.environ.get("SHCR_AE_ADDRLIB",
                             r"C:\Games\Skyrim AE 1.6\Data\SKSE\Plugins\versionlib-1-6-1170-0.bin"),
        "version": "1.6.1170.0",
    },
    "GOG": {
        "exe": os.environ.get(
            "SHCR_GOG_EXE", r"D:\Original Files\Skyrim GOG 1.6.1179\SkyrimSE.exe"),
        "db": os.environ.get(
            "SHCR_GOG_ADDRLIB",
            r"D:\Original Files\Skyrim GOG 1.6.1179\Data\SKSE\Plugins\versionlib-1-6-1179-0.bin"),
        "version": "1.6.1179.0",
    },
    "VR": {
        # Steam's on-disk executable is CEG-encrypted.  The exact Steamless
        # image below has the same PE layout and is used only for read-only
        # generation; the DLL verifies every generated byte against the live,
        # decrypted SkyrimVR.exe image before it writes anything.
        "exe": os.environ.get("SHCR_VR_EXE", r"D:\SkyrimVR\SkyrimVR.exe.unpacked.exe"),
        "db": os.environ.get(
            "SHCR_VR_ADDRLIB",
            r"C:\Development\Tools\ghidra_scripts_fast\SKSE\Plugins\version-1-4-15-0.csv"),
        "version": "1.4.15.0",
    },
}


def open_runtime(tag: str) -> tuple[Image, AddressLibrary]:
    cfg = RUNTIMES[tag]
    return Image(cfg["exe"]), load_addrlib(cfg["db"])


if __name__ == "__main__":
    for tag in sys.argv[1:] or ["SE", "AE", "GOG", "VR"]:
        img, lib = open_runtime(tag)
        print(f"== {tag}  {RUNTIMES[tag]['version']}")
        print(f"   exe      {img.path}  base={img.base:#x}")
        print(f"   addrlib  fmt={lib.format} ver={lib.version} module={lib.module!r} ids={len(lib.id_to_offset)}")
        print(f"   sections {[(n, hex(v), hex(s)) for n, v, s, _, _, _ in img.sections]}")
