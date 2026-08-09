"""PE image helper with function boundaries from the exception directory.

x64 PE images carry a complete RUNTIME_FUNCTION table in .pdata: every
non-leaf function's exact [begin, end) RVA. That gives precise function
bounds for disassembly and an exhaustive function list for whole-image
scans -- no heuristics, no Ghidra dependency.
"""

from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass
from pathlib import Path

import capstone
import pefile

from addrlib import RUNTIMES, load_addrlib


@dataclass(frozen=True)
class Func:
    begin: int  # RVA
    end: int    # RVA (exclusive)

    def __contains__(self, rva: int) -> bool:
        return self.begin <= rva < self.end


class Image:
    def __init__(self, exe: str | Path) -> None:
        self.path = Path(exe)
        self.pe = pefile.PE(str(exe), fast_load=True)
        self.pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
        )
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.data = self.pe.__data__
        self._sections = [
            (
                s.Name.rstrip(b"\x00").decode(errors="replace"),
                s.VirtualAddress,
                max(s.Misc_VirtualSize, s.SizeOfRawData),
                s.PointerToRawData,
                s.SizeOfRawData,
            )
            for s in self.pe.sections
        ]
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

        self.funcs: list[Func] = self._load_pdata()
        self._starts = [f.begin for f in self.funcs]

    # -- layout ------------------------------------------------------------ #

    def _load_pdata(self) -> list[Func]:
        out: list[Func] = []
        seen: set[int] = set()
        for e in getattr(self.pe, "DIRECTORY_ENTRY_EXCEPTION", []) or []:
            b = e.struct.BeginAddress
            n = e.struct.EndAddress
            if n > b and b not in seen:
                seen.add(b)
                out.append(Func(b, n))
        out.sort(key=lambda f: f.begin)
        return out

    def section_of(self, rva: int) -> str | None:
        for name, va, vsz, _, _ in self._sections:
            if va <= rva < va + vsz:
                return name
        return None

    def text_ranges(self) -> list[tuple[int, int]]:
        return [
            (va, va + min(vsz, rsz))
            for name, va, vsz, _, rsz in self._sections
            if name == ".text" and rsz
        ]

    def read(self, rva: int, size: int) -> bytes:
        for _, va, vsz, praw, rsz in self._sections:
            if va <= rva < va + vsz:
                off = rva - va
                if off >= rsz:
                    return b"\x00" * size
                take = max(0, min(size, rsz - off))
                out = self.data[praw + off : praw + off + take]
                return bytes(out) + b"\x00" * (size - len(out))
        raise ValueError(f"rva {rva:#x} is not mapped")

    def u32(self, rva: int) -> int:
        return struct.unpack_from("<I", self.read(rva, 4))[0]

    def u64(self, rva: int) -> int:
        return struct.unpack_from("<Q", self.read(rva, 8))[0]

    # -- functions --------------------------------------------------------- #

    def func_containing(self, rva: int) -> Func | None:
        i = bisect.bisect_right(self._starts, rva) - 1
        if i < 0:
            return None
        f = self.funcs[i]
        return f if rva in f else None

    def disasm(self, rva: int, size: int):
        return list(self.md.disasm(self.read(rva, size), self.base + rva))

    def disasm_func(self, rva: int):
        f = self.func_containing(rva)
        if f is None:
            return self.disasm(rva, 0x200)
        return self.disasm(f.begin, f.end - f.begin)

    def fmt(self, insns, mark: dict[int, str] | None = None) -> str:
        mark = mark or {}
        lines = []
        for ins in insns:
            tag = mark.get(ins.address, "")
            lines.append(
                f"  {ins.address:#012x}  {ins.bytes.hex():<22} {ins.mnemonic:<8} {ins.op_str}"
                + (f"   ; {tag}" if tag else "")
            )
        return "\n".join(lines)

    def dump_func(self, rva: int, title: str = "") -> str:
        f = self.func_containing(rva)
        hdr = (
            f"--- {title or ''} rva={rva:#x} va={self.base + rva:#x}"
            + (f"  [pdata {f.begin:#x}..{f.end:#x}, {f.end - f.begin} bytes]" if f else "  [no pdata entry]")
        )
        return hdr + "\n" + self.fmt(self.disasm_func(rva))

    # -- rip-relative target of an instruction ------------------------------ #

    def rip_targets(self, ins) -> list[int]:
        """RVAs referenced by RIP-relative memory operands of `ins`."""
        out = []
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                out.append(ins.address + ins.size + op.mem.disp - self.base)
        return out


def open_runtime(tag: str):
    cfg = RUNTIMES[tag]
    return Image(cfg["exe"]), load_addrlib(cfg["db"])


if __name__ == "__main__":
    for tag in ("SE", "AE"):
        img, lib = open_runtime(tag)
        print(f"{tag}: {img.path.name} funcs={len(img.funcs)} text={[(hex(a), hex(b)) for a, b in img.text_ranges()]}")
