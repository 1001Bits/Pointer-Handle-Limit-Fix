"""Find how SKSE reaches 0x180088020 (root of the plugin-load chain)."""
from __future__ import annotations

import bisect
import struct
import sys
from pathlib import Path

import capstone
import pefile

OUT = Path(sys.argv[1])
DLL = r"C:\Games\Skyrim SE\skse64_1_5_97.dll"

pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories(directories=[
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
])
BASE = pe.OPTIONAL_HEADER.ImageBase
raw = pe.__data__
secs = [(s.Name.rstrip(b"\x00").decode(errors="replace"), s.VirtualAddress,
         max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData, s.SizeOfRawData)
        for s in pe.sections]
funcs = sorted({(e.struct.BeginAddress, e.struct.EndAddress)
                for e in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", [])
                if e.struct.EndAddress > e.struct.BeginAddress})
fstarts = [b for b, _ in funcs]

L = []
def p(s=""):
    L.append(str(s))

def read(rva, n):
    for _, va, vsz, praw, rsz in secs:
        if va <= rva < va + vsz:
            off = rva - va
            if off >= rsz:
                return b"\x00" * n
            take = max(0, min(n, rsz - off))
            return bytes(raw[praw + off: praw + off + take]) + b"\x00" * (n - take)
    raise ValueError(hex(rva))

def func_of(rva):
    i = bisect.bisect_right(fstarts, rva) - 1
    if i < 0:
        return None
    b, e = funcs[i]
    return b if b <= rva < e else None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

p("== exports")
for exp in getattr(pe, "DIRECTORY_ENTRY_EXPORT", None).symbols if getattr(pe, "DIRECTORY_ENTRY_EXPORT", None) else []:
    p(f"   {exp.name} @ {BASE+exp.address:#x}")

TARGETS = [0x88020, 0x803c0, 0x80750, 0x81000]
p("\n== raw dword/qword occurrences (whole file)")
for t in TARGETS:
    for w, fmt in ((4, "<I"), (8, "<Q")):
        needle = struct.pack(fmt, (BASE + t) if w == 8 else t)
        hits = []
        s = 0
        while True:
            i = raw.find(needle, s)
            if i < 0:
                break
            hits.append(i)
            s = i + 1
        p(f"   {t:#x} as {w}-byte {'va' if w==8 else 'rva'}: {len(hits)} file-offset hits {[hex(h) for h in hits[:10]]}")

p("\n== byte-level rel32 sites targeting them (any opcode)")
for n, va, vsz, praw, rsz in secs:
    if n != ".text" or not rsz:
        continue
    d = bytes(raw[praw:praw + rsz])
    for i in range(1, len(d) - 4):
        disp = struct.unpack_from("<i", d, i)[0]
        tgt = va + i + 4 + disp
        if tgt in TARGETS:
            f = func_of(va + i - 1)
            p(f"   disp at rva {va+i:#x} opcode {d[i-1]:#04x} -> {BASE+tgt:#x}   in func {BASE+f:#x}" if f is not None
              else f"   disp at rva {va+i:#x} opcode {d[i-1]:#04x} -> {BASE+tgt:#x}   [no func]")

p("\n== disasm 0x180088020")
b = func_of(0x88020)
if b is not None:
    e = next(e for bb, e in funcs if bb == b)
    for ins in md.disasm(read(b, e - b), BASE + b):
        p(f"   {ins.address:#x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}")

p("\n== disasm 0x1800803c0")
b = func_of(0x803c0)
e = next(e for bb, e in funcs if bb == b)
for ins in md.disasm(read(b, e - b), BASE + b):
    p(f"   {ins.address:#x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}")

OUT.write_text("\n".join(L), encoding="utf-8")
print("wrote", OUT, len(L))
