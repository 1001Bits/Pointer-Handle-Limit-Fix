"""Trace SKSE's plugin-load code path back to the game hook that triggers it."""
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
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
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
    return (b, e) if b <= rva < e else None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# --- 1. find interesting strings and their RIP refs -----------------------
def find_bytes(needle):
    out = []
    for n, va, vsz, praw, rsz in secs:
        if not rsz:
            continue
        d = bytes(raw[praw:praw + rsz])
        s = 0
        while True:
            i = d.find(needle, s)
            if i < 0:
                break
            out.append((va + i, n))
            s = i + 1
    return out

STRINGS = [b"SKSEPlugin_Load\x00", b"SKSEPlugin_Query\x00",
           b"Data\\SKSE\\Plugins", b"plugin ", b"loaded correctly",
           b"dispatch message"]
p("== string locations")
strloc = {}
for s in STRINGS:
    hits = find_bytes(s)
    strloc[s] = hits
    p(f"  {s!r}: {[(hex(BASE+a), n) for a, n in hits[:6]]}")

# --- 2. all rip-relative refs from .text to a set of targets --------------
def rip_refs(target_rvas):
    tset = set(target_rvas)
    out = []
    for n, va, vsz, praw, rsz in secs:
        if n != ".text" or not rsz:
            continue
        code = bytes(raw[praw:praw + rsz])
        for ins in md.disasm(code, BASE + va):
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    t = ins.address + ins.size + op.mem.disp - BASE
                    if t in tset:
                        out.append((ins.address - BASE, ins.mnemonic, ins.op_str, t))
    return out

targets = [a for s in STRINGS for a, _ in strloc[s]]
p("\n== rip refs to those strings")
for rva, mn, ops, t in rip_refs(targets):
    f = func_of(rva)
    p(f"  {BASE+rva:#x} {mn} {ops}  -> str {BASE+t:#x}   func {BASE+f[0]:#x}" if f
      else f"  {BASE+rva:#x} {mn} {ops}  -> str {BASE+t:#x}   [nofunc]")

# --- 3. all mem-displacement constants in game-RVA range (RelocAddr adds) -
consts = {}
for n, va, vsz, praw, rsz in secs:
    if n != ".text" or not rsz:
        continue
    code = bytes(raw[praw:praw + rsz])
    for ins in md.disasm(code, BASE + va):
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base not in (0, capstone.x86.X86_REG_RIP):
                d = op.mem.disp
                if 0x100000 <= d < 0x1508a00:
                    consts.setdefault(d, []).append((ins.address - BASE, ins.mnemonic, ins.op_str))
p(f"\n== {len(consts)} distinct non-RIP mem displacements in game-RVA range")
for d in sorted(consts):
    site = consts[d][0]
    p(f"  {d:#x} -> game {0x140000000+d:#x}  ({len(consts[d])}x)  e.g. {BASE+site[0]:#x} {site[1]} {site[2]}")

OUT.write_text("\n".join(L), encoding="utf-8")
print("wrote", OUT, len(L))
