"""pdata-bounded scan of skse64_1_5_97.dll."""
from __future__ import annotations

import bisect
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
            out.append(va + i)
            s = i + 1
    return out

# decode every pdata function once
ALL = []   # (rva, ins)
for b, e in funcs:
    code = read(b, e - b)
    for ins in md.disasm(code, BASE + b):
        ALL.append(ins)
p(f"decoded {len(ALL)} instructions over {len(funcs)} pdata functions")

STR = {
    "SKSEPlugin_Load": find_bytes(b"SKSEPlugin_Load\x00"),
    "SKSEPlugin_Query": find_bytes(b"SKSEPlugin_Query\x00"),
    "DataSKSEPlugins": find_bytes(b"Data\\SKSE\\Plugins"),
    "loaded correctly": find_bytes(b"loaded correctly"),
    "dispatch message": find_bytes(b"dispatch message"),
}
p("\n== string rvas")
for k, v in STR.items():
    p(f"  {k}: {[hex(BASE+x) for x in v]}")

tset = {x: k for k, v in STR.items() for x in v}
p("\n== rip refs to those strings (pdata-bounded)")
for ins in ALL:
    for op in ins.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
            t = ins.address + ins.size + op.mem.disp - BASE
            if t in tset:
                f = func_of(ins.address - BASE)
                p(f"  {ins.address:#x} {ins.mnemonic} {ins.op_str}  -> {tset[t]}  func {BASE+f[0]:#x}" if f
                  else f"  {ins.address:#x} {ins.mnemonic} {ins.op_str} -> {tset[t]} [nofunc]")

# all constants (imm or non-rip disp) in game rva range
consts = {}
for ins in ALL:
    for op in ins.operands:
        v = None
        if op.type == capstone.x86.X86_OP_IMM:
            v = op.imm
        elif op.type == capstone.x86.X86_OP_MEM and op.mem.base not in (0, capstone.x86.X86_REG_RIP):
            v = op.mem.disp
        if v is not None and 0x100000 <= v < 0x1508a00:
            consts.setdefault(v, []).append((ins.address, ins.mnemonic, ins.op_str))
p(f"\n== {len(consts)} distinct game-RVA-range constants (pdata-bounded)")
for d in sorted(consts):
    a, mn, ops = consts[d][0]
    f = func_of(a - BASE)
    p(f"  {d:#x} -> game {0x140000000+d:#x} ({len(consts[d])}x) e.g. {a:#x} {mn} {ops}"
      + (f"  func {BASE+f[0]:#x}" if f else ""))

OUT.write_text("\n".join(L), encoding="utf-8")
print("wrote", OUT, len(L))
