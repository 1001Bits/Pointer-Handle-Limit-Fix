"""Look inside skse64_1_5_97.dll for the game RVAs it references (RelocAddr
offsets appear as mov-imm32 constants), and locate its hook targets."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import capstone
import pefile

from image import open_runtime

DLL = r"C:\Games\Skyrim SE\skse64_1_5_97.dll"
OUT = Path(sys.argv[1])

game, _ = open_runtime("SE")
gstarts = {f.begin: f for f in game.funcs}

pe = pefile.PE(DLL, fast_load=True)
data = pe.__data__
secs = [(s.Name.rstrip(b"\x00").decode(errors="replace"), s.VirtualAddress,
         max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData, s.SizeOfRawData)
        for s in pe.sections]
L = []
def p(s=""):
    L.append(str(s))

p(f"skse dll {DLL} base={pe.OPTIONAL_HEADER.ImageBase:#x}")
for n, va, vsz, praw, rsz in secs:
    p(f"  {n:<10} rva={va:#x} vsz={vsz:#x} raw={rsz:#x}")

# raw dword search across the whole file for specific game RVAs
targets = [0x5ae010, 0x5acbd0, 0x5bccb0, 0x125d0, 0x1ec47c0, 0x1ec47ac, 0x1ec47b0]
p("\n== raw dword occurrences of specific game RVAs in the whole DLL file")
for t in targets:
    needle = struct.pack("<I", t)
    hits = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    p(f"  rva {t:#x}: {len(hits)} hits at file offsets {[hex(h) for h in hits[:20]]}")

# collect mov-imm32 constants in .text that look like game RVAs
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
consts = {}
for n, va, vsz, praw, rsz in secs:
    if n != ".text" or not rsz:
        continue
    code = bytes(data[praw:praw + rsz])
    for ins in md.disasm(code, pe.OPTIONAL_HEADER.ImageBase + va):
        if ins.mnemonic not in ("mov", "lea", "cmp", "add", "push"):
            continue
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                v = op.imm
                if 0x1000 <= v < 0x1508a00:
                    consts.setdefault(v, []).append(ins.address)

p(f"\n== {len(consts)} distinct immediates in plausible game-RVA range")
# which land exactly on a game function start
onstart = sorted(v for v in consts if v in gstarts)
p(f"   {len(onstart)} of them land exactly on a game .pdata function start")
for v in onstart:
    p(f"   {v:#x} -> game va {0x140000000+v:#x}   used at {[hex(a) for a in consts[v][:4]]}")

OUT.write_text("\n".join(L), encoding="utf-8")
print("wrote", OUT, len(L), "lines")
