"""Confirm the SKSE hook site inside the CRT startup, and enumerate every
writer of the free-list head/tail."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import capstone
import pefile

from image import open_runtime

OUT = Path(sys.argv[1])
img, lib = open_runtime("SE")
L = []
def p(s=""):
    L.append(str(s))

# --- which import is the hooked IAT slot 0x1415098a8? ---------------------
pe2 = pefile.PE(str(img.path), fast_load=True)
pe2.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
IAT_RVA = 0x15098A8
p(f"== hooked IAT slot va=0x1415098a8 rva={IAT_RVA:#x} section={img.section_of(IAT_RVA)}")
for entry in getattr(pe2, "DIRECTORY_ENTRY_IMPORT", []):
    for imp in entry.imports:
        if imp.address - img.base == IAT_RVA:
            p(f"   -> {entry.dll.decode()} :: {imp.name.decode() if imp.name else imp.ordinal}")

p("\n== CRT startup 0x14134b05c (contains the hooked call and the WinMain call)")
p(img.dump_func(0x134b05c))

p("\n== 0x14134b1fc (WinMainCRTStartup-ish)")
p(img.dump_func(0x134b1fc))

p("\n== entry constructor 0x1401d5970 (from CRT array-construct)")
p(img.dump_func(0x1d5970))

p("\n== release-all / reset 0x1401d59c0")
p(img.dump_func(0x1d59c0))

# --- everything that references head / tail ------------------------------
def riprefs(target_rva):
    hits = []
    for f in img.funcs:
        try:
            code = img.read(f.begin, f.end - f.begin)
        except ValueError:
            continue
        for ins in img.md.disasm(code, img.base + f.begin):
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    if ins.address + ins.size + op.mem.disp - img.base == target_rva:
                        hits.append((f.begin, ins))
    return hits

for name, rva in (("head", 0x1ec47ac), ("tail", 0x1ec47b0), ("lock", 0x1ec47b8)):
    hits = riprefs(rva)
    p(f"\n== {len(hits)} references to {name} (va {img.base+rva:#x})")
    for fb, ins in hits:
        p(f"   {ins.address:#x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}   [func {img.base+fb:#x}]")

OUT.write_text("\n".join(L), encoding="utf-8")
print("wrote", OUT, len(L))
