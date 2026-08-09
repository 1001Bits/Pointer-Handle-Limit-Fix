"""Disassemble around the table-reference sites that fall outside any .pdata function."""
from __future__ import annotations

import bisect
import sys

from image import open_runtime

SITES = [
    0x140132B23,
    0x1403E06D2,
    0x1403EF0E4,
    0x1404344B3,
    0x1406783D7,
    0x140774013,
    0x1408E2302,
    0x14148BD72,
]

img, _ = open_runtime("SE")
base = img.base
starts = img._starts

for va in SITES:
    rva = va - base
    i = bisect.bisect_right(starts, rva) - 1
    prev = img.funcs[i] if i >= 0 else None
    nxt = img.funcs[i + 1] if i + 1 < len(img.funcs) else None
    print("=" * 100)
    print(f"SITE {va:#x}  (rva {rva:#x})  section={img.section_of(rva)}")
    if prev:
        print(f"  prev pdata func {base+prev.begin:#x}..{base+prev.end:#x}  (gap after end = {rva - prev.end} bytes)")
    if nxt:
        print(f"  next pdata func {base+nxt.begin:#x}..{base+nxt.end:#x}  (gap before begin = {nxt.begin - rva} bytes)")
    # dump the whole gap region, plus tail of prev
    lo = prev.end if prev else rva - 0x60
    hi = nxt.begin if nxt else rva + 0x60
    print(f"  --- GAP REGION {base+lo:#x}..{base+hi:#x}  ({hi-lo} bytes) raw:")
    raw = img.read(lo, hi - lo)
    print("      " + raw.hex())
    print(f"  --- disasm from gap start {base+lo:#x}:")
    for ins in img.disasm(lo, hi - lo):
        mark = "  <<<< SITE" if ins.address == va else ""
        print(f"      {ins.address:#012x}  {ins.bytes.hex():<24} {ins.mnemonic:<8} {ins.op_str}{mark}")
    print(f"  --- disasm anchored AT the site (backwards 0x40 raw + forward):")
    for ins in img.disasm(rva, 0x60):
        print(f"      {ins.address:#012x}  {ins.bytes.hex():<24} {ins.mnemonic:<8} {ins.op_str}")
    print(f"  --- tail of prev func (last 0x60 bytes before its end):")
    if prev:
        s = max(prev.begin, prev.end - 0x60)
        for ins in img.disasm(s, prev.end - s):
            print(f"      {ins.address:#012x}  {ins.bytes.hex():<24} {ins.mnemonic:<8} {ins.op_str}")
