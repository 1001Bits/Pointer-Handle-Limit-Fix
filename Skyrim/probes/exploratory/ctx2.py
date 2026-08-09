"""Dump context around specific candidate addresses."""
from __future__ import annotations

import sys

from image import open_runtime

img, _ = open_runtime("SE")
BASE = img.base

for arg in sys.argv[1:]:
    if ":" in arg:
        a, span = arg.split(":")
        back, fwd = (int(x, 0) for x in span.split(","))
    else:
        a, back, fwd = arg, 0x30, 0x60
    va = int(a, 16)
    rva = va - BASE
    f = img.func_containing(rva)
    print("=" * 96)
    print(f"{va:#x}  section={img.section_of(rva)}  pdata="
          + (f"{BASE+f.begin:#x}..{BASE+f.end:#x}" if f else "NONE"))
    start = f.begin if f else rva - back
    end = f.end if f else rva + fwd
    if f and (f.end - f.begin) > 0x400:
        start, end = max(f.begin, rva - back), min(f.end, rva + fwd)
    print(f"  raw at site: {img.read(rva - 0x10, 0x30).hex()}")
    for ins in img.disasm(start, end - start):
        m = "  <<<<" if ins.address == va else ""
        print(f"  {ins.address:#012x}  {ins.bytes.hex():<24} {ins.mnemonic:<9} {ins.op_str}{m}")
