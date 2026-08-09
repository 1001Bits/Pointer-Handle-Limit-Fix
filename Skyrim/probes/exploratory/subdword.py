"""Byte/word-sized accesses to the UPPER bytes of a _refCount word.

A dword at [X+8] / [X+0x28] can also be reached as
  byte  [X+0x09] .. [X+0x0b]   /  [X+0x29] .. [X+0x2b]   (bits 8-31)
  word  [X+0x0a]               /  [X+0x2a]               (bits 16-31)
Those never match a disp of 8 / 0x28, so a dword-only scan misses them.
Byte [X+0x2b] / word [X+0x2a] is exactly where bit 31 lives.
"""
from __future__ import annotations

import json
import sys
from collections import Counter

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from image import open_runtime

DISPS = {0x09: "b8-15", 0x0A: "b16-23/16-31", 0x0B: "b24-31",
         0x29: "b8-15", 0x2A: "b16-23/16-31", 0x2B: "b24-31"}


def main():
    runtime = sys.argv[1] if len(sys.argv) > 1 else "SE"
    img, _ = open_runtime(runtime)
    md = img.md
    text = img.text_ranges()

    def in_text(rva):
        return any(lo <= rva < hi for lo, hi in text)

    hits = []
    for f in img.funcs:
        if not in_text(f.begin):
            continue
        try:
            code = img.read(f.begin, f.end - f.begin)
        except ValueError:
            continue
        for x in md.disasm(code, img.base + f.begin):
            for o in x.operands:
                if (o.type == X86_OP_MEM and o.mem.base not in (0, X86_REG_RIP)
                        and o.mem.index == 0 and o.mem.disp in DISPS and o.size in (1, 2)):
                    hits.append([x.address, f.begin + img.base, o.mem.disp, o.size,
                                 f"{x.mnemonic} {x.op_str}"])
                    break

    print(f"{runtime}: sub-dword accesses at refcount-upper-byte displacements = {len(hits)}")
    c = Counter((h[2], h[3]) for h in hits)
    for (d, s), n in sorted(c.items()):
        print(f"   disp {d:#04x} size {s}  -> {DISPS[d]:<12} {n}")
    # only 0x2a/0x2b/0x0a/0x0b can touch bit 31
    hot = [h for h in hits if h[2] in (0x0A, 0x0B, 0x2A, 0x2B)]
    print(f"\n  touching bits 16-31 ({len(hot)}):")
    for h in hot[:400]:
        print(f"   {h[0]:#012x}  func {h[1]:#x}  disp={h[2]:#x} size={h[3]}  {h[4]}")
    json.dump(hits, open(f"../artifacts/subdword_{runtime}.json", "w"))


if __name__ == "__main__":
    main()
