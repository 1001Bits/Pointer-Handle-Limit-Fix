"""Fast byte-level scan for direct call/jmp sites targeting a given RVA.

E8 rel32 (call) / E9 rel32 (jmp): disp = target - (rva_of_disp + 4).
Scanning .text for that dword and requiring the preceding byte to be E8/E9
finds every direct near call/jmp to the target with no full disassembly.
"""

from __future__ import annotations

import argparse
import struct

from image import open_runtime


def find(img, target_rva: int):
    out = []
    for lo, hi in img.text_ranges():
        data = img.read(lo, hi - lo)
        for p in range(1, len(data) - 4):
            d = struct.unpack_from("<i", data, p)[0]
            if (lo + p) + 4 + d == target_rva and data[p - 1] in (0xE8, 0xE9):
                out.append((lo + p - 1, "call" if data[p - 1] == 0xE8 else "jmp"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", default="SE")
    ap.add_argument("targets", nargs="+")
    a = ap.parse_args()
    img, _ = open_runtime(a.runtime)
    for t in a.targets:
        v = int(t, 16)
        rva = v - img.base if v >= img.base else v
        hits = find(img, rva)
        print(f"== target va {img.base+rva:#x} (rva {rva:#x}): {len(hits)} direct sites")
        for site, kind in hits:
            f = img.func_containing(site)
            fs = f"func {img.base + f.begin:#x}" if f else "NO PDATA"
            print(f"   {kind:<4} at {img.base+site:#x}   [{fs}]")


if __name__ == "__main__":
    main()
