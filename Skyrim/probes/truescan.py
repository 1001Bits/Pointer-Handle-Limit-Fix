"""Decoder-independent scan for RIP-relative refs into a window, grouped by TRUE target.

find_riprefs.py / ae_ctl.py group candidates by `disp_pos + 4 + disp`, which is
only the real RIP target when the disp32 is the LAST field of the instruction.
For forms with a trailing immediate (`mov dword ptr [rip+d], imm32` = C7 05 ..,
`cmp dword ptr [rip+d], imm8` = 83 3D ..) the true target is 1/2/4 bytes higher.

This version widens the candidate window by 4 bytes, then re-derives the target
from capstone's decode, so every reported target is exact.  Superset in, exact
grouping out -- suitable for proving completeness.
"""
from __future__ import annotations

import argparse
import struct
from collections import defaultdict

from capstone.x86 import X86_OP_MEM, X86_REG_RIP

from image import open_runtime


def decode_at(img, start: int, span: int):
    try:
        ins_list = img.disasm(start, span)
    except ValueError:
        return None
    if not ins_list:
        return None
    ins = ins_list[0]
    return ins if ins.address - img.base == start else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", default="AE")
    ap.add_argument("--table", required=True)
    ap.add_argument("--before", type=lambda s: int(s, 0), default=0x40)
    ap.add_argument("--after", type=lambda s: int(s, 0), default=0x20)
    a = ap.parse_args()

    img, _ = open_runtime(a.runtime)
    table = int(a.table, 16)
    lo_t, hi_t = table - a.before, table + a.after

    cand: list[int] = []
    for lo, hi in img.text_ranges():
        data = img.read(lo, hi - lo)
        n = len(data)
        unpack = struct.unpack_from
        # widen by 4 so trailing-immediate forms are still caught
        wl, wh = lo_t - 4, hi_t + 4
        for p in range(0, n - 4):
            t = (lo + p) + 4 + unpack("<i", data, p)[0]
            if wl <= t < wh:
                cand.append(lo + p)

    print(f"== {a.runtime}  window [{img.base+lo_t:#x}, {img.base+hi_t:#x})  table={img.base+table:#x}")
    print(f"   raw dword candidates (widened): {len(cand)}")

    exact = defaultdict(list)
    rejected = []
    for c in cand:
        hit = None
        for back in range(2, 16):
            start = c - back
            ins = decode_at(img, start, back + 16)
            if ins is None or not (start < c < start + ins.size):
                continue
            tgts = img.rip_targets(ins)
            for t in tgts:
                if lo_t <= t < hi_t:
                    # prefer longest decode covering this disp
                    if hit is None or ins.size > hit[0].size:
                        hit = (ins, t)
        if hit:
            exact[hit[1]].append(hit[0])
        else:
            rejected.append(c)

    for t in sorted(exact):
        rel = t - table
        lbl = "TABLE_BASE" if rel == 0 else f"table{rel:+#x}"
        print(f"\n  >>> {img.base+t:#x}  ({lbl})   refs={len(exact[t])}")
        fset = set()
        for ins in sorted(exact[t], key=lambda i: i.address):
            f = img.func_containing(ins.address - img.base)
            fset.add(f.begin if f else -1)
            fs = f"{img.base+f.begin:#x}" if f else "NO-PDATA"
            print(f"    {ins.address:#x}  {ins.bytes.hex():<22} {ins.mnemonic:<6} {ins.op_str}   [func {fs}]")
        print(f"      distinct funcs={len(fset - {-1})}  no-pdata refs={sum(1 for i in exact[t] if img.func_containing(i.address-img.base) is None)}")

    print(f"\n  candidates with no decodable RIP instruction into window: {len(rejected)}")
    for c in rejected:
        print(f"    {img.base+c:#x} section={img.section_of(c)}")


if __name__ == "__main__":
    main()
