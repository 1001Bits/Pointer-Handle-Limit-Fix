"""Single-pass byte-level scan for RIP-relative refs into the manager control block.

Finds every dword in .text that, interpreted as a disp32, lands anywhere in
[table - before, table + after).  Decoder-independent superset, then confirmed
by backward disassembly.  Used to locate the free-list head/tail globals
without assuming they sit at the SE offsets.
"""
from __future__ import annotations

import argparse
import struct
from collections import defaultdict

from capstone.x86 import X86_OP_MEM, X86_REG_RIP

from image import open_runtime


def confirm(img, disp_rva: int, window: int = 16):
    best = None
    for back in range(2, window):
        start = disp_rva - back
        try:
            ins_list = img.disasm(start, back + 12)
        except ValueError:
            continue
        if not ins_list:
            continue
        ins = ins_list[0]
        if ins.address - img.base != start:
            continue
        if not (start < disp_rva < start + ins.size):
            continue
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                if best is None:
                    best = ins
                # prefer the longest (REX-prefixed) decode
                elif ins.size > best.size:
                    best = ins
    return best


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", default="AE")
    ap.add_argument("--table", required=True)
    ap.add_argument("--before", type=lambda s: int(s, 0), default=0x80)
    ap.add_argument("--after", type=lambda s: int(s, 0), default=0x10)
    a = ap.parse_args()

    img, _ = open_runtime(a.runtime)
    table = int(a.table, 16)
    lo_t, hi_t = table - a.before, table + a.after

    hits = defaultdict(list)
    for lo, hi in img.text_ranges():
        data = img.read(lo, hi - lo)
        n = len(data)
        unpack = struct.unpack_from
        for p in range(0, n - 4):
            d = unpack("<i", data, p)[0]
            t = (lo + p) + 4 + d
            if lo_t <= t < hi_t:
                hits[t].append(lo + p)

    print(f"== {a.runtime}  ctl window [{img.base+lo_t:#x}, {img.base+hi_t:#x})  table={img.base+table:#x}")
    for t in sorted(hits):
        rel = t - table
        print(f"\n  target {img.base+t:#x}  (table{rel:+#x})  raw candidates={len(hits[t])}")
        good = 0
        for c in hits[t]:
            ins = confirm(img, c)
            if not ins:
                print(f"    UNCONFIRMED dword at {img.base+c:#x}")
                continue
            good += 1
            f = img.func_containing(ins.address - img.base)
            fs = f"{img.base + f.begin:#x}" if f else "NO-PDATA"
            print(f"    {ins.address:#x}  {ins.bytes.hex():<20} {ins.mnemonic:<6} {ins.op_str}   [func {fs}]")
        print(f"    -> confirmed {good}/{len(hits[t])}")


if __name__ == "__main__":
    main()
