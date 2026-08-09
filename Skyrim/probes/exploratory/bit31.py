"""(a) Any instruction touching bit 31 of a dword at [X+8] / [X+0x28].
   (b) Full audit of every [X+8]/[X+0x28] dword access inside the functions
       that reference the handle entry table.
"""
from __future__ import annotations

import json
import re
import sys

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from image import open_runtime


def is_rc_mem(op):
    return (op.type == X86_OP_MEM and op.mem.base not in (0, X86_REG_RIP)
            and op.mem.index == 0 and op.mem.disp in (0x08, 0x28) and op.size == 4)


def main():
    runtime = sys.argv[1] if len(sys.argv) > 1 else "SE"
    img, _ = open_runtime(runtime)
    md = img.md
    text = img.text_ranges()

    # functions that reference the entry table
    hf = set()
    txt = open(f"../artifacts/riprefs_table_{runtime}.txt").read()
    for m in re.finditer(r"\[func (0x[0-9a-f]+)\]", txt):
        hf.add(int(m.group(1), 16) - img.base)

    def in_text(rva):
        return any(lo <= rva < hi for lo, hi in text)

    bit31 = []
    audit = {}
    for f in img.funcs:
        if not in_text(f.begin):
            continue
        try:
            code = img.read(f.begin, f.end - f.begin)
        except ValueError:
            continue
        rows = []
        for x in md.disasm(code, img.base + f.begin):
            ops = x.operands
            if not any(is_rc_mem(o) for o in ops):
                continue
            mn = x.mnemonic.replace("lock ", "")
            imm = next((o.imm & 0xFFFFFFFF for o in ops if o.type == X86_OP_IMM), None)
            if (mn in ("bt", "bts", "btr", "btc") and imm == 0x1F) or \
               (imm is not None and (imm & 0x80000000) and imm not in (0xFFFFFFFF,)):
                bit31.append((x.address, f.begin + img.base, f"{x.mnemonic} {x.op_str}"))
            if f.begin in hf:
                rows.append((x.address, f"{x.mnemonic} {x.op_str}"))
        if rows:
            audit[f"{f.begin + img.base:#x}"] = rows

    print(f"{runtime}: bit-31 / high-bit immediates on [X+8]/[X+0x28] = {len(bit31)}")
    for a, fv, s in bit31:
        print(f"   {a:#012x}  func {fv:#x}   {s}")
    print(f"\nhandle-table functions with [X+8]/[X+0x28] accesses: {len(audit)} "
          f"(of {len(hf)} table-referencing funcs)")
    for k, rows in sorted(audit.items(), key=lambda kv: int(kv[0], 16)):
        print(f"  == func {k}")
        for a, s in rows:
            print(f"       {a:#012x}  {s}")
    json.dump({"bit31": bit31, "audit": audit}, open(f"../artifacts/bit31_{runtime}.json", "w"))


if __name__ == "__main__":
    main()
