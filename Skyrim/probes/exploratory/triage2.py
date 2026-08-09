"""Triage every outside-region in-use-bit construct: bt/bts/btr ,0x1a and
`test/and/or MEM, 0x4000000` -- either could be an entry-word touch.
"""
from __future__ import annotations

import bisect
import json

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from image import open_runtime
from sweep import sweep

BASE = 0x140000000
TABLE = 0x1EC47C0
patch = json.load(open("../artifacts/patch_SE.json"))
REG = sorted(tuple(r) for r in patch["regions"])
starts = [b for b, _ in REG]


def in_region(rva):
    i = bisect.bisect_right(starts, rva) - 1
    return i >= 0 and REG[i][0] <= rva < REG[i][1]


img, _ = open_runtime("SE")

cand = []
for ins in sweep(img):
    rva = ins.address - BASE
    if in_region(rva):
        continue
    ops = ins.operands
    if ins.mnemonic in ("bt", "bts", "btr", "btc") and ops and ops[-1].type == X86_OP_IMM \
       and ops[-1].imm == 0x1A:
        cand.append((rva, "bt26", f"{ins.address:#012x} {ins.mnemonic} {ins.op_str}"))
    for op in ops:
        if op.type == X86_OP_IMM and (op.imm & 0xFFFFFFFF) == 0x04000000:
            kind = "inuse_MEM" if ops[0].type == X86_OP_MEM else "inuse_REG"
            cand.append((rva, kind, f"{ins.address:#012x} {ins.mnemonic} {ins.op_str}"))
            break

print(f"outside-region in-use-bit candidates: {len(cand)}\n")

# for each, does the containing function look handle-related?
cache = {}


def func_marks(fb, fe):
    key = (fb, fe)
    if key in cache:
        return cache[key]
    marks = set()
    for ins in img.disasm(fb, fe - fb):
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address - BASE + ins.size + op.mem.disp
                if TABLE <= t < TABLE + 0x1000000:
                    marks.add("TABLE_REF")
            v = op.imm & 0xFFFFFFFF if op.type == X86_OP_IMM else None
            if v == 0x03F00000:
                marks.add("AGE_MASK")
            elif v == 0x000FFFFF:
                marks.add("IDX_MASK")
            elif v == 0xFFF00000:
                marks.add("CLEAR_NEXT")
            elif v == 0xFBFFFFFF:
                marks.add("CLEAR_INUSE")
    cache[key] = marks
    return marks


byk = {}
for rva, kind, txt in cand:
    f = img.func_containing(rva)
    if f is None:
        fb, fe = rva - 0x40, rva + 0x40
        tag = "no-pdata"
    else:
        fb, fe = f.begin, f.end
        tag = f"func {BASE+fb:#x}"
    m = func_marks(fb, fe)
    hot = bool(m & {"TABLE_REF", "AGE_MASK", "CLEAR_NEXT", "CLEAR_INUSE"})
    print(f"  [{kind:<9}] {txt:<52} {tag:<20} marks={sorted(m) or '-'}"
          + ("   <<<<< HANDLE-RELATED" if hot else ""))
