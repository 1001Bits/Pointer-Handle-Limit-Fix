"""Triage the outside-region 0x100000 / 0xFFFFF sites: is the containing function
handle-related at all?
"""
from __future__ import annotations

import json

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from image import open_runtime

BASE = 0x140000000
TABLE = 0x1EC47C0

SITES = [
    # cmp reg, 0x100000  (outside patch regions)
    0x140195113, 0x1402117EF, 0x140211B01, 0x140211B3B, 0x140211C11, 0x140211C60,
    0x1402899AF, 0x140314439, 0x140577166, 0x1405EC669, 0x140665B69, 0x14074B4C2,
    0x1408A8B37, 0x1409D492D, 0x1409E47F7, 0x140D54180, 0x140D868A6, 0x140D8FC15,
    0x140D8FEA2, 0x140D9018F,
    # and eax, 0x100000
    0x14018E13A,
    # and/test reg, 0xFFFFF (outside)
    0x140D8F65F, 0x140D8F8C3, 0x140DDD9CC, 0x140DDDD7B, 0x140DDDE52, 0x140DF926D,
]

img, _ = open_runtime("SE")
patch = json.load(open("../artifacts/patch_SE.json"))
REG = sorted(tuple(r) for r in patch["regions"])
KNOWN = {0x140131F60, 0x1401774E0, 0x140142550, 0x1401329D0, 0x1401328A0,
         0x1402130F0, 0x1401D59C0, 0x1405BCCB0, 0x140132A6D, 0x140213111}

for va in SITES:
    rva = va - BASE
    f = img.func_containing(rva)
    if f is None:
        print(f"{va:#x}: no pdata function")
        continue
    marks = set()
    calls = set()
    for ins in img.disasm(f.begin, f.end - f.begin):
        if ins.mnemonic == "call" and ins.operands and ins.operands[0].type == X86_OP_IMM:
            t = ins.operands[0].imm
            if t in KNOWN:
                calls.add(t)
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address - BASE + ins.size + op.mem.disp
                if TABLE <= t < TABLE + 0x1000000:
                    marks.add("TABLE_REF")
            v = None
            if op.type == X86_OP_IMM:
                v = op.imm & 0xFFFFFFFF
            elif op.type == X86_OP_MEM and op.mem.base != X86_REG_RIP:
                v = op.mem.disp & 0xFFFFFFFF
            if v == 0x03F00000:
                marks.add("AGE_MASK")
            elif v == 0x000FFFFF:
                marks.add("IDX_MASK")
            elif v == 0xFFFFF800:
                marks.add("OBJ_IDX")
        if ins.mnemonic in ("bt", "bts", "btr") and ins.operands[-1].type == X86_OP_IMM \
           and ins.operands[-1].imm == 0x1A:
            marks.add("BT26")
        if ins.mnemonic in ("shr", "shl") and len(ins.operands) == 2 \
           and ins.operands[1].type == X86_OP_IMM and ins.operands[1].imm == 0x0B:
            marks.add("SH11")
    inreg = any(b <= rva < e for b, e in REG)
    verdict = "HANDLE-RELATED" if (marks & {"TABLE_REF", "AGE_MASK", "BT26"}) else "unrelated"
    print(f"{va:#x}  func {BASE+f.begin:#x}  in_region={inreg}  marks={sorted(marks) or '-'}"
          f"  calls={[hex(c) for c in calls] or '-'}   => {verdict}")
