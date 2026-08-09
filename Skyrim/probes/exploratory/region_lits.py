"""Enumerate EVERY immediate/displacement/shift inside the 103 patch regions.

Anything the rewrite map does not cover shows up here, so a constant that
needs shifting but was never classified cannot hide.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from image import open_runtime

BASE = 0x140000000
patch = json.load(open("../artifacts/patch_SE.json"))
REGIONS = sorted(tuple(r) for r in patch["regions"])
PATCHED = {p["rva"] for p in patch["patches"]}

REWRITTEN = {
    0x000FFFFF, 0x03F00000, 0x00100000, 0x01000000,
    0xFC0FFFFF, 0xFFF00000, 0xFBFFFFFF, 0x04000000,
}

img, _ = open_runtime("SE")

imm_hist = Counter()
imm_where = defaultdict(list)
shift_hist = Counter()
shift_where = defaultdict(list)
bit_hist = Counter()
bit_where = defaultdict(list)
mul_where = []

for b, e in REGIONS:
    for ins in img.disasm(b, e - b):
        rva = ins.address - BASE
        if rva >= e:
            break
        txt = f"{ins.address:#012x} {ins.mnemonic} {ins.op_str}"
        if ins.mnemonic in ("shl", "shr", "sar", "sal", "rol", "ror") and len(ins.operands) == 2 \
           and ins.operands[1].type == X86_OP_IMM:
            a = ins.operands[1].imm
            shift_hist[(ins.mnemonic, a)] += 1
            shift_where[(ins.mnemonic, a)].append(txt)
        if ins.mnemonic in ("bt", "bts", "btr", "btc") and ins.operands and ins.operands[-1].type == X86_OP_IMM:
            a = ins.operands[-1].imm
            bit_hist[(ins.mnemonic, a)] += 1
            bit_where[(ins.mnemonic, a)].append(txt)
        if ins.mnemonic in ("imul", "mul", "div", "idiv"):
            mul_where.append(txt)
        for op in ins.operands:
            if op.type == X86_OP_IMM:
                v = op.imm & 0xFFFFFFFFFFFFFFFF
            elif op.type == X86_OP_MEM and op.mem.base != X86_REG_RIP and op.mem.disp:
                v = op.mem.disp & 0xFFFFFFFFFFFFFFFF
            else:
                continue
            imm_hist[v] += 1
            if len(imm_where[v]) < 6:
                imm_where[v].append(txt)

print("=== immediates / displacements inside the patch regions, by value ===")
print("    (REWRITTEN = handled by the patch map)")
for v, n in sorted(imm_hist.items()):
    tag = "REWRITTEN" if (v & 0xFFFFFFFF) in REWRITTEN else ""
    # highlight anything that looks like it encodes the 20-bit split
    sus = ""
    v32 = v & 0xFFFFFFFF
    if not tag:
        if 0x00080000 <= v32 <= 0x08000000:
            sus = "  <-- INSPECT (in the index/age numeric range)"
        elif v32 in (0x3F, 0x3E, 0x40, 0x14, 0x15, 0x1F, 0x1FFFFF, 0x7FFFF):
            sus = "  <-- INSPECT"
        elif 0xF0000000 <= v32 <= 0xFFFFFFFF and v32 not in (0xFFFFFFFF,):
            sus = "  <-- INSPECT (high mask)"
    print(f"  {v:#018x}  n={n:<5} {tag}{sus}")
    if sus:
        for t in imm_where[v]:
            print(f"        {t}")

print("\n=== shifts inside the patch regions ===")
for (m, a), n in sorted(shift_hist.items()):
    flag = ""
    if a in (0x14, 0x15, 0x0C, 0x2C, 0x1A, 0x1B, 0x06):
        flag = "  <-- INSPECT"
    print(f"  {m} ,{a:#x}  n={n}{flag}")
    if flag:
        for t in shift_where[(m, a)][:12]:
            print(f"        {t}")

print("\n=== bit ops inside the patch regions ===")
for (m, a), n in sorted(bit_hist.items()):
    print(f"  {m} ,{a:#x}  n={n}")

print(f"\n=== mul/div inside the patch regions: {len(mul_where)}")
for t in mul_where[:20]:
    print(f"   {t}")
