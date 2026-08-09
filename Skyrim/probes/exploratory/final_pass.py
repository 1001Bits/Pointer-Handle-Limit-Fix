"""Final targeted pass: capacity checks, 20-bit object-field assumptions, handle
construction, and aligned absolute pointers.
"""
from __future__ import annotations

import json
from collections import defaultdict

import numpy as np
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from image import open_runtime
from sweep import sweep

BASE = 0x140000000
TABLE = 0x1EC47C0
N = 0x100000
TABLE_END = TABLE + N * 0x10

patch = json.load(open("../artifacts/patch_SE.json"))
REG = sorted(tuple(r) for r in patch["regions"])
starts = [b for b, _ in REG]
import bisect


def in_region(rva):
    i = bisect.bisect_right(starts, rva) - 1
    return i >= 0 and REG[i][0] <= rva < REG[i][1]


img, _ = open_runtime("SE")

# --------------------------------------------------------------------------- #
print("=== 0. decode the 8 disp32-to-table_end candidates ===")
for va in (0x1401EF382, 0x1401EF40F, 0x141372B9B, 0x141372BB3,
           0x14148BE2C, 0x14148BE3F, 0x14148BE4B, 0x14148BE6D):
    rva = va - BASE
    got = None
    for back in range(2, 10):
        for ins in img.disasm(rva - back, back + 12)[:1]:
            for t in img.rip_targets(ins):
                if t == TABLE_END and ins.size >= back + 4:
                    got = ins
        if got:
            break
    if got:
        print(f"  {va:#x}: REAL  {got.address:#012x} {got.mnemonic} {got.op_str}  "
              f"[func {BASE+img.func_containing(got.address-BASE).begin:#x}]"
              if img.func_containing(got.address - BASE) else
              f"  {va:#x}: REAL  {got.address:#012x} {got.mnemonic} {got.op_str} [no pdata]")
    else:
        print(f"  {va:#x}: no aligned rip-relative instruction decodes to table_end")

# --------------------------------------------------------------------------- #
print("\n=== 1. aligned absolute pointers to the manager block (all sections) ===")
WANT = {BASE + TABLE: "table base", BASE + TABLE_END: "table end",
        BASE + 0x1EC47AC: "head", BASE + 0x1EC47B0: "tail", BASE + 0x1EC47B8: "lock"}
found = 0
for name, va, vsz, praw, rsz in img._sections:
    if rsz < 8:
        continue
    d = img.read(va, rsz)
    pad = (-va) % 8
    arr = np.frombuffer(d[pad: pad + ((len(d) - pad) // 8) * 8], dtype="<u8")
    for w, lbl in WANT.items():
        for p in np.flatnonzero(arr == np.uint64(w)):
            print(f"  {name} rva {va+pad+int(p)*8:#x} = {w:#x}  [{lbl}]")
            found += 1
print(f"  aligned absolute pointers found: {found}")

# --------------------------------------------------------------------------- #
print("\n=== 2. sweep: capacity/limit checks and 20-bit object-field assumptions ===")
OBJ20 = {0x7FFFF800, 0x0007FFFF, 0x000FFFFF}
buckets = defaultdict(list)
prev = None
for ins in sweep(img):
    rva = ins.address - BASE
    inr = in_region(rva)
    txt = f"{ins.address:#012x} {ins.bytes.hex():<18} {ins.mnemonic} {ins.op_str}"
    ops = ins.operands
    for op in ops:
        v = None
        if op.type == X86_OP_IMM:
            v = op.imm & 0xFFFFFFFF
        elif op.type == X86_OP_MEM and op.mem.base != X86_REG_RIP and op.mem.disp:
            v = op.mem.disp & 0xFFFFFFFF
        if v is None:
            continue
        if v == 0x00100000 and ins.mnemonic in ("cmp", "sub", "test", "and", "add", "lea", "mov"):
            buckets[("cap_0x100000", ins.mnemonic, inr)].append(txt)
        if v == 0x7FFFF800:
            buckets[("obj_index_20bit_mask", ins.mnemonic, inr)].append(txt)
        if v == 0x000FFFFF and ins.mnemonic in ("cmp",):
            buckets[("cmp_index_mask", ins.mnemonic, inr)].append(txt)
    # shr reg,0xb immediately followed by a compare/mask that assumes 20 bits
    if prev is not None and prev.mnemonic in ("shr", "sar") and len(prev.operands) == 2 \
       and prev.operands[1].type == X86_OP_IMM and prev.operands[1].imm == 0x0B:
        if ins.mnemonic in ("cmp", "and", "test") and ops and ops[-1].type == X86_OP_IMM:
            v = ops[-1].imm & 0xFFFFFFFF
            if v in (0x000FFFFF, 0x00100000, 0x0007FFFF, 0x00080000):
                buckets[("shr11_then_20bit", ins.mnemonic, inr)].append(
                    f"{prev.address:#012x} {prev.mnemonic} {prev.op_str}  ||  {txt}")
    prev = ins

for k in sorted(buckets, key=lambda t: (t[0], t[2], t[1])):
    v = buckets[k]
    print(f"  {k[0]:<24} {k[1]:<6} in_region={k[2]}  n={len(v)}")
    if k[0] != "cap_0x100000" or not k[2]:
        for t in v[:20]:
            print(f"      {t}")
        if len(v) > 20:
            print(f"      ... +{len(v)-20} more")
