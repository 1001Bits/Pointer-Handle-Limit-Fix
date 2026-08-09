"""Hunt for handle encode/decode sites the .pdata-driven scan could have missed.

One pass over the int3-aware exhaustive sweep, collecting every class of
construct that could decode/encode a BSPointerHandle without using the literal
masks that the existing scan keys on.
"""
from __future__ import annotations

import json
from collections import defaultdict

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from image import open_runtime
from sweep import sweep

BASE = 0x140000000
TABLE = 0x1EC47C0
TABLE_END = TABLE + 0x100000 * 0x10
HEAD, TAIL, LOCK = 0x1EC47AC, 0x1EC47B0, 0x1EC47B8

LITS = {
    0x000FFFFF: "index_mask",
    0x03F00000: "age_mask",
    0x00100000: "age_inc/count",
    0x01000000: "table_bytes",
    0xFC0FFFFF: "clear_age",
    0xFFF00000: "clear_next",
    0xFBFFFFFF: "clear_inuse",
    0x04000000: "inuse_bit",
    0x03FFFFFF: "index|age",
    0x001FFFFF: "21b mask (already!)",
    0x000FFFFE: "index_mask-1",
    0x00200000: "1<<21",
    0x0FFFFF00: "index<<8",
}

patch = json.load(open("../artifacts/patch_SE.json"))
REGIONS = sorted(tuple(r) for r in patch["regions"])
PATCHED_RVA = {p["rva"] for p in patch["patches"]}
LEA_RVA = set(patch["lea_disp_rvas"])


def in_region(rva):
    for b, e in REGIONS:
        if b <= rva < e:
            return True
        if b > rva:
            break
    return False


img, _ = open_runtime("SE")

out = defaultdict(list)
prev = [None] * 8  # small rolling window of instructions

n = 0
for ins in sweep(img):
    n += 1
    rva = ins.address - BASE
    inr = in_region(rva)
    txt = f"{ins.address:#012x} {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}"

    # ---- 1. RIP-relative into the table or the control block ------------- #
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            tgt = rva + ins.size + op.mem.disp
            if TABLE <= tgt < TABLE_END:
                key = "table_base" if tgt == TABLE else "table_INTERIOR"
                out[key].append((rva, tgt, inr, txt))
            elif HEAD - 0x20 <= tgt <= LOCK + 0x8:
                out["ctl_block"].append((rva, tgt, inr, txt))

    # ---- 2. literals (immediate or displacement, incl. 64-bit) ----------- #
    for op in ins.operands:
        if op.type == X86_OP_IMM:
            v = op.imm
        elif op.type == X86_OP_MEM and op.mem.base != X86_REG_RIP and op.mem.disp:
            v = op.mem.disp
        else:
            continue
        v64 = v & 0xFFFFFFFFFFFFFFFF
        v32 = v & 0xFFFFFFFF
        if v32 in LITS and not inr:
            out["lit_outside:" + LITS[v32]].append((rva, v32, inr, txt))
        # 64-bit-register masks with the same semantic
        if v64 in (0x00000000000FFFFF, 0xFFFFFFFFFFF00000, 0x00000000FFFFFFFF & 0x3F00000):
            if not inr:
                out["lit64_outside"].append((rva, v64, inr, txt))

    # ---- 3. bit ops on the in-use bit ------------------------------------ #
    if ins.mnemonic in ("bt", "bts", "btr", "btc") and ins.operands and ins.operands[-1].type == X86_OP_IMM:
        b = ins.operands[-1].imm
        if b in (0x1A, 0x14, 0x1B) and not inr:
            out[f"bt{b:#x}_outside"].append((rva, b, inr, txt))

    # ---- 4. BMI / unusual field extraction ------------------------------- #
    if ins.mnemonic in ("bextr", "bzhi", "andn", "pext", "pdep", "shrx", "shlx", "sarx", "rorx"):
        out["bmi:" + ins.mnemonic].append((rva, 0, inr, txt))

    # ---- 5. shift-based masking ------------------------------------------ #
    if ins.mnemonic in ("shl", "shr", "sar", "sal") and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_IMM:
        amt = ins.operands[1].imm
        reg = ins.operands[0].reg
        # candidate 20/21-bit isolation amounts
        if amt in (0x0C, 0x2C, 0x14, 0x0B, 0x1A, 0x1B):
            p = prev[-1]
            if p is not None and p.mnemonic in ("shl", "shr", "sal", "sar") and len(p.operands) == 2 \
               and p.operands[1].type == X86_OP_IMM and p.operands[0].type == X86_OP_REG:
                if p.operands[1].imm == amt and p.operands[0].reg == reg:
                    out["shift_pair_%d" % amt].append(
                        (rva, amt, inr, f"{p.address:#012x} {p.mnemonic} {p.op_str}  ||  {txt}")
                    )
    prev.pop(0)
    prev.append(ins)

print(f"instructions swept: {n}\n")
for k in sorted(out):
    v = out[k]
    print(f"== {k}: {len(v)}")
with open("../artifacts/hunt_SE.json", "w") as fh:
    json.dump({k: v for k, v in out.items()}, fh, indent=1)
print("\nwrote ../artifacts/hunt_SE.json")
