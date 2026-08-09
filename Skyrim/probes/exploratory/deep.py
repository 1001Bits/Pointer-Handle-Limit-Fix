"""Exhaustive linear sweep of ALL executable bytes (pdata functions + pdata gaps
+ every executable section), scoring each code blob for handle-encoding
indicators, including alternative encodings the literal-mask scan cannot see.
"""
from __future__ import annotations
import json, struct, sys
from collections import defaultdict

import numpy as np
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP, X86_REG_RSP, X86_REG_RBP

from image import open_runtime

TABLE = 0x1EC47C0
TABLE_END = TABLE + 0x1000000
CTL = {0x1EC47AC: "head", 0x1EC47B0: "tail", 0x1EC47B8: "lock"}

# literals that would need a rewrite (or that mark handle code)
MASK_LITS = {
    0x000FFFFF: "idx20",
    0x03F00000: "age",
    0xFC0FFFFF: "~age",
    0xFFF00000: "~idx20",
    0xFBFFFFFF: "~inuse26",
    0x04000000: "inuse26",
    0x00100000: "1<<20",
    0x01000000: "16MB",
    0x03FFFFFF: "idx|age",
    0x7FFFF800: "obj idx20 @11",   # would be a MISSED narrowing mask
    0xFFFFF800: "obj idx21 @11",
    0x000FFFFE: "idx20-ish",
    0x001FFFFF: "idx21 (already?)",
    0x0000003F: "age6",
    0x000003FF: "rc",
    0x00000400: "hvalid",
    0x000007FF: "rc|valid",
    0xFFFFFC00: "~rc|valid?",
}
SHIFTS = {0x04, 0x0B, 0x0C, 0x14, 0x15, 0x1A, 0x1B, 0x2B, 0x2C, 0x05}
BTBITS = set(range(0x14, 0x1C))


def blobs(img):
    """(kind, begin, end) covering every executable byte exactly once."""
    out = []
    for lo, hi in img.text_ranges():
        cur = lo
        for f in img.funcs:
            if f.end <= lo or f.begin >= hi:
                continue
            b, e = max(f.begin, lo), min(f.end, hi)
            if b > cur:
                out.append(("gap", cur, b))
            out.append(("pdata", b, e))
            cur = max(cur, e)
        if cur < hi:
            out.append(("gap", cur, hi))
    return out


def sweep(img):
    """Disassemble every blob; for gaps, resync after int3 runs."""
    md = img.md
    recs = []          # (blob_key, rva, kind_tag, detail)
    for kind, b, e in blobs(img):
        if e - b <= 0:
            continue
        data = img.read(b, e - b)
        if kind == "pdata":
            segs = [(b, data)]
        else:
            # split on runs of >=1 int3 / 00 padding, disassemble each chunk
            segs = []
            i = 0
            n = len(data)
            while i < n:
                while i < n and data[i] in (0xCC,):
                    i += 1
                j = i
                while j < n and data[j] != 0xCC:
                    j += 1
                if j > i:
                    segs.append((b + i, data[i:j]))
                i = j
        for sb, sd in segs:
            for ins in md.disasm(sd, img.base + sb):
                rva = ins.address - img.base
                tags = []
                for op in ins.operands:
                    if op.type == X86_OP_IMM:
                        v = op.imm & 0xFFFFFFFF
                        if v in MASK_LITS:
                            tags.append(("LIT", v))
                    elif op.type == X86_OP_MEM:
                        if op.mem.base == X86_REG_RIP:
                            t = rva + ins.size + op.mem.disp
                            if TABLE <= t < TABLE_END:
                                tags.append(("TBL", t - TABLE))
                            elif t in CTL:
                                tags.append(("CTL", t))
                        else:
                            d = op.mem.disp & 0xFFFFFFFF
                            if d in MASK_LITS and op.mem.base not in (X86_REG_RSP, X86_REG_RBP):
                                tags.append(("DISP", d))
                if ins.mnemonic in ("shr", "shl", "sal", "sar") and ins.operands and \
                        ins.operands[-1].type == X86_OP_IMM and ins.operands[-1].imm in SHIFTS:
                    tags.append(("SH", ins.operands[-1].imm))
                if ins.mnemonic in ("bt", "bts", "btr", "btc") and ins.operands and \
                        ins.operands[-1].type == X86_OP_IMM and ins.operands[-1].imm in BTBITS:
                    tags.append(("BT", ins.operands[-1].imm))
                if ins.mnemonic in ("bextr", "bzhi", "pext", "pdep", "andn"):
                    tags.append(("BMI", 0))
                for t in tags:
                    recs.append(((kind, sb), rva, t, f"{ins.mnemonic} {ins.op_str}"))
    return recs


def main():
    img, _ = open_runtime("SE")
    regions = sorted(tuple(r) for r in json.load(open("../artifacts/patch_SE.json"))["regions"])

    def inreg(r):
        return any(b <= r < e for b, e in regions)

    recs = sweep(img)
    print(f"total tagged instructions: {len(recs)}")

    # ---- global counts by tag
    c = defaultdict(int)
    for _, _, t, _ in recs:
        c[t] += 1
    print("\n== global tag counts ==")
    for k in sorted(c, key=lambda x: -c[x]):
        kind, v = k
        print(f"  {kind:<5} {v if isinstance(v,int) else v:#x}  {c[k]}")

    # ---- BMI / exotic
    bmi = [(r, s) for _, r, t, s in recs if t[0] == "BMI"]
    print(f"\n== BMI-family instructions (bextr/bzhi/pext/pdep/andn): {len(bmi)}")
    for r, s in bmi[:40]:
        print(f"   {img.base+r:#x} {s}  inreg={inreg(r)}")

    # ---- everything OUTSIDE the patch regions, grouped by blob, scored
    print("\n== blobs OUTSIDE patch regions, with handle-suspicious tag mixes ==")
    byblob = defaultdict(list)
    for bk, r, t, s in recs:
        if not inreg(r):
            byblob[bk].append((r, t, s))
    sus = []
    for bk, items in byblob.items():
        tags = {t for _, t, _ in items}
        lits = {v for k, v in tags if k == "LIT"} | {v for k, v in tags if k == "DISP"}
        shs = {v for k, v in tags if k == "SH"}
        bts = {v for k, v in tags if k == "BT"}
        tbl = any(k == "TBL" for k, _ in tags)
        ctl = any(k == "CTL" for k, _ in tags)
        score = 0
        why = []
        if tbl:
            score += 10; why.append("TABLE-REF")
        if ctl:
            score += 6; why.append("CTL-REF")
        if 0x03F00000 in lits or 0xFC0FFFFF in lits:
            score += 6; why.append("age-mask")
        if 0x7FFFF800 in lits:
            score += 8; why.append("obj-idx20-mask")
        if 0x001FFFFF in lits:
            score += 4; why.append("idx21-lit")
        if 0x000FFFFF in lits:
            score += 3; why.append("idx20-mask")
        if 0xFFF00000 in lits:
            score += 3; why.append("~idx20")
        if 0x0B in shs:
            score += 3; why.append("shr/shl 11")
        if 0x1A in bts:
            score += 2; why.append("bt26")
        if 0x04000000 in lits or 0xFBFFFFFF in lits:
            score += 1; why.append("inuse26-lit")
        if 0x0C in shs or 0x2C in shs:
            score += 1; why.append("shift12/44")
        if 0x14 in shs:
            score += 1; why.append("shift20")
        if 0x00100000 in lits:
            score += 1; why.append("1<<20")
        if 0xFFFFF800 in lits:
            score += 1; why.append("objidx21")
        if score >= 4:
            sus.append((score, bk, why, items))
    sus.sort(key=lambda x: -x[0])
    print(f"  suspicious blobs: {len(sus)}")
    for score, bk, why, items in sus:
        kind, sb = bk
        f = img.func_containing(sb)
        print(f"\n  --- score={score} blob {kind}@{img.base+sb:#x} "
              f"{'pdata %#x' % (img.base+f.begin) if f else 'NO-PDATA'}  {why}")
        for r, t, s in sorted(items)[:30]:
            print(f"      {img.base+r:#x}  {t[0]}:{t[1]:#x}  {s}")


if __name__ == "__main__":
    main()
