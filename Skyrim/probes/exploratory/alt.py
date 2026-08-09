"""Alternative-encoding decoder hunt + table-interior reference scan."""
from __future__ import annotations
import json, struct, sys
from collections import defaultdict

import numpy as np
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP, X86_OP_REG

from image import open_runtime
from deep import blobs

TABLE = 0x1EC47C0
TABLE_END = TABLE + 0x1000000


def linear(img):
    """Yield every decoded instruction over all executable bytes (pdata + gaps)."""
    md = img.md
    for kind, b, e in blobs(img):
        if e <= b:
            continue
        data = img.read(b, e - b)
        if kind == "pdata":
            segs = [(b, data)]
        else:
            segs = []
            i, n = 0, len(data)
            while i < n:
                while i < n and data[i] == 0xCC:
                    i += 1
                j = i
                while j < n and data[j] != 0xCC:
                    j += 1
                if j > i:
                    segs.append((b + i, data[i:j]))
                i = j
        for sb, sd in segs:
            for ins in md.disasm(sd, img.base + sb):
                yield kind, sb, ins


def interior_refs(img):
    """Decoder-independent superset scan for RIP disp32 landing in [TABLE, TABLE_END).

    Prefilter: the byte before the disp32 must be a ModRM with mod=00, r/m=101.
    """
    print("=== decoder-independent scan: RIP disp32 into table INTERIOR ===")
    hits = []
    for name, va, vsz, praw, rsz in img._sections:
        if not rsz:
            continue
        data = np.frombuffer(img.data[praw:praw + rsz], dtype=np.uint8)
        if data.size < 8:
            continue
        w = np.lib.stride_tricks.sliding_window_view(data, 4).astype(np.int64)
        vals = (w[:, 0] | (w[:, 1] << 8) | (w[:, 2] << 16) | (w[:, 3] << 24)).astype(np.uint32)
        vals = vals.astype(np.int64)
        vals = np.where(vals >= 2**31, vals - 2**32, vals)
        pos = np.arange(vals.size, dtype=np.int64)
        tgt = va + pos + 4 + vals
        m = (tgt >= TABLE) & (tgt < TABLE_END)
        idx = np.flatnonzero(m)
        # ModRM prefilter
        idx = idx[idx >= 1]
        modrm = data[idx - 1]
        idx = idx[(modrm & 0xC7) == 0x05]
        for p in idx:
            hits.append((name, va + int(p), int(tgt[p])))
    print(f"  raw dwords with ModRM prefilter: {len(hits)}")
    from missed import confirm_insn
    conf = []
    for s, r, t in hits:
        ins = confirm_insn(img, r)
        if ins is None:
            continue
        ok = False
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                if (ins.address - img.base) + ins.size + op.mem.disp == t:
                    ok = True
        if ok:
            conf.append((s, r, t, ins))
    print(f"  confirmed as real RIP-relative instructions: {len(conf)}")
    for s, r, t, ins in conf:
        f = img.func_containing(ins.address - img.base)
        fs = f"pdata {img.base+f.begin:#x}" if f else "NO-PDATA"
        print(f"    [{s}] {ins.address:#x} -> table+{t-TABLE:#x}  {ins.mnemonic} {ins.op_str}  [{fs}]")
    return conf


def adjacency(img, regions):
    """Alternative bitfield extraction idioms, image-wide."""
    def inreg(r):
        return any(b <= r < e for b, e in regions)

    win = []
    found = defaultdict(list)
    for kind, sb, ins in linear(img):
        win.append(ins)
        if len(win) > 8:
            win.pop(0)
        rva = ins.address - img.base

        def imm(i):
            return i.operands[-1].imm if i.operands and i.operands[-1].type == X86_OP_IMM else None

        def reg0(i):
            return i.operands[0].reg if i.operands and i.operands[0].type == X86_OP_REG else None

        # A) shl X,n ; shr X,n  (mask low 32-n bits) for n in {12, 44, 11, 5}
        if ins.mnemonic in ("shr", "sar") and imm(ins) in (0x0C, 0x2C, 0x0B, 0x05, 0x0A):
            n = imm(ins)
            r0 = reg0(ins)
            for prev in win[:-1]:
                if prev.mnemonic in ("shl", "sal") and imm(prev) == n and reg0(prev) == r0:
                    found[f"shl/shr {n:#x} mask"].append((rva, prev, ins))
        # B) shr X,0x14 ; and X,0x3f  (age extract without the age mask literal)
        if ins.mnemonic == "and" and imm(ins) == 0x3F:
            r0 = reg0(ins)
            for prev in win[:-1]:
                if prev.mnemonic in ("shr", "sar") and imm(prev) in (0x14, 0x13, 0x15) and reg0(prev) == r0:
                    found[f"shr {imm(prev):#x} + and 0x3f (age)"].append((rva, prev, ins))
        # C) and X,0x3f ; shl X,0x14  (age insert)
        if ins.mnemonic in ("shl", "sal") and imm(ins) == 0x14:
            r0 = reg0(ins)
            for prev in win[:-1]:
                if prev.mnemonic == "and" and imm(prev) == 0x3F and reg0(prev) == r0:
                    found["and 0x3f + shl 0x14 (age insert)"].append((rva, prev, ins))
        # D) shr X,0x1a ; and X,1  (in-use test without bt)
        if ins.mnemonic == "and" and imm(ins) == 1:
            r0 = reg0(ins)
            for prev in win[:-1]:
                if prev.mnemonic in ("shr", "sar") and imm(prev) == 0x1A:
                    found["shr 0x1a + and 1 (inuse)"].append((rva, prev, ins))
        # E) movzx from a 16-bit read followed by shl 4 (partial index read)
        if ins.mnemonic in ("shl", "sal") and imm(ins) == 4:
            for prev in win[:-1]:
                if prev.mnemonic == "movzx" and "word ptr" in prev.op_str:
                    found["movzx word + shl 4"].append((rva, prev, ins))

    print("\n=== alternative bitfield idioms (image-wide linear sweep) ===")
    for k, v in sorted(found.items()):
        out = [x for x in v if not inreg(x[0])]
        print(f"  {k}: {len(v)} total, {len(out)} outside patch regions")
        for rva, a, b in out[:60]:
            f = img.func_containing(rva)
            fs = f"pdata {img.base+f.begin:#x}" if f else "NO-PDATA"
            print(f"     {a.address:#x} {a.mnemonic} {a.op_str} ; {b.address:#x} {b.mnemonic} {b.op_str}  [{fs}]")
        if len(out) > 60:
            print(f"     ... {len(out)-60} more")


if __name__ == "__main__":
    img, _ = open_runtime("SE")
    regions = sorted(tuple(r) for r in json.load(open("../artifacts/patch_SE.json"))["regions"])
    if "interior" in sys.argv:
        interior_refs(img)
    if "adj" in sys.argv:
        adjacency(img, regions)
