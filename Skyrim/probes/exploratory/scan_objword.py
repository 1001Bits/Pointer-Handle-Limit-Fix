"""Adversarial scan of the OBJECT-side handle word (NiRefObject::_refCount).

Goal: refute or survive the claim that bits [31:11] of that dword are
exclusively the handle index.

Pass 1 (exhaustive, .pdata-driven): classify every instruction in .text that
could touch bits >=10 of a refcount-shaped dword:
  * shift-by-10/11/12 of any flavour (shl/shr/sar/rol/ror/shld/shrd)
  * immediates from the object-word literal set
  * bt/bts/btr/btc with bit index 10 or 11
  * every LOCK-prefixed RMW (candidate atomic refcount inc/dec)
  * signed reads of the word (movsxd / sar / js after test)
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict

from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_RIP,
)

from image import open_runtime

SHIFTS = {"shl", "shr", "sar", "rol", "ror", "shld", "shrd", "sal"}
BITOPS = {"bt", "bts", "btr", "btc"}

OBJ_LITS = {
    0x000003FF: "refcount mask 0x3FF",
    0x000003FE: "refcount-1",
    0x00000400: "handle-valid bit (1<<10)",
    0x000007FF: "count|valid",
    0x00000800: "index LSB (1<<11)",
    0xFFFFF800: "index field ~[10:0]  (21b)",
    0xFFFFFBFF: "~valid",
    0xFFFFFC00: "~count",
    0xFFFFF7FF: "~(1<<11)",
    0x7FFFF800: "20-bit index IN PLACE  <<< SMOKING GUN",
    0x7FFFFFFF: "sign strip",
    0x80000000: "sign bit",
    0x000FFFFF: "20-bit mask (post-shift?)",
    0x001FFFFF: "21-bit mask",
    0x00000401: "count1|valid",
}

MEM_DISPS = {0x08, 0x28}


def opsize(ins, op):
    return op.size


def mem_desc(ins):
    """Return list of (disp, size, is_rip) for memory operands."""
    out = []
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base != X86_REG_RIP:
            out.append((op.mem.disp, op.size, op.mem.base, op.mem.index))
    return out


def main():
    runtime = sys.argv[1] if len(sys.argv) > 1 else "SE"
    img, _ = open_runtime(runtime)
    md = img.md
    text = img.text_ranges()

    def in_text(rva):
        return any(lo <= rva < hi for lo, hi in text)

    recs = []            # every hit
    func_flags = defaultdict(set)
    stats = Counter()
    total = 0

    for fi, f in enumerate(img.funcs):
        if not in_text(f.begin):
            continue
        try:
            code = img.read(f.begin, f.end - f.begin)
        except ValueError:
            continue
        for ins in md.disasm(code, img.base + f.begin):
            total += 1
            rva = ins.address - img.base
            cats = []

            ops = ins.operands
            lastimm = None
            if ops and ops[-1].type == X86_OP_IMM:
                lastimm = ops[-1].imm

            # 1. shifts by 10/11/12
            if ins.mnemonic in SHIFTS and lastimm in (0x0A, 0x0B, 0x0C):
                cats.append(f"SHIFT{lastimm}_{ins.mnemonic}")

            # shifts by CL on a dword (dynamic) -- note only, rare
            # 2. object literals
            for op in ops:
                if op.type == X86_OP_IMM:
                    v = op.imm & 0xFFFFFFFF
                    if v in OBJ_LITS:
                        cats.append(f"LIT_{v:08x}")

            # 3. bit ops at 10/11
            if ins.mnemonic in BITOPS and lastimm in (0x0A, 0x0B):
                cats.append(f"BIT{lastimm}_{ins.mnemonic}")

            # 4. lock-prefixed RMW
            if ins.bytes and ins.bytes[0] == 0xF0:
                cats.append("LOCK_" + ins.mnemonic)

            # 5. movsxd (sign-extending 32->64 read)
            if ins.mnemonic in ("movsxd", "movsx", "cdq", "cdqe"):
                md_ = mem_desc(ins)
                if any(d in MEM_DISPS and s == 4 for d, s, _, _ in md_):
                    cats.append("SIGNEXT_MEM" + ins.mnemonic)

            if cats:
                recs.append(
                    {
                        "rva": rva,
                        "va": ins.address,
                        "f": f.begin,
                        "m": ins.mnemonic,
                        "o": ins.op_str,
                        "b": ins.bytes.hex(),
                        "c": cats,
                        "mem": [[d, s] for d, s, _, _ in mem_desc(ins)],
                    }
                )
                for c in cats:
                    stats[c] += 1
                    func_flags[f.begin].add(c)
        if fi % 20000 == 0:
            print(f"  ... {fi}/{len(img.funcs)} funcs {total} insns", file=sys.stderr)

    print(f"== {runtime} instructions={total} hits={len(recs)}")
    for k, v in sorted(stats.items(), key=lambda kv: -kv[1]):
        print(f"   {k:<28} {v}")

    out = f"../artifacts/objword_{runtime}.json"
    with open(out, "w") as fh:
        json.dump({"runtime": runtime, "total": total, "recs": recs}, fh)
    print("wrote", out)


if __name__ == "__main__":
    main()
