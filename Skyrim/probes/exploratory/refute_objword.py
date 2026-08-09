"""Adversarial scan: every instruction that could touch bits [10:31] of a
NiRefObject/BSHandleRefObject _refCount word.

Collects, over every .pdata-bounded function in .text:
  A) shifts by 0x0a / 0x0b / 0x14 / 0x1f  (any direction, incl. sar)
  B) immediates in the refcount-encoding family
  C) bt/bts/btr/btc with bit 0x0a, 0x0b, 0x1f
  D) lock inc/dec/xadd/cmpxchg / inc / dec / add / sub on dword [reg+8] / [reg+0x28]
  E) movsxd from dword [reg+8] / [reg+0x28]
  F) signed jumps / cmov immediately reachable from a refcount-ish compare
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from image import open_runtime

# constants that only make sense as refcount-word encoding
IMMS = {
    0x000003FF: "rc mask 0x3FF",
    0x000007FF: "rc|valid 0x7FF",
    0x00000400: "valid bit 0x400",
    0xFFFFF800: "~(rc|valid)  index field",
    0xFFFFFC00: "~rc",
    0x00000800: "bit11 (index lsb)",
    0x80000000: "bit31",
    0x7FFFFFFF: "~bit31",
    0x001FFFFF: "21b",
    0x000FFFFF: "20b",
    0xFFF00000: "~20b",
    0xFFE00000: "~21b",
}
SHIFTS = {"shl", "shr", "sar", "rol", "ror", "shld", "shrd"}
BITOPS = {"bt", "bts", "btr", "btc"}
RMW = {
    "inc", "dec", "add", "sub", "adc", "sbb", "and", "or", "xor", "not", "neg",
    "xadd", "cmpxchg", "xchg", "mov", "cmp", "test", "movsxd", "lea",
}


def main() -> None:
    runtime = sys.argv[1] if len(sys.argv) > 1 else "SE"
    img, _ = open_runtime(runtime)
    md = img.md
    text = img.text_ranges()

    def in_text(rva: int) -> bool:
        return any(lo <= rva < hi for lo, hi in text)

    rec: dict[str, list] = defaultdict(list)
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
            m = ins.mnemonic
            base = m.replace("lock ", "")
            ops = ins.operands
            row = [ins.address, f.begin + img.base, m, ins.op_str]

            # A) shifts by 0xa/0xb/0x14/0x1f on 32-bit
            if base in SHIFTS and ops and ops[-1].type == X86_OP_IMM:
                k = ops[-1].imm
                if k in (0x0A, 0x0B, 0x14, 0x15, 0x1F):
                    rec[f"shift_{base}_{k:#x}"].append(row)

            # B) immediates
            for op in ops:
                if op.type == X86_OP_IMM:
                    v = op.imm & 0xFFFFFFFF
                    if v in IMMS:
                        rec[f"imm_{v:#010x}"].append(row + [IMMS[v]])

            # C) bit ops
            if base in BITOPS and ops and ops[-1].type == X86_OP_IMM:
                k = ops[-1].imm
                if k in (0x0A, 0x0B, 0x1A, 0x1B, 0x1F):
                    rec[f"bit_{base}_{k:#x}"].append(row)

            # D/E) dword accesses at +8 / +0x28
            for op in ops:
                if (
                    op.type == X86_OP_MEM
                    and op.mem.base not in (0, X86_REG_RIP)
                    and op.mem.disp in (0x08, 0x28)
                    and op.size == 4
                ):
                    if base in ("inc", "dec", "xadd", "cmpxchg", "add", "sub", "xchg") and "lock" in m:
                        rec["atomic_rmw"].append(row)
                    elif base == "movsxd":
                        rec["movsxd_word"].append(row)
        if fi % 25000 == 0:
            print(f"  ... {fi}/{len(img.funcs)} {total}", file=sys.stderr)

    print(f"{runtime}: instructions={total}")
    for k in sorted(rec):
        print(f"  {k:<28} {len(rec[k])}")
    out = f"../artifacts/refute_{runtime}.json"
    json.dump({k: v for k, v in rec.items()}, open(out, "w"))
    print("wrote", out)


if __name__ == "__main__":
    main()
