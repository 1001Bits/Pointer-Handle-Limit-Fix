"""Exhaustive census of every DWORD write to [reg+0x08] and [reg+0x28].

These are the only two displacements at which a NiRefObject::_refCount can be
addressed in Skyrim SE (NiRefObject subobject at +0x00 -> word at +0x08;
subobject at +0x20, as in TESObjectREFR, -> word at +0x28).

Collecting every writer lets us prove or disprove that bits [31:11] of that
word are written only by the handle allocator/releaser.
"""

from __future__ import annotations

import json
import sys

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from image import open_runtime

WRITERS = {
    "mov", "or", "and", "xor", "add", "sub", "adc", "sbb",
    "bts", "btr", "btc", "inc", "dec", "not", "neg", "shl", "shr", "sar",
    "xadd", "cmpxchg", "xchg", "lock inc", "lock dec", "lock or", "lock and",
    "lock xor", "lock add", "lock sub", "lock xadd", "lock cmpxchg", "lock btr",
    "lock bts", "lock btc", "movbe",
}
READERS = {"cmp", "test", "bt"}


def main():
    runtime = sys.argv[1] if len(sys.argv) > 1 else "SE"
    img, _ = open_runtime(runtime)
    md = img.md
    text = img.text_ranges()

    def in_text(rva):
        return any(lo <= rva < hi for lo, hi in text)

    out = []
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
            ops = ins.operands
            if not ops:
                continue
            hit = False
            for op in ops:
                if (
                    op.type == X86_OP_MEM
                    and op.mem.base != X86_REG_RIP
                    and op.mem.base != 0
                    and op.mem.index == 0
                    and op.mem.disp in (0x08, 0x28)
                    and op.size == 4
                ):
                    hit = True
            if not hit:
                continue
            base = ins.mnemonic.replace("lock ", "")
            kind = "W" if base in WRITERS else ("R" if base in READERS else "?")
            imm = None
            for op in ops:
                if op.type == X86_OP_IMM:
                    imm = op.imm & 0xFFFFFFFF
            out.append(
                [ins.address - img.base, ins.address, f.begin, ins.mnemonic, ins.op_str, kind, imm]
            )
        if fi % 20000 == 0:
            print(f"  ... {fi}/{len(img.funcs)} {total}", file=sys.stderr)

    print(f"{runtime}: instructions={total} dword-at-8/0x28 accesses={len(out)}")
    p = f"../artifacts/w28_{runtime}.json"
    json.dump(out, open(p, "w"))
    print("wrote", p)


if __name__ == "__main__":
    main()
