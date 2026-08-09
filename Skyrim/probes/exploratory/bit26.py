"""Review every bit-26 test/set/clear outside the patch regions, with provenance.

An Entry's bits word lives at offset 0 of an Entry. Any code operating on a
handle entry without a table reference would have to hold an `Entry*`, so the
tell-tale is a bit-26 operation on `dword ptr [reg]` with displacement 0, or on
a register loaded from `[reg]`.
"""
from __future__ import annotations
import json
from collections import defaultdict
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from image import open_runtime
from alt import linear

TARGETS_IMM = {0x04000000, 0xFBFFFFFF}


def main():
    img, _ = open_runtime("SE")
    regions = sorted(tuple(r) for r in json.load(open("../artifacts/patch_SE.json"))["regions"])

    def inreg(r):
        return any(b <= r < e for b, e in regions)

    win = []
    hits = []
    for kind, sb, ins in linear(img):
        win.append(ins)
        if len(win) > 8:
            win.pop(0)
        rva = ins.address - img.base
        why = None
        if ins.mnemonic in ("bt", "bts", "btr", "btc") and ins.operands and \
                ins.operands[-1].type == X86_OP_IMM and ins.operands[-1].imm == 0x1A:
            why = "bt26"
        else:
            for op in ins.operands:
                if op.type == X86_OP_IMM and (op.imm & 0xFFFFFFFF) in TARGETS_IMM:
                    why = f"imm {op.imm & 0xFFFFFFFF:#x}"
        if why is None or inreg(rva):
            continue
        # provenance of operand 0
        op0 = ins.operands[0]
        srcdesc = ""
        if op0.type == X86_OP_MEM:
            srcdesc = f"MEM disp={op0.mem.disp:#x} base={ins.reg_name(op0.mem.base)}"
        elif op0.type == X86_OP_REG:
            r = op0.reg
            for prev in reversed(win[:-1]):
                if prev.operands and prev.operands[0].type == X86_OP_REG and prev.operands[0].reg == r \
                        and prev.mnemonic in ("mov", "movzx", "movsx", "lea"):
                    srcdesc = f"REG {ins.reg_name(r)} <- {prev.mnemonic} {prev.op_str}"
                    break
            if not srcdesc:
                srcdesc = f"REG {ins.reg_name(r)} (src not in window)"
        f = img.func_containing(rva)
        hits.append((rva, why, ins, srcdesc, f))

    print(f"bit-26 operations OUTSIDE patch regions: {len(hits)}")
    # group: only those touching offset 0 of a pointer are candidate Entry accesses
    danger = []
    for rva, why, ins, src, f in hits:
        isdisp0 = "disp=0x0" in src
        srcdisp0 = "qword ptr [" in src and "+" not in src
        tag = "  <== disp0" if isdisp0 or ("dword ptr [r" in src and "+" not in src) else ""
        if tag:
            danger.append((rva, why, ins, src, f))
    print(f"  of which operate at displacement 0 of a pointer: {len(danger)}\n")
    for rva, why, ins, src, f in hits:
        fs = f"pdata {img.base+f.begin:#x}" if f else "NO-PDATA"
        d = " <== DISP0" if (rva, why, ins, src, f) in danger else ""
        print(f"  {img.base+rva:#x} {why:<14} {ins.mnemonic:<5} {ins.op_str:<44} | {src:<48} [{fs}]{d}")


if __name__ == "__main__":
    main()
