"""Backward-slice: which shifts / bit-ops / compares actually operate on a
value loaded from dword [reg+0x08] or dword [reg+0x28] (a NiRefObject
_refCount word), and which forward uses that value feeds.

Intra-basic-block, register-alias aware (mov r32,r32 chains). Deliberately
over-approximates: a hit here is a candidate, reported with full context.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from image import open_runtime

R32 = {}


def reg_root(md, r):
    """Canonical 64-bit-ish root name for a register id."""
    n = md.reg_name(r)
    if n is None:
        return None
    m = {
        "al": "a", "ah": "a", "ax": "a", "eax": "a", "rax": "a",
        "bl": "b", "bh": "b", "bx": "b", "ebx": "b", "rbx": "b",
        "cl": "c", "ch": "c", "cx": "c", "ecx": "c", "rcx": "c",
        "dl": "d", "dh": "d", "dx": "d", "edx": "d", "rdx": "d",
        "sil": "si", "si": "si", "esi": "si", "rsi": "si",
        "dil": "di", "di": "di", "edi": "di", "rdi": "di",
        "bpl": "bp", "bp": "bp", "ebp": "bp", "rbp": "bp",
        "spl": "sp", "sp": "sp", "esp": "sp", "rsp": "sp",
    }
    if n in m:
        return m[n]
    for i in (8, 9, 10, 11, 12, 13, 14, 15):
        if n in (f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b"):
            return f"r{i}"
    return n


def main() -> None:
    runtime = sys.argv[1] if len(sys.argv) > 1 else "SE"
    window = 12
    img, _ = open_runtime(runtime)
    md = img.md
    text = img.text_ranges()

    def in_text(rva):
        return any(lo <= rva < hi for lo, hi in text)

    results = defaultdict(list)
    for f in img.funcs:
        if not in_text(f.begin):
            continue
        try:
            code = img.read(f.begin, f.end - f.begin)
        except ValueError:
            continue
        ins = list(md.disasm(code, img.base + f.begin))
        # map: instruction index -> set of reg roots currently holding a
        # value derived from a _refCount word load
        tainted: dict[str, int] = {}   # root -> index of defining load
        for i, x in enumerate(ins):
            mn = x.mnemonic.replace("lock ", "")
            ops = x.operands

            # a control-flow join / branch target kills the slice (conservative:
            # only kill on unconditional jmp / ret / call)
            if mn in ("ret", "jmp"):
                tainted.clear()
                continue
            if mn == "call":
                tainted = {k: v for k, v in tainted.items()
                           if k in ("b", "si", "di", "bp", "r12", "r13", "r14", "r15")}
                continue

            # --- detect taint source: mov r32, dword [X + 8|0x28]
            if mn in ("mov", "movzx", "movsxd") and len(ops) == 2 and ops[0].type == X86_OP_REG:
                src = ops[1]
                if (src.type == X86_OP_MEM and src.mem.base not in (0, X86_REG_RIP)
                        and src.mem.index == 0 and src.mem.disp in (0x08, 0x28)
                        and src.size == 4):
                    tainted[reg_root(md, ops[0].reg)] = i
                    if mn == "movsxd":
                        results["SIGN_EXTEND_LOAD"].append((f.begin, i, x.address))
                    continue

            # --- propagate through mov r32, r32
            if mn == "mov" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
                d, s = reg_root(md, ops[0].reg), reg_root(md, ops[1].reg)
                if s in tainted:
                    tainted[d] = tainted[s]
                else:
                    tainted.pop(d, None)
                continue

            # --- uses
            first = ops[0] if ops else None
            froot = reg_root(md, first.reg) if (first and first.type == X86_OP_REG) else None
            mem_rc = any(
                op.type == X86_OP_MEM and op.mem.base not in (0, X86_REG_RIP)
                and op.mem.index == 0 and op.mem.disp in (0x08, 0x28) and op.size == 4
                for op in ops
            )
            hit = (froot in tainted) or mem_rc
            if hit:
                key = None
                if mn in ("shr", "shl", "sar", "rol", "ror") and ops[-1].type == X86_OP_IMM:
                    key = f"{mn}_{ops[-1].imm:#x}"
                elif mn in ("bt", "bts", "btr", "btc") and ops[-1].type == X86_OP_IMM:
                    key = f"{mn}_{ops[-1].imm:#x}"
                elif mn in ("cmp", "test", "and", "or", "xor", "add", "sub", "movsxd", "imul", "idiv", "div", "cdq", "cdqe", "neg", "not"):
                    v = None
                    for op in ops:
                        if op.type == X86_OP_IMM:
                            v = op.imm & 0xFFFFFFFF
                    key = f"{mn}_{v:#x}" if v is not None else f"{mn}_reg"
                if key:
                    results[key].append((f.begin, i, x.address))

            # --- kill on redefinition by anything else
            if froot and mn not in ("cmp", "test", "bt", "push"):
                if mn in ("and", "or", "shr", "shl", "sar", "xor", "add", "sub", "inc", "dec", "bts", "btr", "btc"):
                    pass  # still derived from the word
                else:
                    tainted.pop(froot, None)

    print(f"{runtime}: taint-derived uses of a dword [reg+8]/[reg+0x28] value")
    for k in sorted(results, key=lambda k: -len(results[k])):
        print(f"  {k:<24} {len(results[k])}")
    json.dump({k: v for k, v in results.items()}, open(f"../artifacts/taint_{runtime}.json", "w"))


if __name__ == "__main__":
    main()
