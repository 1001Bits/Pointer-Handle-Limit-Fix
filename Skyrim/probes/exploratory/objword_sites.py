"""Precise enumeration of code that manipulates a BSHandleRefObject
_refCount word, plus every atomic RMW on a NiRefObject _refCount word.

Two independent classifications:

  HW  "handle-word aware": an instruction from the encoding alphabet
      (shr/sar/shl by 0xb, bt*/0xa, and/or/test with 0x3ff / 0x400 / 0x7ff)
      whose operand is provably a value loaded from dword [X+0x08] or
      dword [X+0x28] within the same basic block (or the memory operand
      itself).

  RC  every atomic RMW (lock inc / lock dec / lock xadd / lock cmpxchg /
      lock add / lock sub) on dword [X+0x08] or dword [X+0x28], with the
      following 8 instructions so the zero-test can be classified as
      masked (test/and 0x3ff) or unmasked (test eax,eax / flags).
"""
from __future__ import annotations

import json
import sys

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from image import open_runtime

ENC_SHIFTS = {0x0A, 0x0B}
ENC_IMMS = {0x000003FF, 0x00000400, 0x000007FF, 0xFFFFF800, 0xFFFFFC00}
ATOMIC = {"inc", "dec", "xadd", "cmpxchg", "add", "sub", "and", "or", "xor", "btr", "bts"}


def root(md, r):
    n = md.reg_name(r)
    if not n:
        return None
    for pre, out in (("r", None),):
        pass
    m = {"al": "a", "ax": "a", "eax": "a", "rax": "a",
         "bl": "b", "bx": "b", "ebx": "b", "rbx": "b",
         "cl": "c", "cx": "c", "ecx": "c", "rcx": "c",
         "dl": "d", "dx": "d", "edx": "d", "rdx": "d",
         "sil": "si", "esi": "si", "rsi": "si",
         "dil": "di", "edi": "di", "rdi": "di",
         "bpl": "bp", "ebp": "bp", "rbp": "bp"}
    if n in m:
        return m[n]
    for i in range(8, 16):
        if n in (f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b"):
            return f"r{i}"
    return n


def is_rc_mem(op):
    return (op.type == X86_OP_MEM and op.mem.base not in (0, X86_REG_RIP)
            and op.mem.index == 0 and op.mem.disp in (0x08, 0x28) and op.size == 4)


def main() -> None:
    runtime = sys.argv[1] if len(sys.argv) > 1 else "SE"
    img, _ = open_runtime(runtime)
    md = img.md
    text = img.text_ranges()

    def in_text(rva):
        return any(lo <= rva < hi for lo, hi in text)

    hw, rc = [], []
    for f in img.funcs:
        if not in_text(f.begin):
            continue
        try:
            code = img.read(f.begin, f.end - f.begin)
        except ValueError:
            continue
        ins = list(md.disasm(code, img.base + f.begin))
        taint: dict[str, int] = {}
        for i, x in enumerate(ins):
            mn = x.mnemonic.replace("lock ", "")
            ops = x.operands
            if mn in ("ret", "jmp", "call"):
                taint.clear()
                continue

            # taint source
            if mn in ("mov", "movzx", "movsxd") and len(ops) == 2 and ops[0].type == X86_OP_REG and is_rc_mem(ops[1]):
                taint[root(md, ops[0].reg)] = i
                continue
            if mn == "mov" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
                d, s = root(md, ops[0].reg), root(md, ops[1].reg)
                if s in taint:
                    taint[d] = taint[s]
                else:
                    taint.pop(d, None)
                continue

            tgt_mem = any(is_rc_mem(o) for o in ops)
            tgt_reg = ops and ops[0].type == X86_OP_REG and root(md, ops[0].reg) in taint
            src_reg = any(o.type == X86_OP_REG and root(md, o.reg) in taint for o in ops)

            enc = False
            if mn in ("shr", "shl", "sar", "rol", "ror") and ops[-1].type == X86_OP_IMM and ops[-1].imm in ENC_SHIFTS:
                enc = True
            if mn in ("bt", "bts", "btr", "btc") and ops[-1].type == X86_OP_IMM and ops[-1].imm == 0x0A:
                enc = True
            for o in ops:
                if o.type == X86_OP_IMM and (o.imm & 0xFFFFFFFF) in ENC_IMMS:
                    enc = True

            if enc and (tgt_mem or tgt_reg or src_reg):
                ctx = []
                for y in ins[max(0, i - 5): i + 8]:
                    ctx.append([y.address, y.mnemonic, y.op_str])
                hw.append({"va": x.address, "func": f.begin + img.base,
                           "ins": f"{x.mnemonic} {x.op_str}", "ctx": ctx})

            if x.mnemonic.startswith("lock ") and mn in ATOMIC and tgt_mem:
                ctx = []
                for y in ins[max(0, i - 3): i + 9]:
                    ctx.append([y.address, y.mnemonic, y.op_str])
                rc.append({"va": x.address, "func": f.begin + img.base,
                           "ins": f"{x.mnemonic} {x.op_str}", "ctx": ctx})

            if ops and ops[0].type == X86_OP_REG and mn not in ("cmp", "test", "bt", "push"):
                r0 = root(md, ops[0].reg)
                if mn not in ("and", "or", "shr", "shl", "sar", "xor", "add", "sub", "inc", "dec", "bts", "btr", "btc"):
                    taint.pop(r0, None)

    print(f"{runtime}: handle-word-encoding sites = {len(hw)}   atomic RMW on [+8]/[+0x28] = {len(rc)}")
    json.dump({"hw": hw, "rc": rc}, open(f"../artifacts/objword_sites_{runtime}.json", "w"))


if __name__ == "__main__":
    main()
