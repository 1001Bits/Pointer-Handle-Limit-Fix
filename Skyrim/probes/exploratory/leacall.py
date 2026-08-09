"""Precise: does any table `lea` still hold the table in an ARG register at a call?

Walks forward from each lea, killing the register on redefinition, and reports
the first call/jmp reached while the register is still live.
"""
from __future__ import annotations

import json

import capstone
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from image import open_runtime

BASE = 0x140000000
TABLE = 0x1EC47C0
ARGN = {"rcx", "rdx", "r8", "r9"}

patch = json.load(open("../artifacts/patch_SE.json"))
LEAS = sorted(patch["lea_disp_rvas"])
img, _ = open_runtime("SE")


def root(img, r):
    n = img.md.reg_name(r) or ""
    m = {"eax": "rax", "ecx": "rcx", "edx": "rdx", "ebx": "rbx", "esp": "rsp",
         "ebp": "rbp", "esi": "rsi", "edi": "rdi",
         "ax": "rax", "cx": "rcx", "dx": "rdx", "bx": "rbx",
         "al": "rax", "cl": "rcx", "dl": "rdx", "bl": "rbx"}
    if n in m:
        return m[n]
    if n.startswith("r") and (n.endswith("d") or n.endswith("w") or n.endswith("b")) and n[1:-1].isdigit():
        return n[:-1]
    return n


hits = []
for d in LEAS:
    ins0 = None
    for back in range(2, 6):
        c = img.disasm(d - back, back + 12)
        if c and c[0].mnemonic == "lea" and c[0].size >= back + 4:
            t = img.rip_targets(c[0])
            if t and t[0] == TABLE:
                ins0 = c[0]
                break
    if ins0 is None:
        print(f"!! resync fail {d:#x}")
        continue
    reg = root(img, ins0.operands[0].reg)
    start = ins0.address - BASE
    win = img.disasm(start, 0x120)
    live = reg
    for ins in win[1:]:
        w = ins.regs_access()[1] if hasattr(ins, "regs_access") else ([], [])
        # call / jmp while live and live is an arg register
        if ins.mnemonic in ("call", "jmp"):
            if live in ARGN:
                hits.append((ins0.address, live, ins))
            break
        if ins.mnemonic == "ret":
            break
        # kill on redefinition (any write to the live register)
        try:
            _, written = ins.regs_access()
        except Exception:
            written = []
        if any(root(img, r) == live for r in written):
            # unless it is a pure propagation we don't care about
            break
        # also treat explicit dest-operand writes
        ops = ins.operands
        if ops and ops[0].type == X86_OP_REG and root(img, ops[0].reg) == live \
           and ins.mnemonic not in ("cmp", "test", "bt", "push"):
            break

print(f"table pointer live in an arg register at a call/jmp: {len(hits)}\n")
for lea, reg, ins in hits:
    print(f"  lea@{lea:#x} ({reg}) -> {ins.address:#012x}  {ins.mnemonic} {ins.op_str}")
