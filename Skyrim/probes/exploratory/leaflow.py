"""For every table `lea`, follow the destination register a short way.

Answers three questions the literal scan cannot:
  * does the table pointer get passed to a CALL (decode happens in a callee)?
  * does it get STORED to memory (cached pointer, decoders read it elsewhere)?
  * is the table walked by an END POINTER (needs the new end address too)?
"""
from __future__ import annotations

import json

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from image import open_runtime

BASE = 0x140000000
TABLE = 0x1EC47C0

ARG_REGS = {
    capstone.x86.X86_REG_RCX, capstone.x86.X86_REG_RDX,
    capstone.x86.X86_REG_R8, capstone.x86.X86_REG_R9,
}

patch = json.load(open("../artifacts/patch_SE.json"))
LEAS = sorted(patch["lea_disp_rvas"])
REGIONS = sorted(tuple(r) for r in patch["regions"])

img, _ = open_runtime("SE")
md = img.md


def root(r):
    """Canonical 64-bit form of a register."""
    n = img.md.reg_name(r) or ""
    m = {
        "eax": "rax", "ecx": "rcx", "edx": "rdx", "ebx": "rbx", "esp": "rsp",
        "ebp": "rbp", "esi": "rsi", "edi": "rdi",
    }
    if n in m:
        return m[n]
    if n.startswith("r") and n.endswith("d"):
        return n[:-1]
    return n


flagged = {"call": [], "store": [], "cmp_end": [], "add_big": []}

for d in LEAS:
    # the lea starts a few bytes before the disp32; find its start
    ins0 = None
    for back in range(2, 6):
        cands = img.disasm(d - back, back + 12)
        if cands and cands[0].size >= back + 4 and cands[0].mnemonic == "lea":
            tg = img.rip_targets(cands[0])
            if tg and tg[0] == TABLE:
                ins0 = cands[0]
                break
    if ins0 is None:
        print(f"!! could not resync lea at rva {d:#x}")
        continue
    reg = root(ins0.operands[0].reg)
    start = ins0.address - BASE
    win = img.disasm(start, 0x90)
    live = {reg}
    for k, ins in enumerate(win[1:], 1):
        txt = f"{ins.address:#012x} {ins.mnemonic} {ins.op_str}"
        ops = ins.operands
        # propagate through mov reg, reg / lea reg,[reg...]
        if ins.mnemonic in ("mov", "lea") and len(ops) == 2 and ops[0].type == X86_OP_REG:
            src_regs = set()
            if ops[1].type == X86_OP_REG:
                src_regs.add(root(ops[1].reg))
            elif ops[1].type == X86_OP_MEM:
                if ops[1].mem.base:
                    src_regs.add(root(ops[1].mem.base))
                if ops[1].mem.index:
                    src_regs.add(root(ops[1].mem.index))
            if src_regs & live and ins.mnemonic == "lea":
                live.add(root(ops[0].reg))
            elif ops[1].type == X86_OP_REG and root(ops[1].reg) in live:
                live.add(root(ops[0].reg))
        # store of a live reg to memory
        if ins.mnemonic == "mov" and len(ops) == 2 and ops[0].type == X86_OP_MEM \
           and ops[1].type == X86_OP_REG and root(ops[1].reg) in live:
            flagged["store"].append((ins0.address, txt))
        # add of a large constant to a live reg (end-pointer computation)
        if ins.mnemonic in ("add", "lea") and len(ops) == 2:
            v = None
            if ops[1].type == X86_OP_IMM:
                v = ops[1].imm
            elif ops[1].type == X86_OP_MEM and ops[1].mem.base and root(ops[1].mem.base) in live:
                v = ops[1].mem.disp
            if v and abs(v) >= 0x10000 and ops[0].type == X86_OP_REG:
                flagged["add_big"].append((ins0.address, txt))
        # comparison of a live reg against another pointer
        if ins.mnemonic in ("cmp", "sub") and len(ops) == 2 and ops[0].type == X86_OP_REG \
           and root(ops[0].reg) in live and ops[1].type == X86_OP_REG:
            flagged["cmp_end"].append((ins0.address, txt))
        if ins.mnemonic in ("call", "jmp") and (live & {img.md.reg_name(r) for r in ARG_REGS}):
            flagged["call"].append((ins0.address, f"{txt}   [live={sorted(live)}]"))
            break
        if ins.mnemonic == "ret":
            break

for k, v in flagged.items():
    print(f"=== {k}: {len(v)}")
    seen = set()
    for lea, txt in v:
        if (lea, txt) in seen:
            continue
        seen.add((lea, txt))
        print(f"   lea@{lea:#x}  {txt}")
