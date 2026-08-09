"""Does anything treat a BSHandleRefObject _refCount word as SIGNED?

Today idx <= 0xFFFFF so (idx<<11) never sets bit 31: the word is always a
non-negative int32. A 21-bit index sets bit 31 for idx >= 0x100000, so any
signed use of that word is a hard blocker.

Method: per function, build register slices tainted from
`mov r32, dword [X+8|0x28]`. A slice is CONFIRMED to be a refcount word if any
use is one of the encoding ops (and/test 0x3ff | 0x7ff | 0x400, shr 0xa,
shr/shl 0xb, bt* 0xa). Report every CONFIRMED slice whose uses include a
signed/sign-extending operation, and every direct-memory signed use.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from image import open_runtime

SIGNED = {
    "sar", "movsx", "movsxd", "cdq", "cdqe", "cqo", "idiv", "imul", "neg",
    "cvtsi2ss", "cvtsi2sd", "js", "jns", "jg", "jge", "jl", "jle",
    "setg", "setge", "setl", "setle", "sets", "setns",
    "cmovs", "cmovns", "cmovg", "cmovge", "cmovl", "cmovle",
}
FLAGSETTERS = {"cmp", "test", "and", "or", "xor", "add", "sub", "inc", "dec",
               "shr", "shl", "sar", "neg", "not", "bt", "bts", "btr", "imul"}
CONFIRM_IMMS = {0x3FF, 0x7FF, 0x400, 0xFFFFF800}


def root(md, r):
    n = md.reg_name(r)
    if not n:
        return None
    m = {"al": "a", "ah": "a", "ax": "a", "eax": "a", "rax": "a",
         "bl": "b", "bh": "b", "bx": "b", "ebx": "b", "rbx": "b",
         "cl": "c", "ch": "c", "cx": "c", "ecx": "c", "rcx": "c",
         "dl": "d", "dh": "d", "dx": "d", "edx": "d", "rdx": "d",
         "sil": "si", "si": "si", "esi": "si", "rsi": "si",
         "dil": "di", "di": "di", "edi": "di", "rdi": "di",
         "bpl": "bp", "bp": "bp", "ebp": "bp", "rbp": "bp"}
    if n in m:
        return m[n]
    for i in range(8, 16):
        if n in (f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b"):
            return f"r{i}"
    return n


def is_rc_mem(op):
    return (op.type == X86_OP_MEM and op.mem.base not in (0, X86_REG_RIP)
            and op.mem.index == 0 and op.mem.disp in (0x08, 0x28) and op.size == 4)


def main():
    runtime = sys.argv[1] if len(sys.argv) > 1 else "SE"
    img, _ = open_runtime(runtime)
    md = img.md
    text = img.text_ranges()

    def in_text(rva):
        return any(lo <= rva < hi for lo, hi in text)

    slices: dict[tuple, dict] = {}
    reported = []
    direct_signed = []
    stats = Counter()

    for f in img.funcs:
        if not in_text(f.begin):
            continue
        try:
            code = img.read(f.begin, f.end - f.begin)
        except ValueError:
            continue
        ins = list(md.disasm(code, img.base + f.begin))
        # slice id -> {confirmed, uses}
        live: dict[str, tuple] = {}     # reg root -> slice key
        S: dict[tuple, dict] = {}
        flag_owner = None               # slice key that last set flags

        for i, x in enumerate(ins):
            mn = x.mnemonic.replace("lock ", "")
            ops = x.operands

            if mn in ("ret", "jmp"):
                live.clear(); flag_owner = None
                continue
            if mn == "call":
                live = {k: v for k, v in live.items()
                        if k in ("b", "si", "di", "bp", "r12", "r13", "r14", "r15")}
                flag_owner = None
                continue

            # signed jcc / setcc / cmovcc consuming flags from a confirmed slice
            if mn in SIGNED and mn[0] in "jsc" and mn not in ("cvtsi2ss", "cvtsi2sd"):
                if flag_owner is not None and flag_owner in S:
                    S[flag_owner]["uses"].append((x.address, f"{mn} {x.op_str}"))
                    S[flag_owner]["signed"] = True
                continue

            # taint source
            if mn in ("mov", "movzx") and len(ops) == 2 and ops[0].type == X86_OP_REG and is_rc_mem(ops[1]):
                key = (f.begin, i)
                S[key] = {"src": x.address, "confirmed": False, "signed": False, "uses": []}
                live[root(md, ops[0].reg)] = key
                flag_owner = None
                continue
            if mn == "movsxd" and len(ops) == 2 and is_rc_mem(ops[1]):
                direct_signed.append((x.address, f.begin + img.base, f"{mn} {x.op_str}"))
                continue

            # direct memory signed op
            if any(is_rc_mem(o) for o in ops) and mn in SIGNED:
                direct_signed.append((x.address, f.begin + img.base, f"{mn} {x.op_str}"))

            # propagate reg-to-reg
            if mn == "mov" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
                d, s = root(md, ops[0].reg), root(md, ops[1].reg)
                if s in live:
                    live[d] = live[s]
                else:
                    live.pop(d, None)
                continue

            # uses
            key = None
            for o in ops:
                if o.type == X86_OP_REG and root(md, o.reg) in live:
                    key = live[root(md, o.reg)]
                    break
            if key is not None and key in S:
                S[key]["uses"].append((x.address, f"{mn} {x.op_str}"))
                imm = next((o.imm & 0xFFFFFFFF for o in ops if o.type == X86_OP_IMM), None)
                if imm in CONFIRM_IMMS:
                    S[key]["confirmed"] = True
                if mn in ("shr", "shl", "sar", "bt", "bts", "btr", "btc") and imm in (0x0A, 0x0B):
                    S[key]["confirmed"] = True
                if mn in SIGNED:
                    S[key]["signed"] = True
                if mn in FLAGSETTERS:
                    flag_owner = key
            elif mn in FLAGSETTERS:
                flag_owner = None

            # kill on full redefinition
            if ops and ops[0].type == X86_OP_REG and mn not in ("cmp", "test", "bt", "push"):
                r0 = root(md, ops[0].reg)
                if mn not in ("and", "or", "shr", "shl", "sar", "xor", "add", "sub",
                              "inc", "dec", "bts", "btr", "btc", "movzx"):
                    live.pop(r0, None)

        for k, v in S.items():
            if v["confirmed"]:
                stats["confirmed_slices"] += 1
                if v["signed"]:
                    reported.append({"func": f.begin + img.base, "src": v["src"], "uses": v["uses"]})

    print(f"{runtime}: confirmed refcount-word slices = {stats['confirmed_slices']}")
    print(f"  slices with a SIGNED use            = {len(reported)}")
    print(f"  direct signed/sign-extending memory ops on [X+8]/[X+0x28] = {len(direct_signed)}")
    for r in reported[:60]:
        print(f"  !! func {r['func']:#x}  load {r['src']:#x}")
        for a, s in r["uses"]:
            print(f"       {a:#012x}  {s}")
    json.dump({"signed_slices": reported, "direct": direct_signed},
              open(f"../artifacts/signedness_{runtime}.json", "w"))


if __name__ == "__main__":
    main()
