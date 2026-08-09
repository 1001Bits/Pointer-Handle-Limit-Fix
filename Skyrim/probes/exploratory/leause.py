"""For every `lea reg,[rip+table]` site: is the pointer consumed locally, or is it
passed to a call / stored to memory (which would hide a decoder elsewhere)?"""
from __future__ import annotations
import json
import capstone
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_RIP
from image import open_runtime

TABLE = 0x1EC47C0
ARGREGS = {capstone.x86.X86_REG_RCX: "rcx", capstone.x86.X86_REG_RDX: "rdx",
           capstone.x86.X86_REG_R8: "r8", capstone.x86.X86_REG_R9: "r9"}

SITES = [0x1400125d6,0x140012606,0x140131f9f,0x14013212f,0x1401328ce,0x1401329f5,
0x140132b23,0x140135e42,0x14013619b,0x1401362db,0x14014257e,0x140177535,0x1401d58fe,
0x1401d59f1,0x140213115,0x14023729e,0x140380084,0x1403e06d2,0x1403e0837,0x1403e667a,
0x1403ef0e4,0x1403f14cb,0x140400d60,0x14040bb2b,0x14040d08e,0x14040d6fe,0x140410df5,
0x14041eb68,0x14041eee5,0x14042b6de,0x14042b803,0x1404344b3,0x14054a85f,0x14054abae,
0x1405521e5,0x14055e7ae,0x140587a86,0x1405a8f2f,0x1405bccbc,0x1405ce7fe,0x1405dc004,
0x1405ecdcd,0x1405f59fd,0x140606bda,0x14060d236,0x140615059,0x1406195dd,0x14062f221,
0x1406565a5,0x14065a12e,0x14066d4c2,0x1406783d7,0x1406a5b3a,0x1406a992f,0x1406aec4d,
0x1406aedab,0x1406af10d,0x1406af225,0x1406d7885,0x1406d7be3,0x1406d7bec,0x1406d7cc0,
0x1406da207,0x1406da284,0x1406da4f6,0x1406da8be,0x1406dab28,0x1406daf63,0x1406db157,
0x140706b32,0x14071316b,0x1407133c7,0x140715990,0x140715a4f,0x140715eb1,0x14073d24f,
0x14073d3f4,0x140742204,0x140756274,0x14076a0eb,0x14076dd2e,0x14076df6e,0x140771d04,
0x14077290f,0x140774013,0x1408476f6,0x140847b04,0x14084842d,0x14087eaac,0x1408dd4a0,
0x1408dd8b2,0x1408e1f21,0x1408e2140,0x1408e2302,0x1408e287d,0x14148bd72]


def analyse(img, va, span=0x60):
    rva = va - img.base
    ins_list = img.disasm(rva, span)
    if not ins_list:
        return "??", []
    lea = ins_list[0]
    dst = lea.operands[0].reg
    dname = lea.reg_name(dst)
    trail = []
    verdict = "local"
    live = {dst}
    for ins in ins_list[1:]:
        trail.append(f"{ins.mnemonic} {ins.op_str}")
        # store of the pointer to memory?
        if ins.mnemonic in ("mov", "movq") and ins.operands and ins.operands[0].type == X86_OP_MEM:
            if len(ins.operands) > 1 and ins.operands[1].type == X86_OP_REG and ins.operands[1].reg in live:
                verdict = "STORED-TO-MEMORY"
                break
        if ins.mnemonic in ("call", "jmp"):
            if dst in ARGREGS and dst in live:
                verdict = f"PASSED-AS-ARG({ARGREGS[dst]}) -> {ins.op_str}"
            else:
                verdict = f"call/jmp with ptr in {dname} (non-arg reg) -> {ins.op_str}"
            break
        # consumed into an entry pointer
        if ins.mnemonic in ("add", "lea") and any(
                (op.type == X86_OP_REG and op.reg in live) or
                (op.type == X86_OP_MEM and (op.mem.base in live or op.mem.index in live))
                for op in ins.operands):
            verdict = "local (entry-ptr arithmetic)"
            break
        if ins.mnemonic in ("mov", "movzx", "movsx") and ins.operands and \
                ins.operands[0].type == X86_OP_MEM and ins.operands[0].mem.base in live:
            verdict = "local (direct table load)"
            break
        # overwritten
        if ins.operands and ins.operands[0].type == X86_OP_REG and ins.operands[0].reg == dst \
                and ins.mnemonic not in ("cmp", "test"):
            verdict = "clobbered-before-use?"
            break
    return f"{dname}: {verdict}", trail


if __name__ == "__main__":
    img, _ = open_runtime("SE")
    cats = {}
    for va in SITES:
        v, trail = analyse(img, va)
        cats.setdefault(v.split(":")[1].strip().split("(")[0], []).append((va, v, trail))
    for k in sorted(cats):
        print(f"\n===== {k}  ({len(cats[k])} sites)")
        for va, v, trail in cats[k]:
            print(f"  {va:#x}  {v}")
            if not k.startswith("local"):
                for t in trail[:6]:
                    print(f"        {t}")
