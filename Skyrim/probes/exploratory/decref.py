"""Find every NiRefObject-style DecRefCount epilogue and classify its zero test.

Signature (MSVC, Skyrim SE):
    or   eax, 0xffffffff              ; or  mov eax, -1
    lock xadd dword ptr [X+8], eax    ; X = NiRefObject*  (or [X+0x28])
    dec  eax                          ; new count
    test eax, <MASK>                  ; <-- the question
    jne  skip
    mov  rax, qword ptr [X]
    call qword ptr [rax+8]            ; NiRefObject::DeleteThis (vtbl[1])

MASK == 0x3FF  -> BSHandleRefObject-aware (masked)
MASK == self   -> plain NiRefObject, full 32-bit zero test

Also catches `lock dec` / `lock sub` variants and inc-side idioms.
"""
from __future__ import annotations

import json
import sys
from collections import Counter

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from image import open_runtime


def is_rc_mem(op, disps=(0x08, 0x28)):
    return (op.type == X86_OP_MEM and op.mem.base not in (0, X86_REG_RIP)
            and op.mem.index == 0 and op.mem.disp in disps and op.size == 4)


def main() -> None:
    runtime = sys.argv[1] if len(sys.argv) > 1 else "SE"
    img, _ = open_runtime(runtime)
    md = img.md
    text = img.text_ranges()

    def in_text(rva):
        return any(lo <= rva < hi for lo, hi in text)

    hits = []
    for f in img.funcs:
        if not in_text(f.begin):
            continue
        try:
            code = img.read(f.begin, f.end - f.begin)
        except ValueError:
            continue
        ins = list(md.disasm(code, img.base + f.begin))
        for i, x in enumerate(ins):
            mn = x.mnemonic
            base = mn.replace("lock ", "")
            if not mn.startswith("lock "):
                continue
            if base not in ("xadd", "dec", "sub", "add", "inc"):
                continue
            if not any(is_rc_mem(o) for o in x.operands):
                continue
            disp = next(o.mem.disp for o in x.operands if is_rc_mem(o))

            # look ahead for a DeleteThis-style virtual call within 10 insns
            win = ins[i + 1: i + 11]
            del_idx = None
            for j, y in enumerate(win):
                if y.mnemonic == "call" and y.operands and y.operands[0].type == X86_OP_MEM \
                        and y.operands[0].mem.base not in (0, X86_REG_RIP) \
                        and y.operands[0].mem.disp == 0x08:
                    del_idx = j
                    break
            if del_idx is None:
                continue

            # classify the zero test between the RMW and the call
            mask = "NONE"
            for y in win[:del_idx]:
                if y.mnemonic in ("test", "and", "cmp") and y.operands and y.operands[-1].type == X86_OP_IMM:
                    mask = f"{y.operands[-1].imm & 0xFFFFFFFF:#x}"
                    break
                if y.mnemonic == "test" and len(y.operands) == 2 and \
                        all(o.type == X86_OP_REG for o in y.operands) and \
                        y.operands[0].reg == y.operands[1].reg:
                    mask = "SELF(full 32-bit)"
                    break
                if y.mnemonic in ("jne", "je", "jz", "jnz") :
                    mask = "FLAGS(full 32-bit)"
                    break
            hits.append({"va": x.address, "func": f.begin + img.base, "disp": disp,
                         "ins": f"{mn} {x.op_str}", "mask": mask,
                         "ctx": [[y.address, y.mnemonic, y.op_str] for y in ins[max(0, i - 3): i + del_idx + 3]]})

    c = Counter((h["mask"], h["disp"]) for h in hits)
    print(f"{runtime}: refcount-with-DeleteThis sites = {len(hits)}")
    for k, v in sorted(c.items(), key=lambda kv: -kv[1]):
        print(f"   mask={k[0]:<22} disp={k[1]:#x}  count={v}")
    json.dump(hits, open(f"../artifacts/decref_{runtime}.json", "w"))


if __name__ == "__main__":
    main()
