"""Fast numpy byte-level scan for every RIP-relative reference to head/tail/lock/table."""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

from image import open_runtime

OUT = Path(sys.argv[1])
img, _ = open_runtime("SE")
L = []
def p(s=""):
    L.append(str(s))

def candidates(target_rva):
    out = []
    for lo, hi in img.text_ranges():
        data = np.frombuffer(img.read(lo, hi - lo), dtype=np.uint8).astype(np.int64)
        n = len(data)
        v = (data[0:n-3] | (data[1:n-2] << 8) | (data[2:n-1] << 16) | (data[3:n] << 24))
        v = np.where(v >= 0x80000000, v - 0x100000000, v)
        pos = np.arange(0, n - 3, dtype=np.int64)
        hit = np.nonzero((lo + pos + 4 + v) == target_rva)[0]
        out.extend(int(lo + h) for h in hit)
    return out

def confirm(disp_rva, window=16):
    for back in range(2, window):
        start = disp_rva - back
        try:
            ins_list = img.disasm(start, back + 8)
        except ValueError:
            continue
        if not ins_list:
            continue
        ins = ins_list[0]
        if ins.address - img.base != start:
            continue
        if not (start < disp_rva < start + ins.size):
            continue
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                return ins
    return None

for name, rva in (("HEAD", 0x1ec47ac), ("TAIL", 0x1ec47b0), ("LOCK", 0x1ec47b8), ("TABLE", 0x1ec47c0)):
    cands = candidates(rva)
    p(f"\n== {name} va={img.base+rva:#x}: {len(cands)} dword candidates")
    conf = 0
    funcs = set()
    for c in cands:
        ins = confirm(c)
        if ins is None:
            p(f"   UNCONFIRMED dword at rva {c:#x} (va {img.base+c:#x})")
            continue
        conf += 1
        f = img.func_containing(ins.address - img.base)
        funcs.add(f.begin if f else -1)
        loc = f"func {img.base+f.begin:#x}" if f else "NO-PDATA"
        p(f"   {ins.address:#x}  {ins.bytes.hex():<22} {ins.mnemonic:<6} {ins.op_str}   [{loc}]")
    p(f"   confirmed={conf}  distinct functions={len(funcs)}")

OUT.write_text("\n".join(L), encoding="utf-8")
print("wrote", OUT, len(L))
