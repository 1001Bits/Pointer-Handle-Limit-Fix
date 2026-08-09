"""Whole-image call/data cross-reference index, cached to disk.

Builds, once per runtime, an index over every .pdata function:
  calls[target_rva]  -> [(site_rva, func_rva, mnemonic), ...]   direct rel32 call/jmp
  datarefs[tgt_rva]  -> [(site_rva, func_rva, mnemonic, op_str), ...]  RIP-relative
  fcalls[func_rva]   -> sorted set of direct call targets
Cached as a pickle in the scratchpad.
"""

from __future__ import annotations

import pickle
import os
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from image import open_runtime

CACHE = Path(os.environ.get("SHCR_XREF_CACHE", tempfile.gettempdir())) / "skyrim-handle-cap-raise" / "xrefidx"


class Index:
    def __init__(self, img, calls, datarefs, fcalls):
        self.img = img
        self.calls = calls
        self.datarefs = datarefs
        self.fcalls = fcalls

    def callers(self, va_or_rva: int):
        rva = va_or_rva - self.img.base if va_or_rva >= self.img.base else va_or_rva
        return self.calls.get(rva, [])

    def refs(self, va_or_rva: int):
        rva = va_or_rva - self.img.base if va_or_rva >= self.img.base else va_or_rva
        return self.datarefs.get(rva, [])


def build(tag: str = "SE", force: bool = False) -> Index:
    CACHE.mkdir(parents=True, exist_ok=True)
    p = CACHE / f"xrefidx_{tag}.pkl"
    img, _ = open_runtime(tag)
    if p.exists() and not force:
        with open(p, "rb") as fh:
            calls, datarefs, fcalls = pickle.load(fh)
        return Index(img, calls, datarefs, fcalls)

    calls = defaultdict(list)
    datarefs = defaultdict(list)
    fcalls = {}
    md = img.md
    text = img.text_ranges()

    def in_text(rva):
        return any(lo <= rva < hi for lo, hi in text)

    for fi, f in enumerate(img.funcs):
        if not in_text(f.begin):
            continue
        try:
            code = img.read(f.begin, f.end - f.begin)
        except ValueError:
            continue
        tgts = set()
        for ins in md.disasm(code, img.base + f.begin):
            rva = ins.address - img.base
            if ins.mnemonic in ("call", "jmp") and ins.operands and ins.operands[0].type == X86_OP_IMM:
                t = ins.operands[0].imm - img.base
                calls[t].append((rva, f.begin, ins.mnemonic))
                if ins.mnemonic == "call":
                    tgts.add(t)
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    t = rva + ins.size + op.mem.disp
                    datarefs[t].append((rva, f.begin, ins.mnemonic, ins.op_str))
        fcalls[f.begin] = sorted(tgts)
        if fi % 20000 == 0:
            print(f"  ... {fi}/{len(img.funcs)}", file=sys.stderr)

    calls = dict(calls)
    datarefs = dict(datarefs)
    with open(p, "wb") as fh:
        pickle.dump((calls, datarefs, fcalls), fh, protocol=4)
    print(f"  wrote {p}", file=sys.stderr)
    return Index(img, calls, datarefs, fcalls)


if __name__ == "__main__":
    tag = sys.argv[1] if len(sys.argv) > 1 else "SE"
    idx = build(tag, force="--force" in sys.argv)
    print(f"{tag}: call targets={len(idx.calls)} dataref targets={len(idx.datarefs)} funcs={len(idx.fcalls)}")
