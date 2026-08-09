"""Decoder-independent completeness check for references to a target RVA.

A RIP-relative operand stores disp32 = target - (rva_of_disp + 4). Scanning
every byte offset in .text for a dword equal to that value finds a strict
SUPERSET of all RIP-relative references to the target, regardless of whether
the surrounding bytes decode as an instruction. Each candidate is then
confirmed by disassembling backwards from nearby instruction starts.

If the superset scan agrees with the pdata-driven disassembly scan, the site
list is provably complete -- which is the precondition for patching the
handle encoding without leaving a silently-truncating decoder behind.
"""

from __future__ import annotations

import argparse
import struct

from capstone.x86 import X86_OP_MEM, X86_REG_RIP

from image import open_runtime


def candidates(img, target_rva: int) -> list[int]:
    """RVAs of dword positions in .text whose value is the disp32 for target."""
    out = []
    for lo, hi in img.text_ranges():
        data = img.read(lo, hi - lo)
        n = len(data)
        for p in range(0, n - 4):
            d = struct.unpack_from("<i", data, p)[0]
            if (lo + p) + 4 + d == target_rva:
                out.append(lo + p)
    return out


def confirm(img, disp_rva: int, window: int = 16):
    """Find the real instruction whose RIP operand lands on disp_rva.

    Decoding backwards, the SHORTEST candidate is usually wrong: it starts one
    byte late and swallows the REX prefix, so `lea rax, [rip+d]` is reported as
    `lea eax, [rip+d]` at address+1. The correct instruction is the one that
    starts EARLIEST, so all candidates are collected and the longest wins.
    """
    best = None
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
        if any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP for op in ins.operands):
            if best is None or ins.size > best.size:
                best = ins
    return best


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", default="SE")
    ap.add_argument("--target", required=True, help="target RVA in hex")
    a = ap.parse_args()

    img, _ = open_runtime(a.runtime)
    t = int(a.target, 16)
    cands = candidates(img, t)
    print(f"{a.runtime}: dword-superset candidates for rva {t:#x} (va {img.base+t:#x}): {len(cands)}")

    confirmed, unconfirmed = [], []
    for c in cands:
        ins = confirm(img, c)
        (confirmed if ins else unconfirmed).append((c, ins))

    print(f"  confirmed as real RIP-relative instructions: {len(confirmed)}")
    print(f"  unconfirmed (likely coincidental data bytes): {len(unconfirmed)}")
    fns = set()
    for c, ins in confirmed:
        f = img.func_containing(ins.address - img.base)
        fns.add(f.begin if f else -1)
        print(f"    {ins.address:#x}  {ins.mnemonic:<6} {ins.op_str}   [func {img.base + f.begin:#x}]" if f
              else f"    {ins.address:#x}  {ins.mnemonic:<6} {ins.op_str}   [NO PDATA FUNC]")
    n_orphan = sum(1 for _, ins in confirmed if img.func_containing(ins.address - img.base) is None)
    print(f"  distinct containing .pdata functions: {len(fns - {-1})}  (sites with no .pdata function: {n_orphan})")
    for c, _ in unconfirmed:
        print(f"    unconfirmed dword at rva {c:#x} (va {img.base+c:#x}) section={img.section_of(c)}")


if __name__ == "__main__":
    main()
