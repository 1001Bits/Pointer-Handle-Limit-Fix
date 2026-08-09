"""Fast, authoritative handle-site scan driven by the PE exception directory.

Every non-leaf x64 function has a RUNTIME_FUNCTION entry giving exact
[begin,end) bounds, so disassembling function-by-function covers real code
without resyncing through padding, jump tables, or data islands.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from image import open_runtime

LITERALS = {
    0x000FFFFF: "index mask (20b)",
    0xFC0FFFFF: "clear-age mask",
    0x01000000: "table byte size (16 MB)",
    0x03F00000: "age mask (6b @20)",
    0x00100000: "age inc / entry count (1<<20)",
    0x04000000: "in-use bit (1<<26)",
    0x03FFFFFF: "index|age",
    0xFFF00000: "~index",
    0xFBFFFFFF: "~in-use",
    0x000003FF: "refcount mask (obj)",
    0x00000400: "handle-valid bit (obj)",
    0xFFFFF800: "obj index field",
    0x000007FF: "refcount|valid (obj)",
}
OBJ_ONLY = {0x000003FF, 0x00000400, 0xFFFFF800, 0x000007FF}
OBJ_MNEM = {"and", "or", "test", "xor", "cmp", "mov"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", default="SE")
    ap.add_argument("--table", required=True)
    ap.add_argument("--ctl-before", type=lambda s: int(s, 0), default=0x80)
    ap.add_argument("--ctl-after", type=lambda s: int(s, 0), default=0x80)
    ap.add_argument("--json")
    a = ap.parse_args()

    img, _ = open_runtime(a.runtime)
    table = int(a.table, 16)
    table_end = table + 0x100000 * 0x10
    ctl_lo, ctl_hi = table - a.ctl_before, table + a.ctl_after

    data_hits = defaultdict(list)
    lit_hits = defaultdict(list)
    shift_hits = defaultdict(list)
    bt_hits = defaultdict(list)

    md = img.md
    text = img.text_ranges()

    def in_text(rva):
        return any(lo <= rva < hi for lo, hi in text)

    total_ins = 0
    for fi, f in enumerate(img.funcs):
        if not in_text(f.begin):
            continue
        try:
            code = img.read(f.begin, f.end - f.begin)
        except ValueError:
            continue
        for ins in md.disasm(code, img.base + f.begin):
            total_ins += 1
            rva = ins.address - img.base
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    tgt = rva + ins.size + op.mem.disp
                    if ctl_lo <= tgt < ctl_hi or table <= tgt < table_end:
                        data_hits[f.begin].append([rva, tgt, ins.mnemonic, ins.op_str])
                elif op.type == X86_OP_IMM:
                    v = op.imm & 0xFFFFFFFF
                    if v in LITERALS:
                        if v in OBJ_ONLY and ins.mnemonic not in OBJ_MNEM:
                            continue
                        lit_hits[f.begin].append([rva, v, LITERALS[v], ins.mnemonic, ins.op_str])
            if ins.operands and ins.operands[-1].type == X86_OP_IMM:
                last = ins.operands[-1].imm
                if ins.mnemonic in ("shr", "shl", "sar") and last == 0x0B:
                    shift_hits[f.begin].append([rva, ins.mnemonic, ins.op_str])
                elif ins.mnemonic in ("bt", "bts", "btr", "btc") and last in (0x1A, 0x0A):
                    bt_hits[f.begin].append([rva, ins.mnemonic, ins.op_str])
        if fi % 20000 == 0:
            print(f"  ... {fi}/{len(img.funcs)} funcs, {total_ins} insns", file=sys.stderr)

    funcs = sorted(set(data_hits) | set(lit_hits) | set(shift_hits) | set(bt_hits))
    print(f"===== {a.runtime}  instructions={total_ins}  functions_with_hits={len(funcs)}")
    print(
        f"  totals: data={sum(map(len, data_hits.values()))} "
        f"lit={sum(map(len, lit_hits.values()))} "
        f"shr11={sum(map(len, shift_hits.values()))} "
        f"bt26={sum(map(len, bt_hits.values()))}"
    )

    report = {"runtime": a.runtime, "table_rva": table, "instructions": total_ins, "functions": []}
    for f in funcs:
        e = {
            "func_rva": f,
            "func_va": img.base + f,
            "data": data_hits.get(f, []),
            "lit": lit_hits.get(f, []),
            "shr11": shift_hits.get(f, []),
            "bt": bt_hits.get(f, []),
        }
        report["functions"].append(e)

    # Print only the functions that touch the manager data block or the
    # manager-side literals; object-side refcount literals alone are noise.
    core = [
        e
        for e in report["functions"]
        if e["data"] or any(l[1] not in OBJ_ONLY for l in e["lit"])
    ]
    print(f"\n  CORE (touch manager data or manager literals): {len(core)} functions\n")
    for e in core:
        print(f"  func {e['func_va']:#x}  (rva {e['func_rva']:#x})")
        for rva, tgt, m, o in e["data"]:
            what = "TABLE_BASE" if tgt == table else ("TABLE+%#x" % (tgt - table)) if tgt > table else "ctl-%#x" % (table - tgt)
            print(f"    DATA {img.base+rva:#x} -> {img.base+tgt:#x} [{what}]  {m} {o}")
        for rva, v, why, m, o in e["lit"]:
            print(f"    LIT  {img.base+rva:#x}  {v:#010x} {why:<28} {m} {o}")
        for rva, m, o in e["shr11"]:
            print(f"    SH11 {img.base+rva:#x}  {m} {o}")
        for rva, m, o in e["bt"]:
            print(f"    BT   {img.base+rva:#x}  {m} {o}")
        print()

    if a.json:
        with open(a.json, "w") as fh:
            json.dump(report, fh, indent=1)
        print(f"  wrote {a.json}")


if __name__ == "__main__":
    main()
