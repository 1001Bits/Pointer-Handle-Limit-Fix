"""Exhaustive whole-image audit of Skyrim's pointer-handle encoding sites.

Disassembles every byte of .text and reports, grouped by containing function:

  * every RIP-relative reference landing in the handle-manager data block
    (the 16 MB entry table plus the control globals immediately around it);
  * every instruction carrying one of the handle-encoding literals
    (index mask, age mask/increment, in-use bit, table entry count);
  * every shift by 11 (the object-side stored index) and bit-test of the
    in-use bit position.

This is the Skyrim analogue of the Starfield inline-decode audit: raising the
cap is only safe if the complete set of sites that encode/decode a handle is
known, because a missed site silently truncates an index and resolves to the
WRONG object rather than crashing.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from image import open_runtime

# Handle-encoding literals as they appear in stock code (see HANDLE_ENCODING.md).
LITERALS = {
    0x000FFFFF: "index mask (20 bits)",
    0x03F00000: "age mask (6 bits @ shift 20)",
    0x00100000: "age increment / entry count (1 << 20)",
    0x04000000: "in-use bit (1 << 26)",
    0x03FFFFFF: "index|age mask",
    0xFFF00000: "~index mask (upper)",
    0xFFEFFFFF: "clear age-inc",
    0xFBFFFFFF: "clear in-use bit",
    0x0000FFFF: None,  # noise, kept out
}
LITERALS = {k: v for k, v in LITERALS.items() if v}

# Object-side: BSHandleRefObject::_refCount packs [9:0] refcount, [10] handle-valid,
# [31:11] handle index.
OBJ_LITERALS = {
    0x000003FF: "refcount mask",
    0x00000400: "handle-valid bit",
    0xFFFFF800: "index field in refcount word",
    0x000007FF: "refcount|valid mask",
}


def scan(tag: str, table_rva: int, ctl_lo: int, ctl_hi: int, verbose: bool):
    img, _ = open_runtime(tag)
    table_end = table_rva + 0x100000 * 0x10

    hits_data: dict[int, list] = defaultdict(list)
    hits_lit: dict[int, list] = defaultdict(list)
    hits_shift: dict[int, list] = defaultdict(list)
    hits_bt: dict[int, list] = defaultdict(list)

    md = img.md

    def sweep():
        """Every instruction in .text, resyncing byte-by-byte past data/padding.

        capstone's disasm() stops at the first undecodable byte, so a single
        linear pass silently covers only the first few hundred bytes of the
        section. Resyncing is what makes this audit exhaustive.
        """
        for lo, hi in img.text_ranges():
            code = img.read(lo, hi - lo)
            pos = 0
            n = len(code)
            while pos < n:
                got = 0
                for ins in md.disasm(code[pos:], img.base + lo + pos):
                    got = ins.address + ins.size - (img.base + lo)
                    yield ins
                pos = got if got > pos else pos + 1

    for ins in sweep():
        rva = ins.address - img.base
        fn = img.func_containing(rva)
        key = fn.begin if fn else -1

        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                tgt = rva + ins.size + op.mem.disp
                if ctl_lo <= tgt < ctl_hi or table_rva <= tgt < table_end:
                    hits_data[key].append((rva, tgt, ins.mnemonic, ins.op_str))
            elif op.type == X86_OP_IMM:
                v = op.imm & 0xFFFFFFFF
                if v in LITERALS:
                    hits_lit[key].append((rva, v, LITERALS[v], ins.mnemonic, ins.op_str))
                elif v in OBJ_LITERALS and ins.mnemonic in ("and", "or", "test", "xor", "cmp"):
                    hits_lit[key].append((rva, v, OBJ_LITERALS[v], ins.mnemonic, ins.op_str))

        if ins.operands and ins.operands[-1].type == X86_OP_IMM:
            last = ins.operands[-1].imm
            if ins.mnemonic in ("shr", "shl", "sar") and last == 0x0B:
                hits_shift[key].append((rva, ins.mnemonic, ins.op_str))
            elif ins.mnemonic in ("bt", "bts", "btr", "btc") and last == 0x1A:
                hits_bt[key].append((rva, ins.mnemonic, ins.op_str))

    all_funcs = sorted(set(hits_data) | set(hits_lit) | set(hits_shift) | set(hits_bt))
    report = {
        "runtime": tag,
        "table_rva": table_rva,
        "functions": [],
        "totals": {
            "data_refs": sum(len(v) for v in hits_data.values()),
            "literals": sum(len(v) for v in hits_lit.values()),
            "shr11": sum(len(v) for v in hits_shift.values()),
            "bt26": sum(len(v) for v in hits_bt.values()),
        },
    }
    for f in all_funcs:
        report["functions"].append(
            {
                "func_rva": f,
                "func_va": img.base + f if f >= 0 else None,
                "data_refs": hits_data.get(f, []),
                "literals": hits_lit.get(f, []),
                "shr11": hits_shift.get(f, []),
                "bt26": hits_bt.get(f, []),
            }
        )

    print(f"===== {tag}: {report['totals']}  functions touched: {len(all_funcs)}")
    for entry in report["functions"]:
        f = entry["func_rva"]
        n = sum(len(entry[k]) for k in ("data_refs", "literals", "shr11", "bt26"))
        print(f"\n  func {f:#x} (va {img.base + f:#x})   hits={n}")
        for rva, tgt, m, o in entry["data_refs"]:
            what = "TABLE" if tgt >= table_rva else f"ctl+{tgt - ctl_lo:#x}"
            print(f"    DATA {rva:#x}  -> {tgt:#x} [{what}]   {m} {o}")
        for rva, v, why, m, o in entry["literals"]:
            print(f"    LIT  {rva:#x}  {v:#010x} {why:<32} {m} {o}")
        for rva, m, o in entry["shr11"]:
            print(f"    SH11 {rva:#x}  {m} {o}")
        for rva, m, o in entry["bt26"]:
            print(f"    BT26 {rva:#x}  {m} {o}")

    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", default="SE")
    ap.add_argument("--table", required=True, help="entry table RVA, hex")
    ap.add_argument("--ctl-before", type=lambda s: int(s, 0), default=0x40)
    ap.add_argument("--json", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    t = int(a.table, 16)
    rep = scan(a.runtime, t, t - a.ctl_before, t, a.verbose)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(rep, fh, indent=1)
