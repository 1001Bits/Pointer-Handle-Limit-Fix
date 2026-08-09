"""Hunt for handle encode/decode sites the region-based patch table would miss.

Region set in patch_SE.json is derived ONLY from table-reference sites, so any
decoder that never loads the table base is structurally invisible to it.
"""
from __future__ import annotations
import json, struct, sys
from collections import defaultdict

import numpy as np
import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from image import open_runtime

TABLE = 0x1EC47C0
TABLE_END = TABLE + 0x1000000
HEAD, TAIL, LOCK = 0x1EC47AC, 0x1EC47B0, 0x1EC47B8

LITS = {
    0x000FFFFF: "index_mask",
    0x03F00000: "age_mask",
    0x00100000: "age_inc/count",
    0x01000000: "table_bytes",
    0xFC0FFFFF: "clear_age",
    0xFFF00000: "clear_next",
    0xFBFFFFFF: "clear_inuse",
    0x04000000: "inuse_bit",
    0x03FFFFFF: "index|age",
}


def load_regions():
    d = json.load(open("../artifacts/patch_SE.json"))
    return sorted(tuple(r) for r in d["regions"]), d


def sections(img):
    return img._sections


def byte_hits_all(img, pattern: bytes):
    """(section_name, rva) for every occurrence of pattern in every section's raw data."""
    pat = np.frombuffer(pattern, dtype=np.uint8)
    out = []
    for name, va, vsz, praw, rsz in img._sections:
        if not rsz:
            continue
        data = np.frombuffer(img.data[praw:praw + rsz], dtype=np.uint8)
        if data.size < pat.size:
            continue
        cand = np.flatnonzero(data[: data.size - pat.size + 1] == pat[0])
        for k in range(1, pat.size):
            if cand.size == 0:
                break
            cand = cand[data[cand + k] == pat[k]]
        out.extend((name, va + int(p)) for p in cand)
    return out


def confirm_insn(img, byte_rva, window=18):
    """Longest instruction starting <= byte_rva-1 that covers byte_rva."""
    best = None
    for back in range(1, window):
        start = byte_rva - back
        try:
            lst = img.disasm(start, back + 16)
        except ValueError:
            continue
        if not lst:
            continue
        ins = lst[0]
        if ins.address - img.base != start:
            continue
        if not (start <= byte_rva < start + ins.size):
            continue
        if best is None or ins.size > best.size:
            best = ins
    return best


def cmd_literals(img, regions):
    def inreg(r):
        return any(b <= r < e for b, e in regions)

    exec_secs = {".text"}
    print("=== whole-IMAGE byte scan for each handle literal ===")
    print(f"(regions from patch_SE.json: {len(regions)})\n")
    for val, name in LITS.items():
        pat = struct.pack("<I", val)
        hits = byte_hits_all(img, pat)
        bysec = defaultdict(int)
        for s, _ in hits:
            bysec[s] += 1
        outside = [(s, r) for s, r in hits if s in exec_secs and not inreg(r)]
        print(f"-- {val:#010x} {name:<14} total={len(hits)} bysec={dict(bysec)} "
              f"text-outside-regions={len(outside)}")
        conf = []
        for s, r in outside:
            ins = confirm_insn(img, r)
            if ins is None:
                continue
            # instruction must actually carry the value as imm or disp
            got = False
            for op in ins.operands:
                if op.type == X86_OP_IMM and (op.imm & 0xFFFFFFFF) == val:
                    got = True
                elif op.type == X86_OP_MEM and op.mem.base != X86_REG_RIP and (op.mem.disp & 0xFFFFFFFF) == val:
                    got = True
            if got:
                conf.append((r, ins))
        print(f"   -> decode as real instructions carrying {val:#x}: {len(conf)}")
        for r, ins in conf:
            f = img.func_containing(ins.address - img.base)
            fs = f"func {img.base+f.begin:#x}" if f else "NO-PDATA"
            print(f"      {ins.address:#x}  {ins.bytes.hex():<18} {ins.mnemonic:<6} {ins.op_str}   [{fs}]")
        print()


def cmd_bt(img, regions):
    """All bt/bts/btr/btc with imm8 0x1a (in-use bit) anywhere in .text."""
    def inreg(r):
        return any(b <= r < e for b, e in regions)

    print("=== byte scan: 0F BA /4../7 imm8=0x1A  (bt-family on in-use bit 26) ===")
    found = []
    for name, va, vsz, praw, rsz in img._sections:
        if name != ".text" or not rsz:
            continue
        d = img.data[praw:praw + rsz]
        arr = np.frombuffer(d, dtype=np.uint8)
        c = np.flatnonzero(arr[:-3] == 0x0F)
        c = c[arr[c + 1] == 0xBA]
        keep = []
        for p in c:
            modrm = arr[p + 2]
            reg = (modrm >> 3) & 7
            if reg < 4:
                continue
            if modrm >= 0xC0:  # register form: imm8 at p+3
                if arr[p + 3] == 0x1A:
                    keep.append((int(p), 4))
            else:
                # memory forms: try decode
                keep.append((int(p), None))
        for p, _ in keep:
            rva = va + p
            ins = confirm_insn(img, rva + 1)
            if ins is None:
                continue
            if ins.mnemonic not in ("bt", "bts", "btr", "btc"):
                continue
            ops = ins.operands
            if not ops or ops[-1].type != X86_OP_IMM or ops[-1].imm != 0x1A:
                continue
            found.append((ins.address - img.base, ins))
    print(f"  total bt-family imm 0x1A in .text: {len(found)}")
    out = [(r, i) for r, i in found if not inreg(r)]
    print(f"  OUTSIDE patch regions: {len(out)}")
    for r, ins in out:
        f = img.func_containing(r)
        fs = f"func {img.base+f.begin:#x}" if f else "NO-PDATA"
        print(f"    {ins.address:#x}  {ins.bytes.hex():<14} {ins.mnemonic:<5} {ins.op_str}  [{fs}]")
    print()


def cmd_abs(img):
    """Absolute 8-byte and 4-byte references to the table / table_end / interior."""
    print("=== absolute references ===")
    base = img.base
    targets = {
        "table_base": base + TABLE,
        "table_end": base + TABLE_END,
        "head": base + HEAD,
        "tail": base + TAIL,
        "lock": base + LOCK,
    }
    for nm, va in targets.items():
        pat = struct.pack("<Q", va)
        hits = byte_hits_all(img, pat)
        print(f"  qword {nm:<10} {va:#x}: {len(hits)} hits {[(s,hex(base+r)) for s,r in hits][:12]}")
    # any qword pointing INTO the table (aligned 8) anywhere
    print("  scanning all sections for any qword in [table, table_end) ...")
    lo, hi = base + TABLE, base + TABLE_END
    tot = 0
    for name, va, vsz, praw, rsz in img._sections:
        if not rsz:
            continue
        n = rsz // 8 * 8
        a = np.frombuffer(img.data[praw:praw + n], dtype='<u8')
        m = np.flatnonzero((a >= lo) & (a < hi))
        if m.size:
            tot += m.size
            for i in m[:20]:
                print(f"    {name} rva {va + int(i)*8:#x} -> {int(a[i]):#x} (table+{int(a[i])-lo:#x})")
    print(f"  total aligned qwords pointing into table: {tot}")
    # imm32 absolute (only meaningful for the low dword; table VA > 4G so no imm32)
    print()


def cmd_riprefs(img, rva, label):
    """Confirmed RIP-relative refs to an arbitrary RVA, image-wide code sections."""
    out = []
    for name, va, vsz, praw, rsz in img._sections:
        if not rsz:
            continue
        data = np.frombuffer(img.data[praw:praw + rsz], dtype=np.uint8)
        if data.size < 4:
            continue
        w = np.lib.stride_tricks.sliding_window_view(data, 4).astype(np.uint32)
        vals = w[:, 0] | (w[:, 1] << 8) | (w[:, 2] << 16) | (w[:, 3] << 24)
        pos = np.arange(vals.size, dtype=np.uint32)
        want = (np.uint32(rva) - (np.uint32(va) + pos + np.uint32(4))).astype(np.uint32)
        for p in np.flatnonzero(vals == want):
            out.append((name, va + int(p)))
    conf = []
    for s, r in out:
        ins = confirm_insn(img, r)
        if ins is None:
            continue
        if any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP
               and (ins.address - img.base) + ins.size + op.mem.disp == rva
               for op in ins.operands):
            conf.append((s, r, ins))
    print(f"=== RIP refs to {label} rva={rva:#x} va={img.base+rva:#x}: "
          f"{len(out)} raw dwords, {len(conf)} confirmed ===")
    for s, r, ins in conf:
        f = img.func_containing(ins.address - img.base)
        fs = f"func {img.base+f.begin:#x}" if f else "NO-PDATA"
        print(f"    [{s}] {ins.address:#x}  {ins.mnemonic:<6} {ins.op_str}  [{fs}]")
    return conf


if __name__ == "__main__":
    img, _ = open_runtime("SE")
    regions, meta = load_regions()
    for c in sys.argv[1:]:
        if c == "lits":
            cmd_literals(img, regions)
        elif c == "bt":
            cmd_bt(img, regions)
        elif c == "abs":
            cmd_abs(img)
        elif c == "end":
            cmd_riprefs(img, TABLE_END, "TABLE_END")
        elif c == "ctl":
            for r, n in ((HEAD, "HEAD"), (TAIL, "TAIL"), (LOCK, "LOCK")):
                cmd_riprefs(img, r, n)
