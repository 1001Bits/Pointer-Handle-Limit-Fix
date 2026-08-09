"""Decoder-independent byte-level hunts (no disassembly, so nothing can hide).

1. disp32 in .text that targets ANY byte of the table (base or interior).
2. absolute 32/64-bit values anywhere in the image that land in the table,
   the control block, or one entry past the end (range-iteration end pointer).
3. base relocations that would fix up such a pointer at load time.
"""
from __future__ import annotations

import struct

import numpy as np

from image import open_runtime

BASE = 0x140000000
TABLE = 0x1EC47C0
N = 0x100000
TABLE_END = TABLE + N * 0x10           # 0x2ec47c0
HEAD, TAIL, LOCK = 0x1EC47AC, 0x1EC47B0, 0x1EC47B8

img, _ = open_runtime("SE")
print("sections:")
for name, va, vsz, praw, rsz in img._sections:
    print(f"  {name:<10} rva {va:#010x}..{va+vsz:#010x}  raw {rsz:#x}")

# --------------------------------------------------------------------------- #
print("\n=== 1. disp32 in .text targeting anywhere in [table, table_end) ===")
hits = []
for lo, hi in img.text_ranges():
    d = np.frombuffer(img.read(lo, hi - lo), dtype=np.uint8)
    w = np.lib.stride_tricks.sliding_window_view(d, 4).astype(np.uint32)
    vals = (w[:, 0] | (w[:, 1] << 8) | (w[:, 2] << 16) | (w[:, 3] << 24)).astype(np.uint32)
    pos = np.arange(vals.size, dtype=np.uint32)
    # instruction-end is unknown; try every plausible end offset after the disp32
    for tail in range(0, 5):
        tgt = (vals + np.uint32(lo) + pos + np.uint32(4) + np.uint32(tail)).astype(np.int64)
        m = np.flatnonzero((tgt >= TABLE) & (tgt < TABLE_END))
        for p in m:
            hits.append((int(lo + p), int(tgt[p]), tail))
base_hits = [h for h in hits if h[1] == TABLE]
int_hits = [h for h in hits if h[1] != TABLE]
print(f"  raw candidate dword positions: {len(hits)}  (target==base: {len(base_hits)}, interior: {len(int_hits)})")

# confirm interior candidates by decoding backwards for a real rip-rel insn
print("\n  --- interior candidates, confirmed by decode ---")
confirmed = []
for pos, tgt, tail in sorted(set(int_hits)):
    ok = None
    for back in range(2, 10):
        s = pos - back
        try:
            ins = next(iter(img.disasm(s, back + 4 + tail + 8)), None)
        except ValueError:
            continue
        if ins is None:
            continue
        if ins.size == back + 4 + tail:
            for t in img.rip_targets(ins):
                if t == tgt:
                    ok = ins
        if ok:
            break
    if ok:
        confirmed.append((pos, tgt, ok))
        print(f"    CONFIRMED {BASE+ok.address-BASE:#x} -> table+{tgt-TABLE:#x}   {ok.mnemonic} {ok.op_str}")
print(f"  interior confirmed: {len(confirmed)} of {len(set(int_hits))} candidates")

# --------------------------------------------------------------------------- #
print("\n=== 2. absolute 32/64-bit values pointing at the table / control block ===")
targets64 = {}
for k in (0, 0x10, 0x100, N * 0x10, N * 0x10 - 0x10):
    targets64[BASE + TABLE + k] = f"table+{k:#x}"
targets64[BASE + HEAD] = "head"
targets64[BASE + TAIL] = "tail"
targets64[BASE + LOCK] = "lock"
found_any = False
for name, va, vsz, praw, rsz in img._sections:
    if not rsz:
        continue
    d = np.frombuffer(img.read(va, rsz), dtype=np.uint8)
    if d.size < 8:
        continue
    w8 = np.lib.stride_tricks.sliding_window_view(d, 8).astype(np.uint64)
    q = np.zeros(w8.shape[0], dtype=np.uint64)
    for i in range(8):
        q |= w8[:, i].astype(np.uint64) << np.uint64(8 * i)
    # any qword landing inside the table or the control block
    m = np.flatnonzero((q >= np.uint64(BASE + HEAD)) & (q < np.uint64(BASE + TABLE_END + 0x10)))
    for p in m:
        found_any = True
        print(f"  QWORD {name} rva {va+int(p):#x} = {int(q[p]):#x} "
              f"({targets64.get(int(q[p]), 'table+%#x' % (int(q[p]) - BASE - TABLE))})")
    w4 = np.lib.stride_tricks.sliding_window_view(d, 4).astype(np.uint32)
    dw = (w4[:, 0] | (w4[:, 1] << 8) | (w4[:, 2] << 16) | (w4[:, 3] << 24)).astype(np.uint32)
    for want, lbl in ((TABLE, "table rva"), (BASE + TABLE, "table va lo32 (0x41ec47c0)")):
        for p in np.flatnonzero(dw == np.uint32(want & 0xFFFFFFFF)):
            print(f"  DWORD {name} rva {va+int(p):#x} = {want & 0xFFFFFFFF:#x}  [{lbl}]")
            found_any = True
if not found_any:
    print("  (none)")

# --------------------------------------------------------------------------- #
print("\n=== 3. base relocations ===")
try:
    import pefile
    img.pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
    nrel = 0
    for b in getattr(img.pe, "DIRECTORY_ENTRY_BASERELOC", []) or []:
        nrel += len(b.entries)
    print(f"  relocation entries: {nrel}")
except Exception as e:
    print(f"  reloc parse failed: {e}")

# --------------------------------------------------------------------------- #
print("\n=== 4. end-of-table pointer constants (range iteration) ===")
# the 'end' of the raised table is a different value; look for anything
# encoding table_end as disp32 in .text
for lo, hi in img.text_ranges():
    d = np.frombuffer(img.read(lo, hi - lo), dtype=np.uint8)
    w = np.lib.stride_tricks.sliding_window_view(d, 4).astype(np.uint32)
    vals = (w[:, 0] | (w[:, 1] << 8) | (w[:, 2] << 16) | (w[:, 3] << 24)).astype(np.uint32)
    pos = np.arange(vals.size, dtype=np.uint32)
    for lbl, t in (("table_end", TABLE_END), ("table_end-16", TABLE_END - 0x10)):
        for tail in range(0, 5):
            tgt = (vals + np.uint32(lo) + pos + np.uint32(4) + np.uint32(tail)).astype(np.int64)
            for p in np.flatnonzero(tgt == t):
                print(f"  {lbl}: dword at rva {lo+int(p):#x} (va {BASE+lo+int(p):#x}) tail={tail}")
print("  (done)")
