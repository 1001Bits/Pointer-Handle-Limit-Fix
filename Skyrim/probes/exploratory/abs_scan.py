"""Absolute-pointer and end-pointer scans over the whole image (all sections)."""
from __future__ import annotations

import numpy as np

from image import open_runtime

BASE = 0x140000000
TABLE = 0x1EC47C0
N = 0x100000
TABLE_END = TABLE + N * 0x10
HEAD, TAIL, LOCK = 0x1EC47AC, 0x1EC47B0, 0x1EC47B8

img, _ = open_runtime("SE")

print("=== A. any qword ANYWHERE in the image that lands in [head, table_end] ===")
hit = 0
for name, va, vsz, praw, rsz in img._sections:
    if rsz < 8:
        continue
    d = np.frombuffer(img.read(va, rsz), dtype=np.uint8)
    w = np.lib.stride_tricks.sliding_window_view(d, 8)
    q = np.zeros(w.shape[0], dtype=np.uint64)
    for i in range(8):
        q |= w[:, i].astype(np.uint64) << np.uint64(8 * i)
    lo, hi = np.uint64(BASE + HEAD), np.uint64(BASE + TABLE_END)
    for p in np.flatnonzero((q >= lo) & (q <= hi)):
        v = int(q[p])
        print(f"  {name} rva {va+int(p):#x} = {v:#x}  (table+{v - BASE - TABLE:#x})")
        hit += 1
print(f"  total: {hit}")

print("\n=== B. any dword ANYWHERE equal to the table RVA or VA-low32 ===")
hit = 0
for name, va, vsz, praw, rsz in img._sections:
    if rsz < 4:
        continue
    d = np.frombuffer(img.read(va, rsz), dtype=np.uint8)
    w = np.lib.stride_tricks.sliding_window_view(d, 4).astype(np.uint32)
    dw = (w[:, 0] | (w[:, 1] << 8) | (w[:, 2] << 16) | (w[:, 3] << 24)).astype(np.uint32)
    for want, lbl in ((TABLE, "table RVA"), ((BASE + TABLE) & 0xFFFFFFFF, "table VA low32")):
        idx = np.flatnonzero(dw == np.uint32(want))
        for p in idx[:40]:
            print(f"  {name} rva {va+int(p):#x} = {want:#x}  [{lbl}]")
            hit += 1
        if idx.size > 40:
            print(f"  ... {idx.size} total in {name} for {lbl}")
print(f"  total printed: {hit}")

print("\n=== C. disp32 in .text targeting table_end / table_end-16 (range iteration) ===")
hit = 0
for lo, hi in img.text_ranges():
    d = np.frombuffer(img.read(lo, hi - lo), dtype=np.uint8)
    w = np.lib.stride_tricks.sliding_window_view(d, 4).astype(np.uint32)
    vals = (w[:, 0] | (w[:, 1] << 8) | (w[:, 2] << 16) | (w[:, 3] << 24)).astype(np.uint32)
    pos = np.arange(vals.size, dtype=np.uint32)
    for lbl, t in (("table_end", TABLE_END), ("table_end-0x10", TABLE_END - 0x10),
                   ("head", HEAD), ("tail", TAIL), ("lock", LOCK)):
        for tail in range(0, 5):
            tgt = (vals + np.uint32(lo) + pos + np.uint32(4 + tail)).astype(np.uint32)
            m = np.flatnonzero(tgt == np.uint32(t))
            if lbl.startswith("table_end"):
                for p in m:
                    print(f"  {lbl}: dword rva {lo+int(p):#x} (va {BASE+lo+int(p):#x}) tail={tail}")
                    hit += 1
            else:
                if m.size:
                    print(f"  {lbl}: {m.size} dword candidates at tail={tail}")
print(f"  table_end candidates: {hit}")

print("\n=== D. .reloc entries inside .data near the manager block ===")
import pefile
img.pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
tot = 0
near = 0
for b in getattr(img.pe, "DIRECTORY_ENTRY_BASERELOC", []) or []:
    for e in b.entries:
        tot += 1
        if HEAD - 0x100 <= e.rva <= TABLE_END + 0x100:
            near += 1
            print(f"  reloc at rva {e.rva:#x} type={e.type}")
print(f"  total relocs {tot}, near the manager block: {near}")
