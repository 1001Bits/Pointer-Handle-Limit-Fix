"""Byte-level hunt for handle-encoding fingerprints anywhere in .text.

The age mask 0x03F00000 is a rare, distinctive constant: in SkyrimSE.exe 1.5.97
every .pdata function that contains it ALSO references the handle entry table.
So scanning the raw bytes for its little-endian encoding finds handle code even
where .pdata has no entry (leaf functions and tail-call thunks -- exactly where
a real validator was already found at 0x1408e2300).

Any hit that falls outside the known handle-manager regions is a candidate
missed decoder and must be reviewed by hand before the cap can be raised.
"""

from __future__ import annotations

import argparse
import json

import numpy as np

from image import open_runtime
from logical_funcs import build_chunk_to_root, logical_ranges


def byte_hits(img, pattern: bytes) -> list[int]:
    out = []
    for lo, hi in img.text_ranges():
        data = np.frombuffer(img.read(lo, hi - lo), dtype=np.uint8)
        pat = np.frombuffer(pattern, dtype=np.uint8)
        if data.size < pat.size:
            continue
        cand = np.flatnonzero(data[: data.size - pat.size + 1] == pat[0])
        for k in range(1, pat.size):
            if cand.size == 0:
                break
            cand = cand[data[cand + k] == pat[k]]
        out.extend(int(lo + p) for p in cand)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", default="SE")
    ap.add_argument("--sites", required=True)
    ap.add_argument("--patterns", default="3f00000,fffff,fff00000,fbffffff,fc0fffff")
    a = ap.parse_args()

    img, _ = open_runtime(a.runtime)
    sites = json.load(open(a.sites))
    T = sites["table_rva"]
    known_funcs = {
        f["func_rva"]
        for f in sites["functions"]
        if any(d[1] == T for d in f["data"]) or {0xFFFFF, 0x3F00000} <= {l[1] for l in f["lit"]}
    }
    root_map = build_chunk_to_root(img)
    ranges = logical_ranges(img, root_map)

    covered: list[tuple[int, int]] = []
    for r in known_funcs:
        covered.extend(ranges.get(root_map.get(r, r), [(r, r)]))
    covered.sort()

    def is_covered(rva: int) -> bool:
        return any(b <= rva < e for b, e in covered)

    for pat_hex in a.patterns.split(","):
        v = int(pat_hex, 16)
        pat = v.to_bytes(4, "little")
        hits = byte_hits(img, pat)
        outside = [h for h in hits if not is_covered(h)]
        print(f"\n== literal {v:#010x}  bytes {pat.hex()}  raw byte hits in .text: {len(hits)}")
        print(f"   inside known handle regions: {len(hits) - len(outside)}   OUTSIDE: {len(outside)}")
        shown = 0
        for h in outside:
            fn = img.func_containing(h)
            tag = f"pdata {img.base + fn.begin:#x}" if fn else "NO PDATA"
            if fn and fn.begin in known_funcs:
                continue
            shown += 1
            if shown <= 60:
                # show the instruction that most plausibly owns this dword
                ctx = ""
                for back in range(2, 12):
                    ins = img.disasm(h - back, back + 8)
                    if ins and ins[0].address - img.base == h - back and h < (h - back) + ins[0].size:
                        ctx = f"{ins[0].mnemonic} {ins[0].op_str}"
                        break
                print(f"     {img.base + h:#x}  [{tag}]  {ctx}")
        if shown > 60:
            print(f"     ... and {shown - 60} more")


if __name__ == "__main__":
    main()
