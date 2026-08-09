"""Exhaustive-as-possible instruction sweep of .text, independent of .pdata.

Code blobs = (a) every .pdata function body, plus (b) every non-int3 run in the
gaps between .pdata functions.  Disassembling both gives coverage of leaf
functions with no unwind data, which a pure .pdata sweep silently drops.
"""
from __future__ import annotations

import re

from image import open_runtime

# a gap run ends at >=2 int3 or >=8 zero bytes
_RUN = re.compile(rb"(?:(?!\xcc\xcc)(?!\x00{8}).)+", re.S)


def code_blobs(img):
    """[(start_rva, end_rva)] covering pdata bodies + int3-delimited gap runs."""
    blobs = []
    for lo, hi in img.text_ranges():
        fns = sorted(
            ((f.begin, min(f.end, hi)) for f in img.funcs if lo <= f.begin < hi),
            key=lambda t: t[0],
        )
        cur = lo
        for b, e in fns:
            if b > cur:
                blobs.extend(_split_gap(img, cur, b))
            blobs.append((b, e))
            cur = max(cur, e)
        if cur < hi:
            blobs.extend(_split_gap(img, cur, hi))
    return blobs


def _split_gap(img, lo, hi):
    if hi <= lo:
        return []
    data = img.read(lo, hi - lo)
    out = []
    for m in _RUN.finditer(data):
        s, e = m.start(), m.end()
        # trim leading/trailing padding bytes
        while s < e and data[s] in (0xCC, 0x00):
            s += 1
        while e > s and data[e - 1] in (0xCC, 0x00):
            e -= 1
        if e - s >= 2:
            out.append((lo + s, lo + e))
    return out


def sweep(img):
    """Yield capstone instructions over all code blobs (deduped by address)."""
    seen = set()
    md = img.md
    for b, e in code_blobs(img):
        if e <= b:
            continue
        try:
            code = img.read(b, e - b)
        except ValueError:
            continue
        for ins in md.disasm(code, img.base + b):
            if ins.address in seen:
                continue
            seen.add(ins.address)
            yield ins


if __name__ == "__main__":
    img, _ = open_runtime("SE")
    blobs = code_blobs(img)
    tot = sum(e - b for b, e in blobs)
    print(f"blobs={len(blobs)} bytes={tot:#x}")
    n = sum(1 for _ in sweep(img))
    print(f"instructions={n}")
