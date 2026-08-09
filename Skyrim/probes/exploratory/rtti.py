"""Locate MSVC RTTI vtables for a class given its mangled type-descriptor name."""

from __future__ import annotations

import argparse
import struct

from image import open_runtime


def find_type_descriptor(img, name: str):
    """Return RVA of the TypeDescriptor whose name string equals `name`."""
    nb = name.encode() + b"\x00"
    out = []
    for sname, va, vsz, praw, rsz in img._sections:
        if not rsz:
            continue
        d = img.data[praw : praw + rsz]
        p = 0
        while True:
            p = d.find(nb, p)
            if p < 0:
                break
            out.append(va + p - 0x10)  # name field is at +0x10 in TypeDescriptor
            p += 1
    return out


def find_vtables(img, td_rva: int):
    """COL has pTypeDescriptor (image-relative) at +0x0C; vtable ptr is COL+8."""
    cols = []
    for sname, va, vsz, praw, rsz in img._sections:
        if not rsz:
            continue
        d = img.data[praw : praw + rsz]
        for i in range(0, len(d) - 4, 4):
            if struct.unpack_from("<I", d, i)[0] == td_rva:
                cols.append((sname, va + i - 0x0C))
    vts = []
    for sname, col_rva in cols:
        col_va = img.base + col_rva
        for s2, va2, vsz2, praw2, rsz2 in img._sections:
            if not rsz2:
                continue
            d2 = img.data[praw2 : praw2 + rsz2]
            for i in range(0, len(d2) - 8, 8):
                if struct.unpack_from("<Q", d2, i)[0] == col_va:
                    vts.append((s2, va2 + i + 8, col_rva))
    return vts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", default="SE")
    ap.add_argument("--slots", type=int, default=24)
    ap.add_argument("name")
    a = ap.parse_args()
    img, _ = open_runtime(a.runtime)
    tds = find_type_descriptor(img, a.name)
    print(f"type descriptors: {[hex(img.base+t) for t in tds]}")
    for td in tds:
        for sect, vt_rva, col in find_vtables(img, td):
            print(f"  vtable {img.base+vt_rva:#x} (sect {sect}, COL {img.base+col:#x})")
            for i in range(a.slots):
                fn = struct.unpack_from("<Q", img.read(vt_rva + i * 8, 8), 0)[0]
                if fn < img.base or fn > img.base + 0x4000000:
                    break
                print(f"    [{i:2}] {fn:#x}")


if __name__ == "__main__":
    main()
