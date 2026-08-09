"""Find every e8/e9 rel32 call/jmp whose target is a given RVA, plus any
absolute qword references (vtable / function-table entries)."""

from __future__ import annotations

import argparse
import struct

from image import open_runtime


def rel_sites(img, target_rva: int):
    out = []
    for lo, hi in img.text_ranges():
        data = img.read(lo, hi - lo)
        n = len(data)
        start = 0
        while True:
            i = data.find(b"\xe8", start)
            j = data.find(b"\xe9", start)
            if i < 0 and j < 0:
                break
            if i < 0 or (0 <= j < i):
                i = j
            if i > n - 5:
                break
            d = struct.unpack_from("<i", data, i + 1)[0]
            if (lo + i + 5) + d == target_rva:
                out.append((lo + i, data[i]))
            start = i + 1
    return out


def abs_refs(img, target_va: int):
    needle = struct.pack("<Q", target_va)
    out = []
    for name, va, vsz, praw, rsz in img._sections:
        if not rsz:
            continue
        data = img.read(va, rsz)
        start = 0
        while True:
            i = data.find(needle, start)
            if i < 0:
                break
            out.append((va + i, name))
            start = i + 1
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", default="SE")
    ap.add_argument("--target", required=True)
    ap.add_argument("--abs", action="store_true")
    a = ap.parse_args()

    img, _ = open_runtime(a.runtime)
    t = int(a.target, 16)
    print(f"{a.runtime}: callers of rva {t:#x} (va {img.base+t:#x})")
    for rva, op in rel_sites(img, t):
        f = img.func_containing(rva)
        ins = img.disasm(rva, 8)
        txt = f"{ins[0].mnemonic} {ins[0].op_str}" if ins else "?"
        loc = f"in func va={img.base+f.begin:#x}" if f else "[NO PDATA FUNC]"
        print(f"  site va={img.base+rva:#x}  [{txt}]  {loc}")
    if a.abs:
        print("  absolute qword refs:")
        for rva, sec in abs_refs(img, img.base + t):
            print(f"    va={img.base+rva:#x} rva={rva:#x} section={sec}")


if __name__ == "__main__":
    main()
