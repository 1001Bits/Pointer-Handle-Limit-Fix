"""Dump pdata-bounded disassembly for a list of RVAs/VAs of one runtime."""
from __future__ import annotations

import argparse

from image import open_runtime


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", default="SE")
    ap.add_argument("addrs", nargs="+", help="hex VA (0x14...) or RVA")
    ap.add_argument("--max", type=lambda s: int(s, 0), default=0x600)
    ap.add_argument("--span", type=lambda s: int(s, 0), default=0,
                    help="force a fixed byte span from the address, ignoring pdata bounds")
    a = ap.parse_args()

    img, _ = open_runtime(a.runtime)
    for s in a.addrs:
        v = int(s, 16)
        rva = v - img.base if v >= img.base else v
        if a.span:
            f = img.func_containing(rva)
            b = f"[pdata {img.base+f.begin:#x}..{img.base+f.end:#x}]" if f else "[no pdata entry]"
            print(f"--- {a.runtime} rva={rva:#x} va={img.base+rva:#x}  {b}  FORCED SPAN {a.span:#x}")
            print(img.fmt(img.disasm(rva, a.span)))
            print()
            continue
        f = img.func_containing(rva)
        if f and (f.end - f.begin) <= a.max:
            print(img.dump_func(rva, title=a.runtime))
        else:
            hdr = f"--- {a.runtime} rva={rva:#x} va={img.base+rva:#x}"
            if f:
                hdr += f"  [pdata {img.base+f.begin:#x}..{img.base+f.end:#x}, {f.end-f.begin} bytes -- TRUNCATED to {a.max:#x}]"
                print(hdr)
                print(img.fmt(img.disasm(f.begin, a.max)))
            else:
                hdr += "  [no pdata entry]"
                print(hdr)
                print(img.fmt(img.disasm(rva, a.max)))
        print()


if __name__ == "__main__":
    main()
