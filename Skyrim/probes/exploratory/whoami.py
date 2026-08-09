"""Given function VAs, find which vtables reference them and name the class via RTTI."""
from __future__ import annotations

import struct
import sys

from image import open_runtime


def build_index(img):
    """Map: COL VA -> RTTI mangled name; and list of (rva, qword) over data sections."""
    # type descriptors: ".?AV...@@" strings preceded by 0x10 bytes
    tds = {}
    for sname, va, vsz, praw, rsz in img._sections:
        if not rsz:
            continue
        d = img.data[praw:praw + rsz]
        p = 0
        while True:
            p = d.find(b".?AV", p)
            if p < 0:
                break
            e = d.find(b"\x00", p)
            if 0 < e - p < 200:
                tds[va + p - 0x10] = d[p:e].decode("ascii", "replace")
            p = e + 1 if e > p else p + 1
    # COLs: dword at COL+0x0C == td rva
    cols = {}
    for sname, va, vsz, praw, rsz in img._sections:
        if not rsz:
            continue
        d = img.data[praw:praw + rsz]
        for i in range(0, len(d) - 4, 4):
            v = struct.unpack_from("<I", d, i)[0]
            if v in tds:
                cols[img.base + va + i - 0x0C] = tds[v]
    return cols


def main():
    img, _ = open_runtime(sys.argv[1] if len(sys.argv) > 1 else "SE")
    targets = [int(a, 16) for a in sys.argv[2:]]
    cols = build_index(img)
    print(f"indexed {len(cols)} complete-object-locators")

    for sname, va, vsz, praw, rsz in img._sections:
        if not rsz or sname == ".text":
            continue
        d = img.data[praw:praw + rsz]
        for i in range(0, len(d) - 8, 8):
            q = struct.unpack_from("<Q", d, i)[0]
            if q in targets:
                slot_va = img.base + va + i
                # walk back to find the vtable head (preceded by a COL pointer)
                head = None
                for back in range(0, 0x400, 8):
                    j = i - back
                    if j < 8:
                        break
                    prev = struct.unpack_from("<Q", d, j - 8)[0]
                    if prev in cols:
                        head = (img.base + va + j, cols[prev], back // 8)
                        break
                print(f"  {q:#x} referenced at {slot_va:#x} ({sname})" +
                      (f"   vtable {head[0]:#x} slot[{head[2]}] class={head[1]}" if head else "   [no COL found]"))


if __name__ == "__main__":
    main()
