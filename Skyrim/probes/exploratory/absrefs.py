"""Look for ANY absolute reference to a target VA: imm64 loads and stored pointers.

Three independent checks:
  1. raw byte search of the whole file image for the 8-byte little-endian VA
     (catches `mov reg, imm64` and any qword pointer sitting in initialised data)
  2. raw byte search for the 4-byte little-endian low dword of the VA outside
     .text (catches a 32-bit absolute store, impossible >4GB but cheap to check)
  3. base-relocation walk: every DIR64 fixup is a place the loader rebases an
     absolute pointer.  If none of them holds the target, no stored pointer to
     the table exists anywhere in the image.
"""
from __future__ import annotations

import argparse
import struct

import pefile


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--rva", required=True)
    a = ap.parse_args()

    pe = pefile.PE(a.exe, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]]
    )
    base = pe.OPTIONAL_HEADER.ImageBase
    rva = int(a.rva, 16)
    va = base + rva
    data = bytes(pe.__data__)

    secs = [
        (s.Name.rstrip(b"\x00").decode(errors="replace"), s.VirtualAddress,
         max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData, s.SizeOfRawData)
        for s in pe.sections
    ]

    def sec_of_off(off):
        for n, v, vs, pr, rs in secs:
            if pr <= off < pr + rs:
                return n, v + (off - pr)
        return None, None

    print(f"exe={a.exe}\ntarget rva={rva:#x} va={va:#x}  filesize={len(data):#x}")

    pat8 = struct.pack("<Q", va)
    hits = []
    p = data.find(pat8)
    while p != -1:
        hits.append(p)
        p = data.find(pat8, p + 1)
    print(f"\n[1] qword {va:#x} occurrences in raw file: {len(hits)}")
    for h in hits:
        n, r = sec_of_off(h)
        print(f"    file off {h:#x}  section={n} rva={r:#x}" if r else f"    file off {h:#x} (outside sections)")

    pat4 = struct.pack("<I", va & 0xFFFFFFFF)
    n4 = 0
    p = data.find(pat4)
    while p != -1:
        n4 += 1
        p = data.find(pat4, p + 1)
    print(f"\n[2] dword {va & 0xFFFFFFFF:#010x} occurrences in raw file: {n4}"
          f"  (informational - the low dword also appears as an ordinary constant/disp)")

    total = 0
    match = 0
    for blk in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []) or []:
        for e in blk.entries:
            if e.type == 0:  # ABSOLUTE padding
                continue
            total += 1
            if e.type != 10:  # DIR64
                continue
            r = e.rva
            for n, v, vs, pr, rs in secs:
                if v <= r < v + rs:
                    off = pr + (r - v)
                    if off + 8 <= len(data):
                        val = struct.unpack_from("<Q", data, off)[0]
                        if val == va:
                            match += 1
                            print(f"    RELOC-HELD POINTER at rva {r:#x} (section {n}) -> {val:#x}")
                    break
    print(f"\n[3] base relocations examined: {total}; DIR64 slots holding {va:#x}: {match}")


if __name__ == "__main__":
    main()
