"""Analyse skse64_steam_loader.dll: how/when does it call StartSKSE?"""
from __future__ import annotations

import bisect
import struct
import sys
from pathlib import Path

import capstone
import pefile

OUT = Path(sys.argv[1])
DLL = r"C:\Games\Skyrim SE\skse64_steam_loader.dll"

pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories(directories=[
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
])
BASE = pe.OPTIONAL_HEADER.ImageBase
raw = pe.__data__
secs = [(s.Name.rstrip(b"\x00").decode(errors="replace"), s.VirtualAddress,
         max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData, s.SizeOfRawData)
        for s in pe.sections]
funcs = sorted({(e.struct.BeginAddress, e.struct.EndAddress)
                for e in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", [])
                if e.struct.EndAddress > e.struct.BeginAddress})
fstarts = [b for b, _ in funcs]

L = []
def p(s=""):
    L.append(str(s))

def read(rva, n):
    for _, va, vsz, praw, rsz in secs:
        if va <= rva < va + vsz:
            off = rva - va
            if off >= rsz:
                return b"\x00" * n
            take = max(0, min(n, rsz - off))
            return bytes(raw[praw + off: praw + off + take]) + b"\x00" * (n - take)
    raise ValueError(hex(rva))

def func_of(rva):
    i = bisect.bisect_right(fstarts, rva) - 1
    if i < 0:
        return None
    b, e = funcs[i]
    return b if b <= rva < e else None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

p(f"{DLL} base={BASE:#x} entry={BASE+pe.OPTIONAL_HEADER.AddressOfEntryPoint:#x} size={len(raw)}")
for n, va, vsz, praw, rsz in secs:
    p(f"  {n:<10} rva={va:#x} vsz={vsz:#x} raw={rsz:#x}")
tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
p(f"  TLS dir: {'yes' if tls else 'no'}")
if tls:
    cb = tls.struct.AddressOfCallBacks
    p(f"    callbacks array at {cb:#x}")
    off = cb - BASE
    for i in range(8):
        v = struct.unpack_from("<Q", read(off + i * 8, 8))[0]
        p(f"      cb[{i}] = {v:#x}")
        if v == 0:
            break

p("\n== imports")
for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    names = [imp.name.decode() if imp.name else f"ord{imp.ordinal}" for imp in entry.imports]
    p(f"  {entry.dll.decode()}: {names}")

p("\n== exports")
ex = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
if ex:
    for s in ex.symbols:
        p(f"  {s.name} @ {BASE+s.address:#x}")

p("\n== ascii strings of interest")
for n, va, vsz, praw, rsz in secs:
    if not rsz:
        continue
    d = bytes(raw[praw:praw + rsz])
    for needle in (b"StartSKSE", b"skse64_", b"SkyrimSE", b"steam", b"Steam", b".dll"):
        s = 0
        while True:
            i = d.find(needle, s)
            if i < 0:
                break
            # widen
            st = i
            while st > 0 and 0x20 <= d[st - 1] < 0x7f:
                st -= 1
            en = i
            while en < len(d) and 0x20 <= d[en] < 0x7f:
                en += 1
            p(f"  {BASE+va+st:#x} ({n}): {d[st:en].decode('latin1')!r}")
            s = i + 1

p("\n== full disasm of all pdata functions")
for b, e in funcs:
    p(f"--- func {BASE+b:#x} .. {BASE+e:#x}")
    for ins in md.disasm(read(b, e - b), BASE + b):
        p(f"   {ins.address:#x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}")

OUT.write_text("\n".join(L), encoding="utf-8")
print("wrote", OUT, len(L))
