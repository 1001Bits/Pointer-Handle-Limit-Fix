"""One-shot probe for the patch-window question."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from image import open_runtime
from find_callers import rel_sites, abs_refs

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "window_probe.txt")

img, lib = open_runtime("SE")
L = []
def p(s=""):
    L.append(str(s))

p(f"image {img.path} base={img.base:#x}")
p("sections:")
for name, va, vsz, praw, rsz in img._sections:
    p(f"  {name:<10} rva={va:#010x} vsz={vsz:#x} raw={rsz:#x}  va={img.base+va:#x}..{img.base+va+vsz:#x}")
p()

def callers(rva, label, do_abs=True):
    p(f"== callers of {label} rva={rva:#x} va={img.base+rva:#x}")
    rs = rel_sites(img, rva)
    if not rs:
        p("   (no e8/e9 rel32 sites)")
    for site, op in rs:
        f = img.func_containing(site)
        ins = img.disasm(site, 8)
        txt = f"{ins[0].mnemonic} {ins[0].op_str}" if ins else "?"
        loc = f"func va={img.base+f.begin:#x}" if f else "[NO PDATA FUNC]"
        p(f"   {img.base+site:#x}  {txt}   in {loc}")
    if do_abs:
        ar = abs_refs(img, img.base + rva)
        if not ar:
            p("   (no absolute qword refs)")
        for a, sec in ar:
            p(f"   ABS ptr at va={img.base+a:#x} rva={a:#x} section={sec}")
    p()

callers(0x5bccb0, "free-list init")
callers(0x5ae010, "caller-of-free-list-init (Main::Init?)")
callers(0x125d0, "CRT static init for handle table")

# CRT initializer array neighbourhood: find the abs ptr to 0x1400125d0 and dump around it
for a, sec in abs_refs(img, img.base + 0x125d0):
    p(f"== CRT init table neighbourhood around rva={a:#x} ({sec})")
    lo = a - 0x80
    data = img.read(lo, 0x100)
    for i in range(0, 0x100, 8):
        v = struct.unpack_from("<Q", data, i)[0]
        mark = "  <== 0x1400125d0" if v == img.base + 0x125d0 else ""
        p(f"   {img.base+lo+i:#x}: {v:#018x}{mark}")
    p()

p("== free-list init 0x1405bccb0")
p(img.dump_func(0x5bccb0))
p()
p("== CRT static init 0x1400125d0")
p(img.dump_func(0x125d0))
p()

OUT.write_text("\n".join(L), encoding="utf-8")
print("wrote", OUT, len(L), "lines")
