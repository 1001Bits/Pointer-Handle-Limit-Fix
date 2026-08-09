"""Table-interior RIP refs, cross-checked against real instruction boundaries."""
from __future__ import annotations
import numpy as np
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
from image import open_runtime
from alt import interior_refs, linear

if __name__ == "__main__":
    img, _ = open_runtime("SE")
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        conf = interior_refs(img)
    print(buf.getvalue().splitlines()[1])
    print(buf.getvalue().splitlines()[2])

    starts = set()
    for kind, sb, ins in linear(img):
        starts.add(ins.address - img.base)
    print(f"valid instruction starts from linear sweep: {len(starts)}")

    real = [(s, r, t, i) for s, r, t, i in conf if (i.address - img.base) in starts]
    print(f"interior refs whose instruction begins at a REAL boundary: {len(real)}")
    nonbase = [x for x in real if x[2] != 0x1EC47C0]
    print(f"  of which target table+k with k != 0: {len(nonbase)}")
    for s, r, t, i in nonbase:
        f = img.func_containing(i.address - img.base)
        fs = f"pdata {img.base+f.begin:#x}" if f else "NO-PDATA"
        print(f"    [{s}] {i.address:#x} -> table+{t-0x1EC47C0:#x}  {i.mnemonic} {i.op_str}  [{fs}]")
