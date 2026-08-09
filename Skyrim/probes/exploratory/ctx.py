"""Dump linear context around arbitrary VAs."""
from __future__ import annotations
import sys
from image import open_runtime

if __name__ == "__main__":
    img, _ = open_runtime("SE")
    back = 0x60
    fwd = 0x70
    for s in sys.argv[1:]:
        if s.startswith("b="):
            back = int(s[2:], 0); continue
        if s.startswith("f="):
            fwd = int(s[2:], 0); continue
        va = int(s, 16)
        rva = va - img.base
        f = img.func_containing(rva)
        print("=" * 70)
        print(f"{va:#x}  pdata={'%#x..%#x' % (img.base+f.begin, img.base+f.end) if f else 'NONE'}")
        for ins in img.disasm(rva - back, back + fwd):
            m = " <<<" if ins.address == va else ""
            print(f"  {ins.address:#012x}  {ins.bytes.hex():<20} {ins.mnemonic:<7} {ins.op_str}{m}")
        print()
