"""Step 1: resolve AE handle-manager globals from the Address Library."""
from __future__ import annotations
import sys
from addrlib import open_runtime, RUNTIMES

IDS = {
    "SE": {"entries": 514478, "lock": 514477},
    "AE": {"entries": 400622, "lock": 400621},
}

for tag in sys.argv[1:] or ["SE", "AE"]:
    img, lib = open_runtime(tag)
    print(f"== {tag} {RUNTIMES[tag]['version']}  base={img.base:#x}  addrlib ver={lib.version} ids={len(lib.id_to_offset)}")
    for name, ident in IDS[tag].items():
        try:
            rva = lib.rva(ident)
        except KeyError:
            print(f"   {name:10} id {ident}: NOT PRESENT")
            continue
        print(f"   {name:10} id {ident:>7} -> rva {rva:#x}  va {img.base+rva:#x}  section={img.section_of(rva)}")
    # dump the 64 bytes before the entry table and first 64 of it
    ent = lib.rva(IDS[tag]["entries"])
    lo = ent - 0x40
    blob = img.read(lo, 0x80)
    for i in range(0, 0x80, 16):
        va = img.base + lo + i
        words = " ".join(f"{int.from_bytes(blob[i+j:i+j+4],'little'):08x}" for j in range(0, 16, 4))
        tag2 = "  <== ENTRY TABLE" if lo + i == ent else ""
        print(f"     {va:#012x}  {words}  sec={img.section_of(lo+i)}{tag2}")
    print()
