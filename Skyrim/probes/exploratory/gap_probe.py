"""Task 1 + coverage: dump the no-pdata table-ref sites and measure .pdata coverage."""
from __future__ import annotations
import sys
from image import open_runtime

TABLE = 0x1EC47C0

NOPDATA = [
    0x140132B23, 0x1403E06D2, 0x1403EF0E4, 0x1404344B3,
    0x1406783D7, 0x140774013, 0x1408E2302, 0x14148BD72,
]


def coverage(img):
    print("=== .text coverage by .pdata ===")
    for lo, hi in img.text_ranges():
        covered = 0
        gaps = []
        cur = lo
        for f in img.funcs:
            if f.end <= lo or f.begin >= hi:
                continue
            b, e = max(f.begin, lo), min(f.end, hi)
            if b > cur:
                gaps.append((cur, b))
            cur = max(cur, e)
        if cur < hi:
            gaps.append((cur, hi))
        covered = (hi - lo) - sum(e - b for b, e in gaps)
        big = sorted(gaps, key=lambda g: g[1] - g[0], reverse=True)
        print(f"  .text {lo:#x}..{hi:#x}  size={hi-lo:#x}  covered={covered:#x} "
              f"({100.0*covered/(hi-lo):.3f}%)  gaps={len(gaps)} gapbytes={hi-lo-covered:#x}")
        print("   largest gaps:")
        for b, e in big[:15]:
            print(f"     {img.base+b:#x}..{img.base+e:#x}  {e-b:#x} bytes")
    return


def dump_sites(img):
    for va in NOPDATA:
        rva = va - img.base
        f = img.func_containing(rva)
        print("=" * 78)
        print(f"SITE va={va:#x} rva={rva:#x}  pdata_func={f}")
        # nearest pdata function before and after
        import bisect
        i = bisect.bisect_right(img._starts, rva) - 1
        prev = img.funcs[i] if i >= 0 else None
        nxt = img.funcs[i + 1] if i + 1 < len(img.funcs) else None
        if prev:
            print(f"  prev pdata func {img.base+prev.begin:#x}..{img.base+prev.end:#x} "
                  f"(ends {rva-prev.end:#x} bytes before site)")
        if nxt:
            print(f"  next pdata func {img.base+nxt.begin:#x}..{img.base+nxt.end:#x} "
                  f"(starts {nxt.begin-rva:#x} bytes after site)")
        lo = max(0, rva - 0xA0)
        print(f"  --- linear disasm {img.base+lo:#x} .. {img.base+rva+0xA0:#x}")
        for ins in img.disasm(lo, 0x140):
            mark = "  <<<<" if ins.address == va else ""
            print(f"    {ins.address:#012x}  {ins.bytes.hex():<20} {ins.mnemonic:<8} {ins.op_str}{mark}")
        print()


if __name__ == "__main__":
    img, _ = open_runtime("SE")
    if "cov" in sys.argv:
        coverage(img)
    if "sites" in sys.argv:
        dump_sites(img)
