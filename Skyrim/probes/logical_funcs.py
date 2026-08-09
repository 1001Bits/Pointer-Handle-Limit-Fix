"""Group .pdata chunks into logical functions via UNWIND_INFO chaining.

MSVC splits one C++ function into several RUNTIME_FUNCTION entries (hot/cold
chunks, funclets). Chunks other than the primary one set UNW_FLAG_CHAININFO
and carry a trailing RUNTIME_FUNCTION pointing at their parent. Following that
chain is what turns 117k pdata entries into real function boundaries.

This matters here because a handle-decode sequence can live in a chunk whose
own pdata entry does not contain the `lea` that loads the table base -- so
grouping by raw pdata entry would silently under-include patch sites.
"""

from __future__ import annotations

import struct

UNW_FLAG_CHAININFO = 0x4


def build_chunk_to_root(img) -> dict[int, int]:
    """Map every pdata chunk begin-RVA to the RVA of its logical function."""
    # chunk -> parent (one hop)
    parent: dict[int, int] = {}
    for f in img.funcs:
        ui = _unwind_addr(img, f.begin)
        if ui is None:
            continue
        try:
            ver_flags = img.read(ui, 1)[0]
        except ValueError:
            continue
        flags = ver_flags >> 3
        if not (flags & UNW_FLAG_CHAININFO):
            continue
        count = img.read(ui + 2, 1)[0]
        # unwind codes are 2 bytes each, padded to an even count
        codes_end = ui + 4 + 2 * ((count + 1) & ~1)
        try:
            pbegin = struct.unpack_from("<I", img.read(codes_end, 4))[0]
        except ValueError:
            continue
        if pbegin:
            parent[f.begin] = pbegin

    # collapse chains
    root: dict[int, int] = {}

    def resolve(b: int, depth: int = 0) -> int:
        if depth > 16:
            return b
        p = parent.get(b)
        if p is None or p == b:
            return b
        return resolve(p, depth + 1)

    for f in img.funcs:
        root[f.begin] = resolve(f.begin)
    return root


_unwind_cache: dict[int, int] = {}


def _unwind_addr(img, begin_rva: int) -> int | None:
    if not _unwind_cache:
        for e in getattr(img.pe, "DIRECTORY_ENTRY_EXCEPTION", []) or []:
            _unwind_cache[e.struct.BeginAddress] = e.struct.UnwindData
    return _unwind_cache.get(begin_rva)


def logical_ranges(img, root_map: dict[int, int]) -> dict[int, list[tuple[int, int]]]:
    """root RVA -> sorted list of (begin, end) chunk ranges."""
    out: dict[int, list[tuple[int, int]]] = {}
    for f in img.funcs:
        r = root_map.get(f.begin, f.begin)
        out.setdefault(r, []).append((f.begin, f.end))
    for v in out.values():
        v.sort()
    return out


if __name__ == "__main__":
    from image import open_runtime

    img, _ = open_runtime("SE")
    rm = build_chunk_to_root(img)
    lr = logical_ranges(img, rm)
    chained = sum(1 for k, v in rm.items() if v != k)
    print(f"pdata chunks={len(img.funcs)} logical functions={len(lr)} chained chunks={chained}")
    # sanity: the GetSmartPointer chunks seen earlier should share a root
    for probe in (0x1328CA, 0x132946, 0x1329F1, 0x132A6D, 0x1329D0, 0x14257A, 0x1425F6, 0x142550):
        print(f"  chunk {probe:#x} -> root {rm.get(probe, None) and hex(rm[probe])}")
