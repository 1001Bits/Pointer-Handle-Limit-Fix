"""Interactive-ish query helpers over the cached xref index."""

from __future__ import annotations

import sys

from xrefidx import build

TAG = "SE"
idx = build(TAG)
img = idx.img
B = img.base


def R(x):
    return x - B if x >= B else x


def callers(x, label=""):
    rva = R(x)
    hits = idx.calls.get(rva, [])
    print(f"== callers of {B+rva:#x} {label}: {len(hits)}")
    for site, f, m in hits:
        print(f"   {m:<4} {B+site:#x}  in func {B+f:#x}")
    return hits


def refs(x, label=""):
    rva = R(x)
    hits = idx.datarefs.get(rva, [])
    print(f"== rip-refs to {B+rva:#x} {label}: {len(hits)}")
    for site, f, m, o in hits:
        print(f"   {B+site:#x}  in func {B+f:#x}   {m} {o}")
    return hits


def dump(x, label=""):
    print(img.dump_func(R(x), label))


def calls_of(x):
    f = img.func_containing(R(x))
    if not f:
        print("no pdata func")
        return []
    t = idx.fcalls.get(f.begin, [])
    print(f"== func {B+f.begin:#x} calls {len(t)} targets")
    for c in t:
        print(f"   {B+c:#x}")
    return t


if __name__ == "__main__":
    for a in sys.argv[1:]:
        k, _, v = a.partition(":")
        v = int(v, 16)
        {"c": callers, "r": refs, "d": dump, "f": calls_of}[k](v)
        print()
