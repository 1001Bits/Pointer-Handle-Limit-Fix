"""Extract ASCII/UTF-16 strings from the image with RVAs, and grep them."""

from __future__ import annotations

import argparse
import re

from image import open_runtime


def ascii_strings(img, minlen=4):
    out = []
    for name, va, vsz, praw, rsz in img._sections:
        if name in (".text",) or not rsz:
            continue
        data = img.data[praw : praw + rsz]
        for m in re.finditer(rb"[\x20-\x7e]{%d,}\x00" % minlen, data):
            out.append((va + m.start(), m.group()[:-1].decode("ascii")))
    return out


def utf16_strings(img, minlen=4):
    out = []
    for name, va, vsz, praw, rsz in img._sections:
        if name in (".text",) or not rsz:
            continue
        data = img.data[praw : praw + rsz]
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}\x00\x00" % minlen, data):
            out.append((va + m.start(), m.group()[:-2].decode("utf-16-le")))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", default="SE")
    ap.add_argument("--wide", action="store_true")
    ap.add_argument("-i", "--icase", action="store_true")
    ap.add_argument("pattern")
    a = ap.parse_args()
    img, _ = open_runtime(a.runtime)
    rx = re.compile(a.pattern, re.I if a.icase else 0)
    strs = utf16_strings(img) if a.wide else ascii_strings(img)
    n = 0
    for rva, s in strs:
        if rx.search(s):
            print(f"{img.base+rva:#x}  {s!r}")
            n += 1
    print(f"-- {n} matches of {len(strs)} strings")


if __name__ == "__main__":
    main()
