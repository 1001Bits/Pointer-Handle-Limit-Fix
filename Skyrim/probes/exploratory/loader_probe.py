"""Strings + relevant code from skse64_loader.exe to find how/when
InitSKSESteamLoader gets invoked in the game process."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pefile

OUT = Path(sys.argv[1])
EXE = r"C:\Games\Skyrim SE\skse64_loader.exe"

pe = pefile.PE(EXE, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
raw = pe.__data__
L = []
def p(s=""):
    L.append(str(s))

p(f"{EXE} base={pe.OPTIONAL_HEADER.ImageBase:#x}")
p("\n== imports")
for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    names = [imp.name.decode() if imp.name else f"ord{imp.ordinal}" for imp in entry.imports]
    p(f"  {entry.dll.decode()}: {names}")

p("\n== ascii strings (len>=6)")
for m in re.finditer(rb"[\x20-\x7e]{6,}", raw):
    s = m.group().decode("latin1")
    p(f"  {m.start():#x}: {s}")

OUT.write_text("\n".join(L), encoding="utf-8")
print("wrote", OUT, len(L))
