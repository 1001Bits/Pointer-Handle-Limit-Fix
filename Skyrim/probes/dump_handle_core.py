"""Dump the Skyrim pointer-handle manager core functions for SE and AE.

Resolves the CommonLibSSE-NG relocation IDs for the handle manager and prints
disassembly of each, so the index/age encoding and the location of every
compile-time constant can be read directly off the instruction stream.
"""

from __future__ import annotations

from addrlib import open_runtime

# CommonLibSSE-NG RELOCATION_ID(SE, AE) for the handle manager surface.
IDS = {
    "GetHandle (BSPointerHandleManagerInterface::GetHandle)": (15967, 16212),
    "GetSmartPointer (non-const, clears handle)": (12785, 12922),
    "GetSmartPointer (const)": (12204, 12332),
    "IsValid (BSPointerHandleManager::IsValid)": (75454, 77239),
}

DATA_IDS = {
    "handle entries array (Entry[0x100000])": (514478, 400622),
    "handle manager lock (BSReadWriteLock)": (514477, 400621),
}


def main() -> None:
    for tag in ("SE", "AE"):
        img, lib = open_runtime(tag)
        idx = 0 if tag == "SE" else 1
        print("=" * 78)
        print(f"RUNTIME {tag}   {img.path}")
        print("=" * 78)

        for label, ids in DATA_IDS.items():
            ident = ids[idx]
            rva = lib.rva(ident)
            print(f"\n-- {label}\n   id={ident}  rva={rva:#x}  va={img.base + rva:#x}  section={img.section_of(rva)}")

        for label, ids in IDS.items():
            ident = ids[idx]
            rva = lib.rva(ident)
            print(f"\n-- {label}\n   id={ident}  rva={rva:#x}  va={img.base + rva:#x}  section={img.section_of(rva)}")
            print(img.dump(rva, 0x300))
        print()


if __name__ == "__main__":
    main()
