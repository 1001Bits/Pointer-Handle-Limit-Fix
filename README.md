# Pointer Handle Limit Fix

Public source and reverse-engineering evidence snapshot for the Starfield and
Skyrim pointer-handle-cap projects.

| Directory | Contents |
|---|---|
| [`Starfield/`](Starfield/) | Starfield 1.16.244 runtime source, the available 1.16.236 Ghidra audit probes, exact input hashes, and verification limits. |
| [`Skyrim/`](Skyrim/README.md) | Skyrim runtime source, [design](Skyrim/DESIGN.md), [per-site original/replacement disassembly](Skyrim/docs/patch-sites/README.md), [exact input hashes](Skyrim/HASHES.md), and [offline verification instructions](Skyrim/VERIFY.md). |

No game executable, Address Library database, compiled DLL, package, or raw
decompiler output is included. Users must supply their own legally obtained
game and Address Library files when running the probes.

The two implementations are structurally different. Skyrim patches many
compile-time/inlined handle operations and therefore has generated
`patch_*.json`, `sites_*.json`, and `PatchTable.g.h` artifacts. Starfield swaps
six mutable manager fields and has no equivalent generated instruction-patch
table. That absence is documented rather than replaced with a fabricated
artifact.
