# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

A **source and reverse-engineering evidence snapshot**, not a buildable project.
It holds two independent native plugins that raise the Creation Engine's
pointer-handle cap to 4,194,304 handles, plus the evidence that they are safe:

| Path | Contents |
|---|---|
| `Starfield/` | SFSE plugin for `Starfield.exe` 1.16.244 (2^21 → 2^22). Single translation unit, Ghidra audit probes. |
| `Skyrim/` | SKSE/SKSEVR plugin for four exact Skyrim runtimes (2^20 → 2^22). Modular C++, generated patch tables, Python probe pipeline. |
| `Docs/` | Cross-project technical write-up of the engine limit and the Starfield fix. |

**There is no build system in this tree.** CMake files, vcpkg manifests, compiled
DLLs, INIs, release packages, game executables, Address Library databases, and raw
decompiler output are all deliberately excluded. You cannot compile either plugin
from here, and generated release artifacts must not be added. The only executable
workflow is the Python probe pipeline.

## Commands

### Verify the Skyrim deliverables (the closest thing to a test suite)

Requires Python 3.12, `probes/requirements.txt` (capstone, numpy, pefile), and the
user's own exact executables + Address Library files listed in `Skyrim/HASHES.md`.
Point at them first — tags are `SE` (1.5.97), `AE` (1.6.1170), `GOG` (1.6.1179),
`VR` (1.4.15):

```powershell
$env:SHCR_SE_EXE='C:\path\to\SkyrimSE-1.5.97.exe'
$env:SHCR_SE_ADDRLIB='C:\path\to\version-1-5-97-0.bin'
# ...SHCR_AE_*, SHCR_GOG_*, SHCR_VR_* likewise (VR's Address Library is a .csv)
```

From `Skyrim/probes`:

```powershell
python -m pip install -r requirements.txt
python test_patch.py --runtime SE --patch ../artifacts/patch_SE.json   # one runtime
python verify_deliverable.py --offline
```

`test_patch.py` must print `PASS` for each of SE/AE/GOG/VR; `verify_deliverable.py`
must print `ALL CONSISTENT`. `--offline` is **mandatory** here — the DLL/package
half of the verifier has nothing to check in a source-only tree.

### Regenerate the Skyrim patch tables

Full deterministic pipeline and the four per-runtime `--table/--head/--tail/--lock`
RVAs are in `Skyrim/probes/README.md`. Order matters:

```
gen_patchtable.py  ->  artifacts/patch_{SE,AE,GOG,VR}.json
gen_cpp.py         ->  src/PatchTable.g.h
gen_patch_docs.py  ->  docs/patch-sites/*.md
test_patch.py + verify_deliverable.py --offline
```

### Starfield audit probes

Ghidra scripts, run manually: import the exact `Starfield.exe`, add
`Starfield/probes/` to the Script Manager paths, run `McpScalar2.java`, then
`McpMaskCtx.java` with `0x1fffff` and `0x200000` as script arguments. See
`Starfield/probes/README.md`.

## Architecture

### The two implementations are structurally different — this is the central fact

Do not try to make them symmetric.

**Starfield's handle manager is data-driven.** Capacity, index mask, and generation
unit live in mutable instance fields (`+0x50` pool, `+0x58/+0x5C` free head/tail,
`+0x60` free counter, `+0x64` capacity/generation unit, `+0x68` index mask). Raising
the cap is: allocate a 64 MiB pool, thread its free list, and write those six fields
during the quiet window between manager construction (~1 s) and first handle
allocation (~38 s). **Zero instructions are patched**, so there are correctly no
`patch_*.json`, no `sites_*.json`, and no generated `PatchTable.g.h` on that side.
That absence is documented deliberately — never fabricate an equivalent artifact.

**Skyrim's constants are inlined by the optimizer**, and its 22-bit index does not
fit the 21 spare bits in `BSHandleRefObject::_refCount`, so the complete index needs
a sidecar in `NiRefObject::_pad0C`. Raising the cap therefore means 2,714 exact-byte
instruction patches across four runtimes, plus a 64 MiB table allocated within
signed-32-bit RIP displacement range of every `lea` that addresses it.

`Docs/Starfield-Handle-Cap-Raise.md` explains the engine background behind this
split; `Skyrim/DESIGN.md` is authoritative for the Skyrim side.

### Generated artifacts are never hand-edited

`patch_*.json` is the byte-level source of truth, bound to `exe_sha256`. Both
`src/PatchTable.g.h` and `docs/patch-sites/*.md` are projections of it, and
`verify_deliverable.py` byte-compares the committed copies against a fresh render
and requires every mutation/evidence record ID to appear exactly once. Editing any
of the three by hand breaks verification — regenerate instead.

### Runtime safety model

Both plugins are built around refusing rather than guessing:

- Exact-stock verification before any write (Skyrim: `memcmp` of every original
  instruction plus a pristine-pool check under the manager lock; Starfield: all six
  manager fields must hold their exact stock values).
- Transactional apply with post-write verification and rollback. Skyrim escalates an
  unprovable rollback to `TerminateProcess` rather than continue with mixed handle
  encodings; Starfield reverts to stock and no-ops.
- Exact binary profiles, **not** version families — an unrecognised build is logged
  and left untouched.
- `Skyrim/src/main.cpp` is orchestration only; patching, monitoring, and diagnostics
  live in separately reviewable modules (`PatchTransaction`, `TableMonitor`,
  `GenerationDiagnostic`, …). `DESIGN.md` treats that boundary as an invariant.

### Evidence discipline

This is the repository's defining convention: every claim is bound to an exact
SHA-256 input, and each document owns exactly one role (`DESIGN.md` = architecture,
`docs/patch-sites/` = generated bytes, `HASHES.md` = inputs, `VERIFY.md` = how to
re-check). Limits are stated explicitly and **must not be softened when editing
docs**:

- VR 1.4.15 is offline-only — never describe it as live-tested.
- GOG 1.6.1179 has a recorded startup/resize pass but no live above-cap result.
- The Starfield literal audit was run against 1.16.236 while the shipped source
  targets 1.16.244; a hash-bound 1.16.244 audit is open work.
- Starfield has no offline simulator.

## Gotchas

- **Source hashes in `HASHES.md` are LF-normalized.** `core.autocrlf=true`, so
  hashing a checked-out file directly will not match. Compare with
  `tr -d '\r' < file | sha256sum`.
- **Trailing-immediate trap:** a RIP displacement is relative to the end of the
  *whole* instruction. Use `truescan.py`, not `find_riprefs.py`, for targets
  referenced by instructions that carry a trailing immediate (`mov dword [rip+d],
  imm32`). `Skyrim/probes/README.md` documents why.
- **`probes/exploratory/`** (~50 scripts) is unmaintained evidence of what was
  checked during review. Several hardcode paths and take ad-hoc arguments. Read
  before running; do not treat as part of the pipeline.
- The generator **fails rather than guesses** on unreviewed capacity-shaped literals
  and unrecognised sidecar shapes. A new raise is a review task, not a widened
  regex.
