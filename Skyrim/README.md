# Skyrim Handle Cap Raise

An experimental SKSE/SKSEVR plugin that raises Skyrim's process-local
reference-handle table from 1,048,576 to 4,194,304 entries on four exact
runtime profiles.

The raised raw handle is still a complete 32-bit value: it contains a 22-bit
table index and six-bit generation. The separate object-side cache preserves
the 10-bit intrusive reference count and bit-10 handle-valid flag by storing
the complete cached index in existing `NiRefObject::_pad0C` storage. See the
[design document](DESIGN.md#three-distinct-representations) for the three
representations and their exact layouts.

> **Experimental status:** SE 1.5.97 and AE 1.6.1170 have live high-handle
> evidence. GOG 1.6.1179 has a live startup/resize result but no live above-cap
> result. VR 1.4.15 remains offline-only. A missed private decoder can alias an
> object without crashing, so exact offline verification does not replace
> representative in-game and native-plugin testing.

## Start here

| Document | Purpose |
|---|---|
| [DESIGN.md](DESIGN.md) | Authoritative current architecture, invariants, safety model, compatibility boundary, and source-module map. |
| [Generated patch-site audit](docs/patch-sites/README.md) | Original and replacement bytes/disassembly for all 2,714 cap-raise mutation records and the 20 optional generation-wrap call redirects. Runtime-derived displacements are shown as exact templates and formulas. |
| [Exact profiles and input hashes](HASHES.md) | Exact executable and Address Library inputs to which the generated profiles are bound. |
| [Regenerate and verify](VERIFY.md) | Source-snapshot prerequisites, all four offline simulations, and deterministic deliverable verification. |
| [Probe pipeline](probes/README.md#the-maintained-pipeline) | Complete generation criteria, commands, and maintained-versus-exploratory tooling boundary. |

## Current implementation

```text
Raw handle:       index [21:0] | generation [27:22] | [31:28] unused
Table entry word: index [21:0] | generation [27:22] | bit 28 in use
Object metadata:  refcount [9:0] | bit 10 valid | low 21 cached index bits
Object +0x2C:     complete 22-bit cached table index
```

- The replacement table is 64 MiB and retains the 16-byte entry stride.
- All table references are retargeted to a runtime allocation within signed
  32-bit RIP-relative displacement range.
- Every write is gated by exact original bytes and an exact pristine-pool
  check under Skyrim's manager lock.
- Installation is transactional and verified; a post-write failure restores
  and verifies every original instruction and manager value.
- The default generation-wrap detector adds a 16 MiB counter array and one
  4 KiB executable relay page. Its assignment hook performs no allocation,
  attribution, formatting, or logging.
- Loading the DLL always attempts the cap raise. There is no public enable or
  dry-run switch.

## Supported profiles and evidence

| Runtime | Offline patch simulation | Recorded live evidence |
|---|---|---|
| SE 1.5.97.0 | Complete | Approximately 3.5M occupied handles; high-bit lookup, bounded release, and exact-slot reuse passed. |
| AE 1.6.1170.0 | Complete | Approximately 3.5M occupied handles; high-bit lookup, bounded release, and exact-slot reuse passed. |
| GOG 1.6.1179.0 | Complete | Exact-profile startup and 4M resize passed; no live above-cap result. |
| VR 1.4.15.0 | Complete | None; offline-only. |

Other runtime versions are logged and left untouched. These are exact binary
profiles, not version-family aliases. This repository publishes the source,
exact static evidence, and offline verifier; private live-test captures are not
redistributed as part of this source snapshot.

## Compatibility boundary

The plugin preserves 32-bit handle storage/calling width, object sizes and
offsets, the 10-bit reference-count field, valid bit 10, and all six generation
bits. It changes the private raw-handle encoding, table layout/address, and the
meaning of `NiRefObject::_pad0C`; “ABI-compatible” without those qualifications
would be misleading.

Ordinary engine/CommonLib-style code that treats a handle as an opaque
`uint32_t` and calls Skyrim to create or resolve it is the intended path. A DLL
requires review if it:

- privately decodes raw handles using the original masks;
- treats `_refCount >> 11` as the complete object-side index;
- reads the original table or assumes its original capacity/in-use bit;
- uses `_pad0C` as private storage; or
- patches one of the same Skyrim instructions.

Engine Fixes implementations reviewed here only use the abandoned table for a
handle-usage warning, so that count becomes stale rather than redirecting to
the new table. That finding does not certify every past or future Engine Fixes
binary, and a concrete same-instruction collision still fails Skyrim's exact
original-byte preflight.

## Configuration

The shipping configuration is:

```ini
[General]
VerboseLogging = 0
GenerationWrapDetection = 1
SampleSize = 16
```

`GenerationWrapDetection=0` disables only the counter array, relay, publisher
redirects, and reuse reporting; it does not disable the cap raise.
`VerboseLogging=1` enables bounded, read-only high-handle attribution after a
successful load/new-game event. `SampleSize` limits individual sample rows, not
aggregate totals. The implementation and scheduling are separated into
[`TableMonitor.cpp`](src/TableMonitor.cpp),
[`GenerationDiagnostic.cpp`](src/GenerationDiagnostic.cpp), and
[`StressTest.cpp`](src/StressTest.cpp).

## Offline regeneration and verification

Run these commands from the `Skyrim/` directory:

```powershell
$env:PYTHONPATH = 'probes'
python probes\test_patch.py --runtime SE --patch artifacts\patch_SE.json
python probes\test_patch.py --runtime AE --patch artifacts\patch_AE.json
python probes\test_patch.py --runtime GOG --patch artifacts\patch_GOG.json
python probes\test_patch.py --runtime VR --patch artifacts\patch_VR.json
python probes\verify_deliverable.py --offline
```

Python regeneration requires the packages pinned in
[`probes/requirements.txt`](probes/requirements.txt) and the user's own exact
game executables and Address Library inputs. No Bethesda binary is
redistributed. Follow [the maintained pipeline](probes/README.md#the-maintained-pipeline)
rather than hand-editing generated JSON, generated Markdown, or
`src/PatchTable.g.h`. This public tree is an auditable source/evidence snapshot;
release build tooling, binaries, INIs, packages, and proprietary inputs are not
included.

## Evidence boundary

The offline simulator applies each exact profile, re-disassembles the result,
and verifies the coherent 22-bit encoding, table-reference census,
object-cache publication, and release clears. It cannot prove behavior in an
unseen native DLL or substitute for live VR/GOG above-cap testing. Likewise,
the recorded SE save-removal result establishes save-format safety for that
tested path, not capacity safety after restoring Skyrim's 1M runtime ceiling.

Treat the project as experimental, preserve logs from failures, and report the
exact runtime and native DLL versions with any reproduction.
