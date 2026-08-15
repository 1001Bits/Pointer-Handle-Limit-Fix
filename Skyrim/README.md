# Skyrim Handle Cap Raise

An experimental SKSE/SKSEVR plugin that raises Skyrim's process-local
reference-handle table from 1,048,576 to 2,097,152 physical entries on four
exact runtime profiles.

Version 2.2 uses a compatibility-first layout: a 21-bit table index, a five-bit
age, and Skyrim's original bit 26 table-entry in-use flag. Every raw handle
therefore remains within bits 0–25, and the complete index fits the existing
21-bit object-side cache in `_refCount[31:11]`. No object padding or sidecar is
used.

One value is deliberately preserved: `PlayerCharacter` keeps Skyrim's vanilla
raw handle `0x00100000`. Physical slot `0x100000` is reserved for that purpose
and never enters the ordinary FIFO allocator. This is a one-value reservation,
not a general compatibility decoder; the player's FormID remains
`0x00000014`.

> **Prerelease status:** the 2M/21+5 architecture has deterministic generated
> profiles, passing offline simulations for SE, AE, GOG, and VR, and a passing
> native Release build. The prior 4M live captures are historical evidence for
> a different encoding and are not release evidence for version 2.2. Fresh 2M
> stress and compatibility/lifecycle gates are required before publication.

## Start here

| Document | Purpose |
|---|---|
| [DESIGN.md](DESIGN.md) | Authoritative architecture, invariants, transaction model, and compatibility boundary. |
| [Public-source compatibility audit](docs/HANDLE-COMPATIBILITY-AUDIT-2026-08-11.md) | Dated review of raw-handle consumers, fixed-table access, storage, and persistence. |
| [Generated patch-site audit](docs/patch-sites/README.md) | Exact original and replacement instructions for all 1,876 mandatory mutation records, including 20 generation-guard redirects. |
| [Exact inputs](HASHES.md) | Executable and Address Library hashes to which the profiles are bound. |
| [Build and verification](VERIFY.md) | Regeneration, build, simulation, packaging, and live acceptance gates. |
| [Probe pipeline](probes/README.md#the-maintained-pipeline) | Maintained generation and verification tooling. |

## Current implementation

```text
Raw handle:       index [20:0] | age [25:21] | [31:26] unused
Table entry word: next/index [20:0] | age [25:21] | bit 26 in use
Object _refCount: refcount [9:0] | bit 10 valid | cached index [31:11]
Reserved player:  physical slot 0x100000 | raw handle 0x00100000
```

Exact constants:

| Property | Value |
|---|---:|
| Physical entries | `0x00200000` |
| Ordinary entries | `0x001FFFFF` |
| Index mask | `0x001FFFFF` |
| Age mask / increment | `0x03E00000` / `0x00200000` |
| Entry in-use bit | `0x04000000` |
| Raw-handle envelope | `0x03FFFFFF` |
| Clear-age / clear-next masks | `0xFC1FFFFF` / `0xFFE00000` |
| Detached player entry | `0x03F00000` |
| Live player entry state | `(entry & 0x07E00000) == 0x04000000`; low successor bits may vary |
| Replacement table | 32 MiB, 16-byte entries |
| Mandatory reuse counters | 8 MiB, one `uint32_t` per slot |

The reserved slot begins as the detached generation-31 self-link
`0x03F00000`. A validated player claim publishes generation zero and raw handle
`0x00100000`; release restores the exact sentinel without appending the slot to
the FIFO. Player identity is established by the canonical constructor call and
then by the published singleton, because construction can cache a handle before
the singleton store.

Every exact runtime profile contains:

- all field constants needed for 21-bit indexing and five-bit age handling;
- every RIP-relative reference to the relocated table;
- three startup-initializer guards;
- five allocator selectors, one player-constructor hook, and one player-release
  hook; and
- five mandatory assignment redirects for the pre-publication generation guard.

The generated mandatory-site counts are:

| Runtime | Field sites | Table references | Init guards | Player hooks | Guard redirects | Mandatory total |
|---|---:|---:|---:|---:|---:|---:|
| SE 1.5.97.0 | 293 | 96 | 3 | 7 | 5 | 404 |
| AE 1.6.1170.0 | 394 | 115 | 3 | 7 | 5 | 524 |
| GOG 1.6.1179.0 | 394 | 115 | 3 | 7 | 5 | 524 |
| VR 1.4.15.0 | 307 | 102 | 3 | 7 | 5 | 424 |

The total is 1,876 mandatory mutations, including 20 generation-guard call
redirects. The prior 4M design required 858 additional in-use-bit and sidecar
mutations; those categories do not exist in the 2M schema.

Installation remains fail-closed and transactional. Every original byte and
manager value is authenticated before publication. Any write or postcondition
failure restores and verifies the complete original transaction.

## Compatibility boundary

The 2M layout deliberately preserves more of Skyrim's native representation
than the former 4M design:

- raw handles fit in the original 26-bit value envelope;
- table-entry bit 26 remains the in-use bit;
- `_refCount >> 11` again yields the complete cached index;
- object sizes, offsets, padding, reference-count bits, and valid bit 10 are
  unchanged; and
- CommonLib-style opaque `uint32_t` handles continue to call Skyrim for create
  and resolve operations.

It is still not stock-layout compatible. Review any native DLL that:

- decodes a raw handle with `handle & 0xFFFFF` or `handle >> 20`;
- directly reads the original one-million-entry table;
- assumes the original capacity or patches the same Skyrim instructions; or
- serializes a raw `BSPointerHandle` rather than a FormID or supported VM
  handle.

For example, raw handle `0x00300001` represents 2M-layout index `0x100001`, age
1. A stock decoder interprets it as index 1, age 3. Keeping bit 26 and 26-bit
storage cannot repair that private decoder.

The reviewed Engine Fixes handle-usage warning reads CommonLib's fixed original
table and therefore reports a stale count after relocation. The authenticated
AE 1.6.1170 FormCaching/SafetyHook overlap has a separate exact interoperability
contract in [docs/ENGINE-FIXES-FORM-CACHING-INTEROP.md](docs/ENGINE-FIXES-FORM-CACHING-INTEROP.md).

Raw non-player handles remain process-local. A layout change cannot generically
migrate one because the dword does not carry a FormID. Save data that uses
supported FormID or Papyrus VM serialization is a separate mechanism; code
that persists raw handles, including SKSE's narrow delayed
`PapyrusSpawnerTask` path, remains a compatibility risk.

The first previously issued age would repeat on assignment 33, after 32 reuses
of the same ordinary slot. That is the explicit cost of retaining a 26-bit raw
value while doubling the physical table. Exact per-slot tracking is therefore
mandatory: it logs each new successful reuse high-water through 31 and
fail-stops assignment 33 before the table pointer/object cache can be published,
the assignment can return, the manager can unlock, or the repeated value can
become resolvable.

There is no runtime-selectable 2M/4M mode. The same raw dword has different
meaning under different layouts, so shipping a switch would create an
unversioned persistence hazard and double the proof matrix.

## Supported profiles and evidence

| Runtime | Offline simulation | Current 2M live evidence |
|---|---|---|
| SE 1.5.97.0 | PASS | Pending fresh prerelease run |
| AE 1.6.1170.0 | PASS | Pending fresh stress and compatibility/lifecycle gates |
| GOG 1.6.1179.0 | PASS | Pending |
| VR 1.4.15.0 | PASS | Pending |

Unsupported runtime versions are logged and left untouched. These are exact
binary profiles, not version-family aliases. Historical 4M captures remain
useful design evidence but cannot be promoted into this table.

## Configuration

The shipping configuration is:

```ini
[General]
VerboseLogging=0
LifecycleVerification=0
GenerationWrapDetection=1
SampleSize=16
```

`GenerationWrapDetection=0` is incompatible with the 2M layout and makes the
plugin refuse the cap raise. The 8 MiB exact counter array and pre-publication
guard are safety infrastructure, not optional diagnostics.
`VerboseLogging=1` enables bounded read-only attribution.
`LifecycleVerification=1` is prerelease-only and adds manager-locked full-table
and FIFO checkpoints that can hitch a load screen.

`[StressTest] Enabled=1` is a throwaway-process harness, never a shipping
setting. The release stress gate fills above the stock ceiling while staying
below the 2M limit, re-resolves every retained object in a complete second
pass, then exercises bounded high-bank release, 31 safe exact-slot reuses,
stale-handle rejection, hottest-handle logging, and an authenticated guarded
termination on boundary attempt 32 without loading or saving.

In this contract, “no wrap” means zero repeated-generation/ABA publication or
resolvability. Safe reuse 31 advances the five-bit age numerically from 31 to
zero, but that age-zero value has not previously been issued for the selected
slot. Reuse attempt 32 would repeat its initial age-one raw value and is stopped
before a table pointer can make that value resolvable.

## Build and package

From an x64 Visual Studio developer shell:

```powershell
cmake -S . -B build --fresh -A x64
cmake --build build --config Release --parallel
python probes\verify_deliverable.py
```

The build stages `SkyrimHandleCapRaise.dll` and the shipping INI below
`package/Data/SKSE/Plugins`, then creates
`package/Data/Pointer Handle Limit Fix.zip`. Release linking uses MSVC
`/Brepro`, and packaging uses a fixed `SOURCE_DATE_EPOCH`; two clean builds
must reproduce both DLL and ZIP byte-for-byte before release.

## Offline regeneration and verification

From the repository root:

```powershell
$env:PYTHONPATH = 'probes'
python probes\test_patch.py --runtime SE --patch artifacts\patch_SE.json
python probes\test_patch.py --runtime AE --patch artifacts\patch_AE.json
python probes\test_patch.py --runtime GOG --patch artifacts\patch_GOG.json
python probes\test_patch.py --runtime VR --patch artifacts\patch_VR.json
python probes\verify_deliverable.py --offline
```

Regeneration requires the packages pinned in
[probes/requirements.txt](probes/requirements.txt) and the user's own exact game
executables and Address Library inputs. Bethesda binaries are never included.
Generated JSON, Markdown, and `src/PatchTable.g.h` must be regenerated through
the maintained pipeline rather than edited by hand.

## Release evidence boundary

Offline simulation proves the exact known binaries are patched coherently. It
cannot prove behavior in a private native DLL or a runtime not represented by
the profile. Publication additionally requires:

1. deterministic regeneration and complete production verification;
2. two byte-identical clean Release builds and packages;
3. a fresh above-stock 2M stress PASS with exact restoration;
4. a fresh AE compatibility/lifecycle PASS covering Player, OAR, Precision,
   real combat, teardown, and terminal clone cleanup; and
5. immutable evidence manifests plus post-run clean-root audits.

Treat any missing gate as a release blocker, preserve all failure evidence, and
report the exact runtime and native DLL versions with reproductions.
