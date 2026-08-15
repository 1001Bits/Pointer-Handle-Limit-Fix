# Skyrim build and verification

This is the release checklist for the fixed 2M/21+5 architecture. A source
test, a clean build, a live run, and a clean restoration prove different
things; none substitutes for another.

## Prerequisites

- Python 3.12 and `probes/requirements.txt`
- x64 Visual Studio/MSVC environment for Release builds
- each exact executable and Address Library input listed in `HASHES.md`
- clean, separately audited live-test installations for any runtime on which a
  live claim is made

Optional input overrides:

```powershell
$env:SHCR_SE_EXE='C:\path\to\SkyrimSE-1.5.97.exe'
$env:SHCR_SE_ADDRLIB='C:\path\to\version-1-5-97-0.bin'
$env:SHCR_AE_EXE='C:\path\to\SkyrimSE-1.6.1170.exe'
$env:SHCR_AE_ADDRLIB='C:\path\to\versionlib-1-6-1170-0.bin'
$env:SHCR_GOG_EXE='C:\path\to\SkyrimSE-1.6.1179.exe'
$env:SHCR_GOG_ADDRLIB='C:\path\to\versionlib-1-6-1179-0.bin'
$env:SHCR_VR_EXE='C:\path\to\SkyrimVR-1.4.15.exe'
$env:SHCR_VR_ADDRLIB='C:\path\to\version-1-4-15-0.csv'
```

## Deterministic regeneration

Run the maintained commands from `Skyrim/probes`:

```powershell
python gen_patchtable.py --runtime SE --table 1ec47c0 --head 1ec47ac --tail 1ec47b0 --lock 1ec47b8 --out ..\artifacts\patch_SE.json
python gen_patchtable.py --runtime AE --table 20fc600 --head 20fc5ec --tail 20fc5f0 --lock 20fc5f8 --out ..\artifacts\patch_AE.json
python gen_patchtable.py --runtime GOG --table 20fda00 --head 20fd9ec --tail 20fd9f0 --lock 20fd9f8 --out ..\artifacts\patch_GOG.json
python gen_patchtable.py --runtime VR --table 1f89660 --head 1f8964c --tail 1f89650 --lock 1f89658 --out ..\artifacts\patch_VR.json
python gen_cpp.py --se ..\artifacts\patch_SE.json --ae ..\artifacts\patch_AE.json --gog ..\artifacts\patch_GOG.json --vr ..\artifacts\patch_VR.json --out ..\src\PatchTable.g.h
python gen_patch_docs.py --se ..\artifacts\patch_SE.json --ae ..\artifacts\patch_AE.json --gog ..\artifacts\patch_GOG.json --vr ..\artifacts\patch_VR.json --out-dir ..\docs\patch-sites
```

Repeat regeneration in a clean temporary output location and byte-compare all
four JSON files, the generated header, and generated Markdown. A timestamp-only
or ordering difference is a release blocker.

The exact generated architecture is:

| Runtime | Fields | Table refs | Init | Player | Guard redirects | Mandatory total |
|---|---:|---:|---:|---:|---:|---:|
| SE | 293 | 96 | 3 | 7 | 5 | 404 |
| AE | 394 | 115 | 3 | 7 | 5 | 524 |
| GOG | 394 | 115 | 3 | 7 | 5 | 524 |
| VR | 307 | 102 | 3 | 7 | 5 | 424 |

Every artifact must say `raised_entries=0x200000` and `entry_size=0x10`.
Allowed field categories are only `table_bytes`, `age_inc_or_count`,
`index_mask`, `age_mask`, `clear_age`, and `clear_next`. The old collections
`raw_patches`, `release_sites`, and `excluded_shift11` must be absent, as must
sidecar and moved-in-use mutation categories.

## Offline simulations

From the repository root:

```powershell
$env:PYTHONPATH='probes'
python probes\test_patch.py --runtime SE --patch artifacts\patch_SE.json
python probes\test_patch.py --runtime AE --patch artifacts\patch_AE.json
python probes\test_patch.py --runtime GOG --patch artifacts\patch_GOG.json
python probes\test_patch.py --runtime VR --patch artifacts\patch_VR.json
python probes\verify_deliverable.py --offline
```

All four simulations must end in `PASS`; the verifier must end in
`ALL CONSISTENT`. The simulator applies every fixed mutation to an in-memory
copy of the exact executable and re-disassembles the result.

The production verifier independently requires:

- exact executable/profile hashes and schemas;
- the 21-bit index and five-bit age masks and instructions;
- stock bit-26 in-use semantics with no relocation mutations;
- complete `_refCount >> 11` caching and untouched `+0x2C` padding;
- a 32 MiB replacement table and 8 MiB mandatory counter array;
- exact field/reference/init/player/assignment counts;
- exact JSON/header/generated-document agreement; and
- version identity `2.2.0` / `0x020200`.

## Reserved player acceptance

Each runtime simulation must prove:

- slot `0x100000` begins as `0x03F00000`, with null pointer and zero padding;
- the ordinary FIFO contains 2,097,151 slots, links `0x0FFFFF` directly to
  `0x100001`, and never contains the reservation;
- the exact seven-hook constructor/selector/release set is complete;
- constructor arming accepts only the exact in-flight candidate, then the exact
  published singleton;
- a player claim creates generation-zero/in-use state
  `(entry & 0x07E00000) == 0x04000000`, caches index `0x100000` in
  `_refCount[31:11]`, and returns raw `0x00100000`; its live low successor bits
  are not required to equal the physical index;
- release restores `0x03F00000` without changing ordinary FIFO endpoints;
- a later authenticated claim returns the same player value; and
- ordinary release still uses stock-width cache invalidation and leaves object
  padding at `+0x2C` untouched.

The reserved Player intentionally lacks per-lifecycle stale protection because
the complete raw value is fixed. Ordinary slots must prove next-age issuance
and stale rejection through the five-bit/32-generation contract.

## Build, package, and full verification

From an x64 developer shell:

```powershell
cmake -S . -B build --fresh -A x64
cmake --build build --config Release --parallel
python probes\verify_deliverable.py
```

Non-offline verification additionally checks exact runtime inputs, PE exports,
plugin metadata, generated arrays embedded in the DLL, source freshness,
staged DLL/INI bytes, ZIP membership and hashes, and package consistency.

For a release candidate, perform two independent clean builds into distinct
empty directories. Require byte-identical:

- `SkyrimHandleCapRaise.dll`;
- staged shipping INI;
- package tree; and
- `Pointer Handle Limit Fix.zip`.

MSVC `/Brepro`, a fixed `SOURCE_DATE_EPOCH`, and the absence of precompiled
headers are part of that contract. Never pin the first build before the second
reproduces it.

## Fresh 2M stress gate

The active stress gate is `.tmp/stress-release-gate`. Its reproducible
candidate, release ZIP, and evidence verifier are sequentially hash-frozen.
Plan and self-tests remain nonmutating, and Execute still requires the exact
explicit token before any staging or launch.

After sequential freeze, the single live stress run must prove:

- exact version, profile, candidate, INI, game, and helper identities;
- 2,097,152 entries, 21 index bits, five age bits, stock bit 26;
- reserved slot `0x100000`, exact detached word, masked live state, and player
  raw value;
- a fill target of 1,800,000, above stock and below the 2M ceiling;
- a complete second exact resolution pass over all retained fillers;
- manager-locked FIFO equality and at least 262,144 allocatable free slots;
- high-bank release targets strictly above `0x100000`;
- exact-slot FIFO reuse, next five-bit age, stale-handle rejection, and intact
  neighbors;
- assignment count 32/generation zero after 31 safe reuses, with exactly 31
  successful high-water rows proving levels 1 through 31 without gaps or
  duplicates, the terminal target logged as hottest, and all wrap/prevented
  counters still zero;
- boundary attempt 32 stopped by the exact pre-publication guard FATAL before
  a repeated handle can become resolvable, with zero `CRITICAL`/cycle-32 PASS;
- keeper exit `0x53485752`, zero load/save/`qqq` requests, exact restoration,
  captured pre/post clean-root audits, exact orchestrator/event replay, and a
  SHA-256 manifest covering every other regular evidence file exactly once.

No synthetic success line is sufficient by itself; the verifier binds ordering,
counts, handles, table state, process identity, and restored bytes.

Finalization order is fixed: write the final PASS orchestrator, generate
`sha256-manifest.json` over every other regular evidence file (excluding only
itself), then run the read-only verifier. A successful verifier is followed by
no evidence mutation. If it rejects the archive, the runner records FAIL and
regenerates the manifest, but that coherent failure archive is not a gate PASS.

Here zero-wrap means zero repeated-generation/ABA publications or resolvable
aliases. Safe reuse 31 is allowed to advance the numeric age from 31 to zero
because age zero has not yet been issued for that slot. Attempt 32 would repeat
the initial age-one raw value and must fail-stop before pointer publication.

## Compatibility and lifecycle gate

The active AE gate is `.tmp/compat-lifecycle-gate`. It is a separate process and
profile from the synthetic stress run. The frozen 2M candidate and probe must
pass the complete existing fail-closed sequence, including:

- clean-root and exact-input preflight;
- hidden-desktop launch with no OS input or focus APIs;
- exact player handle `0x00100000` and reserved-slot lifecycle;
- exact owned dynamic clone identity and selection;
- genuine OAR `IsGreetingPlayer` before/during/after evidence;
- Precision V4 callbacks, correlated melee damage, and hostile TESHit evidence;
- native weapon draw and stock action dispatch with bounded observation windows;
- terminal clone deletion/nonresolution and zero high-list occurrence;
- clean Skyrim exit and exact stage/profile/runtime-residue restoration;
- post-restore clean-root audit; and
- immutable manifest plus full independent verifier PASS.

The compatibility gate's Player reservation checks must additionally prove the
2M startup log, index21/age5, generation-31 detached entry, bit26 in-use, stock
`_refCount` cache, no sidecar, and the 8 MiB mandatory guard counters.

Previous 4M evidence and failed 2M attempts remain immutable. They may diagnose
problems but cannot satisfy a current PASS.

## Release decision

Publication is allowed only when all of these are true:

1. deterministic generated outputs match;
2. all four simulations and all maintained unit/adversarial/source tests pass;
3. production offline and full verification pass;
4. two clean Release builds and ZIPs are byte-identical;
5. fresh stress and compatibility/lifecycle Executes pass;
6. both live runs have clean exits, exact restoration, clean-root audits, and
   complete manifests; and
7. the final package is the exact candidate authenticated by those live runs.

If any condition is false or unknown, the release state is BLOCKED. Preserve
the evidence and fix the cause; do not edit or promote a failed run.
