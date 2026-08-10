# Skyrim Handle Cap Raise design

This document is the authoritative human-readable description of the current
4,194,304-entry Skyrim design. The [generated JSON profiles](artifacts/)
remain the byte-level source of truth for individual runtime edits, and the generated
[`PatchTable.g.h`](src/PatchTable.g.h) is their compiled representation.

The implementation targets exactly these executable profiles:

- Skyrim SE 1.5.97.0
- Skyrim AE 1.6.1170.0
- Skyrim GOG 1.6.1179.0
- Skyrim VR 1.4.15.0

See the [exact-input hashes](HASHES.md), the
[patch-site index](docs/patch-sites/README.md) for original and replacement
instructions, and the [verification instructions](VERIFY.md)
for deterministic regeneration and simulation commands.

## Design goals and non-goals

The design raises the process-local reference-handle table from 2^20 to 2^22
entries while retaining:

- a complete, self-contained 32-bit raw handle;
- all six stale-handle generation bits;
- the 10-bit intrusive reference count and its 1023 maximum;
- the object-side handle-valid flag at bit 10;
- existing object sizes and member offsets; and
- the existing 16-byte table-entry stride and manager lock.

It deliberately changes private engine representation details: the raw-handle
bit positions, table address and masks, table-entry in-use bit, and the meaning
of `NiRefObject::_pad0C`. It therefore does not claim blanket ABI compatibility
with DLLs that decode those internals themselves.

This is a fixed 4M implementation, not a runtime-selectable 2M/4M design. It
does not change Skyrim's save format, make the abandoned 1M table report useful
data, or establish compatibility with every closed-source native plugin.

## Three distinct representations

The raw handle, table entry, and object-side cache are related, but they are
not the same value. Keeping them separate is essential to understanding the
patch.

### 1. Raw `BSPointerHandle`

A raw `ActorHandle`, `ObjectRefHandle`, or other `BSPointerHandle` remains a
complete `uint32_t` value. It contains both the table index and generation; it
does not need the object-side cache to recover missing bits.

```text
Stock raw handle
  bits  0-19  complete 20-bit table index
  bits 20-25  complete 6-bit generation
  bits 26-31  unused

Raised raw handle
  bits  0-21  complete 22-bit table index
  bits 22-27  complete 6-bit generation
  bits 28-31  unused
```

The raised masks are `0x003FFFFF` for the index and `0x0FC00000` for the
generation. Copying, storing, comparing, hashing, or passing the full 32-bit
value does not truncate it.

### 2. Handle-table entry

The first dword of each 16-byte table entry uses the same index and generation
positions as the raw handle, plus an in-use bit that is not part of the raw
handle:

```text
Stock table entry word
  bits  0-19  next-free index / allocated index
  bits 20-25  generation
  bit      26 in use
  bits 27-31  unused

Raised table entry word
  bits  0-21  next-free index / allocated index
  bits 22-27  generation
  bit      28 in use
  bits 29-31  unused
```

The pointer at entry `+0x08` remains a
`NiPointer<BSHandleRefObject>`. Entry size remains 16 bytes; only capacity and
field positions change.

### 3. Object-side handle metadata

`BSHandleRefObject::_refCount` is a packed object metadata word, not a stored
raw `BSPointerHandle`:

```text
BSHandleRefObject +0x08 / TESObjectREFR +0x28
  bits  0-9   intrusive reference count
  bit      10 handle-valid flag
  bits 11-31  low 21 bits of the cached table index

BSHandleRefObject +0x0C / TESObjectREFR +0x2C
  bits  0-21  complete 22-bit cached table index
```

The second dword is the existing `NiRefObject::_pad0C` storage. Reusing it does
not grow an object or move a later member. The low 21 index bits remain mirrored
in `_refCount`, while enumerated engine code that needs the complete object-side
index reads `+0x2C`.

The `+0x2C` dword is an object-side index cache. It neither extends nor
completes the raw handle, which already carries all 22 index bits.

## Allocation and publication

The allocator removes a free table entry, advances its six-bit generation,
combines that generation with the complete 22-bit index, and writes the
complete value to the returned raw handle. It then publishes the pointer and
object-side cache while holding Skyrim's existing manager write lock.

Five allocation clones per supported runtime contain the object-cache writer.
The relevant stock transformation is:

```asm
shl eax, 11
bts eax, 10
```

The same-length raised transformation is:

```asm
mov dword ptr [object+0x2C], eax
stc
rcl eax, 11
```

`STC` and `RCL` form one operation. Immediately before the sequence, `EAX`
contains the complete 22-bit index. Treating `CF:EAX` as a 33-bit value gives:

```text
EAX = ((index & 0x1FFFFF) << 11) | 0x400
CF  = (index >> 21) & 1
```

The initial carry becomes object metadata valid bit 10. Source index bits 0-20
become the mirrored bits 11-31, and source bit 21 exits into carry only after
the complete index has been stored at `+0x2C`. The following `OR` into
`_refCount` overwrites arithmetic flags, so the final carry is not consumed.
The original `BTS` carry was likewise not consumed because the same following
`OR` replaced it.

This sequence therefore sets the object-side valid flag correctly. It is not a
replacement of `BTS` by an unrelated `STC`; it is a same-length replacement of
the combined shift-and-set transformation.

Publication order is intentional: the complete object-side index is stored
before the valid metadata word is published. The table pointer is assigned by
Skyrim's original pointer helper before the optional generation observer
records the assignment.

## Lookup, validation, and release

Raw-handle lookup decodes the complete 22-bit index and six-bit generation from
the raw value, indexes the relocated table, and checks the raised entry fields.
Object-side validators that formerly derived an index from `_refCount >> 11`
are redirected to the complete cache at `+0x2C`. Paths that still need
`_refCount` for its count or valid flag keep that load and replace only the
index extraction.

Release must invalidate both object-side representations before an entry can
be reused. The stock dword clear that preserves only `_refCount[9:0]` becomes a
same-length, aligned 64-bit operation across `+0x28` and `+0x2C`. It preserves
the 10-bit count while clearing the valid flag, mirrored index, and complete
cached index together. The independently enumerated release-site census is
cross-referenced to its covering writes in the generated
[patch-site audit](docs/patch-sites/README.md).

## Table relocation

Skyrim compiles the manager capacity and static table address into many
inlined functions; there is no capacity member to update. The plugin therefore
allocates a 64 MiB table and rewrites every enumerated RIP-relative reference
to the original 16 MiB table.

The new allocation must lie within the signed 32-bit RIP-relative displacement
range of every table instruction. Allocation searches near the executable,
then validates the proposed displacement at every individual site. This keeps
each original `LEA` a single instruction and avoids a trampoline on every table
access.

The replacement displacement is necessarily runtime-derived because the
allocation address is chosen at startup. Consequently, the patch-site index
shows these replacements symbolically as references to the raised table rather
than pretending they have one fixed replacement byte string.

The original image-backed table remains mapped. Direct consumers of its fixed
address see abandoned 1M storage, not the relocated table.

## Startup initialization ordering

Changing the encoding after any handle has been allocated is unsafe. Under the
manager write lock, the plugin accepts exactly one of two complete states:

1. the pre-free-list zero state: zero head, zero tail, and an all-zero 1M table;
   or
2. the initialized state: the exact pristine 1M free-list chain, including
   head, tail, entry words, padding, and null pointers.

A pool that was used and later emptied is rejected because retained generation
or pointer state fails the complete comparison. The zero state does not prove
that the C++ static initializer has not run: its table zeroing and element
construction may already have completed while the separate free-list
initializer has not.

When the all-zero state is observed, three runtime-specific guards prevent any
not-yet-executed startup path from overwriting the raised pool:

- disable the C++ static-initializer call that zeros the 16 MiB handle table;
- disable the C++ static-initializer call that constructs 1,048,576 table
  entries; and
- skip the subsequent handle-table/free-list initialization.

The first pair belongs to a callback registered in the executable's C++ static
initializer list; it is not treated as unused code. If that callback already
ran, changing its call sites is harmless because those sites are behind the
current execution point. If it has not run, the guards prevent it from wiping
the raised table. The subsequent initialization is a one-shot call on SE/VR
and an inlined block on AE/GOG. The AE/GOG block publishes the head, clears the
table, writes the next-index chain, and publishes the tail, so
“handle-table/free-list initialization” describes the operation precisely.

If the exact pristine free list already exists, those paths have run and the
three guard sites remain unmodified.

## Runtime identification

Windows version resources expose both numeric `VS_FIXEDFILEINFO` members and
translated strings. Runtime selection parses the translated
`StringFileInfo\\<language-codepage>\\ProductVersion` string; it does not use a
vague “fixed numeric version.” On the tested SE 1.5.97 and VR 1.4.15
executables, the numeric file/product fields are `1.0.0.0`, while the translated
ProductVersion string identifies the actual runtime build.

GOG's executable ProductVersion string is `1.6.1179.0`; SKSE uses its low
runtime-version nibble as a storefront tag and reports the GOG loader value as
`1.6.1179.1`. Profile selection still requires the expected ProductVersion and
then verifies every complete original instruction before any write.

## Generated patch profiles and audit document

The maintained inputs are `artifacts/patch_SE.json`, `patch_AE.json`,
`patch_GOG.json`, and `patch_VR.json`. Their records fall into distinct forms:

- field patches contain a complete original instruction and the scalar field
  to replace;
- raw and initialization patches contain complete original and replacement
  byte sequences;
- table references contain complete original instructions plus the
  displacement location, because the new table target is runtime-derived; and
- optional diagnostic calls contain exact original calls and verified owner
  context, while their relay target is also runtime-derived.

The generated [patch-site index](docs/patch-sites/README.md) presents original
and replacement bytes and disassembly for fixed edits, and explicit byte
templates plus symbolic targets for runtime-derived edits. It also records
reviewed exclusions separately from write sites. Independently enumerated
release fingerprints are cross-referenced to the raw patches that cover them;
they are not counted as additional writes.

Completeness does not rest on one disassembler pass. It combines decoded and
decoder-independent table-reference searches, `.pdata`/unwind reconstruction,
leaf-code recovery, mask fingerprints, object-reader dataflow, independent
writer/publisher mapping, and release-site enumeration. The detailed counts,
negative searches, and exclusions are committed in the generated JSON profiles
and rendered in the [patch-site audit](docs/patch-sites/README.md).

## Transaction and rollback model

The cap raise is one guarded transaction:

1. select an exact runtime profile and locate the executable code section;
2. verify every complete original field, raw, initialization, table, and
   release-gate instruction;
3. confirm the independent raw-reference count to the original table;
4. allocate, construct, and verify the complete 4M replacement table before
   making code writable;
5. take Skyrim's manager write lock and verify an accepted pristine state;
6. apply all required code changes and publish the raised head/tail;
7. verify every replacement byte, table displacement, manager global, and
   entry in the new free-list chain; and
8. flush the instruction cache, restore page protection, and release the lock.

A failure before writes is a clean refusal. A failure after writes restores
every original instruction and manager value, then verifies that restoration.
If rollback, cache flushing, or page-protection restoration cannot be proven,
the process stops rather than continuing with mixed handle encodings.

Exact-byte preflight also catches another code mod that edited the same Skyrim
instruction. It cannot detect a DLL that privately decodes handle fields inside
its own module without touching Skyrim's code.

## Generation-wrap detector and monitoring

Generation-wrap detection is separate from the cap transaction. When enabled,
it allocates a 16 MiB array containing one `uint32_t` assignment counter per
slot and one 4 KiB executable relay page within `CALL rel32` reach. The five
successful publisher calls remain untouched until the cap transaction commits
and every owner, setup, call, target, and shared-helper fingerprint verifies.

Each redirected call invokes Skyrim's original pointer-assignment helper first,
preserves its return value, and then updates preallocated counters. The hook
does no allocation, attribution, formatting, or logging. Its owners are
serialized by the manager write lock, and the periodic monitor reads the table
and counters under the same lock.

The replacement table starts at generation zero and Skyrim increments before
publication, so the first issued generation is one. Assignment 64 (reuse count
63) rolls the field from 63 to zero, but zero has not previously been issued in
that pristine session. Assignment 65 (reuse count 64) repeats generation one
and is the first stale-handle ABA boundary. The warning threshold is therefore
64 reuses.

A mismatch or allocation failure before diagnostic call installation disables
only the detector; the committed cap raise remains active. A clean installation
failure restores all five calls. An inability to prove restoration of a
partially redirected call site is fail-stop because mixed call targets are not
a safe diagnostic-off state.

Detailed high-handle attribution is a separate, read-only monitor enabled by
verbose logging. Its bounded main-thread tasks resolve candidates through
Skyrim's own API and release each temporary pin. The scheduling and attribution
paths are isolated in [`TableMonitor.cpp`](src/TableMonitor.cpp),
[`GenerationDiagnostic.cpp`](src/GenerationDiagnostic.cpp), and
[`StressTest.cpp`](src/StressTest.cpp).

## Compatibility boundary

The design preserves specific binary interfaces, not every private
interpretation of their contents.

Preserved:

- 32-bit handle storage and calling width;
- object and subobject sizes and offsets;
- `_refCount & 0x3FF`, its 1023 maximum, and valid bit 10;
- six generation bits and 64 possible generation values;
- the manager lock address; and
- ordinary engine/CommonLib-style creation and resolution paths that treat the
  raw handle as an opaque 32-bit value.

Changed:

- raw-handle index/generation positions;
- table capacity, address, masks, and in-use bit;
- the meaning of `NiRefObject::_pad0C`; and
- the way engine object validators obtain the complete cached index.

A DLL requires review if it manually masks or shifts a raw handle, assumes
`_refCount >> 11` is the complete object-side index, reads the original table
or fixed capacity directly, assumes the original in-use bit, or uses `_pad0C`
as private storage. Merely storing or passing a complete `ActorHandle` or
`ObjectRefHandle` does not truncate it.

Engine Fixes versions reviewed by this project only count in-use entries in the
fixed original table for a warning. That count becomes stale (normally zero)
but remains memory-safe because the original table stays mapped. This is a
finding about the audited versions, not certification of every release. The
compatibility boundary therefore remains behavior-based: concrete private
decoders and conflicting engine-instruction patches require separate review.

## Save and memory consequences

Raw reference handles, table entries, and the object-side index cache are
process-local. The plugin adds no save or co-save record. The recorded SE
removal test establishes save-format safety for that tested path; it does not
make removal capacity-safe for a load order that genuinely needs more than the
restored 1M runtime slots.

The raised table commits 64 MiB. The default generation detector adds a 16 MiB
counter array and one 4 KiB relay page. The original 16 MiB image table remains
mapped but clean pages need not remain resident, so an address-space sum is not
a measured steady working set. Lookup remains O(1), but startup cost,
cache/TLB effects, and broad mod-stack behavior still require measurement.

## Source-module responsibilities

The runtime source is split by responsibility so that patch safety, monitoring,
and diagnostics can be reviewed independently:

| Module | Responsibility |
|---|---|
| `main.cpp` | SKSE exports, plugin lifecycle, and orchestration only. |
| `Logging.h/.cpp` | Thread-safe log creation and writes. |
| `PluginPaths.h/.cpp` | Game, plugin, and module path discovery. |
| `Configuration.h/.cpp` | INI parsing and immutable user settings. |
| `RuntimeTypes.h` | Shared runtime context, text range, and exact-runtime offsets. |
| `RuntimeDetection.h/.cpp` | ProductVersion parsing, PE `.text` discovery, profile/offset selection, and the Engine Fixes compatibility notice. |
| `HandleTable.h` | Packed table-entry representation and read-only table views. |
| `EngineAccess.h/.cpp` | Manager lock/unlock calls and engine smart-pointer/pin helpers. |
| `FormAttribution.h/.cpp` | Reference names, FormIDs, and source/winning-plugin attribution used by diagnostics and tests. |
| `GenerationDiagnostic.h/.cpp` | Assignment relay/hook, per-slot counters, wrap detection, and hottest-slot snapshots. |
| `TableMonitor.h/.cpp` | One-minute/five-minute usage and generation-report scheduling. |
| `PatchTransaction.h/.cpp` | Exact-byte preflight, near allocation, pristine-pool validation, apply/verify, rollback, and fail-stop handling. |
| `EngineFixesConfig.h/.cpp` | Engine Fixes configuration/version parsing used by compatibility reporting. |
| `GenerationTracker.h` | Pure generation/reuse accounting rules and warning threshold. |
| `StressTest.h/.cpp` | Explicitly enabled synthetic and live-reference test harness. |
| `StockProbe.cpp` | Separate stock-1M exhaustion control DLL; it does not link or invoke the cap-raise transaction. |
| `PatchTable.g.h` | Generated, byte-exact runtime profiles; never hand-edited. |

The architectural boundary is an invariant: `main.cpp` coordinates components,
while patch mutation, monitoring, and diagnostic presentation remain separately
reviewable implementation units.

## Evidence limits

All four exact profiles pass the complete offline patch simulation, including
application and re-disassembly of every generated edit. Live evidence is not
uniform:

- SE 1.5.97 and AE 1.6.1170 have recorded approximately 3.5M-handle runs with
  complete high-bit lookup, bounded release, and exact-slot reuse checks.
- GOG 1.6.1179 has a recorded exact-profile startup/resize pass, but no live
  above-cap lookup, release, or reuse result.
- VR 1.4.15 remains offline-only and must not be described as live-tested.

These results do not prove universal native-plugin compatibility, concurrency
safety under every mod stack, or a performance benefit below 2M live handles.
Private live-test captures are not redistributed in this source snapshot; the
published verifier covers the exact static profiles and generated evidence.

## Documentation map

To keep claims from drifting, each document has one role:

| Document | Owns |
|---|---|
| [DESIGN.md](DESIGN.md) | Current architecture, invariants, and compatibility model. |
| [Patch-site index](docs/patch-sites/README.md) | Generated original/replacement bytes and disassembly for every write site. |
| [HASHES.md](HASHES.md) | Exact executable and Address Library generation inputs. |
| [VERIFY.md](VERIFY.md) | Offline simulation and generated-deliverable verification. |
| [probes/README.md](probes/README.md) | Regeneration and verification commands. |
| [artifacts/](artifacts/) | Committed machine-readable profiles and site inventories. |
