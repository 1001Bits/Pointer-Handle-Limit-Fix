# Skyrim Handle Cap Raise design

This document describes version 2.2.0's fixed 2M/21+5 architecture. Generated
JSON in [`artifacts/`](artifacts/), generated C++ in
[`src/PatchTable.g.h`](src/PatchTable.g.h), and the generated patch-site pages
are the machine-checked realization of this design.

The previous 4M/22+6 implementation is not a selectable mode. It used a moved
in-use bit and an object-padding sidecar; those mutations and their historical
live evidence do not apply to version 2.2.

## Goals and non-goals

The design must:

- double the physical table from `0x100000` to `0x200000` entries;
- preserve Player's complete raw handle `0x00100000`;
- keep all raw handles inside the original 26-bit envelope;
- keep table-entry bit 26 as Skyrim's in-use flag;
- make `_refCount >> 11` the complete object-side index again;
- leave object padding, object sizes, and public calling widths unchanged;
- patch only four exact runtime binaries and fail closed everywhere else;
- install transactionally, with byte-exact rollback; and
- produce independently replayable static and live release evidence.

It does not make a private stock-layout decoder work for upper-bank indices,
make the relocated table visible at its old address, or turn a raw handle into
a persistent identifier.

## Three representations

Confusing the raw handle, table entry word, and object cache is the easiest way
to create a silent alias. They are related but not interchangeable.

### Raw `BSPointerHandle`

```text
31              26 25              21 20                       0
+-----------------+------------------+--------------------------+
|     unused      |   age (5 bits)   |     index (21 bits)      |
+-----------------+------------------+--------------------------+
```

```text
index mask        0x001FFFFF
age mask          0x03E00000
age increment     0x00200000
raw envelope      0x03FFFFFF
```

Indices range from zero through `0x1FFFFF`. Ages range from zero through 31.
A normal create/resolve/release path must preserve the complete 32-bit dword,
even though valid values use only bits 0–25.

The first previously issued ordinary raw value can repeat after 32 reuses of
the same slot (assignment 33). This is half the former 4M design's 64-reuse
horizon, but the complete index×age namespace remains `2^26`, matching
Skyrim's original namespace size.

### Handle-table entry word

Each table entry remains 16 bytes. Its first dword is:

```text
31           27 26 25              21 20                       0
+--------------+--+------------------+--------------------------+
|    unused    |U |   age (5 bits)   | next/index (21 bits)     |
+--------------+--+------------------+--------------------------+
```

`U` is Skyrim's stock bit-26 in-use flag (`0x04000000`). A free entry's low 21
bits link the FIFO. A stock live entry may retain the successor from the free
entry it consumed; physical identity comes from the table index selected by the
raw handle, not from those live low bits. The relevant masks are:

```text
in use            0x04000000
clear in use      0xFBFFFFFF
clear age         0xFC1FFFFF
clear next/index  0xFFE00000
```

Unlike the old 4M design, no executable site moves this bit. Any generated
`inuse_bit`, `inuse_bitpos`, or `clear_inuse` mutation is a schema error.

### Object-side `_refCount`

The stock 32-bit object word is preserved:

```text
31                              11 10 9                         0
+--------------------------------+--+----------------------------+
| complete cached index (21 bits)|V | intrusive refcount (10 bits)|
+--------------------------------+--+----------------------------+
```

Bit 10 remains the handle-valid flag. Because the new index is exactly 21
bits, `_refCount >> 11` is complete. The object dword at
`TESObjectREFR+0x2C` is padding again and is neither read nor written by this
plugin. Release uses Skyrim's stock-width dword invalidation and must leave
that padding untouched.

This is the central compatibility advantage over 4M/22+6: all sidecar reads,
writes, qword clears, and object-layout assumptions disappear.

## Reserved player slot

Physical slot `0x100000` is excluded from the ordinary FIFO. That index is the
first value above Skyrim's stock 20-bit ceiling and numerically preserves the
vanilla Player handle when its age is zero.

```text
physical slot              0x00100000
detached entry             0x03F00000
live state mask            0x07E00000
live state                 0x04000000 (low successor bits may vary)
published raw handle       0x00100000
Player FormID              0x00000014
```

The detached entry combines age 31 with a self-link and has no object pointer.
It is not free allocator capacity. A player claim advances it to age zero, sets
bit 26, publishes the Player pointer, and caches index `0x100000` in
`_refCount[31:11]`. The stock allocator can retain the ordinary FIFO successor
in the live entry's low 21 bits, so live validation masks generation/in-use
state rather than requiring the canonical `0x04100000` example. Player release
restores the exact detached sentinel and never appends it to the FIFO.

The ordinary capacity is therefore 2,097,151 entries.

### Constructor-first identity

Allocation order and FormID are not sufficient identity checks. Each profile
authenticates and redirects seven sites:

1. the canonical `PlayerCharacter` constructor call;
2. five allocator selectors; and
3. the canonical release path.

The constructor wrapper arms only the exact candidate surrounding the original
constructor call. Selectors accept that armed candidate during construction or
the later published `PlayerCharacter` singleton. All pre-hook bytes, original
call target, constructor fingerprint, post-call publication window, register
ABI, lock boundaries, and continuations are authenticated before a relay is
published.

This two-phase identity is required because the constructor can establish the
object cache before the singleton store. Null, nested, mismatched, or stale
arms fail closed. Ordinary objects at the same allocator site remain on the
FIFO path.

### Deliberate player stale-handle tradeoff

The reserved slot always republishes the same generation-zero raw value. If
Player is destroyed and recreated in one process, a stale old player handle
can resolve to the new Player. That tradeoff is necessary to preserve the
complete vanilla constant. It applies only to the reserved slot; ordinary
slots use five-bit age advancement and are covered by the reuse detector.

## Allocation, lookup, and release

Ordinary allocation removes the FIFO head while holding Skyrim's manager lock,
advances the five-bit age, sets bit 26, stores the object pointer, publishes a
raw handle from the complete 21-bit index and age, and caches the same index in
`_refCount[31:11]`.

Lookup decodes the complete 21-bit index, bounds-checks against `0x200000`,
requires bit 26, compares the five-bit age, and acquires the referenced object
through Skyrim's normal ownership path.

Ordinary release decodes the complete cached index, authenticates the entry and
object, clears the stock-width object cache/valid state, marks the entry free,
and appends its physical index to the FIFO. Reserved release takes its separate
sentinel-restoration branch.

The generated field mutations are limited to these categories:

```text
table_bytes
age_inc_or_count
index_mask
age_mask
clear_age
clear_next
```

The generator intentionally emits no raw sidecar/release-window collections.
The five assignment-hook sites per runtime are separately authenticated stock
publishers redirected through the mandatory pre-publication guard. They do not
change the 21+5 field layout, but the cap transaction refuses to install unless
all five redirects and their guard state verify.

## Table relocation and initialization

The stock one-million-entry table occupies 16 MiB in the executable image and
cannot be enlarged in place. Startup therefore reserves and constructs a
32 MiB replacement table within signed 32-bit RIP-relative range of every
known reference, then retargets the exact enumerated instructions.

The original image table remains mapped but is abandoned. Three exact startup
guards prevent stock initializers from overwriting the replacement manager
state. The transaction constructs all ordinary FIFO links while skipping slot
`0x100000`, installs the detached player sentinel, and proves head, tail,
counts, links, padding, and reservation state under the manager lock before
publication.

All 428 table references across the four profiles remain required:

| Runtime | References |
|---|---:|
| SE | 96 |
| AE | 115 |
| GOG | 115 |
| VR | 102 |

A direct consumer of CommonLib's fixed `Entry(*)[0x100000]` helper still sees
the abandoned original table. Mirroring it would not make upper-bank handles
safe and is intentionally not attempted.

## Generated profiles

The generator binds each profile to an exact executable hash and emits:

- field mutations with original and replacement bytes;
- all table RIP-reference records;
- the three initializer guards;
- exact player constructor/selector/release evidence;
- five mandatory generation-guard assignment-hook sites; and
- reviewed literal exclusions and out-of-function fingerprints.

The generated schema deliberately has no `raw_patches`, `release_sites`, or
`excluded_shift11` collections. The generated C++ `Profile` likewise has no
`bytePatches` or `releaseSites` members. Reintroducing one is a verifier
failure, not a backwards-compatibility feature.

Current mandatory counts are:

| Runtime | Fields | References | Init | Player | Guard | Total |
|---|---:|---:|---:|---:|---:|---:|
| SE | 293 | 96 | 3 | 7 | 5 | 404 |
| AE | 394 | 115 | 3 | 7 | 5 | 524 |
| GOG | 394 | 115 | 3 | 7 | 5 | 524 |
| VR | 307 | 102 | 3 | 7 | 5 | 424 |

The 1,876 mandatory total includes 20 generation-guard redirects and is 858
fewer records than the corresponding previous 4M design.

## Transaction and rollback

Startup is a single fail-closed transaction:

1. identify the exact runtime and executable image;
2. validate generated profile structure and every pristine original byte;
3. authenticate collision-sensitive third-party hook state where explicitly
   supported;
4. allocate and construct the replacement table and relay pages;
5. make all writes while Skyrim's manager state is controlled;
6. verify every patched instruction, target, page protection, manager pointer,
   FIFO invariant, player sentinel, and mandatory generation-guard hook; and
7. publish success only after all postconditions hold.

Any failure before success restores every original instruction and manager
value, verifies the rollback, frees unpublished allocations where safe, and
refuses to continue. Loading an unsupported or modified executable never
falls through to a partially patched mode.

The AE Engine Fixes FormCaching overlap is the sole documented third-party
instruction-owner exception. It is accepted only after exact binary, wrapper,
trampoline, live-target, and downstream-site authentication. All other
collisions fail closed.

## Diagnostics and stress testing

`GenerationWrapDetection=1` allocates one `uint32_t` assignment counter per
physical slot: 8 MiB total. Five exact assignment redirects per runtime check
the counter before the stock table-pointer publisher and commit it only after
the publisher succeeds. New successful high-water values are logged through
the maximum safe reuse of 31.

An ordinary slot would become age-ambiguous after 32 reuses. The guard keeps
the player reservation separate and terminates on assignment 33 before the
table pointer/object cache is published, the assignment returns, the manager
unlocks, or the repeated raw value becomes resolvable. A separate prevented
event records the attempted reuse while the successful hottest value remains
31 and published-wrap count remains zero.

“No wrap” in the release oracle means zero repeated-generation/ABA publication
or resolvability, not that the five-bit number never crosses 31 to zero. Safe
reuse 31 issues age zero for the first time for the selected slot. Reuse attempt
32 would repeat the slot's initial age-one value; the caller may already have
written that transient raw dword when the hooked helper fail-stops, but no table
pointer, object cache, function return, or unlock can expose it as a resolvable
handle.

The prerelease stress harness is a disposable-process tool. For 2M it must:

- fill to an exact target above `0x100000` and below `0x200000`;
- prove no ordinary allocation used reserved slot `0x100000`;
- complete a second resolution pass over every retained synthetic handle;
- validate the locked FIFO and a minimum 262,144-slot free cushion;
- release only exact high-bank targets;
- rotate the FIFO to exact-slot reuse;
- prove next-age issuance and stale-handle rejection; and
- prove 31 safe reuses, exact hottest-handle reporting, and zero wrap events;
  then authenticate fail-stop boundary attempt 32 without exhausting the table,
  loading a save, or issuing a normal quit request.

The current release-gate target is 1,800,000, leaving a gross 297,152-slot
margin before incidental live allocations and more than the locked 262,144
minimum.

## Memory and persistence consequences

The replacement table commits 32 MiB instead of the stock 16 MiB. The
mandatory exact counters add 8 MiB. The original image table remains
mapped, though untouched pages need not all become private committed memory.
Relay pages are 4 KiB each.

The table is process-local. Supported save mechanisms persist FormIDs or VM
identities, not these raw dwords. A raw handle produced under stock, 4M/22+6,
or 2M/21+5 cannot be generically migrated because it carries no durable object
identity. Only the deliberately fixed Player value is numerically common.

Do not ship runtime-selectable layouts or auto-migrate raw values. If another
layout is distributed, it must be a distinct, mutually exclusive package with
separate evidence and an explicit persistence warning.

## Compatibility boundary

Compatibility is strongest for code that treats `BSPointerHandle` as opaque
and calls engine APIs. The 2M design additionally preserves CommonLib's
nominal `BSUntypedPointerHandle<21,5>` dimensions, 26-bit storage, table bit 26,
and the complete stock object cache.

It cannot protect private code that:

- masks indices to 20 bits or shifts age by 20;
- dereferences the old fixed table;
- embeds capacity or instruction addresses;
- patches a colliding site without the authenticated exception; or
- persists raw handles across process or layout boundaries.

An upper-bank handle can therefore be silently aliased by a stock decoder.
This risk is why fresh compatibility testing with representative native mods is
required even after complete static verification.

## Source responsibilities

| Component | Responsibility |
|---|---|
| `GenerationTracker.h` | Exact 21+5 constants and reuse-event schema. |
| `ReservedPlayerSlot.h` | Reserved index, sentinel/live words, lifecycle state. |
| `PatchTable.g.h` | Generated exact-runtime records. |
| `PatchTransaction.cpp` | Validation, relocation, install, rollback, player relays. |
| `StockProbe.cpp` | Exact stock/runtime structural checks. |
| `GenerationDiagnostic.cpp` | Mandatory pre-publication guard, exact counters, and reuse high-water reporting. |
| `TableMonitor.cpp` | Read-only table/FIFO/player observations. |
| `StressTest.cpp` | Disposable high-bank second-pass/release/reuse gate. |
| `RuntimeDetection.cpp` | Exact runtime/profile selection. |
| `probes/gen_patchtable.py` | Executable census and JSON generation. |
| `probes/test_patch.py` | In-memory patch and semantic simulation. |
| `probes/verify_deliverable.py` | Cross-artifact/source/binary/package verifier. |

## Evidence limits

Static generation and simulation can prove completeness relative to the exact
audited binaries. They cannot enumerate unknown closed-source mods or validate
timing and ownership inside a live game.

A release claim therefore requires both static and live evidence. Historical
4M results may explain design decisions, but only fresh 2M stress,
compatibility/lifecycle, restoration, and immutable-manifest PASS results can
support version 2.2 publication.
