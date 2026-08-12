# Raising the Creation Engine Pointer-Handle Cap in Starfield

A technical analysis of `Starfield/src/main.cpp` — the SFSE plugin that raises
Starfield's reference-handle capacity from 2^21 (2,097,152) to 2^22
(4,194,304) by replacing the engine's static handle pool and rewriting six
mutable fields of the handle manager, with no machine-code patching.

Target runtime: `Starfield.exe` 1.16.244.0. Built against CommonLibSF
(libxse fork).

---

## TL;DR — in plain English

Think of the game as a cloakroom. Every object in the loaded world — every NPC,
crate, ship part, projectile — gets a numbered ticket, so the rest of the game
can find it again later. The ticket book has a fixed size: about **2.1 million
tickets**. When it runs out, the game can't keep track of anything new, and you
get infinite loading screens, crashes, or objects that quietly stop working.

**Why it was stuck there for 15 years.** In Skyrim and Fallout 4, each object's
ticket number was crammed into a slice of memory it *shares* with other
bookkeeping about that object. There was physically no room for a longer number
without stealing space from something else — and the size was also baked into
the game's compiled instructions in hundreds of places. Fallout 4 already used
every last bit of that shared space. This is a genuine wall, not laziness.

**Why Starfield is different.** Bethesda rebuilt this part of the engine. The
ticket number now has a space of its own, and — the key point — the game no
longer has "2.1 million" hard-wired into its code. It *looks up* how big the
book is, and how to read a ticket, from six values sitting in memory.

**So the fix itself is tiny.** Hand the game a ticket book twice the size, then
update those six values to describe it. That is 24 bytes written and not one
instruction changed. The cap was never really a limit — it was a setting that
nobody had a way to change from the outside.

**The hard part is doing it safely.** Three things carry that weight:

* **Timing.** There is a roughly 37-second window early in startup where the
  cloakroom is fully built but nobody has asked for a ticket yet. Swapping the
  book *there* means nothing can catch the change half-finished. Do it later,
  while several threads are handing out and checking tickets at once, and
  someone eventually gets handed the wrong coat — which is far worse than a
  crash, because the game carries on as if nothing happened.
* **Proof before writing.** Before touching anything, the mod checks that all
  six values are exactly what a brand-new, never-used cloakroom should hold. If
  anything looks even slightly different — a game update, another mod, tickets
  already issued — it does nothing at all and says so in the log.
* **The trade-off.** A ticket number has a fixed number of digits, split
  between "which slot" and "how many times this slot has been reused" — the
  second half is how the game recognises an out-of-date ticket. Doubling the
  slots takes one digit from the reuse counter, so it now cycles every 1,024
  reuses instead of 2,048. In practice that is billions of allocations away,
  but the mod counts them anyway and shouts loudly if it ever wraps.

Everything below is the detailed version, with sources.

---

## 1. Executive summary

| | Stock | After the plugin |
|---|---:|---:|
| Index bits | 21 | 22 |
| Handle slots | 2,097,152 | 4,194,304 |
| Usable handles (slot 0 reserved) | 2,097,151 | 4,194,303 |
| Generation bits | 11 | 10 |
| Generations before reuse aliasing | 2,048 | 1,024 |
| Pool storage | 32 MiB static (in-image) | 64 MiB `VirtualAlloc` |
| Instructions patched | — | **0** |
| Bytes of engine state written | — | **24** (six fields) |

A note on the commonly cited "~2 million handle limit": that figure is exact
for Starfield (2^21 = 2,097,152) but not for Skyrim, whose table holds 2^20 =
1,048,576 entries. The two engines share the design and the failure mode, not
the number (§2.4).

The plugin's central finding is that **Starfield's handle manager is
data-driven, not constant-driven.** The index mask and the generation
increment are read at runtime from fields of the manager object rather than
baked into instruction immediates. That makes the cap a *value*, not a
*layout* — so raising it requires no code patching at all, only:

1. allocating a bigger slot pool and threading its free list, and
2. writing six 32/64-bit fields in the manager during a proven-quiet window
   in startup.

Everything else in the plugin is verification, timing, and diagnostics.

---

## 2. Background: what a "pointer handle" is

### 2.1 The problem handles solve

Creation Engine game objects (`TESObjectREFR` and its subclasses — placed
references, actors, projectiles) are heap objects that can be destroyed at any
time: an actor unloads, a projectile despawns, a cell is dropped. Thousands of
subsystems — AI packages, combat, quests, Papyrus scripts, havok, the renderer
— need to *refer* to those objects across frames.

Raw pointers cannot do that safely: the referent may be freed, leaving a
dangling pointer that reads freed memory. Reference-counted pointers cannot do
it either, because everything holding one would keep dead objects alive
forever.

The engine's answer is a **weak handle**: a 32-bit integer, not a pointer.
Handles are resolved through a central table that can answer "this handle no
longer refers to anything" instead of returning garbage.

### 2.2 The encoding

A handle packs two fields into one 32-bit word:

```
  31                     21 20                              0
 +--------------------------+---------------------------------+
 |  generation (11 bits)    |      slot index (21 bits)       |  stock
 +--------------------------+---------------------------------+

  31                   22 21                                 0
 +------------------------+-----------------------------------+
 | generation (10 bits)   |       slot index (22 bits)        |  after the
 +------------------------+-----------------------------------+  plugin
```

* **Slot index** — which entry of the handle table this handle refers to.
* **Generation** (also called *age*) — a counter incremented every time the
  slot is recycled onto a new object.

Resolution is: mask off the index, load the table entry, and compare the
stored generation with the generation carried in the handle. If they differ,
the slot has been recycled since the handle was minted and the lookup fails
cleanly instead of returning the wrong object. This is the classic *slot map /
generational index* pattern.

The two fields share one 32-bit word, so **every bit given to the index is a
bit taken from the generation counter.** That trade-off is the reason the cap
cannot simply be raised to an arbitrary number, and it is why the plugin ships
a generation-wrap detector (§7).

### 2.3 The table entry

Starfield's pool entry is 16 bytes:

| Offset | Size | Meaning |
|---:|---:|---|
| `+0x00` | 8 | Object pointer — the `TESObjectREFR`-derived object occupying this slot, or `0` if free |
| `+0x08` | 8 | Free-list "next index" while free / generation bits while live |

Two consequences the plugin relies on directly:

* **A slot is live iff `qword0 != 0`.** `CreateHandle` writes the object
  pointer there and `Release` writes `0` back
  (`Starfield/src/main.cpp:353-360`). That is what makes the above-cap
  diagnostic scan possible (§8.2).
* **The free list is threaded through the entries themselves.** Free slots
  form a singly-linked list where each entry's `qword1` holds the index of the
  next free slot. No separate allocation, no side table.

### 2.4 How Skyrim did it, and why the constraint was different

Skyrim's equivalent is `BSPointerHandleManager` / `BSUntypedPointerHandle`,
and it is both smaller and structurally tighter. Stock layouts across the three
generations of the engine — the Skyrim column is identical for all four
runtimes this repository supports:

| | Skyrim SE/AE/VR | Fallout 4 | Starfield |
|---|---|---|---|
| Raw handle index | bits `[19:0]` — **20** | bits `[20:0]` — **21** | bits `[20:0]` — **21** |
| Generation ("age") | bits `[25:20]` — 6 bits, 64 gens | bits `[25:21]` — 5 bits, 32 gens | bits `[31:21]` — 11 bits, 2,048 gens |
| In-use bit | bit 26 (entry word only) | bit 26 (entry word only) | n/a (object pointer non-null = live) |
| Unused handle bits | `[31:26]` | `[31:26]` | none |
| Capacity | 2^20 = **1,048,576** | 2^21 = **2,097,152** | 2^21 = **2,097,152** |
| Table storage | 16 MiB static, in-image | 32 MiB static | 32 MiB static, in-image |
| Entry stride | 16 bytes | 16 bytes | 16 bytes |
| Capacity/mask location | **inlined into instructions** | **inlined into instructions** | **mutable manager fields** |

*(Skyrim figures: `Skyrim/DESIGN.md:53-58`, `:76-80`, with
`stockEntries = 0x100000` in every generated profile in
`Skyrim/src/PatchTable.g.h`. Independently confirmed by CommonLibSSE's
concrete constants — `kAgeInc = 1 << 20`, `kFreeListMask = 0xFFFFF`,
`kInUseBit = 1 << 26`, and the table declared `Entry(*)[0x100000]` — in
[powerof3/CommonLibSSE `RE/B/BSPointerHandleManager.h`](https://github.com/powerof3/CommonLibSSE/blob/dev/include/RE/B/BSPointerHandleManager.h),
and by CKPE's `IBSUntypedPointerHandle<uint32_t, 20, 6>` typedef. Fallout 4
figures from CKPE's Fallout 4 header, which states outright
`// vanilla --- class BSUntypedPointerHandle<21,5>`.)*

Note the `<21, 5>` default template arguments that appear in the CommonLib
family's `BSUntypedPointerHandle` forward declaration are **Fallout 4's**
values. They are copied boilerplate in the Skyrim and Starfield forks and
contradict those games' actual constants; do not treat them as evidence for
either.

Skyrim then adds a second constraint Starfield does not have. Each object
caches its own table index in the *same 32-bit word as its reference count* —
`BSHandleRefObject::_refCount`, at `NiRefObject+0x08` (so `TESObjectREFR+0x28`):

```cpp
enum
{
    kRefCountMask = 0x3FF,      // bits 0..9   -> max refcount 1023
    kHandleValid  = 1 << 10,    // bit 10
                                // bits 11..31 -> 21 bits of cached index
};
```

*(verified locally: `include/RE/BSMain/BSHandleRefObject.h:14-19`, with the
mask arithmetic in `src/RE/BSMain/BSHandleRefObject.cpp:8-36`; the same split
is documented at `Skyrim/DESIGN.md:98-103` and encoded in
`Skyrim/src/StressTest.cpp:76-78`.)*

That word is mutated by `InterlockedIncrement` / `InterlockedDecrement` on
every reference operation in the game — unmasked, on the whole dword, which
only works because the index sits *above* the refcount field (a refcount
carrying out of bit 9 would corrupt the valid flag and then the cached index).
And it has exactly **21 spare bits**.

**That 21-bit field is where the famous "~2 million" ceiling actually comes
from.** It is not the table size; it is the object-side cache. A 20-bit index
fits, a 21-bit index fits exactly, and a 22-bit index does not. Going past 2^21
on this design means taking a bit from the refcount (halving maximum
simultaneous references to one object from 1023 to 511), taking the
handle-valid flag, or storing the index somewhere else entirely. CKPE's
Creation Kit patches demonstrate the first option is real and costly: its
"extremely extended" mode reaches 23 index bits precisely by cutting the
refcount field from 10 bits to 8 (max 255 references per object).

**Fallout 4 sits exactly on that ceiling.** Bethesda shipped it with 21 index
bits and 5 age bits — 2,097,152 handles, the most that design can address
without touching the refcount word (§10).

This repository's Skyrim project takes the third option — storing the index
elsewhere. It puts the complete 22-bit index in the adjacent existing padding dword
`NiRefObject::_pad0C` (`TESObjectREFR+0x2C`) and rewrites every compiler-inlined
reader, writer, and release site to use it (`Skyrim/DESIGN.md:104-111`,
`Skyrim/README.md:7-12`). It reaches the same 4,194,304-handle target as the
Starfield plugin — but by patching **2,714 instruction sites** across four
runtimes, with 6 generation bits preserved by consuming previously-unused high
handle bits (`Skyrim/src/GenerationTracker.h:11-25`,
`Skyrim/docs/patch-sites/README.md:6-12`).

**Starfield has neither constraint.** The comment at
`Starfield/src/main.cpp:5-6` records the audit result explicitly: the
`TESForm+8` word holds no handle index, so widening the index costs no refcount
bits. Starfield caches the object's handle in its own full, unshared 32-bit
word at `TESForm+0x24` (`Starfield/src/main.cpp:363`) — and, per §3, keeps the
capacity itself in a mutable field instead of in instruction immediates.

### 2.5 What running out looks like

The failure is **silent by construction**. When the free list empties,
`CreateHandle` does not throw, does not allocate, and does not return an error
— it returns a bitwise-null handle. The Creation Kit build carries an assert
for this (`"OUT OF HANDLE ARRAY ENTRIES. Null handle created for pointer
0x%p."` in Nukem9's reimplementation); the optimised retail build does not.
Every subsequent `GetSmartPointer` on that handle simply reports "nothing
there".

So the observable symptom is not "allocation failed". It is **a reference that
exists in memory but is unreachable through the handle system** — invisible to
every subsystem that looks references up by handle. From aers (author of SSE
Engine Fixes), in the canonical 2019 write-up:

> "There's a cap of 2^20, or 1048576, active reference handles at any time. If
> you hit the cap, the game will either get stuck loading or just outright CTD
> or really do any number of things."

The Skyrim-specific reason load orders reach it is worth knowing, because it is
counter-intuitive: **temporary references stream in and out only for masters.
All temporary references from regular plugins are loaded before the main menu.**
A few large `.esp` worldspace mods can therefore consume a quarter of the whole
table before the player has pressed New Game — aers cites ~136k temporary refs
for one dungeon mod and ~110k for another — and community counts of ~1.03M
loaded references on large load orders are within a rounding error of the cap.
Saves compound this, since a playthrough accumulates its own references over
time.

Two clarifications, because both are widely muddled in community threads:

* **This does not corrupt save files.** Handles are process-local and are never
  serialised; saves reference objects by FormID. The documented symptoms are
  infinite load screens, crashes, and references that stop working — not
  on-disk corruption.
* **`MaxStdIO` is a different limit.** The Engine Fixes / Buffout setting that
  "fixes the false save corruption bug" raises the CRT's `_setmaxstdio` **file
  descriptor** limit. It has nothing to do with `BSPointerHandleManager`. The
  name collision is the single most common source of confusion here.

For Starfield the situation-specific pressure is the same shape — long
playthroughs, dense outposts, large ships, heavy load orders — though public,
first-hand exhaustion reports are scarce. What is verifiable is that demand
exists: Starfield Engine Fixes ships a pointer-handle dump
(`DumpPointerHandles` / `dph`), a configurable low-handle warning threshold,
and an option to auto-save when that threshold trips.

### 2.6 Prior art

The cap has been raised before — but, with the exception of the projects in
this repository, **only in the Creation Kit, never in the shipped game.**

| Tool | Target | What it does |
|---|---|---|
| Nukem9 `skyrimse-test` / CK64Fixes | Skyrim **CK** | Reimplements the handle manager at 21 index bits. Header comment: *"Handle index bits increased from 20 (vanilla) to 21 (limit doubled)"* |
| CKPE (Creation Kit Platform Extended) | Skyrim **CK** | Detours 10 manager entry points; 21 bits by default, `bBSPointerHandleExtremly` → 23 bits by cutting the refcount to 8 bits |
| CKPE | Fallout 4 **CK** | 21 (vanilla) → 23 → 26 index bits, the wider modes backed by a 64-bit manager |
| Nukem9 PR #28 | Skyrim **CK** | Proposed 25 bits by stealing a refcount bit — open since 2022, never merged |
| **Fallout 4 itself** | game | Bethesda shipped the doubled 2^21 cap (§10) |
| SSE Engine Fixes | Skyrim game | **Warns only.** Counts in-use entries by testing bit 26 across the 0x100000 array; `uRefrMainMenuLimit = 800000`, `uRefrLoadedGameLimit = 1000000` |
| Daytripper 4, Addictol | FO4 game | **Warn only.** Addictol's current behaviour on exhaustion is save-and-quit |
| Starfield Engine Fixes | Starfield game | **Reports only.** `DumpPointerHandles` console command, low-handle warning, save-on-warning |
| xEdit `count_loaded_refs_in_load_order.pas`; Persistentify Those Plugins | load order | Pre-flight counting; converting plugins to masters to reduce resident temporaries |

Two things stand out. First, **Buffout 4 has no handle feature at all** — its
`[Warnings]` section covers only `CreateTexture2D` and `ImageSpaceAdapter`.
Attributions of a reference-handle limiter to Buffout are misattributions of
Addictol's and Daytripper's settings. Second, the reason everyone stopped at
the Creation Kit is documented by aers himself:

> "FO4 actually has the limit doubled to 2^21 by doing.. basically what the CK
> fix does. **Its harder to implement the patch in the game because CK is
> compiled with basically no optimizations whereas the game is, so a lot of
> stuff ends up inlined — including some ref handle functions.**"

That is precisely the wall the sibling Skyrim project had to climb with 2,714
instruction patches — and precisely the wall that Starfield's redesigned,
field-driven manager removes.

---

## 3. The key finding: Starfield's cap is data, not code

The plugin's entire approach rests on one reverse-engineering result: on
Starfield 1.16.244 the handle manager keeps its capacity, index mask, and
generation increment **in mutable instance fields**, and the engine's handle
code reads them from there.

### 3.1 The manager's control fields

Verified offsets from the manager object
(`Starfield/src/main.cpp:58-69`):

| Offset | Type | Field | Stock value |
|---:|---|---|---:|
| `+0x00` | `void**` | vtable pointer | ID `450711` |
| `+0x50` | `T*` | pool pointer | in-image static pool |
| `+0x58` | `u32` | free-list head | `1` |
| `+0x5C` | `u32` | free-list tail | `0x1FFFFF` |
| `+0x60` | `u32` | free counter | `0x200000` |
| `+0x64` | `u32` | capacity **== generation unit** | `0x200000` |
| `+0x68` | `u32` | index mask | `0x1FFFFF` |

The load-bearing entry is `+0x64`. It is simultaneously the pool capacity and
the **generation increment**: a handle is formed as

```
handle = generation * capacity + index      (capacity a power of two,
       = (generation << 22) | index          so this is a shift and an OR)
```

Because the increment is the capacity field, widening the pool automatically
moves the generation field up one bit and halves the generation space — the
engine needs no separate notion of "how many generation bits are there".
Writing `0x400000` into `+0x64` and `0x3FFFFF` into `+0x68` reconfigures the
entire handle format.

**Independent corroboration.** CKPE reverse-engineered Starfield's *Creation
Kit* handle manager separately and arrived at the same structural shape — and
it is a genuinely different structure from Skyrim's and Fallout 4's:

```cpp
// CKPE.Starfield — TESPointerHandleDetail.h
struct TESHandleManagerTag {
    Forms::TESObjectREFR* Refr;   // 00  — a RAW pointer, not NiPointer
    std::uint32_t         Index;  // 08
    char                  pad0C[4];
};
static_assert(sizeof(TESHandleManagerTag) == 0x10);

template <typename TType, std::uint32_t Total> class Manager {
    char          pad08[0x50];
    std::uint32_t _HeadEntries;  // 0x58
    std::uint32_t _Unk5C;        // 0x5C
    std::uint32_t _FreeEntries;  // 0x60
    std::uint32_t _Unk64;        // 0x64
    std::uint32_t _MaxEntries;   // 0x68
    std::uint32_t _TailEntries;  // 0x6C
    ...
    inline static ISingleton<Manager<TType, Total>> Singleton;
    virtual std::uint32_t GetMax_Virtual() const;   // capacity is VIRTUAL
};
```

The two reverse-engineering efforts agree on everything that matters to this
plugin: a **polymorphic singleton**, 16-byte entries with the object pointer at
offset 0, and a block of head / tail / free / max control dwords at `0x58`–`0x6C`
— i.e. **capacity is a runtime member, not a compile-time constant.** CKPE even
exposes it through a virtual `GetMax_Virtual()`, which is about as explicit as
an engine can be that the value was meant to be variable.

They differ on which dword is which. CKPE labels `+0x68` `_MaxEntries` and
`+0x6C` `_TailEntries` and leaves `+0x64` unnamed; this plugin treats `+0x5C`
as the free-list tail, `+0x64` as the capacity / generation unit, and `+0x68`
as the index mask. The capacity disagreement is reconcilable — a mask of
`0x1FFFFF` read as a count is "max index = 2,097,151" — and CKPE targets the
*Creation Kit* binary, a different build from the game, so field assignments
need not match. (CKPE's template also instantiates `Total = 8388608` for the
CK; that is a CK figure and says nothing about the game's capacity.)

Either way, the labelling ambiguity is not load-bearing here, because the
plugin never writes a field in isolation: the stock-shape gate (§6.2) requires
all six to hold their exact stock values, and the commit writes a
self-consistent replacement set. If `+0x64` is "generation unit" rather than
"capacity", the written value is correct under either reading.

### 3.2 Why that means no code patching

If the mask (`0x1FFFFF`) or the generation unit (`0x200000`) were compiled
into instruction immediates anywhere in the handle path, changing the fields
would desynchronise those sites from the manager and produce handles that
decode differently depending on which code touched them — the worst possible
failure mode.

The two Ghidra probes in `Starfield/probes/` exist to test exactly that:

* **`McpScalar2.java`** enumerates every occurrence of the relevant
  immediates — `0x1FFFFF` (stock index mask), `0x200000` (stock generation
  unit), `0xFFE00000` (stock generation mask), plus the widened candidates
  `0x3FFFFF` / `0xFFC00000` and near-variants — across the whole image
  (`McpScalar2.java:17-27`). Critically, it separates *pure immediate
  operands* from *scalars that are only address displacements inside memory
  operands* (`McpScalar2.java:52-54`), because a whole-image scan for
  `0x200000` is otherwise dominated by `LEA` addressing noise. The comment on
  line 20 flags the trap: `0x1FFFFF` is also a plausible refcount mask, so hits
  must be classified, not counted.
* **`McpMaskCtx.java`** takes one immediate, finds every function containing it
  as a pure operand, decompiles each one, and classifies it by whether the
  surrounding code shifts by 21 (`>> 0x15` / `<< 0x15`), touches refcount flag
  bits, or calls the known handle-manager routines
  (`McpMaskCtx.java:26-72`).

Together they answer "is the cap a constant anywhere in this binary?" — and
the plugin's design (six field writes, no instruction patches) is the
published answer: on the audited image, it is not.

**Verification caveat, stated plainly:** per `Starfield/VERIFY.md:18-21` and
`Starfield/probes/README.md:14-19`, the reviewed probe run targeted the exact
1.16.236 image, not the 1.16.244 release target. A fresh hash-bound 1.16.244
whole-image audit is listed as open work. The runtime stock-shape gate (§6.2)
is what protects the 1.16.244 user in the meantime.

### 3.3 Contrast with the Skyrim implementation in this repository

Both halves of this repository raise the cap to the same 4,194,304 handles.
Almost nothing else about them is the same, and the difference is not
stylistic — it follows directly from §2.4 and §3.1.

| | **Starfield** | **Skyrim** |
|---|---|---|
| Cap source | six mutable manager fields | constants inlined into instructions |
| Change applied | **6 field writes (24 bytes)** | **2,714 instruction sites** across 4 runtimes |
| Instruction sites patched | 0 | 1,838 field rewrites, 436 sidecar windows, 428 table refs, 12 init guards |
| Object-side index | own 32-bit word at `+0x24` | shares refcount word; 22-bit index needs a sidecar in `_pad0C` (`+0x2C`) |
| Pool | `VirtualAlloc` anywhere | `VirtualAlloc` **within ±2 GB of every table instruction**, because 96–115 `lea reg,[rip+disp32]` sites address it directly |
| Address resolution | Address Library IDs | hard-coded per-profile RVAs + exact stock-byte `memcmp` gates |
| Runtimes supported | 1.16.244 | SE 1.5.97, AE 1.6.1170, GOG 1.6.1179, VR 1.4.15 |
| Generation budget after raise | 2,048 → **1,024** | **64, unchanged** (extra index bits taken from unused high bits) |
| Diagnostic hook | 1 vtable slot | 5 `CALL rel32` redirects — Skyrim has no manager vtable callback, and the allocator exists as five compiler clones |
| Generated artifacts | none (correctly) | `patch_*.json`, `sites_*.json`, `PatchTable.g.h`, per-site disassembly docs |

*(Skyrim counts from `Skyrim/docs/patch-sites/README.md:6-12`; the
five-clone/no-vtable finding from `Skyrim/probes/gen_patchtable.py:639-644`;
the displacement-range constraint from
`Skyrim/src/PatchTransaction.cpp:264-298`.)*

The root `README.md:19-25` records this asymmetry as the reason Starfield ships
no equivalent generated patch table: there are no instructions to tabulate.
The absence is documented rather than papered over with a fabricated artifact.

---

## 4. What the plugin does

### 4.1 Lifecycle

```
SFSE_PLUGIN_LOAD                       (main.cpp:929)
  ├─ SFSE::Init(trampoline = false)     no code hooks needed at load
  ├─ LoadConfig()                       Data\SFSE\Plugins\StarfieldHandleCapRaise.ini
  └─ CreateThread(WatcherThread)

WatcherThread                           (main.cpp:899)
  ├─ PreparePool()                      VirtualAlloc 64 MiB + thread free list
  ├─ PrepareGenerationDetector()        VirtualAlloc 8 MiB sidecar (optional)
  ├─ poll singleton ptr every 1 ms, 120 s deadline
  │     └─ TryCommit(manager)
  │           ├─ Wait     -> keep polling
  │           ├─ Refused  -> release everything, exit (no-op)
  │           └─ Done     -> InstallGenerationDetector(), then LivenessLog()
  └─ timeout -> warn, release everything, exit
```

### 4.2 Building the replacement pool

`PreparePool()` (`main.cpp:131-150`) runs *before* the swap window so the swap
itself is only field writes:

```cpp
g_newCap = 1ull << kTargetBits;                       // 4,194,304
const std::size_t poolSz = g_newCap * kPoolEntrySize; // 64 MiB
g_newPool = VirtualAlloc(nullptr, poolSz, MEM_RESERVE | MEM_COMMIT,
                         PAGE_READWRITE);

for (std::uint64_t i = 1; i < g_newCap; ++i) {
    *(std::uint64_t*)(g_newPool + i * 16 + 8) =
        (i + 1 < g_newCap) ? (i + 1) : 0ull;
}
```

Three details matter:

* **Index 0 is reserved** as the null handle and is deliberately left out of
  the free list — matching the stock free-list head of `1`.
* **The threading pattern was copied from the engine's own constructor.** The
  comment at line 144 records that the engine builds its list with
  `MOV [pool + i*16 + 8], i+1`, i.e. entry *i* points to *i+1* with the tail
  entry storing `0`. The plugin reproduces that byte-for-byte rather than
  inventing an equivalent-looking layout.
* **`VirtualAlloc` zero-fills**, so every `qword0` starts null — which is both
  the correct "slot is free" state and the precondition for the above-cap
  liveness scan in §8.2.

The pool is never freed once committed; ownership transfers to the engine
(`main.cpp:911`). The stock 32 MiB pool is static, in-image memory, so nothing
leaks — it simply stops being referenced.

### 4.3 The swap

`TryCommit()` (`main.cpp:287-351`) performs the whole capacity change:

```cpp
*pPool = (std::uint64_t)g_newPool;   // +0x50  new 64 MiB pool
*pHead = 1u;                         // +0x58  first free slot
*pTail = newMask;                    // +0x5C  0x3FFFFF
*pCtr  = newCap;                     // +0x60  0x400000
*pCap  = newCap;                     // +0x64  0x400000  (also generation unit)
*pMask = newMask;                    // +0x68  0x3FFFFF
```

That is the entire cap raise: one pointer and five integers.

Note that the free counter is set to `newCap` (`0x400000`), not `newCap - 1`,
even though only indices `1..newCap-1` are actually free. This preserves the
engine's own off-by-one convention — stock ships `0x200000` in that field with
`0x1FFFFF` genuinely-free slots. The plugin mirrors the engine rather than
"fixing" it, and the reporting code compensates by measuring usage against
`g_newCap - 1` (`main.cpp:866-879`). Deviating here would have made the
plugin's state inconsistent with whatever engine code also reads that counter.

All six pointers are declared `volatile` (`main.cpp:290-295`) because they
alias live engine memory that other threads may touch.

---

## 5. Timing: the load-bearing detail

Naively, one would resize at first use or at some SFSE message like
`kDataLoaded`. The plugin does neither, and the reasoning
(`main.cpp:8-15`) is the most interesting engineering decision in the project.

Two facts from instrumented runs:

* the handle manager is **constructed during startup init, at ~1 s**;
* the **first handle is not allocated until content loads, at ~38 s**.

That leaves a **~37-second window in which the manager is fully constructed
but completely untouched** — no `CreateHandle`, no `LookupByHandle`, no
`Release`, on any thread. Inside that window the six writes are effectively
single-threaded and need no synchronisation at all.

Contrast with swapping at first use: by then the render thread is concurrently
resolving handles. A non-atomic six-field swap there is torn by construction —
another thread can read the new pool pointer with the old mask, or the new mask
with the old pool — and a torn read resolves a handle to the *wrong object*,
which is a silent memory-safety failure, not a clean crash.

The detection mechanism is precise and cheap: the manager's **singleton
pointer is the last thing its constructor publishes**, so a non-null read there
means the manager — pool, threaded free list, all six fields — is fully built
(`main.cpp:45-50`). The watcher polls that pointer (Address Library ID
`883285`) at 1 ms intervals with a 120-second wall-clock deadline
(`main.cpp:904-921`) and commits the moment it is published.

This is why the plugin sets `.trampoline = false` at init (`main.cpp:933`): it
needs no code trampoline, because it never hooks a hot function to catch the
right moment.

---

## 6. Safety engineering

The swap itself is 6 writes; the rest of `TryCommit` is about never performing
those writes against a structure that isn't the one that was verified.

### 6.1 The three-state commit

`enum class Commit { Wait, Done, Refused }` (`main.cpp:278`) separates "not
ready yet" from "ready but wrong", so a partially-constructed manager keeps the
watcher polling while an unrecognised manager stops it permanently.

### 6.2 The stock-shape gate

Before writing anything, **every one of the six fields must hold its exact
stock value** (`main.cpp:298-315`):

| Check | Required value |
|---|---:|
| mask | `0x1FFFFF` (else `Wait` — written mid-construction) |
| head | `1` |
| tail | `0x1FFFFF` |
| free counter | `0x200000` |
| capacity | `0x200000` |
| pool pointer | non-null |

This is a *layout* check disguised as a *value* check, and that is the point:
if the struct layout differed on some other build, six unrelated fields would
not coincidentally all hold the exact stock constants at these offsets. A
mismatch therefore means "refuse", never "write to the wrong place". It also
doubles as a liveness check — a non-pristine free counter means handles are
already in use, so the window has been missed.

The failure log distinguishes the two possible causes explicitly
(`main.cpp:309-313`): *"either handles are already in use or the struct layout
differs on this game version"*.

### 6.3 Read-back and revert

After writing, all six fields are read back and compared. On any mismatch the
plugin restores the exact previous values, logs, and refuses
(`main.cpp:329-339`). The source itself labels this "additive
belt-and-suspenders" — the real protection is the gate above — which is a
notably honest way to document a defence.

### 6.4 Version binding

The plugin declares itself layout-dependent and binds to one runtime
(`main.cpp:953-965`):

```cpp
data.UsesAddressLibrary(true);
data.UsesSigScanning(false);
data.IsLayoutDependent(true);
data.CompatibleVersions({ SFSE::RUNTIME_SF_1_16_244 });
```

Every engine address is resolved through Address Library IDs, never hard-coded
RVAs, so the mapping is data supplied per game version rather than assumptions
baked into the DLL (`Starfield/HASHES.md:17-24`):

| ID | Purpose | 1.16.236 RVA | 1.16.244 RVA |
|---:|---|---:|---:|
| `883285` | handle-manager singleton pointer | `0x5E68140` | `0x5E60380` |
| `36239` | reference lookup by handle | `0x2CF360` | `0x2CEC10` |
| `450711` | handle-manager primary vtable | `0x4CB6D88` | `0x4CB2E98` |
| `99517` | native-handle assignment callback | `0x18A2090` | `0x189F8D0` |
| `139363` | core handle resolver (audit only) | `0x28D0FF0` | `0x28CCC40` |

---

## 7. The generation-wrap detector

### 7.1 Why it exists

The one real cost of the change is in §2.2's bit budget: 22 index bits leave
10 generation bits, so a slot's generation now wraps after **1,024** reuses
instead of 2,048. After a wrap, a stale handle minted 1,024 reuses ago decodes
to the same `(index, generation)` pair as a live one and will resolve
*successfully* to the wrong object.

That is the most dangerous failure mode in the whole design, precisely because
it is *not* a crash: the lookup succeeds and hands back a live, valid pointer
to an unrelated reference.

How much margin is 1,024, really? The manager keeps both a free-list **head**
(`+0x58`) and a **tail** (`+0x5C`), which is the signature of a FIFO queue —
allocation pops the head, release appends to the tail. That is exactly how
Skyrim's manager is known to work, and it has a strong consequence: a released
slot goes to the *back* of the queue, so it is not reused until every other
free slot has been handed out first. Reusing one slot 1,024 times therefore
takes on the order of 1,024 × the free-list length allocations — billions, in
a pool of four million. *(Inference from the head/tail field pair and the
documented Skyrim behaviour, not from disassembly of Starfield's release
routine.)*

So the expected risk is low — but "expected" is doing real work in that
sentence, and the cost of being wrong is silent wrong-object resolution.
Rather than assert it is fine, the plugin measures it. On by default
(`GenerationWrapDetection=1`).

### 7.2 How it hooks

Rather than trampolining `CreateHandle`, the detector replaces **slot 2 of the
manager's own vtable** — a callback the engine already invokes after assigning
a new handle, *while holding the manager's exclusive lock*
(`main.cpp:76-82`, `236-276`). Two benefits: no trampoline and no code
patching anywhere, and the sidecar update inherits the engine's own mutual
exclusion, so it needs no atomics (`main.cpp:91-94`).

Installation is itself gated: the manager's vtable pointer must equal the
Address Library value for ID `450711`, *and* the existing slot-2 pointer must
equal ID `99517`, before anything is written (`main.cpp:240-257`). The write
goes through `REL::WriteSafeData`, is read back for confirmation, and any
failure rolls the detector's state back and disables it rather than the plugin
(`main.cpp:262-273`). A failure to restore page protection is logged as a
warning, not silently swallowed.

Because a vtable is shared by all instances of a class, the hook also checks
`manager == g_trackedManager` before recording, so a second manager instance
cannot pollute the statistics (`main.cpp:205`).

### 7.3 What it tracks

An 8 MiB sidecar array holds one `uint16` assignment counter per slot
(4,194,304 × 2 bytes). Per assignment (`RecordHandleGeneration`,
`main.cpp:152-197`):

* increment that slot's counter (measuring up to 65,534 reuses — 63 complete
  wraps — before saturating);
* if the pre-increment reuse count is a non-zero multiple of 1,024, that is a
  `1023 → 0` transition: publish a **wrap event**;
* cross-check the generation actually observed in the handle against
  `reuses % 1024`; a disagreement means tracking is no longer exact, so the
  slot is recorded and reports are flagged `tracking UNRELIABLE`;
* maintain a "hottest handle" — the slot with the most reuses — using a CAS
  loop on a single 64-bit atomic that packs `reuses` and `handle` together, so
  a report can never mix the reuse count of one slot with the handle of
  another (`main.cpp:187-196`).

Wrap events are published through a **seqlock**: the writer bumps a sequence
counter to odd, stores the event and total, then bumps it to even
(`main.cpp:170-177`); the monitor retries until it reads a stable even
sequence around its snapshot (`ReadWrapSnapshot`, `main.cpp:811-823`). That
gives the reader a coherent (total, latest-event) pair without ever blocking
the game thread.

A detected wrap is logged at `critical`:

```
HANDLE GENERATION WRAP DETECTED: total N, slot S, reuse R, new handle 0xHHHHHHHH;
stale-handle aliasing is now possible
```

---

## 8. Diagnostics

### 8.1 Routine reporting

`LivenessLog` (`main.cpp:828-886`) ticks once a minute and reports every five
minutes:

```
handles in use: 2431902 / 4194303 (58.0%) | generation reuse: highest 37 / 1024
at slot 918273 (handle 0x09600F81, current ref [0x000ABCDE] "SomePlugin.esm"), wraps 0
```

(one line in the log; wrapped here for readability — the exact format strings
are at `main.cpp:869-879` and `main.cpp:553-604`)

Usage is derived lock-free from the free counter (`used = capacity - free`). If
that counter ever reads above capacity, the field no longer looks like the
counter and the monitor stops rather than emitting noise
(`main.cpp:861-865`).

The "hottest handle" line resolves the handle through the engine's own lookup
(Address Library ID `36239`) rather than reading `qword0` from the pool
directly, because that wrapper takes the manager's read lock and increments the
form refcount before returning — so calling virtual methods on the result
cannot race the reference's destruction (`main.cpp:52-56`, `389-397`).

### 8.2 The "what is actually using the extra handles" report

With `VerboseLogging=1`, once usage exceeds the old cap the plugin scans
indices `2^21 .. 2^22` once per minute (`ReportPastCap`, `main.cpp:746-803`).
The logic is a direct consequence of §2.3: a slot is live iff `qword0 != 0`,
and the extension range was zero-filled by `VirtualAlloc`, so **every non-null
object pointer at or above index 2^21 is a reference that only exists because
the cap was raised.**

For each such object it reads the cached native handle, FormID, form type, and
source-file index, then logs:

* the total past the old cap, plus how many objects independently agree they
  live at that index (`(nativeHandle & mask) == i`) and how many were
  unreadable;
* a histogram of the top 8 form types, named for the reference family (`REFR`,
  `ACHR`, `PMIS`, `PARW`, `PGRE`, `PBEA`, `PFLA`, `PCON`, `PPLA`, `PBAR`,
  `PEMI`, `PHZD` — `main.cpp:608-617`; anything else prints numerically and is
  itself a red flag);
* a histogram of the top 6 **source plugins** — i.e. which mod is responsible;
* up to 64 detailed samples with editor IDs, display names, and base forms.

That turns "the cap was raised" into an auditable claim about *which content*
consumes the extra capacity.

### 8.3 Reading engine memory without crashing

Every read of a possibly-stale object pointer is wrapped in SEH
(`SafeReadObject`, `main.cpp:371-384`; `SafeReadFormText`, `main.cpp:427-445`;
`SafeGetSourceFile`, `main.cpp:447-456`). A slot can be freed and its object
deleted between reading `qword0` and dereferencing it; SEH turns that rare
use-after-free into a clean "unreadable" tally instead of a fault. The bodies
are POD-only because MSVC forbids C++ objects requiring unwinding in a
function using `__try` — the owning `NiPointer` is held by the caller.

There is also a small piece of defensive archaeology: CommonLibSF's public
`TESFile` layout predates Starfield 1.16.x, so its declared `fileName` field is
not at `+0x38` on the supported runtime. Rather than dereference a stale
offset, `PluginFileName` (`main.cpp:518-539`) *searches* the live `TESFile`
object for a NUL-terminated string that looks like a plugin name — printable
name characters, length ≥ 5, ending in `.esm` / `.esp` / `.esl`
(`main.cpp:481-505`) — first inline in the first `0x800` bytes, then via
plausible readable header pointers. Every candidate address is validated with
`VirtualQuery` for committed, non-guard, readable pages before being touched
(`Readable`, `main.cpp:462-479`).

### 8.4 Configuration

`Data\SFSE\Plugins\StarfieldHandleCapRaise.ini` (`main.cpp:111-127`):

| `[General]` key | Default | Effect |
|---|---:|---|
| `VerboseLogging` | `0` | Enables the per-minute above-cap report (§8.2) |
| `GenerationWrapDetection` | `1` | Enables the 8 MiB sidecar detector (§7) |
| `SampleSize` | `16` | Detailed samples per report, clamped to `0..64` |

---

## 9. Costs and trade-offs

| Cost | Detail |
|---|---|
| **Memory** | +64 MiB for the pool, +8 MiB for the detector when enabled. The stock 32 MiB pool is static in-image memory and is simply abandoned, not freed. |
| **Generation margin** | 2,048 → 1,024 reuses per slot before wrap. Mitigated by measurement, not assumption (§7). |
| **Startup** | One 4.19M-iteration loop to thread the free list, and a 1 ms polling thread bounded at 120 s. Both negligible. |
| **Version coupling** | Bound to 1.16.244; a different build takes the `Refused` path and changes nothing. |
| **Save games** | Handles are runtime-only — saves store FormIDs — so the save format is untouched (`main.cpp:4-6`). Removing the plugin does not corrupt saves; a save whose content genuinely needs more than 2^21 live handles will simply hit the stock ceiling again. |
| **Unaudited assumption** | Any engine code that caches the pool base pointer separately, or that hard-codes the stock mask, would desynchronise. The probes in §3.2 are the evidence against that — on 1.16.236. |
| **Non-reference handle users** | Starfield Engine Fixes reports Cell handle counts alongside Reference handle counts and notes that "in Starfield, not only References have handles". Whether cells occupy this pool or a sibling manager instance is not established here — the plugin swaps exactly one singleton (ID `883285`). Its above-cap classifier prints any non-reference form type numerically, which is the tell if that assumption is ever wrong. |
| **Third-party reporting** | Other tools' handle readouts will not reflect the raise unless they read the manager's fields. Starfield Engine Fixes is publicly documented as reporting the vanilla cap in its pointer-handle logging. |

---

## 10. So why didn't Bethesda do this?

The premise deserves a correction before the answer: Bethesda *did* raise it,
once. The interesting question is why they raised it exactly as far as they
did, and then stopped. Worth taking the three engine generations separately.

**Skyrim-era (2011 → 2024).** Three things were genuinely in the way, and only
one of them is a hard wall.

1. *Memory, in 2011.* The handle table is a statically sized array in the
   image: 2^20 entries × 16 bytes = 16 MiB, resident always, on a console
   generation with 512 MB of unified RAM. Quadrupling it to 64 MiB would have
   claimed roughly an eighth of the entire memory budget for a table that is
   mostly empty in normal play. As an original engineering decision this is
   defensible, not lazy.
2. *The object-side bit budget, past 2^21.* The cached index shares a word with
   the refcount and the valid flag and has exactly 21 spare bits (§2.4). Up to
   2^21 that word is fine; past it, `BSHandleRefObject`'s meaning has to change
   — which is an ABI break visible to every native plugin ever compiled against
   it. This is the hard wall, and it is why the sibling Skyrim project needed a
   sidecar dword rather than a wider field.
3. *Inertia and blast radius.* The constants are inlined everywhere by the
   optimiser. Bethesda has the source, so that is a recompile rather than 2,714
   binary patches — but it still re-touches every handle operation in the
   engine, for a benefit no vanilla player ever sees.

**And they did raise it — once.** Fallout 4 ships **21 index bits and 5 age
bits: 2,097,152 handles**, exactly double Skyrim's. aers describes the change
as "basically what the CK fix does". Note what that number is: 21 bits is the
entire spare capacity of the object-side word (§2.4). Fallout 4 sits precisely
on the ceiling, with not one bit left over.

So the accurate version of "Bethesda never raised the limit" is sharper and
more interesting than the usual telling: **they raised it once, by exactly the
maximum the layout allowed, and then stopped because the layout allowed nothing
more.**

What that does not explain is Skyrim. The 2^20 → 2^21 step was nearly free —
six unused high bits in the handle word, one spare bit in the object word, 16
MiB more table, no ABI change — and it was never taken across SE, AE, VR, or
any re-release, long after the 2011 memory argument had evaporated.

**Starfield.** The structural obstacle is gone, and Bethesda are the ones who
removed it. The handle index no longer shares the refcount word; the manager
became a polymorphic singleton whose capacity is a runtime member reachable
through a virtual getter (§3.1); the mask and generation unit live in mutable
fields the engine reads at runtime. The engine is *already written to support a
different capacity*.

And then it shipped with 2^21 — the same number Fallout 4 was forced into by a
constraint Starfield no longer has, backed by a statically sized 32 MiB pool on
a platform where doubling it is noise.

So the plugin does not defeat a design limit. It supplies a different value to
a parameter Bethesda had already made a parameter, and pays the
10-generation-bit cost knowingly and with instrumentation.

The honest framing: **on Starfield this is a configuration change to a value
Bethesda left fixed at 2^21, and the difficulty is not in the change but in
proving it is safe** — establishing that the constants are not
inlined anywhere, finding a window where the swap is atomic without locks, and
verifying the manager really is the structure that was audited. That is where
essentially all of the plugin's code goes.

---

## 11. Verification status

Per `Starfield/VERIFY.md`, stated without embellishment:

**In place**
* Address Library resolution for every engine address; no signature scanning.
* Exact stock six-field shape required before any write.
* Read-back verification of all six fields with restore-on-mismatch.
* Independent vtable + callback verification before the diagnostic hook.
* Runtime generation-wrap detection with explicit unreliability reporting.
* Exact input hashes published for both images and Address Library files
  (`Starfield/HASHES.md`), plus a source hash for `src/main.cpp`.

**Open**
* The exhaustive whole-image literal audit is **1.16.236-only**; no fresh
  hash-bound 1.16.244 audit has been published.
* No standalone offline manager simulator exists for Starfield.
* No `patch_*.json` / `sites_*.json` / generated `PatchTable.g.h` — and
  correctly so: there are no instruction patches to tabulate. Their absence is
  documented rather than filled with a fabricated artifact
  (root `README.md:22-25`).

---

## 12. Reference

### 12.1 Constants

| Constant | Value | Meaning |
|---|---|---|
| `kStockBits` | `21` | stock index bits |
| `kStockCap` | `0x200000` | stock capacity (2,097,152) |
| `kStockFreeCount` | `0x200000` | pristine free-counter value |
| `kTargetBits` | `22` | raised index bits |
| `g_newCap` | `0x400000` | raised capacity (4,194,304) |
| `kGenerationCount` | `1 << (32 - 22)` = `1024` | generations after the raise |
| `kPoolEntrySize` | `16` | bytes per pool entry |
| `kReportTickMilliseconds` | `60'000` | monitor tick |
| `kNormalReportMinutes` | `5` | usage report interval |

### 12.2 Object field offsets (1.16.244)

| Offset | Type | Field |
|---:|---|---|
| `+0x24` | `u32` | cached native handle |
| `+0x28` | `u32` | FormID |
| `+0x2E` | `u8` | form type |
| `+0x30` | `u16` | source-file index |

### 12.3 Glossary

* **Handle** — 32-bit weak reference: `generation:index`.
* **Generation / age** — per-slot reuse counter that invalidates stale handles.
* **Free list** — singly-linked list of free slots threaded through the pool
  entries' second qword.
* **Stock shape** — the exact set of six field values a freshly constructed,
  never-used 1.16.244 manager holds.
* **Swap window** — the ~37 s interval between manager construction and first
  handle allocation, during which the manager is quiescent.

---

## 13. Sources

### 13.1 In this repository

* `Starfield/src/main.cpp` — the plugin (all line citations above).
* `Starfield/HASHES.md`, `Starfield/VERIFY.md` — exact inputs, Address Library
  mapping, verification status.
* `Starfield/probes/McpScalar2.java`, `McpMaskCtx.java` — the whole-image
  immediate audit.
* `Skyrim/DESIGN.md`, `Skyrim/docs/patch-sites/README.md`,
  `Skyrim/src/GenerationTracker.h`, `Skyrim/src/PatchTransaction.cpp`,
  `Skyrim/probes/gen_patchtable.py` — the contrasting implementation.

### 13.2 Engine structure (primary code)

* [powerof3/CommonLibSSE — `RE/B/BSPointerHandleManager.h`](https://github.com/powerof3/CommonLibSSE/blob/dev/include/RE/B/BSPointerHandleManager.h)
  — Skyrim's concrete constants (`kAgeInc`, `kFreeListMask`, `kInUseBit`,
  `Entry(*)[0x100000]`).
* [CommonLibSSE-NG — `RE/B/BSHandleRefObject.h`](https://github.com/CharmedBaryon/CommonLibSSE-NG/blob/main/include/RE/B/BSHandleRefObject.h)
  and [`RE/N/NiRefObject.h`](https://github.com/CharmedBaryon/CommonLibSSE-NG/blob/main/include/RE/N/NiRefObject.h)
  — the refcount/handle packing.
* [Nukem9/skyrimse-test — `CKSSE/BSPointerHandleManager.{h,cpp}`, `BSHandleRefObject_CK.h`](https://github.com/Nukem9/skyrimse-test/tree/master/skyrim64_test/src/patches/CKSSE)
  — the most complete public statement of the algorithm (`CreateHandle`,
  `Destroy`, `GetSmartPointer`, FIFO free list).
* [CKPE — Skyrim, Fallout 4 and **Starfield** handle headers](https://github.com/Perchik71/Creation-Kit-Platform-Extended)
  — per-game bit splits, and the independent Starfield
  `TESPointerHandleDetail::Manager` layout used in §3.1.
* [Nukem9 PR #28](https://github.com/Nukem9/skyrimse-test/pull/28/files) — the
  unmerged 25-bit attempt that steals a refcount bit.

### 13.3 Symptoms, prior art and tooling

* [aers, "PSA: The reference handle cap"](https://www.reddit.com/r/skyrimmods/comments/ag4wm7/psa_the_reference_handle_cap_or_diagnosing_one_of/)
  ([STEP mirror](https://stepmodifications.org/forum/topic/18995-reference-handle-cap/))
  — the canonical write-up; source of the quotes in §2.5 and §2.6.
* [aers/EngineFixesSkyrim64 — `src/warnings/warnings.cpp`](https://github.com/aers/EngineFixesSkyrim64/blob/master/src/warnings/warnings.cpp)
  — the warn-only implementation.
* [aers — `count_loaded_refs_in_load_order.pas`](https://gist.github.com/aers/953a50c61b3028bce7e5376e8590abed)
  — the xEdit pre-flight counter.
* [Buffout 4 `Buffout4.toml`](https://github.com/alandtse/Buffout4/blob/master/data/Data/F4SE/Plugins/Buffout4.toml)
  — evidence for the *absence* of a handle feature.
* Nexus: [Starfield Engine Fixes](https://www.nexusmods.com/starfield/mods/10457),
  [Addictol](https://www.nexusmods.com/fallout4/mods/84214),
  [Daytripper 4](https://www.nexusmods.com/fallout4/mods/91141),
  [Persistentify Those Plugins](https://www.nexusmods.com/skyrimspecialedition/mods/76750),
  [Pointer Handle Limit Fix (public release of this plugin)](https://www.nexusmods.com/starfield/mods/17890).

### 13.4 Confidence

Claims in this document fall into three tiers, and the text marks the second
and third explicitly wherever they occur:

1. **Read from source in this repository** — everything in §4–§8 and §12.
2. **Verified against primary external code** — the Skyrim, Fallout 4 and CKPE
   Starfield constants in §2.4, §2.6 and §3.1.
3. **Inference, labelled as such** — the FIFO-margin argument in §7.1, the
   CKPE field-map reconciliation in §3.1, and the reading of Bethesda's design
   history in §10.

Not verified anywhere: Starfield's stock 2^21 capacity has no *independent*
third-party confirmation in public sources — it rests on this project's own
reverse engineering, which is why the runtime stock-shape gate refuses to write
unless the engine presents exactly that shape.
