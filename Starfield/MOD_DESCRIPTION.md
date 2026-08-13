# Pointer Handle Limit Fix 1.0.1 — Starfield

Starfield has a fixed pool of 2,097,151 usable pointer handles. When that pool is exhausted,
the allocator returns the null handle instead of producing a clear “out of handles” error.
That can present as content that silently fails to exist rather than one consistent crash.

Pointer Handle Limit Fix replaces the stock pool during the quiet startup window, before the
first handle is allocated. The default configuration doubles the usable limit to 4,194,303.
A default-off INI option raises it to 8,388,607.

## Compatibility and requirements

- Starfield 1.16.236 or 1.16.244 only.
- The matching SFSE build for the installed game version.
- The matching Address Library for SFSE Plugins.
- One DLL supports both listed Starfield versions and refuses every other runtime.

The archive root is `SFSE\Plugins`; it intentionally has no outer `Data` directory and no
wrapper directory. Mod managers can install the archive as-is. For a manual installation,
place the archive's `SFSE` directory inside the game's existing `Data` directory.

## What it does

- Default: 4,194,303 usable handles, 1,024 generations, 64 MiB replacement pool.
- 8M mode: 8,388,607 usable handles, 512 generations, 128 MiB replacement pool.
- Checks that all six manager fields still have their exact pristine stock values before writing.
- Reads all six changed fields back and refuses or restores stock state if verification fails.
- Waits without a deadline for unusually slow systems; after two minutes it logs one warning and
  continues waiting.
- Tracks per-slot reuse, reports the most-reused slot, and warns when a generation wraps.
- Can produce detailed above-vanilla-cap reference, type, source-plugin, and consistency reports.

With generation tracking enabled, total allocation is approximately 72 MiB in the default mode
or 144 MiB in 8M mode.

## Configuration

Edit `SFSE\Plugins\StarfieldHandleCapRaise.ini`:

```ini
[General]
Enable8M = 0
VerboseLogging = 0
SampleSize = 16
GenerationWrapDetection = 1
```

`Enable8M=1` selects the 8M tier. `VerboseLogging=1` writes detailed reports once
per minute. `SampleSize` is clamped to 0–64. Generation tracking is recommended, especially in
8M mode.

The log is written to `Documents\My Games\Starfield\SFSE\Logs\StarfieldHandleCapRaise.log`.

## Testing performed by us

We tested the release DLL in-game and read back a verified default 4M pool swap. A five-minute
liveness report showed 899,325 handles in use with generation tracking active.

We separately enabled the production 8M configuration and verified its 8,388,607-slot global
manager commit. A test-only private manager then called Starfield's real Create, Lookup, and
Release routines for 7,900,000 unique simultaneous handles. The run:

- resolved all 7.9 million handles to the exact objects, including a second full lookup pass;
- verified 5,802,849 live entries above the vanilla range with zero unreadable entries;
- released all objects and rejected their stale handles;
- reacquired 4,096 exact released slots in FIFO order with the next generation;
- verified the complete final free-list chain; and
- deliberately reached reuse 512 on one isolated test slot, where the detector reported the
  expected single generation wrap.

After that stress run passed, the production 8M installation loaded into an ordinary save and
the game exited normally.

A separate standalone model repeated the 7.9M allocation, lookup, release, reuse, exhaustion,
fault-handling, free-list, and generation-wrap checks.

## Field reports

Three additional testers reported playing above the vanilla pointer-handle limit for three to
four days each without issues. These are tester reports; their original logs are not preserved
in this source snapshot and they should not be read as proof of indefinite or universal safety.

One tester on a very slow system supplied a v1.0 log showing that the old two-minute readiness
deadline expired before the manager became ready, so no resize occurred. They reported that a
locally patched 20-minute deadline allowed the resize to complete. Version 1.0.1 removes that
deadline: it warns after two minutes but continues waiting.

A separate exhaustion report described 2,088,543 handles in use out of the stock 2,097,152 pool
(99.6%), along with missing city chunks, missing ship parts, unusable saves, and crash logs that
named different mods as each was removed. That is a field report about near-exhaustion, not a
controlled result and not evidence that every crash was caused or fixed by this plugin.

## Important limitations

- This is not a general crash fix. The verified allocator failure is a silent null-handle/content
  failure; unrelated crashes remain unrelated.
- The 8M tier stays disabled by default. It halves generation depth from 1,024 to 512 and doubles
  the replacement-pool memory.
- The 7.9M real-engine stress used a private manager. It did not place 7.9M real TESObjectREFR
  instances in the game's global manager or persist those private objects through a save/reload.
- The ordinary save load verifies that the production 8M installation could load and exit; it is
  not a 7.9M save-persistence test.
- The detector reports a generation wrap; it cannot prevent a sufficiently old stale handle from
  aliasing a new occupant after a complete wrap.
- The plugin relies on the audited post-publication quiet window for its six-field swap. It fails
  closed if the manager is already non-pristine.
- Handles are rebuilt each launch and the plugin does not change the on-disk handle format. That
  architecture does not guarantee that every save or uninstall scenario has been tested.
- Another SFSE plugin that mutates the same handle-manager fields or assignment callback may
  conflict. The stock-shape and callback checks are designed to refuse or disable diagnostics
  when a conflict is detected.
- Starfield's separate dynamic FormID allocator remains an independent limit for workloads that
  create very large numbers of dynamic objects.

The 7.9M live-engine stress was run on one supported game version. The relevant manager layouts,
vtable callbacks, resolvers, constructors, and Address Library mappings were checked directly in
both supported game executables.
