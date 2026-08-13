# Pointer Handle Limit Fix 1.0.1 — Release notes

## Highlights

- Supports exact Starfield 1.16.236 and 1.16.244 in one DLL.
- Raises the default usable pointer-handle limit from 2,097,151 to 4,194,303.
- Adds a default-off 8,388,607-handle tier with `Enable8M=1`.
- Removes the old two-minute startup deadline. Slow systems now receive one warning while the
  plugin continues waiting for the manager.
- Adds per-slot generation/reuse tracking, hottest-slot reporting, and generation-wrap warnings.
- Adds optional detailed above-cap diagnostics with bounded samples and guarded object reads.
- Keeps the exact pristine-manager gate and six-field read-back verification.

## Validation summary

- Current v1.0.1 DLL: verified default 4M startup and liveness in-game.
- Production 8M manager swap: verified in-game, followed by a successful ordinary save load and
  normal exit.
- Real Starfield Create/Lookup/Release routines: passed a private-manager 7.9M unique-handle test,
  full identity lookups, complete release, stale rejection, FIFO exact-slot reuse, free-list
  restoration, and a deliberate 512-reuse wrap/detector check.
- Standalone exact-state model: passed the corresponding 7.9M and injected-fault checks.
- Three additional testers reported three to four days each above the vanilla limit without
  issues. This is attributed field feedback, not locally archived proof.

See `MOD_DESCRIPTION.md` and `VERIFY.md` for the precise evidence boundaries and limitations.

## Distribution

The release archives contain exactly:

```text
SFSE/Plugins/StarfieldHandleCapRaise.dll
SFSE/Plugins/StarfieldHandleCapRaise.ini
```

There is no outer `Data` directory, wrapper directory, README, test DLL, Address Library file,
PDB, or source file in the archives.
