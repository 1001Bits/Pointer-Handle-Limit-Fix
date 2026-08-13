# Starfield verification

## Verify the exact inputs

Use PowerShell against your own files and compare the results with
`HASHES.md`:

```powershell
Get-Item -LiteralPath 'C:\path\to\Starfield.exe' |
  Select-Object Length, @{Name='ProductVersion';Expression={$_.VersionInfo.ProductVersion}}
Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\path\to\Starfield.exe'
Get-Item -LiteralPath 'C:\path\to\versionlib-1-16-244-0.bin' |
  Select-Object Length
Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\path\to\versionlib-1-16-244-0.bin'
```

## Binary audit probes

The available whole-image literal/context probes are in `probes/`. Their
existing reviewed run covers one hash-identified supported image; it does not
establish whole-image coverage for every supported runtime. See
`probes/README.md` for Ghidra instructions and limitations.

## Runtime verifier

Starfield does not use generated instruction patches. `src/main.cpp` resolves
the manager through Address Library IDs, requires the exact stock six-field
manager shape, writes the replacement pool and five associated control values,
reads all six fields back, and restores the stock state if verification fails.
The generation diagnostic independently verifies the expected vtable and
callback before installing its hook.

## 23-bit stress verification

`tests/model_stress/` is a standalone exact-state model of the audited Starfield
Create/Lookup/Release transitions. Its reviewed 2026-08-13 run created 7,900,000
unique simultaneous handles, verified a complete identity lookup pass, scanned
5,802,849 live entries above the stock range, exercised release/FIFO exact-slot
reuse/stale rejection, restored the full free list, and reproduced/detected the
512-generation wrap boundary. See `tests/model_stress/PASS-2026-08-13.txt`.

`tests/live_stress/` is a separate, explicitly enabled, runtime-gated diagnostic
SFSE DLL. It gives a private synthetic manager to the game's real
Create/Lookup/Release routines (Address Library IDs 139362/139363/139364); it
does not read or write the global handle-manager singleton. Its reviewed
2026-08-13 run repeated the 7.9M identity, verbose scan, full release, stale
rejection, exact-slot reuse, free-list cleanup, and wrap checks successfully.
Hash-bound evidence hashes are recorded in `HASHES.md`; raw local logs are not
part of this public source snapshot.

In the same hash-bound session, the production plugin independently selected
23-bit mode, read back a verified 8,388,607-slot global-manager commit, and kept
verbose diagnostics enabled. After the private-manager stress passed, the game
loaded into a save and then exited normally.

These tests do not create 7.9M real TESObjectREFR instances in the global game
manager, exercise reference ownership/refcounts, persist those 7.9M private
objects through save/reload, or remove the production swap's reliance on the
post-publication quiet window. The ordinary save load is a production-plugin
smoke test, not a 7.9M save-persistence test. There are no
`patch_*.json`/`sites_*.json` files or generated `PatchTable.g.h`. The exhaustive
literal audit represented by the published probes covers one supported
executable; an equivalent fresh hash-bound whole-image audit of the other
supported executable remains open verification work.
