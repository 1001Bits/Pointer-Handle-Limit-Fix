# Starfield handle-pool exact-model stress test

This is a standalone, test-only model of the Starfield reference-handle allocator. It does not
load SFSE or modify the game. The modeled transitions come from the hash-identified audited
routines listed in `../../HASHES.md`:

- `CreateHandle` at `0x1428d0e40`
- `LookupByHandle` at `0x1428d0ff0`
- `Release` at `0x1428d1090`

The executable builds the same 23-bit, 16-byte-entry free list as the plugin, creates 7,900,000
simultaneously live handles, performs a full lookup pass, runs the above-stock-cap diagnostic,
and checks release, stale-handle rejection, FIFO exact-slot reuse, full free-list restoration,
and the 512-generation wrap detector boundary.

Build and run from a Visual Studio 2022 developer environment:

```powershell
cmake -S tests/model_stress -B tests/model_stress/build -G "Visual Studio 17 2022" -A x64
cmake --build tests/model_stress/build --config Release
tests/model_stress/build/Release/StarfieldHandleModelStress.exe
```

The test intentionally commits about 560 MiB while running. A passing offline model is evidence
for the pool/free-list/encoding/scanner math only. It does not replace an in-game test of SFSE
loading, the manager's synchronization, callback ABI, engine virtual calls, or save/reload.
