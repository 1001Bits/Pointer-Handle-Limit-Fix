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
existing reviewed run targeted the exact 1.16.236 image, not 1.16.244. See
`probes/README.md` for Ghidra instructions and limitations.

## Runtime verifier

Starfield does not use generated instruction patches. `src/main.cpp` resolves
the manager through Address Library IDs, requires the exact stock six-field
manager shape, writes the replacement pool and five associated control values,
reads all six fields back, and restores the stock state if verification fails.
The generation diagnostic independently verifies the expected vtable and
callback before installing its hook.

There is currently no standalone Starfield offline simulator, no
`patch_*.json`/`sites_*.json`, and no generated `PatchTable.g.h`. The exhaustive
literal audit represented by the published probes is 1.16.236-only. A fresh,
hash-bound 1.16.244 whole-image audit and an independent offline manager
simulator remain open verification work; this snapshot does not claim
otherwise.
