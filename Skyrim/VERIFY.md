# Skyrim simulator and verifier

The probes read the user's own game executables and Address Library files. They
never require those binaries to be copied into this repository.

## Prerequisites

- Python 3.12
- Packages pinned in `probes/requirements.txt`
- Each exact executable and matching Address Library input listed in
  `HASHES.md`

Set the paths in PowerShell:

```powershell
$env:SHCR_SE_EXE='C:\path\to\SkyrimSE-1.5.97.exe'
$env:SHCR_SE_ADDRLIB='C:\path\to\version-1-5-97-0.bin'
$env:SHCR_AE_EXE='C:\path\to\SkyrimSE-1.6.1170.exe'
$env:SHCR_AE_ADDRLIB='C:\path\to\versionlib-1-6-1170-0.bin'
$env:SHCR_GOG_EXE='C:\path\to\SkyrimSE-1.6.1179.exe'
$env:SHCR_GOG_ADDRLIB='C:\path\to\versionlib-1-6-1179-0.bin'
$env:SHCR_VR_EXE='C:\path\to\the-decrypted-SkyrimVR-1.4.15-image.exe'
$env:SHCR_VR_ADDRLIB='C:\path\to\version-1-4-15-0.csv'
```

## Run the offline simulator

From `Skyrim/probes`:

```powershell
python -m pip install -r requirements.txt
python test_patch.py --runtime SE --patch ../artifacts/patch_SE.json
python test_patch.py --runtime AE --patch ../artifacts/patch_AE.json
python test_patch.py --runtime GOG --patch ../artifacts/patch_GOG.json
python test_patch.py --runtime VR --patch ../artifacts/patch_VR.json
```

Each run must end with `PASS`. The simulator applies every generated field,
sidecar, table-reference, initializer, publisher, and release change to an
in-memory copy, re-disassembles it, and verifies the coherent 22-bit encoding.

## Regenerate the readable patch audit

From `Skyrim/probes`, after regenerating or reviewing the four JSON profiles:

```powershell
python gen_patch_docs.py --se ../artifacts/patch_SE.json --ae ../artifacts/patch_AE.json --gog ../artifacts/patch_GOG.json --vr ../artifacts/patch_VR.json --out-dir ../docs/patch-sites
```

The generated pages show original and replacement bytes/disassembly for every
fixed write. Runtime-derived table displacements and generation-relay calls
are shown as invariant byte templates, symbolic targets, and exact formulas.

## Verify the generated deliverables

Still from `Skyrim/probes`:

```powershell
python verify_deliverable.py --offline
```

The command must end with `ALL CONSISTENT`. It independently checks the JSON
schemas and record IDs, requires every mutation/evidence record exactly once in
the generated Markdown, byte-compares the committed pages to a fresh render,
and verifies the generated C++ arrays. The `--offline` mode is required for
this source-only snapshot because build outputs, packages, DLLs, INIs, and CMake
files are intentionally not published here.

Full deterministic regeneration commands for `patch_*.json` and
`src/PatchTable.g.h`, plus the maintained search criteria, are in
`probes/README.md`.
