# probes — reverse-engineering and patch-table generation

All read-only. These read your own installed Skyrim executables and your own
Address Library `.bin` files; nothing Bethesda ships is redistributed here.

Requires Python 3.12 and the pinned packages in `requirements.txt`:

```
python -m pip install -r requirements.txt
```

## The maintained pipeline

Run from this directory.

| script | what it does |
|---|---|
| `addrlib.py` | Address Library reader + runtime registry (`SE` = 1.5.97, `AE` = 1.6.1170, `GOG` = 1.6.1179, `VR` = 1.4.15). Override paths with the matching `SHCR_<TAG>_EXE` and `SHCR_<TAG>_ADDRLIB` variables. Binary versionlib and VR CSV databases are supported. |
| `image.py` | PE loader: section map, `.pdata` function bounds, capstone helpers. |
| `logical_funcs.py` | Rejoins `.pdata` chunks into logical functions via `UNWIND_INFO` chaining. |
| `dump_handle_core.py` | Disassembles the handle manager's core routines for both runtimes. |
| `scan_fast.py` | Whole-image literal/data-reference scan driven by `.pdata`. |
| `find_riprefs.py` | Decoder-independent scan for RIP-relative references to one RVA. |
| `truescan.py` | Same idea, re-deriving each hit's true RIP target by decoding. **Use this, not `find_riprefs.py`, for targets referenced by instructions with a trailing immediate** (e.g. `mov dword [rip+d], imm32`) — see the note below. |
| `sweep.py` | Instruction sweep that resyncs past padding and data islands, so it covers code `.pdata` does not describe. |
| `fingerprint_scan.py` | Byte-level hunt for the age-mask fingerprint anywhere in `.text`. |
| `gen_patchtable.py` | **The generator.** Produces `artifacts/patch_{SE,AE,GOG,VR}.json`. |
| `gen_cpp.py` | Emits `src/PatchTable.g.h` from those JSON files. |
| `test_patch.py` | Applies the table to an in-memory copy and re-verifies the result. |
| `verify_deliverable.py` | End-to-end consistency check. In this source-only snapshot, use `--offline` to verify exact-runtime hashes, generated JSON/header consistency, and unchanged refcount/valid ABI constants without requiring build/package outputs. |
| `inventory_runtime_refs.py` | Dependency-free placed-reference inventory; pass both `--plugins` and `--ccc` to model AE's explicit and automatic load lists. |

Full regeneration:

```
python gen_patchtable.py --runtime SE --table 1ec47c0 --head 1ec47ac --tail 1ec47b0 --lock 1ec47b8 --out ../artifacts/patch_SE.json
python gen_patchtable.py --runtime AE --table 20fc600 --head 20fc5ec --tail 20fc5f0 --lock 20fc5f8 --out ../artifacts/patch_AE.json
python gen_patchtable.py --runtime GOG --table 20fda00 --head 20fd9ec --tail 20fd9f0 --lock 20fd9f8 --out ../artifacts/patch_GOG.json
python gen_patchtable.py --runtime VR --table 1f89660 --head 1f8964c --tail 1f89650 --lock 1f89658 --out ../artifacts/patch_VR.json
python gen_cpp.py --se ../artifacts/patch_SE.json --ae ../artifacts/patch_AE.json --gog ../artifacts/patch_GOG.json --vr ../artifacts/patch_VR.json --out ../src/PatchTable.g.h
python test_patch.py --runtime SE --patch ../artifacts/patch_SE.json
python test_patch.py --runtime AE --patch ../artifacts/patch_AE.json
python test_patch.py --runtime GOG --patch ../artifacts/patch_GOG.json
python test_patch.py --runtime VR --patch ../artifacts/patch_VR.json
```

`test_patch.py` must print `PASS` for all four, then
`python verify_deliverable.py --offline` must print `ALL CONSISTENT`, before the
generated profiles and header are trustworthy.

## Literal classification guard

Capacity-shaped immediates are not accepted merely because they occur in a
logical function that also handles references. The generator requires the two
exact reviewed table-byte initializer RVAs for each runtime and fails on any
unreviewed match. VR RVA `0x006CB0F3` (Address Library ID 39466,
`PlayerCharacter::Revert`) is the sole recorded exclusion:
`mov dword ptr [rsi+0x9B9], 0x01000000` initializes packed player-state bytes
and is not the handle-table byte extent. It remains unchanged, is emitted in
`excluded_literals`, and is checked by `verify_deliverable.py`.

## The trailing-immediate trap

A RIP-relative displacement is relative to the end of the **whole**
instruction, including any immediate that follows the displacement. Testing
`disp + pos + 4 == target` is therefore only correct when the displacement is
the last field. `lea reg, [rip+d]` qualifies; `mov dword [rip+d], imm32`
(`C7 05`) does not — its target is four bytes further on.

Every reference to the handle *table* is a `lea`, so this does not change the
96 / 115 counts. It does affect anything that writes an immediate through a
RIP operand, such as the free-list head/tail globals. `gen_patchtable.py` now
searches trailing widths 0/1/2/4 and confirms each candidate decodes as a real
RIP-relative operand resolving to the target, because a widened search that
patched a coincidence would corrupt four bytes of unrelated code.

## `exploratory/`

Fifty single-purpose scripts written during the adversarial review pass —
signedness checks, object-word writer/reader censuses, SKSE loader probing, AE
control-global location, relocation-table walks, and so on. They are kept as
evidence of what was checked. They are not maintained, take ad-hoc arguments,
and several hardcode paths. Read them before running them.
