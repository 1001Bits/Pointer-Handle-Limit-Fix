# Starfield source layout

The production source follows the same orchestration-first structure as the Skyrim project while
retaining Starfield's different implementation strategy. Skyrim patches generated instruction
sites; Starfield commits one prepared pool by changing six mutable manager fields.

| Module | Responsibility |
|---|---|
| `main.cpp` | SFSE runtime gate, log/config summary, and lifecycle wiring only |
| `Configuration.*` | INI discovery, defaults, and value clamping |
| `RuntimeTypes.h` | Audited IDs, manager offsets, and handle-layout constants |
| `HandleTable.h` | Typed target layout and committed-table view |
| `PatchTransaction.*` | Pool construction, publication wait, exact-stock gate, six-field commit, read-back/rollback |
| `GenerationTracker.h` | Pure per-slot assignment/reuse/wrap state |
| `GenerationDiagnostic.*` | Sidecar allocation, assignment callback validation/hook, reuse snapshots |
| `EngineAccess.*` | Owning handle lookup and SEH-safe raw object capture |
| `FormAttribution.*` | Plugin/type/name attribution and detailed sample logging |
| `TableMonitor.*` | Five-minute liveness, wrap warnings, and optional one-minute above-cap scans |

See `BUILDING.md` for the required toolchain and CommonLibSF dependency
snapshot.

The generated patch table, runtime profile tables, Engine Fixes interop, reserved-player-slot
handling, and production stress harness from Skyrim are intentionally absent because they do not
apply to Starfield's manager-field transaction.

The v1.0.1 upload archives now contain the modular implementation. The exact packaged DLL passed
the standalone 7.9M model test and a hash-bound hidden-desktop in-game smoke with a real save load,
post-load handle telemetry, live world activity, and a clean exit.
