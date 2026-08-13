# Starfield audit probes

These are the two source probes used for the whole-image scalar/context review.
They are Ghidra scripts and contain no Starfield executable data.

1. Import the legally obtained `Starfield.exe` whose size and SHA-256 match the
   audit input in `../HASHES.md`, then let analysis complete.
2. Confirm the executable's size and SHA-256 before running either probe.
3. Add this directory to Ghidra's Script Manager search paths.
4. Run `McpScalar2.java` to enumerate the handle-cap-related immediate values
   and separate pure immediates from address-displacement noise.
5. Run `McpMaskCtx.java` with `0x1fffff` and then `0x200000` as script arguments
   to decompile and classify every containing function.

`McpMaskCtx.java`'s `callsHandleMgr` convenience flag contains virtual addresses
for that hash-identified input. It is single-image historical audit logic, not
a cross-version verifier. The raw
decompiler outputs are deliberately omitted because they were not emitted as
hash-bound, reproducible artifacts. Generate fresh output from the exact input
instead.
