# Starfield audit probes

These are the two source probes used for the whole-image scalar/context review.
They are Ghidra scripts and contain no Starfield executable data.

1. Import your legally obtained `Starfield.exe` 1.16.236.0 into Ghidra and let
   analysis complete.
2. Compare the executable's size and SHA-256 with `../HASHES.md`.
3. Add this directory to Ghidra's Script Manager search paths.
4. Run `McpScalar2.java` to enumerate the handle-cap-related immediate values
   and separate pure immediates from address-displacement noise.
5. Run `McpMaskCtx.java` with `0x1fffff` and then `0x200000` as script arguments
   to decompile and classify every containing function.

`McpMaskCtx.java`'s `callsHandleMgr` convenience flag contains 1.16.236 virtual
addresses. It is historical audit logic, not a 1.16.244 verifier. The raw
decompiler outputs are deliberately omitted because they were not emitted as
hash-bound, reproducible artifacts. Generate fresh output from the exact input
instead.
