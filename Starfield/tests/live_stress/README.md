# Starfield live private-manager stress test

This is a test-only SFSE plugin for one explicitly runtime-gated supported build. It creates a
private 23-bit handle manager and calls the game's audited Create/Lookup/Release routines through
Address Library IDs 139362, 139363, and 139364. It never reads or writes the game's global
handle-manager singleton and is not part of the release archive.

The test creates 7,900,000 unique live objects, runs a verbose above-stock-cap scan, releases all
objects, checks stale-handle rejection, rotates the FIFO free list to reacquire 4,096 exact slots,
and exercises the 512-generation wrap boundary. Every engine call is wrapped in SEH; a fault stops
the test and frees only its private allocations.

The plugin is inert by default. To run it, install its DLL and INI under `Data/SFSE/Plugins`, set
`Enable = 1`, and launch the exact runtime accepted by the source gate with its matching SFSE and
Address Library.
Results are written to `Documents/My Games/Starfield/SFSE/Logs/StarfieldHandleLiveStress.log`.

This validates the real engine allocator/resolver/release code against a private manager. It does
not validate the production plugin's global six-field swap, TESObjectREFR ownership/refcounts,
saves, other engine consumers, or long gameplay sessions.
