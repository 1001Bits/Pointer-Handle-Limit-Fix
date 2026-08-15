# Engine Fixes 7.0.20 FormCaching interoperability

Engine Fixes 7.0.20 with `bFormCaching=true` installs a SafetyHook inline
detour at the entry of AE 1.6.1170 `TESDataHandler::ClearData`, RVA
`0x001B9AB0`. That function owns Skyrim's player teardown sequence, so the
detour changes the generated lifecycle owner fingerprint even though the
handle load, canonical release, zero source, and singleton clear remain stock.

The plugin accepts this one collision only after authenticating all of the
following at runtime:

- Skyrim is exactly AE 1.6.1170 and only bytes 0..4 of the reviewed owner were
  replaced by `E9`; bytes 5..15 remain stock.
- The loaded module is exactly `EngineFixes.dll` 7.0.20.0, SHA-256
  `5D1384ACFB523ABD1333F5AF71AF0B7D131B6EBB1A0EE6B3EDFF86FB4C93ADF3`,
  PE timestamp `0x699FC3BA`, and image size `0x2A4000`.
- The entry jump reaches a single committed executable `MEM_PRIVATE`
  SafetyHook allocation. Its copied prologue is `40 55 53 56 57`, its back
  edge resolves exactly to Skyrim owner+5, and its `FF 25` destination stub
  resolves exactly to Engine Fixes RVA `0x711F0`.
- The complete wrapper range `0x711F0..0x71403` has SHA-256
  `9D9527245B187E31D067F2CCF77E8CB81DD4615DEA263D7608F10F9FC3EE2BE0`.
- Engine Fixes' live `g_hk_ClearData` target, destination, trampoline, and
  24-byte trampoline-size fields agree with that same chain.
- Every deep player lifecycle instruction, call target, zero source, and
  publication/release ordering check still matches the generated stock
  profile.

An authenticated run emits:

```text
compatibility: EngineFixesFormCaching PASS runtime=1.6.1170.0 version=7.0.20.0 sha256=5D1384ACFB523ABD1333F5AF71AF0B7D131B6EBB1A0EE6B3EDFF86FB4C93ADF3 destinationRva=000711F0 safetyHookChain=PASS originalCall=PASS
```

This is not a generic `E9` allowance. Stock owners remain accepted on every
profile, but SE, GOG, VR, `EngineFixesVR.dll`, Wine forks, other Engine Fixes
versions/builds, `FF 14` detours, chained hooks, changed wrapper bytes, and any
changed downstream lifecycle site continue to fail closed.

The fingerprints derive from Engine Fixes tag `v7.0.20` commit
`af982b0b57d8d8935686faaf1f8c49508baf0bd1`, SafetyHook tag `v0.6.9` commit
`c3f3f306a0f12d1811c0b713ad2ed2a8ddc6cf55`, the reviewed release DLL, and a
controlled live ASLR capture. The compatibility boundary must be re-audited
before another binary is added.
