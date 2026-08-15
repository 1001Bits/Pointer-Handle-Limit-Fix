# Public-source handle compatibility audit — 2026-08-11

This is a dated source audit, not a universal compatibility guarantee. It
covered 286 shallow public Git repositories selected with broad Skyrim,
SKSE, CommonLibSSE, native-plugin, and VR searches, followed by targeted
GitHub/Sourcegraph searches for raw pointer-handle constants, masks, shifts,
table access, object padding, and serialization. Closed-source DLLs, deleted
or unindexed repositories, and code generated only in distributed binaries
remain outside the result.

## Results by compatibility surface

| Surface | Confirmed live-code public-source hits | Effect with the raised layout |
|---|---|---|
| Hard-coded raw handle | Precision, TrueHUD, True Directional Movement, Open Animation Replacer, Alternate Conversation Camera, Junk It NG, SpellBender VR, KratosCombat, and RealmShifting use Skyrim's raw player value `0x00100000`. | The reserved-player design preserves this one complete value. It does not make any other stock decoder valid. |
| Stock `& 0xFFFFF` or `>> 20` decoding | No active 64-bit SE/AE/VR plugin found. One active 32-bit Oldrim implementation exists in Immersive Impact's Next-Gen Camera, which cannot load in the same process as this x64 plugin. | Still unsupported; a closed-source/private decoder can silently alias another entry. |
| Storage in 26 bits | No active 64-bit SE/AE/VR plugin found. | Preserved by the 2M/21+5 layout: every valid raw handle is at most `0x03FFFFFF`. |
| Original one-million-entry table | Engine Fixes and its Wine fork, in their reference-limit warning. | The abandoned image table remains mapped, so the warning reads stale data instead of corrupting memory. |
| Old table in-use bit 26 | The same two warning implementations. | Bit 26 remains the live-entry flag, but the warning still reads the abandoned original table and therefore remains stale. |
| `NiRefObject::_pad0C` / `TESObjectREFR+0x2C` as private storage | No active direct reader or writer found. | Preserved by 2M/21+5. The complete 21-bit index fits `_refCount[31:11]`; the plugin leaves `+0x2C` untouched. |
| Serialized raw `ActorHandle` / `ObjectRefHandle` | No direct third-party SE/AE/VR DLL found. One active path exists in SKSE core's `PapyrusSpawnerTask`. | A pending task saved across a process/layout boundary can fail to resolve its non-player target or, in the worst case, resolve an unrelated live reference. |

The Wine Engine Fixes fork has one additional AE-only code-patch collision:
its Form Caching Patch H overwrites AE RVA `0x001790A4`–`0x001790AC` and
replays the stock generation mask. The cap raise changes
`0x001790A8`–`0x001790AC`. Version 2.2 still changes the age-mask instruction
at that overlap. The shipping AE interoperability path accepts only the exact
reviewed Engine Fixes binary and authenticated live SafetyHook/trampoline
state; other owners or layouts fail closed. SE does not install that AE-only
hot-spot patch.

A focused second pass covered 33,516 non-`.git` files in the 286-repository
snapshot. It searched direct zero-index table access, player/slot-zero
proximity, `_pad0C` member access, `TESObjectREFR`/`NiRefObject` with literal
`+0x2C`, exact 26-bit masks and bitfields, and handle-adjacent packing or
serialization calls. It found no co-loadable SE/AE/VR hit in those categories.
The [Oldrim decoder](https://github.com/jarari/Immersive-Impact/blob/f50271177e760f4941a57c4037144524f11410db/Next-Gen%20Camera/CameraController.cpp#L117-L119)
is retained as an out-of-scope positive control rather than silently discarded.

`HitData` was checked separately because it is on Skyrim's melee and projectile
damage paths. Its `aggressor`, `target`, and `sourceRef` members are ordinary
four-byte `ActorHandle`/`ObjectRefHandle` values at offsets `0x18`, `0x1C`, and
`0x20`; they are not 26-bit fields. Exact runtime traces show the producers
copying complete dwords and the consumers passing complete dwords to Skyrim's
normal handle resolvers. Those resolver instructions are present in the
generated 21-bit patch census for every supported profile. No indexed public
`HitData` consumer was found masking, shifting, truncating, privately resolving,
or serializing these members. The [reviewed CommonLib layout](https://github.com/powerof3/CommonLibSSE/blob/431ded26ff2861c2de2e29f839a7c36f1829c592/include/RE/H/HitData.h#L44-L80)
therefore does not itself explain a melee-hit failure.

## 2M/21+5 compatibility update

The audit corpus predates the final 2M pivot, but its source observations can be
re-evaluated directly. Compared with the former 4M/22+6 layout, version 2.2:

- removes 436 object-side sidecar mutations across the four profiles;
- removes 450 moved-in-use-bit mutations;
- keeps all raw values within 26 bits;
- keeps table-entry bit 26 in use;
- makes `_refCount >> 11` the complete index; and
- reduces the replacement table from 64 MiB to 32 MiB.

The known public player-constant consumers remain protected by the reserved
raw value. Precision and Open Animation Replacer use opaque full dwords and
engine resolution paths in the reviewed code; neither contains a live stock
index/age decoder. CommonLibSSE-NG's nominal
`BSUntypedPointerHandle<21,5>` type matches the new bit dimensions, although
its normal handle class stores an opaque dword and delegates resolution to the
engine rather than decoding inline.

The residual upper-bank risk remains real. For example, a valid 2M-layout raw
handle `0x00300001` means index `0x100001`, age 1, while stock masks interpret
it as index 1, age 3. Fixed access to the original one-million-entry table and
raw-handle persistence also remain incompatible. The architecture therefore
reduces the unknown/private-mod surface materially but does not create a
universal compatibility guarantee.

## Representative pinned sources

- [Precision player-handle checks](https://github.com/ersh1/Precision/blob/df3cd228795bf32288de795dc6eb3b38e46abf34/src/Hooks.cpp#L419-L565)
  and its [API impulse check](https://github.com/ersh1/Precision/blob/df3cd228795bf32288de795dc6eb3b38e46abf34/src/ModAPI.cpp#L218-L222).
- [TrueHUD player exclusions](https://github.com/ersh1/TrueHUD/blob/2c7232f16f4c8f09c6dc99108708f5e42aa68732/src/HUDHandler.cpp#L316-L390)
  and [player-widget dispatch](https://github.com/ersh1/TrueHUD/blob/2c7232f16f4c8f09c6dc99108708f5e42aa68732/src/Scaleform/TrueHUDMenu.cpp#L532-L578).
- [True Directional Movement projectile checks](https://github.com/ersh1/TrueDirectionalMovement/blob/ed6b033cf07febf47e0dd563f44f7b5416f934e1/src/Hooks.cpp#L932-L1124).
- [Open Animation Replacer `IsGreetingPlayer`](https://github.com/ersh1/OpenAnimationReplacer/blob/fdaed180f35b0e3ac85cd6c76bc6d33ffac3eab6/src/Conditions.cpp#L3346-L3364).
- [Alternate Conversation Camera's player constant](https://github.com/NasiRawon/AlternateConversationCamera/blob/aa815816fc38aa85f5e23a186742d931bf99de2b/Camera.h#L8)
  and one set of its [active camera branches](https://github.com/NasiRawon/AlternateConversationCamera/blob/aa815816fc38aa85f5e23a186742d931bf99de2b/main.cpp#L762-L770).
- [Junk It NG's barter special case](https://github.com/raziell74/skyrim-junk-it-ng-skse/blob/0ff9ca34054416f63c213c6690d85fb92f910eab/src/util.h#L594-L620).
- [SpellBender VR's shooter check](https://github.com/SamuelJohnBrown/SpellBender-VR---Release-source-file/blob/8dbe8af459eb21d7dcd7917d265934341714a5dc/ControllerAim.cpp#L314-L318),
  [KratosCombat's active projectile check](https://github.com/PhiloSocio/KratosCombat/blob/74ef2164ca94ff3e09c6f61094de14efe8cab75e/src/hook.cpp#L78-L103),
  and [RealmShifting's projectile check](https://github.com/PhiloSocio/RealmShifting/blob/bca03f677b6a1844c0fd08ae8befff29eec9381f/src/hook.cpp#L42-L52).
- [Engine Fixes' fixed-table/bit-26 warning](https://github.com/aers/EngineFixesSkyrim64/blob/c37a8041ffc0a5859e78a19c71b877327773455d/src/warnings/warnings.cpp#L3-L29)
  and the Wine fork's [overlapping Patch H](https://github.com/cashcon57/SSEEngineFixesForWine/blob/cab9fb9de9dbf8d3e249b4d3497a4735672741fa/src/patches/form_caching_patches.h#L906-L995).
- SKSE core's [`PapyrusSpawnerTask` raw target record](https://github.com/ianpatt/skse64/blob/4c1b425415c15f4655c73abb4682023baeb99d48/skse64/PapyrusSpawnerTask.cpp#L42-L170)
  and the [core co-save path](https://github.com/ianpatt/skse64/blob/4c1b425415c15f4655c73abb4682023baeb99d48/skse64/InternalSerialization.cpp#L218-L253).

## Raw-handle persistence scope

`PapyrusSpawnerTask.AddSpawn` captures a target reference as a raw 32-bit
runtime handle. A save can persist it while the task is still in SKSE's
object store or delayed-functor queue. Load resolves the spawned base FormID,
but not the target handle, before `LookupREFRByHandle` consumes the stored
number. The record contains no target FormID from which a generic compatibility
layer could reconstruct the intended reference.

No active public third-party caller of `SpawnerTask.AddSpawn` was found in the
audited corpus; matches were SKSE's commented example, API/core source, and
vendored copies. That makes observed exposure low, not zero. The API accepts
arbitrary `ObjectReference` targets, and scripts or closed-source packages may
exist outside the corpus. The reserved slot preserves the player target's raw
numeric identity once the player handle is live; it does not stabilize any
non-player target. Non-player raw handles remain process-local and must not be
used as save identities. FormIDs and Papyrus VM handles serialized
through their supported resolution APIs are separate namespaces and are not
this problem.
