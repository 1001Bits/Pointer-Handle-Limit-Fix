# Live prerelease player-slot and compatibility test

This protocol produces one-process evidence for the reserved player lifecycle.
It supplements the offline simulator; it does not replace the ordinary build,
hash, and patch-profile gates.

## Separate above-cap stress process

The synthetic above-cap gate is destructive test instrumentation and must run
in a separate throwaway Skyrim process from the lifecycle/compatibility test.
For the AE release gate, use this exact stress section with verbose/lifecycle
diagnostics disabled:

```ini
[StressTest]
Enabled=1
SyntheticFillToIndex=1800000
DetailedLogFromIndex=1048576
MaxDetailedLogs=16
ReferencesPerTask=4096
TaskBudgetMicroseconds=4000
DelayMilliseconds=16
VerifySecondPass=1
ReleaseProbeCount=16
ReuseProbeCycles=32
ChurnCycles=0
StopOnVerificationFailure=1
```

After crossing the stock cap, `VerifySecondPass=1` must enter a distinct,
bounded synthetic second-pass phase. It re-resolves every retained filler
handle to the exact original object, verifies the live table entry and complete
21-bit `_refCount` cache while proving `+0x2C` remains untouched, and balances
the temporary lookup pin. No canonical release, FIFO rotation,
save load, or live sampling may begin before the exact
`SYNTHETIC SECOND PASS PASS` line reports `verified == retained ==` the filler
count. Any lookup, object-identity, live-entry, or pin failure is terminal.

Only then may the log report the 16-handle `RELEASE PROBE PASS`, the locked
free-list cushion/integrity PASS, and exact-slot reuse cycles 1–31. Those safe
cycles must finish at assignment count 32 and the previously unused age-zero
raw value, with every stale handle rejected, the target reported as the hottest
slot at reuse 31, exactly one successful high-water log for each level 1–31 in
strict order, and both published-wrap and prevented-attempt counters still
zero. Earlier high-water levels may name another ordinary slot, but there must
be no missing, duplicate, or skipped level. “No wrap” here means zero
repeated-generation/ABA publication or
resolvability; the numeric five-bit age is allowed to advance from 31 to zero.

Cycle 32 then attempts assignment 33, which would repeat the target's initial
age-one raw value. The mandatory guard must emit its exact FATAL and terminate
with `0x53485752` before the table pointer makes that value resolvable. The
caller may already have written a transient output dword, but there must be no
cycle-32 PASS, lookup/alias, unrelated `CRITICAL` or FATAL, load, save, or
normal quit request. Synthetic handles and blocks are intentionally retained
until that guarded process exit. The lifecycle/compatibility process below is
separate and must not be used to extend the stress run.

The archived stress result is accepted only when its exact-schema keeper,
restored-stage, and orchestrator records replay consistently; captured pre/post
clean-root audit output passes; and the final SHA-256 manifest lists every other
regular evidence file exactly once with its canonical relative path, exact byte
length, and digest. The final PASS orchestrator and manifest must be the same
immutable bytes consumed by the last read-only verifier invocation.

## Disposable profile configuration

Install the candidate DLL and create `Data/SKSE/Plugins/SkyrimHandleCapRaise.ini`:

```ini
[General]
GenerationWrapDetection=1
VerboseLogging=1
LifecycleVerification=1
SampleSize=16

[StressTest]
Enabled=0
```

`LifecycleVerification` is prerelease-only and is ignored unless
`VerboseLogging=1`. At each checkpoint, including `kPreLoadGame`, it holds Skyrim's handle-manager lock
while it validates all 2,097,152 entries and walks the complete ordinary FIFO.
This proves that physical slot `0x100000` is neither an endpoint nor an
intermediate FIFO link. The scan can cause a short load-screen hitch; do not
ship this setting enabled by default.

The startup log for this protocol must identify the fixed 2M compatibility
layout: 21 index bits, five age bits, bit 26 in use, a 32 MiB table, an 8 MiB
generation-counter array, detached entry `03F00000`, masked live state
`(entry & 07E00000) == 04000000` (low successor bits may vary), and no object
sidecar. Any 4M/22+6 identity is historical and must be rejected.

Use the actual release-candidate DLL unchanged for the complete run. Record its
SHA-256 before launch. Enable the tested releases of Precision and Open
Animation Replacer. Enable Alternate Conversation Camera when it is applicable
to the runtime/profile under test.

## Constructor-first identity under test

This run must exercise the constructor-armed design, not the superseded
singleton-only build. The first isolated AE attempt reached a genuine new game
but found physical slot `0x100000` still detached. The follow-up exact
creation-order audit established the reason: the canonical `PlayerCharacter`
constructor can create its object-side cached handle before the caller publishes
`*PlayerCharacterSingleton`. A later getter then reuses that ordinary cached
handle, so merely waiting for the singleton cannot repair the identity.

The candidate fixes that ordering without a timer or allocation-order guess.
Each exact profile requires seven reservation hooks: one canonical constructor
`CALL`, five allocator selectors, and one canonical release hook. The
transaction fingerprints the complete creation pre-hook window, exact
constructor call and target entry, unchanged post-call-to-singleton window,
selector ABI windows, and release ABI window. The patched constructor call
enters a register-neutral near relay, atomically arms only that candidate while
the original constructor runs, validates any valid returned cache against
reserved generation zero under the manager write lock, releases that lock
before any failure logging, and clears the arm on return or C++ unwind.
Selectors accept only that arm or the exact published singleton and revalidate
the identity in the helper.

Before continuing past startup, the log must report that one constructor call,
five selector calls, and one release-quarantine call were prepared, followed by
post-patch verification of the constructor/selector/release relays. Any
missing/mutated pre-hook, retargeted call, incomplete hook set, non-RX relay,
changed post-call window, nested/different constructor arm, unexpected
constructor return, or valid non-reserved cached player handle is a refusal or
fail-stop, not a warning to waive for testing.

## Required single-process sequence

Do not restart Skyrim between these steps:

1. Boot to the main menu and start a new game. Confirm ordinary gameplay begins.
2. Exercise Precision while the player attacks in first person and third person.
   Also allow a hostile actor to land several melee hits on the player.
3. Exercise an OAR condition that uses `IsGreetingPlayer` and confirm the
   expected greeting animation/condition branch is selected.
4. Exercise Alternate Conversation Camera in a player conversation, or record
   why the case is not applicable.
5. Load `LifecycleA` and wait until normal control returns. Record a fresh
   tracked/live lifecycle-counter and player-pointer baseline.
6. First require at least twenty seconds of continuously advancing, unblocked
   live frames after `LifecycleA` completes. Call ordinary
   `Game.QuitToMainMenu` once and wait for advancing, unblocked Main Menu
   frames. This navigation call intentionally retains the current player and
   is not itself release evidence.
7. From that stable Main Menu, execute exactly one case-sensitive `ForceReset`
   console command through DevBench, without opening the console or using
   keyboard, mouse, or focus APIs. Preserve DevBench's exact
   `console.command` event. Require the
   synchronous `player lifecycle transition` to show
   `constructorAssignments` and `releaseQuarantines` advanced by exactly one,
   a changed `PlayerCharacter` base, and raw handle `00100000`; then wait for
   the Main Menu.
8. From that stable Main Menu, load `LifecycleB` and wait until normal control
   returns. Its `kPreLoadGame`/`kPostLoadGame` pair must be live-to-live. Both
   manager-locked snapshots must show exact C+1/R+1/A+1 counters, including
   `lifecycleAssignments`, and object/singleton addresses equal to the
   immediately recreated `PlayerCharacter` base.
9. Call ordinary `Game.QuitToMainMenu` a second and final time and wait for
   advancing, unblocked Main Menu frames. This is also navigation only: on AE
   1.6.1170 it does not release/recreate `PlayerCharacter`, so do not require a
   detached player. The orchestrator must prove exactly these two phase-labelled
   calls (`before-force-reset`, then `after-load-b`) and zero retries.
10. Start a second new game.
11. Quit normally and preserve the complete
   `Documents/My Games/Skyrim Special Edition/SKSE/SkyrimHandleCapRaise.log`
   (use the corresponding GOG or VR Documents directory for those runtimes).

The instrumented DLL emits machine-readable `lifecycle: checkpoint PASS` lines.
A run of the reviewed AE/Engine Fixes test profile must also contain the exact
`compatibility: EngineFixesFormCaching PASS` line documented in
[`ENGINE-FIXES-FORM-CACHING-INTEROP.md`](ENGINE-FIXES-FORM-CACHING-INTEROP.md).
That line proves the run exercised the authenticated FormCaching collision; a
stock owner produced by disabling `bFormCaching` is not equivalent evidence.
The verifier also requires exactly one matching
`lifecycle: EngineFixesFormCaching revalidation PASS` immediately before every
checkpoint BEGIN/PASS pair. This proves the entry, wrapper, live SafetyHook
state, and original-call trampoline remained unchanged throughout the tested
single-process lifecycle.
A PASS is written only after the locked snapshot proves the player entry/FormID,
the raw handle, free-entry count, FIFO endpoints, every FIFO link, and the
absence of slot `0x100000` from the ordinary chain. Save-load checkpoints also
carry a `loadAttempt` ID. A `kPostLoadGame` counts only when SKSE's result
payload has the documented one-byte shape and reports success; failed or
malformed attempts remain paused and cannot be paired with a later load.
Each PASS is followed synchronously by a `lifecycle: snapshot` line carrying
the constructor, release-quarantine, and reserved-assignment counters plus the
current player object/singleton identity. The `LifecycleA` post-load snapshot
is the ForceReset baseline; a stale periodic monitor sample is not accepted.
The immediate post-command `player lifecycle transition` is the C+1/R+1 and
new-object recreation proof. It intentionally does not claim singleton
publication or the mandatory guard assignment count; the following
manager-locked `LifecycleB` Pre/Post snapshots prove those stable properties.

AE may emit a startup `kPreLoadGame`/`kPostLoadGame` pair. Messages before
`kDataLoaded` are explicitly ignored, and any additional startup pair is not a
test anchor. The verifier anchors on the first `kNewGame` after `kDataLoaded`
and checks the following semantic transitions rather than assuming raw SKSE
ordinals always begin at one:

```text
kDataLoaded(detached, or live 0x00100000)
kNewGame(live 0x00100000)
successful LifecycleA load: kPreLoadGame(live) -> kPostLoadGame(live)
ordinary QuitToMainMenu -> stable Main Menu (no detached-player requirement)
exactly one observed ForceReset:
  immediate transition: constructorAssignments C -> C+1
  immediate transition: releaseQuarantines R -> R+1
  immediate transition: PlayerCharacter base changes; raw remains 0x00100000
successful LifecycleB load: kPreLoadGame(live) -> kPostLoadGame(live)
  both locked snapshots: C+1/R+1/A+1
  both locked snapshots: object == singleton == immediate recreated base
  both locked scans: ordinaryFIFO=ABSENT
second ordinary QuitToMainMenu -> stable Main Menu (no detached-player requirement)
kNewGame(live 0x00100000)
```

Every anchored `kNewGame`, successful `kPostLoadGame`, and first tested
`kPreLoadGame` checkpoint must report
`playerReservation=live-player playerRawHandle=00100000` and
`ordinaryFIFO=ABSENT`.
Together with the startup seven-hook proof, the first genuine `kNewGame` result
is the live regression check for the constructor-before-singleton failure that
motivated the arm; the earlier `kDataLoaded` result must not be reused as
acceptance evidence. At `kDataLoaded`, the player may either not yet be
published (`playerReservation=detached playerRawHandle=n/a`) or already be live
(`playerReservation=live-player playerRawHandle=00100000`). Both timings are
valid, but the reserved slot must be `100000` and `ordinaryFIFO=ABSENT` in
either case; mixed or unknown reservation/handle states fail verification.
The tested `kPreLoadGame` and `kPostLoadGame` after `ForceReset` must report a
live player at raw handle `00100000` and `ordinaryFIFO=ABSENT`. Their snapshots
must retain the immediate transition's new player base as both object and
singleton and show exact C+1/R+1/A+1 totals. The synchronous transition plus
these following locked full-chain checkpoints are the live
release/quarantine/reclaim evidence; recurring monitor output is never an
acceptance dependency. Ordinary `QuitToMainMenu` is not such evidence: it
reaches the Main Menu while preserving the recreated player on this runtime.

## Record and verify observations

Generate a blank observation record:

```powershell
python probes/verify_live_lifecycle.py `
  --write-observation-template artifacts/live-observations.json
```

Fill in the exact runtime, candidate DLL SHA-256, mod versions, results, and
short notes describing what was visibly exercised. Precision first-person,
third-person, hostile-melee, and OAR results must be `pass`. Alternate
Conversation Camera may be `not-applicable`, but only with a reason.

Then verify both the engine log and the observations:

```powershell
python probes/verify_live_lifecycle.py `
  'C:\path\to\SkyrimHandleCapRaise.log' `
  --observations artifacts/live-observations.json `
  --orchestrator '.tmp\live-evidence\background-lifecycle-...\orchestrator.json'
```

The command exits zero only when the complete lifecycle sequence, the exact two
phase-labelled `Game.QuitToMainMenu` calls, exact one-command ForceReset
transcript, immediate C+1/R+1 recreation, following locked C+1/R+1/A+1
identity/FIFO proof, and every required compatibility observation pass. Keep
the original log, orchestrator JSON, observation JSON, candidate DLL, and its
SHA-256 together as release evidence.
