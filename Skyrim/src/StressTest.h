#pragma once

#include <cstddef>
#include <cstdint>

// Optional, throwaway-only reference-handle stress harness.
//
// Integration (intentionally not wired into main.cpp by this file):
//
//   shcr::stress::Settings stressSettings;
//   stressSettings.enabled = ReadStressSettingFromIni();
//
//   shcr::stress::Callbacks stressCallbacks;
//   stressCallbacks.context = ...;
//   stressCallbacks.log = ...;
//   stressCallbacks.resolveNames = ...;
//
//   shcr::stress::Initialize(skseLoadInterface, stressSettings, stressCallbacks);
//
// Call Initialize from SKSEPlugin_Load *after* the cap-raise patch has either
// succeeded or cleanly declined.  The SKSE load-interface pointer is the same
// pointer passed to SKSEPlugin_Load.  When enabled, Initialize registers for
// SKSE's kDataLoaded message; all calls into Skyrim's handle manager and all
// resolveNames callbacks then run on Skyrim's main thread.
//
// The normal sample mode deliberately keeps allocated handles and synthetic
// objects alive until process exit.  The opt-in churn mode instead exhausts the
// table and releases/reuses one synthetic high slot through Skyrim's canonical
// handle-manager API.  Temporary GetSmartPointer pins are balanced in both modes.
// Run either mode only in a disposable profile.

namespace shcr::stress
{
    struct ResolvedNames
    {
        char originPlugin[260]{};
        char winningPlugin[260]{};
        char formName[256]{};
        char editorID[256]{};
        char displayName[512]{};
        char baseOriginPlugin[260]{};
        char baseWinningPlugin[260]{};
        char baseName[256]{};
        char baseEditorID[256]{};
        std::uint32_t baseFormID = 0;
    };

    // log may receive embedded newlines.  The harness buffers detailed rows and
    // normally emits one callback per bounded main-thread batch, which avoids a
    // flush for every high-index reference when the host logger is synchronous.
    using LogCallback = void (*)(void* a_context, const char* a_message);

    // Called only on Skyrim's main thread.  a_reference is a TESObjectREFR (or a
    // derived ACHR/projectile/hazard) from TESDataHandler::formArrays.  Fill as
    // many fields as are available; all buffers arrive zero-initialized.
    using ResolveNamesCallback = bool (*)(
        void* a_context,
        const void* a_reference,
        ResolvedNames& a_names);

    // Lightweight attribution used by the production live-table diagnostic.
    // It fills only the reference/base FormIDs and plugin fields; expensive
    // editor, detailed, and display names are requested separately for the
    // configured bounded sample.
    using ResolveAttributionCallback = bool (*)(
        void* a_context,
        const void* a_reference,
        ResolvedNames& a_names);

    // Optional main-thread gate run immediately on kDataLoaded and before any
    // synthetic allocation.  The stock-control DLL uses it to re-prove that no
    // cap raiser or other handle-manager code patch appeared after plugin load.
    using PreflightCallback = bool (*)(void* a_context);

    struct Callbacks
    {
        void*                context = nullptr;
        LogCallback          log = nullptr;
        ResolveAttributionCallback resolveAttribution = nullptr;
        ResolveNamesCallback resolveNames = nullptr;
        PreflightCallback    preflight = nullptr;

        // Relocated table published by the cap raiser.  The live sampler reads
        // candidate handles from it only after kPostLoadGame/kNewGame, then
        // validates every candidate through Skyrim's GetSmartPointer before
        // touching the returned reference.
        const void*          handleTable = nullptr;
        std::uint32_t        handleEntryCount = 0;
    };

    struct Settings
    {
        // Safe default: no listener, thread, allocation, or engine call.
        bool enabled = false;

        // Production-safe, read-only high-handle reports. This mode is mutually
        // exclusive with the synthetic stress harness. Starting one minute after
        // a successful kPostLoadGame/kNewGame, it scans bounded batches over live
        // table slots at/above Skyrim's vanilla cap once per minute, validates
        // candidates through GetSmartPointer, balances every temporary pin, and
        // aggregates plugin attribution. kPreLoadGame pauses the schedule. It
        // never creates or retains a handle.
        bool liveDiagnosticsEnabled = false;
        std::uint32_t diagnosticsDetailedSampleLimit = 16;

        // The cap raiser uses 22 index bits.  Set this to 20 only for a stock-cap
        // control run; decoding a stock handle with 22 bits mistakes age bits
        // 20-21 for index bits.
        std::uint32_t indexBits = 22;

        // Optional test-only filler.  If nonzero, minimally shaped synthetic
        // BSHandleRefObject blocks consume handles until the last filler index is
        // at least syntheticFillToIndex-1.  Real loaded forms are processed next,
        // so 0x100000 makes the first real forms exercise the raised index bit.
        // Synthetic objects are never exposed as TESForms and are intentionally
        // leaked until process exit.  Keep this zero when the real AE load order
        // already contains enough references.
        std::uint32_t syntheticFillToIndex = 0;

        // Detailed rows (and the optional name resolver) begin here.  Skyrim's
        // original ceiling is 0x100000.  For a live sample, this is also the
        // first table index scanned after a save/new game loads.  Synthetic
        // filler objects never enter the name resolver.
        std::uint32_t detailedLogFromIndex = 0x100000;
        std::uint32_t maxDetailedLogs = 0x400000;

        // A task stops at whichever bound is reached first.  Engine calls remain
        // main-thread-only; a coordinator waits between tasks because SKSE drains
        // tasks queued by another task in the same ProcessTasks invocation.
        std::uint32_t maxReferencesPerTask = 4096;
        std::uint32_t maxTaskMicroseconds = 4000;
        std::uint32_t coordinatorDelayMilliseconds = 16;

        // Re-resolve every successfully acquired handle after the allocation pass
        // to catch stale/wrapped/wrong-object decoding, not merely immediate lookup.
        bool verifySecondPass = true;

        // Targeted canonical-release proof that does not require exhausting the
        // 4M table. After the synthetic filler reaches its target, release this
        // many harness-owned handles whose indices are at least 0x200000. Each
        // release must restore owner count 1, clear the full-index sidecar, leave
        // the table entry free with its prior age, and make the stale handle fail
        // lookup. Released records are removed before live sampling. A nonzero
        // value requires 22-bit sample mode, a fill target above 0x200000, and no
        // churn or stock-control mode. Safe default: disabled.
        std::uint32_t releaseProbeCount = 0;

        // Non-exhausting exact-slot reuse proof. After the targeted releases,
        // the harness canonically releases a separate live >=2M synthetic target
        // and rotates Skyrim's FIFO free list with one pristine scratch object.
        // Every non-target allocation is immediately verified and released, so
        // the test never consumes the pre-existing free-slot cushion. When the
        // scratch object reaches the target slot, it must carry the exact next
        // generation and sidecar while the old handle rejects and an adjacent
        // synthetic neighbor remains unchanged. Currently exactly one cycle is
        // supported. A nonzero value requires ReleaseProbeCount>0, a fill target
        // above 2M and below 4M, and no churn/stock-control mode.
        std::uint32_t reuseProbeCycles = 0;

        // Deterministic high-slot release/reuse test.  A nonzero value requires
        // indexBits=22 and SyntheticFillToIndex=0x400000.  The harness first
        // proves exhaustion, then moves slot 0x3FFFFF to a distinct synthetic
        // object through Skyrim's canonical release function each cycle.  It checks
        // the qword sidecar clear, stale rejection, exact object identity, and age
        // increment.  64 cycles additionally demonstrates the documented six-bit
        // generation wrap/ABA boundary.  Safe default: disabled.
        std::uint32_t churnCycles = 0;

        // Default verification mode aborts on the first error. Set false only
        // to continue gathering deliberate 4M-table exhaustion data; lookup,
        // identity, and pin errors still make final completion fail.
        bool stopOnVerificationFailure = true;

        // Separate stock-cap control mode.  A nonzero value requires the stock
        // 20-bit table, SyntheticFillToIndex=0x100000, and ChurnCycles=0.  The
        // harness owns every synthetic reference it creates, consumes every
        // currently free stock slot, proves exhaustion, and then makes exactly
        // this many allocation attempts while the table is full.  The first
        // zero-return that proves exhaustion counts as attempt one.
        //
        // This is intentionally zero for the cap-raise plugin.  The separate
        // SkyrimHandleCapStockProbe test DLL sets it to 4096 by default.
        std::uint32_t stockOverflowAttempts = 0;

        // When false, release every synthetic handle through Skyrim's canonical
        // manager API immediately after the overflow proof.  When true, keep the
        // stock table exhausted until kPostLoadGame/kNewGame, then clean up.  A
        // held run is irreversibly tainted because engine allocations that failed
        // while the table was full cannot be reconstructed; exit without saving.
        bool stockHoldThroughGameLoad = false;
    };

    // Returns false if enabled but the SKSE ABI, runtime, interfaces, or settings
    // are invalid.  Returns true immediately when settings.enabled is false.
    bool Initialize(
        const void* a_skseLoadInterface,
        const Settings& a_settings,
        const Callbacks& a_callbacks) noexcept;

    // Best-effort process-shutdown signal.  The normal throwaway workflow simply
    // exits Skyrim; do not unload this DLL while a stress run is active.
    void Shutdown() noexcept;

    [[nodiscard]] bool IsRunning() noexcept;
}
