// Skyrim Handle Cap Raise -- SKSE plugin entry and component orchestration.

#include <windows.h>

#include <cstdint>

#include "Configuration.h"
#include "FormAttribution.h"
#include "GenerationDiagnostic.h"
#include "Logging.h"
#include "PatchTransaction.h"
#include "RuntimeDetection.h"
#include "RuntimeTypes.h"
#include "StressTest.h"
#include "TableMonitor.h"

namespace shcr
{
    namespace
    {
        struct PluginState
        {
            Settings           settings;
            RuntimeContext     runtime;
            AttributionContext attribution;
            patch::Result      patchResult;
            bool               diagnosticPrepared = false;
            bool               diagnosticInstalled = false;
        };

        PluginState g_state;

        bool OnTablePrepared(
            void* a_context,
            const RuntimeContext& a_runtime,
            HandleTableView a_table) noexcept
        {
            auto& state = *static_cast<PluginState*>(a_context);
            if (!state.settings.generationWrapDetection) {
                Log("ABORT: GenerationWrapDetection=0 is incompatible with "
                    "the 2M/21+5 layout; cap raise refused.");
                return false;
            }
            state.diagnosticPrepared = diagnostic::Prepare(
                a_runtime, a_table, true, &state.attribution);
            if (!state.diagnosticPrepared) {
                Log("ABORT: GenerationWrapDetection=1 requires the exact "
                    "pre-publication guard; cap raise refused.");
            }
            return state.diagnosticPrepared;
        }

        bool OnCommittedWhileManagerLocked(
            void* a_context,
            const RuntimeContext& a_runtime,
            HandleTableView a_table) noexcept
        {
            auto& state = *static_cast<PluginState*>(a_context);

            // Install the requested guard before starting the detached
            // reporter thread.  On install refusal no thread can retain the
            // transaction-owned table while PatchTransaction rolls it back.
            if (state.settings.generationWrapDetection) {
                if (!state.diagnosticPrepared)
                    return false;
                state.diagnosticInstalled = diagnostic::Install();
                if (!state.diagnosticInstalled) {
                    Log("ABORT: mandatory pre-publication generation-wrap "
                        "guard installation failed; cap raise will roll back.");
                    return false;
                }
            }

            const bool reporterStarted = monitor::Start(
                a_runtime, a_table, state.settings.stress.enabled);
            if (!reporterStarted && state.diagnosticInstalled) {
                Log("WARNING: the mandatory generation-wrap guard is active, "
                    "but periodic hottest-slot reporting could not start.");
            }
            return true;
        }

        void OnPatchAborted(void* a_context) noexcept
        {
            auto& state = *static_cast<PluginState*>(a_context);
            diagnostic::CancelPrepared();
            state.diagnosticPrepared = false;
            state.diagnosticInstalled = false;
        }
    }

    void Init(const void* a_skseLoadInterface)
    {
        static_cast<void>(DetectRuntime(g_state.runtime));
        g_state.attribution.runtime = &g_state.runtime;
        OpenLog(g_state.runtime.runtimeVersion);
        g_state.settings = LoadSettings();

        Log("SkyrimHandleCapRaise 2.2.0 (2M compatibility build)");
        Log("configuration: GenerationWrapDetection=%u VerboseLogging=%u "
            "LifecycleVerification=%u SampleSize=%u",
            g_state.settings.generationWrapDetection ? 1u : 0u,
            g_state.settings.stress.liveDiagnosticsEnabled ? 1u : 0u,
            g_state.settings.stress.lifecycleVerificationEnabled ? 1u : 0u,
            g_state.settings.stress.diagnosticsDetailedSampleLimit);
        if (g_state.settings.stress.lifecycleVerificationEnabled &&
            !g_state.settings.stress.liveDiagnosticsEnabled) {
            Log("WARNING: LifecycleVerification=1 requires VerboseLogging=1; "
                "lifecycle checkpoints are disabled for this run.");
        }

        const patch::Lifecycle lifecycle{
            &g_state,
            &OnTablePrepared,
            &OnCommittedWhileManagerLocked,
            &OnPatchAborted,
        };
        g_state.patchResult = patch::Raise(g_state.runtime, lifecycle);

        // The original preparation guard released these resources only after
        // the patch transaction dropped Skyrim's manager lock. Preserve that
        // ordering for every diagnostic refusal or install failure.
        if (!g_state.diagnosticInstalled)
            diagnostic::CancelPrepared();

        if (g_state.patchResult.succeeded &&
            (g_state.settings.stress.enabled ||
             g_state.settings.stress.liveDiagnosticsEnabled)) {
            stress::Callbacks callbacks;
            callbacks.context = &g_state.attribution;
            callbacks.log = &StressLog;
            callbacks.resolveAttribution = &ResolveStressAttribution;
            callbacks.resolveNames = &ResolveStressNames;
            callbacks.handleTable = g_state.patchResult.table.entries;
            callbacks.handleEntryCount = g_state.patchResult.table.count;
            if (!stress::Initialize(a_skseLoadInterface,
                    g_state.settings.stress, callbacks)) {
                Log("WARNING: requested verbose diagnostics or private "
                    "StressTest mode could not be initialized. They are "
                    "mutually exclusive and the SKSE interfaces/settings must "
                    "be valid. The cap raise remains active.");
            }
        }
    }
}

struct SKSEPluginVersionData
{
    enum
    {
        kVersion = 1
    };
    std::uint32_t dataVersion;
    std::uint32_t pluginVersion;
    char          name[256];
    char          author[256];
    char          supportEmail[252];
    std::uint32_t versionIndependenceEx;
    std::uint32_t versionIndependence;
    std::uint32_t compatibleVersions[16];
    std::uint32_t seVersionRequired;
};

#define RUNTIME_VERSION(major, minor, build, sub) \
    ((((major) & 0xFF) << 24) | (((minor) & 0xFF) << 16) | \
     (((build) & 0xFFF) << 4) | ((sub) & 0xF))

extern "C" __declspec(dllexport) SKSEPluginVersionData SKSEPlugin_Version = {
    SKSEPluginVersionData::kVersion,
    0x020200,
    "SkyrimHandleCapRaise",
    "Skyrim Handle Audit",
    "",
    0,
    0,
    { RUNTIME_VERSION(1, 5, 97, 0), RUNTIME_VERSION(1, 6, 1170, 0),
      // SKSE uses the low nibble as the storefront type. The GOG loader
      // reports 1.6.1179 as 0x010649B1 even though the executable's translated
      // ProductVersion string used for profile selection is 1.6.1179.0.
      RUNTIME_VERSION(1, 6, 1179, 1), RUNTIME_VERSION(1, 4, 15, 0), 0 },
    0,
};

struct PluginInfo
{
    std::uint32_t infoVersion;
    const char*   name;
    std::uint32_t version;
};

extern "C" __declspec(dllexport) bool SKSEPlugin_Query(
    void*, PluginInfo* a_info)
{
    if (a_info) {
        a_info->infoVersion = 1;
        a_info->name = "SkyrimHandleCapRaise";
        a_info->version = 0x020200;
    }
    return true;
}

extern "C" __declspec(dllexport) bool SKSEPlugin_Load(void* a_skse)
{
    shcr::Init(a_skse);
    return true;
}

BOOL WINAPI DllMain(HINSTANCE a_instance, DWORD a_reason, LPVOID)
{
    if (a_reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(a_instance);
    return TRUE;
}
