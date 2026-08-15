// Throwaway-only stock Skyrim reference-handle exhaustion control.
//
// This DLL deliberately does not apply the 2M cap patch.  It verifies the full
// audited handle-manager instruction set is stock at plugin load and again at
// kDataLoaded, fills the remaining vanilla 1M table with probe-owned synthetic
// BSHandleRefObjects, proves above-cap allocation failure, and canonically
// releases its handles unless configured to hold through a game load.

#include <windows.h>
#include <shlobj.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>

#include "PatchTable.g.h"
#include "StressTest.h"

namespace shcr::stockprobe
{
    namespace
    {
        struct SKSEInterface
        {
            std::uint32_t skseVersion;
            std::uint32_t runtimeVersion;
            std::uint32_t editorVersion;
            std::uint32_t isEditor;
            void* (*QueryInterface)(std::uint32_t);
            std::uint32_t (*GetPluginHandle)();
            std::uint32_t (*GetReleaseIndex)();
            const void* (*GetPluginInfo)(const char*);
        };

        struct ProbeContext
        {
            const Profile* profile = nullptr;
            std::uintptr_t imageBase = 0;
        };

        FILE*        g_log = nullptr;
        SRWLOCK      g_logLock = SRWLOCK_INIT;
        ProbeContext g_context;

        void OpenSharedLogFile(const wchar_t* a_path)
        {
            int descriptor = -1;
            if (_wsopen_s(&descriptor, a_path,
                    _O_WRONLY | _O_CREAT | _O_TRUNC | _O_TEXT,
                    _SH_DENYWR, _S_IREAD | _S_IWRITE) != 0 || descriptor < 0) {
                return;
            }
            g_log = _fdopen(descriptor, "w");
            if (!g_log)
                _close(descriptor);
        }

        void OpenLog(std::uint32_t a_runtime)
        {
            PWSTR docs = nullptr;
            wchar_t path[MAX_PATH * 2]{};
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &docs))) {
                const wchar_t* gameFolder = a_runtime == 0x010400F0u ? L"Skyrim VR" :
                    a_runtime == 0x010649B1u ? L"Skyrim Special Edition GOG" :
                    L"Skyrim Special Edition";
                swprintf_s(path, L"%s\\My Games\\%s\\SKSE", docs, gameFolder);
                CoTaskMemFree(docs);
                CreateDirectoryW(path, nullptr);
                wcscat_s(path, L"\\SkyrimHandleCapStockProbe.log");
                OpenSharedLogFile(path);
            }
            if (!g_log) {
                const DWORD length = GetTempPathW(
                    static_cast<DWORD>(sizeof(path) / sizeof(path[0])), path);
                if (length != 0 && length < sizeof(path) / sizeof(path[0])) {
                    wcscat_s(path, L"SkyrimHandleCapStockProbe.log");
                    OpenSharedLogFile(path);
                }
            }
        }

        void Log(const char* a_format, ...)
        {
            if (!g_log)
                return;
            AcquireSRWLockExclusive(&g_logLock);
            va_list args;
            va_start(args, a_format);
            vfprintf(g_log, a_format, args);
            va_end(args);
            fputc('\n', g_log);
            fflush(g_log);
            ReleaseSRWLockExclusive(&g_logLock);
        }

        void StressLog(void*, const char* a_message)
        {
            Log("%s", a_message ? a_message : "");
        }

        bool PluginsDir(wchar_t* a_out, std::size_t a_count)
        {
            if (!a_out || a_count == 0)
                return false;
            const DWORD length = GetModuleFileNameW(
                nullptr, a_out, static_cast<DWORD>(a_count));
            if (length == 0 || length >= a_count)
                return false;
            wchar_t* slash = wcsrchr(a_out, L'\\');
            if (!slash)
                return false;
            *(slash + 1) = L'\0';
            return wcscat_s(a_out, a_count, L"Data\\SKSE\\Plugins\\") == 0;
        }

        bool CapRaiseDllIsAbsent()
        {
            wchar_t path[MAX_PATH * 2]{};
            if (!PluginsDir(path, sizeof(path) / sizeof(path[0]))) {
                Log("stock-control: ABORT: could not resolve Data\\SKSE\\Plugins");
                return false;
            }
            if (wcscat_s(path, L"SkyrimHandleCapRaise.dll") != 0) {
                Log("stock-control: ABORT: cap-raise DLL path overflow");
                return false;
            }
            if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
                Log("stock-control: ABORT: SkyrimHandleCapRaise.dll is still present. Move it "
                    "out of Data\\SKSE\\Plugins for a genuine no-cap-patch control run.");
                return false;
            }
            return true;
        }

        void RecordMismatch(
            const char* a_kind,
            std::uint32_t a_rva,
            const std::uint8_t* a_expected,
            const std::uint8_t* a_actual,
            std::size_t& a_count)
        {
            if (a_count < 8) {
                Log("stock-control: non-stock %s at RVA %08X: expected %02X, found %02X",
                    a_kind,
                    a_rva,
                    a_expected ? a_expected[0] : 0,
                    a_actual ? a_actual[0] : 0);
            }
            ++a_count;
        }

        bool VerifyStockCode(const ProbeContext& a_context)
        {
            if (!a_context.profile || !a_context.imageBase)
                return false;

            const Profile& profile = *a_context.profile;
            std::size_t mismatches = 0;
            for (std::uint32_t i = 0; i < profile.fieldCount; ++i) {
                const FieldPatch& patch = profile.fields[i];
                const auto* actual = reinterpret_cast<const std::uint8_t*>(
                    a_context.imageBase + patch.rva);
                if (patch.len == 0 || patch.len > sizeof(patch.orig) ||
                    std::memcmp(actual, patch.orig, patch.len) != 0) {
                    RecordMismatch("field instruction", patch.rva, patch.orig, actual, mismatches);
                }
            }
            for (std::uint32_t i = 0; i < profile.tableRefCount; ++i) {
                const TableRef& reference = profile.tableRefs[i];
                const auto* actual = reinterpret_cast<const std::uint8_t*>(
                    a_context.imageBase + reference.rva);
                bool bad = reference.len == 0 || reference.len > sizeof(reference.orig) ||
                    reference.dispOff + sizeof(std::int32_t) != reference.len ||
                    std::memcmp(actual, reference.orig, reference.len) != 0;
                if (!bad) {
                    std::int32_t displacement = 0;
                    std::memcpy(
                        &displacement, actual + reference.dispOff, sizeof(displacement));
                    const auto target = static_cast<std::uintptr_t>(
                        static_cast<std::int64_t>(
                            a_context.imageBase + reference.rva + reference.len) +
                        displacement);
                    bad = target != a_context.imageBase + profile.tableRva;
                }
                if (bad) {
                    RecordMismatch(
                        "stock-table reference",
                        reference.rva,
                        reference.orig,
                        actual,
                        mismatches);
                }
            }
            for (std::uint32_t i = 0; i < profile.initPatchCount; ++i) {
                const BytePatch& patch = profile.initPatches[i];
                const auto* actual = reinterpret_cast<const std::uint8_t*>(
                    a_context.imageBase + patch.rva);
                if (patch.len == 0 || patch.len > sizeof(patch.orig) ||
                    std::memcmp(actual, patch.orig, patch.len) != 0) {
                    RecordMismatch("initialiser guard", patch.rva, patch.orig, actual, mismatches);
                }
            }
            if (mismatches != 0) {
                Log("stock-control: ABORT: %zu audited handle-manager sites are non-stock; "
                    "the no-cap-patch control is invalid",
                    mismatches);
                return false;
            }
            Log("stock-control: verified stock handle-manager code: %u fields, "
                "%u table references, %u initialiser guards",
                profile.fieldCount,
                profile.tableRefCount,
                profile.initPatchCount);
            return true;
        }

        bool DataLoadedPreflight(void* a_context)
        {
            const auto* context = static_cast<const ProbeContext*>(a_context);
            Log("stock-control: repeating no-cap-patch proof at kDataLoaded");
            return context && CapRaiseDllIsAbsent() && VerifyStockCode(*context);
        }

        const Profile* FindProfile(std::uint32_t a_runtime)
        {
            // Generated patch profiles are keyed by the executable's
            // ProductVersion (.0); SKSE tags GOG as runtime type 1.
            if (a_runtime == 0x010649B1u)
                a_runtime = 0x010649B0u;
            for (std::uint32_t i = 0; i < kProfileCount; ++i) {
                if (kProfiles[i]->runtimeVersion == a_runtime)
                    return kProfiles[i];
            }
            return nullptr;
        }

        bool Arm(const void* a_skseLoadInterface)
        {
            const auto* skse = static_cast<const SKSEInterface*>(a_skseLoadInterface);
            if (!skse) {
                Log("stock-control: ABORT: SKSE load interface is null");
                return false;
            }
            const Profile* profile = FindProfile(skse->runtimeVersion);
            if (!profile) {
                Log("stock-control: ABORT: unsupported runtime %08X; supported: Skyrim SE "
                    "1.5.97, AE 1.6.1170, GOG 1.6.1179, and VR 1.4.15",
                    skse->runtimeVersion);
                return false;
            }

            wchar_t ini[MAX_PATH * 2]{};
            if (!PluginsDir(ini, sizeof(ini) / sizeof(ini[0])) ||
                wcscat_s(ini, L"SkyrimHandleCapStockProbe.ini") != 0) {
                Log("stock-control: ABORT: could not resolve probe INI path");
                return false;
            }
            if (GetPrivateProfileIntW(L"General", L"Enabled", 0, ini) == 0) {
                Log("stock-control: Enabled=0 -- probe is inert");
                return true;
            }

            g_context.profile = profile;
            g_context.imageBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
            if (!g_context.imageBase || !CapRaiseDllIsAbsent() ||
                !VerifyStockCode(g_context)) {
                return false;
            }

            stress::Settings settings;
            settings.enabled = true;
            settings.indexBits = 20;
            settings.syntheticFillToIndex = profile->stockEntries;
            settings.detailedLogFromIndex = profile->stockEntries;
            settings.maxDetailedLogs = 0;
            settings.maxReferencesPerTask = static_cast<std::uint32_t>(
                GetPrivateProfileIntW(L"StockProbe", L"ReferencesPerTask", 4096, ini));
            settings.maxTaskMicroseconds = static_cast<std::uint32_t>(
                GetPrivateProfileIntW(L"StockProbe", L"TaskBudgetMicroseconds", 4000, ini));
            settings.coordinatorDelayMilliseconds = static_cast<std::uint32_t>(
                GetPrivateProfileIntW(L"StockProbe", L"DelayMilliseconds", 16, ini));
            settings.verifySecondPass = false;
            settings.churnCycles = 0;
            settings.stopOnVerificationFailure = true;
            settings.stockOverflowAttempts = static_cast<std::uint32_t>(
                GetPrivateProfileIntW(L"StockProbe", L"OverflowAttempts", 4096, ini));
            settings.stockHoldThroughGameLoad =
                GetPrivateProfileIntW(
                    L"StockProbe", L"HoldThroughPostLoadGame", 0, ini) != 0;

            if (settings.stockOverflowAttempts == 0 ||
                settings.stockOverflowAttempts > profile->stockEntries) {
                Log("stock-control: ABORT: OverflowAttempts must be in [1, %u]",
                    profile->stockEntries);
                return false;
            }

            stress::Callbacks callbacks;
            callbacks.context = &g_context;
            callbacks.log = &StressLog;
            callbacks.preflight = &DataLoadedPreflight;
            callbacks.handleTable = reinterpret_cast<const void*>(
                g_context.imageBase + profile->tableRva);
            callbacks.handleEntryCount = profile->stockEntries;

            Log("SkyrimHandleCapStockProbe 1.0.0 -- %s, vanilla entries=%u, "
                "overflowAttempts=%u, holdThroughPostLoadGame=%u",
                profile->name,
                profile->stockEntries,
                settings.stockOverflowAttempts,
                settings.stockHoldThroughGameLoad ? 1u : 0u);
            Log("stock-control: THROWAWAY TEST ONLY; never save during this run");
            if (!stress::Initialize(a_skseLoadInterface, settings, callbacks)) {
                Log("stock-control: ABORT: stress harness rejected SKSE interfaces or settings");
                return false;
            }
            return true;
        }
    }

    void Init(const void* a_skseLoadInterface)
    {
        const auto* skse = static_cast<const SKSEInterface*>(a_skseLoadInterface);
        OpenLog(skse ? skse->runtimeVersion : 0);
        if (!Arm(a_skseLoadInterface))
            Log("stock-control: probe did not arm; no synthetic references were allocated");
    }
}

struct SKSEPluginVersionData
{
    enum : std::uint32_t
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

#define STOCK_RUNTIME_VERSION(major, minor, build, sub) \
    ((((major) & 0xFF) << 24) | (((minor) & 0xFF) << 16) | \
     (((build) & 0xFFF) << 4) | ((sub) & 0xF))

extern "C" __declspec(dllexport) SKSEPluginVersionData SKSEPlugin_Version = {
    SKSEPluginVersionData::kVersion,
    0x010000,
    "SkyrimHandleCapStockProbe",
    "Skyrim Handle Audit",
    "",
    0,
    0,
    { STOCK_RUNTIME_VERSION(1, 5, 97, 0), STOCK_RUNTIME_VERSION(1, 6, 1170, 0),
      // SKSE encodes the GOG storefront in the packed runtime's low nibble.
      STOCK_RUNTIME_VERSION(1, 6, 1179, 1), STOCK_RUNTIME_VERSION(1, 4, 15, 0), 0 },
    0,
};

struct PluginInfo
{
    std::uint32_t infoVersion;
    const char*   name;
    std::uint32_t version;
};

extern "C" __declspec(dllexport) bool SKSEPlugin_Query(void*, PluginInfo* a_info)
{
    if (a_info) {
        a_info->infoVersion = 1;
        a_info->name = "SkyrimHandleCapStockProbe";
        a_info->version = 0x010000;
    }
    return true;
}

extern "C" __declspec(dllexport) bool SKSEPlugin_Load(void* a_skse)
{
    shcr::stockprobe::Init(a_skse);
    return true;
}

BOOL WINAPI DllMain(HINSTANCE a_instance, DWORD a_reason, LPVOID)
{
    if (a_reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(a_instance);
    return TRUE;
}
