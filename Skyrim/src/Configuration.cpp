#include "Configuration.h"

#include "GenerationTracker.h"
#include "PluginPaths.h"

#include <windows.h>

#include <algorithm>
#include <cstdint>

namespace shcr
{
    Settings LoadSettings() noexcept
    {
        Settings settings;
        wchar_t ini[MAX_PATH * 2]{};
        PluginsDir(ini, MAX_PATH * 2);
        wcscat_s(ini, L"SkyrimHandleCapRaise.ini");
        settings.generationWrapDetection =
            GetPrivateProfileIntW(
                L"General", L"GenerationWrapDetection", 1, ini) != 0;
        settings.stress.liveDiagnosticsEnabled =
            GetPrivateProfileIntW(L"General", L"VerboseLogging", 0, ini) != 0;
        settings.stress.lifecycleVerificationEnabled =
            GetPrivateProfileIntW(
                L"General", L"LifecycleVerification", 0, ini) != 0;
        const int configuredSampleSize = static_cast<int>(
            GetPrivateProfileIntW(L"General", L"SampleSize", 16, ini));
        settings.stress.diagnosticsDetailedSampleLimit =
            static_cast<std::uint32_t>((std::clamp)(
                configuredSampleSize, 0, 4096));
        settings.stress.enabled =
            GetPrivateProfileIntW(L"StressTest", L"Enabled", 0, ini) != 0;
        settings.stress.indexBits = generation::kIndexBits;
        settings.stress.syntheticFillToIndex = static_cast<std::uint32_t>(
            GetPrivateProfileIntW(
                L"StressTest", L"SyntheticFillToIndex", 0, ini));
        settings.stress.detailedLogFromIndex = static_cast<std::uint32_t>(
            GetPrivateProfileIntW(
                L"StressTest", L"DetailedLogFromIndex", 0x100000, ini));
        settings.stress.maxDetailedLogs = static_cast<std::uint32_t>(
            GetPrivateProfileIntW(
                L"StressTest", L"MaxDetailedLogs",
                generation::kEntryCount, ini));
        settings.stress.maxReferencesPerTask = static_cast<std::uint32_t>(
            GetPrivateProfileIntW(
                L"StressTest", L"ReferencesPerTask", 4096, ini));
        settings.stress.maxTaskMicroseconds = static_cast<std::uint32_t>(
            GetPrivateProfileIntW(
                L"StressTest", L"TaskBudgetMicroseconds", 4000, ini));
        settings.stress.coordinatorDelayMilliseconds = static_cast<std::uint32_t>(
            GetPrivateProfileIntW(
                L"StressTest", L"DelayMilliseconds", 16, ini));
        settings.stress.verifySecondPass =
            GetPrivateProfileIntW(
                L"StressTest", L"VerifySecondPass", 1, ini) != 0;
        settings.stress.releaseProbeCount = static_cast<std::uint32_t>(
            GetPrivateProfileIntW(
                L"StressTest", L"ReleaseProbeCount", 0, ini));
        settings.stress.reuseProbeCycles = static_cast<std::uint32_t>(
            GetPrivateProfileIntW(
                L"StressTest", L"ReuseProbeCycles", 0, ini));
        settings.stress.churnCycles = static_cast<std::uint32_t>(
            GetPrivateProfileIntW(L"StressTest", L"ChurnCycles", 0, ini));
        settings.stress.stopOnVerificationFailure =
            GetPrivateProfileIntW(
                L"StressTest", L"StopOnVerificationFailure", 1, ini) != 0;
        return settings;
    }
}
