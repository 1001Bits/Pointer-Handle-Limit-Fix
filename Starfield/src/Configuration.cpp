#include "Configuration.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>

namespace
{
    constexpr wchar_t kIniRelativePath[] =
        L"Data\\SFSE\\Plugins\\StarfieldHandleCapRaise.ini";

    void BuildIniPath(wchar_t* path, std::size_t capacity) noexcept
    {
        // Keep the same executable-relative lookup used by the original single-file plugin.
        ::GetModuleFileNameW(nullptr, path, MAX_PATH);

        wchar_t* lastSlash = nullptr;
        for (wchar_t* cursor = path; *cursor != L'\0'; ++cursor) {
            if (*cursor == L'\\' || *cursor == L'/') {
                lastSlash = cursor;
            }
        }
        if (lastSlash != nullptr) {
            lastSlash[1] = L'\0';
        }

        ::wcscat_s(path, capacity, kIniRelativePath);
    }
}

namespace sfhcr
{
    Settings LoadSettings() noexcept
    {
        Settings settings;

        // MAX_PATH is the exact executable-path budget used previously; the second half leaves
        // room for the fixed Data\SFSE\Plugins suffix without heap allocation.
        wchar_t iniPath[MAX_PATH * 2]{};
        BuildIniPath(iniPath, MAX_PATH * 2);

        const bool enable8M =
            ::GetPrivateProfileIntW(L"General", L"Enable8M", 0, iniPath) != 0;
        settings.targetIndexBits = enable8M ? kHighCapIndexBits : kDefaultIndexBits;
        settings.verboseLogging =
            ::GetPrivateProfileIntW(L"General", L"VerboseLogging", 0, iniPath) != 0;
        settings.generationWrapDetection =
            ::GetPrivateProfileIntW(
                L"General", L"GenerationWrapDetection", 1, iniPath) != 0;

        const int sampleSize = static_cast<int>(
            ::GetPrivateProfileIntW(L"General", L"SampleSize", 16, iniPath));
        settings.detailedSampleCount =
            static_cast<std::size_t>((std::clamp)(sampleSize, 0, 64));

        return settings;
    }
}
