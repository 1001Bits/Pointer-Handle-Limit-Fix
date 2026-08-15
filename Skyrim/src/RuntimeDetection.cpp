#include "RuntimeDetection.h"

#include "EngineFixesConfig.h"
#include "Logging.h"
#include "PatchTable.g.h"
#include "PluginPaths.h"

#include <windows.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <string_view>

namespace shcr
{
    namespace
    {
        [[nodiscard]] bool LoadVersionResource(
            const wchar_t* a_path, void*& a_data) noexcept
        {
            a_data = nullptr;
            DWORD ignored = 0;
            const DWORD size = GetFileVersionInfoSizeW(a_path, &ignored);
            if (size == 0)
                return false;

            a_data = std::malloc(size);
            if (!a_data)
                return false;
            if (!GetFileVersionInfoW(a_path, 0, size, a_data)) {
                std::free(a_data);
                a_data = nullptr;
                return false;
            }
            return true;
        }

        [[nodiscard]] bool ReadFixedFileVersion(
            const wchar_t* a_path,
            enginefixes::FileVersion& a_version) noexcept
        {
            a_version = {};
            void* data = nullptr;
            if (!LoadVersionResource(a_path, data))
                return false;

            bool succeeded = false;
            VS_FIXEDFILEINFO* fixed = nullptr;
            UINT fixedSize = 0;
            if (VerQueryValueW(data, L"\\", reinterpret_cast<void**>(&fixed),
                    &fixedSize) &&
                fixed && fixedSize >= sizeof(VS_FIXEDFILEINFO) &&
                fixed->dwSignature == VS_FFI_SIGNATURE) {
                a_version = {
                    HIWORD(fixed->dwFileVersionMS),
                    LOWORD(fixed->dwFileVersionMS),
                    HIWORD(fixed->dwFileVersionLS),
                    LOWORD(fixed->dwFileVersionLS)
                };
                succeeded = true;
            }
            std::free(data);
            return succeeded;
        }

        [[nodiscard]] bool ReadProductVersion(
            const wchar_t* a_path,
            enginefixes::FileVersion& a_version) noexcept
        {
            a_version = {};
            void* data = nullptr;
            if (!LoadVersionResource(a_path, data))
                return false;

            void* rawTranslations = nullptr;
            UINT translationBytes = 0;
            bool found = false;
            bool valid = VerQueryValueW(data, L"\\VarFileInfo\\Translation",
                &rawTranslations, &translationBytes) && rawTranslations &&
                translationBytes != 0 &&
                translationBytes % (sizeof(WORD) * 2u) == 0;

            const auto* translations =
                static_cast<const unsigned char*>(rawTranslations);
            for (UINT offset = 0; valid && offset < translationBytes;
                 offset += sizeof(WORD) * 2u) {
                WORD language = 0;
                WORD codePage = 0;
                std::memcpy(&language, translations + offset, sizeof(language));
                std::memcpy(&codePage,
                    translations + offset + sizeof(language), sizeof(codePage));

                wchar_t query[64]{};
                if (swprintf_s(query,
                        L"\\StringFileInfo\\%04x%04x\\ProductVersion",
                        static_cast<unsigned>(language),
                        static_cast<unsigned>(codePage)) < 0) {
                    valid = false;
                    break;
                }

                wchar_t* text = nullptr;
                UINT textCharacters = 0;
                if (!VerQueryValueW(data, query,
                        reinterpret_cast<void**>(&text), &textCharacters)) {
                    continue;
                }
                if (!text || textCharacters < 2) {
                    valid = false;
                    break;
                }

                std::size_t textLength = 0;
                while (textLength < textCharacters && text[textLength] != L'\0')
                    ++textLength;
                if (textLength == 0 || textLength >= textCharacters) {
                    valid = false;
                    break;
                }

                enginefixes::FileVersion parsed;
                if (!enginefixes::ParseVersionString(
                        std::wstring_view(text, textLength), parsed)) {
                    valid = false;
                    break;
                }
                if (found &&
                    (a_version.major != parsed.major ||
                     a_version.minor != parsed.minor ||
                     a_version.build != parsed.build ||
                     a_version.revision != parsed.revision)) {
                    valid = false;
                    break;
                }
                a_version = parsed;
                found = true;
            }

            std::free(data);
            if (!valid || !found) {
                a_version = {};
                return false;
            }
            return true;
        }

        [[nodiscard]] std::uint32_t RuntimeVersion() noexcept
        {
            wchar_t executable[MAX_PATH]{};
            if (!GetLoadedModulePath(
                    GetModuleHandleW(nullptr), executable,
                    std::size(executable))) {
                return 0;
            }

            enginefixes::FileVersion version;
            // SE 1.5.97 and VR 1.4.15 both leave the numeric
            // VS_FIXEDFILEINFO file/product fields at 1.0.0.0. Select every
            // supported runtime consistently from the translated
            // StringFileInfo ProductVersion string instead.
            if (!ReadProductVersion(executable, version))
                return 0;
            return ((static_cast<std::uint32_t>(version.major) & 0xFFu) << 24) |
                   ((static_cast<std::uint32_t>(version.minor) & 0xFFu) << 16) |
                   ((static_cast<std::uint32_t>(version.build) & 0xFFFu) << 4) |
                   (static_cast<std::uint32_t>(version.revision) & 0xFu);
        }

        [[nodiscard]] bool FindText(RuntimeContext& a_context) noexcept
        {
            a_context.imageBase = reinterpret_cast<std::uintptr_t>(
                GetModuleHandleW(nullptr));
            if (!a_context.imageBase)
                return false;
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(
                a_context.imageBase);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
                a_context.imageBase + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;
            auto* section = IMAGE_FIRST_SECTION(nt);
            for (WORD index = 0;
                 index < nt->FileHeader.NumberOfSections; ++index) {
                // Skyrim's handle code is in its first .text section. The
                // second .text section is a small stub with no handle code.
                if (std::memcmp(section[index].Name, ".text", 5) == 0) {
                    a_context.text.begin = reinterpret_cast<std::uint8_t*>(
                        a_context.imageBase + section[index].VirtualAddress);
                    a_context.text.size = section[index].Misc.VirtualSize;
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] RuntimeOffsets OffsetsForRuntime(
            std::uint32_t a_runtimeVersion) noexcept
        {
            switch (a_runtimeVersion) {
            case kRuntimeSE: return { 0x002961F0u, 0x001329D0u };
            case kRuntimeAE: return { 0x002EA340u, 0x00179710u };
            case kRuntimeGOG: return { 0x002EA170u, 0x00179540u };
            case kRuntimeVR: return { 0x002A78F0u, 0x00143180u };
            default: return {};
            }
        }

        [[nodiscard]] bool LogDetectedEngineFixes(
            const wchar_t* a_dllName) noexcept
        {
            const HMODULE module = GetModuleHandleW(a_dllName);
            wchar_t installedPath[MAX_PATH * 2]{};
            const bool pathBuilt = BuildPluginPath(
                installedPath, std::size(installedPath), a_dllName);
            const DWORD attributes = pathBuilt ?
                GetFileAttributesW(installedPath) : INVALID_FILE_ATTRIBUTES;
            const bool filePresent = attributes != INVALID_FILE_ATTRIBUTES &&
                (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
            if (!module && !filePresent)
                return false;

            wchar_t loadedPath[32768]{};
            const wchar_t* versionPath = nullptr;
            if (module && GetLoadedModulePath(
                    module, loadedPath, std::size(loadedPath))) {
                versionPath = loadedPath;
            } else if (filePresent) {
                versionPath = installedPath;
            }

            enginefixes::FileVersion fileVersion;
            if (versionPath &&
                ReadFixedFileVersion(versionPath, fileVersion)) {
                Log("Engine Fixes detected: %ls FileVersion %u.%u.%u.%u at "
                    "%ls%s.", a_dllName,
                    static_cast<unsigned>(fileVersion.major),
                    static_cast<unsigned>(fileVersion.minor),
                    static_cast<unsigned>(fileVersion.build),
                    static_cast<unsigned>(fileVersion.revision), versionPath,
                    module ? " (loaded)" :
                        " (installed, not currently loaded)");
            } else {
                Log("Engine Fixes detected: %ls%s; version metadata is unavailable.",
                    a_dllName, module ? " (loaded)" :
                        " (installed, not currently loaded)");
            }
            return true;
        }
    }

    bool DetectRuntime(RuntimeContext& a_context) noexcept
    {
        a_context = {};
        const bool foundText = FindText(a_context);
        a_context.runtimeVersion = RuntimeVersion();
        for (std::uint32_t index = 0; index < kProfileCount; ++index) {
            if (kProfiles[index]->runtimeVersion ==
                a_context.runtimeVersion) {
                a_context.profile = kProfiles[index];
                break;
            }
        }
        a_context.offsets = OffsetsForRuntime(a_context.runtimeVersion);
        return foundText;
    }

    void LogEngineFixesCompatibility() noexcept
    {
        const bool canonical = LogDetectedEngineFixes(L"EngineFixes.dll");
        const bool legacyVr = LogDetectedEngineFixes(L"EngineFixesVR.dll");
        if (!canonical && !legacyVr)
            return;

        Log("");
        Log("  WARNING: Engine Fixes pointer-handle logging may read Skyrim's");
        Log("  abandoned vanilla 1,048,576-entry table after this plugin relocates");
        Log("  the live table. Its displayed handle count may therefore be stale.");
        Log("  Configuration format, missing configuration, and bRefHandleLimit");
        Log("  never gate this plugin. Continuing with exact-code safety checks.");
        Log("  Same-code detours require a separate authenticated allowlist;");
        Log("  unknown Engine Fixes versions, forks, and hook chains fail closed.");
        Log("  Use SkyrimHandleCapRaise.log for the live 2,097,152-entry usage count.");
        Log("");
    }
}
