// Skyrim Handle Cap Raise -- SKSE plugin.
//
// Raises Skyrim's reference pointer-handle ceiling from 1,048,576 (2^20) to
// 4,194,304 (2^22), moves the table-side age and in-use fields up to match,
// and relocates the engine's static 16 MB table to a 64 MB allocation.
//
// HOW THE 22ND INDEX BIT FITS (see RE_FINDINGS.md for the evidence):
//   * BSHandleRefObject::_refCount at object+0x28 packs [9:0] reference count,
//     [10] handle-valid, [31:11] handle index. That index field is already 21
//     bits wide. The low 21 bits remain mirrored there for compatibility. The
//     full 22-bit index is stored in NiRefObject's unused padding dword at
//     object+0x2C. The 10-bit reference count and bit-10 validity ABI do not move.
//   * The handle's own bits 29..31 remain unused, so age keeps its full 6 bits.
//     Stale-handle detection depth is UNCHANGED at 64 generations. (Starfield's
//     equivalent raise had to spend generation bits; Skyrim's does not.)
//   * Handles are runtime-only; Skyrim saves reference objects by FormID. The
//     save format is untouched.
//
// WHY THE CAP RAISE IS A CODE PATCH AND NOT A FIELD WRITE:
//   Skyrim's BSPointerHandleManager is a template whose capacity is a compile
//   time constant, and its lookup/alloc/release bodies are inlined across the
//   engine. There is no runtime field to rewrite. Every replacement is the
//   same length, so the cap change itself remains an in-place edit. The optional
//   generation-wrap diagnostic separately redirects five exact, byte-verified
//   successful-assignment calls through one relay. A collision there disables
//   only that diagnostic and leaves the already-verified cap change operational.
//
// SAFETY: the patch set is generated offline by an exhaustive scan
// (probes/gen_patchtable.py) and shipped with the full stock bytes of every
// instruction. Nothing is written until every byte matches, the live table is
// proven exactly pristine, and every table reference is accounted for. Writes
// are verified transactionally and rolled back on failure; inability to prove
// a safe rollback terminates the process before a save can be made, because a
// partial encoding can resolve a handle to the WRONG object silently.

#include <windows.h>
#include <shlobj.h>

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <io.h>
#include <new>
#include <share.h>
#include <sys/stat.h>

#include "EngineFixesConfig.h"
#include "GenerationTracker.h"
#include "PatchTable.g.h"
#include "StressTest.h"

namespace shcr
{
    // ---------------------------------------------------------------------
    // logging
    // ---------------------------------------------------------------------

    namespace
    {
        FILE*   g_log = nullptr;
        SRWLOCK g_logLock = SRWLOCK_INIT;

        uint32_t RuntimeVersion();

        void OpenSharedLogFile(const wchar_t* path)
        {
            int descriptor = -1;
            if (_wsopen_s(&descriptor, path,
                    _O_WRONLY | _O_CREAT | _O_TRUNC | _O_TEXT,
                    _SH_DENYWR, _S_IREAD | _S_IWRITE) != 0 || descriptor < 0) {
                return;
            }
            g_log = _fdopen(descriptor, "w");
            if (!g_log)
                _close(descriptor);
        }

        void OpenLog()
        {
            PWSTR docs = nullptr;
            wchar_t path[MAX_PATH * 2]{};
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &docs))) {
                const uint32_t runtime = RuntimeVersion();
                const wchar_t* gameFolder = runtime == 0x010400F0u ? L"Skyrim VR" :
                    runtime == 0x010649B0u ? L"Skyrim Special Edition GOG" :
                    L"Skyrim Special Edition";
                swprintf_s(path, L"%s\\My Games\\%s\\SKSE", docs, gameFolder);
                CoTaskMemFree(docs);
                CreateDirectoryW(path, nullptr);
                wcscat_s(path, L"\\SkyrimHandleCapRaise.log");
                OpenSharedLogFile(path);
            }
            if (!g_log) {
                const DWORD n = GetTempPathW(static_cast<DWORD>(std::size(path)), path);
                if (n != 0 && n < std::size(path)) {
                    wcscat_s(path, L"SkyrimHandleCapRaise.log");
                    OpenSharedLogFile(path);
                }
            }
        }

        void Log(const char* fmt, ...)
        {
            if (!g_log)
                return;
            AcquireSRWLockExclusive(&g_logLock);
            va_list ap;
            va_start(ap, fmt);
            vfprintf(g_log, fmt, ap);
            va_end(ap);
            fputc('\n', g_log);
            fflush(g_log);
            ReleaseSRWLockExclusive(&g_logLock);
        }
    }

    // ---------------------------------------------------------------------
    // configuration
    // ---------------------------------------------------------------------

    struct Settings
    {
        bool generationWrapDetection = true;
        stress::Settings stress;
    };

    namespace
    {
        Settings g_set;
        bool     g_raiseSucceeded = false;
        void*    g_raisedTable = nullptr;
        uint32_t g_raisedEntryCount = 0;

        void PluginsDir(wchar_t* out, size_t n)
        {
            GetModuleFileNameW(nullptr, out, static_cast<DWORD>(n));
            if (wchar_t* slash = wcsrchr(out, L'\\'))
                *(slash + 1) = 0;
            wcscat_s(out, n, L"Data\\SKSE\\Plugins\\");
        }

        void LoadSettings()
        {
            wchar_t ini[MAX_PATH * 2]{};
            PluginsDir(ini, MAX_PATH * 2);
            wcscat_s(ini, L"SkyrimHandleCapRaise.ini");
            g_set.generationWrapDetection =
                GetPrivateProfileIntW(
                    L"General", L"GenerationWrapDetection", 1, ini) != 0;
            g_set.stress.liveDiagnosticsEnabled =
                GetPrivateProfileIntW(L"General", L"VerboseLogging", 0, ini) != 0;
            const int configuredSampleSize = static_cast<int>(
                GetPrivateProfileIntW(L"General", L"SampleSize", 16, ini));
            g_set.stress.diagnosticsDetailedSampleLimit = static_cast<uint32_t>(
                (std::clamp)(configuredSampleSize, 0, 4096));
            g_set.stress.enabled =
                GetPrivateProfileIntW(L"StressTest", L"Enabled", 0, ini) != 0;
            g_set.stress.indexBits = 22;
            g_set.stress.syntheticFillToIndex = static_cast<uint32_t>(
                GetPrivateProfileIntW(L"StressTest", L"SyntheticFillToIndex", 0, ini));
            g_set.stress.detailedLogFromIndex = static_cast<uint32_t>(
                GetPrivateProfileIntW(L"StressTest", L"DetailedLogFromIndex", 0x100000, ini));
            g_set.stress.maxDetailedLogs = static_cast<uint32_t>(
                GetPrivateProfileIntW(L"StressTest", L"MaxDetailedLogs", 0x400000, ini));
            g_set.stress.maxReferencesPerTask = static_cast<uint32_t>(
                GetPrivateProfileIntW(L"StressTest", L"ReferencesPerTask", 4096, ini));
            g_set.stress.maxTaskMicroseconds = static_cast<uint32_t>(
                GetPrivateProfileIntW(L"StressTest", L"TaskBudgetMicroseconds", 4000, ini));
            g_set.stress.coordinatorDelayMilliseconds = static_cast<uint32_t>(
                GetPrivateProfileIntW(L"StressTest", L"DelayMilliseconds", 16, ini));
            g_set.stress.verifySecondPass =
                GetPrivateProfileIntW(L"StressTest", L"VerifySecondPass", 1, ini) != 0;
            g_set.stress.releaseProbeCount = static_cast<uint32_t>(
                GetPrivateProfileIntW(L"StressTest", L"ReleaseProbeCount", 0, ini));
            g_set.stress.reuseProbeCycles = static_cast<uint32_t>(
                GetPrivateProfileIntW(L"StressTest", L"ReuseProbeCycles", 0, ini));
            g_set.stress.churnCycles = static_cast<uint32_t>(
                GetPrivateProfileIntW(L"StressTest", L"ChurnCycles", 0, ini));
            g_set.stress.stopOnVerificationFailure =
                GetPrivateProfileIntW(L"StressTest", L"StopOnVerificationFailure", 1, ini) != 0;
        }

        [[nodiscard]] bool BuildPluginPath(
            wchar_t* out, std::size_t count, const wchar_t* name)
        {
            PluginsDir(out, count);
            return out[0] != L'\0' && wcscat_s(out, count, name) == 0;
        }

        [[nodiscard]] bool LoadVersionResource(
            const wchar_t* path, void*& data) noexcept
        {
            data = nullptr;
            DWORD ignored = 0;
            const DWORD size = GetFileVersionInfoSizeW(path, &ignored);
            if (size == 0)
                return false;

            data = malloc(size);
            if (!data)
                return false;
            if (!GetFileVersionInfoW(path, 0, size, data)) {
                free(data);
                data = nullptr;
                return false;
            }
            return true;
        }

        [[nodiscard]] bool ReadFixedFileVersion(
            const wchar_t* path, enginefixes::FileVersion& version) noexcept
        {
            version = {};
            void* data = nullptr;
            if (!LoadVersionResource(path, data))
                return false;

            bool succeeded = false;
            VS_FIXEDFILEINFO* fixed = nullptr;
            UINT fixedSize = 0;
            if (VerQueryValueW(data, L"\\", reinterpret_cast<void**>(&fixed),
                    &fixedSize) &&
                fixed && fixedSize >= sizeof(VS_FIXEDFILEINFO) &&
                fixed->dwSignature == VS_FFI_SIGNATURE) {
                version = {
                    HIWORD(fixed->dwFileVersionMS),
                    LOWORD(fixed->dwFileVersionMS),
                    HIWORD(fixed->dwFileVersionLS),
                    LOWORD(fixed->dwFileVersionLS)
                };
                succeeded = true;
            }
            free(data);
            return succeeded;
        }

        [[nodiscard]] bool ReadProductVersion(
            const wchar_t* path, enginefixes::FileVersion& version) noexcept
        {
            version = {};
            void* data = nullptr;
            if (!LoadVersionResource(path, data))
                return false;

            void* rawTranslations = nullptr;
            UINT translationBytes = 0;
            bool found = false;
            bool valid = VerQueryValueW(data, L"\\VarFileInfo\\Translation",
                &rawTranslations, &translationBytes) && rawTranslations &&
                translationBytes != 0 &&
                translationBytes % (sizeof(WORD) * 2u) == 0;

            const auto* translations = static_cast<const unsigned char*>(rawTranslations);
            for (UINT offset = 0; valid && offset < translationBytes;
                 offset += sizeof(WORD) * 2u) {
                WORD language = 0;
                WORD codePage = 0;
                memcpy(&language, translations + offset, sizeof(language));
                memcpy(&codePage, translations + offset + sizeof(language),
                    sizeof(codePage));

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
                if (!VerQueryValueW(data, query, reinterpret_cast<void**>(&text),
                        &textCharacters)) {
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
                    (version.major != parsed.major || version.minor != parsed.minor ||
                     version.build != parsed.build ||
                     version.revision != parsed.revision)) {
                    valid = false;
                    break;
                }
                version = parsed;
                found = true;
            }

            free(data);
            if (!valid || !found) {
                version = {};
                return false;
            }
            return true;
        }

        [[nodiscard]] bool GetLoadedModulePath(
            HMODULE module, wchar_t* path, std::size_t count) noexcept
        {
            if (!module || !path || count == 0 || count > MAXDWORD)
                return false;
            const DWORD length = GetModuleFileNameW(
                module, path, static_cast<DWORD>(count));
            if (length == 0 || length >= count) {
                path[0] = L'\0';
                return false;
            }
            return true;
        }

        [[nodiscard]] bool LogDetectedEngineFixes(const wchar_t* dllName)
        {
            const HMODULE module = GetModuleHandleW(dllName);
            wchar_t installedPath[MAX_PATH * 2]{};
            const bool pathBuilt = BuildPluginPath(
                installedPath, std::size(installedPath), dllName);
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
            if (versionPath && ReadFixedFileVersion(versionPath, fileVersion)) {
                Log("Engine Fixes detected: %ls FileVersion %u.%u.%u.%u at %ls%s.",
                    dllName,
                    static_cast<unsigned>(fileVersion.major),
                    static_cast<unsigned>(fileVersion.minor),
                    static_cast<unsigned>(fileVersion.build),
                    static_cast<unsigned>(fileVersion.revision), versionPath,
                    module ? " (loaded)" : " (installed, not currently loaded)");
            } else {
                Log("Engine Fixes detected: %ls%s; version metadata is unavailable.",
                    dllName, module ? " (loaded)" : " (installed, not currently loaded)");
            }
            return true;
        }

        // Engine Fixes compatibility is deliberately informational. Some builds
        // read the abandoned vanilla table for bRefHandleLimit and consequently
        // report a stale value after relocation, but neither their version nor
        // their configuration is grounds for blocking the cap raise. A build
        // that actually patches the same Skyrim instructions is still caught by
        // the exact stock-byte verification performed immediately afterwards.
        void LogEngineFixesCompatibility()
        {
            const bool canonical = LogDetectedEngineFixes(L"EngineFixes.dll");
            const bool legacyVr = LogDetectedEngineFixes(L"EngineFixesVR.dll");
            if (!canonical && !legacyVr)
                return;

            Log("");
            Log("  WARNING: Engine Fixes pointer-handle logging may read Skyrim's");
            Log("  abandoned vanilla 1,048,576-entry table after this plugin relocates");
            Log("  the live table. Its displayed handle count may therefore be stale.");
            Log("  Every Engine Fixes version, DLL-name variant, configuration format,");
            Log("  missing configuration, and bRefHandleLimit value is allowed here.");
            Log("  Continuing with the normal Skyrim profile and exact-byte safety checks.");
            Log("  Use SkyrimHandleCapRaise.log for the live 4,194,304-entry usage count.");
            Log("");
        }
    }

    // ---------------------------------------------------------------------
    // image helpers
    // ---------------------------------------------------------------------

    struct TextRange
    {
        uint8_t* begin = nullptr;
        size_t   size = 0;
    };

    namespace
    {
        uintptr_t g_base = 0;
        TextRange g_text;
        uint32_t  g_runtimeVersion = 0;

        bool FindText()
        {
            g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
            if (!g_base)
                return false;
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(g_base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(g_base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;
            auto* sec = IMAGE_FIRST_SECTION(nt);
            // The engine's code lives in the FIRST .text section; the second one
            // Skyrim carries is a tiny 6 KB stub with no handle code.
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                if (memcmp(sec[i].Name, ".text", 5) == 0) {
                    g_text.begin = reinterpret_cast<uint8_t*>(g_base + sec[i].VirtualAddress);
                    g_text.size = sec[i].Misc.VirtualSize;
                    return true;
                }
            }
            return false;
        }

        uint32_t RuntimeVersion()
        {
            wchar_t exe[MAX_PATH]{};
            if (!GetLoadedModulePath(GetModuleHandleW(nullptr), exe, std::size(exe)))
                return 0;
            enginefixes::FileVersion version;
            // Bethesda leaves SkyrimSE.exe's fixed numeric versions at
            // 1.0.0.0 in SE; the actual runtime build is the ProductVersion
            // string (including 1.5.97.0, 1.6.1170.0, GOG 1.6.1179.0,
            // and Skyrim VR 1.4.15.0).
            if (!ReadProductVersion(exe, version))
                return 0;
            return ((static_cast<uint32_t>(version.major) & 0xFFu) << 24) |
                   ((static_cast<uint32_t>(version.minor) & 0xFFu) << 16) |
                   ((static_cast<uint32_t>(version.build) & 0xFFFu) << 4) |
                   (static_cast<uint32_t>(version.revision) & 0xFu);
        }
    }

    // ---------------------------------------------------------------------
    // stress-test form attribution (main thread only)
    // ---------------------------------------------------------------------

    namespace
    {
        struct RawStaticArray
        {
            void**   data;
            uint32_t size;
            uint32_t pad0C;
        };
        static_assert(sizeof(RawStaticArray) == 0x10);

        template <size_t N>
        void CopyGameText(char (&out)[N], const char* source, size_t sourceLimit = N - 1)
        {
            if (!source) {
                out[0] = '\0';
                return;
            }
            const size_t n = strnlen_s(source, (std::min)(sourceLimit, N - 1));
            memcpy(out, source, n);
            out[n] = '\0';
        }

        template <size_t N>
        void CopyPluginName(char (&out)[N], const void* file)
        {
            if (!file) {
                out[0] = '\0';
                return;
            }
            CopyGameText(out, static_cast<const char*>(file) + 0x58, 260);
        }

        template <size_t A, size_t B>
        bool ResolvePlugins(const void* form, char (&origin)[A], char (&winner)[B])
        {
            if (!form)
                return false;
            const auto* bytes = static_cast<const uint8_t*>(form);
            const auto* files = *reinterpret_cast<RawStaticArray* const*>(bytes + 0x08);
            if (!files || !files->data || files->size == 0 || files->size > 0x1000)
                return false;
            CopyPluginName(origin, files->data[0]);
            CopyPluginName(winner, files->data[files->size - 1]);
            return origin[0] != '\0' || winner[0] != '\0';
        }

        template <size_t N>
        void ResolveEditorID(const void* form, char (&out)[N])
        {
            if (!form)
                return;
            auto** vtable = *reinterpret_cast<void***>(const_cast<void*>(form));
            if (!vtable)
                return;
            using Fn = const char* (__fastcall*)(const void*);
            const auto fn = reinterpret_cast<Fn>(vtable[0x32]);
            if (fn)
                CopyGameText(out, fn(form));
        }

        template <size_t N>
        void ResolveDetailedName(void* form, char (&out)[N])
        {
            if (!form)
                return;
            auto** vtable = *reinterpret_cast<void***>(form);
            if (!vtable)
                return;
            using Fn = void (__fastcall*)(void*, char*, uint32_t);
            const auto fn = reinterpret_cast<Fn>(vtable[0x16]);
            if (fn)
                fn(form, out, static_cast<uint32_t>(N));
            out[N - 1] = '\0';
        }

        bool ResolveStressAttribution(
            void*, const void* reference, stress::ResolvedNames& names)
        {
            if (!reference)
                return false;
            bool attributed =
                ResolvePlugins(reference, names.originPlugin, names.winningPlugin);
            const uint32_t refFormID = *reinterpret_cast<const uint32_t*>(
                static_cast<const uint8_t*>(reference) + 0x14);
            if (names.originPlugin[0] == '\0' && (refFormID >> 24) == 0xFF) {
                CopyGameText(names.originPlugin, "<dynamic>");
                attributed = true;
            }

            const void* base = *reinterpret_cast<void* const*>(
                static_cast<const uint8_t*>(reference) + 0x40);
            if (base) {
                names.baseFormID = *reinterpret_cast<const uint32_t*>(
                    static_cast<const uint8_t*>(base) + 0x14);
                attributed =
                    ResolvePlugins(base, names.baseOriginPlugin, names.baseWinningPlugin) ||
                    attributed;
                if (names.baseOriginPlugin[0] == '\0' &&
                    (names.baseFormID >> 24) == 0xFF) {
                    CopyGameText(names.baseOriginPlugin, "<dynamic>");
                    attributed = true;
                }
            }
            return attributed;
        }

        bool ResolveStressNames(void* context, const void* reference, stress::ResolvedNames& names)
        {
            if (!reference)
                return false;
            const bool attributed = ResolveStressAttribution(context, reference, names);
            auto* ref = const_cast<void*>(reference);
            ResolveDetailedName(ref, names.formName);
            ResolveEditorID(reference, names.editorID);

            uint32_t displayRva = 0;
            switch (g_runtimeVersion) {
            case 0x01050610u: displayRva = 0x002961F0u; break;  // SE, ID 19354
            case 0x01064920u: displayRva = 0x002EA340u; break;  // AE, ID 19781
            case 0x010649B0u: displayRva = 0x002EA170u; break;  // GOG, ID 19781
            case 0x010400F0u: displayRva = 0x002A78F0u; break;  // VR, ID 19354
            default: return false;
            }
            using DisplayNameFn = const char* (__fastcall*)(void*);
            const auto display = reinterpret_cast<DisplayNameFn>(g_base + displayRva);
            CopyGameText(names.displayName, display(ref));

            void* base = *reinterpret_cast<void**>(static_cast<uint8_t*>(ref) + 0x40);
            if (base) {
                ResolveDetailedName(base, names.baseName);
                ResolveEditorID(base, names.baseEditorID);
            }
            const bool hasIdentity = names.formName[0] != '\0' || names.editorID[0] != '\0' ||
                names.displayName[0] != '\0' || names.baseName[0] != '\0' ||
                names.baseEditorID[0] != '\0';
            return attributed && hasIdentity;
        }

        void StressLog(void*, const char* message)
        {
            Log("%s", message ? message : "");
        }
    }

    // ---------------------------------------------------------------------
    // handle table types
    // ---------------------------------------------------------------------

#pragma pack(push, 1)
    struct HandleEntry
    {
        uint32_t bits;  // [next index] [age] [in-use]
        uint32_t pad;
        void*    pointer;
    };
#pragma pack(pop)
    static_assert(sizeof(HandleEntry) == 0x10, "handle entry must be 16 bytes");

    // ---------------------------------------------------------------------
    // verification
    // ---------------------------------------------------------------------

    namespace
    {
        // Count dword positions in .text that encode a RIP-relative disp32 to
        // `targetRva`. Decoder independent, so it cannot miss a reference; the
        // count is compared against the shipped table as a completeness check
        // on THIS binary rather than on the one the table was generated from.
        size_t CountDispRefs(uintptr_t target)
        {
            size_t n = 0;
            const uint8_t* p = g_text.begin;
            if (g_text.size < 4)
                return 0;
            const size_t limit = g_text.size - 4;
            for (size_t i = 0; i <= limit; ++i) {
                int32_t disp;
                memcpy(&disp, p + i, 4);
                const uintptr_t end = reinterpret_cast<uintptr_t>(p + i + 4);
                if (static_cast<uintptr_t>(static_cast<int64_t>(end) + disp) == target)
                    ++n;
            }
            return n;
        }

        void LogByteMismatch(
            const char* kind, uint32_t rva, const uint8_t* want, const uint8_t* got,
            size_t mismatchNumber)
        {
            if (mismatchNumber < 8) {
                Log("  MISMATCH %s at rva %08x: expected first byte %02x, found %02x",
                    kind, rva, want[0], got[0]);
            }
        }

        bool VerifyStockCode(const Profile& pf, size_t& mismatches)
        {
            mismatches = 0;
            for (uint32_t i = 0; i < pf.fieldCount; ++i) {
                const FieldPatch& f = pf.fields[i];
                const auto* at = reinterpret_cast<const uint8_t*>(g_base + f.rva);
                if (f.len == 0 || f.len > sizeof(f.orig) || f.fieldW == 0 ||
                    f.fieldOff + f.fieldW > f.len || memcmp(at, f.orig, f.len) != 0) {
                    LogByteMismatch(CategoryName(f.cat), f.rva, f.orig, at, mismatches);
                    ++mismatches;
                }
            }
            for (uint32_t i = 0; i < pf.bytePatchCount; ++i) {
                const BytePatch& p = pf.bytePatches[i];
                const auto* at = reinterpret_cast<const uint8_t*>(g_base + p.rva);
                if (p.len == 0 || p.len > sizeof(p.orig) || memcmp(at, p.orig, p.len) != 0) {
                    LogByteMismatch(CategoryName(p.cat), p.rva, p.orig, at, mismatches);
                    ++mismatches;
                }
            }
            for (uint32_t i = 0; i < pf.tableRefCount; ++i) {
                const TableRef& r = pf.tableRefs[i];
                const auto* at = reinterpret_cast<const uint8_t*>(g_base + r.rva);
                bool bad = r.len == 0 || r.len > sizeof(r.orig) ||
                    r.dispOff + sizeof(int32_t) != r.len || memcmp(at, r.orig, r.len) != 0;
                if (!bad) {
                    int32_t disp = 0;
                    memcpy(&disp, at + r.dispOff, sizeof(disp));
                    const uintptr_t target = static_cast<uintptr_t>(
                        static_cast<int64_t>(g_base + r.rva + r.len) + disp);
                    bad = target != g_base + pf.tableRva;
                }
                if (bad) {
                    LogByteMismatch("table reference", r.rva, r.orig, at, mismatches);
                    ++mismatches;
                }
            }
            for (uint32_t i = 0; i < pf.initPatchCount; ++i) {
                const BytePatch& p = pf.initPatches[i];
                const auto* at = reinterpret_cast<const uint8_t*>(g_base + p.rva);
                if (p.len == 0 || p.len > sizeof(p.orig) || memcmp(at, p.orig, p.len) != 0) {
                    LogByteMismatch("initialiser guard", p.rva, p.orig, at, mismatches);
                    ++mismatches;
                }
            }
            for (uint32_t i = 0; i < pf.releaseSiteCount; ++i) {
                const ExactSite& s = pf.releaseSites[i];
                const auto* at = reinterpret_cast<const uint8_t*>(g_base + s.rva);
                if (s.len == 0 || s.len > sizeof(s.orig) || memcmp(at, s.orig, s.len) != 0) {
                    LogByteMismatch("sidecar release gate", s.rva, s.orig, at, mismatches);
                    ++mismatches;
                }
            }
            return mismatches == 0;
        }

        bool VerifyPatchedCode(
            const Profile& pf, uintptr_t table, bool patchedInitPatches, size_t& mismatches)
        {
            mismatches = 0;
            uint8_t want[15]{};
            for (uint32_t i = 0; i < pf.fieldCount; ++i) {
                const FieldPatch& f = pf.fields[i];
                memcpy(want, f.orig, f.len);
                if (f.fieldW == 4)
                    memcpy(want + f.fieldOff, &f.newVal, sizeof(f.newVal));
                else
                    want[f.fieldOff] = static_cast<uint8_t>(f.newVal);
                const auto* at = reinterpret_cast<const uint8_t*>(g_base + f.rva);
                if (memcmp(at, want, f.len) != 0) {
                    LogByteMismatch(CategoryName(f.cat), f.rva, want, at, mismatches);
                    ++mismatches;
                }
            }
            for (uint32_t i = 0; i < pf.bytePatchCount; ++i) {
                const BytePatch& p = pf.bytePatches[i];
                const auto* at = reinterpret_cast<const uint8_t*>(g_base + p.rva);
                if (memcmp(at, p.repl, p.len) != 0) {
                    LogByteMismatch(CategoryName(p.cat), p.rva, p.repl, at, mismatches);
                    ++mismatches;
                }
            }
            for (uint32_t i = 0; i < pf.tableRefCount; ++i) {
                const TableRef& r = pf.tableRefs[i];
                memcpy(want, r.orig, r.len);
                const int64_t delta = static_cast<int64_t>(table) -
                    static_cast<int64_t>(g_base + r.rva + r.len);
                const int32_t disp = static_cast<int32_t>(delta);
                memcpy(want + r.dispOff, &disp, sizeof(disp));
                const auto* at = reinterpret_cast<const uint8_t*>(g_base + r.rva);
                if (memcmp(at, want, r.len) != 0) {
                    LogByteMismatch("table reference", r.rva, want, at, mismatches);
                    ++mismatches;
                }
            }
            for (uint32_t i = 0; i < pf.initPatchCount; ++i) {
                const BytePatch& p = pf.initPatches[i];
                const uint8_t* wantPatch = patchedInitPatches ? p.repl : p.orig;
                const auto* at = reinterpret_cast<const uint8_t*>(g_base + p.rva);
                if (memcmp(at, wantPatch, p.len) != 0) {
                    LogByteMismatch("initialiser guard", p.rva, wantPatch, at, mismatches);
                    ++mismatches;
                }
            }
            // releaseSites are independently enumerated stock fingerprints.
            // Their bytes sit inside kCat_sidecar_release BytePatches and are
            // therefore already checked against the full replacement above.
            return mismatches == 0;
        }

        // The encoding change invalidates every handle already handed out, so
        // the pool must be byte-for-byte pristine. Two states are acceptable:
        // the zero-filled image before its initializer, or the exact stock
        // free-list chain after initialization. Merely observing no in-use bits
        // is insufficient: a used-and-released pool can retain age bits.
        bool VerifyPristine(const Profile& pf, bool& initAlreadyRan)
        {
            const uint32_t head = *reinterpret_cast<uint32_t*>(g_base + pf.headRva);
            const uint32_t tail = *reinterpret_cast<uint32_t*>(g_base + pf.tailRva);
            const uint32_t stockTail = pf.stockEntries - 1;

            auto* table = reinterpret_cast<HandleEntry*>(g_base + pf.tableRva);

            const bool zeroState = head == 0 && tail == 0;
            const bool stockState = head == 0 && tail == stockTail;
            if (!zeroState && !stockState) {
                Log("  pool is not pristine: head=%08x tail=%08x (expected 0/0 or 0/%08x)",
                    head, tail, stockTail);
                return false;
            }

            size_t bad = 0;
            for (uint32_t i = 0; i < pf.stockEntries; ++i) {
                const uint32_t wantBits = zeroState ? 0u :
                    (i + 1 < pf.stockEntries ? i + 1 : i);
                if (table[i].bits != wantBits || table[i].pad != 0 || table[i].pointer != nullptr) {
                    if (bad < 8) {
                        Log("  entry %u is not pristine: bits=%08x (want %08x), pad=%08x, "
                            "pointer=%p", i, table[i].bits, wantBits, table[i].pad,
                            table[i].pointer);
                    }
                    ++bad;
                }
            }
            if (bad) {
                Log("  refusing to patch: %zu stock-table entries differ from the exact %s state",
                    bad, zeroState ? "zero-filled" : "initial free-list");
                return false;
            }
            initAlreadyRan = stockState;
            return true;
        }
    }

    // ---------------------------------------------------------------------
    // allocation
    // ---------------------------------------------------------------------

    namespace
    {
        // Every table reference is a 32-bit RIP-relative displacement, so the
        // new table must sit within +/-2 GB of all of them. Allocating just
        // above the image keeps the displacements small and well inside range.
        uint8_t* AllocTableNear(size_t bytes)
        {
            for (uintptr_t off = 0x10000000; off <= 0x40000000; off += 0x04000000) {
                if (auto* p = static_cast<uint8_t*>(VirtualAlloc(
                        reinterpret_cast<void*>(g_base + off), bytes,
                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
                    return p;
            }
            // Fall back to letting the OS choose, then range-check it.
            return static_cast<uint8_t*>(
                VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        }

        bool InDispRange(const Profile& pf, uintptr_t table)
        {
            for (uint32_t i = 0; i < pf.tableRefCount; ++i) {
                const TableRef& r = pf.tableRefs[i];
                const uintptr_t insEnd = g_base + r.rva + r.len;
                const int64_t   delta = static_cast<int64_t>(table) - static_cast<int64_t>(insEnd);
                if (delta < INT32_MIN || delta > INT32_MAX)
                    return false;
            }
            return true;
        }

        void InitializeTable(const Profile& pf, uint8_t* table)
        {
            auto* entries = reinterpret_cast<HandleEntry*>(table);
            const uint32_t last = pf.raisedEntries - 1;
            for (uint32_t i = 0; i < pf.raisedEntries; ++i) {
                entries[i].bits = i < last ? i + 1 : i;
                entries[i].pad = 0;
                entries[i].pointer = nullptr;
            }
        }

        bool VerifyNewTable(const Profile& pf, const uint8_t* table)
        {
            const auto* entries = reinterpret_cast<const HandleEntry*>(table);
            const uint32_t last = pf.raisedEntries - 1;
            for (uint32_t i = 0; i < pf.raisedEntries; ++i) {
                const uint32_t want = i < last ? i + 1 : i;
                if (entries[i].bits != want || entries[i].pad != 0 ||
                    entries[i].pointer != nullptr) {
                    Log("  new-table verification failed at entry %u: bits=%08x "
                        "(want %08x), pad=%08x, pointer=%p", i, entries[i].bits,
                        want, entries[i].pad, entries[i].pointer);
                    return false;
                }
            }
            return true;
        }

        using ManagerLockFn = void (__fastcall*)(void*);

        void LockManager(const Profile& pf)
        {
            const auto fn = reinterpret_cast<ManagerLockFn>(g_base + pf.lockWriteRva);
            fn(reinterpret_cast<void*>(g_base + pf.lockRva));
        }

        void UnlockManager(const Profile& pf)
        {
            const auto fn = reinterpret_cast<ManagerLockFn>(g_base + pf.unlockWriteRva);
            fn(reinterpret_cast<void*>(g_base + pf.lockRva));
        }

        constexpr uint32_t kVanillaHandleEntries = 0x100000;
        constexpr uint32_t kReporterTickMilliseconds = 60u * 1000u;
        constexpr uint32_t kUsageReportIntervalMinutes = 5u;
        constexpr uint32_t kUsageScanEntriesPerLock = 0x10000;
        constexpr size_t   kAssignmentRelayBytes = 14;
        constexpr size_t   kAssignmentRelayAllocationBytes = 0x1000;

        using AssignmentHelperFn = void* (__fastcall*)(void**, void*);
        using GetSmartPointerFn = bool (__fastcall*)(const uint32_t*, void**);
        static_assert(std::atomic<AssignmentHelperFn>::is_always_lock_free);
        static_assert(std::atomic<uint64_t>::is_always_lock_free);

        uint32_t* g_slotAssignments = nullptr;
        uint8_t*  g_assignmentRelay = nullptr;
        const HandleEntry* g_generationTable = nullptr;
        uint32_t g_generationEntryCount = 0;
        std::atomic<AssignmentHelperFn> g_originalAssignmentHelper{ nullptr };
        std::atomic<bool> g_generationDetectorActive{ false };
        std::atomic<uint64_t> g_hottestHandle{ 0 };  // high dword=reuses, low=handle
        std::atomic<uint64_t> g_generationWraps{ 0 };
        std::atomic<uint64_t> g_lastWrapEvent{ 0 };  // high dword=reuses, low=handle
        std::atomic<uint32_t> g_wrapEventSequence{ 0 };
        std::atomic<uint32_t> g_unreliableSlot{ 0 };  // slot+1; UINT32_MAX=unknown

        void MarkGenerationTrackingUnreliable(uint32_t slot) noexcept
        {
            uint32_t unset = 0;
            const uint32_t encoded = slot < generation::kEntryCount ?
                slot + 1u : UINT32_MAX;
            g_unreliableSlot.compare_exchange_strong(
                unset, encoded, std::memory_order_release,
                std::memory_order_relaxed);
        }

        void RecordHandleGeneration(void** destination, void* subobject) noexcept
        {
            if (!destination || !subobject || !g_slotAssignments ||
                !g_generationTable || *destination != subobject) {
                MarkGenerationTrackingUnreliable(UINT32_MAX);
                return;
            }

            const uintptr_t table = reinterpret_cast<uintptr_t>(g_generationTable);
            const uintptr_t firstPointer = table + offsetof(HandleEntry, pointer);
            const uintptr_t destinationAddress =
                reinterpret_cast<uintptr_t>(destination);
            if (destinationAddress < firstPointer) {
                MarkGenerationTrackingUnreliable(UINT32_MAX);
                return;
            }
            const uintptr_t byteOffset = destinationAddress - firstPointer;
            if ((byteOffset % sizeof(HandleEntry)) != 0) {
                MarkGenerationTrackingUnreliable(UINT32_MAX);
                return;
            }
            const uintptr_t wideIndex = byteOffset / sizeof(HandleEntry);
            if (wideIndex >= g_generationEntryCount) {
                MarkGenerationTrackingUnreliable(UINT32_MAX);
                return;
            }

            const uint32_t index = static_cast<uint32_t>(wideIndex);
            const uint32_t bits = g_generationTable[index].bits;
            if ((bits & generation::kInUseMask) == 0) {
                MarkGenerationTrackingUnreliable(index);
                return;
            }

            const uint32_t priorAssignments = g_slotAssignments[index];
            const generation::Transition transition = generation::ObserveAssignment(
                priorAssignments, generation::GenerationFromEntryBits(bits));
            if (transition.saturated) {
                MarkGenerationTrackingUnreliable(index);
                return;
            }
            g_slotAssignments[index] = transition.assignmentCount;
            if (!transition.generationMatches)
                MarkGenerationTrackingUnreliable(index);

            const uint32_t handle = generation::HandleFromEntryBits(index, bits);
            if (transition.reuseCount != 0) {
                const uint64_t candidate =
                    (static_cast<uint64_t>(transition.reuseCount) << 32) | handle;
                uint64_t hottest = g_hottestHandle.load(std::memory_order_relaxed);
                while (transition.reuseCount > static_cast<uint32_t>(hottest >> 32) &&
                       !g_hottestHandle.compare_exchange_weak(
                           hottest, candidate, std::memory_order_release,
                           std::memory_order_relaxed)) {
                }
            }

            if (transition.abaWrap) {
                g_wrapEventSequence.fetch_add(
                    1, std::memory_order_acq_rel);  // odd: writer active
                g_lastWrapEvent.store(
                    (static_cast<uint64_t>(transition.reuseCount) << 32) | handle,
                    std::memory_order_relaxed);
                g_generationWraps.fetch_add(1, std::memory_order_relaxed);
                g_wrapEventSequence.fetch_add(
                    1, std::memory_order_release);  // even: published
            }
        }

        void* __fastcall AssignmentHelperHook(
            void** destination, void* subobject) noexcept
        {
            const AssignmentHelperFn original =
                g_originalAssignmentHelper.load(std::memory_order_acquire);
            if (!original)
                return destination;
            void* const result = original(destination, subobject);
            RecordHandleGeneration(destination, subobject);
            return result;
        }

        bool TextContains(uint32_t rva, size_t bytes) noexcept
        {
            const uintptr_t begin = reinterpret_cast<uintptr_t>(g_text.begin);
            const uintptr_t address = g_base + rva;
            return address >= begin && bytes <= g_text.size &&
                address - begin <= g_text.size - bytes;
        }

        bool VerifyAssignmentHookTargets(const Profile& profile, bool logMismatch)
        {
            if (profile.assignmentHookSiteCount != 5 ||
                !profile.assignmentHookSites ||
                !TextContains(profile.assignmentHelperRva,
                    sizeof(profile.assignmentHelperBytes))) {
                if (logMismatch) {
                    Log("ERROR: generation-wrap detector profile has invalid assignment-hook "
                        "metadata; detector disabled, cap raise continues.");
                }
                return false;
            }
            const auto* helper = reinterpret_cast<const uint8_t*>(
                g_base + profile.assignmentHelperRva);
            if (memcmp(helper, profile.assignmentHelperBytes,
                    sizeof(profile.assignmentHelperBytes)) != 0) {
                if (logMismatch) {
                    Log("ERROR: generation-wrap detector assignment helper at rva %08X "
                        "differs from the verified runtime; detector disabled, cap raise "
                        "continues.", profile.assignmentHelperRva);
                }
                return false;
            }

            for (uint32_t i = 0; i < profile.assignmentHookSiteCount; ++i) {
                const AssignmentHookSite& site = profile.assignmentHookSites[i];
                if (site.callRva < sizeof(site.setupBytes) ||
                    !TextContains(site.functionRva, sizeof(site.functionBytes)) ||
                    !TextContains(
                        site.callRva - static_cast<uint32_t>(sizeof(site.setupBytes)),
                        sizeof(site.setupBytes) + sizeof(site.callBytes))) {
                    if (logMismatch) {
                        Log("ERROR: generation-wrap detector site %u is outside .text; "
                            "detector disabled, cap raise continues.", i);
                    }
                    return false;
                }
                const auto* owner = reinterpret_cast<const uint8_t*>(
                    g_base + site.functionRva);
                const auto* setup = reinterpret_cast<const uint8_t*>(
                    g_base + site.callRva - sizeof(site.setupBytes));
                const auto* call = reinterpret_cast<const uint8_t*>(
                    g_base + site.callRva);
                int32_t displacement = 0;
                if (site.callBytes[0] != 0xE8 || call[0] != 0xE8 ||
                    memcmp(owner, site.functionBytes,
                        sizeof(site.functionBytes)) != 0 ||
                    memcmp(setup, site.setupBytes, sizeof(site.setupBytes)) != 0 ||
                    memcmp(call, site.callBytes, sizeof(site.callBytes)) != 0) {
                    if (logMismatch) {
                        Log("ERROR: generation-wrap detector assignment target %u at rva "
                            "%08X differs from the verified owner/setup/call bytes; detector "
                            "disabled, cap raise continues.", i, site.callRva);
                    }
                    return false;
                }
                memcpy(&displacement, call + 1, sizeof(displacement));
                const uintptr_t target = static_cast<uintptr_t>(
                    static_cast<int64_t>(g_base + site.callRva + 5u) + displacement);
                if (target != g_base + profile.assignmentHelperRva) {
                    if (logMismatch) {
                        Log("ERROR: generation-wrap detector call %u resolves to %016llX, "
                            "not verified helper %016llX; detector disabled, cap raise "
                            "continues.", i,
                            static_cast<unsigned long long>(target),
                            static_cast<unsigned long long>(
                                g_base + profile.assignmentHelperRva));
                    }
                    return false;
                }
            }
            return true;
        }

        bool RelayIsReachable(const Profile& profile, uintptr_t relay) noexcept
        {
            for (uint32_t i = 0; i < profile.assignmentHookSiteCount; ++i) {
                const int64_t displacement = static_cast<int64_t>(relay) -
                    static_cast<int64_t>(
                        g_base + profile.assignmentHookSites[i].callRva + 5u);
                if (displacement < INT32_MIN || displacement > INT32_MAX)
                    return false;
            }
            return true;
        }

        uint8_t* AllocateAssignmentRelay(const Profile& profile)
        {
            for (uintptr_t offset = 0x08000000u; offset <= 0x70000000u;
                 offset += 0x04000000u) {
                auto* relay = static_cast<uint8_t*>(VirtualAlloc(
                    reinterpret_cast<void*>(g_base + offset),
                    kAssignmentRelayAllocationBytes,
                    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
                if (!relay)
                    continue;
                if (RelayIsReachable(profile, reinterpret_cast<uintptr_t>(relay)))
                    return relay;
                VirtualFree(relay, 0, MEM_RELEASE);
            }
            auto* relay = static_cast<uint8_t*>(VirtualAlloc(
                nullptr, kAssignmentRelayAllocationBytes,
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (relay && !RelayIsReachable(
                    profile, reinterpret_cast<uintptr_t>(relay))) {
                VirtualFree(relay, 0, MEM_RELEASE);
                relay = nullptr;
            }
            return relay;
        }

        void ReleasePreparedGenerationDetector() noexcept
        {
            g_generationDetectorActive.store(false, std::memory_order_release);
            g_originalAssignmentHelper.store(nullptr, std::memory_order_release);
            g_generationTable = nullptr;
            g_generationEntryCount = 0;
            if (g_assignmentRelay) {
                VirtualFree(g_assignmentRelay, 0, MEM_RELEASE);
                g_assignmentRelay = nullptr;
            }
            if (g_slotAssignments) {
                VirtualFree(g_slotAssignments, 0, MEM_RELEASE);
                g_slotAssignments = nullptr;
            }
        }

        bool PrepareGenerationDetector(
            const Profile& profile, const HandleEntry* table)
        {
            if (!g_set.generationWrapDetection)
                return false;
            if (profile.raisedEntries != generation::kEntryCount ||
                profile.entrySize != sizeof(HandleEntry) ||
                !VerifyAssignmentHookTargets(profile, true)) {
                Log("generation-wrap detector disabled; the cap raise remains independent.");
                return false;
            }

            const size_t sidecarBytes =
                static_cast<size_t>(profile.raisedEntries) * sizeof(uint32_t);
            g_slotAssignments = static_cast<uint32_t*>(VirtualAlloc(
                nullptr, sidecarBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (!g_slotAssignments) {
                Log("ERROR: generation-wrap detector could not allocate its %zu-byte "
                    "sidecar (error %lu); detector disabled, cap raise continues.",
                    sidecarBytes, GetLastError());
                return false;
            }
            g_assignmentRelay = AllocateAssignmentRelay(profile);
            if (!g_assignmentRelay) {
                Log("ERROR: generation-wrap detector could not allocate a rel32-reachable "
                    "relay; detector disabled, cap raise continues.");
                ReleasePreparedGenerationDetector();
                return false;
            }

            uint8_t relay[kAssignmentRelayBytes] = {
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
            };
            const uintptr_t hook =
                reinterpret_cast<uintptr_t>(&AssignmentHelperHook);
            memcpy(relay + 6, &hook, sizeof(hook));
            memcpy(g_assignmentRelay, relay, sizeof(relay));
            DWORD oldProtection = 0;
            if (!VirtualProtect(g_assignmentRelay,
                    kAssignmentRelayAllocationBytes, PAGE_EXECUTE_READ,
                    &oldProtection) ||
                !FlushInstructionCache(
                    GetCurrentProcess(), g_assignmentRelay, sizeof(relay))) {
                Log("ERROR: generation-wrap detector could not publish its relay (error "
                    "%lu); detector disabled, cap raise continues.", GetLastError());
                ReleasePreparedGenerationDetector();
                return false;
            }

            g_generationTable = table;
            g_generationEntryCount = profile.raisedEntries;
            g_hottestHandle.store(0, std::memory_order_relaxed);
            g_generationWraps.store(0, std::memory_order_relaxed);
            g_lastWrapEvent.store(0, std::memory_order_relaxed);
            g_wrapEventSequence.store(0, std::memory_order_relaxed);
            g_unreliableSlot.store(0, std::memory_order_relaxed);
            Log("generation-wrap detector prepared: exact uint32 reuse counters for %u "
                "slots (%zu MiB) and one executable relay page.",
                profile.raisedEntries, sidecarBytes / (1024u * 1024u));
            return true;
        }

        [[noreturn]] void FatalAssignmentHookRollback()
        {
            Log("FATAL: generation-wrap detector could not restore all five original "
                "assignment calls after a diagnostic install failure.");
            Log("Terminating Skyrim because continuing through a partially written call "
                "site is unsafe; the cap-table transaction itself had succeeded.");
            TerminateProcess(GetCurrentProcess(), 0x53484744u);
            ExitProcess(0x44u);
        }

        bool OriginalAssignmentCallsMatch(const Profile& profile) noexcept
        {
            for (uint32_t i = 0; i < profile.assignmentHookSiteCount; ++i) {
                const AssignmentHookSite& site = profile.assignmentHookSites[i];
                if (memcmp(reinterpret_cast<const void*>(g_base + site.callRva),
                        site.callBytes, sizeof(site.callBytes)) != 0) {
                    return false;
                }
            }
            return true;
        }

        void RestoreAssignmentCallsOrStop(const Profile& profile)
        {
            for (uint32_t i = 0; i < profile.assignmentHookSiteCount; ++i) {
                const AssignmentHookSite& site = profile.assignmentHookSites[i];
                memcpy(reinterpret_cast<void*>(g_base + site.callRva),
                    site.callBytes, sizeof(site.callBytes));
            }
            if (!OriginalAssignmentCallsMatch(profile) ||
                !FlushInstructionCache(
                    GetCurrentProcess(), g_text.begin, g_text.size)) {
                FatalAssignmentHookRollback();
            }
        }

        bool InstallGenerationDetector(const Profile& profile)
        {
            if (!g_slotAssignments || !g_assignmentRelay ||
                !VerifyAssignmentHookTargets(profile, true)) {
                return false;
            }

            DWORD oldProtection = 0;
            if (!VirtualProtect(g_text.begin, g_text.size,
                    PAGE_EXECUTE_READWRITE, &oldProtection)) {
                Log("ERROR: generation-wrap detector could not make .text writable "
                    "(error %lu); detector disabled, cap raise remains active.",
                    GetLastError());
                return false;
            }

            const uintptr_t relay = reinterpret_cast<uintptr_t>(g_assignmentRelay);
            for (uint32_t i = 0; i < profile.assignmentHookSiteCount; ++i) {
                const AssignmentHookSite& site = profile.assignmentHookSites[i];
                const int64_t wideDisplacement = static_cast<int64_t>(relay) -
                    static_cast<int64_t>(g_base + site.callRva + 5u);
                const int32_t displacement = static_cast<int32_t>(wideDisplacement);
                uint8_t call[5] = { 0xE8, 0, 0, 0, 0 };
                memcpy(call + 1, &displacement, sizeof(displacement));
                memcpy(reinterpret_cast<void*>(g_base + site.callRva),
                    call, sizeof(call));
            }

            bool callsGood = true;
            for (uint32_t i = 0; i < profile.assignmentHookSiteCount; ++i) {
                const AssignmentHookSite& site = profile.assignmentHookSites[i];
                const auto* call = reinterpret_cast<const uint8_t*>(
                    g_base + site.callRva);
                int32_t displacement = 0;
                memcpy(&displacement, call + 1, sizeof(displacement));
                const uintptr_t target = static_cast<uintptr_t>(
                    static_cast<int64_t>(g_base + site.callRva + 5u) +
                    displacement);
                callsGood = callsGood && call[0] == 0xE8 && target == relay;
            }
            const bool cacheGood = callsGood && FlushInstructionCache(
                GetCurrentProcess(), g_text.begin, g_text.size) != FALSE;
            if (!cacheGood) {
                RestoreAssignmentCallsOrStop(profile);
                DWORD ignored = 0;
                const bool protectionRestored = VirtualProtect(
                    g_text.begin, g_text.size, oldProtection, &ignored) != FALSE;
                Log("ERROR: generation-wrap detector call installation did not verify; "
                    "all stock calls were restored%s. The cap raise remains active.",
                    protectionRestored ? "" :
                        ", but restoring .text page protection also failed");
                return false;
            }

            DWORD ignored = 0;
            if (!VirtualProtect(
                    g_text.begin, g_text.size, oldProtection, &ignored)) {
                RestoreAssignmentCallsOrStop(profile);
                DWORD retryIgnored = 0;
                const bool protectionRestored = VirtualProtect(
                    g_text.begin, g_text.size, oldProtection,
                    &retryIgnored) != FALSE;
                Log("ERROR: generation-wrap detector could not restore .text page "
                    "protection after installing; all stock calls were restored%s. "
                    "The cap raise remains active.",
                    protectionRestored ? "" :
                        ", although .text remains writable/executable");
                return false;
            }

            g_originalAssignmentHelper.store(
                reinterpret_cast<AssignmentHelperFn>(
                    g_base + profile.assignmentHelperRva),
                std::memory_order_release);
            g_generationDetectorActive.store(true, std::memory_order_release);
            Log("generation-wrap detector installed at all %u verified Skyrim "
                "assignment sites: 22 index bits + 6 generation bits = %u-value "
                "reuse threshold.", profile.assignmentHookSiteCount,
                generation::kGenerationCount);
            return true;
        }

        struct GenerationPreparationGuard
        {
            bool keep = false;

            ~GenerationPreparationGuard()
            {
                if (!keep)
                    ReleasePreparedGenerationDetector();
            }
        };

        struct WrapSnapshot
        {
            uint64_t total = 0;
            uint64_t event = 0;
        };

        WrapSnapshot ReadWrapSnapshot() noexcept
        {
            WrapSnapshot snapshot;
            uint32_t before = 0;
            uint32_t after = 0;
            do {
                before = g_wrapEventSequence.load(std::memory_order_acquire);
                if ((before & 1u) != 0)
                    continue;
                snapshot.total =
                    g_generationWraps.load(std::memory_order_relaxed);
                snapshot.event =
                    g_lastWrapEvent.load(std::memory_order_relaxed);
                after = g_wrapEventSequence.load(std::memory_order_acquire);
            } while (before != after || (after & 1u) != 0);
            return snapshot;
        }

        uint32_t GetSmartPointerRva() noexcept
        {
            switch (g_runtimeVersion) {
            case 0x01050610u: return 0x001329D0u;
            case 0x01064920u: return 0x00179710u;
            case 0x010649B0u: return 0x00179540u;
            case 0x010400F0u: return 0x00143180u;
            default: return 0;
            }
        }

        void ReleasePinnedReference(void* reference) noexcept
        {
            if (!reference)
                return;
            auto* word = reinterpret_cast<volatile LONG*>(
                static_cast<uint8_t*>(reference) + 0x28);
            const uint32_t after = static_cast<uint32_t>(
                InterlockedDecrement(word));
            if ((after & 0x3FFu) != 0)
                return;
            auto* subobject = static_cast<uint8_t*>(reference) + 0x20;
            auto** vtable = *reinterpret_cast<void***>(subobject);
            if (vtable && vtable[1]) {
                using DeleteThisFn = void (__fastcall*)(void*);
                reinterpret_cast<DeleteThisFn>(vtable[1])(subobject);
            }
        }

        struct CurrentReferenceSnapshot
        {
            uint32_t reuseCount = 0;
            uint32_t slot = 0;
            uint32_t handle = 0;
            void* expectedReference = nullptr;
            void* pinnedReference = nullptr;
            uint32_t formID = 0;
            uint32_t baseFormID = 0;
            char sourcePlugin[260]{};
            char baseSourcePlugin[260]{};
            bool hasHottest = false;
            bool hasCurrentHandle = false;
            bool resolvedCurrentReference = false;
            bool attributionSkipped = false;
        };

        CurrentReferenceSnapshot CaptureCurrentHottest(
            const Profile& profile, bool skipAttribution)
        {
            CurrentReferenceSnapshot snapshot;
            LockManager(profile);
            const uint64_t hottest =
                g_hottestHandle.load(std::memory_order_acquire);
            snapshot.reuseCount = static_cast<uint32_t>(hottest >> 32);
            if (snapshot.reuseCount != 0) {
                snapshot.hasHottest = true;
                snapshot.slot = static_cast<uint32_t>(hottest) &
                    generation::kIndexMask;
                if (snapshot.slot < g_generationEntryCount &&
                    g_slotAssignments[snapshot.slot] != 0) {
                    snapshot.reuseCount =
                        g_slotAssignments[snapshot.slot] - 1u;
                    const HandleEntry& entry =
                        g_generationTable[snapshot.slot];
                    if ((entry.bits & generation::kInUseMask) != 0 &&
                        entry.pointer) {
                        snapshot.hasCurrentHandle = true;
                        snapshot.handle = generation::HandleFromEntryBits(
                            snapshot.slot, entry.bits);
                        snapshot.expectedReference =
                            static_cast<uint8_t*>(entry.pointer) - 0x20;
                    }
                }
            }
            UnlockManager(profile);

            if (!snapshot.hasCurrentHandle)
                return snapshot;
            if (skipAttribution) {
                snapshot.attributionSkipped = true;
                return snapshot;
            }

            const uint32_t getSmartPointerRva = GetSmartPointerRva();
            if (!getSmartPointerRva)
                return snapshot;
            const auto getSmartPointer = reinterpret_cast<GetSmartPointerFn>(
                g_base + getSmartPointerRva);
            void* reference = nullptr;
            const bool resolved = getSmartPointer(&snapshot.handle, &reference);
            if (resolved && reference &&
                reference == snapshot.expectedReference) {
                snapshot.resolvedCurrentReference = true;
                snapshot.pinnedReference = reference;
                snapshot.formID = *reinterpret_cast<const uint32_t*>(
                    static_cast<const uint8_t*>(reference) + 0x14);
                stress::ResolvedNames names;
                ResolveStressAttribution(nullptr, reference, names);
                const char* source = names.originPlugin[0] != '\0' ?
                    names.originPlugin : names.winningPlugin;
                CopyGameText(snapshot.sourcePlugin,
                    source && source[0] != '\0' ? source : "<unknown>");
                snapshot.baseFormID = names.baseFormID;
                const char* baseSource = names.baseOriginPlugin[0] != '\0' ?
                    names.baseOriginPlugin : names.baseWinningPlugin;
                if (snapshot.baseFormID != 0) {
                    CopyGameText(snapshot.baseSourcePlugin,
                        baseSource && baseSource[0] != '\0' ?
                            baseSource : "<unknown>");
                }
            }
            if (reference)
                ReleasePinnedReference(reference);
            return snapshot;
        }

        void LogGenerationStatus(
            const Profile& profile,
            bool skipAttribution,
            uint64_t trackedAssignments,
            uint64_t trackedSlots,
            uint64_t untrackedLive)
        {
            if (!g_generationDetectorActive.load(std::memory_order_acquire))
                return;
            const CurrentReferenceSnapshot snapshot =
                CaptureCurrentHottest(profile, skipAttribution);
            const unsigned long long wraps = static_cast<unsigned long long>(
                g_generationWraps.load(std::memory_order_acquire));
            const uint32_t unreliable =
                g_unreliableSlot.load(std::memory_order_acquire);
            const char* reliability = unreliable == 0 ? "exact" : "UNRELIABLE";
            if (!snapshot.hasHottest) {
                Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                    "untrackedLive=%llu highest=0 wrapThreshold=%u hottestSlot=none "
                    "currentHandle=none currentReference=none FormID=none "
                    "source=none wraps=%llu tracking=%s",
                    static_cast<unsigned long long>(trackedAssignments),
                    static_cast<unsigned long long>(trackedSlots),
                    static_cast<unsigned long long>(untrackedLive),
                    generation::kGenerationCount, wraps, reliability);
            } else if (!snapshot.hasCurrentHandle) {
                Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                    "untrackedLive=%llu highest=%u wrapThreshold=%u hottestSlot=%06X "
                    "currentHandle=none (slot currently free) currentReference=none "
                    "FormID=none source=none wraps=%llu tracking=%s",
                    static_cast<unsigned long long>(trackedAssignments),
                    static_cast<unsigned long long>(trackedSlots),
                    static_cast<unsigned long long>(untrackedLive),
                    snapshot.reuseCount, generation::kGenerationCount,
                    snapshot.slot, wraps, reliability);
            } else if (snapshot.attributionSkipped) {
                Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                    "untrackedLive=%llu highest=%u wrapThreshold=%u hottestSlot=%06X "
                    "currentHandle=%08X currentReference=%p FormID=skipped "
                    "source=<private StressTest attribution skipped> wraps=%llu "
                    "tracking=%s",
                    static_cast<unsigned long long>(trackedAssignments),
                    static_cast<unsigned long long>(trackedSlots),
                    static_cast<unsigned long long>(untrackedLive),
                    snapshot.reuseCount, generation::kGenerationCount,
                    snapshot.slot, snapshot.handle, snapshot.expectedReference,
                    wraps, reliability);
            } else if (!snapshot.resolvedCurrentReference) {
                Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                    "untrackedLive=%llu highest=%u wrapThreshold=%u hottestSlot=%06X "
                    "currentHandle=%08X currentReference=not currently resolvable "
                    "FormID=none source=none wraps=%llu tracking=%s",
                    static_cast<unsigned long long>(trackedAssignments),
                    static_cast<unsigned long long>(trackedSlots),
                    static_cast<unsigned long long>(untrackedLive),
                    snapshot.reuseCount, generation::kGenerationCount,
                    snapshot.slot, snapshot.handle, wraps, reliability);
            } else if (snapshot.baseFormID != 0) {
                Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                    "untrackedLive=%llu highest=%u wrapThreshold=%u hottestSlot=%06X "
                    "currentHandle=%08X currentReference=%p FormID=%08X "
                    "source=\"%s\" baseFormID=%08X baseSource=\"%s\" "
                    "wraps=%llu tracking=%s",
                    static_cast<unsigned long long>(trackedAssignments),
                    static_cast<unsigned long long>(trackedSlots),
                    static_cast<unsigned long long>(untrackedLive),
                    snapshot.reuseCount, generation::kGenerationCount,
                    snapshot.slot, snapshot.handle, snapshot.pinnedReference,
                    snapshot.formID, snapshot.sourcePlugin,
                    snapshot.baseFormID, snapshot.baseSourcePlugin,
                    wraps, reliability);
            } else {
                Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                    "untrackedLive=%llu highest=%u wrapThreshold=%u hottestSlot=%06X "
                    "currentHandle=%08X currentReference=%p FormID=%08X "
                    "source=\"%s\" wraps=%llu tracking=%s",
                    static_cast<unsigned long long>(trackedAssignments),
                    static_cast<unsigned long long>(trackedSlots),
                    static_cast<unsigned long long>(untrackedLive),
                    snapshot.reuseCount, generation::kGenerationCount,
                    snapshot.slot, snapshot.handle, snapshot.pinnedReference,
                    snapshot.formID, snapshot.sourcePlugin, wraps, reliability);
            }
        }

        struct UsageReporterContext
        {
            const Profile*     profile;
            const HandleEntry* table;
            uint32_t           entryCount;
            ULONGLONG          nextTick;
            uint64_t           elapsedMinutes;
            uint64_t           reportedWraps;
            bool               reportedUnreliable;
            bool               skipAttribution;
        };

        DWORD WINAPI UsageReporterThread(void* rawContext)
        {
            auto* context = static_cast<UsageReporterContext*>(rawContext);
            for (;;) {
                ULONGLONG now = GetTickCount64();
                if (now < context->nextTick) {
                    Sleep(static_cast<DWORD>(context->nextTick - now));
                    continue;
                }

                if (g_generationDetectorActive.load(std::memory_order_acquire)) {
                    const WrapSnapshot wrap = ReadWrapSnapshot();
                    if (wrap.total != context->reportedWraps) {
                        const uint32_t reuseCount =
                            static_cast<uint32_t>(wrap.event >> 32);
                        const uint32_t handle = static_cast<uint32_t>(wrap.event);
                        const uint32_t slot = handle & generation::kIndexMask;
                        Log("CRITICAL: HANDLE GENERATION WRAP DETECTED: wraps=%llu "
                            "(+%llu), slot=%06X reuseCount=%u newHandle=%08X; "
                            "the six-bit generation repeated after %u reuses and "
                            "stale-handle aliasing is now possible.",
                            static_cast<unsigned long long>(wrap.total),
                            static_cast<unsigned long long>(
                                wrap.total - context->reportedWraps),
                            slot, reuseCount, handle,
                            generation::kGenerationCount);
                        context->reportedWraps = wrap.total;
                    }
                    const uint32_t unreliable =
                        g_unreliableSlot.load(std::memory_order_acquire);
                    if (unreliable != 0 && !context->reportedUnreliable) {
                        if (unreliable == UINT32_MAX) {
                            Log("CRITICAL: generation-wrap detector lost exact tracking "
                                "at an invalid assignment destination; wrap totals are "
                                "now unreliable.");
                        } else {
                            Log("CRITICAL: generation-wrap detector lost exact tracking "
                                "at slot %06X; its uint32 counter saturated or its "
                                "generation disagreed with Skyrim. Wrap totals are now "
                                "unreliable.", unreliable - 1u);
                        }
                        context->reportedUnreliable = true;
                    }
                }

                uint64_t elapsed = 0;
                do {
                    context->nextTick += kReporterTickMilliseconds;
                    ++elapsed;
                } while (context->nextTick <= now);
                const uint64_t previousMinutes = context->elapsedMinutes;
                context->elapsedMinutes += elapsed;
                if (previousMinutes / kUsageReportIntervalMinutes ==
                    context->elapsedMinutes / kUsageReportIntervalMinutes) {
                    continue;
                }

                uint64_t inUse = 0;
                uint64_t aboveVanilla = 0;
                uint64_t trackedAssignments = 0;
                uint64_t trackedSlots = 0;
                uint64_t untrackedLive = 0;
                uint32_t highest = 0;
                bool hasLiveHandle = false;
                const bool detectorActive =
                    g_generationDetectorActive.load(std::memory_order_acquire);
                for (uint32_t begin = 0; begin < context->entryCount;
                     begin += kUsageScanEntriesPerLock) {
                    const uint32_t end = (std::min)(
                        context->entryCount, begin + kUsageScanEntriesPerLock);
                    LockManager(*context->profile);
                    for (uint32_t index = begin; index < end; ++index) {
                        uint32_t assignments = 0;
                        if (detectorActive) {
                            assignments = g_slotAssignments[index];
                            if (assignments != 0) {
                                ++trackedSlots;
                                trackedAssignments += assignments;
                            }
                        }
                        if ((context->table[index].bits &
                                generation::kInUseMask) == 0) {
                            continue;
                        }
                        ++inUse;
                        if (detectorActive && assignments == 0) {
                            ++untrackedLive;
                            MarkGenerationTrackingUnreliable(index);
                        }
                        if (index >= kVanillaHandleEntries)
                            ++aboveVanilla;
                        highest = index;
                        hasLiveHandle = true;
                    }
                    UnlockManager(*context->profile);
                    SwitchToThread();
                }

                const uint64_t freeCount = context->entryCount - inUse;
                if (hasLiveHandle) {
                    Log("handle usage: inUse=%llu/%u free=%llu aboveVanilla=%llu "
                        "highest=%06X (rolling locked snapshot)",
                        static_cast<unsigned long long>(inUse),
                        context->entryCount,
                        static_cast<unsigned long long>(freeCount),
                        static_cast<unsigned long long>(aboveVanilla),
                        highest);
                } else {
                    Log("handle usage: inUse=0/%u free=%u aboveVanilla=0 highest=none "
                        "(rolling locked snapshot)",
                        context->entryCount,
                        context->entryCount);
                }
                LogGenerationStatus(*context->profile,
                    context->skipAttribution, trackedAssignments,
                    trackedSlots, untrackedLive);
            }
        }

        bool StartHandleUsageReporter(const Profile& profile)
        {
            auto* context = new (std::nothrow) UsageReporterContext{
                &profile,
                static_cast<const HandleEntry*>(g_raisedTable),
                g_raisedEntryCount,
                GetTickCount64() + kReporterTickMilliseconds,
                0,
                0,
                false,
                g_set.stress.enabled,
            };
            if (!context) {
                Log("WARNING: could not allocate the five-minute handle-usage reporter; "
                    "the cap raise remains active.");
                return false;
            }
            HANDLE thread = CreateThread(
                nullptr, 0, &UsageReporterThread, context, 0, nullptr);
            if (!thread) {
                const DWORD error = GetLastError();
                delete context;
                Log("WARNING: could not start the five-minute handle-usage reporter "
                    "(error %lu); the cap raise remains active.", error);
                return false;
            }
            CloseHandle(thread);
            Log("handle usage reporting armed: normal status first reports in five "
                "minutes, then every five minutes; enabled generation diagnostics "
                "are polled every minute.");
            return true;
        }

        void ApplyCode(const Profile& pf, uintptr_t table, bool patchInitPatches)
        {
            for (uint32_t i = 0; i < pf.fieldCount; ++i) {
                const FieldPatch& f = pf.fields[i];
                auto* at = reinterpret_cast<uint8_t*>(g_base + f.rva) + f.fieldOff;
                if (f.fieldW == 4)
                    memcpy(at, &f.newVal, sizeof(f.newVal));
                else
                    *at = static_cast<uint8_t>(f.newVal);
            }
            for (uint32_t i = 0; i < pf.bytePatchCount; ++i) {
                const BytePatch& p = pf.bytePatches[i];
                memcpy(reinterpret_cast<void*>(g_base + p.rva), p.repl, p.len);
            }
            for (uint32_t i = 0; i < pf.tableRefCount; ++i) {
                const TableRef& r = pf.tableRefs[i];
                const int64_t delta = static_cast<int64_t>(table) -
                    static_cast<int64_t>(g_base + r.rva + r.len);
                const int32_t disp = static_cast<int32_t>(delta);
                memcpy(reinterpret_cast<void*>(g_base + r.rva + r.dispOff),
                    &disp, sizeof(disp));
            }
            if (patchInitPatches) {
                for (uint32_t i = 0; i < pf.initPatchCount; ++i) {
                    const BytePatch& p = pf.initPatches[i];
                    memcpy(reinterpret_cast<void*>(g_base + p.rva), p.repl, p.len);
                }
            }
        }

        void RestoreStockCode(const Profile& pf)
        {
            for (uint32_t i = 0; i < pf.fieldCount; ++i) {
                const FieldPatch& f = pf.fields[i];
                memcpy(reinterpret_cast<void*>(g_base + f.rva), f.orig, f.len);
            }
            for (uint32_t i = 0; i < pf.bytePatchCount; ++i) {
                const BytePatch& p = pf.bytePatches[i];
                memcpy(reinterpret_cast<void*>(g_base + p.rva), p.orig, p.len);
            }
            for (uint32_t i = 0; i < pf.tableRefCount; ++i) {
                const TableRef& r = pf.tableRefs[i];
                memcpy(reinterpret_cast<void*>(g_base + r.rva), r.orig, r.len);
            }
            for (uint32_t i = 0; i < pf.initPatchCount; ++i) {
                const BytePatch& p = pf.initPatches[i];
                memcpy(reinterpret_cast<void*>(g_base + p.rva), p.orig, p.len);
            }
        }

        [[noreturn]] void FatalStop(const char* reason)
        {
            Log("FATAL: %s", reason);
            Log("The patch could not prove a complete rollback. Terminating Skyrim before "
                "engine state or a save can be corrupted.");
            TerminateProcess(GetCurrentProcess(), 0x53484352u);
            ExitProcess(0x52u);
        }

        void RollBackOrStop(
            const Profile& pf, DWORD oldProtection, uint32_t oldHead, uint32_t oldTail,
            const char* reason)
        {
            Log("ABORT after writes: %s; restoring every stock instruction.", reason);
            DWORD currentProtection = 0;
            if (!VirtualProtect(g_text.begin, g_text.size, PAGE_EXECUTE_READWRITE,
                    &currentProtection)) {
                FatalStop("could not make .text writable for rollback");
            }
            *reinterpret_cast<uint32_t*>(g_base + pf.headRva) = oldHead;
            *reinterpret_cast<uint32_t*>(g_base + pf.tailRva) = oldTail;
            RestoreStockCode(pf);

            size_t mismatches = 0;
            const bool bytesRestored = VerifyStockCode(pf, mismatches);
            const size_t stockRefs = CountDispRefs(g_base + pf.tableRva);
            const bool globalsRestored =
                *reinterpret_cast<const uint32_t*>(g_base + pf.headRva) == oldHead &&
                *reinterpret_cast<const uint32_t*>(g_base + pf.tailRva) == oldTail;
            bool restoredInitAlreadyRan = false;
            const bool poolRestored = globalsRestored &&
                VerifyPristine(pf, restoredInitAlreadyRan) &&
                restoredInitAlreadyRan == (oldTail == pf.stockEntries - 1);
            const bool cacheFlushed =
                FlushInstructionCache(GetCurrentProcess(), g_text.begin, g_text.size) != FALSE;
            DWORD ignored = 0;
            const bool protectionRestored =
                VirtualProtect(g_text.begin, g_text.size, oldProtection, &ignored) != FALSE;
            if (!bytesRestored || stockRefs != pf.tableRefCount || !poolRestored ||
                !cacheFlushed || !protectionRestored) {
                FatalStop("stock bytes, table references, manager globals/pool, cache, or page "
                    "protection did not verify after rollback");
            }
            Log("rollback verified: all stock bytes, %u stock table references, manager "
                "globals, and the complete pristine pool were restored; no cap raise remains "
                "active.", pf.tableRefCount);
        }
    }

    // ---------------------------------------------------------------------
    // the raise
    // ---------------------------------------------------------------------

    void Raise()
    {
        if (!FindText()) {
            Log("could not locate the executable's .text section; no changes made");
            return;
        }

        const uint32_t ver = RuntimeVersion();
        g_runtimeVersion = ver;
        const Profile* pf = nullptr;
        for (uint32_t i = 0; i < kProfileCount; ++i) {
            if (kProfiles[i]->runtimeVersion == ver) {
                pf = kProfiles[i];
                break;
            }
        }
        Log("runtime version %u.%u.%u.%u, image base %016llx, .text %016llx + %zu",
            (ver >> 24) & 0xFF, (ver >> 16) & 0xFF, (ver >> 4) & 0xFFF, ver & 0xF,
            static_cast<unsigned long long>(g_base),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(g_text.begin)),
            g_text.size);

        if (!pf) {
            Log("no verified patch profile for this runtime; no changes made.");
            Log("supported: Skyrim SE 1.5.97, Skyrim AE 1.6.1170, "
                "Skyrim GOG 1.6.1179, and Skyrim VR 1.4.15.");
            return;
        }
        Log("profile: %s -- %u field rewrites + %u sidecar rewrites + %u table "
            "references, slots %u -> %u", pf->name, pf->fieldCount,
            pf->bytePatchCount, pf->tableRefCount, pf->stockEntries, pf->raisedEntries);

        // -- verify before touching anything -------------------------------
        LogEngineFixesCompatibility();

        size_t mismatches = 0;
        if (!VerifyStockCode(*pf, mismatches)) {
            Log("ABORT: %zu instructions or audited release sites do not match their "
                "expected stock bytes.", mismatches);
            Log("The executable is not the build this profile was built from, or another "
                "mod patched the same code. No changes made.");
            return;
        }

        const size_t liveRefs = CountDispRefs(g_base + pf->tableRva);
        if (liveRefs != pf->tableRefCount) {
            Log("ABORT: this executable contains %zu references to the handle table but the "
                "profile knows %u. Patching a partial set resolves handles to the wrong "
                "object silently, so no changes were made.", liveRefs, pf->tableRefCount);
            return;
        }
        Log("verified stock bytes: %u fields, %u sidecar rewrites, %u table references, "
            "%u initialiser guards, and %u release gates", pf->fieldCount,
            pf->bytePatchCount, pf->tableRefCount, pf->initPatchCount,
            pf->releaseSiteCount);

        // -- allocate and fully construct the wider table before code writes
        const size_t bytes = static_cast<size_t>(pf->raisedEntries) * pf->entrySize;
        uint8_t*     table = AllocTableNear(bytes);
        if (!table) {
            Log("ABORT: could not allocate %zu bytes for the new handle table.", bytes);
            return;
        }
        if (!InDispRange(*pf, reinterpret_cast<uintptr_t>(table))) {
            Log("ABORT: the allocation at %016llx is out of 32-bit displacement range of the "
                "code that must address it.", static_cast<unsigned long long>(
                                                  reinterpret_cast<uintptr_t>(table)));
            VirtualFree(table, 0, MEM_RELEASE);
            return;
        }
        InitializeTable(*pf, table);
        if (!VerifyNewTable(*pf, table)) {
            Log("ABORT: the new table's complete free-list chain did not verify.");
            VirtualFree(table, 0, MEM_RELEASE);
            return;
        }
        Log("new handle table: %zu MB at %016llx", bytes / (1024 * 1024),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(table)));
        Log("new free list verified through final index %08x", pf->raisedEntries - 1);

        // Prepare the optional diagnostic before committing the cap raise, but
        // do not redirect a single engine call until the independent table/code
        // transaction has fully committed. The guard frees both allocations on
        // every cap-abort or diagnostic-refusal path.
        GenerationPreparationGuard detectorGuard;
        const bool detectorPrepared = PrepareGenerationDetector(
            *pf, reinterpret_cast<const HandleEntry*>(table));

        // The stock manager lock closes the gap between the exact-pristine
        // check and publishing the new head/tail. No used handle can enter the
        // transaction.
        LockManager(*pf);
        bool initAlreadyRan = false;
        if (!VerifyPristine(*pf, initAlreadyRan)) {
            UnlockManager(*pf);
            Log("ABORT: the handle pool is not exactly pristine. No changes made.");
            VirtualFree(table, 0, MEM_RELEASE);
            return;
        }
        Log("pool is pristine (free-list initialiser %s run yet)",
            initAlreadyRan ? "has" : "has not");

        const uint32_t oldHead = *reinterpret_cast<uint32_t*>(g_base + pf->headRva);
        const uint32_t oldTail = *reinterpret_cast<uint32_t*>(g_base + pf->tailRva);
        DWORD oldProt = 0;
        if (!VirtualProtect(g_text.begin, g_text.size, PAGE_EXECUTE_READWRITE, &oldProt)) {
            Log("ABORT: could not make .text writable (error %lu).", GetLastError());
            UnlockManager(*pf);
            VirtualFree(table, 0, MEM_RELEASE);
            return;
        }

        const bool patchInitPatches = !initAlreadyRan;
        ApplyCode(*pf, reinterpret_cast<uintptr_t>(table), patchInitPatches);
        const uint32_t last = pf->raisedEntries - 1;
        *reinterpret_cast<uint32_t*>(g_base + pf->headRva) = 0;
        *reinterpret_cast<uint32_t*>(g_base + pf->tailRva) = last;

        // Verify all new instructions, both raw decoder-independent reference
        // counts, the entire free list, and the shared head/tail before commit.
        size_t patchedMismatches = 0;
        const bool codeGood = VerifyPatchedCode(*pf, reinterpret_cast<uintptr_t>(table),
            patchInitPatches, patchedMismatches);
        const size_t staleRefs = CountDispRefs(g_base + pf->tableRva);
        const size_t newRefs = CountDispRefs(reinterpret_cast<uintptr_t>(table));
        const bool globalsGood =
            *reinterpret_cast<uint32_t*>(g_base + pf->headRva) == 0 &&
            *reinterpret_cast<uint32_t*>(g_base + pf->tailRva) == last;
        const bool tableGood = VerifyNewTable(*pf, table);
        if (!codeGood || staleRefs != 0 || newRefs != pf->tableRefCount ||
            !globalsGood || !tableGood) {
            Log("post-write verification: mismatches=%zu oldRefs=%zu newRefs=%zu "
                "globals=%s table=%s", patchedMismatches, staleRefs, newRefs,
                globalsGood ? "PASS" : "FAIL", tableGood ? "PASS" : "FAIL");
            RollBackOrStop(*pf, oldProt, oldHead, oldTail,
                "post-write verification failed");
            UnlockManager(*pf);
            VirtualFree(table, 0, MEM_RELEASE);
            return;
        }

        if (!FlushInstructionCache(GetCurrentProcess(), g_text.begin, g_text.size)) {
            RollBackOrStop(*pf, oldProt, oldHead, oldTail,
                "FlushInstructionCache failed before commit");
            UnlockManager(*pf);
            VirtualFree(table, 0, MEM_RELEASE);
            return;
        }
        DWORD ignored = 0;
        if (!VirtualProtect(g_text.begin, g_text.size, oldProt, &ignored)) {
            RollBackOrStop(*pf, oldProt, oldHead, oldTail,
                "could not restore executable page protection before commit");
            UnlockManager(*pf);
            VirtualFree(table, 0, MEM_RELEASE);
            return;
        }

        Log("SUCCESS: reference handle slots raised %u -> %u (index 22 bits, age still 6 bits "
            "/ 64 generations, reference count and valid bit remain stock-compatible).",
            pf->stockEntries, pf->raisedEntries);
        Log("post-patch verification: 0 stale references, %zu/%u new references, all "
            "rewrites/free-list/globals verified%s.", newRefs, pf->tableRefCount,
            patchInitPatches ? "; future stock initialisation disabled" : "");

        g_raiseSucceeded = true;
        g_raisedTable = table;
        g_raisedEntryCount = pf->raisedEntries;

        // Start the reporter before publishing any hook. It sleeps for its
        // first one-minute tick, so it cannot contend with this still-held
        // manager lock. If thread creation fails, the detector remains wholly
        // uninstalled and the cap fix remains operational.
        const bool reporterStarted = StartHandleUsageReporter(*pf);
        if (detectorPrepared && reporterStarted) {
            detectorGuard.keep = InstallGenerationDetector(*pf);
        } else if (detectorPrepared) {
            Log("ERROR: generation-wrap detector disabled because its reporting thread "
                "could not start; cap raise remains active.");
        }
        UnlockManager(*pf);
    }

    void Init(const void* skseLoadInterface)
    {
        OpenLog();
        LoadSettings();
        Log("SkyrimHandleCapRaise 2.0.0 (4M build)");
        Log("configuration: GenerationWrapDetection=%u VerboseLogging=%u SampleSize=%u",
            g_set.generationWrapDetection ? 1u : 0u,
            g_set.stress.liveDiagnosticsEnabled ? 1u : 0u,
            g_set.stress.diagnosticsDetailedSampleLimit);
        Raise();
        if (g_raiseSucceeded &&
            (g_set.stress.enabled || g_set.stress.liveDiagnosticsEnabled)) {
            stress::Callbacks callbacks;
            callbacks.log = &StressLog;
            callbacks.resolveAttribution = &ResolveStressAttribution;
            callbacks.resolveNames = &ResolveStressNames;
            callbacks.handleTable = g_raisedTable;
            callbacks.handleEntryCount = g_raisedEntryCount;
            if (!stress::Initialize(skseLoadInterface, g_set.stress, callbacks)) {
                Log("WARNING: requested verbose diagnostics or private StressTest mode "
                    "could not be initialized. They are mutually exclusive and the SKSE "
                    "interfaces/settings must be valid. The cap raise remains active.");
            }
        }
    }
}

// -------------------------------------------------------------------------
// SKSE plugin exports
// -------------------------------------------------------------------------

struct SKSEPluginVersionData
{
    enum
    {
        kVersion = 1
    };
    uint32_t dataVersion;
    uint32_t pluginVersion;
    char     name[256];
    char     author[256];
    char     supportEmail[252];
    uint32_t versionIndependenceEx;
    uint32_t versionIndependence;
    uint32_t compatibleVersions[16];
    uint32_t seVersionRequired;
};

#define RUNTIME_VERSION(major, minor, build, sub) \
    ((((major) & 0xFF) << 24) | (((minor) & 0xFF) << 16) | (((build) & 0xFFF) << 4) | ((sub) & 0xF))

extern "C" __declspec(dllexport) SKSEPluginVersionData SKSEPlugin_Version = {
    SKSEPluginVersionData::kVersion,
    0x020000,  // 2.0.0
    "SkyrimHandleCapRaise",
    "Skyrim Handle Audit",
    "",
    0,
    0,  // version dependent: exact per-runtime byte-verified patch tables
    { RUNTIME_VERSION(1, 5, 97, 0), RUNTIME_VERSION(1, 6, 1170, 0),
      // SKSE uses the low nibble as the storefront type.  The GOG loader
      // therefore reports 1.6.1179 as 0x010649B1 even though the executable's
      // ProductVersion string (used to select our exact patch profile) is
      // 1.6.1179.0.
      RUNTIME_VERSION(1, 6, 1179, 1), RUNTIME_VERSION(1, 4, 15, 0), 0 },
    0,
};

struct PluginInfo
{
    uint32_t    infoVersion;
    const char* name;
    uint32_t    version;
};

// Legacy SKSE/SKSEVR loader query path.
extern "C" __declspec(dllexport) bool SKSEPlugin_Query(void*, PluginInfo* info)
{
    if (info) {
        info->infoVersion = 1;
        info->name = "SkyrimHandleCapRaise";
        info->version = 0x020000;
    }
    return true;
}

extern "C" __declspec(dllexport) bool SKSEPlugin_Load(void* skse)
{
    shcr::Init(skse);
    return true;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hinst);
    return TRUE;
}
