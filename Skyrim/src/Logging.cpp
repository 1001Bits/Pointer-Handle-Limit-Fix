#include "Logging.h"

#include "RuntimeTypes.h"

#include <windows.h>
#include <shlobj.h>

#include <cstdarg>
#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <iterator>
#include <share.h>
#include <sys/stat.h>

namespace shcr
{
    namespace
    {
        FILE*   g_log = nullptr;
        SRWLOCK g_logLock = SRWLOCK_INIT;

        void OpenSharedLogFile(const wchar_t* a_path) noexcept
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
    }

    void OpenLog(std::uint32_t a_runtimeVersion) noexcept
    {
        PWSTR docs = nullptr;
        wchar_t path[MAX_PATH * 2]{};
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &docs))) {
            const wchar_t* gameFolder = a_runtimeVersion == kRuntimeVR ?
                L"Skyrim VR" : a_runtimeVersion == kRuntimeGOG ?
                L"Skyrim Special Edition GOG" : L"Skyrim Special Edition";
            swprintf_s(path, L"%s\\My Games\\%s\\SKSE", docs, gameFolder);
            CoTaskMemFree(docs);
            CreateDirectoryW(path, nullptr);
            wcscat_s(path, L"\\SkyrimHandleCapRaise.log");
            OpenSharedLogFile(path);
        }
        if (!g_log) {
            const DWORD length = GetTempPathW(
                static_cast<DWORD>(std::size(path)), path);
            if (length != 0 && length < std::size(path)) {
                wcscat_s(path, L"SkyrimHandleCapRaise.log");
                OpenSharedLogFile(path);
            }
        }
    }

    void Log(const char* a_format, ...) noexcept
    {
        if (!g_log)
            return;
        AcquireSRWLockExclusive(&g_logLock);
        va_list arguments;
        va_start(arguments, a_format);
        vfprintf(g_log, a_format, arguments);
        va_end(arguments);
        fputc('\n', g_log);
        fflush(g_log);
        ReleaseSRWLockExclusive(&g_logLock);
    }
}
