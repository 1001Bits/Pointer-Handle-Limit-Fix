#include "PluginPaths.h"

#include <cwchar>

namespace shcr
{
    void PluginsDir(wchar_t* a_out, std::size_t a_count) noexcept
    {
        GetModuleFileNameW(nullptr, a_out, static_cast<DWORD>(a_count));
        if (wchar_t* slash = wcsrchr(a_out, L'\\'))
            *(slash + 1) = 0;
        wcscat_s(a_out, a_count, L"Data\\SKSE\\Plugins\\");
    }

    bool BuildPluginPath(
        wchar_t* a_out,
        std::size_t a_count,
        const wchar_t* a_name) noexcept
    {
        PluginsDir(a_out, a_count);
        return a_out[0] != L'\0' && wcscat_s(a_out, a_count, a_name) == 0;
    }

    bool GetLoadedModulePath(
        HMODULE a_module,
        wchar_t* a_path,
        std::size_t a_count) noexcept
    {
        if (!a_module || !a_path || a_count == 0 || a_count > MAXDWORD)
            return false;
        const DWORD length = GetModuleFileNameW(
            a_module, a_path, static_cast<DWORD>(a_count));
        if (length == 0 || length >= a_count) {
            a_path[0] = L'\0';
            return false;
        }
        return true;
    }
}
