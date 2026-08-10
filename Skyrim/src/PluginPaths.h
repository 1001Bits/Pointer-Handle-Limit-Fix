#pragma once

#include <windows.h>

#include <cstddef>

namespace shcr
{
    void PluginsDir(wchar_t* a_out, std::size_t a_count) noexcept;

    [[nodiscard]] bool BuildPluginPath(
        wchar_t* a_out,
        std::size_t a_count,
        const wchar_t* a_name) noexcept;

    [[nodiscard]] bool GetLoadedModulePath(
        HMODULE a_module,
        wchar_t* a_path,
        std::size_t a_count) noexcept;
}
