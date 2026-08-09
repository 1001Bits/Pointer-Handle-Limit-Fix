#pragma once

#include <cstdint>
#include <string_view>

namespace shcr::enginefixes
{
    struct FileVersion
    {
        std::uint16_t major = 0;
        std::uint16_t minor = 0;
        std::uint16_t build = 0;
        std::uint16_t revision = 0;
    };

    // Parses the numeric StringFileInfo ProductVersion used by Skyrim executables.
    // Exactly four dot-separated decimal uint16 components are required.
    [[nodiscard]] bool ParseVersionString(
        std::wstring_view a_text, FileVersion& a_version) noexcept;
}
