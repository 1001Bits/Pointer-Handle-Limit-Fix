#pragma once

#include <cstdint>

namespace shcr
{
    void OpenLog(std::uint32_t a_runtimeVersion) noexcept;
    void Log(const char* a_format, ...) noexcept;
}
