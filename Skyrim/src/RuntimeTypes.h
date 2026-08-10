#pragma once

#include <cstddef>
#include <cstdint>

namespace shcr
{
    struct Profile;

    inline constexpr std::uint32_t kRuntimeSE = 0x01050610u;
    inline constexpr std::uint32_t kRuntimeAE = 0x01064920u;
    inline constexpr std::uint32_t kRuntimeGOG = 0x010649B0u;
    inline constexpr std::uint32_t kRuntimeVR = 0x010400F0u;

    struct TextRange
    {
        std::uint8_t* begin = nullptr;
        std::size_t   size = 0;
    };

    struct RuntimeOffsets
    {
        std::uint32_t displayNameRva = 0;
        std::uint32_t getSmartPointerRva = 0;
    };

    struct RuntimeContext
    {
        std::uintptr_t imageBase = 0;
        TextRange      text;
        std::uint32_t  runtimeVersion = 0;
        const Profile* profile = nullptr;
        RuntimeOffsets offsets;
    };
}
