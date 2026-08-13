#pragma once

#include "RuntimeTypes.h"

#include <cstddef>
#include <cstdint>

namespace sfhcr
{
    struct Settings
    {
        std::uint32_t targetIndexBits = kDefaultIndexBits;
        bool verboseLogging = false;
        std::size_t detailedSampleCount = 16;
        bool generationWrapDetection = true;

        [[nodiscard]] constexpr std::uint64_t Capacity() const noexcept
        {
            return CapacityForBits(targetIndexBits);
        }

        [[nodiscard]] constexpr std::uint32_t GenerationCount() const noexcept
        {
            return GenerationCountForBits(targetIndexBits);
        }
    };

    [[nodiscard]] Settings LoadSettings() noexcept;
}
