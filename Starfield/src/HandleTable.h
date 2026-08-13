#pragma once

#include "RuntimeTypes.h"

#include <cstdint>

namespace sfhcr
{
    struct HandleLayout
    {
        std::uint32_t indexBits = kDefaultIndexBits;
        std::uint32_t generationCount = GenerationCountForBits(kDefaultIndexBits);
        std::uint64_t capacity = CapacityForBits(kDefaultIndexBits);

        [[nodiscard]] constexpr std::uint32_t IndexMask() const noexcept
        {
            return static_cast<std::uint32_t>(capacity - 1);
        }

        [[nodiscard]] constexpr std::uint64_t UsableCapacity() const noexcept
        {
            return capacity - 1;
        }
    };

    [[nodiscard]] constexpr HandleLayout MakeHandleLayout(
        std::uint32_t a_indexBits) noexcept
    {
        return HandleLayout{
            a_indexBits,
            GenerationCountForBits(a_indexBits),
            CapacityForBits(a_indexBits)
        };
    }

    struct HandleTableView
    {
        std::uintptr_t manager = 0;
        std::uint8_t* pool = nullptr;
        HandleLayout layout{};
    };
}
