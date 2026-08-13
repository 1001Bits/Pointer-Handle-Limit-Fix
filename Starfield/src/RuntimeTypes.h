#pragma once

#include <cstddef>
#include <cstdint>

namespace sfhcr
{
    // Address Library IDs shared by both supported Starfield runtimes.
    inline constexpr std::uint64_t kID_SingletonPtr = 883285;
    inline constexpr std::uint64_t kID_LookupReferenceByHandle = 36239;
    inline constexpr std::uint64_t kID_HandleManagerVtable = 450711;
    inline constexpr std::uint64_t kID_AssignNativeHandle = 99517;
    inline constexpr std::size_t kAssignNativeHandleSlot = 2;

    // Audited reference-handle manager layout.
    inline constexpr std::size_t kOff_PoolPtr = 0x50;
    inline constexpr std::size_t kOff_FreeHead = 0x58;
    inline constexpr std::size_t kOff_FreeTail = 0x5c;
    inline constexpr std::size_t kOff_FreeCounter = 0x60;
    inline constexpr std::size_t kOff_Capacity = 0x64;
    inline constexpr std::size_t kOff_IndexMask = 0x68;

    inline constexpr std::uint32_t kStockBits = 21;
    inline constexpr std::uint32_t kStockCap = 1u << kStockBits;
    inline constexpr std::uint32_t kStockFreeCount = kStockCap;
    inline constexpr std::size_t kPoolEntrySize = 16;

    inline constexpr std::uint32_t kDefaultIndexBits = 22;
    inline constexpr std::uint32_t kHighCapIndexBits = 23;

    [[nodiscard]] constexpr std::uint64_t CapacityForBits(std::uint32_t bits) noexcept
    {
        return 1ull << bits;
    }

    [[nodiscard]] constexpr std::uint32_t GenerationCountForBits(std::uint32_t bits) noexcept
    {
        return 1u << (32u - bits);
    }

    [[nodiscard]] constexpr std::uint64_t MaxEncodedHandleForBits(
        std::uint32_t bits) noexcept
    {
        return (static_cast<std::uint64_t>(GenerationCountForBits(bits) - 1u) << bits) |
               (CapacityForBits(bits) - 1u);
    }

    static_assert(kStockBits < kDefaultIndexBits &&
                  kDefaultIndexBits < kHighCapIndexBits && kHighCapIndexBits < 32u);
    static_assert(CapacityForBits(kDefaultIndexBits) == 0x400000ull);
    static_assert(CapacityForBits(kHighCapIndexBits) == 0x800000ull);
    static_assert(GenerationCountForBits(kDefaultIndexBits) == 1024u);
    static_assert(GenerationCountForBits(kHighCapIndexBits) == 512u);
    static_assert(MaxEncodedHandleForBits(kDefaultIndexBits) == 0xffffffffull);
    static_assert(MaxEncodedHandleForBits(kHighCapIndexBits) == 0xffffffffull);
}
