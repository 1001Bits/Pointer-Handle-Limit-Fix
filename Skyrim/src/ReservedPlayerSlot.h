#pragma once

#include "GenerationTracker.h"
#include "HandleTable.h"

#include <cstdint>

namespace shcr::player_slot
{
    // Physical slot 0x100000 with generation zero is Skyrim's vanilla raw
    // player handle.  Generation 31 is the detached seed because the allocator
    // increments it modulo 32 immediately before publication.
    inline constexpr std::uint32_t kIndex = 0x00100000u;
    inline constexpr std::uint32_t kVanillaRawHandle = 0x00100000u;
    inline constexpr std::uint32_t kDetachedGeneration =
        generation::kSafeReuseLimit;
    inline constexpr std::uint32_t kDetachedBits =
        (kDetachedGeneration << generation::kIndexBits) | kIndex;
    // Exact live bits only when the ordinary FIFO was empty and the injected
    // reserved entry self-linked. A non-empty injection retains ordinaryHead
    // in bits 0..20, so production validation must use the mask predicate.
    inline constexpr std::uint32_t kLiveBits =
        generation::kInUseMask | kVanillaRawHandle;
    inline constexpr std::uint32_t kLiveGenerationZeroMask =
        generation::kGenerationMask | generation::kInUseMask;
    inline constexpr std::uint32_t kPlayerFormID = 0x00000014u;

    static_assert(kIndex < generation::kEntryCount);
    static_assert(kVanillaRawHandle == kIndex);
    static_assert(kDetachedBits == 0x03F00000u);
    static_assert((kDetachedBits & generation::kIndexMask) == kIndex);
    static_assert(generation::GenerationFromEntryBits(kDetachedBits) ==
                  kDetachedGeneration);
    static_assert((kDetachedBits & generation::kInUseMask) == 0);
    static_assert(generation::HandleFromEntryBits(kIndex, 0) ==
                  kVanillaRawHandle);
    static_assert(kLiveBits == 0x04100000u);
    static_assert(kLiveGenerationZeroMask == 0x07E00000u);
    static_assert(((kDetachedBits + (1u << generation::kIndexBits)) &
                   generation::kGenerationMask) == 0);

    [[nodiscard]] constexpr bool HasLiveGenerationZeroState(
        std::uint32_t a_bits) noexcept
    {
        // Stock allocation retains the consumed free entry's successor in
        // bits 0..20.  For the injected player slot that successor is the
        // ordinary FIFO head, not necessarily the reserved physical index.
        // Only the in-use and generation fields define this live state; the
        // raw player handle still comes from physical index 0x100000.
        return (a_bits & kLiveGenerationZeroMask) ==
            generation::kInUseMask;
    }

    static_assert(HasLiveGenerationZeroState(kLiveBits));
    static_assert(HasLiveGenerationZeroState(
        generation::kInUseMask | 0x20u));
    static_assert(!HasLiveGenerationZeroState(
        generation::kInUseMask | (1u << generation::kIndexBits)));
    static_assert(!HasLiveGenerationZeroState(kVanillaRawHandle));

    [[nodiscard]] inline bool IsDetached(
        const HandleEntry& a_entry) noexcept
    {
        return a_entry.bits == kDetachedBits && a_entry.pad == 0 &&
            a_entry.pointer == nullptr;
    }

    [[nodiscard]] inline bool IsLiveGenerationZero(
        const HandleEntry& a_entry) noexcept
    {
        return HasLiveGenerationZeroState(a_entry.bits) &&
            a_entry.pointer != nullptr;
    }
}
