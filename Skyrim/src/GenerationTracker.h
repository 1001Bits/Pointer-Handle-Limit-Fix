#pragma once

#include <cstdint>
#include <limits>

namespace shcr::generation
{
    // Skyrim's native pointer handle uses bits 0..27.  The raised layout keeps
    // the engine's six generation bits and gives bits 0..21 to the index;
    // table-only in-use state begins at bit 28 and is not part of the handle.
    inline constexpr std::uint32_t kHandleValueBits = 28;
    inline constexpr std::uint32_t kIndexBits = 22;
    inline constexpr std::uint32_t kGenerationBits =
        kHandleValueBits - kIndexBits;
    inline constexpr std::uint32_t kEntryCount = 1u << kIndexBits;
    inline constexpr std::uint32_t kIndexMask = kEntryCount - 1u;
    inline constexpr std::uint32_t kGenerationCount = 1u << kGenerationBits;
    inline constexpr std::uint32_t kGenerationMask =
        (kGenerationCount - 1u) << kIndexBits;
    inline constexpr std::uint32_t kInUseMask = 1u << kHandleValueBits;

    static_assert(kEntryCount == 0x00400000u);
    static_assert(kGenerationCount == 64u);
    static_assert(kGenerationMask == 0x0FC00000u);
    static_assert(kInUseMask == 0x10000000u);

    struct Transition
    {
        std::uint32_t assignmentCount;
        std::uint32_t reuseCount;
        bool generationMatches;
        bool abaWrap;
        bool saturated;
    };

    [[nodiscard]] constexpr std::uint32_t GenerationFromEntryBits(
        std::uint32_t a_bits) noexcept
    {
        return (a_bits & kGenerationMask) >> kIndexBits;
    }

    [[nodiscard]] constexpr std::uint32_t HandleFromEntryBits(
        std::uint32_t a_index, std::uint32_t a_bits) noexcept
    {
        return (a_index & kIndexMask) | (a_bits & kGenerationMask);
    }

    // The cap is installed only after proving every table age is zero.  Skyrim
    // advances the six-bit generation before publishing an assignment, so the
    // first observed generation is 1.  `priorAssignments` is also the exact
    // number of reuses before this assignment.  A stale handle can first alias
    // after 64 reuses, when an already-issued generation is repeated.
    [[nodiscard]] constexpr Transition ObserveAssignment(
        std::uint32_t a_priorAssignments,
        std::uint32_t a_observedGeneration) noexcept
    {
        if (a_priorAssignments == (std::numeric_limits<std::uint32_t>::max)()) {
            return {
                a_priorAssignments,
                a_priorAssignments,
                false,
                false,
                true,
            };
        }

        const std::uint32_t assignmentCount = a_priorAssignments + 1u;
        const std::uint32_t expectedGeneration =
            assignmentCount & (kGenerationCount - 1u);
        const bool generationMatches =
            a_observedGeneration == expectedGeneration;
        const bool abaWrap = generationMatches && a_priorAssignments != 0u &&
            (a_priorAssignments & (kGenerationCount - 1u)) == 0u;
        return {
            assignmentCount,
            a_priorAssignments,
            generationMatches,
            abaWrap,
            false,
        };
    }
}
