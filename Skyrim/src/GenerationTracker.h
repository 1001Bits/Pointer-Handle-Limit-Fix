#pragma once

#include <cstdint>
#include <limits>

namespace shcr::generation
{
    // The raised layout expands Skyrim's index by one bit while preserving its
    // 26-bit handle/table shape: bits 0..20 are the index, bits 21..25 are age,
    // and table-only in-use state remains at bit 26.  This is also the complete
    // index width already available in BSHandleRefObject::_refCount[31:11].
    inline constexpr std::uint32_t kHandleValueBits = 26;
    inline constexpr std::uint32_t kIndexBits = 21;
    inline constexpr std::uint32_t kGenerationBits = 5;
    inline constexpr std::uint32_t kEntryCount = 1u << kIndexBits;
    inline constexpr std::uint32_t kIndexMask = kEntryCount - 1u;
    inline constexpr std::uint32_t kGenerationCount = 1u << kGenerationBits;
    // Every ordinary slot may publish all 32 distinct five-bit generations.
    // Its first assignment is not a reuse, so 31 successful reuses are safe.
    // The next attempt would repeat the first issued generation and is stopped
    // before the table pointer, object cache, assignment-function return, and
    // manager unlock can make that repeated handle resolvable.
    inline constexpr std::uint32_t kSafeReuseLimit = kGenerationCount - 1u;
    inline constexpr std::uint32_t kFirstPreventedReuse = kGenerationCount;
    inline constexpr std::uint32_t kGenerationMask =
        (kGenerationCount - 1u) << kIndexBits;
    inline constexpr std::uint32_t kInUseMask = 1u << kHandleValueBits;

    static_assert(kEntryCount == 0x00200000u);
    static_assert(kIndexMask == 0x001FFFFFu);
    static_assert(kGenerationCount == 32u);
    static_assert(kSafeReuseLimit == 31u);
    static_assert(kFirstPreventedReuse == 32u);
    static_assert(kGenerationMask == 0x03E00000u);
    static_assert(kInUseMask == 0x04000000u);
    static_assert(kIndexBits + kGenerationBits == kHandleValueBits);

    struct Transition
    {
        std::uint32_t assignmentCount;
        std::uint32_t reuseCount;
        bool generationMatches;
        // True means this attempted assignment would repeat an already-issued
        // generation. The mandatory hook treats it as a pre-publication stop,
        // never as permission to publish a wrap.
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
    // advances the five-bit generation before publishing an assignment, so the
    // first observed generation is 1.  `priorAssignments` is also the exact
    // number of reuses before this assignment.  A stale handle can first alias
    // after 32 reuses, when an already-issued generation is repeated.
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

    // Compile the exact release boundary into every native build.  These are
    // deliberately coupled to ObserveAssignment rather than duplicated in a
    // separate model: changing the production predicate must fail the build.
    static_assert(ObserveAssignment(0u, 1u).assignmentCount == 1u);
    static_assert(ObserveAssignment(0u, 1u).reuseCount == 0u);
    static_assert(ObserveAssignment(0u, 1u).generationMatches);
    static_assert(!ObserveAssignment(0u, 1u).abaWrap);
    static_assert(ObserveAssignment(31u, 0u).assignmentCount == 32u);
    static_assert(ObserveAssignment(31u, 0u).reuseCount == kSafeReuseLimit);
    static_assert(ObserveAssignment(31u, 0u).generationMatches);
    static_assert(!ObserveAssignment(31u, 0u).abaWrap);
    static_assert(ObserveAssignment(32u, 1u).assignmentCount == 33u);
    static_assert(ObserveAssignment(32u, 1u).reuseCount ==
                  kFirstPreventedReuse);
    static_assert(ObserveAssignment(32u, 1u).generationMatches);
    static_assert(ObserveAssignment(32u, 1u).abaWrap);
}
