#pragma once

#include <cstddef>
#include <cstdint>

namespace shcr
{
    struct RuntimeContext;

    namespace enginefixes
    {
        // Accepts only the independently fingerprinted Engine Fixes 7.0.20
        // FormCaching/SafetyHook detour on Skyrim AE 1.6.1170. Stock owner
        // bytes remain the normal path on every supported runtime.
        [[nodiscard]] bool IsAuthenticatedFormCachingLifecycleOwner(
            const RuntimeContext& a_runtime,
            std::uint32_t a_ownerRva,
            const std::uint8_t* a_stockBytes,
            std::size_t a_stockByteCount) noexcept;

        [[nodiscard]] bool WasFormCachingLifecycleOwnerAuthenticated() noexcept;

        // Repeats the complete binary/hook/trampoline proof at prerelease
        // lifecycle checkpoints, before the handle-manager lock is acquired.
        [[nodiscard]] bool RevalidateFormCachingLifecycleOwner(
            const RuntimeContext& a_runtime) noexcept;

        // Emitted only after the caller has also verified every exact
        // downstream lifecycle site and ordering invariant.
        void LogAuthenticatedFormCachingLifecycleOwner() noexcept;
    }
}
