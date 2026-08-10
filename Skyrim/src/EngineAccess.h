#pragma once

#include "RuntimeTypes.h"

#include <cstdint>

namespace shcr
{
    void LockManager(
        const RuntimeContext& a_runtime,
        const Profile& a_profile) noexcept;

    void UnlockManager(
        const RuntimeContext& a_runtime,
        const Profile& a_profile) noexcept;

    [[nodiscard]] bool ResolveSmartPointer(
        const RuntimeContext& a_runtime,
        std::uint32_t a_handle,
        void*& a_reference) noexcept;

    void ReleasePinnedReference(void* a_reference) noexcept;
}
