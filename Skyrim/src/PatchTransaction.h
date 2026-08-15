#pragma once

#include "HandleTable.h"
#include "RuntimeTypes.h"

#include <cstdint>

namespace shcr::patch
{
    struct Result
    {
        bool            succeeded = false;
        HandleTableView table;
        const Profile*  profile = nullptr;
    };

    struct Lifecycle
    {
        void* context = nullptr;

        bool (*onTablePrepared)(
            void*, const RuntimeContext&, HandleTableView) noexcept = nullptr;

        // A false commit callback result must leave any callback-owned code
        // hooks fully restored so the transaction can roll back the cap.
        bool (*onCommittedWhileManagerLocked)(
            void*, const RuntimeContext&, HandleTableView) noexcept = nullptr;

        void (*onPatchAborted)(void*) noexcept = nullptr;
    };

    struct ReservedPlayerLifecycleSnapshot
    {
        std::uint64_t constructorAssignments = 0;
        std::uint64_t releaseQuarantines = 0;
    };

    [[nodiscard]] ReservedPlayerLifecycleSnapshot
    ReadReservedPlayerLifecycleSnapshot() noexcept;

    [[nodiscard]] Result Raise(
        const RuntimeContext& a_runtime,
        const Lifecycle& a_lifecycle) noexcept;
}
