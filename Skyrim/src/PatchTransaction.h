#pragma once

#include "HandleTable.h"
#include "RuntimeTypes.h"

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

        void (*onTablePrepared)(
            void*, const RuntimeContext&, HandleTableView) noexcept = nullptr;

        void (*onCommittedWhileManagerLocked)(
            void*, const RuntimeContext&, HandleTableView) noexcept = nullptr;

        void (*onPatchAborted)(void*) noexcept = nullptr;
    };

    [[nodiscard]] Result Raise(
        const RuntimeContext& a_runtime,
        const Lifecycle& a_lifecycle) noexcept;
}
