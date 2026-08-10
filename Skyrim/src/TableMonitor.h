#pragma once

#include "HandleTable.h"
#include "RuntimeTypes.h"

namespace shcr::monitor
{
    [[nodiscard]] bool Start(
        const RuntimeContext& a_runtime,
        HandleTableView a_table,
        bool a_skipAttribution) noexcept;
}
