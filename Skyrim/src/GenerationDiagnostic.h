#pragma once

#include "FormAttribution.h"
#include "HandleTable.h"
#include "RuntimeTypes.h"

#include <cstdint>

namespace shcr::diagnostic
{
    struct EventSnapshot
    {
        std::uint64_t totalWraps = 0;
        std::uint64_t lastWrapEvent = 0;
        std::uint32_t unreliableSlot = 0;
    };

    [[nodiscard]] bool Prepare(
        const RuntimeContext& a_runtime,
        HandleTableView a_table,
        bool a_enabled,
        AttributionContext* a_attribution) noexcept;

    [[nodiscard]] bool Install() noexcept;
    void CancelPrepared() noexcept;

    [[nodiscard]] bool IsActive() noexcept;
    [[nodiscard]] std::uint32_t AssignmentCount(
        std::uint32_t a_index) noexcept;
    void MarkUnreliable(std::uint32_t a_slot) noexcept;
    [[nodiscard]] EventSnapshot ReadEventSnapshot() noexcept;

    void LogStatus(
        bool a_skipAttribution,
        std::uint64_t a_trackedAssignments,
        std::uint64_t a_trackedSlots,
        std::uint64_t a_untrackedLive) noexcept;

}
