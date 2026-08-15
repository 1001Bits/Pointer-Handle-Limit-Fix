#pragma once

#include "FormAttribution.h"
#include "HandleTable.h"
#include "RuntimeTypes.h"

#include <cstdint>

namespace shcr::diagnostic
{
    struct EventSnapshot
    {
        // Compatibility names retained for the existing stress/reporting API.
        // The pre-publication guard has no mutation path for either value: a
        // repeated generation is fail-stopped before it becomes resolvable.
        std::uint64_t totalWraps = 0;
        std::uint64_t lastWrapEvent = 0;
        // These identify an attempted generation repeat which the guard
        // recorded immediately before terminating the process. High dword of
        // lastPreventedEvent = attempted reuse count; low dword = raw handle.
        std::uint64_t preventedWrapAttempts = 0;
        std::uint64_t lastPreventedEvent = 0;
        // High dword = greatest exact successfully published reuse count; low
        // dword = the handle observed at that assignment. Strict-greater
        // updates retain the first slot when several slots tie.
        std::uint64_t hottestHandle = 0;
        std::uint32_t reservedPlayerAssignments = 0;
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
    [[nodiscard]] std::uint32_t ReservedPlayerAssignmentCount() noexcept;
    void MarkUnreliable(std::uint32_t a_slot) noexcept;
    [[nodiscard]] EventSnapshot ReadEventSnapshot() noexcept;

    void LogStatus(
        bool a_skipAttribution,
        std::uint64_t a_trackedAssignments,
        std::uint64_t a_trackedSlots,
        std::uint64_t a_untrackedLive) noexcept;

}
