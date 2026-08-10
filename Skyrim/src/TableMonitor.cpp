#include "TableMonitor.h"

#include "EngineAccess.h"
#include "GenerationDiagnostic.h"
#include "GenerationTracker.h"
#include "Logging.h"
#include "PatchTable.g.h"

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <new>

namespace shcr::monitor
{
    namespace
    {
        constexpr std::uint32_t kVanillaHandleEntries = 0x100000;
        constexpr std::uint32_t kReporterTickMilliseconds = 60u * 1000u;
        constexpr std::uint32_t kUsageReportIntervalMinutes = 5u;
        constexpr std::uint32_t kUsageScanEntriesPerLock = 0x10000;

        struct Context
        {
            RuntimeContext     runtime;
            const HandleEntry* table;
            std::uint32_t      entryCount;
            ULONGLONG          nextTick;
            std::uint64_t      elapsedMinutes;
            std::uint64_t      reportedWraps;
            bool               reportedUnreliable;
            bool               skipAttribution;
        };

        DWORD WINAPI ReporterThread(void* a_rawContext)
        {
            auto* context = static_cast<Context*>(a_rawContext);
            for (;;) {
                ULONGLONG now = GetTickCount64();
                if (now < context->nextTick) {
                    Sleep(static_cast<DWORD>(context->nextTick - now));
                    continue;
                }

                if (diagnostic::IsActive()) {
                    const diagnostic::EventSnapshot events =
                        diagnostic::ReadEventSnapshot();
                    if (events.totalWraps != context->reportedWraps) {
                        const std::uint32_t reuseCount =
                            static_cast<std::uint32_t>(
                                events.lastWrapEvent >> 32);
                        const std::uint32_t handle =
                            static_cast<std::uint32_t>(
                                events.lastWrapEvent);
                        const std::uint32_t slot =
                            handle & generation::kIndexMask;
                        Log("CRITICAL: HANDLE GENERATION WRAP DETECTED: "
                            "wraps=%llu (+%llu), slot=%06X reuseCount=%u "
                            "newHandle=%08X; the six-bit generation repeated "
                            "after %u reuses and stale-handle aliasing is now "
                            "possible.",
                            static_cast<unsigned long long>(events.totalWraps),
                            static_cast<unsigned long long>(
                                events.totalWraps - context->reportedWraps),
                            slot, reuseCount, handle,
                            generation::kGenerationCount);
                        context->reportedWraps = events.totalWraps;
                    }
                    const std::uint32_t unreliable =
                        events.unreliableSlot;
                    if (unreliable != 0 &&
                        !context->reportedUnreliable) {
                        if (unreliable == UINT32_MAX) {
                            Log("CRITICAL: generation-wrap detector lost exact "
                                "tracking at an invalid assignment destination; "
                                "wrap totals are now unreliable.");
                        } else {
                            Log("CRITICAL: generation-wrap detector lost exact "
                                "tracking at slot %06X; its uint32 counter "
                                "saturated or its generation disagreed with "
                                "Skyrim. Wrap totals are now unreliable.",
                                unreliable - 1u);
                        }
                        context->reportedUnreliable = true;
                    }
                }

                std::uint64_t elapsed = 0;
                do {
                    context->nextTick += kReporterTickMilliseconds;
                    ++elapsed;
                } while (context->nextTick <= now);
                const std::uint64_t previousMinutes =
                    context->elapsedMinutes;
                context->elapsedMinutes += elapsed;
                if (previousMinutes / kUsageReportIntervalMinutes ==
                    context->elapsedMinutes /
                        kUsageReportIntervalMinutes) {
                    continue;
                }

                std::uint64_t inUse = 0;
                std::uint64_t aboveVanilla = 0;
                std::uint64_t trackedAssignments = 0;
                std::uint64_t trackedSlots = 0;
                std::uint64_t untrackedLive = 0;
                std::uint32_t highest = 0;
                bool hasLiveHandle = false;
                const bool detectorActive = diagnostic::IsActive();
                for (std::uint32_t begin = 0;
                     begin < context->entryCount;
                     begin += kUsageScanEntriesPerLock) {
                    const std::uint32_t end = (std::min)(
                        context->entryCount,
                        begin + kUsageScanEntriesPerLock);
                    LockManager(context->runtime,
                        *context->runtime.profile);
                    for (std::uint32_t index = begin;
                         index < end; ++index) {
                        std::uint32_t assignments = 0;
                        if (detectorActive) {
                            assignments =
                                diagnostic::AssignmentCount(index);
                            if (assignments != 0) {
                                ++trackedSlots;
                                trackedAssignments += assignments;
                            }
                        }
                        if ((context->table[index].bits &
                                generation::kInUseMask) == 0) {
                            continue;
                        }
                        ++inUse;
                        if (detectorActive && assignments == 0) {
                            ++untrackedLive;
                            diagnostic::MarkUnreliable(index);
                        }
                        if (index >= kVanillaHandleEntries)
                            ++aboveVanilla;
                        highest = index;
                        hasLiveHandle = true;
                    }
                    UnlockManager(context->runtime,
                        *context->runtime.profile);
                    SwitchToThread();
                }

                const std::uint64_t freeCount =
                    context->entryCount - inUse;
                if (hasLiveHandle) {
                    Log("handle usage: inUse=%llu/%u free=%llu "
                        "aboveVanilla=%llu highest=%06X "
                        "(rolling locked snapshot)",
                        static_cast<unsigned long long>(inUse),
                        context->entryCount,
                        static_cast<unsigned long long>(freeCount),
                        static_cast<unsigned long long>(aboveVanilla),
                        highest);
                } else {
                    Log("handle usage: inUse=0/%u free=%u "
                        "aboveVanilla=0 highest=none "
                        "(rolling locked snapshot)",
                        context->entryCount, context->entryCount);
                }
                diagnostic::LogStatus(context->skipAttribution,
                    trackedAssignments, trackedSlots, untrackedLive);
            }
        }
    }

    bool Start(
        const RuntimeContext& a_runtime,
        HandleTableView a_table,
        bool a_skipAttribution) noexcept
    {
        auto* context = new (std::nothrow) Context{
            a_runtime,
            a_table.entries,
            a_table.count,
            GetTickCount64() + kReporterTickMilliseconds,
            0,
            0,
            false,
            a_skipAttribution,
        };
        if (!context) {
            Log("WARNING: could not allocate the five-minute handle-usage "
                "reporter; the cap raise remains active.");
            return false;
        }
        HANDLE thread = CreateThread(
            nullptr, 0, &ReporterThread, context, 0, nullptr);
        if (!thread) {
            const DWORD error = GetLastError();
            delete context;
            Log("WARNING: could not start the five-minute handle-usage "
                "reporter (error %lu); the cap raise remains active.", error);
            return false;
        }
        CloseHandle(thread);
        Log("handle usage reporting armed: normal status first reports in five "
            "minutes, then every five minutes; enabled generation diagnostics "
            "are polled every minute.");
        return true;
    }
}
