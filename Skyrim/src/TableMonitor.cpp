#include "TableMonitor.h"

#include "EngineAccess.h"
#include "GenerationDiagnostic.h"
#include "GenerationTracker.h"
#include "Logging.h"
#include "PatchTransaction.h"
#include "PatchTable.g.h"
#include "ReservedPlayerSlot.h"

#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <new>

namespace shcr::monitor
{
    namespace
    {
        constexpr std::uint32_t kVanillaHandleEntries = player_slot::kIndex;
        constexpr std::uint32_t kReporterTickMilliseconds = 60u * 1000u;
        constexpr std::uint32_t kUsageReportIntervalMinutes = 5u;
        constexpr std::uint32_t kUsageScanEntriesPerLock = 0x10000;

        static_assert(sizeof(HandleEntry) == 0x10);
        static_assert(offsetof(HandleEntry, bits) == 0x00);
        static_assert(offsetof(HandleEntry, pad) == 0x04);
        static_assert(offsetof(HandleEntry, pointer) == 0x08);

        enum class PlayerReservationState : std::uint8_t
        {
            kNotApplicable,
            kDetached,
            kLive,
            kInvalid,
        };

        struct PlayerReservationSnapshot
        {
            PlayerReservationState state =
                PlayerReservationState::kNotApplicable;
            std::uint32_t bits = 0;
            std::uint32_t pad = 0;
            std::uint32_t rawHandle = 0;
            std::uint32_t freeHead = 0;
            std::uint32_t freeTail = 0;
            void* pointer = nullptr;
            void* playerSingleton = nullptr;
            bool inUse = false;
        };

        struct Context
        {
            RuntimeContext     runtime;
            const HandleEntry* table;
            std::uint32_t      entryCount;
            ULONGLONG          nextTick;
            std::uint64_t      elapsedMinutes;
            bool               skipAttribution;
            patch::ReservedPlayerLifecycleSnapshot playerLifecycle;
            std::uint32_t      lifecycleAssignments;
            bool               lifecycleTracking;
            bool               reportedPlayerLifecycle;
            PlayerReservationSnapshot playerReservation;
            bool               reportedPlayerReservation;
        };

        [[nodiscard]] bool ReservationApplies(
            const Context& a_context) noexcept
        {
            return a_context.table != nullptr &&
                   a_context.entryCount == generation::kEntryCount;
        }

        [[nodiscard]] const char* ReservationStateName(
            PlayerReservationState a_state) noexcept
        {
            switch (a_state) {
            case PlayerReservationState::kDetached:
                return "detached";
            case PlayerReservationState::kLive:
                return "live-player";
            case PlayerReservationState::kInvalid:
                return "INVALID";
            default:
                return "n/a";
            }
        }

        [[nodiscard]] PlayerReservationSnapshot CapturePlayerReservation(
            Context& a_context) noexcept
        {
            PlayerReservationSnapshot snapshot;
            if (!ReservationApplies(a_context))
                return snapshot;

            snapshot.state = PlayerReservationState::kInvalid;
            if (!a_context.runtime.profile ||
                a_context.runtime.profile->playerSingletonRva == 0) {
                return snapshot;
            }

            HandleEntry entry{};
            LockManager(a_context.runtime, *a_context.runtime.profile);
            snapshot.playerSingleton =
                *reinterpret_cast<void* const*>(
                    a_context.runtime.imageBase +
                    a_context.runtime.profile->playerSingletonRva);
            snapshot.freeHead =
                *reinterpret_cast<const std::uint32_t*>(
                    a_context.runtime.imageBase +
                    a_context.runtime.profile->headRva);
            snapshot.freeTail =
                *reinterpret_cast<const std::uint32_t*>(
                    a_context.runtime.imageBase +
                    a_context.runtime.profile->tailRva);
            entry = a_context.table[player_slot::kIndex];
            snapshot.bits = entry.bits;
            snapshot.pad = entry.pad;
            snapshot.pointer = entry.pointer;
            UnlockManager(a_context.runtime, *a_context.runtime.profile);

            snapshot.inUse =
                (snapshot.bits & generation::kInUseMask) != 0;
            snapshot.rawHandle = generation::HandleFromEntryBits(
                player_slot::kIndex, snapshot.bits);
            if (snapshot.freeHead == player_slot::kIndex ||
                snapshot.freeTail == player_slot::kIndex) {
                return snapshot;
            }
            if (!snapshot.inUse) {
                if (player_slot::IsDetached(entry)) {
                    snapshot.state = PlayerReservationState::kDetached;
                }
                return snapshot;
            }

            const void* expectedSubobject = snapshot.playerSingleton ?
                static_cast<const std::uint8_t*>(snapshot.playerSingleton) +
                    0x20 :
                nullptr;
            if (player_slot::IsLiveGenerationZero(entry) &&
                snapshot.pad == 0 &&
                snapshot.pointer == expectedSubobject &&
                snapshot.rawHandle == player_slot::kVanillaRawHandle) {
                snapshot.state = PlayerReservationState::kLive;
            }
            return snapshot;
        }

        [[nodiscard]] bool SameReservationObservation(
            const PlayerReservationSnapshot& a_left,
            const PlayerReservationSnapshot& a_right) noexcept
        {
            return a_left.state == a_right.state &&
                   a_left.bits == a_right.bits &&
                   a_left.pad == a_right.pad &&
                   a_left.freeHead == a_right.freeHead &&
                   a_left.freeTail == a_right.freeTail &&
                   a_left.pointer == a_right.pointer &&
                   a_left.playerSingleton == a_right.playerSingleton;
        }

        void ReportPlayerReservation(
            Context& a_context,
            const PlayerReservationSnapshot& a_snapshot) noexcept
        {
            if (a_context.reportedPlayerReservation &&
                SameReservationObservation(
                    a_context.playerReservation, a_snapshot)) {
                return;
            }

            a_context.playerReservation = a_snapshot;
            a_context.reportedPlayerReservation = true;
            switch (a_snapshot.state) {
            case PlayerReservationState::kDetached:
                Log("player reservation: detached sentinel PASS; slot=%06X "
                    "bits=%08X and neither FIFO endpoint references the slot "
                    "(full-chain verification is stress-only).",
                    player_slot::kIndex, a_snapshot.bits);
                break;
            case PlayerReservationState::kLive:
                Log("player reservation: live-player PASS; slot=%06X "
                    "rawHandle=%08X object=%p singleton=%p generation=0.",
                    player_slot::kIndex, a_snapshot.rawHandle,
                    a_snapshot.pointer, a_snapshot.playerSingleton);
                break;
            case PlayerReservationState::kInvalid:
                Log("CRITICAL: reserved player slot invariant failed: "
                    "slot=%06X bits=%08X pad=%08X pointer=%p singleton=%p "
                    "rawHandle=%08X head=%08X tail=%08X; expected detached "
                    "bits=%08X or a "
                    "generation-zero live pointer to PlayerCharacter.",
                    player_slot::kIndex, a_snapshot.bits, a_snapshot.pad,
                    a_snapshot.pointer, a_snapshot.playerSingleton,
                    a_snapshot.rawHandle, a_snapshot.freeHead,
                    a_snapshot.freeTail, player_slot::kDetachedBits);
                break;
            default:
                break;
            }
        }

        void ReportPlayerLifecycle(
            Context& a_context,
            const PlayerReservationSnapshot& a_reservation) noexcept
        {
            const patch::ReservedPlayerLifecycleSnapshot lifecycle =
                patch::ReadReservedPlayerLifecycleSnapshot();
            const bool tracking = diagnostic::IsActive();
            const std::uint32_t assignments = tracking ?
                diagnostic::ReservedPlayerAssignmentCount() : 0;
            if (a_context.reportedPlayerLifecycle &&
                lifecycle.constructorAssignments ==
                    a_context.playerLifecycle.constructorAssignments &&
                lifecycle.releaseQuarantines ==
                    a_context.playerLifecycle.releaseQuarantines &&
                assignments == a_context.lifecycleAssignments &&
                tracking == a_context.lifecycleTracking) {
                return;
            }

            const std::uint64_t constructorDelta =
                lifecycle.constructorAssignments >=
                    a_context.playerLifecycle.constructorAssignments ?
                lifecycle.constructorAssignments -
                    a_context.playerLifecycle.constructorAssignments :
                lifecycle.constructorAssignments;
            const std::uint64_t quarantineDelta =
                lifecycle.releaseQuarantines >=
                    a_context.playerLifecycle.releaseQuarantines ?
                lifecycle.releaseQuarantines -
                    a_context.playerLifecycle.releaseQuarantines :
                lifecycle.releaseQuarantines;
            const std::uint32_t assignmentDelta =
                assignments >= a_context.lifecycleAssignments ?
                assignments - a_context.lifecycleAssignments : assignments;
            Log("player lifecycle counters: constructorAssignments=%llu "
                "(+%llu) releaseQuarantines=%llu (+%llu) "
                "lifecycleAssignments=%u (+%u) tracking=%s "
                "reservation=%s raw=%08X",
                static_cast<unsigned long long>(
                    lifecycle.constructorAssignments),
                static_cast<unsigned long long>(constructorDelta),
                static_cast<unsigned long long>(
                    lifecycle.releaseQuarantines),
                static_cast<unsigned long long>(quarantineDelta),
                assignments, assignmentDelta,
                tracking ? "active" : "disabled",
                ReservationStateName(a_reservation.state),
                a_reservation.rawHandle);

            a_context.playerLifecycle = lifecycle;
            a_context.lifecycleAssignments = assignments;
            a_context.lifecycleTracking = tracking;
            a_context.reportedPlayerLifecycle = true;
        }

        DWORD WINAPI ReporterThread(void* a_rawContext)
        {
            auto* context = static_cast<Context*>(a_rawContext);
            for (;;) {
                ULONGLONG now = GetTickCount64();
                if (now < context->nextTick) {
                    Sleep(static_cast<DWORD>(context->nextTick - now));
                    continue;
                }

                const PlayerReservationSnapshot playerReservation =
                    CapturePlayerReservation(*context);
                ReportPlayerReservation(*context, playerReservation);
                ReportPlayerLifecycle(*context, playerReservation);

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
                        if (ReservationApplies(*context) &&
                            index == player_slot::kIndex) {
                            if (playerReservation.inUse) {
                                ++inUse;
                                highest = index;
                                hasLiveHandle = true;
                            }
                            continue;
                        }
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

                const std::uint64_t physicalFreeCount =
                    context->entryCount - inUse;
                const std::uint64_t reservedUnavailable =
                    ReservationApplies(*context) &&
                        !playerReservation.inUse ?
                    1u : 0u;
                const std::uint64_t allocatableFreeCount =
                    physicalFreeCount - reservedUnavailable;
                if (hasLiveHandle) {
                    Log("handle usage: inUse=%llu/%u allocatableFree=%llu "
                        "physicalFree=%llu aboveVanilla=%llu highest=%06X "
                        "playerReservation=%s (rolling locked snapshot)",
                        static_cast<unsigned long long>(inUse),
                        context->entryCount,
                        static_cast<unsigned long long>(allocatableFreeCount),
                        static_cast<unsigned long long>(physicalFreeCount),
                        static_cast<unsigned long long>(aboveVanilla),
                        highest,
                        ReservationStateName(playerReservation.state));
                } else {
                    Log("handle usage: inUse=0/%u allocatableFree=%llu "
                        "physicalFree=%llu aboveVanilla=0 highest=none "
                        "playerReservation=%s (rolling locked snapshot)",
                        context->entryCount,
                        static_cast<unsigned long long>(allocatableFreeCount),
                        static_cast<unsigned long long>(physicalFreeCount),
                        ReservationStateName(playerReservation.state));
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
            a_skipAttribution,
            {},
            0,
            false,
            false,
            {},
            false,
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
        Log("handle usage reporting armed: the reserved player slot is checked "
            "every minute; normal usage, hottest successful reuse, "
            "publishedWraps=0, and prevented-attempt state first report in "
            "five minutes, then every five minutes.");
        return true;
    }
}
