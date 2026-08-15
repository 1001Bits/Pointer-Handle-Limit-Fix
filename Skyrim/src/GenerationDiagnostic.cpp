#include "GenerationDiagnostic.h"

#include "EngineAccess.h"
#include "GenerationTracker.h"
#include "Logging.h"
#include "PatchTransaction.h"
#include "PatchTable.g.h"
#include "ReservedPlayerSlot.h"

#include <windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace shcr::diagnostic
{
    namespace
    {
        constexpr std::size_t kAssignmentRelayBytes = 14;
        constexpr std::size_t kAssignmentRelayAllocationBytes = 0x1000;
        constexpr DWORD kGenerationGuardExitCode = 0x53485752u;
        static_assert(kGenerationGuardExitCode == 0x53485752u);

        using AssignmentHelperFunction = void* (__fastcall*)(void**, void*);
        static_assert(
            std::atomic<AssignmentHelperFunction>::is_always_lock_free);
        static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
        static_assert(std::atomic<std::uint32_t>::is_always_lock_free);
        static_assert(std::atomic_ref<std::uint32_t>::is_always_lock_free);
        static_assert(alignof(std::uint32_t) >=
                      std::atomic_ref<std::uint32_t>::required_alignment);

        RuntimeContext      g_runtime;
        AttributionContext* g_attribution = nullptr;
        const Profile*      g_profile = nullptr;
        std::uint32_t*      g_slotAssignments = nullptr;
        std::uint8_t*       g_assignmentRelay = nullptr;
        const HandleEntry*  g_generationTable = nullptr;
        std::uint32_t       g_generationEntryCount = 0;
        std::atomic<AssignmentHelperFunction> g_originalAssignmentHelper{
            nullptr
        };
        std::atomic<bool> g_generationDetectorActive{ false };
        std::atomic<std::uint64_t> g_hottestHandle{ 0 };
        std::atomic<std::uint64_t> g_preventedWrapAttempts{ 0 };
        std::atomic<std::uint64_t> g_lastPreventedEvent{ 0 };
        std::atomic<std::uint32_t> g_reservedPlayerAssignments{ 0 };
        std::atomic<std::uint32_t> g_unreliableSlot{ 0 };

        struct PendingAssignment
        {
            std::uint32_t index = 0;
            std::uint32_t bits = 0;
            generation::Transition transition{};
            bool reservedPlayer = false;
        };

        [[nodiscard]] std::uint32_t LoadAssignmentCount(
            std::uint32_t a_index) noexcept
        {
            std::atomic_ref<std::uint32_t> counter(
                g_slotAssignments[a_index]);
            return counter.load(std::memory_order_acquire);
        }

        void StoreAssignmentCount(
            std::uint32_t a_index, std::uint32_t a_count) noexcept
        {
            std::atomic_ref<std::uint32_t> counter(
                g_slotAssignments[a_index]);
            counter.store(a_count, std::memory_order_release);
        }

        void UpdateHottest(
            std::uint32_t a_reuseCount,
            std::uint32_t a_handle,
            bool a_logHighWater) noexcept
        {
            if (a_reuseCount == 0)
                return;
            const std::uint64_t candidate =
                (static_cast<std::uint64_t>(a_reuseCount) << 32) | a_handle;
            std::uint64_t hottest =
                g_hottestHandle.load(std::memory_order_relaxed);
            while (a_reuseCount >
                   static_cast<std::uint32_t>(hottest >> 32)) {
                if (g_hottestHandle.compare_exchange_weak(
                        hottest, candidate, std::memory_order_release,
                        std::memory_order_relaxed)) {
                    // This runs inside Skyrim's manager write lock. Log takes
                    // only its private SRW lock and never calls back into the
                    // manager. Successful publications can advance this at
                    // most 31 times before the mandatory guard fail-stops.
                    if (a_logHighWater) {
                        Log("generation reuse high-water: reuse=%u slot=%06X "
                            "handle=%08X safeReuseLimit=%u guard=active "
                            "publishedWraps=0",
                            a_reuseCount,
                            a_handle & generation::kIndexMask,
                            a_handle, generation::kSafeReuseLimit);
                        if (a_reuseCount == generation::kSafeReuseLimit) {
                            Log("WARNING: generation reuse reached safe limit: "
                                "reuse=%u slot=%06X handle=%08X "
                                "safeReuseLimit=%u guard=active "
                                "publishedWraps=0; the next reuse of this slot "
                                "will fail-stop before resolvability.",
                                a_reuseCount,
                                a_handle & generation::kIndexMask,
                                a_handle, generation::kSafeReuseLimit);
                        }
                    }
                    return;
                }
            }
        }

        [[noreturn]] void TerminateForAssignmentGuard() noexcept
        {
            Log("Terminating Skyrim before assignment-function return and "
                "manager unlock can expose invalid handle state. The "
                "preceding FATAL line records the exact publication stage.");
            TerminateProcess(GetCurrentProcess(), kGenerationGuardExitCode);
            ExitProcess(kGenerationGuardExitCode);
        }

        [[noreturn]] void FatalAssignmentGuard(
            const char* a_reason,
            std::uint32_t a_index,
            std::uint32_t a_bits,
            std::uint32_t a_priorAssignments) noexcept
        {
            const unsigned long long prevented =
                static_cast<unsigned long long>(
                    g_preventedWrapAttempts.load(std::memory_order_acquire));
            Log("FATAL: pre-publication generation guard: %s; slot=%06X "
                "entryBits=%08X priorAssignments=%u nextHandle=%08X "
                "safeReuseLimit=%u publishedWraps=0 "
                "preventedWrapAttempts=%llu",
                a_reason ? a_reason : "unknown invariant failure",
                a_index, a_bits, a_priorAssignments,
                generation::HandleFromEntryBits(a_index, a_bits),
                generation::kSafeReuseLimit, prevented);
            TerminateForAssignmentGuard();
        }

        [[noreturn]] void PreventRepeatedGeneration(
            std::uint32_t a_index,
            std::uint32_t a_bits,
            std::uint32_t a_priorAssignments) noexcept
        {
            const std::uint32_t handle =
                generation::HandleFromEntryBits(a_index, a_bits);
            const std::uint64_t event =
                (static_cast<std::uint64_t>(a_priorAssignments) << 32) |
                handle;
            // Record the exact prevented event separately from the successful
            // high-water. The hottest published reuse therefore remains 31;
            // the slot counter is deliberately not committed, and no
            // published-wrap counter exists anywhere in this implementation.
            g_lastPreventedEvent.store(event, std::memory_order_relaxed);
            const std::uint64_t prevented =
                g_preventedWrapAttempts.fetch_add(
                    1, std::memory_order_release) + 1u;
            Log("FATAL: pre-publication generation guard: generation repeat "
                "prevented before table-pointer publication; slot=%06X "
                "entryBits=%08X priorAssignments=%u nextHandle=%08X "
                "tablePointer=null objectCachePublished=0 "
                "assignmentReturned=0 managerUnlocked=0 safeReuseLimit=%u "
                "publishedWraps=0 preventedWrapAttempts=%llu",
                a_index, a_bits, a_priorAssignments, handle,
                generation::kSafeReuseLimit,
                static_cast<unsigned long long>(prevented));
            Log("Generation-repeat boundary detail: the caller's transient "
                "output dword may already contain the next five-bit age, but "
                "tablePointer=null keeps the repeated handle unresolvable.");
            TerminateForAssignmentGuard();
        }

        [[nodiscard]] PendingAssignment PrepareAssignment(
            void** a_destination, void* a_subobject) noexcept
        {
            if (!a_destination || !a_subobject || !g_slotAssignments ||
                !g_generationTable) {
                FatalAssignmentGuard("incomplete assignment state",
                    UINT32_MAX, 0, 0);
            }

            const std::uintptr_t table =
                reinterpret_cast<std::uintptr_t>(g_generationTable);
            const std::uintptr_t firstPointer =
                table + offsetof(HandleEntry, pointer);
            const std::uintptr_t destinationAddress =
                reinterpret_cast<std::uintptr_t>(a_destination);
            if (destinationAddress < firstPointer) {
                FatalAssignmentGuard("destination precedes the raised table",
                    UINT32_MAX, 0, 0);
            }
            const std::uintptr_t byteOffset =
                destinationAddress - firstPointer;
            if ((byteOffset % sizeof(HandleEntry)) != 0) {
                FatalAssignmentGuard("destination is not an entry pointer field",
                    UINT32_MAX, 0, 0);
            }
            const std::uintptr_t wideIndex = byteOffset / sizeof(HandleEntry);
            if (wideIndex >= g_generationEntryCount) {
                FatalAssignmentGuard("destination lies beyond the raised table",
                    UINT32_MAX, 0, 0);
            }

            const std::uint32_t index =
                static_cast<std::uint32_t>(wideIndex);
            const HandleEntry& entry = g_generationTable[index];
            const std::uint32_t bits = entry.bits;
            if (*a_destination != nullptr || entry.pad != 0 ||
                (bits & generation::kInUseMask) == 0) {
                FatalAssignmentGuard(
                    "fresh entry was already published or malformed",
                    index, bits, 0);
            }

            if (index == player_slot::kIndex) {
                const std::uint32_t handle =
                    generation::HandleFromEntryBits(index, bits);
                if (!player_slot::HasLiveGenerationZeroState(bits) ||
                    handle != player_slot::kVanillaRawHandle) {
                    FatalAssignmentGuard(
                        "reserved player assignment lost generation zero",
                        index, bits, 0);
                }
                const std::uint32_t count =
                    g_reservedPlayerAssignments.load(
                        std::memory_order_relaxed);
                if (count == UINT32_MAX) {
                    FatalAssignmentGuard(
                        "reserved player assignment counter saturated",
                        index, bits, count);
                }
                return { index, bits, {}, true };
            }

            const std::uint32_t priorAssignments =
                LoadAssignmentCount(index);
            const generation::Transition transition =
                generation::ObserveAssignment(priorAssignments,
                    generation::GenerationFromEntryBits(bits));
            if (transition.saturated) {
                FatalAssignmentGuard("assignment counter saturated",
                    index, bits, priorAssignments);
            }
            if (!transition.generationMatches) {
                FatalAssignmentGuard(
                    "entry generation disagrees with the exact slot counter",
                    index, bits, priorAssignments);
            }
            if (transition.abaWrap) {
                PreventRepeatedGeneration(index, bits, priorAssignments);
            }
            return { index, bits, transition, false };
        }

        void CommitAssignment(
            const PendingAssignment& a_pending,
            void** a_destination,
            void* a_subobject,
            void* a_result) noexcept
        {
            const HandleEntry& entry =
                g_generationTable[a_pending.index];
            if (a_result != a_destination || *a_destination != a_subobject ||
                entry.pointer != a_subobject || entry.pad != 0 ||
                entry.bits != a_pending.bits) {
                FatalAssignmentGuard(
                    "stock pointer publisher did not preserve the prepared assignment",
                    a_pending.index, entry.bits,
                    a_pending.reservedPlayer ? 0 :
                        a_pending.transition.reuseCount);
            }

            if (a_pending.reservedPlayer) {
                const std::uint32_t prior =
                    g_reservedPlayerAssignments.fetch_add(
                        1, std::memory_order_release);
                if (prior == UINT32_MAX) {
                    FatalAssignmentGuard(
                        "reserved player assignment counter overflowed",
                        a_pending.index, entry.bits, prior);
                }
                return;
            }

            StoreAssignmentCount(a_pending.index,
                a_pending.transition.assignmentCount);

            const std::uint32_t handle =
                generation::HandleFromEntryBits(a_pending.index, entry.bits);
            UpdateHottest(a_pending.transition.reuseCount, handle, true);
        }

        void* __fastcall AssignmentHelperHook(
            void** a_destination, void* a_subobject) noexcept
        {
            const AssignmentHelperFunction original =
                g_originalAssignmentHelper.load(std::memory_order_acquire);
            if (!original) {
                FatalAssignmentGuard(
                    "assignment hook became reachable without its stock publisher",
                    UINT32_MAX, 0, 0);
            }
            const PendingAssignment pending =
                PrepareAssignment(a_destination, a_subobject);
            void* const result = original(a_destination, a_subobject);
            CommitAssignment(pending, a_destination, a_subobject, result);
            return result;
        }

        [[nodiscard]] bool TextContains(
            std::uint32_t a_rva, std::size_t a_bytes) noexcept
        {
            const std::uintptr_t begin =
                reinterpret_cast<std::uintptr_t>(g_runtime.text.begin);
            const std::uintptr_t address = g_runtime.imageBase + a_rva;
            return address >= begin && a_bytes <= g_runtime.text.size &&
                address - begin <= g_runtime.text.size - a_bytes;
        }

        [[nodiscard]] bool VerifyAssignmentHookTargets(
            const Profile& a_profile, bool a_logMismatch) noexcept
        {
            if (a_profile.assignmentHookSiteCount != 5 ||
                !a_profile.assignmentHookSites ||
                !TextContains(a_profile.assignmentHelperRva,
                    sizeof(a_profile.assignmentHelperBytes))) {
                if (a_logMismatch) {
                    Log("ERROR: generation-wrap guard profile has invalid "
                        "assignment-hook metadata; mandatory preparation refused.");
                }
                return false;
            }
            const auto* helper = reinterpret_cast<const std::uint8_t*>(
                g_runtime.imageBase + a_profile.assignmentHelperRva);
            if (std::memcmp(helper, a_profile.assignmentHelperBytes,
                    sizeof(a_profile.assignmentHelperBytes)) != 0) {
                if (a_logMismatch) {
                    Log("ERROR: generation-wrap guard assignment helper at "
                        "rva %08X differs from the verified runtime; guard "
                        "preparation refused.",
                        a_profile.assignmentHelperRva);
                }
                return false;
            }

            for (std::uint32_t index = 0;
                 index < a_profile.assignmentHookSiteCount; ++index) {
                const AssignmentHookSite& site =
                    a_profile.assignmentHookSites[index];
                if (site.callRva < sizeof(site.setupBytes) ||
                    !TextContains(
                        site.functionRva, sizeof(site.functionBytes)) ||
                    !TextContains(site.callRva -
                            static_cast<std::uint32_t>(sizeof(site.setupBytes)),
                        sizeof(site.setupBytes) + sizeof(site.callBytes))) {
                    if (a_logMismatch) {
                        Log("ERROR: generation-wrap guard site %u is outside "
                            ".text; mandatory preparation refused.",
                            index);
                    }
                    return false;
                }
                const auto* owner = reinterpret_cast<const std::uint8_t*>(
                    g_runtime.imageBase + site.functionRva);
                const auto* setup = reinterpret_cast<const std::uint8_t*>(
                    g_runtime.imageBase + site.callRva -
                    sizeof(site.setupBytes));
                const auto* call = reinterpret_cast<const std::uint8_t*>(
                    g_runtime.imageBase + site.callRva);
                std::int32_t displacement = 0;
                if (site.callBytes[0] != 0xE8 || call[0] != 0xE8 ||
                    std::memcmp(owner, site.functionBytes,
                        sizeof(site.functionBytes)) != 0 ||
                    std::memcmp(setup, site.setupBytes,
                        sizeof(site.setupBytes)) != 0 ||
                    std::memcmp(call, site.callBytes,
                        sizeof(site.callBytes)) != 0) {
                    if (a_logMismatch) {
                        Log("ERROR: generation-wrap guard assignment target "
                            "%u at rva %08X differs from the verified "
                            "owner/setup/call bytes; mandatory preparation "
                            "refused.", index, site.callRva);
                    }
                    return false;
                }
                std::memcpy(&displacement, call + 1, sizeof(displacement));
                const std::uintptr_t target = static_cast<std::uintptr_t>(
                    static_cast<std::int64_t>(
                        g_runtime.imageBase + site.callRva + 5u) +
                    displacement);
                if (target !=
                    g_runtime.imageBase + a_profile.assignmentHelperRva) {
                    if (a_logMismatch) {
                        Log("ERROR: generation-wrap guard call %u resolves "
                            "to %016llX, not verified helper %016llX; guard "
                            "preparation refused.", index,
                            static_cast<unsigned long long>(target),
                            static_cast<unsigned long long>(
                                g_runtime.imageBase +
                                a_profile.assignmentHelperRva));
                    }
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] bool RelayIsReachable(
            const Profile& a_profile, std::uintptr_t a_relay) noexcept
        {
            for (std::uint32_t index = 0;
                 index < a_profile.assignmentHookSiteCount; ++index) {
                const std::int64_t displacement =
                    static_cast<std::int64_t>(a_relay) -
                    static_cast<std::int64_t>(g_runtime.imageBase +
                        a_profile.assignmentHookSites[index].callRva + 5u);
                if (displacement < INT32_MIN || displacement > INT32_MAX)
                    return false;
            }
            return true;
        }

        [[nodiscard]] std::uint8_t* AllocateAssignmentRelay(
            const Profile& a_profile) noexcept
        {
            for (std::uintptr_t offset = 0x08000000u;
                 offset <= 0x70000000u; offset += 0x04000000u) {
                auto* relay = static_cast<std::uint8_t*>(VirtualAlloc(
                    reinterpret_cast<void*>(g_runtime.imageBase + offset),
                    kAssignmentRelayAllocationBytes,
                    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
                if (!relay)
                    continue;
                if (RelayIsReachable(
                        a_profile, reinterpret_cast<std::uintptr_t>(relay))) {
                    return relay;
                }
                VirtualFree(relay, 0, MEM_RELEASE);
            }
            auto* relay = static_cast<std::uint8_t*>(VirtualAlloc(
                nullptr, kAssignmentRelayAllocationBytes,
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (relay && !RelayIsReachable(
                    a_profile, reinterpret_cast<std::uintptr_t>(relay))) {
                VirtualFree(relay, 0, MEM_RELEASE);
                relay = nullptr;
            }
            return relay;
        }

        [[noreturn]] void FatalAssignmentHookRollback() noexcept
        {
            Log("FATAL: generation-wrap guard could not restore all five "
                "original assignment calls after a guard install failure.");
            Log("Terminating Skyrim because continuing through a partially "
                "written call site is unsafe; the cap-table transaction itself "
                "had succeeded.");
            TerminateProcess(GetCurrentProcess(), 0x53484744u);
            ExitProcess(0x44u);
        }

        [[nodiscard]] bool OriginalAssignmentCallsMatch(
            const Profile& a_profile) noexcept
        {
            for (std::uint32_t index = 0;
                 index < a_profile.assignmentHookSiteCount; ++index) {
                const AssignmentHookSite& site =
                    a_profile.assignmentHookSites[index];
                if (std::memcmp(reinterpret_cast<const void*>(
                            g_runtime.imageBase + site.callRva),
                        site.callBytes, sizeof(site.callBytes)) != 0) {
                    return false;
                }
            }
            return true;
        }

        void RestoreAssignmentCallsOrStop(
            const Profile& a_profile) noexcept
        {
            for (std::uint32_t index = 0;
                 index < a_profile.assignmentHookSiteCount; ++index) {
                const AssignmentHookSite& site =
                    a_profile.assignmentHookSites[index];
                std::memcpy(reinterpret_cast<void*>(
                        g_runtime.imageBase + site.callRva),
                    site.callBytes, sizeof(site.callBytes));
            }
            if (!OriginalAssignmentCallsMatch(a_profile) ||
                !FlushInstructionCache(GetCurrentProcess(),
                    g_runtime.text.begin, g_runtime.text.size)) {
                FatalAssignmentHookRollback();
            }
        }

        struct CurrentReferenceSnapshot
        {
            std::uint32_t reuseCount = 0;
            std::uint32_t slot = 0;
            std::uint32_t handle = 0;
            void* expectedReference = nullptr;
            void* pinnedReference = nullptr;
            std::uint32_t formID = 0;
            std::uint32_t baseFormID = 0;
            char sourcePlugin[260]{};
            char baseSourcePlugin[260]{};
            bool hasHottest = false;
            bool hasCurrentHandle = false;
            bool resolvedCurrentReference = false;
            bool attributionSkipped = false;
        };

        [[nodiscard]] CurrentReferenceSnapshot CaptureCurrentHottest(
            bool a_skipAttribution) noexcept
        {
            CurrentReferenceSnapshot snapshot;
            if (!g_profile)
                return snapshot;
            LockManager(g_runtime, *g_profile);
            const std::uint64_t hottest =
                g_hottestHandle.load(std::memory_order_acquire);
            snapshot.reuseCount = static_cast<std::uint32_t>(hottest >> 32);
            if (snapshot.reuseCount != 0) {
                snapshot.hasHottest = true;
                snapshot.slot = static_cast<std::uint32_t>(hottest) &
                    generation::kIndexMask;
                if (snapshot.slot < g_generationEntryCount) {
                    const std::uint32_t assignments =
                        LoadAssignmentCount(snapshot.slot);
                    if (assignments != 0) {
                        snapshot.reuseCount = assignments - 1u;
                        const HandleEntry& entry =
                            g_generationTable[snapshot.slot];
                        if ((entry.bits & generation::kInUseMask) != 0 &&
                            entry.pointer) {
                            snapshot.hasCurrentHandle = true;
                            snapshot.handle = generation::HandleFromEntryBits(
                                snapshot.slot, entry.bits);
                            snapshot.expectedReference =
                                static_cast<std::uint8_t*>(entry.pointer) - 0x20;
                        }
                    }
                }
            }
            UnlockManager(g_runtime, *g_profile);

            if (!snapshot.hasCurrentHandle)
                return snapshot;
            if (a_skipAttribution) {
                snapshot.attributionSkipped = true;
                return snapshot;
            }

            void* reference = nullptr;
            const bool resolved = ResolveSmartPointer(
                g_runtime, snapshot.handle, reference);
            if (resolved && reference &&
                reference == snapshot.expectedReference) {
                snapshot.resolvedCurrentReference = true;
                snapshot.pinnedReference = reference;
                snapshot.formID = *reinterpret_cast<const std::uint32_t*>(
                    static_cast<const std::uint8_t*>(reference) + 0x14);
                stress::ResolvedNames names;
                ResolveStressAttribution(g_attribution, reference, names);
                const char* source = names.originPlugin[0] != '\0' ?
                    names.originPlugin : names.winningPlugin;
                CopyAttributionText(snapshot.sourcePlugin,
                    sizeof(snapshot.sourcePlugin),
                    source && source[0] != '\0' ? source : "<unknown>",
                    sizeof(snapshot.sourcePlugin) - 1);
                snapshot.baseFormID = names.baseFormID;
                const char* baseSource =
                    names.baseOriginPlugin[0] != '\0' ?
                    names.baseOriginPlugin : names.baseWinningPlugin;
                if (snapshot.baseFormID != 0) {
                    CopyAttributionText(snapshot.baseSourcePlugin,
                        sizeof(snapshot.baseSourcePlugin),
                        baseSource && baseSource[0] != '\0' ?
                            baseSource : "<unknown>",
                        sizeof(snapshot.baseSourcePlugin) - 1);
                }
            }
            if (reference)
                ReleasePinnedReference(reference);
            return snapshot;
        }
    }

    void MarkUnreliable(std::uint32_t a_slot) noexcept
    {
        std::uint32_t unset = 0;
        const std::uint32_t encoded = a_slot < generation::kEntryCount ?
            a_slot + 1u : UINT32_MAX;
        g_unreliableSlot.compare_exchange_strong(
            unset, encoded, std::memory_order_release,
            std::memory_order_relaxed);
    }

    bool Prepare(
        const RuntimeContext& a_runtime,
        HandleTableView a_table,
        bool a_enabled,
        AttributionContext* a_attribution) noexcept
    {
        if (!a_enabled)
            return false;
        if (!a_runtime.profile ||
            a_runtime.profile->raisedEntries != generation::kEntryCount ||
            a_runtime.profile->entrySize != sizeof(HandleEntry)) {
            Log("generation-wrap guard geometry is invalid; mandatory "
                "preparation refused.");
            return false;
        }

        g_runtime = a_runtime;
        g_profile = a_runtime.profile;
        g_attribution = a_attribution;
        if (!VerifyAssignmentHookTargets(*g_profile, true)) {
            Log("generation-wrap guard target authentication failed; "
                "mandatory preparation refused.");
            g_profile = nullptr;
            return false;
        }

        const std::size_t counterBytes =
            static_cast<std::size_t>(a_table.count) * sizeof(std::uint32_t);
        g_slotAssignments = static_cast<std::uint32_t*>(VirtualAlloc(
            nullptr, counterBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!g_slotAssignments) {
            Log("ERROR: generation-wrap guard could not allocate its %zu-byte "
                "reuse-counter array (error %lu); mandatory preparation "
                "refused.", counterBytes, GetLastError());
            g_profile = nullptr;
            return false;
        }
        g_assignmentRelay = AllocateAssignmentRelay(*g_profile);
        if (!g_assignmentRelay) {
            Log("ERROR: generation-wrap guard could not allocate a "
                "rel32-reachable relay; mandatory preparation refused.");
            CancelPrepared();
            return false;
        }

        std::uint8_t relay[kAssignmentRelayBytes] = {
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        };
        const std::uintptr_t hook =
            reinterpret_cast<std::uintptr_t>(&AssignmentHelperHook);
        std::memcpy(relay + 6, &hook, sizeof(hook));
        std::memcpy(g_assignmentRelay, relay, sizeof(relay));
        DWORD oldProtection = 0;
        if (!VirtualProtect(g_assignmentRelay,
                kAssignmentRelayAllocationBytes, PAGE_EXECUTE_READ,
                &oldProtection) ||
            !FlushInstructionCache(GetCurrentProcess(),
                g_assignmentRelay, sizeof(relay))) {
            Log("ERROR: generation-wrap guard could not publish its relay "
                "(error %lu); mandatory preparation refused.",
                GetLastError());
            CancelPrepared();
            return false;
        }

        g_generationTable = a_table.entries;
        g_generationEntryCount = a_table.count;
        g_hottestHandle.store(0, std::memory_order_relaxed);
        g_preventedWrapAttempts.store(0, std::memory_order_relaxed);
        g_lastPreventedEvent.store(0, std::memory_order_relaxed);
        g_reservedPlayerAssignments.store(0, std::memory_order_relaxed);
        g_unreliableSlot.store(0, std::memory_order_relaxed);
        Log("pre-publication generation-wrap guard prepared: exact uint32 "
            "assignment counters for %u slots (%zu MiB) and one executable "
            "relay page.",
            a_table.count, counterBytes / (1024u * 1024u));
        return true;
    }

    void CancelPrepared() noexcept
    {
        if (g_generationDetectorActive.load(std::memory_order_acquire))
            return;
        g_originalAssignmentHelper.store(nullptr, std::memory_order_release);
        g_generationTable = nullptr;
        g_generationEntryCount = 0;
        if (g_assignmentRelay) {
            VirtualFree(g_assignmentRelay, 0, MEM_RELEASE);
            g_assignmentRelay = nullptr;
        }
        if (g_slotAssignments) {
            VirtualFree(g_slotAssignments, 0, MEM_RELEASE);
            g_slotAssignments = nullptr;
        }
        g_profile = nullptr;
        g_attribution = nullptr;
    }

    bool Install() noexcept
    {
        if (!g_profile || !g_slotAssignments || !g_assignmentRelay ||
            !VerifyAssignmentHookTargets(*g_profile, true)) {
            return false;
        }

        // Publish the authenticated stock helper before any call site can
        // reach the relay.  Installation runs under the manager write lock,
        // but this ordering also fails closed if a future runtime introduces
        // a publisher outside that lock.
        const AssignmentHelperFunction original =
            reinterpret_cast<AssignmentHelperFunction>(
                g_runtime.imageBase + g_profile->assignmentHelperRva);
        g_originalAssignmentHelper.store(original, std::memory_order_release);

        DWORD oldProtection = 0;
        if (!VirtualProtect(g_runtime.text.begin, g_runtime.text.size,
                PAGE_EXECUTE_READWRITE, &oldProtection)) {
            g_originalAssignmentHelper.store(nullptr, std::memory_order_release);
            Log("ERROR: generation-wrap guard could not make .text writable "
                "(error %lu); mandatory installation refused.",
                GetLastError());
            return false;
        }

        const std::uintptr_t relay =
            reinterpret_cast<std::uintptr_t>(g_assignmentRelay);
        for (std::uint32_t index = 0;
             index < g_profile->assignmentHookSiteCount; ++index) {
            const AssignmentHookSite& site =
                g_profile->assignmentHookSites[index];
            const std::int64_t wideDisplacement =
                static_cast<std::int64_t>(relay) -
                static_cast<std::int64_t>(
                    g_runtime.imageBase + site.callRva + 5u);
            const std::int32_t displacement =
                static_cast<std::int32_t>(wideDisplacement);
            std::uint8_t call[5] = { 0xE8, 0, 0, 0, 0 };
            std::memcpy(call + 1, &displacement, sizeof(displacement));
            std::memcpy(reinterpret_cast<void*>(
                    g_runtime.imageBase + site.callRva),
                call, sizeof(call));
        }

        bool callsGood = true;
        for (std::uint32_t index = 0;
             index < g_profile->assignmentHookSiteCount; ++index) {
            const AssignmentHookSite& site =
                g_profile->assignmentHookSites[index];
            const auto* call = reinterpret_cast<const std::uint8_t*>(
                g_runtime.imageBase + site.callRva);
            std::int32_t displacement = 0;
            std::memcpy(&displacement, call + 1, sizeof(displacement));
            const std::uintptr_t target = static_cast<std::uintptr_t>(
                static_cast<std::int64_t>(
                    g_runtime.imageBase + site.callRva + 5u) +
                displacement);
            callsGood = callsGood && call[0] == 0xE8 && target == relay;
        }
        const bool cacheGood = callsGood &&
            FlushInstructionCache(GetCurrentProcess(),
                g_runtime.text.begin, g_runtime.text.size) != FALSE;
        if (!cacheGood) {
            RestoreAssignmentCallsOrStop(*g_profile);
            DWORD ignored = 0;
            const bool protectionRestored = VirtualProtect(
                g_runtime.text.begin, g_runtime.text.size,
                oldProtection, &ignored) != FALSE;
            g_originalAssignmentHelper.store(nullptr, std::memory_order_release);
            Log("ERROR: generation-wrap guard call installation did not "
                "verify; all stock calls were restored%s. Mandatory "
                "installation refused.", protectionRestored ? "" :
                    ", but restoring .text page protection also failed");
            return false;
        }

        DWORD ignored = 0;
        if (!VirtualProtect(g_runtime.text.begin, g_runtime.text.size,
                oldProtection, &ignored)) {
            RestoreAssignmentCallsOrStop(*g_profile);
            DWORD retryIgnored = 0;
            const bool protectionRestored = VirtualProtect(
                g_runtime.text.begin, g_runtime.text.size,
                oldProtection, &retryIgnored) != FALSE;
            g_originalAssignmentHelper.store(nullptr, std::memory_order_release);
            Log("ERROR: generation-wrap guard could not restore .text page "
                "protection after installing; all stock calls were restored%s. "
                "Mandatory installation refused.", protectionRestored ? "" :
                    ", although .text remains writable/executable");
            return false;
        }

        g_generationDetectorActive.store(true, std::memory_order_release);
        Log("pre-publication generation-wrap guard installed at all %u "
            "verified Skyrim assignment sites: exact per-slot counters, "
            "21 index bits + 5 generation bits, maximum safe reuse=%u; "
            "a repeated generation terminates before table-pointer "
            "publication and resolvability.",
            g_profile->assignmentHookSiteCount,
            generation::kSafeReuseLimit);
        return true;
    }

    bool IsActive() noexcept
    {
        return g_generationDetectorActive.load(std::memory_order_acquire);
    }

    std::uint32_t AssignmentCount(std::uint32_t a_index) noexcept
    {
        return a_index != player_slot::kIndex && g_slotAssignments &&
            a_index < g_generationEntryCount ?
            LoadAssignmentCount(a_index) : 0;
    }

    std::uint32_t ReservedPlayerAssignmentCount() noexcept
    {
        return g_reservedPlayerAssignments.load(std::memory_order_acquire);
    }

    EventSnapshot ReadEventSnapshot() noexcept
    {
        EventSnapshot snapshot;
        // totalWraps and lastWrapEvent intentionally retain their zero
        // initializers. There is no post-publication wrap-recording path: the
        // attempt is recorded below and fail-stopped before it is resolvable.
        snapshot.preventedWrapAttempts =
            g_preventedWrapAttempts.load(std::memory_order_acquire);
        snapshot.lastPreventedEvent =
            g_lastPreventedEvent.load(std::memory_order_acquire);
        snapshot.hottestHandle =
            g_hottestHandle.load(std::memory_order_acquire);
        snapshot.unreliableSlot =
            g_unreliableSlot.load(std::memory_order_acquire);
        snapshot.reservedPlayerAssignments =
            g_reservedPlayerAssignments.load(std::memory_order_acquire);
        return snapshot;
    }

    void LogStatus(
        bool a_skipAttribution,
        std::uint64_t a_trackedAssignments,
        std::uint64_t a_trackedSlots,
        std::uint64_t a_untrackedLive) noexcept
    {
        if (!IsActive())
            return;
        const CurrentReferenceSnapshot snapshot =
            CaptureCurrentHottest(a_skipAttribution);
        const EventSnapshot events = ReadEventSnapshot();
        const unsigned long long publishedWraps =
            static_cast<unsigned long long>(events.totalWraps);
        const unsigned long long preventedWrapAttempts =
            static_cast<unsigned long long>(events.preventedWrapAttempts);
        const char* reliability =
            events.unreliableSlot == 0 ? "exact" : "UNRELIABLE";
        const bool reservedUnreliable =
            events.unreliableSlot == player_slot::kIndex + 1u ||
            events.unreliableSlot == UINT32_MAX;
        const patch::ReservedPlayerLifecycleSnapshot lifecycle =
            patch::ReadReservedPlayerLifecycleSnapshot();
        Log("player handle identity: reservedSlot=%06X raw=%08X "
            "lifecycleAssignments=%u constructorAssignments=%llu "
            "releaseQuarantines=%llu tracking=%s",
            player_slot::kIndex, player_slot::kVanillaRawHandle,
            events.reservedPlayerAssignments,
            static_cast<unsigned long long>(
                lifecycle.constructorAssignments),
            static_cast<unsigned long long>(lifecycle.releaseQuarantines),
            reservedUnreliable ? "UNRELIABLE" : "exact");
        if (!snapshot.hasHottest) {
            Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                "untrackedLive=%llu highest=0 safeReuseLimit=%u guard=active "
                "hottestSlot=none currentHandle=none currentReference=none "
                "FormID=none source=none publishedWraps=%llu "
                "preventedWrapAttempts=%llu tracking=%s",
                static_cast<unsigned long long>(a_trackedAssignments),
                static_cast<unsigned long long>(a_trackedSlots),
                static_cast<unsigned long long>(a_untrackedLive),
                generation::kSafeReuseLimit, publishedWraps,
                preventedWrapAttempts, reliability);
        } else if (!snapshot.hasCurrentHandle) {
            Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                "untrackedLive=%llu highest=%u safeReuseLimit=%u guard=active "
                "hottestSlot=%06X currentHandle=none (slot currently free) "
                "currentReference=none FormID=none source=none "
                "publishedWraps=%llu preventedWrapAttempts=%llu tracking=%s",
                static_cast<unsigned long long>(a_trackedAssignments),
                static_cast<unsigned long long>(a_trackedSlots),
                static_cast<unsigned long long>(a_untrackedLive),
                snapshot.reuseCount, generation::kSafeReuseLimit,
                snapshot.slot, publishedWraps, preventedWrapAttempts,
                reliability);
        } else if (snapshot.attributionSkipped) {
            Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                "untrackedLive=%llu highest=%u safeReuseLimit=%u guard=active "
                "hottestSlot=%06X currentHandle=%08X currentReference=%p "
                "FormID=skipped source=<private StressTest attribution "
                "skipped> publishedWraps=%llu preventedWrapAttempts=%llu "
                "tracking=%s",
                static_cast<unsigned long long>(a_trackedAssignments),
                static_cast<unsigned long long>(a_trackedSlots),
                static_cast<unsigned long long>(a_untrackedLive),
                snapshot.reuseCount, generation::kSafeReuseLimit,
                snapshot.slot, snapshot.handle, snapshot.expectedReference,
                publishedWraps, preventedWrapAttempts, reliability);
        } else if (!snapshot.resolvedCurrentReference) {
            Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                "untrackedLive=%llu highest=%u safeReuseLimit=%u guard=active "
                "hottestSlot=%06X currentHandle=%08X currentReference=not "
                "currently resolvable FormID=none source=none "
                "publishedWraps=%llu preventedWrapAttempts=%llu tracking=%s",
                static_cast<unsigned long long>(a_trackedAssignments),
                static_cast<unsigned long long>(a_trackedSlots),
                static_cast<unsigned long long>(a_untrackedLive),
                snapshot.reuseCount, generation::kSafeReuseLimit,
                snapshot.slot, snapshot.handle, publishedWraps,
                preventedWrapAttempts, reliability);
        } else if (snapshot.baseFormID != 0) {
            Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                "untrackedLive=%llu highest=%u safeReuseLimit=%u guard=active "
                "hottestSlot=%06X currentHandle=%08X currentReference=%p "
                "FormID=%08X source=\"%s\" baseFormID=%08X "
                "baseSource=\"%s\" publishedWraps=%llu "
                "preventedWrapAttempts=%llu tracking=%s",
                static_cast<unsigned long long>(a_trackedAssignments),
                static_cast<unsigned long long>(a_trackedSlots),
                static_cast<unsigned long long>(a_untrackedLive),
                snapshot.reuseCount, generation::kSafeReuseLimit,
                snapshot.slot, snapshot.handle, snapshot.pinnedReference,
                snapshot.formID, snapshot.sourcePlugin,
                snapshot.baseFormID, snapshot.baseSourcePlugin,
                publishedWraps, preventedWrapAttempts, reliability);
        } else {
            Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                "untrackedLive=%llu highest=%u safeReuseLimit=%u guard=active "
                "hottestSlot=%06X currentHandle=%08X currentReference=%p "
                "FormID=%08X source=\"%s\" publishedWraps=%llu "
                "preventedWrapAttempts=%llu tracking=%s",
                static_cast<unsigned long long>(a_trackedAssignments),
                static_cast<unsigned long long>(a_trackedSlots),
                static_cast<unsigned long long>(a_untrackedLive),
                snapshot.reuseCount, generation::kSafeReuseLimit,
                snapshot.slot, snapshot.handle, snapshot.pinnedReference,
                snapshot.formID, snapshot.sourcePlugin, publishedWraps,
                preventedWrapAttempts, reliability);
        }
    }
}
