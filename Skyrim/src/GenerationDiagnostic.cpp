#include "GenerationDiagnostic.h"

#include "EngineAccess.h"
#include "GenerationTracker.h"
#include "Logging.h"
#include "PatchTable.g.h"

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

        using AssignmentHelperFunction = void* (__fastcall*)(void**, void*);
        static_assert(
            std::atomic<AssignmentHelperFunction>::is_always_lock_free);
        static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

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
        std::atomic<std::uint64_t> g_generationWraps{ 0 };
        std::atomic<std::uint64_t> g_lastWrapEvent{ 0 };
        std::atomic<std::uint32_t> g_wrapEventSequence{ 0 };
        std::atomic<std::uint32_t> g_unreliableSlot{ 0 };

        void RecordHandleGeneration(
            void** a_destination, void* a_subobject) noexcept
        {
            if (!a_destination || !a_subobject || !g_slotAssignments ||
                !g_generationTable || *a_destination != a_subobject) {
                MarkUnreliable(UINT32_MAX);
                return;
            }

            const std::uintptr_t table =
                reinterpret_cast<std::uintptr_t>(g_generationTable);
            const std::uintptr_t firstPointer =
                table + offsetof(HandleEntry, pointer);
            const std::uintptr_t destinationAddress =
                reinterpret_cast<std::uintptr_t>(a_destination);
            if (destinationAddress < firstPointer) {
                MarkUnreliable(UINT32_MAX);
                return;
            }
            const std::uintptr_t byteOffset =
                destinationAddress - firstPointer;
            if ((byteOffset % sizeof(HandleEntry)) != 0) {
                MarkUnreliable(UINT32_MAX);
                return;
            }
            const std::uintptr_t wideIndex = byteOffset / sizeof(HandleEntry);
            if (wideIndex >= g_generationEntryCount) {
                MarkUnreliable(UINT32_MAX);
                return;
            }

            const std::uint32_t index =
                static_cast<std::uint32_t>(wideIndex);
            const std::uint32_t bits = g_generationTable[index].bits;
            if ((bits & generation::kInUseMask) == 0) {
                MarkUnreliable(index);
                return;
            }

            const std::uint32_t priorAssignments =
                g_slotAssignments[index];
            const generation::Transition transition =
                generation::ObserveAssignment(priorAssignments,
                    generation::GenerationFromEntryBits(bits));
            if (transition.saturated) {
                MarkUnreliable(index);
                return;
            }
            g_slotAssignments[index] = transition.assignmentCount;
            if (!transition.generationMatches)
                MarkUnreliable(index);

            const std::uint32_t handle =
                generation::HandleFromEntryBits(index, bits);
            if (transition.reuseCount != 0) {
                const std::uint64_t candidate =
                    (static_cast<std::uint64_t>(transition.reuseCount) << 32) |
                    handle;
                std::uint64_t hottest =
                    g_hottestHandle.load(std::memory_order_relaxed);
                while (transition.reuseCount >
                           static_cast<std::uint32_t>(hottest >> 32) &&
                       !g_hottestHandle.compare_exchange_weak(
                           hottest, candidate, std::memory_order_release,
                           std::memory_order_relaxed)) {
                }
            }

            if (transition.abaWrap) {
                g_wrapEventSequence.fetch_add(
                    1, std::memory_order_acq_rel);
                g_lastWrapEvent.store(
                    (static_cast<std::uint64_t>(transition.reuseCount) << 32) |
                        handle,
                    std::memory_order_relaxed);
                g_generationWraps.fetch_add(1, std::memory_order_relaxed);
                g_wrapEventSequence.fetch_add(
                    1, std::memory_order_release);
            }
        }

        void* __fastcall AssignmentHelperHook(
            void** a_destination, void* a_subobject) noexcept
        {
            const AssignmentHelperFunction original =
                g_originalAssignmentHelper.load(std::memory_order_acquire);
            if (!original)
                return a_destination;
            void* const result = original(a_destination, a_subobject);
            RecordHandleGeneration(a_destination, a_subobject);
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
                    Log("ERROR: generation-wrap detector profile has invalid "
                        "assignment-hook metadata; detector disabled, cap raise "
                        "continues.");
                }
                return false;
            }
            const auto* helper = reinterpret_cast<const std::uint8_t*>(
                g_runtime.imageBase + a_profile.assignmentHelperRva);
            if (std::memcmp(helper, a_profile.assignmentHelperBytes,
                    sizeof(a_profile.assignmentHelperBytes)) != 0) {
                if (a_logMismatch) {
                    Log("ERROR: generation-wrap detector assignment helper at "
                        "rva %08X differs from the verified runtime; detector "
                        "disabled, cap raise continues.",
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
                        Log("ERROR: generation-wrap detector site %u is outside "
                            ".text; detector disabled, cap raise continues.",
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
                        Log("ERROR: generation-wrap detector assignment target "
                            "%u at rva %08X differs from the verified "
                            "owner/setup/call bytes; detector disabled, cap "
                            "raise continues.", index, site.callRva);
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
                        Log("ERROR: generation-wrap detector call %u resolves "
                            "to %016llX, not verified helper %016llX; detector "
                            "disabled, cap raise continues.", index,
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
            Log("FATAL: generation-wrap detector could not restore all five "
                "original assignment calls after a diagnostic install failure.");
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
                if (snapshot.slot < g_generationEntryCount &&
                    g_slotAssignments[snapshot.slot] != 0) {
                    snapshot.reuseCount =
                        g_slotAssignments[snapshot.slot] - 1u;
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
            Log("generation-wrap detector disabled; the cap raise remains "
                "independent.");
            return false;
        }

        g_runtime = a_runtime;
        g_profile = a_runtime.profile;
        g_attribution = a_attribution;
        if (!VerifyAssignmentHookTargets(*g_profile, true)) {
            Log("generation-wrap detector disabled; the cap raise remains "
                "independent.");
            g_profile = nullptr;
            return false;
        }

        const std::size_t sidecarBytes =
            static_cast<std::size_t>(a_table.count) * sizeof(std::uint32_t);
        g_slotAssignments = static_cast<std::uint32_t*>(VirtualAlloc(
            nullptr, sidecarBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!g_slotAssignments) {
            Log("ERROR: generation-wrap detector could not allocate its %zu-byte "
                "sidecar (error %lu); detector disabled, cap raise continues.",
                sidecarBytes, GetLastError());
            g_profile = nullptr;
            return false;
        }
        g_assignmentRelay = AllocateAssignmentRelay(*g_profile);
        if (!g_assignmentRelay) {
            Log("ERROR: generation-wrap detector could not allocate a "
                "rel32-reachable relay; detector disabled, cap raise continues.");
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
            Log("ERROR: generation-wrap detector could not publish its relay "
                "(error %lu); detector disabled, cap raise continues.",
                GetLastError());
            CancelPrepared();
            return false;
        }

        g_generationTable = a_table.entries;
        g_generationEntryCount = a_table.count;
        g_hottestHandle.store(0, std::memory_order_relaxed);
        g_generationWraps.store(0, std::memory_order_relaxed);
        g_lastWrapEvent.store(0, std::memory_order_relaxed);
        g_wrapEventSequence.store(0, std::memory_order_relaxed);
        g_unreliableSlot.store(0, std::memory_order_relaxed);
        Log("generation-wrap detector prepared: exact uint32 reuse counters "
            "for %u slots (%zu MiB) and one executable relay page.",
            a_table.count, sidecarBytes / (1024u * 1024u));
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

        DWORD oldProtection = 0;
        if (!VirtualProtect(g_runtime.text.begin, g_runtime.text.size,
                PAGE_EXECUTE_READWRITE, &oldProtection)) {
            Log("ERROR: generation-wrap detector could not make .text writable "
                "(error %lu); detector disabled, cap raise remains active.",
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
            Log("ERROR: generation-wrap detector call installation did not "
                "verify; all stock calls were restored%s. The cap raise "
                "remains active.", protectionRestored ? "" :
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
            Log("ERROR: generation-wrap detector could not restore .text page "
                "protection after installing; all stock calls were restored%s. "
                "The cap raise remains active.", protectionRestored ? "" :
                    ", although .text remains writable/executable");
            return false;
        }

        g_originalAssignmentHelper.store(
            reinterpret_cast<AssignmentHelperFunction>(
                g_runtime.imageBase + g_profile->assignmentHelperRva),
            std::memory_order_release);
        g_generationDetectorActive.store(true, std::memory_order_release);
        Log("generation-wrap detector installed at all %u verified Skyrim "
            "assignment sites: 22 index bits + 6 generation bits = %u-value "
            "reuse threshold.", g_profile->assignmentHookSiteCount,
            generation::kGenerationCount);
        return true;
    }

    bool IsActive() noexcept
    {
        return g_generationDetectorActive.load(std::memory_order_acquire);
    }

    std::uint32_t AssignmentCount(std::uint32_t a_index) noexcept
    {
        return g_slotAssignments && a_index < g_generationEntryCount ?
            g_slotAssignments[a_index] : 0;
    }

    EventSnapshot ReadEventSnapshot() noexcept
    {
        EventSnapshot snapshot;
        std::uint32_t before = 0;
        std::uint32_t after = 0;
        do {
            before = g_wrapEventSequence.load(std::memory_order_acquire);
            if ((before & 1u) != 0)
                continue;
            snapshot.totalWraps =
                g_generationWraps.load(std::memory_order_relaxed);
            snapshot.lastWrapEvent =
                g_lastWrapEvent.load(std::memory_order_relaxed);
            after = g_wrapEventSequence.load(std::memory_order_acquire);
        } while (before != after || (after & 1u) != 0);
        snapshot.unreliableSlot =
            g_unreliableSlot.load(std::memory_order_acquire);
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
        const unsigned long long wraps =
            static_cast<unsigned long long>(events.totalWraps);
        const char* reliability =
            events.unreliableSlot == 0 ? "exact" : "UNRELIABLE";
        if (!snapshot.hasHottest) {
            Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                "untrackedLive=%llu highest=0 wrapThreshold=%u "
                "hottestSlot=none currentHandle=none currentReference=none "
                "FormID=none source=none wraps=%llu tracking=%s",
                static_cast<unsigned long long>(a_trackedAssignments),
                static_cast<unsigned long long>(a_trackedSlots),
                static_cast<unsigned long long>(a_untrackedLive),
                generation::kGenerationCount, wraps, reliability);
        } else if (!snapshot.hasCurrentHandle) {
            Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                "untrackedLive=%llu highest=%u wrapThreshold=%u "
                "hottestSlot=%06X currentHandle=none (slot currently free) "
                "currentReference=none FormID=none source=none wraps=%llu "
                "tracking=%s",
                static_cast<unsigned long long>(a_trackedAssignments),
                static_cast<unsigned long long>(a_trackedSlots),
                static_cast<unsigned long long>(a_untrackedLive),
                snapshot.reuseCount, generation::kGenerationCount,
                snapshot.slot, wraps, reliability);
        } else if (snapshot.attributionSkipped) {
            Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                "untrackedLive=%llu highest=%u wrapThreshold=%u "
                "hottestSlot=%06X currentHandle=%08X currentReference=%p "
                "FormID=skipped source=<private StressTest attribution "
                "skipped> wraps=%llu tracking=%s",
                static_cast<unsigned long long>(a_trackedAssignments),
                static_cast<unsigned long long>(a_trackedSlots),
                static_cast<unsigned long long>(a_untrackedLive),
                snapshot.reuseCount, generation::kGenerationCount,
                snapshot.slot, snapshot.handle, snapshot.expectedReference,
                wraps, reliability);
        } else if (!snapshot.resolvedCurrentReference) {
            Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                "untrackedLive=%llu highest=%u wrapThreshold=%u "
                "hottestSlot=%06X currentHandle=%08X currentReference=not "
                "currently resolvable FormID=none source=none wraps=%llu "
                "tracking=%s",
                static_cast<unsigned long long>(a_trackedAssignments),
                static_cast<unsigned long long>(a_trackedSlots),
                static_cast<unsigned long long>(a_untrackedLive),
                snapshot.reuseCount, generation::kGenerationCount,
                snapshot.slot, snapshot.handle, wraps, reliability);
        } else if (snapshot.baseFormID != 0) {
            Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                "untrackedLive=%llu highest=%u wrapThreshold=%u "
                "hottestSlot=%06X currentHandle=%08X currentReference=%p "
                "FormID=%08X source=\"%s\" baseFormID=%08X "
                "baseSource=\"%s\" wraps=%llu tracking=%s",
                static_cast<unsigned long long>(a_trackedAssignments),
                static_cast<unsigned long long>(a_trackedSlots),
                static_cast<unsigned long long>(a_untrackedLive),
                snapshot.reuseCount, generation::kGenerationCount,
                snapshot.slot, snapshot.handle, snapshot.pinnedReference,
                snapshot.formID, snapshot.sourcePlugin,
                snapshot.baseFormID, snapshot.baseSourcePlugin,
                wraps, reliability);
        } else {
            Log("generation reuse: trackedAssignments=%llu trackedSlots=%llu "
                "untrackedLive=%llu highest=%u wrapThreshold=%u "
                "hottestSlot=%06X currentHandle=%08X currentReference=%p "
                "FormID=%08X source=\"%s\" wraps=%llu tracking=%s",
                static_cast<unsigned long long>(a_trackedAssignments),
                static_cast<unsigned long long>(a_trackedSlots),
                static_cast<unsigned long long>(a_untrackedLive),
                snapshot.reuseCount, generation::kGenerationCount,
                snapshot.slot, snapshot.handle, snapshot.pinnedReference,
                snapshot.formID, snapshot.sourcePlugin, wraps, reliability);
        }
    }
}
