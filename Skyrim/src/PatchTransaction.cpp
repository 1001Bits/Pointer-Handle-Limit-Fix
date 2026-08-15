#include "PatchTransaction.h"

#include "EngineAccess.h"
#include "EngineFixesInterop.h"
#include "Logging.h"
#include "PatchTable.g.h"
#include "ReservedPlayerSlot.h"
#include "RuntimeDetection.h"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstring>

namespace shcr::patch
{
    namespace
    {
        constexpr std::uint32_t kNoFreeIndex = UINT32_MAX;
        constexpr std::size_t kReservationRelayAllocationBytes = 0x1000;
        constexpr std::size_t kSelectorRelayOffset = 0x00;
        constexpr std::size_t kSelectorRelayBytes = 46;
        constexpr std::size_t kReleaseRelayOffset = 0x100;
        constexpr std::size_t kReleaseRelayBytes = 78;
        constexpr std::size_t kConstructorRelayOffset = 0x200;
        constexpr std::size_t kConstructorRelayBytes = 14;
        constexpr std::uint32_t kCachedHandleValidBit = 1u << 10;
        constexpr std::uint32_t kCachedHandleIndexShift = 11;
        static_assert((generation::kIndexMask << kCachedHandleIndexShift) ==
                      0xFFFFF800u);
        static_assert((player_slot::kIndex << kCachedHandleIndexShift) ==
                      0x80000000u);
        static_assert((kCachedHandleValidBit |
                       (player_slot::kIndex << kCachedHandleIndexShift)) ==
                      0x80000400u);
        static_assert(kSelectorRelayOffset + kSelectorRelayBytes <=
                      kReleaseRelayOffset);
        static_assert(kReleaseRelayOffset + kReleaseRelayBytes <=
                      kConstructorRelayOffset);
        static_assert(kConstructorRelayOffset + kConstructorRelayBytes <=
                      kReservationRelayAllocationBytes);

        // The selector relay performs one aligned machine-word read of this
        // object before the C++ helper repeats the load through the atomic
        // interface.  These assertions make that lock-free x64 representation
        // an explicit prerequisite instead of silently depending on a library
        // lock or a wider atomic object.
        alignas(void*) std::atomic<void*> g_constructingPlayer{ nullptr };
        std::atomic<std::uint64_t> g_reservedPlayerConstructorAssignments{ 0 };
        std::atomic<std::uint64_t> g_reservedPlayerReleaseQuarantines{ 0 };
        static_assert(std::atomic<void*>::is_always_lock_free);
        static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
        static_assert(sizeof(g_constructingPlayer) == sizeof(void*));
        static_assert(sizeof(g_reservedPlayerReleaseQuarantines) ==
                      sizeof(std::uint64_t));
        static_assert(alignof(decltype(g_constructingPlayer)) >=
                      alignof(void*));
        static_assert(alignof(
                          decltype(g_reservedPlayerReleaseQuarantines)) >=
                      alignof(std::uint64_t));

        struct ReservationRelayState
        {
            RuntimeContext runtime;
            const Profile* profile = nullptr;
            HandleEntry* entries = nullptr;
            std::uint32_t* head = nullptr;
            std::uint32_t* tail = nullptr;
            void** playerSingleton = nullptr;
            std::uint8_t* allocation = nullptr;
            std::uint8_t selectorBytes[kSelectorRelayBytes]{};
            std::uint8_t releaseBytes[kReleaseRelayBytes]{};
            std::uint8_t constructorBytes[kConstructorRelayBytes]{};
            HandleEntry releaseScratch{};
            bool hooksActive = false;
            bool committed = false;
        };

        ReservationRelayState g_reservation;

        [[noreturn]] void FatalStop(const char* a_reason) noexcept;

        [[nodiscard]] bool TextContains(
            const RuntimeContext& a_runtime,
            std::uint32_t a_rva,
            std::size_t a_bytes) noexcept
        {
            const std::uintptr_t text =
                reinterpret_cast<std::uintptr_t>(a_runtime.text.begin);
            const std::uintptr_t address = a_runtime.imageBase + a_rva;
            return address >= text && a_bytes <= a_runtime.text.size &&
                address - text <= a_runtime.text.size - a_bytes;
        }

        [[nodiscard]] bool EncodeRelative32(
            std::uintptr_t a_instructionEnd,
            std::uintptr_t a_target,
            std::int32_t& a_displacement) noexcept
        {
            const std::int64_t delta = static_cast<std::int64_t>(a_target) -
                static_cast<std::int64_t>(a_instructionEnd);
            if (delta < INT32_MIN || delta > INT32_MAX)
                return false;
            a_displacement = static_cast<std::int32_t>(delta);
            return true;
        }

        [[nodiscard]] bool BuildHookBranch(
            std::uint8_t a_opcode,
            std::uintptr_t a_source,
            std::uintptr_t a_target,
            std::uint8_t (&a_patch)[6]) noexcept
        {
            std::int32_t displacement = 0;
            if (!EncodeRelative32(a_source + 5u, a_target, displacement))
                return false;
            a_patch[0] = a_opcode;
            std::memcpy(a_patch + 1, &displacement, sizeof(displacement));
            a_patch[5] = 0x90;
            return true;
        }

        [[nodiscard]] bool BuildCallBranch(
            std::uintptr_t a_source,
            std::uintptr_t a_target,
            std::uint8_t (&a_patch)[5]) noexcept
        {
            std::int32_t displacement = 0;
            if (!EncodeRelative32(a_source + sizeof(a_patch),
                    a_target, displacement)) {
                return false;
            }
            a_patch[0] = 0xE8;
            std::memcpy(a_patch + 1, &displacement, sizeof(displacement));
            return true;
        }

        [[nodiscard]] std::uintptr_t RelativeTargetAt(
            const std::uint8_t* a_bytes,
            std::uintptr_t a_instructionAddress,
            std::size_t a_displacementOffset,
            std::size_t a_instructionLength) noexcept
        {
            std::int32_t displacement = 0;
            std::memcpy(&displacement,
                a_bytes + a_displacementOffset,
                sizeof(displacement));
            return static_cast<std::uintptr_t>(
                static_cast<std::int64_t>(a_instructionAddress) +
                static_cast<std::int64_t>(a_instructionLength) + displacement);
        }

        [[nodiscard]] std::uintptr_t RelativeTarget(
            const std::uint8_t* a_instruction,
            std::size_t a_displacementOffset,
            std::size_t a_instructionBytes) noexcept
        {
            return RelativeTargetAt(a_instruction,
                reinterpret_cast<std::uintptr_t>(a_instruction),
                a_displacementOffset, a_instructionBytes);
        }

        struct PlayerCharacter;
        using PlayerConstructor =
            PlayerCharacter* (__fastcall*)(PlayerCharacter*);

        struct ConstructorArmGuard
        {
            void* candidate;

            ~ConstructorArmGuard() noexcept
            {
                void* expected = candidate;
                if (!g_constructingPlayer.compare_exchange_strong(expected,
                        nullptr, std::memory_order_acq_rel,
                        std::memory_order_acquire)) {
                    FatalStop("player constructor arm changed before completion");
                }
            }
        };

        struct ManagerWriteLockGuard
        {
            const RuntimeContext& runtime;
            const Profile& profile;

            ManagerWriteLockGuard(
                const RuntimeContext& a_runtime,
                const Profile& a_profile) noexcept :
                runtime(a_runtime), profile(a_profile)
            {
                LockManager(runtime, profile);
            }

            ~ManagerWriteLockGuard() noexcept
            {
                UnlockManager(runtime, profile);
            }

            ManagerWriteLockGuard(const ManagerWriteLockGuard&) = delete;
            ManagerWriteLockGuard& operator=(
                const ManagerWriteLockGuard&) = delete;
        };

        // The stock creation CALL supplies the return address (including its
        // CET shadow-stack entry) and the caller's Windows-x64 shadow space.
        // Its near relay is a register-neutral FF25 tail jump into this normal
        // compiled function, whose pdata covers its prologue and whose RET
        // therefore balances the original CALL.
        __declspec(noinline) PlayerCharacter* __fastcall
        ConstructReservedPlayer(PlayerCharacter* a_candidate)
        {
            if (!a_candidate)
                FatalStop("player constructor hook received a null candidate");
            if (!g_reservation.profile || !g_reservation.entries ||
                !g_reservation.playerSingleton || !g_reservation.allocation ||
                !g_reservation.hooksActive) {
                FatalStop("player constructor hook ran without complete active state");
            }

            void* expected = nullptr;
            if (!g_constructingPlayer.compare_exchange_strong(expected,
                    a_candidate, std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                FatalStop(expected == a_candidate ?
                    "nested player construction reused the armed candidate" :
                    "concurrent player construction armed a different candidate");
            }
            const ConstructorArmGuard arm{ a_candidate };

            const PlayerLifecycleMetadata& lifecycle =
                g_reservation.profile->playerLifecycle;
            const ExactSite& constructorCall = lifecycle.constructorCall;
            const bool livePreHookWindowGood =
                lifecycle.constructorPreHookRva ==
                    lifecycle.creationFunctionRva &&
                lifecycle.constructorPreHookLen != 0 &&
                lifecycle.constructorPreHookLen <=
                    sizeof(lifecycle.constructorPreHookBytes) &&
                lifecycle.constructorPreHookRva +
                    lifecycle.constructorPreHookLen == constructorCall.rva &&
                TextContains(g_reservation.runtime,
                    lifecycle.constructorPreHookRva,
                    lifecycle.constructorPreHookLen) &&
                std::memcmp(reinterpret_cast<const void*>(
                        g_reservation.runtime.imageBase +
                            lifecycle.constructorPreHookRva),
                    lifecycle.constructorPreHookBytes,
                    lifecycle.constructorPreHookLen) == 0;
            if (!livePreHookWindowGood) {
                FatalStop("live player creation pre-call owner window changed");
            }

            std::uint8_t expectedConstructorCall[5]{};
            const bool liveConstructorCallGood =
                constructorCall.len == sizeof(expectedConstructorCall) &&
                BuildCallBranch(
                    g_reservation.runtime.imageBase + constructorCall.rva,
                    reinterpret_cast<std::uintptr_t>(
                        g_reservation.allocation +
                            kConstructorRelayOffset),
                    expectedConstructorCall) &&
                TextContains(g_reservation.runtime, constructorCall.rva,
                    sizeof(expectedConstructorCall)) &&
                std::memcmp(reinterpret_cast<const void*>(
                        g_reservation.runtime.imageBase +
                            constructorCall.rva),
                    expectedConstructorCall,
                    sizeof(expectedConstructorCall)) == 0;
            if (!liveConstructorCallGood) {
                FatalStop("live player constructor call no longer targets its exact relay");
            }

            const bool livePostCallWindowGood =
                constructorCall.len == 5 &&
                lifecycle.constructorPostCallLen != 0 &&
                lifecycle.constructorPostCallLen <=
                    sizeof(lifecycle.constructorPostCallBytes) &&
                lifecycle.constructorPostCallRva ==
                    constructorCall.rva + constructorCall.len &&
                lifecycle.constructorPostCallRva +
                    lifecycle.constructorPostCallLen ==
                        lifecycle.singletonStore.rva &&
                TextContains(g_reservation.runtime,
                    lifecycle.constructorPostCallRva,
                    lifecycle.constructorPostCallLen) &&
                std::memcmp(reinterpret_cast<const void*>(
                        g_reservation.runtime.imageBase +
                            lifecycle.constructorPostCallRva),
                    lifecycle.constructorPostCallBytes,
                    lifecycle.constructorPostCallLen) == 0;
            if (!livePostCallWindowGood) {
                FatalStop("live player constructor post-call publication window changed");
            }
            if (!TextContains(g_reservation.runtime,
                    lifecycle.constructorFunctionRva,
                    sizeof(lifecycle.constructorFunctionBytes)) ||
                std::memcmp(reinterpret_cast<const void*>(
                        g_reservation.runtime.imageBase +
                            lifecycle.constructorFunctionRva),
                    lifecycle.constructorFunctionBytes,
                    sizeof(lifecycle.constructorFunctionBytes)) != 0) {
                FatalStop("live player constructor entry no longer matches its exact fingerprint");
            }

            auto constructor = reinterpret_cast<PlayerConstructor>(
                g_reservation.runtime.imageBase +
                    lifecycle.constructorFunctionRva);
            PlayerCharacter* const result = constructor(a_candidate);
            if (!result || result != a_candidate)
                FatalStop("player constructor returned an unexpected object");

            const auto* candidateBytes =
                reinterpret_cast<const std::uint8_t*>(a_candidate);
            bool cachedHandleGood = true;
            bool reservedAssignmentGood = false;
            {
                // The constructor can publish through a selector that uses
                // this same write lock.  Snapshot and validate its cache and
                // table entry under that lock, but defer fail-stop logging
                // until after the guard has released it.
                const ManagerWriteLockGuard managerLock{
                    g_reservation.runtime, *g_reservation.profile
                };
                static_cast<void>(managerLock);
                std::uint32_t cachedState = 0;
                std::memcpy(&cachedState, candidateBytes + 0x28,
                    sizeof(cachedState));
                const HandleEntry reserved =
                    g_reservation.entries[player_slot::kIndex];
                reservedAssignmentGood =
                    player_slot::IsLiveGenerationZero(reserved) &&
                    reserved.pad == 0 &&
                    reserved.pointer == candidateBytes + 0x20;
                if ((cachedState & kCachedHandleValidBit) != 0) {
                    const std::uint32_t cachedIndex =
                        cachedState >> kCachedHandleIndexShift;
                    cachedHandleGood =
                        cachedIndex == player_slot::kIndex &&
                        reservedAssignmentGood;
                }
            }
            if (!cachedHandleGood) {
                FatalStop("player constructor cached a non-reserved or malformed handle");
            }
            if (reservedAssignmentGood) {
                const std::uint64_t assignment =
                    g_reservedPlayerConstructorAssignments.fetch_add(
                        1, std::memory_order_acq_rel) + 1u;
                const std::uint64_t quarantines =
                    g_reservedPlayerReleaseQuarantines.load(
                        std::memory_order_acquire);
                Log("player lifecycle transition: constructorAssignments=%llu "
                    "releaseQuarantines=%llu reservedSlot=%06X raw=%08X "
                    "object=%p",
                    static_cast<unsigned long long>(assignment),
                    static_cast<unsigned long long>(quarantines),
                    player_slot::kIndex, player_slot::kVanillaRawHandle,
                    a_candidate);
            }

            return result;
        }

        std::uint32_t __fastcall SelectPlayerFreeHead(
            void* a_candidate) noexcept
        {
            if (!g_reservation.profile || !g_reservation.entries ||
                !g_reservation.head || !g_reservation.tail ||
                !g_reservation.playerSingleton) {
                FatalStop("player selector relay ran without complete state");
            }

            const std::uint32_t ordinaryHead = *g_reservation.head;
            void* const player = *g_reservation.playerSingleton;
            void* const constructing = g_constructingPlayer.load(
                std::memory_order_acquire);
            const bool publishedPlayer =
                player && a_candidate == player;
            const bool constructingPlayer =
                constructing && a_candidate == constructing;
            if (!publishedPlayer && !constructingPlayer)
                return ordinaryHead;

            const Profile& profile = *g_reservation.profile;
            if (player_slot::kIndex >= profile.raisedEntries) {
                FatalStop("reserved player slot lies outside the raised table");
            }
            HandleEntry& reserved =
                g_reservation.entries[player_slot::kIndex];
            if (!player_slot::IsDetached(reserved)) {
                FatalStop("reserved player slot was not detached before player allocation");
            }

            const std::uint32_t ordinaryTail = *g_reservation.tail;
            const bool emptyHead = ordinaryHead == kNoFreeIndex;
            const bool emptyTail = ordinaryTail == kNoFreeIndex;
            if (emptyHead != emptyTail) {
                FatalStop("free-list head/tail disagree before player injection");
            }
            if (!emptyHead) {
                if (ordinaryHead >= profile.raisedEntries ||
                    ordinaryTail >= profile.raisedEntries ||
                    ordinaryHead == player_slot::kIndex ||
                    ordinaryTail == player_slot::kIndex) {
                    FatalStop("free-list endpoint is invalid before player injection");
                }
                const HandleEntry& headEntry =
                    g_reservation.entries[ordinaryHead];
                const HandleEntry& tailEntry =
                    g_reservation.entries[ordinaryTail];
                if ((headEntry.bits & generation::kInUseMask) != 0 ||
                    headEntry.pointer != nullptr ||
                    headEntry.pad != 0 ||
                    (tailEntry.bits & generation::kInUseMask) != 0 ||
                    tailEntry.pointer != nullptr || tailEntry.pad != 0 ||
                    (tailEntry.bits & generation::kIndexMask) !=
                        ordinaryTail) {
                    FatalStop("free-list endpoint is published before player injection");
                }
            }

            reserved.bits = (player_slot::kDetachedGeneration <<
                generation::kIndexBits) |
                (emptyHead ? player_slot::kIndex : ordinaryHead);
            reserved.pad = 0;
            reserved.pointer = nullptr;
            *g_reservation.head = player_slot::kIndex;
            if (emptyHead)
                *g_reservation.tail = player_slot::kIndex;
            return player_slot::kIndex;
        }

        [[nodiscard]] bool ReservationRelayIsReachable(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            std::uintptr_t a_allocation) noexcept
        {
            const std::uintptr_t selector =
                a_allocation + kSelectorRelayOffset;
            for (std::uint32_t index = 0;
                 index < a_profile.playerSelectorHookSiteCount; ++index) {
                std::int32_t displacement = 0;
                if (!EncodeRelative32(a_runtime.imageBase +
                        a_profile.playerSelectorHookSites[index].hookRva + 5u,
                        selector, displacement)) {
                    return false;
                }
            }

            std::int32_t displacement = 0;
            if (!EncodeRelative32(selector + 7u,
                    a_runtime.imageBase + a_profile.playerSingletonRva,
                    displacement) ||
                !EncodeRelative32(selector + 30u,
                    a_runtime.imageBase + a_profile.headRva,
                    displacement)) {
                return false;
            }

            const PlayerReleaseHookSite& release =
                a_profile.playerReleaseHook;
            const std::uintptr_t relay =
                a_allocation + kReleaseRelayOffset;
            const ExactSite& constructorCall =
                a_profile.playerLifecycle.constructorCall;
            return EncodeRelative32(
                       a_runtime.imageBase + release.hookRva + 5u,
                       relay, displacement) &&
                EncodeRelative32(relay + 6u,
                    a_runtime.imageBase + a_profile.tailRva, displacement) &&
                EncodeRelative32(
                    a_runtime.imageBase + constructorCall.rva + 5u,
                    a_allocation + kConstructorRelayOffset, displacement);
        }

        [[nodiscard]] std::uint8_t* AllocateReservationRelay(
            const RuntimeContext& a_runtime,
            const Profile& a_profile) noexcept
        {
            for (std::uintptr_t offset = 0x08000000u;
                 offset <= 0x70000000u; offset += 0x04000000u) {
                auto* allocation = static_cast<std::uint8_t*>(VirtualAlloc(
                    reinterpret_cast<void*>(a_runtime.imageBase + offset),
                    kReservationRelayAllocationBytes,
                    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
                if (!allocation)
                    continue;
                if (ReservationRelayIsReachable(a_runtime, a_profile,
                        reinterpret_cast<std::uintptr_t>(allocation))) {
                    return allocation;
                }
                VirtualFree(allocation, 0, MEM_RELEASE);
            }
            auto* allocation = static_cast<std::uint8_t*>(VirtualAlloc(
                nullptr, kReservationRelayAllocationBytes,
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (allocation && !ReservationRelayIsReachable(
                    a_runtime, a_profile,
                    reinterpret_cast<std::uintptr_t>(allocation))) {
                VirtualFree(allocation, 0, MEM_RELEASE);
                allocation = nullptr;
            }
            return allocation;
        }

        [[nodiscard]] bool BuildReservationRelayBytes() noexcept
        {
            if (!g_reservation.allocation || !g_reservation.profile)
                return false;
            const Profile& profile = *g_reservation.profile;
            const std::uint8_t objectRegister =
                profile.playerSelectorHookSites[0].objectRegister;
            if (objectRegister != kPlayerObject_RBX &&
                objectRegister != kPlayerObject_RDI) {
                return false;
            }

            std::size_t cursor = 0;
            auto emitBytes = [&](const std::uint8_t* a_bytes,
                                 std::size_t a_count) noexcept {
                if (a_count > kSelectorRelayBytes - cursor)
                    return false;
                std::memcpy(g_reservation.selectorBytes + cursor,
                    a_bytes, a_count);
                cursor += a_count;
                return true;
            };

            // The hook is a CALL, so its return address and the stock owner's
            // outgoing shadow space already form a valid Windows x64 call
            // frame.  Ordinary allocation is a stack-neutral leaf.  On exact
            // singleton equality, tail-jump to the normal C++ helper: its own
            // pdata describes any prologue, and RET returns directly to the
            // hook's trailing NOP.  Generated continuation evidence proves
            // the helper-clobbered volatile state and flags are dead there.
            const std::uintptr_t selectorRelay =
                reinterpret_cast<std::uintptr_t>(g_reservation.allocation) +
                kSelectorRelayOffset;
            const std::uint8_t fastCompare[] = {
                0x48, 0x3B,
                static_cast<std::uint8_t>(
                    objectRegister == kPlayerObject_RBX ? 0x1D : 0x3D),
            };
            if (!emitBytes(fastCompare, sizeof(fastCompare)))
                return false;
            std::int32_t selectorDisplacement = 0;
            if (!EncodeRelative32(selectorRelay + 7u,
                    g_reservation.runtime.imageBase +
                        profile.playerSingletonRva,
                    selectorDisplacement) ||
                !emitBytes(reinterpret_cast<const std::uint8_t*>(
                    &selectorDisplacement), sizeof(selectorDisplacement))) {
                return false;
            }
            const std::uint8_t armedComparePrefix[] = {
                0x74, 0x16,                   // je player tail-jump
                0x48, 0xB8,                   // mov rax,atomic storage
            };
            if (!emitBytes(armedComparePrefix,
                    sizeof(armedComparePrefix))) {
                return false;
            }
            const std::uintptr_t constructingPlayer =
                reinterpret_cast<std::uintptr_t>(&g_constructingPlayer);
            if (!emitBytes(reinterpret_cast<const std::uint8_t*>(
                    &constructingPlayer), sizeof(constructingPlayer))) {
                return false;
            }
            const std::uint8_t armedCompareAndOrdinary[] = {
                0x48, 0x3B,
                static_cast<std::uint8_t>(
                    objectRegister == kPlayerObject_RBX ? 0x18 : 0x38),
                0x74, 0x07,                   // je player tail-jump
                0x8B, 0x05,                   // mov eax,[rip+free head]
            };
            if (!emitBytes(armedCompareAndOrdinary,
                    sizeof(armedCompareAndOrdinary)) ||
                !EncodeRelative32(selectorRelay + 30u,
                    g_reservation.runtime.imageBase + profile.headRva,
                    selectorDisplacement) ||
                !emitBytes(reinterpret_cast<const std::uint8_t*>(
                    &selectorDisplacement), sizeof(selectorDisplacement))) {
                return false;
            }
            const std::uint8_t fastReturn = 0xC3;
            if (!emitBytes(&fastReturn, sizeof(fastReturn)))
                return false;
            const std::uint8_t objectMove[] = {
                0x48, 0x8B,
                static_cast<std::uint8_t>(
                    objectRegister == kPlayerObject_RBX ? 0xCB : 0xCF),
            };
            const std::uint8_t callPrefix[] = { 0x48, 0xB8 };
            if (!emitBytes(objectMove, sizeof(objectMove)) ||
                !emitBytes(callPrefix, sizeof(callPrefix))) {
                return false;
            }
            const std::uintptr_t helper =
                reinterpret_cast<std::uintptr_t>(&SelectPlayerFreeHead);
            if (sizeof(helper) > kSelectorRelayBytes - cursor)
                return false;
            std::memcpy(g_reservation.selectorBytes + cursor,
                &helper, sizeof(helper));
            cursor += sizeof(helper);
            const std::uint8_t tailJump[] = { 0xFF, 0xE0 };
            if (!emitBytes(tailJump, sizeof(tailJump)) ||
                cursor != kSelectorRelayBytes) {
                return false;
            }

            cursor = 0;
            auto releaseEmit = [&](const std::uint8_t* a_bytes,
                                   std::size_t a_count) noexcept {
                if (a_count > kReleaseRelayBytes - cursor)
                    return false;
                std::memcpy(g_reservation.releaseBytes + cursor,
                    a_bytes, a_count);
                cursor += a_count;
                return true;
            };
            const std::uint8_t releasePrefix[] = {
                0x8B, 0x05,                   // mov eax,[rip+tail]
            };
            if (!releaseEmit(releasePrefix, sizeof(releasePrefix)))
                return false;
            const std::uintptr_t releaseRelay =
                reinterpret_cast<std::uintptr_t>(g_reservation.allocation) +
                kReleaseRelayOffset;
            std::int32_t displacement = 0;
            if (!EncodeRelative32(releaseRelay + 6u,
                    g_reservation.runtime.imageBase + profile.tailRva,
                    displacement) ||
                !releaseEmit(reinterpret_cast<const std::uint8_t*>(
                    &displacement), sizeof(displacement))) {
                return false;
            }
            const std::uint8_t releaseDispatch[] = {
                0x81, 0xFF, 0x00, 0x00, 0x10, 0x00,
                0x74, 0x01,                   // je reserved path
                0xC3,                         // ordinary: ret
            };
            if (!releaseEmit(releaseDispatch, sizeof(releaseDispatch)))
                return false;
            const std::uint8_t reservedPrefix[] = {
                // mov qword ptr [rbx],03F00000h: detach the reserved entry
                // and clear its stock padding in one naturally aligned store.
                0x48, 0xC7, 0x03, 0x00, 0x00, 0xF0, 0x03,
                0x8B, 0xF8,                   // mov edi,eax
                0x48, 0xB8,                   // mov rax,release counter
            };
            if (!releaseEmit(reservedPrefix, sizeof(reservedPrefix)))
                return false;
            const std::uintptr_t releaseCounter =
                reinterpret_cast<std::uintptr_t>(
                    &g_reservedPlayerReleaseQuarantines);
            if (!releaseEmit(reinterpret_cast<const std::uint8_t*>(
                    &releaseCounter), sizeof(releaseCounter))) {
                return false;
            }
            const std::uint8_t reservedSuffix[] = {
                0xF0, 0x48, 0xFF, 0x00,       // lock inc qword ptr [rax]
                0x8B, 0xC7,                   // mov eax,edi
                0x83, 0xF8, 0xFF,             // cmp eax,-1
                0x74, 0x16,                   // je scratch path
                0x8B, 0xD8,                   // mov ebx,eax
                0x48, 0xC1, 0xE3, 0x04,       // shl rbx,4
                0x48, 0xB8,                   // mov rax,raised table
            };
            if (!releaseEmit(reservedSuffix, sizeof(reservedSuffix)))
                return false;
            const std::uintptr_t entries =
                reinterpret_cast<std::uintptr_t>(g_reservation.entries);
            if (!releaseEmit(reinterpret_cast<const std::uint8_t*>(
                    &entries), sizeof(entries))) {
                return false;
            }
            const std::uint8_t nonemptyExit[] = {
                0x48, 0x03, 0xD8,             // add rbx,rax
                0x8B, 0xC7,                   // mov eax,edi
                0xC3,
                0x48, 0xBB,                   // mov rbx,release scratch
            };
            if (!releaseEmit(nonemptyExit, sizeof(nonemptyExit)))
                return false;
            const std::uintptr_t scratch = reinterpret_cast<std::uintptr_t>(
                &g_reservation.releaseScratch);
            if (!releaseEmit(reinterpret_cast<const std::uint8_t*>(
                    &scratch), sizeof(scratch))) {
                return false;
            }
            const std::uint8_t scratchReturn = 0xC3;
            if (!releaseEmit(&scratchReturn, sizeof(scratchReturn)) ||
                cursor != kReleaseRelayBytes) {
                return false;
            }

            const std::uint8_t constructorPrefix[] = {
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
            };
            std::memcpy(g_reservation.constructorBytes,
                constructorPrefix, sizeof(constructorPrefix));
            const std::uintptr_t constructorWrapper =
                reinterpret_cast<std::uintptr_t>(&ConstructReservedPlayer);
            std::memcpy(g_reservation.constructorBytes +
                    sizeof(constructorPrefix),
                &constructorWrapper, sizeof(constructorWrapper));

            std::memcpy(g_reservation.allocation + kSelectorRelayOffset,
                g_reservation.selectorBytes, kSelectorRelayBytes);
            std::memcpy(g_reservation.allocation + kReleaseRelayOffset,
                g_reservation.releaseBytes, kReleaseRelayBytes);
            std::memcpy(g_reservation.allocation + kConstructorRelayOffset,
                g_reservation.constructorBytes, kConstructorRelayBytes);
            return true;
        }

        void CancelReservationRelays() noexcept
        {
            if (g_reservation.committed)
                return;
            if (g_reservation.hooksActive) {
                FatalStop("attempted to cancel player relays while hooks were active");
            }
            g_constructingPlayer.store(nullptr, std::memory_order_release);
            if (g_reservation.allocation)
                VirtualFree(g_reservation.allocation, 0, MEM_RELEASE);
            g_reservation = {};
        }

        [[nodiscard]] bool PrepareReservationRelays(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            HandleEntry* a_entries) noexcept
        {
            if (g_reservation.allocation || g_reservation.committed ||
                g_constructingPlayer.load(std::memory_order_acquire)) {
                return false;
            }
            g_reservation.runtime = a_runtime;
            g_reservation.profile = &a_profile;
            g_reservation.entries = a_entries;
            g_reservation.head = reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + a_profile.headRva);
            g_reservation.tail = reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + a_profile.tailRva);
            g_reservation.playerSingleton = reinterpret_cast<void**>(
                a_runtime.imageBase + a_profile.playerSingletonRva);
            g_reservedPlayerConstructorAssignments.store(
                0, std::memory_order_relaxed);
            g_reservedPlayerReleaseQuarantines.store(
                0, std::memory_order_relaxed);
            g_reservation.allocation = AllocateReservationRelay(
                a_runtime, a_profile);
            if (!g_reservation.allocation ||
                !BuildReservationRelayBytes()) {
                CancelReservationRelays();
                return false;
            }
            DWORD oldProtection = 0;
            if (!VirtualProtect(g_reservation.allocation,
                    kReservationRelayAllocationBytes, PAGE_EXECUTE_READ,
                    &oldProtection) ||
                !FlushInstructionCache(GetCurrentProcess(),
                    g_reservation.allocation,
                    kReservationRelayAllocationBytes)) {
                CancelReservationRelays();
                return false;
            }
            Log("player-slot relays prepared at %016llx: one constructor "
                "call, five selector calls, and one release-quarantine call",
                static_cast<unsigned long long>(
                    reinterpret_cast<std::uintptr_t>(
                        g_reservation.allocation)));
            return true;
        }

        [[nodiscard]] bool VerifyReservationRelayBytes() noexcept
        {
            MEMORY_BASIC_INFORMATION memory{};
            const bool executableReadOnly = g_reservation.allocation &&
                VirtualQuery(g_reservation.allocation, &memory,
                    sizeof(memory)) == sizeof(memory) &&
                memory.State == MEM_COMMIT &&
                memory.BaseAddress == g_reservation.allocation &&
                memory.AllocationBase == g_reservation.allocation &&
                memory.Protect == PAGE_EXECUTE_READ &&
                memory.RegionSize >= kReservationRelayAllocationBytes;
            const std::uint8_t exactConstructorPrefix[] = {
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
            };
            std::uintptr_t constructorTarget = 0;
            std::memcpy(&constructorTarget,
                g_reservation.constructorBytes +
                    sizeof(exactConstructorPrefix),
                sizeof(constructorTarget));
            const bool constructorTemplateExact =
                std::memcmp(g_reservation.constructorBytes,
                    exactConstructorPrefix,
                    sizeof(exactConstructorPrefix)) == 0 &&
                constructorTarget == reinterpret_cast<std::uintptr_t>(
                    &ConstructReservedPlayer);
            return executableReadOnly && constructorTemplateExact &&
                std::memcmp(g_reservation.allocation + kSelectorRelayOffset,
                    g_reservation.selectorBytes,
                    kSelectorRelayBytes) == 0 &&
                std::memcmp(g_reservation.allocation + kReleaseRelayOffset,
                    g_reservation.releaseBytes,
                    kReleaseRelayBytes) == 0 &&
                std::memcmp(
                    g_reservation.allocation + kConstructorRelayOffset,
                    g_reservation.constructorBytes,
                    kConstructorRelayBytes) == 0;
        }

        void ApplyReservationHooks(
            const RuntimeContext& a_runtime,
            const Profile& a_profile) noexcept
        {
            // From the first published hook until the last stock byte is
            // restored, cancellation must neither clear the constructor arm
            // nor free the executable relay page.
            g_reservation.hooksActive = true;
            for (std::uint32_t index = 0;
                 index < a_profile.playerSelectorHookSiteCount; ++index) {
                const PlayerSelectorHookSite& site =
                    a_profile.playerSelectorHookSites[index];
                std::uint8_t patch[6]{};
                if (!BuildHookBranch(0xE8,
                        a_runtime.imageBase + site.hookRva,
                        reinterpret_cast<std::uintptr_t>(
                            g_reservation.allocation +
                            kSelectorRelayOffset), patch)) {
                    FatalStop("prepared player selector relay became unreachable");
                }
                std::memcpy(reinterpret_cast<void*>(
                        a_runtime.imageBase + site.hookRva),
                    patch, sizeof(patch));
            }
            const PlayerReleaseHookSite& release =
                a_profile.playerReleaseHook;
            std::uint8_t patch[6]{};
            if (!BuildHookBranch(0xE8,
                    a_runtime.imageBase + release.hookRva,
                    reinterpret_cast<std::uintptr_t>(
                        g_reservation.allocation + kReleaseRelayOffset),
                    patch)) {
                FatalStop("prepared player release relay became unreachable");
            }
            std::memcpy(reinterpret_cast<void*>(
                    a_runtime.imageBase + release.hookRva),
                patch, sizeof(patch));

            const ExactSite& constructorCall =
                a_profile.playerLifecycle.constructorCall;
            std::uint8_t constructorPatch[5]{};
            if (!BuildCallBranch(
                    a_runtime.imageBase + constructorCall.rva,
                    reinterpret_cast<std::uintptr_t>(
                        g_reservation.allocation +
                            kConstructorRelayOffset),
                    constructorPatch)) {
                FatalStop("prepared player constructor relay became unreachable");
            }
            std::memcpy(reinterpret_cast<void*>(
                    a_runtime.imageBase + constructorCall.rva),
                constructorPatch, sizeof(constructorPatch));
        }

        void RestoreReservationHooks(
            const RuntimeContext& a_runtime,
            const Profile& a_profile) noexcept
        {
            if (g_constructingPlayer.load(std::memory_order_acquire)) {
                FatalStop("cannot restore player hooks during active construction");
            }
            const ExactSite& constructorCall =
                a_profile.playerLifecycle.constructorCall;
            std::memcpy(reinterpret_cast<void*>(
                    a_runtime.imageBase + constructorCall.rva),
                constructorCall.orig, constructorCall.len);
            for (std::uint32_t index = 0;
                 index < a_profile.playerSelectorHookSiteCount; ++index) {
                const PlayerSelectorHookSite& site =
                    a_profile.playerSelectorHookSites[index];
                std::memcpy(reinterpret_cast<void*>(
                        a_runtime.imageBase + site.hookRva),
                    site.hookBytes, sizeof(site.hookBytes));
            }
            const PlayerReleaseHookSite& release =
                a_profile.playerReleaseHook;
            std::memcpy(reinterpret_cast<void*>(
                    a_runtime.imageBase + release.hookRva),
                release.hookBytes, sizeof(release.hookBytes));
            g_reservation.hooksActive = false;
        }

        [[nodiscard]] std::size_t CountDispRefs(
            const RuntimeContext& a_runtime,
            std::uintptr_t a_target) noexcept
        {
            std::size_t count = 0;
            const std::uint8_t* bytes = a_runtime.text.begin;
            if (a_runtime.text.size < 4)
                return 0;
            const std::size_t limit = a_runtime.text.size - 4;
            for (std::size_t index = 0; index <= limit; ++index) {
                std::int32_t displacement = 0;
                std::memcpy(&displacement, bytes + index, 4);
                const std::uintptr_t end = reinterpret_cast<std::uintptr_t>(
                    bytes + index + 4);
                if (static_cast<std::uintptr_t>(
                        static_cast<std::int64_t>(end) + displacement) ==
                    a_target) {
                    ++count;
                }
            }
            return count;
        }

        void LogByteMismatch(
            const char* a_kind,
            std::uint32_t a_rva,
            const std::uint8_t* a_wanted,
            const std::uint8_t* a_actual,
            std::size_t a_mismatchNumber) noexcept
        {
            if (a_mismatchNumber < 8) {
                Log("  MISMATCH %s at rva %08x: expected first byte %02x, "
                    "found %02x", a_kind, a_rva, a_wanted[0], a_actual[0]);
            }
        }

        void LogReservationMismatch(
            const char* a_kind,
            std::uint32_t a_rva,
            std::size_t a_mismatchNumber) noexcept
        {
            if (a_mismatchNumber < 8) {
                Log("  MISMATCH player reservation %s at rva %08x",
                    a_kind, a_rva);
            }
        }

        [[nodiscard]] bool VerifyExpectedReservationWindow(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            std::uint32_t a_rva,
            const std::uint8_t* a_stock,
            std::uint16_t a_length,
            bool a_expectPatched) noexcept
        {
            constexpr std::size_t kMaximumWindow = 256;
            if (!a_stock || a_length == 0 || a_length > kMaximumWindow ||
                !TextContains(a_runtime, a_rva, a_length)) {
                return false;
            }
            std::uint8_t wanted[kMaximumWindow]{};
            std::memcpy(wanted, a_stock, a_length);
            const std::uint64_t windowBegin = a_rva;
            const std::uint64_t windowEnd = windowBegin + a_length;
            const auto overlaps = [&](std::uint32_t a_patchRva,
                                      std::size_t a_patchLength) noexcept {
                const std::uint64_t begin = a_patchRva;
                const std::uint64_t end = begin + a_patchLength;
                return begin < windowEnd && windowBegin < end;
            };
            const auto contained = [&](std::uint32_t a_patchRva,
                                       std::size_t a_patchLength) noexcept {
                const std::uint64_t begin = a_patchRva;
                const std::uint64_t end = begin + a_patchLength;
                return begin >= windowBegin && end <= windowEnd;
            };

            if (a_expectPatched) {
                for (std::uint32_t index = 0;
                     index < a_profile.fieldCount; ++index) {
                    const FieldPatch& field = a_profile.fields[index];
                    if (!overlaps(field.rva, field.len))
                        continue;
                    if (!contained(field.rva, field.len) ||
                        field.fieldW == 0 ||
                        field.fieldOff + field.fieldW > field.len) {
                        return false;
                    }
                    std::uint8_t* destination = wanted +
                        (field.rva - a_rva) + field.fieldOff;
                    if (field.fieldW == 4) {
                        std::memcpy(destination, &field.newVal,
                            sizeof(field.newVal));
                    } else if (field.fieldW == 1) {
                        *destination = static_cast<std::uint8_t>(field.newVal);
                    } else {
                        return false;
                    }
                }
                if (!g_reservation.entries)
                    return false;
                const std::uintptr_t table =
                    reinterpret_cast<std::uintptr_t>(g_reservation.entries);
                for (std::uint32_t index = 0;
                     index < a_profile.tableRefCount; ++index) {
                    const TableRef& reference = a_profile.tableRefs[index];
                    if (!overlaps(reference.rva, reference.len))
                        continue;
                    if (!contained(reference.rva, reference.len) ||
                        reference.dispOff + sizeof(std::int32_t) !=
                            reference.len) {
                        return false;
                    }
                    std::int32_t displacement = 0;
                    if (!EncodeRelative32(a_runtime.imageBase + reference.rva +
                            reference.len, table, displacement)) {
                        return false;
                    }
                    std::memcpy(wanted + (reference.rva - a_rva) +
                            reference.dispOff,
                        &displacement, sizeof(displacement));
                }
                // Initializer guards are transaction-state dependent and are
                // intentionally outside allocator/release ABI windows.
                for (std::uint32_t index = 0;
                     index < a_profile.initPatchCount; ++index) {
                    const BytePatch& patch = a_profile.initPatches[index];
                    if (overlaps(patch.rva, patch.len))
                        return false;
                }
            }
            return std::memcmp(reinterpret_cast<const void*>(
                    a_runtime.imageBase + a_rva), wanted, a_length) == 0;
        }

        [[nodiscard]] bool VerifyReservationCode(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            bool a_expectPatchedHooks,
            std::size_t& a_mismatches) noexcept
        {
            if (a_profile.playerSelectorHookSiteCount != 5 ||
                !a_profile.playerSelectorHookSites ||
                a_profile.playerHandleRva + sizeof(std::uint32_t) !=
                    a_profile.playerSingletonRva ||
                player_slot::kIndex >= a_profile.raisedEntries ||
                (a_expectPatchedHooks &&
                    (!g_reservation.allocation ||
                        !g_reservation.hooksActive)) ||
                (!a_expectPatchedHooks && g_reservation.hooksActive) ||
                g_constructingPlayer.load(std::memory_order_acquire)) {
                LogReservationMismatch("profile metadata", 0,
                    a_mismatches);
                ++a_mismatches;
                return false;
            }

            std::uint8_t objectRegister = 0;
            for (std::uint32_t index = 0;
                 index < a_profile.playerSelectorHookSiteCount; ++index) {
                const PlayerSelectorHookSite& site =
                    a_profile.playerSelectorHookSites[index];
                const bool rangesGood =
                    TextContains(a_runtime, site.hookRva,
                        sizeof(site.hookBytes)) &&
                    TextContains(a_runtime, site.functionRva,
                        sizeof(site.functionBytes)) &&
                    TextContains(a_runtime, site.objectSetupRva,
                        sizeof(site.objectSetupBytes)) &&
                    TextContains(a_runtime, site.lockCallRva,
                        sizeof(site.lockCallBytes)) &&
                    TextContains(a_runtime, site.unlockCallRva,
                        sizeof(site.unlockCallBytes)) &&
                    site.preHookRva == site.functionRva &&
                    site.preHookLen != 0 &&
                    site.preHookLen <= sizeof(site.preHookBytes) &&
                    site.preHookRva + site.preHookLen == site.hookRva &&
                    TextContains(a_runtime, site.preHookRva,
                        site.preHookLen) &&
                    site.continuationRva == site.hookRva + 6u &&
                    site.continuationLen != 0 &&
                    site.continuationLen <=
                        sizeof(site.continuationBytes) &&
                    TextContains(a_runtime, site.continuationRva,
                        site.continuationLen);
                if (!rangesGood) {
                    LogReservationMismatch("selector range", site.hookRva,
                        a_mismatches);
                    ++a_mismatches;
                    continue;
                }
                const auto* hook = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + site.hookRva);
                const auto* owner = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + site.functionRva);
                const auto* setup = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + site.objectSetupRva);
                const auto* lock = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + site.lockCallRva);
                const auto* unlock = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + site.unlockCallRva);
                std::uint8_t wantedHook[6]{};
                bool hookShapeGood = true;
                if (a_expectPatchedHooks) {
                    hookShapeGood = BuildHookBranch(0xE8,
                        reinterpret_cast<std::uintptr_t>(hook),
                        reinterpret_cast<std::uintptr_t>(
                            g_reservation.allocation +
                            kSelectorRelayOffset),
                        wantedHook);
                } else {
                    std::memcpy(wantedHook, site.hookBytes,
                        sizeof(wantedHook));
                    hookShapeGood = site.hookBytes[0] == 0x8B &&
                        site.hookBytes[1] == 0x05;
                }
                const bool liveHeadTargetGood = a_expectPatchedHooks ||
                    RelativeTarget(hook, 2, 6) ==
                        a_runtime.imageBase + a_profile.headRva;
                const bool callsGood = site.lockCallBytes[0] == 0xE8 &&
                    site.unlockCallBytes[0] == 0xE8 &&
                    RelativeTarget(lock, 1, 5) ==
                        a_runtime.imageBase + a_profile.lockWriteRva &&
                    RelativeTarget(unlock, 1, 5) ==
                        a_runtime.imageBase + a_profile.unlockWriteRva;
                const bool registerGood =
                    site.objectRegister == kPlayerObject_RBX ||
                    site.objectRegister == kPlayerObject_RDI;
                if (index == 0)
                    objectRegister = site.objectRegister;
                const bool exact = hookShapeGood && liveHeadTargetGood &&
                    callsGood && registerGood && site.stackAllocation == 0x30 &&
                    site.objectRegister == objectRegister &&
                    VerifyExpectedReservationWindow(a_runtime, a_profile,
                        site.preHookRva, site.preHookBytes,
                        site.preHookLen, a_expectPatchedHooks) &&
                    VerifyExpectedReservationWindow(a_runtime, a_profile,
                        site.continuationRva, site.continuationBytes,
                        site.continuationLen, a_expectPatchedHooks) &&
                    std::memcmp(hook, wantedHook, sizeof(wantedHook)) == 0 &&
                    std::memcmp(owner, site.functionBytes,
                        sizeof(site.functionBytes)) == 0 &&
                    std::memcmp(setup, site.objectSetupBytes,
                        sizeof(site.objectSetupBytes)) == 0 &&
                    std::memcmp(lock, site.lockCallBytes,
                        sizeof(site.lockCallBytes)) == 0 &&
                    std::memcmp(unlock, site.unlockCallBytes,
                        sizeof(site.unlockCallBytes)) == 0;
                if (!exact) {
                    LogReservationMismatch("selector", site.hookRva,
                        a_mismatches);
                    ++a_mismatches;
                }
            }

            const PlayerReleaseHookSite& release =
                a_profile.playerReleaseHook;
            const bool releaseRangesGood =
                release.resumeRva == release.hookRva + 6u &&
                TextContains(a_runtime, release.hookRva,
                    sizeof(release.hookBytes)) &&
                TextContains(a_runtime, release.functionRva,
                    sizeof(release.functionBytes)) &&
                TextContains(a_runtime, release.unlockCallRva,
                    sizeof(release.unlockCallBytes)) &&
                TextContains(a_runtime, release.resumeRva, 3) &&
                TextContains(a_runtime, release.reservedExitRva, 8) &&
                release.preHookRva == release.functionRva &&
                release.preHookLen != 0 &&
                release.preHookLen <= sizeof(release.preHookBytes) &&
                release.preHookRva + release.preHookLen == release.hookRva &&
                TextContains(a_runtime, release.preHookRva,
                    release.preHookLen) &&
                release.continuationRva == release.resumeRva &&
                release.continuationLen != 0 &&
                release.continuationLen <=
                    sizeof(release.continuationBytes) &&
                TextContains(a_runtime, release.continuationRva,
                    release.continuationLen);
            if (!releaseRangesGood) {
                LogReservationMismatch("release range", release.hookRva,
                    a_mismatches);
                ++a_mismatches;
                return false;
            }
            const auto* hook = reinterpret_cast<const std::uint8_t*>(
                a_runtime.imageBase + release.hookRva);
            const auto* owner = reinterpret_cast<const std::uint8_t*>(
                a_runtime.imageBase + release.functionRva);
            const auto* unlock = reinterpret_cast<const std::uint8_t*>(
                a_runtime.imageBase + release.unlockCallRva);
            const auto* resume = reinterpret_cast<const std::uint8_t*>(
                a_runtime.imageBase + release.resumeRva);
            const auto* reservedExit = reinterpret_cast<const std::uint8_t*>(
                a_runtime.imageBase + release.reservedExitRva);
            std::uint8_t wantedHook[6]{};
            bool hookGood = true;
            if (a_expectPatchedHooks) {
                hookGood = BuildHookBranch(0xE8,
                    reinterpret_cast<std::uintptr_t>(hook),
                    reinterpret_cast<std::uintptr_t>(
                        g_reservation.allocation + kReleaseRelayOffset),
                    wantedHook);
            } else {
                std::memcpy(wantedHook, release.hookBytes,
                    sizeof(wantedHook));
                hookGood = release.hookBytes[0] == 0x8B &&
                    release.hookBytes[1] == 0x05 &&
                    RelativeTarget(hook, 2, 6) ==
                        a_runtime.imageBase + a_profile.tailRva;
            }
            const bool releaseGood = hookGood &&
                VerifyExpectedReservationWindow(a_runtime, a_profile,
                    release.preHookRva, release.preHookBytes,
                    release.preHookLen, a_expectPatchedHooks) &&
                VerifyExpectedReservationWindow(a_runtime, a_profile,
                    release.continuationRva, release.continuationBytes,
                    release.continuationLen, a_expectPatchedHooks) &&
                resume[0] == 0x83 && resume[1] == 0xF8 &&
                resume[2] == 0xFF &&
                reservedExit[0] == 0x48 && reservedExit[1] == 0x8B &&
                reservedExit[2] == 0xCE &&
                release.unlockCallBytes[0] == 0xE8 &&
                RelativeTarget(unlock, 1, 5) ==
                    a_runtime.imageBase + a_profile.unlockWriteRva &&
                std::memcmp(hook, wantedHook, sizeof(wantedHook)) == 0 &&
                std::memcmp(owner, release.functionBytes,
                    sizeof(release.functionBytes)) == 0 &&
                std::memcmp(unlock, release.unlockCallBytes,
                    sizeof(release.unlockCallBytes)) == 0;
            if (!releaseGood) {
                LogReservationMismatch("release", release.hookRva,
                    a_mismatches);
                ++a_mismatches;
            }

            const PlayerLifecycleMetadata& lifecycle =
                a_profile.playerLifecycle;
            const auto exactSiteGood = [&](const ExactSite& a_site) noexcept {
                return a_site.len != 0 && a_site.len <= sizeof(a_site.orig) &&
                    TextContains(a_runtime, a_site.rva, a_site.len) &&
                    std::memcmp(reinterpret_cast<const void*>(
                            a_runtime.imageBase + a_site.rva),
                        a_site.orig, a_site.len) == 0;
            };
            const ExactSite& constructorCall = lifecycle.constructorCall;
            const bool constructorPreHookGood =
                lifecycle.constructorPreHookRva ==
                    lifecycle.creationFunctionRva &&
                lifecycle.constructorPreHookLen != 0 &&
                lifecycle.constructorPreHookLen <=
                    sizeof(lifecycle.constructorPreHookBytes) &&
                lifecycle.constructorPreHookRva +
                    lifecycle.constructorPreHookLen == constructorCall.rva &&
                TextContains(a_runtime, lifecycle.constructorPreHookRva,
                    lifecycle.constructorPreHookLen) &&
                std::memcmp(reinterpret_cast<const void*>(
                        a_runtime.imageBase +
                            lifecycle.constructorPreHookRva),
                    lifecycle.constructorPreHookBytes,
                    lifecycle.constructorPreHookLen) == 0;
            const bool constructorPostCallGood =
                lifecycle.constructorPostCallRva ==
                    constructorCall.rva + constructorCall.len &&
                lifecycle.constructorPostCallLen != 0 &&
                lifecycle.constructorPostCallLen <=
                    sizeof(lifecycle.constructorPostCallBytes) &&
                lifecycle.constructorPostCallRva +
                    lifecycle.constructorPostCallLen ==
                        lifecycle.singletonStore.rva &&
                TextContains(a_runtime, lifecycle.constructorPostCallRva,
                    lifecycle.constructorPostCallLen) &&
                std::memcmp(reinterpret_cast<const void*>(
                        a_runtime.imageBase +
                            lifecycle.constructorPostCallRva),
                    lifecycle.constructorPostCallBytes,
                    lifecycle.constructorPostCallLen) == 0;
            std::uint8_t wantedConstructorCall[5]{};
            bool constructorBranchGood = constructorCall.len ==
                sizeof(wantedConstructorCall);
            if (constructorBranchGood && a_expectPatchedHooks) {
                constructorBranchGood = BuildCallBranch(
                    a_runtime.imageBase + constructorCall.rva,
                    reinterpret_cast<std::uintptr_t>(
                        g_reservation.allocation +
                            kConstructorRelayOffset),
                    wantedConstructorCall);
            } else if (constructorBranchGood) {
                std::memcpy(wantedConstructorCall, constructorCall.orig,
                    sizeof(wantedConstructorCall));
            }
            const bool constructorGood = constructorPreHookGood &&
                constructorPostCallGood &&
                constructorBranchGood &&
                TextContains(a_runtime, constructorCall.rva,
                    sizeof(wantedConstructorCall)) &&
                TextContains(a_runtime, lifecycle.constructorFunctionRva,
                    sizeof(lifecycle.constructorFunctionBytes)) &&
                constructorCall.orig[0] == 0xE8 &&
                RelativeTargetAt(constructorCall.orig,
                    a_runtime.imageBase + constructorCall.rva, 1, 5) ==
                    a_runtime.imageBase +
                        lifecycle.constructorFunctionRva &&
                std::memcmp(reinterpret_cast<const void*>(
                        a_runtime.imageBase + constructorCall.rva),
                    wantedConstructorCall,
                    sizeof(wantedConstructorCall)) == 0 &&
                std::memcmp(reinterpret_cast<const void*>(
                        a_runtime.imageBase +
                            lifecycle.constructorFunctionRva),
                    lifecycle.constructorFunctionBytes,
                    sizeof(lifecycle.constructorFunctionBytes)) == 0;
            const bool teardownOwnerStock =
                TextContains(a_runtime, lifecycle.teardownFunctionRva,
                    sizeof(lifecycle.teardownFunctionBytes)) &&
                std::memcmp(reinterpret_cast<const void*>(
                        a_runtime.imageBase +
                            lifecycle.teardownFunctionRva),
                    lifecycle.teardownFunctionBytes,
                    sizeof(lifecycle.teardownFunctionBytes)) == 0;
            const bool teardownOwnerInterop = !teardownOwnerStock &&
                enginefixes::IsAuthenticatedFormCachingLifecycleOwner(
                    a_runtime, lifecycle.teardownFunctionRva,
                    lifecycle.teardownFunctionBytes,
                    sizeof(lifecycle.teardownFunctionBytes));
            bool lifecycleGood =
                TextContains(a_runtime, lifecycle.creationFunctionRva,
                    sizeof(lifecycle.creationFunctionBytes)) &&
                TextContains(a_runtime, lifecycle.teardownFunctionRva,
                    sizeof(lifecycle.teardownFunctionBytes)) &&
                std::memcmp(reinterpret_cast<const void*>(
                        a_runtime.imageBase + lifecycle.creationFunctionRva),
                    lifecycle.creationFunctionBytes,
                    sizeof(lifecycle.creationFunctionBytes)) == 0 &&
                constructorGood &&
                (teardownOwnerStock || teardownOwnerInterop) &&
                exactSiteGood(lifecycle.singletonStore) &&
                exactSiteGood(lifecycle.candidateLoad) &&
                exactSiteGood(lifecycle.allocatorCall) &&
                exactSiteGood(lifecycle.handleStore) &&
                exactSiteGood(lifecycle.formIDSetup) &&
                exactSiteGood(lifecycle.formIDCall) &&
                exactSiteGood(lifecycle.teardownHandleLoad) &&
                exactSiteGood(lifecycle.teardownReleaseCall) &&
                exactSiteGood(lifecycle.singletonClear) &&
                lifecycle.teardownZeroSources &&
                lifecycle.teardownZeroSourceCount >= 1 &&
                lifecycle.teardownZeroSourceCount <= 2 &&
                lifecycle.creationFunctionRva < constructorCall.rva &&
                constructorCall.rva + constructorCall.len <=
                    lifecycle.singletonStore.rva &&
                lifecycle.singletonStore.rva < lifecycle.candidateLoad.rva &&
                lifecycle.candidateLoad.rva < lifecycle.allocatorCall.rva &&
                lifecycle.allocatorCall.rva < lifecycle.handleStore.rva &&
                lifecycle.handleStore.rva < lifecycle.formIDSetup.rva &&
                lifecycle.formIDSetup.rva < lifecycle.formIDCall.rva &&
                lifecycle.teardownHandleLoad.rva <
                    lifecycle.teardownReleaseCall.rva &&
                lifecycle.teardownReleaseCall.rva <
                    lifecycle.singletonClear.rva;
            for (std::uint32_t index = 0;
                 index < lifecycle.teardownZeroSourceCount; ++index) {
                lifecycleGood = lifecycleGood &&
                    exactSiteGood(lifecycle.teardownZeroSources[index]);
            }
            if (lifecycleGood) {
                const auto* singletonStore =
                    reinterpret_cast<const std::uint8_t*>(
                        a_runtime.imageBase + lifecycle.singletonStore.rva);
                const auto* candidateLoad =
                    reinterpret_cast<const std::uint8_t*>(
                        a_runtime.imageBase + lifecycle.candidateLoad.rva);
                const auto* allocatorCall =
                    reinterpret_cast<const std::uint8_t*>(
                        a_runtime.imageBase + lifecycle.allocatorCall.rva);
                const auto* handleStore =
                    reinterpret_cast<const std::uint8_t*>(
                        a_runtime.imageBase + lifecycle.handleStore.rva);
                const auto* formIDSetup =
                    reinterpret_cast<const std::uint8_t*>(
                        a_runtime.imageBase + lifecycle.formIDSetup.rva);
                const auto* formIDCall =
                    reinterpret_cast<const std::uint8_t*>(
                        a_runtime.imageBase + lifecycle.formIDCall.rva);
                const auto* teardownLoad =
                    reinterpret_cast<const std::uint8_t*>(
                        a_runtime.imageBase + lifecycle.teardownHandleLoad.rva);
                const auto* teardownRelease =
                    reinterpret_cast<const std::uint8_t*>(
                        a_runtime.imageBase + lifecycle.teardownReleaseCall.rva);
                const auto* singletonClear =
                    reinterpret_cast<const std::uint8_t*>(
                        a_runtime.imageBase + lifecycle.singletonClear.rva);
                lifecycleGood =
                    lifecycle.singletonStore.len == 7 &&
                    singletonStore[0] == 0x48 && singletonStore[1] == 0x89 &&
                    RelativeTarget(singletonStore, 3, 7) ==
                        a_runtime.imageBase + a_profile.playerSingletonRva &&
                    lifecycle.candidateLoad.len == 7 &&
                    candidateLoad[0] == 0x48 && candidateLoad[1] == 0x8B &&
                    RelativeTarget(candidateLoad, 3, 7) ==
                        a_runtime.imageBase + a_profile.playerSingletonRva &&
                    lifecycle.allocatorCall.len == 5 &&
                    allocatorCall[0] == 0xE8 &&
                    RelativeTarget(allocatorCall, 1, 5) ==
                        a_runtime.imageBase +
                        a_profile.playerSelectorHookSites[0].functionRva &&
                    lifecycle.handleStore.len == 6 &&
                    handleStore[0] == 0x89 && handleStore[1] == 0x0D &&
                    RelativeTarget(handleStore, 2, 6) ==
                        a_runtime.imageBase + a_profile.playerHandleRva &&
                    lifecycle.formIDSetup.len == 5 &&
                    std::memcmp(formIDSetup,
                        "\xBA\x14\x00\x00\x00", 5) == 0 &&
                    lifecycle.formIDCall.len == 6 &&
                    std::memcmp(formIDCall,
                        "\xFF\x90\xC0\x01\x00\x00", 6) == 0 &&
                    lifecycle.teardownHandleLoad.len == 6 &&
                    teardownLoad[0] == 0x8B && teardownLoad[1] == 0x05 &&
                    RelativeTarget(teardownLoad, 2, 6) ==
                        a_runtime.imageBase + a_profile.playerHandleRva &&
                    lifecycle.teardownReleaseCall.len == 5 &&
                    teardownRelease[0] == 0xE8 &&
                    RelativeTarget(teardownRelease, 1, 5) ==
                        a_runtime.imageBase + release.functionRva &&
                    lifecycle.singletonClear.len == 7 &&
                    singletonClear[0] == 0x48 &&
                    singletonClear[1] == 0x89 &&
                    RelativeTarget(singletonClear, 3, 7) ==
                        a_runtime.imageBase + a_profile.playerSingletonRva;
                const std::uint8_t clearSource = singletonClear[2] == 0x3D ?
                    0xFF : (singletonClear[2] == 0x35 ? 0xF6 : 0);
                for (std::uint32_t index = 0;
                     lifecycleGood &&
                     index < lifecycle.teardownZeroSourceCount; ++index) {
                    const ExactSite& zero =
                        lifecycle.teardownZeroSources[index];
                    lifecycleGood = zero.len == 2 && zero.orig[0] == 0x33 &&
                        zero.orig[1] == clearSource;
                }
            }
            if (!lifecycleGood) {
                LogReservationMismatch("lifecycle ordering/bytes", 0,
                    a_mismatches);
                ++a_mismatches;
            } else if (teardownOwnerInterop) {
                // This line is deliberately deferred until every exact deep
                // lifecycle site and ordering check above has also passed.
                enginefixes::LogAuthenticatedFormCachingLifecycleOwner();
            }
            return a_mismatches == 0;
        }

        [[nodiscard]] bool VerifyStockCode(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            std::size_t& a_mismatches) noexcept
        {
            a_mismatches = 0;
            for (std::uint32_t index = 0;
                 index < a_profile.fieldCount; ++index) {
                const FieldPatch& field = a_profile.fields[index];
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + field.rva);
                if (field.len == 0 || field.len > sizeof(field.orig) ||
                    field.fieldW == 0 ||
                    field.fieldOff + field.fieldW > field.len ||
                    std::memcmp(address, field.orig, field.len) != 0) {
                    LogByteMismatch(CategoryName(field.cat), field.rva,
                        field.orig, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            for (std::uint32_t index = 0;
                 index < a_profile.tableRefCount; ++index) {
                const TableRef& reference = a_profile.tableRefs[index];
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + reference.rva);
                bool bad = reference.len == 0 ||
                    reference.len > sizeof(reference.orig) ||
                    reference.dispOff + sizeof(std::int32_t) != reference.len ||
                    std::memcmp(
                        address, reference.orig, reference.len) != 0;
                if (!bad) {
                    std::int32_t displacement = 0;
                    std::memcpy(&displacement,
                        address + reference.dispOff, sizeof(displacement));
                    const std::uintptr_t target =
                        static_cast<std::uintptr_t>(
                            static_cast<std::int64_t>(a_runtime.imageBase +
                                reference.rva + reference.len) + displacement);
                    bad = target !=
                        a_runtime.imageBase + a_profile.tableRva;
                }
                if (bad) {
                    LogByteMismatch("table reference", reference.rva,
                        reference.orig, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            for (std::uint32_t index = 0;
                 index < a_profile.initPatchCount; ++index) {
                const BytePatch& patch = a_profile.initPatches[index];
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + patch.rva);
                if (patch.len == 0 || patch.len > sizeof(patch.orig) ||
                    std::memcmp(address, patch.orig, patch.len) != 0) {
                    LogByteMismatch("initialiser guard", patch.rva,
                        patch.orig, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            (void)VerifyReservationCode(
                a_runtime, a_profile, false, a_mismatches);
            return a_mismatches == 0;
        }

        [[nodiscard]] bool VerifyPatchedCode(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            std::uintptr_t a_table,
            bool a_patchedInitPatches,
            std::size_t& a_mismatches) noexcept
        {
            a_mismatches = 0;
            std::uint8_t wanted[15]{};
            for (std::uint32_t index = 0;
                 index < a_profile.fieldCount; ++index) {
                const FieldPatch& field = a_profile.fields[index];
                std::memcpy(wanted, field.orig, field.len);
                if (field.fieldW == 4) {
                    std::memcpy(wanted + field.fieldOff,
                        &field.newVal, sizeof(field.newVal));
                } else {
                    wanted[field.fieldOff] =
                        static_cast<std::uint8_t>(field.newVal);
                }
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + field.rva);
                if (std::memcmp(address, wanted, field.len) != 0) {
                    LogByteMismatch(CategoryName(field.cat), field.rva,
                        wanted, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            for (std::uint32_t index = 0;
                 index < a_profile.tableRefCount; ++index) {
                const TableRef& reference = a_profile.tableRefs[index];
                std::memcpy(wanted, reference.orig, reference.len);
                const std::int64_t delta =
                    static_cast<std::int64_t>(a_table) -
                    static_cast<std::int64_t>(a_runtime.imageBase +
                        reference.rva + reference.len);
                const std::int32_t displacement =
                    static_cast<std::int32_t>(delta);
                std::memcpy(wanted + reference.dispOff,
                    &displacement, sizeof(displacement));
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + reference.rva);
                if (std::memcmp(address, wanted, reference.len) != 0) {
                    LogByteMismatch("table reference", reference.rva,
                        wanted, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            for (std::uint32_t index = 0;
                 index < a_profile.initPatchCount; ++index) {
                const BytePatch& patch = a_profile.initPatches[index];
                const std::uint8_t* wantedPatch = a_patchedInitPatches ?
                    patch.repl : patch.orig;
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + patch.rva);
                if (std::memcmp(address, wantedPatch, patch.len) != 0) {
                    LogByteMismatch("initialiser guard", patch.rva,
                        wantedPatch, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            (void)VerifyReservationCode(
                a_runtime, a_profile, true, a_mismatches);
            if (!VerifyReservationRelayBytes()) {
                LogReservationMismatch("relay bytes", 0, a_mismatches);
                ++a_mismatches;
            }
            return a_mismatches == 0;
        }

        [[nodiscard]] bool VerifyPristine(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            bool& a_stockFreeListInitialized) noexcept
        {
            const std::uint32_t head =
                *reinterpret_cast<std::uint32_t*>(
                    a_runtime.imageBase + a_profile.headRva);
            const std::uint32_t tail =
                *reinterpret_cast<std::uint32_t*>(
                    a_runtime.imageBase + a_profile.tailRva);
            const std::uint32_t stockTail = a_profile.stockEntries - 1;
            auto* table = reinterpret_cast<HandleEntry*>(
                a_runtime.imageBase + a_profile.tableRva);

            const bool zeroState = head == 0 && tail == 0;
            const bool stockState = head == 0 && tail == stockTail;
            if (!zeroState && !stockState) {
                Log("  pool is not pristine: head=%08x tail=%08x "
                    "(expected 0/0 or 0/%08x)", head, tail, stockTail);
                return false;
            }

            std::size_t bad = 0;
            for (std::uint32_t index = 0;
                 index < a_profile.stockEntries; ++index) {
                const std::uint32_t wantedBits = zeroState ? 0u :
                    (index + 1 < a_profile.stockEntries ? index + 1 : index);
                if (table[index].bits != wantedBits ||
                    table[index].pad != 0 ||
                    table[index].pointer != nullptr) {
                    if (bad < 8) {
                        Log("  entry %u is not pristine: bits=%08x "
                            "(want %08x), pad=%08x, pointer=%p", index,
                            table[index].bits, wantedBits,
                            table[index].pad, table[index].pointer);
                    }
                    ++bad;
                }
            }
            if (bad) {
                Log("  refusing to patch: %zu stock-table entries differ "
                    "from the exact %s state", bad,
                    zeroState ? "zero-filled" : "initial free-list");
                return false;
            }
            a_stockFreeListInitialized = stockState;
            return true;
        }

        [[nodiscard]] std::uint8_t* AllocateTableNear(
            const RuntimeContext& a_runtime,
            std::size_t a_bytes) noexcept
        {
            for (std::uintptr_t offset = 0x10000000;
                 offset <= 0x40000000; offset += 0x04000000) {
                if (auto* allocation = static_cast<std::uint8_t*>(VirtualAlloc(
                        reinterpret_cast<void*>(
                            a_runtime.imageBase + offset),
                        a_bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
                    return allocation;
                }
            }
            return static_cast<std::uint8_t*>(VirtualAlloc(
                nullptr, a_bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        }

        [[nodiscard]] bool InDispRange(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            std::uintptr_t a_table) noexcept
        {
            for (std::uint32_t index = 0;
                 index < a_profile.tableRefCount; ++index) {
                const TableRef& reference = a_profile.tableRefs[index];
                const std::uintptr_t instructionEnd =
                    a_runtime.imageBase + reference.rva + reference.len;
                const std::int64_t delta =
                    static_cast<std::int64_t>(a_table) -
                    static_cast<std::int64_t>(instructionEnd);
                if (delta < INT32_MIN || delta > INT32_MAX)
                    return false;
            }
            return true;
        }

        void InitializeTable(
            const Profile& a_profile, std::uint8_t* a_table) noexcept
        {
            auto* entries = reinterpret_cast<HandleEntry*>(a_table);
            const std::uint32_t last = a_profile.raisedEntries - 1;
            for (std::uint32_t index = 0;
                 index < a_profile.raisedEntries; ++index) {
                if (index == player_slot::kIndex) {
                    entries[index].bits = player_slot::kDetachedBits;
                } else if (index + 1u == player_slot::kIndex) {
                    entries[index].bits = player_slot::kIndex + 1u;
                } else {
                    entries[index].bits = index < last ? index + 1 : index;
                }
                entries[index].pad = 0;
                entries[index].pointer = nullptr;
            }
        }

        [[nodiscard]] bool VerifyNewTable(
            const Profile& a_profile,
            const std::uint8_t* a_table) noexcept
        {
            const auto* entries =
                reinterpret_cast<const HandleEntry*>(a_table);
            const std::uint32_t last = a_profile.raisedEntries - 1;
            for (std::uint32_t index = 0;
                 index < a_profile.raisedEntries; ++index) {
                std::uint32_t wanted = index < last ? index + 1 : index;
                if (index == player_slot::kIndex)
                    wanted = player_slot::kDetachedBits;
                else if (index + 1u == player_slot::kIndex)
                    wanted = player_slot::kIndex + 1u;
                if (entries[index].bits != wanted ||
                    entries[index].pad != 0 ||
                    entries[index].pointer != nullptr) {
                    Log("  new-table verification failed at entry %u: "
                        "bits=%08x (want %08x), pad=%08x, pointer=%p", index,
                        entries[index].bits, wanted, entries[index].pad,
                        entries[index].pointer);
                    return false;
                }
            }
            return true;
        }

        void ApplyCode(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            std::uintptr_t a_table,
            bool a_patchInitPatches) noexcept
        {
            for (std::uint32_t index = 0;
                 index < a_profile.fieldCount; ++index) {
                const FieldPatch& field = a_profile.fields[index];
                auto* address = reinterpret_cast<std::uint8_t*>(
                    a_runtime.imageBase + field.rva) + field.fieldOff;
                if (field.fieldW == 4)
                    std::memcpy(address, &field.newVal, sizeof(field.newVal));
                else
                    *address = static_cast<std::uint8_t>(field.newVal);
            }
            for (std::uint32_t index = 0;
                 index < a_profile.tableRefCount; ++index) {
                const TableRef& reference = a_profile.tableRefs[index];
                const std::int64_t delta =
                    static_cast<std::int64_t>(a_table) -
                    static_cast<std::int64_t>(a_runtime.imageBase +
                        reference.rva + reference.len);
                const std::int32_t displacement =
                    static_cast<std::int32_t>(delta);
                std::memcpy(reinterpret_cast<void*>(a_runtime.imageBase +
                        reference.rva + reference.dispOff),
                    &displacement, sizeof(displacement));
            }
            if (a_patchInitPatches) {
                for (std::uint32_t index = 0;
                     index < a_profile.initPatchCount; ++index) {
                    const BytePatch& patch = a_profile.initPatches[index];
                    std::memcpy(reinterpret_cast<void*>(
                            a_runtime.imageBase + patch.rva),
                    patch.repl, patch.len);
                }
            }
            ApplyReservationHooks(a_runtime, a_profile);
        }

        void RestoreStockCode(
            const RuntimeContext& a_runtime,
            const Profile& a_profile) noexcept
        {
            // Hooks are restored first.  Only after no engine path can enter
            // the relays may rollback/free the relay page or raised table.
            RestoreReservationHooks(a_runtime, a_profile);
            for (std::uint32_t index = 0;
                 index < a_profile.fieldCount; ++index) {
                const FieldPatch& field = a_profile.fields[index];
                std::memcpy(reinterpret_cast<void*>(
                        a_runtime.imageBase + field.rva),
                    field.orig, field.len);
            }
            for (std::uint32_t index = 0;
                 index < a_profile.tableRefCount; ++index) {
                const TableRef& reference = a_profile.tableRefs[index];
                std::memcpy(reinterpret_cast<void*>(
                        a_runtime.imageBase + reference.rva),
                    reference.orig, reference.len);
            }
            for (std::uint32_t index = 0;
                 index < a_profile.initPatchCount; ++index) {
                const BytePatch& patch = a_profile.initPatches[index];
                std::memcpy(reinterpret_cast<void*>(
                        a_runtime.imageBase + patch.rva),
                    patch.orig, patch.len);
            }
        }

        [[noreturn]] void FatalStop(const char* a_reason) noexcept
        {
            Log("FATAL: %s", a_reason);
            Log("The patch could not prove a complete rollback. Terminating "
                "Skyrim before engine state or a save can be corrupted.");
            TerminateProcess(GetCurrentProcess(), 0x53484352u);
            ExitProcess(0x52u);
        }

        void RollBackOrStop(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            DWORD a_oldProtection,
            std::uint32_t a_oldHead,
            std::uint32_t a_oldTail,
            const char* a_reason) noexcept
        {
            Log("ABORT after writes: %s; restoring every stock instruction.",
                a_reason);
            DWORD currentProtection = 0;
            if (!VirtualProtect(a_runtime.text.begin, a_runtime.text.size,
                    PAGE_EXECUTE_READWRITE, &currentProtection)) {
                FatalStop("could not make .text writable for rollback");
            }
            *reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + a_profile.headRva) = a_oldHead;
            *reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + a_profile.tailRva) = a_oldTail;
            RestoreStockCode(a_runtime, a_profile);

            std::size_t mismatches = 0;
            const bool bytesRestored = VerifyStockCode(
                a_runtime, a_profile, mismatches);
            const std::size_t stockRefs = CountDispRefs(
                a_runtime, a_runtime.imageBase + a_profile.tableRva);
            const bool globalsRestored =
                *reinterpret_cast<const std::uint32_t*>(
                    a_runtime.imageBase + a_profile.headRva) == a_oldHead &&
                *reinterpret_cast<const std::uint32_t*>(
                    a_runtime.imageBase + a_profile.tailRva) == a_oldTail;
            bool restoredStockFreeListInitialized = false;
            const bool poolRestored = globalsRestored &&
                VerifyPristine(a_runtime, a_profile,
                    restoredStockFreeListInitialized) &&
                restoredStockFreeListInitialized ==
                    (a_oldTail == a_profile.stockEntries - 1);
            const bool cacheFlushed = FlushInstructionCache(
                GetCurrentProcess(), a_runtime.text.begin,
                a_runtime.text.size) != FALSE;
            DWORD ignored = 0;
            const bool protectionRestored = VirtualProtect(
                a_runtime.text.begin, a_runtime.text.size,
                a_oldProtection, &ignored) != FALSE;
            if (!bytesRestored || stockRefs != a_profile.tableRefCount ||
                !poolRestored || !cacheFlushed || !protectionRestored) {
                FatalStop("stock bytes, table references, manager globals/pool, "
                    "cache, or page protection did not verify after rollback");
            }
            Log("rollback verified: all stock bytes, %u stock table references, "
                "manager globals, and the complete pristine pool were restored; "
                "no cap raise remains active.", a_profile.tableRefCount);
        }
    }

    ReservedPlayerLifecycleSnapshot
    ReadReservedPlayerLifecycleSnapshot() noexcept
    {
        return {
            g_reservedPlayerConstructorAssignments.load(
                std::memory_order_acquire),
            g_reservedPlayerReleaseQuarantines.load(
                std::memory_order_acquire),
        };
    }

    Result Raise(
        const RuntimeContext& a_runtime,
        const Lifecycle& a_lifecycle) noexcept
    {
        Result result;
        bool lifecyclePrepared = false;
        const auto notifyAbort = [&]() noexcept {
            if (lifecyclePrepared && a_lifecycle.onPatchAborted) {
                a_lifecycle.onPatchAborted(a_lifecycle.context);
                lifecyclePrepared = false;
            }
        };

        if (!a_runtime.text.begin) {
            Log("could not locate the executable's .text section; no changes made");
            return result;
        }

        const std::uint32_t version = a_runtime.runtimeVersion;
        const Profile* profile = a_runtime.profile;
        Log("runtime version %u.%u.%u.%u, image base %016llx, "
            ".text %016llx + %zu",
            (version >> 24) & 0xFF, (version >> 16) & 0xFF,
            (version >> 4) & 0xFFF, version & 0xF,
            static_cast<unsigned long long>(a_runtime.imageBase),
            static_cast<unsigned long long>(
                reinterpret_cast<std::uintptr_t>(a_runtime.text.begin)),
            a_runtime.text.size);

        if (!profile) {
            Log("no verified patch profile for this runtime; no changes made.");
            Log("supported: Skyrim SE 1.5.97, Skyrim AE 1.6.1170, "
                "Skyrim GOG 1.6.1179, and Skyrim VR 1.4.15.");
            return result;
        }
        if (profile->stockEntries != player_slot::kIndex ||
            profile->raisedEntries != generation::kEntryCount ||
            profile->entrySize != sizeof(HandleEntry)) {
            Log("ABORT: profile layout is %u -> %u entries of %u bytes, but "
                "this runtime requires exactly %u -> %u entries of %zu bytes.",
                profile->stockEntries, profile->raisedEntries,
                profile->entrySize, player_slot::kIndex,
                generation::kEntryCount, sizeof(HandleEntry));
            return result;
        }
        Log("profile: %s -- %u field rewrites + %u table references, "
            "slots %u -> %u", profile->name,
            profile->fieldCount, profile->tableRefCount, profile->stockEntries,
            profile->raisedEntries);

        LogEngineFixesCompatibility();

        std::size_t mismatches = 0;
        if (!VerifyStockCode(a_runtime, *profile, mismatches)) {
            Log("ABORT: %zu audited instructions or lifecycle sites do not "
                "match their expected stock bytes.", mismatches);
            Log("The executable is not the build this profile was built from, "
                "or another mod patched the same code. No changes made.");
            return result;
        }

        const std::size_t liveRefs = CountDispRefs(
            a_runtime, a_runtime.imageBase + profile->tableRva);
        if (liveRefs != profile->tableRefCount) {
            Log("ABORT: this executable contains %zu references to the handle "
                "table but the profile knows %u. Patching a partial set "
                "resolves handles to the wrong object silently, so no changes "
                "were made.", liveRefs, profile->tableRefCount);
            return result;
        }
        Log("verified stock bytes: %u fields, %u table references, and %u "
            "initialiser guards; object cache and release invalidation remain stock",
            profile->fieldCount, profile->tableRefCount,
            profile->initPatchCount);

        const std::size_t tableBytes =
            static_cast<std::size_t>(profile->raisedEntries) *
            profile->entrySize;
        std::uint8_t* table = AllocateTableNear(a_runtime, tableBytes);
        if (!table) {
            Log("ABORT: could not allocate %zu bytes for the new handle table.",
                tableBytes);
            return result;
        }
        if (!InDispRange(a_runtime, *profile,
                reinterpret_cast<std::uintptr_t>(table))) {
            Log("ABORT: the allocation at %016llx is out of 32-bit "
                "displacement range of the code that must address it.",
                static_cast<unsigned long long>(
                    reinterpret_cast<std::uintptr_t>(table)));
            VirtualFree(table, 0, MEM_RELEASE);
            return result;
        }
        InitializeTable(*profile, table);
        if (!VerifyNewTable(*profile, table)) {
            Log("ABORT: the new table's complete free-list chain did not verify.");
            VirtualFree(table, 0, MEM_RELEASE);
            return result;
        }
        Log("new handle table: %zu MB at %016llx",
            tableBytes / (1024 * 1024),
            static_cast<unsigned long long>(
                reinterpret_cast<std::uintptr_t>(table)));
        Log("new free list verified through final index %08x with player "
            "slot %08x detached at generation %u",
            profile->raisedEntries - 1, player_slot::kIndex,
            player_slot::kDetachedGeneration);

        if (!PrepareReservationRelays(a_runtime, *profile,
                reinterpret_cast<HandleEntry*>(table))) {
            Log("ABORT: could not build and publish rel32-reachable, "
                "byte-verified player reservation relays.");
            VirtualFree(table, 0, MEM_RELEASE);
            return result;
        }

        const HandleTableView tableView{
            reinterpret_cast<HandleEntry*>(table), profile->raisedEntries
        };
        if (a_lifecycle.onTablePrepared) {
            lifecyclePrepared = true;
            if (!a_lifecycle.onTablePrepared(
                    a_lifecycle.context, a_runtime, tableView)) {
                Log("ABORT: a mandatory pre-commit component could not be "
                    "prepared; no executable changes were made.");
                CancelReservationRelays();
                VirtualFree(table, 0, MEM_RELEASE);
                notifyAbort();
                return result;
            }
        }

        LockManager(a_runtime, *profile);
        bool stockFreeListInitialized = false;
        if (!VerifyPristine(
                a_runtime, *profile, stockFreeListInitialized)) {
            UnlockManager(a_runtime, *profile);
            Log("ABORT: the handle pool is not exactly pristine. No changes made.");
            CancelReservationRelays();
            VirtualFree(table, 0, MEM_RELEASE);
            notifyAbort();
            return result;
        }
        Log("pool is pristine (free-list initializer %s run)",
            stockFreeListInitialized ? "has" : "has not");

        const std::uint32_t oldHead =
            *reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + profile->headRva);
        const std::uint32_t oldTail =
            *reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + profile->tailRva);
        DWORD oldProtection = 0;
        if (!VirtualProtect(a_runtime.text.begin, a_runtime.text.size,
                PAGE_EXECUTE_READWRITE, &oldProtection)) {
            Log("ABORT: could not make .text writable (error %lu).",
                GetLastError());
            UnlockManager(a_runtime, *profile);
            CancelReservationRelays();
            VirtualFree(table, 0, MEM_RELEASE);
            notifyAbort();
            return result;
        }

        const bool patchInitPatches = !stockFreeListInitialized;
        ApplyCode(a_runtime, *profile,
            reinterpret_cast<std::uintptr_t>(table), patchInitPatches);
        const std::uint32_t last = profile->raisedEntries - 1;
        *reinterpret_cast<std::uint32_t*>(
            a_runtime.imageBase + profile->headRva) = 0;
        *reinterpret_cast<std::uint32_t*>(
            a_runtime.imageBase + profile->tailRva) = last;

        std::size_t patchedMismatches = 0;
        const bool codeGood = VerifyPatchedCode(a_runtime, *profile,
            reinterpret_cast<std::uintptr_t>(table), patchInitPatches,
            patchedMismatches);
        const std::size_t staleRefs = CountDispRefs(
            a_runtime, a_runtime.imageBase + profile->tableRva);
        const std::size_t newRefs = CountDispRefs(
            a_runtime, reinterpret_cast<std::uintptr_t>(table));
        const bool globalsGood =
            *reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + profile->headRva) == 0 &&
            *reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + profile->tailRva) == last;
        const bool tableGood = VerifyNewTable(*profile, table);
        if (!codeGood || staleRefs != 0 ||
            newRefs != profile->tableRefCount || !globalsGood || !tableGood) {
            Log("post-write verification: mismatches=%zu oldRefs=%zu "
                "newRefs=%zu globals=%s table=%s", patchedMismatches,
                staleRefs, newRefs, globalsGood ? "PASS" : "FAIL",
                tableGood ? "PASS" : "FAIL");
            RollBackOrStop(a_runtime, *profile, oldProtection,
                oldHead, oldTail, "post-write verification failed");
            CancelReservationRelays();
            UnlockManager(a_runtime, *profile);
            VirtualFree(table, 0, MEM_RELEASE);
            notifyAbort();
            return result;
        }

        if (!FlushInstructionCache(GetCurrentProcess(),
                a_runtime.text.begin, a_runtime.text.size)) {
            RollBackOrStop(a_runtime, *profile, oldProtection,
                oldHead, oldTail,
                "FlushInstructionCache failed before commit");
            CancelReservationRelays();
            UnlockManager(a_runtime, *profile);
            VirtualFree(table, 0, MEM_RELEASE);
            notifyAbort();
            return result;
        }
        DWORD ignored = 0;
        if (!VirtualProtect(a_runtime.text.begin, a_runtime.text.size,
                oldProtection, &ignored)) {
            RollBackOrStop(a_runtime, *profile, oldProtection,
                oldHead, oldTail,
                "could not restore executable page protection before commit");
            CancelReservationRelays();
            UnlockManager(a_runtime, *profile);
            VirtualFree(table, 0, MEM_RELEASE);
            notifyAbort();
            return result;
        }

        if (a_lifecycle.onCommittedWhileManagerLocked) {
            if (!a_lifecycle.onCommittedWhileManagerLocked(
                    a_lifecycle.context, a_runtime, tableView)) {
                RollBackOrStop(a_runtime, *profile, oldProtection,
                    oldHead, oldTail,
                    "mandatory manager-locked commit component failed");
                CancelReservationRelays();
                UnlockManager(a_runtime, *profile);
                VirtualFree(table, 0, MEM_RELEASE);
                notifyAbort();
                return result;
            }
        }

        Log("SUCCESS: reference handle slots raised %u -> %u (index 21 bits, "
            "age 5 bits / 32 generations, in-use bit 26 and the complete "
            "_refCount index cache remain stock-shaped).", profile->stockEntries,
            profile->raisedEntries);
        Log("post-patch verification: 0 stale references, %zu/%u new "
            "references, all rewrites/free-list/globals and player "
            "constructor/selector/release relays verified%s.", newRefs,
            profile->tableRefCount, patchInitPatches ?
                "; future stock initialisation disabled" : "");

        g_reservation.committed = true;
        result = { true, tableView, profile };
        UnlockManager(a_runtime, *profile);
        lifecyclePrepared = false;
        return result;
    }
}
