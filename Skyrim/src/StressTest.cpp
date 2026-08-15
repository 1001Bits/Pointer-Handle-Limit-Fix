#include "StressTest.h"

#include "EngineFixesInterop.h"
#include "GenerationDiagnostic.h"
#include "PatchTransaction.h"
#include "ReservedPlayerSlot.h"
#include "RuntimeTypes.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <string>
#include <unordered_map>
#include <vector>

namespace shcr::stress
{
    namespace
    {
        using PluginHandle = std::uint32_t;

        // Raw SKSE ABI. These layouts are shared by SKSE 2.0.20 (SE 1.5.97),
        // the AE/GOG loader, and SKSEVR 2.0.12 (VR 1.4.15).
        struct SKSEInterface
        {
            std::uint32_t skseVersion;
            std::uint32_t runtimeVersion;
            std::uint32_t editorVersion;
            std::uint32_t isEditor;
            void* (*QueryInterface)(std::uint32_t);
            PluginHandle (*GetPluginHandle)();
            std::uint32_t (*GetReleaseIndex)();
            const void* (*GetPluginInfo)(const char*);
        };

        struct SKSEMessagingInterface
        {
            std::uint32_t interfaceVersion;
            bool (*RegisterListener)(PluginHandle, const char*, void*);
            bool (*Dispatch)(PluginHandle, std::uint32_t, void*, std::uint32_t, const char*);
            void* (*GetEventDispatcher)(std::uint32_t);
        };

        struct SKSETaskInterface
        {
            std::uint32_t interfaceVersion;
            void (*AddTask)(void*);
            void (*AddUITask)(void*);
        };

        struct SKSEMessage
        {
            const char*   sender;
            std::uint32_t type;
            std::uint32_t dataLen;
            void*         data;
        };

        class TaskDelegate
        {
        public:
            virtual void Run() = 0;
            virtual void Dispose() = 0;

        protected:
            ~TaskDelegate() = default;
        };

        constexpr std::uint32_t kTaskInterface = 4;
        constexpr std::uint32_t kMessagingInterface = 5;
        constexpr std::uint32_t kPreLoadGame = 2;
        constexpr std::uint32_t kPostLoadGame = 3;
        constexpr std::uint32_t kNewGame = 7;
        constexpr std::uint32_t kDataLoaded = 8;
        constexpr std::uint32_t kReferenceCountMask = 0x3FF;
        constexpr std::uint32_t kHandleValidBit = 0x400;
        constexpr std::uint32_t kObjectIndexMask = 0x1FFFFF;
        constexpr std::uint32_t kStockCrossingIndex = player_slot::kIndex;
        constexpr std::uint32_t kFirstOrdinaryRaisedIndex =
            player_slot::kIndex + 1u;
        // The 2M compatibility layout's prerelease target is 1,800,000. Keep
        // at least 256K ordinary slots available for the FIFO rotation and
        // incidental live allocations; the frozen gate additionally proves
        // the larger observed gross margin at the exact target.
        constexpr std::uint32_t kMinimumReuseFreeCushion = 0x40000;
        constexpr std::uint32_t kMaxRaisedAttributionAttempts = 64;
        constexpr std::uint32_t kMaxDiagnosticDetailedSamples = 4096;
        constexpr std::uint32_t kDiagnosticReferencesPerTask = 4096;
        constexpr std::uint32_t kDiagnosticTaskMicroseconds = 4000;
        constexpr std::uint32_t kDiagnosticDelayMilliseconds = 16;
        constexpr std::uint64_t kDiagnosticReportIntervalMilliseconds = 60u * 1000u;
        constexpr std::size_t   kMaxDetailBytesPerTask = 64 * 1024;

        static_assert(kObjectIndexMask == generation::kIndexMask);
        static_assert(kFirstOrdinaryRaisedIndex < generation::kEntryCount);

        constexpr generation::Transition kFirstOrdinaryAssignment =
            generation::ObserveAssignment(0, 1);
        constexpr generation::Transition kOrdinaryGenerationZeroAssignment =
            generation::ObserveAssignment(
                generation::kGenerationCount - 1u, 0);
        constexpr generation::Transition kFirstOrdinaryWrap =
            generation::ObserveAssignment(
                generation::kGenerationCount, 1);
        constexpr generation::Transition kSaturatedAssignment =
            generation::ObserveAssignment(
                (std::numeric_limits<std::uint32_t>::max)(), 0);
        static_assert(kFirstOrdinaryAssignment.assignmentCount == 1 &&
                      kFirstOrdinaryAssignment.reuseCount == 0 &&
                      kFirstOrdinaryAssignment.generationMatches &&
                      !kFirstOrdinaryAssignment.abaWrap);
        static_assert(kOrdinaryGenerationZeroAssignment.assignmentCount ==
                          generation::kGenerationCount &&
                      kOrdinaryGenerationZeroAssignment.reuseCount ==
                          generation::kGenerationCount - 1u &&
                      kOrdinaryGenerationZeroAssignment.generationMatches &&
                      !kOrdinaryGenerationZeroAssignment.abaWrap);
        static_assert(kFirstOrdinaryWrap.assignmentCount ==
                          generation::kGenerationCount + 1u &&
                      kFirstOrdinaryWrap.reuseCount ==
                          generation::kGenerationCount &&
                      kFirstOrdinaryWrap.generationMatches &&
                      kFirstOrdinaryWrap.abaWrap);
        static_assert(kSaturatedAssignment.saturated &&
                      !kSaturatedAssignment.generationMatches &&
                      !kSaturatedAssignment.abaWrap);

        constexpr std::uint32_t PackRuntime(
            std::uint32_t a_major,
            std::uint32_t a_minor,
            std::uint32_t a_build,
            std::uint32_t a_sub) noexcept
        {
            return ((a_major & 0xFF) << 24) | ((a_minor & 0xFF) << 16) |
                   ((a_build & 0xFFF) << 4) | (a_sub & 0xF);
        }

        struct RuntimeProfile
        {
            std::uint32_t runtimeVersion;
            const char*   name;
            std::uint32_t dataHandlerSingletonRva;
            std::uint32_t createRefHandleRva;
            std::uint32_t getHandleRva;
            std::uint32_t getSmartPointerRva;
            std::uint32_t releaseHandleRva;
            std::uint32_t freeHeadRva;
            std::uint32_t freeTailRva;
            std::uint32_t managerLockRva;
            std::uint32_t lockManagerRva;
            std::uint32_t unlockManagerRva;
            std::uint32_t playerSingletonRva;
        };

        // Address Library IDs and their resolved RVAs:
        //
        //                               SE ID/RVA          AE/GOG ID          VR ID/RVA
        // TESDataHandler**              514141/01EBE428   400269              514141/01F82AD8
        // RE::CreateRefHandle           12193 /001320F0   12326               12193 /001428A0
        // BSPointerHandle::GetHandle    15967 /001EE670   16212               15967 /001FF150
        // const GetSmartPointer         12204 /001329D0   12332               12204 /00143180
        constexpr RuntimeProfile kProfiles[] = {
            { PackRuntime(1, 5, 97, 0), "Skyrim SE 1.5.97", 0x01EBE428, 0x001320F0,
              0x001EE670, 0x001329D0, 0x001774E0, 0x01EC47AC, 0x01EC47B0,
              0x01EC47B8, 0x00C07350, 0x00C075A0, 0x02F26EF8 },
            { PackRuntime(1, 6, 1170, 0), "Skyrim AE 1.6.1170", 0x020F6320, 0x00179050,
              0x0023B780, 0x00179710, 0x001C24F0, 0x020FC5EC, 0x020FC5F0,
              0x020FC5F8, 0x00CC9140, 0x00CC9390, 0x031874F8 },
            // The SKSE load interface tags GOG in the packed runtime's low
            // nibble even though SkyrimSE.exe reports ProductVersion .0.
            { PackRuntime(1, 6, 1179, 1), "Skyrim GOG 1.6.1179", 0x020F7720, 0x00178E80,
              0x0023B5B0, 0x00179540, 0x001C2320, 0x020FD9EC, 0x020FD9F0,
              0x020FD9F8, 0x00CCAC00, 0x00CCAE50, 0x03188918 },
            { PackRuntime(1, 4, 15, 0), "Skyrim VR 1.4.15", 0x01F82AD8, 0x001428A0,
              0x001FF150, 0x00143180, 0x001873F0, 0x01F8964C, 0x01F89650,
              0x01F89658, 0x00C421D0, 0x00C42420, 0x02FEB9F0 },
        };

        // GetHandle returns a non-trivial four-byte BSPointerHandle.  MSVC uses
        // RCX as a hidden result pointer and RDX for TESObjectREFR*.  The engine
        // also returns that result pointer in RAX.
        using GetHandleFn = std::uint32_t* (__fastcall*)(std::uint32_t*, void*);

        // Included for profile diagnostics and ABI documentation.  GetHandle
        // calls this canonical allocator after checking the low refcount bits.
        using CreateRefHandleFn = void (__fastcall*)(std::uint32_t*, void*);

        // const BSPointerHandleManagerInterface::GetSmartPointer:
        // RCX=&nativeHandle, RDX=&NiPointer<TESObjectREFR> (one pointer wide).
        using GetSmartPointerFn = bool (__fastcall*)(const std::uint32_t*, void**);

        // Canonical BSPointerHandleManager release-by-handle path.  Address
        // Library IDs: SE 13777, AE 13874.  It validates the handle under the
        // manager lock, unpublishes the entry, drops its NiPointer ownership,
        // and appends the slot to the free-list tail.  It does not zero *handle.
        using ReleaseHandleFn = void (__fastcall*)(const std::uint32_t*);
        using ManagerLockFn = void (__fastcall*)(void*);

        struct RawBSTArray
        {
            void**        data;      // +00
            std::uint32_t capacity;  // +08
            std::uint32_t pad0C;
            std::uint32_t size;      // +10
            std::uint32_t pad14;
        };
        static_assert(sizeof(RawBSTArray) == 0x18);

        constexpr std::uint8_t kReferenceFormTypes[] = {
            0x3D,  // REFR
            0x3E,  // ACHR
            0x3F,  // PMIS
            0x40,  // PARW
            0x41,  // PGRE
            0x42,  // PBEA
            0x43,  // PFLA
            0x44,  // PCON
            0x45,  // PBAR
            0x46,  // PHZD
        };

        using SyntheticScalarDeletingDestructor = void* (__fastcall*)(void*, std::uint32_t);
        using SyntheticDeleteThis = void (__fastcall*)(void*);

        void* __fastcall SyntheticScalarDelete(void* a_self, std::uint32_t) noexcept
        {
            return a_self;
        }

        void __fastcall SyntheticDelete(void*) noexcept
        {
            // A correct churn run never reaches either virtual: the harness's
            // owner reference remains after the table drops its ownership.
        }

        struct SyntheticVtable
        {
            SyntheticScalarDeletingDestructor scalarDeletingDestructor;
            SyntheticDeleteThis                deleteThis;
        };

        SyntheticVtable g_syntheticVtable = {
            &SyntheticScalarDelete,
            &SyntheticDelete,
        };

        // Only the BSHandleRefObject subobject at +20 and its packed word at +28
        // are observed by GetHandle/GetSmartPointer.  No fake is ever passed to
        // a TESForm/name callback or to ordinary gameplay code.
        struct alignas(16) SyntheticReference
        {
            std::byte       prefix[0x20]{};
            SyntheticVtable*  vtable = &g_syntheticVtable;
            std::uint32_t   packedRefCount = 1;
            std::uint32_t   pad2C = 0;
        };
        static_assert(sizeof(SyntheticReference) == 0x30);

        struct HeldHandle
        {
            void*         expected;
            std::uint32_t handle;
            std::uint32_t index;
        };
        static_assert(sizeof(HeldHandle) == 0x10);

        struct ReleaseProbeTarget
        {
            std::size_t heldIndex;
            HeldHandle held;
        };

        struct PluginAttributionCounts
        {
            std::uint64_t references = 0;
            std::uint64_t referenceOrigin = 0;
            std::uint64_t referenceWinner = 0;
            std::uint64_t baseOrigin = 0;
            std::uint64_t baseWinner = 0;
        };

        enum class Phase
        {
            kSyntheticFill,
            kSyntheticSecondPass,
            kRealReferences,
            kSecondPass,
            kWaitForGameLoad,
            kDiagnosticWait,
            kLiveTableSample,
            kDiagnosticSummary,
            kReleaseProbe,
            kReuseProbe,
            kChurn,
            kChurnCleanup,
            kChurnVerifyCleanup,
            kStockOverflow,
            kStockWaitForGameLoad,
            kStockCleanup,
            kStockVerifyCleanup,
            kDone,
            kFailed,
        };

        struct State;
        std::atomic<State*> g_state{ nullptr };

        struct State
        {
            struct LifecycleSnapshot
            {
                patch::ReservedPlayerLifecycleSnapshot lifecycle{};
                std::uint32_t assignments = 0;
                const void* playerObject = nullptr;
                const void* playerSingleton = nullptr;
            };

            Settings  settings;
            Callbacks callbacks;

            const RuntimeProfile*       profile = nullptr;
            const SKSETaskInterface*    tasks = nullptr;
            GetHandleFn                 getHandle = nullptr;
            CreateRefHandleFn           createRefHandle = nullptr;
            GetSmartPointerFn           getSmartPointer = nullptr;
            ReleaseHandleFn             releaseHandle = nullptr;
            ManagerLockFn               lockManager = nullptr;
            ManagerLockFn               unlockManager = nullptr;
            void*                       managerLock = nullptr;
            const volatile std::uint32_t* freeHead = nullptr;
            const volatile std::uint32_t* freeTail = nullptr;
            std::uintptr_t               imageBase = 0;
            const HandleEntry*           handleTable = nullptr;
            std::uint32_t                handleEntryCount = 0;

            std::vector<void*>       realReferences;
            std::vector<HeldHandle>  heldHandles;
            SyntheticReference*      syntheticReferences = nullptr;
            std::size_t              syntheticCapacity = 0;
            std::size_t              syntheticCursor = 0;
            std::size_t              syntheticVerifyCursor = 0;
            std::size_t              syntheticVerifyExpected = 0;
            std::size_t              realCursor = 0;
            std::size_t              verifyCursor = 0;
            std::uint32_t            liveScanCursor = kStockCrossingIndex;
            std::uint32_t            liveScanPasses = 0;
            std::vector<std::uint32_t> sampledHandles;
            std::unordered_map<std::string, PluginAttributionCounts>
                diagnosticPluginCounts;
            std::vector<std::string> diagnosticSortedPlugins;
            std::vector<std::uint32_t> churnHistory;
            std::vector<ReleaseProbeTarget> releaseProbeTargets;
            Phase                    phase = Phase::kRealReferences;

            std::size_t         releaseProbeCursor = 0;
            std::uint32_t       releaseProbeMinIndex = 0xFFFFFFFFu;
            std::uint32_t       releaseProbeMaxIndex = 0;

            std::size_t         reuseHeldIndex = (std::numeric_limits<std::size_t>::max)();
            HeldHandle          reuseTarget{};
            HeldHandle          reuseNeighbor{};
            SyntheticReference* reuseScratch = nullptr;
            std::uint32_t       reuseOldHandle = 0;
            std::uint32_t       reuseExpectedHandle = 0;
            std::uint32_t       reuseCompleted = 0;
            std::uint64_t       reuseRotationsThisCycle = 0;
            std::uint64_t       reuseTotalRotations = 0;
            std::uint64_t       reuseInitialFreeCount = 0;
            std::uint32_t       reuseInitialHandle = 0;
            std::uint32_t       reuseInitialAssignmentCount = 0;
            std::uint64_t       reuseInitialWrapCount = 0;
            SyntheticReference* reuseInitialObject = nullptr;

            std::size_t         churnHeldIndex = (std::numeric_limits<std::size_t>::max)();
            SyntheticReference* churnCurrent = nullptr;
            SyntheticReference* churnNext = nullptr;
            std::uint32_t       churnHandle = 0;
            std::uint32_t       churnIndex = 0;
            std::uint32_t       churnCompleted = 0;
            std::size_t         churnCleanupCursor = 0;
            std::uint32_t       churnTableVerifyCursor = 0;
            HeldHandle          churnNeighbor{};

            std::uint32_t stockOverflowCompleted = 0;
            std::uint32_t stockUnexpectedSuccesses = 0;
            std::size_t   stockCleanupCursor = 0;
            std::uint32_t stockTableVerifyCursor = 0;
            bool          stockProbePassed = false;
            bool          stockHeldThroughGameLoad = false;
            const char*   stockFailureReason = nullptr;

            HANDLE stopEvent = nullptr;
            HANDLE taskDoneEvent = nullptr;
            HANDLE coordinatorWakeEvent = nullptr;
            std::atomic<bool> started{ false };
            std::atomic<bool> finished{ false };
            std::atomic<bool> stopRequested{ false };
            std::atomic<bool> gameLoadSeen{ false };
            std::atomic<bool> taskWorkReady{ true };
            std::atomic<std::uint64_t> diagnosticNextPassTick{ 0 };

            std::uint32_t lifecycleDataLoadedCount = 0;
            std::uint32_t lifecyclePreLoadCount = 0;
            std::uint32_t lifecyclePostLoadCount = 0;
            std::uint32_t lifecycleNewGameCount = 0;
            std::uint32_t lifecycleLoadAttemptCount = 0;
            std::uint32_t lifecyclePendingLoadAttempt = 0;
            bool          lifecycleDataLoadedSeen = false;

            LARGE_INTEGER qpcFrequency{};
            std::mutex    logLock;
            std::string   detailBuffer;

            std::uint64_t snapshotNulls = 0;
            std::uint64_t fillerAttempted = 0;
            std::uint64_t realAttempted = 0;
            std::uint64_t nonzeroHandles = 0;
            std::uint64_t zeroHandles = 0;
            std::uint64_t immediateResolveFailures = 0;
            std::uint64_t immediateResolveMismatches = 0;
            std::uint64_t lookupReleaseFailures = 0;
            std::uint64_t secondPassFailures = 0;
            std::uint64_t secondPassMismatches = 0;
            std::uint64_t detailedLogs = 0;
            std::uint64_t raisedDetailedLogs = 0;
            std::uint64_t attributedDetailedLogs = 0;
            std::uint32_t raisedAttributionAttempts = 0;
            std::uint32_t raisedAttributedLogs = 0;
            std::uint64_t realAboveStock = 0;
            std::uint64_t realWithRaisedIndex = 0;
            std::uint32_t maxIndex = 0;
            bool          crossingLogged = false;
            bool          reservedPlayerLogged = false;
            bool          detailsTruncatedLogged = false;
            bool          waitingForGameLogged = false;
            bool          liveSampleMode = false;
            std::uint64_t liveScanCandidates = 0;
            std::uint64_t liveScanRaces = 0;
            std::uint64_t diagnosticResolved = 0;
            std::uint64_t diagnosticAttributed = 0;
            std::uint64_t diagnosticUnattributed = 0;
            std::uint64_t diagnosticNonReferences = 0;
            std::uint64_t diagnosticDetailedSamples = 0;
            std::size_t diagnosticSummaryCursor = 0;
            std::uint64_t diagnosticPassStartedTick = 0;

            [[nodiscard]] bool IsLiveDiagnostics() const noexcept
            {
                return settings.liveDiagnosticsEnabled && !settings.enabled;
            }

            [[nodiscard]] bool IsLifecycleVerification() const noexcept
            {
                return IsLiveDiagnostics() &&
                       settings.lifecycleVerificationEnabled;
            }

            [[nodiscard]] std::uint32_t ActiveReferencesPerTask() const noexcept
            {
                return IsLiveDiagnostics() ? kDiagnosticReferencesPerTask :
                    settings.maxReferencesPerTask;
            }

            [[nodiscard]] std::uint32_t ActiveTaskMicroseconds() const noexcept
            {
                return IsLiveDiagnostics() ? kDiagnosticTaskMicroseconds :
                    settings.maxTaskMicroseconds;
            }

            [[nodiscard]] std::uint32_t ActiveDelayMilliseconds() const noexcept
            {
                return IsLiveDiagnostics() ? kDiagnosticDelayMilliseconds :
                    settings.coordinatorDelayMilliseconds;
            }

            void WakeCoordinator() const noexcept
            {
                if (coordinatorWakeEvent)
                    SetEvent(coordinatorWakeEvent);
            }

            void SetTaskWorkReady(bool a_ready) noexcept
            {
                taskWorkReady.store(a_ready, std::memory_order_release);
            }

            [[nodiscard]] std::uint32_t IndexMask() const noexcept
            {
                return (1u << settings.indexBits) - 1u;
            }

            [[nodiscard]] std::uint32_t AgeMask() const noexcept
            {
                return settings.indexBits == generation::kIndexBits ?
                    generation::kGenerationMask : 0x03F00000u;
            }

            [[nodiscard]] std::uint32_t InUseMask() const noexcept
            {
                return generation::kInUseMask;
            }

            [[nodiscard]] std::uint32_t AgeIncrement() const noexcept
            {
                return 1u << settings.indexBits;
            }

            [[nodiscard]] bool UsesReservedPlayerSlot() const noexcept
            {
                return settings.indexBits == generation::kIndexBits &&
                       handleEntryCount == generation::kEntryCount;
            }

            [[nodiscard]] bool IsReservedPlayerSlot(
                std::uint32_t a_index) const noexcept
            {
                return UsesReservedPlayerSlot() &&
                       a_index == player_slot::kIndex;
            }

            [[nodiscard]] bool IsStockControl() const noexcept
            {
                return settings.stockOverflowAttempts != 0;
            }

            [[nodiscard]] static std::uint32_t ReadPackedWord(
                const void* a_reference) noexcept
            {
                std::uint32_t packed = 0;
                std::memcpy(
                    &packed,
                    static_cast<const std::uint8_t*>(a_reference) + 0x28,
                    sizeof(packed));
                return packed;
            }

            [[nodiscard]] static std::uint32_t ReadFormID(
                const void* a_reference) noexcept
            {
                std::uint32_t formID = 0;
                std::memcpy(&formID,
                    static_cast<const std::uint8_t*>(a_reference) + 0x14,
                    sizeof(formID));
                return formID;
            }

            [[nodiscard]] bool IsSyntheticReference(const void* a_reference) const noexcept
            {
                if (!a_reference || !syntheticReferences || syntheticCapacity == 0)
                    return false;
                const auto address = reinterpret_cast<std::uintptr_t>(a_reference);
                const auto begin = reinterpret_cast<std::uintptr_t>(syntheticReferences);
                const auto end = begin + syntheticCapacity * sizeof(SyntheticReference);
                return address >= begin && address < end;
            }

            void Emit(const char* a_message)
            {
                if (!a_message)
                    return;

                std::lock_guard lock(logLock);
                if (callbacks.log) {
                    callbacks.log(callbacks.context, a_message);
                } else {
                    OutputDebugStringA(a_message);
                    OutputDebugStringA("\n");
                }
            }

            void Log(const char* a_format, ...)
            {
                char    text[2048]{};
                va_list args;
                va_start(args, a_format);
                const int result = std::vsnprintf(text, sizeof(text), a_format, args);
                va_end(args);
                if (result < 0)
                    text[sizeof(text) - 1] = '\0';
                Emit(text);
            }

            void FlushDetails()
            {
                if (!detailBuffer.empty()) {
                    Emit(detailBuffer.c_str());
                    detailBuffer.clear();
                }
            }

            template <std::size_t N>
            static void Sanitize(char (&a_text)[N]) noexcept
            {
                a_text[N - 1] = '\0';
                for (char* cursor = a_text; *cursor; ++cursor) {
                    const unsigned char value = static_cast<unsigned char>(*cursor);
                    if (value < 0x20 || *cursor == '"')
                        *cursor = (*cursor == '"') ? '\'' : ' ';
                }
            }

            static void SanitizeResolvedNames(ResolvedNames& a_names) noexcept
            {
                Sanitize(a_names.originPlugin);
                Sanitize(a_names.winningPlugin);
                Sanitize(a_names.formName);
                Sanitize(a_names.editorID);
                Sanitize(a_names.displayName);
                Sanitize(a_names.baseOriginPlugin);
                Sanitize(a_names.baseWinningPlugin);
                Sanitize(a_names.baseName);
                Sanitize(a_names.baseEditorID);
            }

            [[nodiscard]] bool RecordDiagnosticAttribution(
                const ResolvedNames& a_names)
            {
                struct Role
                {
                    const char* name;
                    std::uint64_t PluginAttributionCounts::* count;
                };
                const Role roles[] = {
                    { a_names.originPlugin, &PluginAttributionCounts::referenceOrigin },
                    { a_names.winningPlugin, &PluginAttributionCounts::referenceWinner },
                    { a_names.baseOriginPlugin, &PluginAttributionCounts::baseOrigin },
                    { a_names.baseWinningPlugin, &PluginAttributionCounts::baseWinner },
                };

                bool any = false;
                for (const Role& role : roles) {
                    if (!role.name[0])
                        continue;
                    auto& counts = diagnosticPluginCounts[role.name];
                    ++(counts.*(role.count));
                    any = true;
                }

                // A plugin may occupy several attribution roles for one live
                // reference. Count that reference only once in its aggregate.
                for (std::size_t i = 0; i < std::size(roles); ++i) {
                    if (!roles[i].name[0])
                        continue;
                    bool alreadyCounted = false;
                    for (std::size_t j = 0; j < i; ++j) {
                        if (roles[j].name[0] &&
                            std::strcmp(roles[i].name, roles[j].name) == 0) {
                            alreadyCounted = true;
                            break;
                        }
                    }
                    if (!alreadyCounted)
                        ++diagnosticPluginCounts[roles[i].name].references;
                }
                return any;
            }

            void AppendDiagnosticSample(
                void* a_reference,
                std::uint32_t a_handle,
                std::uint32_t a_index)
            {
                if (diagnosticDetailedSamples >=
                    settings.diagnosticsDetailedSampleLimit) {
                    return;
                }

                // An attempted row consumes one configured sample slot. That
                // keeps expensive virtual name resolution strictly bounded even
                // when a form has no printable identity.
                ++diagnosticDetailedSamples;
                ResolvedNames names{};
                bool namesResolved = false;
                if (callbacks.resolveNames) {
                    namesResolved = callbacks.resolveNames(
                        callbacks.context, a_reference, names);
                }
                SanitizeResolvedNames(names);

                const auto* bytes = static_cast<const std::uint8_t*>(a_reference);
                std::uint32_t formID = 0;
                std::memcpy(&formID, bytes + 0x14, sizeof(formID));
                const std::uint8_t formType = bytes[0x1A];

                char line[4096]{};
                std::snprintf(
                    line,
                    sizeof(line),
                    "diagnostics: HIGH SAMPLE lookup=PASS handle=%08X index=%06X "
                    "formID=%08X type=%02X names=%s origin=\"%s\" winner=\"%s\" "
                    "form=\"%s\" editor=\"%s\" display=\"%s\" baseID=%08X "
                    "baseOrigin=\"%s\" baseWinner=\"%s\" baseForm=\"%s\" "
                    "baseEditor=\"%s\"\n",
                    a_handle,
                    a_index,
                    formID,
                    formType,
                    namesResolved ? "PASS" : "PARTIAL",
                    names.originPlugin,
                    names.winningPlugin,
                    names.formName,
                    names.editorID,
                    names.displayName,
                    names.baseFormID,
                    names.baseOriginPlugin,
                    names.baseWinningPlugin,
                    names.baseName,
                    names.baseEditorID);
                line[sizeof(line) - 1] = '\0';
                detailBuffer.append(line);
            }

            [[nodiscard]] bool AppendReferenceDetail(
                void* a_reference,
                std::uint32_t a_handle,
                std::uint32_t a_index,
                bool a_requireAttribution = false)
            {
                if (settings.maxDetailedLogs == 0)
                    return false;

                const bool reservedRaisedRow =
                    a_index >= kFirstOrdinaryRaisedIndex &&
                    raisedAttributedLogs == 0 &&
                    raisedAttributionAttempts < kMaxRaisedAttributionAttempts;
                if (a_index < settings.detailedLogFromIndex &&
                    !reservedRaisedRow)
                    return false;

                if (detailedLogs >= settings.maxDetailedLogs &&
                    !reservedRaisedRow) {
                    if (!detailsTruncatedLogged) {
                        detailsTruncatedLogged = true;
                        Log("stress: detailed rows capped at %u; remaining high-index "
                            "references are still verified (up to 64 >1M attribution "
                            "attempts remain)",
                            settings.maxDetailedLogs);
                    }
                    return false;
                }

                ResolvedNames names{};
                bool namesResolved = false;
                if (callbacks.resolveNames) {
                    namesResolved = callbacks.resolveNames(
                        callbacks.context, a_reference, names);
                }
                SanitizeResolvedNames(names);

                if (a_requireAttribution && !namesResolved)
                    return false;

                const auto* bytes = static_cast<const std::uint8_t*>(a_reference);
                std::uint32_t formID = 0;
                std::memcpy(&formID, bytes + 0x14, sizeof(formID));
                const std::uint8_t formType = bytes[0x1A];

                char line[4096]{};
                std::snprintf(
                    line,
                    sizeof(line),
                    "HIGH lookup=PASS handle=%08X index=%06X ptr=%p formID=%08X type=%02X "
                    "names=%s origin=\"%s\" winner=\"%s\" form=\"%s\" "
                    "editor=\"%s\" display=\"%s\" baseID=%08X "
                    "baseOrigin=\"%s\" baseWinner=\"%s\" baseForm=\"%s\" "
                    "baseEditor=\"%s\"\n",
                    a_handle,
                    a_index,
                    a_reference,
                    formID,
                    formType,
                    namesResolved ? "PASS" : "FAIL",
                    names.originPlugin,
                    names.winningPlugin,
                    names.formName,
                    names.editorID,
                    names.displayName,
                    names.baseFormID,
                    names.baseOriginPlugin,
                    names.baseWinningPlugin,
                    names.baseName,
                    names.baseEditorID);
                line[sizeof(line) - 1] = '\0';
                detailBuffer.append(line);
                ++detailedLogs;
                if (namesResolved)
                    ++attributedDetailedLogs;
                if (a_index >= kFirstOrdinaryRaisedIndex) {
                    ++raisedDetailedLogs;
                    if (raisedAttributionAttempts <
                        kMaxRaisedAttributionAttempts) {
                        ++raisedAttributionAttempts;
                    }
                    if (namesResolved)
                        ++raisedAttributedLogs;
                }
                return namesResolved;
            }

            void Fail(const char* a_reason)
            {
                FlushDetails();
                Log("%s: FAILED: %s",
                    IsLiveDiagnostics() ? "diagnostics" : "stress",
                    a_reason ? a_reason : "unknown failure");
                if (settings.churnCycles != 0 && syntheticReferences) {
                    Log("stress: FAILED CHURN RUN RETAINS SYNTHETIC HANDLES; do not load, save, "
                        "or continue gameplay. Exit Skyrim manually after preserving the log.");
                }
                if (settings.reuseProbeCycles != 0 && syntheticReferences) {
                    Log("stress: FAILED REUSE RUN RETAINS SYNTHETIC HANDLES; do not save or "
                        "continue gameplay. Exit Skyrim manually after preserving the log.");
                }
                if (IsStockControl() && syntheticReferences) {
                    Log("stock-control: FAILED RUN MAY RETAIN SYNTHETIC HANDLES; do not load, "
                        "save, or continue gameplay. Exit Skyrim after preserving the log.");
                }
                phase = Phase::kFailed;
                finished.store(true, std::memory_order_release);
                WakeCoordinator();
            }

            void Complete()
            {
                if (immediateResolveFailures != 0 || immediateResolveMismatches != 0 ||
                    lookupReleaseFailures != 0 || secondPassFailures != 0 ||
                    secondPassMismatches != 0) {
                    Fail("one or more handle lookup, identity, or temporary-pin checks failed");
                    return;
                }
                if (!liveSampleMode &&
                    settings.indexBits == generation::kIndexBits &&
                    realWithRaisedIndex == 0) {
                    Fail("no real reference reached an ordinary index above 0x100000; the 21st index bit was not proven");
                    return;
                }
                if (!liveSampleMode &&
                    settings.indexBits == generation::kIndexBits &&
                    settings.maxDetailedLogs != 0 &&
                    raisedAttributedLogs == 0) {
                    Fail("no >1M real-reference row resolved both plugin attribution and a form/base identity");
                    return;
                }
                FlushDetails();
                Log("stress: COMPLETE phase; snapshot=%zu filler=%llu real=%llu "
                    "nonzero=%llu zero=%llu held=%zu maxIndex=%06X detailed=%llu "
                    "attributed=%llu detailed>1M=%llu attributed>1M=%u",
                    realReferences.size(),
                    static_cast<unsigned long long>(fillerAttempted),
                    static_cast<unsigned long long>(realAttempted),
                    static_cast<unsigned long long>(nonzeroHandles),
                    static_cast<unsigned long long>(zeroHandles),
                    heldHandles.size(),
                    maxIndex,
                    static_cast<unsigned long long>(detailedLogs),
                    static_cast<unsigned long long>(attributedDetailedLogs),
                    static_cast<unsigned long long>(raisedDetailedLogs),
                    raisedAttributedLogs);
                Log("stress: immediate resolve failures=%llu mismatches=%llu; "
                    "second-pass failures=%llu mismatches=%llu; lookup-release failures=%llu; "
                    "snapshot nulls=%llu; real>1M=%llu",
                    static_cast<unsigned long long>(immediateResolveFailures),
                    static_cast<unsigned long long>(immediateResolveMismatches),
                    static_cast<unsigned long long>(secondPassFailures),
                    static_cast<unsigned long long>(secondPassMismatches),
                    static_cast<unsigned long long>(lookupReleaseFailures),
                    static_cast<unsigned long long>(snapshotNulls),
                    static_cast<unsigned long long>(realAboveStock));
                if (liveSampleMode) {
                    Log("stress: LIVE SAMPLE COMPLETE; %llu plugin/form-attributed live "
                        "references were observed above Skyrim's vanilla cap; Skyrim remains running",
                        static_cast<unsigned long long>(attributedDetailedLogs));
                } else {
                    Log("stress: handle-table references and synthetic blocks intentionally remain "
                        "live until process exit; quit without loading or saving");
                }
                phase = Phase::kDone;
                finished.store(true, std::memory_order_release);
            }

            [[nodiscard]] bool ShouldStopOnFailure() const noexcept
            {
                return IsLiveDiagnostics() || settings.stopOnVerificationFailure;
            }

            [[nodiscard]] bool ReleaseLookupReference(void* a_reference)
            {
                if (!a_reference)
                    return true;
                auto* word = reinterpret_cast<volatile LONG*>(
                    static_cast<std::uint8_t*>(a_reference) + 0x28);
                const std::uint32_t after = static_cast<std::uint32_t>(
                    InterlockedDecrement(word));
                if ((after & kReferenceCountMask) != 0)
                    return true;

                // Mirror NiPointer/BSHandleRefObject::DecRefCount exactly. The
                // table normally owns another intrusive reference, but a
                // concurrent canonical handle release may remove that ownership
                // after GetSmartPointer pins the object. In that legitimate
                // race our pin is the last one, so reaching zero must dispatch
                // BSHandleRefObject::DeleteThis (virtual slot 1) rather than
                // leaving a zero-count object alive.
                const bool unexpectedSyntheticZero = IsSyntheticReference(a_reference);
                auto* handleObject = static_cast<std::uint8_t*>(a_reference) + 0x20;
                auto** vtable = *reinterpret_cast<void***>(handleObject);
                if (vtable && vtable[1]) {
                    using DeleteThisFn = void(__fastcall*)(void*);
                    reinterpret_cast<DeleteThisFn>(vtable[1])(handleObject);
                    if (unexpectedSyntheticZero) {
                        ++lookupReleaseFailures;
                        if (ShouldStopOnFailure())
                            Fail("a synthetic lookup pin became the final intrusive reference");
                        return false;
                    }
                    return true;
                }

                ++lookupReleaseFailures;
                if (ShouldStopOnFailure()) {
                    Fail("the final lookup NiPointer pin had no valid DeleteThis virtual");
                    return false;
                }
                return false;
            }

            [[nodiscard]] bool AcquireAndVerify(
                void* a_reference,
                bool a_synthetic,
                bool a_allowExpectedExhaustion = false)
            {
                if (!a_reference) {
                    ++snapshotNulls;
                    return true;
                }

                const std::uint32_t packed = ReadPackedWord(a_reference);
                if ((packed & kReferenceCountMask) == 0) {
                    ++zeroHandles;
                    if (ShouldStopOnFailure()) {
                        Fail("reference has a zero intrusive refcount before GetHandle");
                        return false;
                    }
                    return true;
                }

                std::uint32_t handle = 0;
                std::uint32_t* returned = getHandle(&handle, a_reference);
                if (returned != &handle) {
                    ++immediateResolveFailures;
                    if (ShouldStopOnFailure()) {
                        Fail("GetHandle returned an unexpected hidden-result pointer");
                        return false;
                    }
                }

                if (handle == 0) {
                    ++zeroHandles;
                    if (a_allowExpectedExhaustion)
                        return true;
                    if (ShouldStopOnFailure()) {
                        Fail("GetHandle returned zero (handle table exhausted or object invalid)");
                        return false;
                    }
                    return true;
                }

                ++nonzeroHandles;
                const std::uint32_t index = handle & IndexMask();
                maxIndex = (std::max)(maxIndex, index);

                void* resolved = nullptr;
                const bool lookupOK = getSmartPointer(&handle, &resolved);
                if (!lookupOK) {
                    ++immediateResolveFailures;
                    if (ShouldStopOnFailure()) {
                        Fail("GetSmartPointer failed immediately after GetHandle");
                        return false;
                    }
                    return true;
                }
                if (resolved != a_reference) {
                    ++immediateResolveMismatches;
                    static_cast<void>(ReleaseLookupReference(resolved));
                    if (ShouldStopOnFailure()) {
                        Fail("GetSmartPointer resolved a handle to the wrong object");
                        return false;
                    }
                    return true;
                }

                const bool reservedPlayer = IsReservedPlayerSlot(index);
                if (reservedPlayer && a_synthetic) {
                    static_cast<void>(ReleaseLookupReference(resolved));
                    Fail("a synthetic reference acquired the reserved player slot");
                    return false;
                }
                if (reservedPlayer) {
                    const std::uint32_t formID = ReadFormID(a_reference);
                    if (handle != player_slot::kVanillaRawHandle ||
                        formID != player_slot::kPlayerFormID) {
                        static_cast<void>(ReleaseLookupReference(resolved));
                        Fail("the reserved player slot published a non-player or non-vanilla handle");
                        return false;
                    }
                    if (!reservedPlayerLogged) {
                        reservedPlayerLogged = true;
                        Log("stress: reserved player handle PASS; slot=%06X "
                            "handle=%08X formID=%08X",
                            index, handle, formID);
                    }
                }

                heldHandles.push_back({ a_reference, handle, index });

                if (!reservedPlayer && index >= kStockCrossingIndex &&
                    !crossingLogged) {
                    crossingLogged = true;
                    Log("stress: CROSSED stock cap at handle=%08X index=%06X "
                        "(%s reference)",
                        handle,
                        index,
                        a_synthetic ? "synthetic" : "real");
                }

                if (!a_synthetic) {
                    if (!reservedPlayer && index >= kStockCrossingIndex)
                        ++realAboveStock;
                    if (!reservedPlayer &&
                        index >= kFirstOrdinaryRaisedIndex) {
                        ++realWithRaisedIndex;
                    }
                    if (!reservedPlayer) {
                        try {
                            static_cast<void>(AppendReferenceDetail(
                                a_reference, handle, index));
                        } catch (...) {
                            // Keep the temporary GetSmartPointer ownership
                            // balanced even if detail-buffer allocation throws.
                            static_cast<void>(ReleaseLookupReference(resolved));
                            throw;
                        }
                    }
                }
                return ReleaseLookupReference(resolved);
            }

            [[nodiscard]] bool ResolveSyntheticHandleExactly(
                std::uint32_t a_handle,
                const SyntheticReference* a_expected,
                const char* a_failure)
            {
                void* resolved = nullptr;
                const bool lookupOK = getSmartPointer(&a_handle, &resolved);
                if (!lookupOK || resolved != a_expected) {
                    if (lookupOK && resolved)
                        static_cast<void>(ReleaseLookupReference(resolved));
                    Fail(a_failure);
                    return false;
                }
                return ReleaseLookupReference(resolved);
            }

            [[nodiscard]] bool RejectStaleSyntheticHandle(
                std::uint32_t a_handle,
                const char* a_failure)
            {
                void* resolved = nullptr;
                const bool lookupOK = getSmartPointer(&a_handle, &resolved);
                if (!lookupOK && !resolved)
                    return true;

                if (lookupOK && resolved)
                    static_cast<void>(ReleaseLookupReference(resolved));
                Fail(a_failure);
                return false;
            }

            [[nodiscard]] bool VerifyLiveSyntheticState(
                const SyntheticReference* a_reference,
                std::uint32_t a_handle,
                std::uint32_t a_index)
            {
                if (!a_reference || a_index >= handleEntryCount) {
                    Fail("synthetic live-state arguments are outside the handle table");
                    return false;
                }

                const HandleEntry& entry = handleTable[a_index];
                const std::uint32_t bits = entry.bits;
                const auto* expectedSubobject =
                    reinterpret_cast<const std::uint8_t*>(a_reference) + 0x20;
                if ((bits & InUseMask()) == 0 ||
                    (bits & AgeMask()) != (a_handle & AgeMask()) ||
                    entry.pointer != expectedSubobject) {
                    Fail("synthetic live entry does not match its handle, age, or object pointer");
                    return false;
                }

                const std::uint32_t packed = ReadPackedWord(a_reference);
                const std::uint32_t expectedMetadata = kHandleValidBit |
                    ((a_index & kObjectIndexMask) << 11);
                if ((packed & kReferenceCountMask) != 2 ||
                    (packed & ~kReferenceCountMask) != expectedMetadata ||
                    a_reference->pad2C != 0) {
                    Fail("synthetic live object has an incorrect refcount, complete 21-bit index cache, valid bit, or untouched +0x2C padding");
                    return false;
                }
                return true;
            }

            void ContinueAfterSyntheticFill()
            {
                if (gameLoadSeen.load(std::memory_order_acquire))
                    BeginLiveTableSample();
                else
                    WaitForLoadedGame();
            }

            void BeginSyntheticSecondPass()
            {
                if (!settings.verifySecondPass) {
                    BeginReleaseProbe();
                    return;
                }
                if (heldHandles.empty()) {
                    Fail("synthetic second lookup pass has no retained handles");
                    return;
                }

                syntheticVerifyCursor = 0;
                syntheticVerifyExpected = heldHandles.size();
                phase = Phase::kSyntheticSecondPass;
                Log("stress: synthetic allocation pass complete; starting second exact "
                    "lookup pass over %zu retained synthetic handles before any release "
                    "or reuse",
                    syntheticVerifyExpected);
            }

            void ProcessSyntheticSecondPass()
            {
                if (heldHandles.size() != syntheticVerifyExpected) {
                    ++secondPassMismatches;
                    Fail("retained synthetic handle set changed during the second lookup pass");
                    return;
                }
                if (syntheticVerifyCursor >= syntheticVerifyExpected) {
                    Log("stress: SYNTHETIC SECOND PASS PASS; verified=%zu retained=%zu "
                        "exact-object=PASS live-entry=PASS balanced-pins=PASS; no release "
                        "or reuse began before completion",
                        syntheticVerifyCursor,
                        syntheticVerifyExpected);
                    BeginReleaseProbe();
                    return;
                }

                const HeldHandle& held = heldHandles[syntheticVerifyCursor];
                if (!held.expected || !IsSyntheticReference(held.expected) ||
                    held.index >= handleEntryCount ||
                    (held.handle & IndexMask()) != held.index) {
                    ++secondPassMismatches;
                    Fail("synthetic second-pass record has an invalid object, handle, or index");
                    return;
                }
                if (!VerifyLiveSyntheticState(
                        static_cast<const SyntheticReference*>(held.expected),
                        held.handle,
                        held.index)) {
                    ++secondPassMismatches;
                    return;
                }

                void* resolved = nullptr;
                const bool lookupOK = getSmartPointer(&held.handle, &resolved);
                if (!lookupOK) {
                    ++secondPassFailures;
                    if (resolved)
                        static_cast<void>(ReleaseLookupReference(resolved));
                    if (phase != Phase::kFailed) {
                        Fail("GetSmartPointer failed during the synthetic second lookup pass");
                    }
                    return;
                }
                if (resolved != held.expected) {
                    ++secondPassMismatches;
                    if (resolved)
                        static_cast<void>(ReleaseLookupReference(resolved));
                    if (phase != Phase::kFailed) {
                        Fail("synthetic second lookup pass resolved a handle to the wrong object");
                    }
                    return;
                }
                if (!ReleaseLookupReference(resolved))
                    return;

                ++syntheticVerifyCursor;
            }

            [[nodiscard]] bool ReuseTargetIsFreeAtOldAge() const noexcept
            {
                if (reuseTarget.index >= handleEntryCount)
                    return false;
                const HandleEntry& entry = handleTable[reuseTarget.index];
                return (entry.bits & InUseMask()) == 0 && entry.pointer == nullptr &&
                       (entry.bits & AgeMask()) == (reuseOldHandle & AgeMask());
            }

            [[nodiscard]] bool VerifyNoWrapDetectorProgress(
                std::uint32_t a_expectedAssignments,
                const char* a_stage)
            {
                if (settings.reuseProbeCycles !=
                        generation::kGenerationCount)
                    return true;
                if (!diagnostic::IsActive()) {
                    Fail("31-cycle no-wrap proof lost the mandatory generation guard");
                    return false;
                }
                const diagnostic::EventSnapshot events =
                    diagnostic::ReadEventSnapshot();
                if (events.unreliableSlot != 0) {
                    Fail("31-cycle no-wrap proof observed unreliable generation tracking");
                    return false;
                }
                if (events.totalWraps != reuseInitialWrapCount ||
                    events.lastWrapEvent != 0 ||
                    events.preventedWrapAttempts != 0 ||
                    events.lastPreventedEvent != 0) {
                    Fail("31-cycle no-wrap proof observed a generation-wrap event");
                    return false;
                }
                const std::uint32_t assignments =
                    diagnostic::AssignmentCount(reuseTarget.index);
                if (assignments != a_expectedAssignments) {
                    Log("stress: NO-WRAP detector mismatch at %s: target=%06X "
                        "expectedAssignments=%u observedAssignments=%u",
                        a_stage ? a_stage : "unknown stage",
                        reuseTarget.index,
                        a_expectedAssignments,
                        assignments);
                    Fail("31-cycle no-wrap target assignment count was not exact");
                    return false;
                }
                return true;
            }

            [[nodiscard]] bool FinishNoWrapBoundaryProof()
            {
                if (settings.reuseProbeCycles !=
                        generation::kGenerationCount)
                    return true;
                if (reuseCompleted != generation::kGenerationCount - 1u) {
                    Fail("no-wrap boundary proof was requested at the wrong completed-cycle count");
                    return false;
                }
                if (!VerifyNoWrapDetectorProgress(
                        generation::kGenerationCount,
                        "final exact-slot assignment")) {
                    return false;
                }
                if (reuseInitialAssignmentCount != 1u ||
                    reuseInitialHandle !=
                        (reuseTarget.index | generation::kEntryCount) ||
                    reuseTarget.handle != reuseTarget.index ||
                    reuseTarget.index != (reuseInitialHandle & IndexMask()) ||
                    reuseTarget.expected == reuseInitialObject ||
                    (reuseTarget.handle &
                        ~(generation::kIndexMask |
                          generation::kGenerationMask)) != 0) {
                    Fail("31-cycle no-wrap boundary handles were not exact");
                    return false;
                }
                if (!VerifyLiveSyntheticState(
                        static_cast<const SyntheticReference*>(reuseTarget.expected),
                        reuseTarget.handle,
                        reuseTarget.index) ||
                    !RejectStaleSyntheticHandle(
                        reuseInitialHandle,
                        "captured initial handle resolved at the no-wrap boundary") ||
                    !ResolveSyntheticHandleExactly(
                        reuseTarget.handle,
                        static_cast<const SyntheticReference*>(reuseTarget.expected),
                        "generation-zero boundary handle did not resolve to the exact final target")) {
                    return false;
                }

                const diagnostic::EventSnapshot events =
                    diagnostic::ReadEventSnapshot();
                const std::uint32_t highestReuse =
                    static_cast<std::uint32_t>(events.hottestHandle >> 32);
                const std::uint32_t hottestHandle =
                    static_cast<std::uint32_t>(events.hottestHandle);
                const std::uint32_t hottestSlot =
                    hottestHandle & generation::kIndexMask;
                if (events.unreliableSlot != 0 ||
                    events.totalWraps != 0 || events.lastWrapEvent != 0 ||
                    events.preventedWrapAttempts != 0 ||
                    events.lastPreventedEvent != 0 ||
                    highestReuse != generation::kGenerationCount - 1u ||
                    hottestSlot != reuseTarget.index ||
                    hottestHandle != reuseTarget.handle ||
                    (hottestHandle & ~(generation::kIndexMask |
                        generation::kGenerationMask)) != 0 ||
                    diagnostic::AssignmentCount(hottestSlot) !=
                        generation::kGenerationCount) {
                    Fail("31-cycle no-wrap detector/hottest-slot evidence was not exact");
                    return false;
                }

                Log("stress: NO-WRAP BOUNDARY PASS; cycles=31 target=%06X "
                    "initialHandle=%08X finalHandle=%08X initialAssignments=%u "
                    "finalAssignments=%u reuseCount=31 guard=active "
                    "tracking=exact finalGeneration=0 object-changed=PASS "
                    "exact-target=PASS initial-stale=REJECTED "
                    "immediate-stale-rejection-each-cycle=PASS "
                    "wrapEvents=0 preventedWrapAttempts=0 highestReuse=%u hottestSlot=%06X "
                    "hottestHandle=%08X; table exhaustion was never requested",
                    reuseTarget.index,
                    reuseInitialHandle,
                    reuseTarget.handle,
                    reuseInitialAssignmentCount,
                    diagnostic::AssignmentCount(reuseTarget.index),
                    highestReuse, hottestSlot, hottestHandle);
                return true;
            }

            void BeginReuseCycle()
            {
                const bool startingGuardBoundaryAttempt =
                    settings.reuseProbeCycles == generation::kGenerationCount &&
                    reuseCompleted == generation::kGenerationCount - 1u;
                if (startingGuardBoundaryAttempt) {
                    if (!FinishNoWrapBoundaryProof())
                        return;
                } else if (reuseCompleted >= settings.reuseProbeCycles) {
                    Log("stress: REUSE PROBE PASS; cycles=%u target=%06X totalFIFOrotations=%llu; "
                        "exact-slot=PASS next-age=PASS refcount-cache=PASS "
                        "dword-invalidation=PASS stale-rejection=PASS "
                        "neighbor=PASS; table exhaustion was never requested",
                        reuseCompleted,
                        reuseTarget.index,
                        static_cast<unsigned long long>(reuseTotalRotations));
                    ContinueAfterSyntheticFill();
                    return;
                }
                if (syntheticCursor >= syntheticCapacity) {
                    Fail("synthetic arena has no pristine object for the FIFO reuse probe");
                    return;
                }

                auto* current = static_cast<SyntheticReference*>(reuseTarget.expected);
                if (!VerifyLiveSyntheticState(
                        current, reuseTarget.handle, reuseTarget.index) ||
                    !ResolveSyntheticHandleExactly(
                        reuseTarget.handle,
                        current,
                        "FIFO reuse target failed exact pre-release resolution") ||
                    !VerifyLiveSyntheticState(
                        static_cast<const SyntheticReference*>(reuseNeighbor.expected),
                        reuseNeighbor.handle,
                        reuseNeighbor.index) ||
                    !ResolveSyntheticHandleExactly(
                        reuseNeighbor.handle,
                        static_cast<const SyntheticReference*>(reuseNeighbor.expected),
                        "FIFO reuse neighbor failed exact pre-release resolution")) {
                    return;
                }

                reuseOldHandle = reuseTarget.handle;
                reuseExpectedHandle = reuseTarget.index |
                    (((reuseOldHandle & AgeMask()) + AgeIncrement()) & AgeMask());
                std::uint32_t releaseArgument = reuseOldHandle;
                releaseHandle(&releaseArgument);
                if (releaseArgument != reuseOldHandle) {
                    Fail("canonical ReleaseHandle modified the FIFO reuse target input word");
                    return;
                }
                if (!VerifyReleasedSyntheticState(
                        current, reuseOldHandle, reuseTarget.index, true) ||
                    !RejectStaleSyntheticHandle(
                        reuseOldHandle,
                        "FIFO reuse target's old handle resolved immediately after release")) {
                    return;
                }
                heldHandles[reuseHeldIndex] = {};

                reuseScratch = syntheticReferences + syntheticCursor++;
                reuseScratch->vtable = &g_syntheticVtable;
                reuseScratch->packedRefCount = 1;
                reuseScratch->pad2C = 0;
                if (reuseScratch == current) {
                    Fail("FIFO reuse scratch object was not distinct from the released target");
                    return;
                }

                reuseRotationsThisCycle = 0;
                phase = Phase::kReuseProbe;
                Log("stress: REUSE PROBE cycle %u/%u rotating the non-empty FIFO toward "
                    "target=%06X oldHandle=%08X expectedHandle=%08X neighbor=%06X; "
                    "rotationLimit=%u",
                    reuseCompleted + 1,
                    settings.reuseProbeCycles,
                    reuseTarget.index,
                    reuseOldHandle,
                    reuseExpectedHandle,
                    reuseNeighbor.index,
                    handleEntryCount * 2u);
                if (startingGuardBoundaryAttempt) {
                    Log("stress: NO-WRAP GUARD ATTEMPT; cycle=32/32 target=%06X "
                        "priorAssignments=32 nextHandle=%08X capturedInitial=%08X "
                        "expectedStop=before-pointer-publication wraps=0 "
                        "preventedWrapAttempts=0",
                        reuseTarget.index,
                        reuseExpectedHandle,
                        reuseInitialHandle);
                }
            }

            void BeginReuseProbe()
            {
                if (settings.reuseProbeCycles == 0) {
                    ContinueAfterSyntheticFill();
                    return;
                }

                reuseHeldIndex = (std::numeric_limits<std::size_t>::max)();
                for (std::size_t i = heldHandles.size(); i != 0; --i) {
                    const std::size_t candidateIndex = i - 1;
                    const HeldHandle& candidate = heldHandles[candidateIndex];
                    if (candidate.index < kFirstOrdinaryRaisedIndex ||
                        !IsSyntheticReference(candidate.expected)) {
                        continue;
                    }

                    if (candidateIndex != 0) {
                        const HeldHandle& neighbor = heldHandles[candidateIndex - 1];
                        if (neighbor.index >= kFirstOrdinaryRaisedIndex &&
                            neighbor.index + 1u == candidate.index &&
                            IsSyntheticReference(neighbor.expected)) {
                            reuseHeldIndex = candidateIndex;
                            reuseTarget = candidate;
                            reuseNeighbor = neighbor;
                            break;
                        }
                    }
                    if (candidateIndex + 1 < heldHandles.size()) {
                        const HeldHandle& neighbor = heldHandles[candidateIndex + 1];
                        if (neighbor.index >= kFirstOrdinaryRaisedIndex &&
                            candidate.index + 1u == neighbor.index &&
                            IsSyntheticReference(neighbor.expected)) {
                            reuseHeldIndex = candidateIndex;
                            reuseTarget = candidate;
                            reuseNeighbor = neighbor;
                            break;
                        }
                    }
                }
                if (reuseHeldIndex == (std::numeric_limits<std::size_t>::max)()) {
                    Fail("FIFO reuse probe could not find a separate adjacent pair of harness-owned >1M handles");
                    return;
                }

                if (!VerifyManagerFreeList(
                        "REUSE-CUSHION", &reuseInitialFreeCount)) {
                    return;
                }
                if (reuseInitialFreeCount < kMinimumReuseFreeCushion) {
                    FinishReuseInconclusive(
                        "locked allocatable free-list count was below the required 0x40000-slot cushion");
                    return;
                }
                Log("stress: REUSE PROBE locked allocatable free-slot cushion "
                    "accepted: free=%llu "
                    "required>=%u; the target has not been released yet",
                    static_cast<unsigned long long>(reuseInitialFreeCount),
                    kMinimumReuseFreeCushion);

                if (settings.reuseProbeCycles ==
                        generation::kGenerationCount) {
                    if (!diagnostic::IsActive()) {
                        Fail("31-cycle no-wrap proof requires the mandatory generation guard");
                        return;
                    }
                    const diagnostic::EventSnapshot events =
                        diagnostic::ReadEventSnapshot();
                    reuseInitialHandle = reuseTarget.handle;
                    reuseInitialObject = static_cast<SyntheticReference*>(
                        reuseTarget.expected);
                    reuseInitialAssignmentCount =
                        diagnostic::AssignmentCount(reuseTarget.index);
                    reuseInitialWrapCount = events.totalWraps;
                    if (events.unreliableSlot != 0 ||
                        events.totalWraps != 0 ||
                        events.lastWrapEvent != 0 ||
                        events.preventedWrapAttempts != 0 ||
                        events.lastPreventedEvent != 0 ||
                        reuseInitialAssignmentCount != 1u ||
                        (reuseInitialHandle & generation::kGenerationMask) !=
                            (1u << generation::kIndexBits) ||
                        (reuseInitialHandle &
                            ~(generation::kIndexMask |
                              generation::kGenerationMask)) != 0 ||
                        (reuseInitialHandle & IndexMask()) != reuseTarget.index) {
                        Fail("31-cycle no-wrap proof did not start from one exact tracked assignment with zero wraps");
                        return;
                    }
                    Log("stress: NO-WRAP BOUNDARY armed; cycles=31 target=%06X "
                        "initialHandle=%08X initialAssignments=%u detector=active "
                        "tracking=exact wrapEvents=0 preventedWrapAttempts=0",
                        reuseTarget.index,
                        reuseInitialHandle,
                        reuseInitialAssignmentCount);
                }

                BeginReuseCycle();
            }

            void BeginReleaseProbe()
            {
                if (settings.releaseProbeCount == 0) {
                    ContinueAfterSyntheticFill();
                    return;
                }
                if (!releaseHandle) {
                    Fail("canonical ReleaseHandle is unavailable for the targeted release probe");
                    return;
                }

                releaseProbeTargets.clear();
                releaseProbeTargets.reserve(settings.releaseProbeCount);
                releaseProbeMinIndex = 0xFFFFFFFFu;
                releaseProbeMaxIndex = 0;
                for (std::size_t i = heldHandles.size();
                     i != 0 && releaseProbeTargets.size() < settings.releaseProbeCount;
                     --i) {
                    const HeldHandle& held = heldHandles[i - 1];
                    if (held.index < kFirstOrdinaryRaisedIndex ||
                        !IsSyntheticReference(held.expected)) {
                        continue;
                    }
                    releaseProbeTargets.push_back({ i - 1, held });
                    releaseProbeMinIndex = (std::min)(releaseProbeMinIndex, held.index);
                    releaseProbeMaxIndex = (std::max)(releaseProbeMaxIndex, held.index);
                }
                if (releaseProbeTargets.size() != settings.releaseProbeCount) {
                    Fail("not enough harness-owned synthetic handles above reserved index 0x100000 for the targeted release probe");
                    return;
                }

                releaseProbeCursor = 0;
                phase = Phase::kReleaseProbe;
                Log("stress: RELEASE PROBE starting canonical release of %u harness-owned "
                    "synthetic handles in high-index range %06X..%06X",
                    settings.releaseProbeCount,
                    releaseProbeMinIndex,
                    releaseProbeMaxIndex);
            }

            void ProcessReleaseProbe()
            {
                if (releaseProbeCursor >= releaseProbeTargets.size()) {
                    std::erase_if(heldHandles, [](const HeldHandle& a_held) {
                        return a_held.handle == 0;
                    });
                    Log("stress: RELEASE PROBE PASS; released=%u range=%06X..%06X; "
                        "owner-count=1 complete-index-cache-cleared=PASS "
                        "padding+0x2C-untouched=PASS entry-free-prior-age=PASS "
                        "stale-rejection=PASS",
                        settings.releaseProbeCount,
                        releaseProbeMinIndex,
                        releaseProbeMaxIndex);
                    BeginReuseProbe();
                    return;
                }

                const ReleaseProbeTarget& target =
                    releaseProbeTargets[releaseProbeCursor];
                if (target.heldIndex >= heldHandles.size() ||
                    heldHandles[target.heldIndex].handle != target.held.handle ||
                    heldHandles[target.heldIndex].expected != target.held.expected) {
                    Fail("targeted release record changed before canonical release");
                    return;
                }

                auto* reference = static_cast<SyntheticReference*>(target.held.expected);
                if (!VerifyLiveSyntheticState(
                        reference, target.held.handle, target.held.index) ||
                    !ResolveSyntheticHandleExactly(
                        target.held.handle,
                        reference,
                        "targeted high-index handle failed exact pre-release resolution")) {
                    return;
                }

                std::uint32_t releaseArgument = target.held.handle;
                releaseHandle(&releaseArgument);
                if (releaseArgument != target.held.handle) {
                    Fail("canonical ReleaseHandle modified the targeted probe input word");
                    return;
                }
                if (!VerifyReleasedSyntheticState(
                        reference,
                        target.held.handle,
                        target.held.index,
                        true) ||
                    !RejectStaleSyntheticHandle(
                        target.held.handle,
                        "a targeted high-index stale handle still resolved after release")) {
                    return;
                }

                heldHandles[target.heldIndex] = {};
                ++releaseProbeCursor;
            }

            [[nodiscard]] bool ReleaseReuseScratch(
                std::uint32_t a_handle,
                std::uint32_t a_index)
            {
                std::uint32_t releaseArgument = a_handle;
                releaseHandle(&releaseArgument);
                if (releaseArgument != a_handle) {
                    Fail("canonical ReleaseHandle modified the FIFO scratch input word");
                    return false;
                }
                if (!VerifyReleasedSyntheticState(
                        reuseScratch, a_handle, a_index, true)) {
                    return false;
                }
                heldHandles[reuseHeldIndex] = {};
                return true;
            }

            void FinishReuseInconclusive(const char* a_reason)
            {
                std::erase_if(heldHandles, [](const HeldHandle& a_held) {
                    return a_held.handle == 0;
                });
                Log("stress: REUSE PROBE INCONCLUSIVE: %s; rotations=%llu; no empty-table "
                    "allocation was attempted and no harness-owned scratch handle remains",
                    a_reason ? a_reason : "concurrent handle-manager activity changed the FIFO",
                    static_cast<unsigned long long>(reuseTotalRotations));
                ContinueAfterSyntheticFill();
            }

            void ReleaseReuseScratchAndConclude(
                std::uint32_t a_handle,
                std::uint32_t a_index,
                const char* a_reason)
            {
                if (ReleaseReuseScratch(a_handle, a_index))
                    FinishReuseInconclusive(a_reason);
            }

            void ProcessReuseProbe()
            {
                const std::uint64_t rotationLimit =
                    static_cast<std::uint64_t>(handleEntryCount) * 2ull;
                if (reuseRotationsThisCycle >= rotationLimit) {
                    FinishReuseInconclusive(
                        "FIFO target was not reached within twice the table size");
                    return;
                }
                if (!ReuseTargetIsFreeAtOldAge()) {
                    FinishReuseInconclusive(
                        "the target was claimed or its age changed before the harness reached it");
                    return;
                }
                if (!freeHead || !freeTail || *freeHead == 0xFFFFFFFFu ||
                    *freeTail == 0xFFFFFFFFu) {
                    FinishReuseInconclusive(
                        "the previously measured free-slot cushion became empty during concurrent activity");
                    return;
                }
                if (!reuseScratch || ReadPackedWord(reuseScratch) != 1 ||
                    reuseScratch->pad2C != 0) {
                    Fail("FIFO reuse scratch object was not pristine before GetHandle");
                    return;
                }

                std::uint32_t handle = 0;
                std::uint32_t* returned = getHandle(&handle, reuseScratch);
                if (returned != &handle || handle == 0) {
                    if (handle != 0) {
                        heldHandles[reuseHeldIndex] = {
                            reuseScratch, handle, handle & IndexMask()
                        };
                    }
                    Fail(handle == 0 ?
                        "FIFO reuse GetHandle returned zero despite the reserved free cushion" :
                        "FIFO reuse GetHandle returned an unexpected hidden-result pointer");
                    return;
                }

                ++nonzeroHandles;
                ++reuseRotationsThisCycle;
                ++reuseTotalRotations;
                const std::uint32_t index = handle & IndexMask();
                heldHandles[reuseHeldIndex] = { reuseScratch, handle, index };
                if (settings.reuseProbeCycles == generation::kGenerationCount &&
                    reuseCompleted == generation::kGenerationCount - 1u &&
                    index == reuseTarget.index) {
                    Fail("mandatory pre-publication generation guard returned after publishing the repeated raw handle");
                    return;
                }
                if (!VerifyLiveSyntheticState(reuseScratch, handle, index) ||
                    !ResolveSyntheticHandleExactly(
                        handle,
                        reuseScratch,
                        "FIFO rotation handle failed exact resolution")) {
                    return;
                }

                if (index == reuseTarget.index) {
                    if (handle != reuseExpectedHandle) {
                        ReleaseReuseScratchAndConclude(
                            handle,
                            index,
                            "FIFO target returned with an unexpected generation after concurrent activity");
                        return;
                    }
                    if (!RejectStaleSyntheticHandle(
                            reuseOldHandle,
                            "old FIFO target handle resolved after exact-slot reuse") ||
                        !VerifyLiveSyntheticState(
                            static_cast<const SyntheticReference*>(reuseNeighbor.expected),
                            reuseNeighbor.handle,
                            reuseNeighbor.index) ||
                        !ResolveSyntheticHandleExactly(
                            reuseNeighbor.handle,
                            static_cast<const SyntheticReference*>(reuseNeighbor.expected),
                            "FIFO reuse changed the adjacent synthetic neighbor")) {
                        return;
                    }

                    reuseTarget = { reuseScratch, handle, index };
                    ++reuseCompleted;
                    if (settings.reuseProbeCycles ==
                            generation::kGenerationCount) {
                        if (!RejectStaleSyntheticHandle(
                                reuseInitialHandle,
                                "captured initial handle resolved during the 31-cycle no-wrap proof")) {
                            return;
                        }
                    }
                    if (!VerifyNoWrapDetectorProgress(
                            reuseCompleted + 1u,
                            "per-cycle exact-slot assignment")) {
                        return;
                    }
                    if (settings.reuseProbeCycles ==
                            generation::kGenerationCount) {
                        Log("stress: REUSE PROBE cycle %u/32 exact-slot PASS target=%06X "
                            "handle=%08X FIFOrotations=%llu assignmentCount=%u "
                            "stale-old=REJECTED captured-initial=REJECTED "
                            "exact-target=PASS tracking=exact wrapEvents=0 "
                            "preventedWrapAttempts=0",
                            reuseCompleted,
                            index,
                            handle,
                            static_cast<unsigned long long>(reuseRotationsThisCycle),
                            diagnostic::AssignmentCount(index));
                    } else {
                        Log("stress: REUSE PROBE cycle %u/%u exact-slot PASS target=%06X "
                            "handle=%08X FIFOrotations=%llu",
                            reuseCompleted,
                            settings.reuseProbeCycles,
                            index,
                            handle,
                            static_cast<unsigned long long>(reuseRotationsThisCycle));
                    }
                    BeginReuseCycle();
                    return;
                }

                if (!ReuseTargetIsFreeAtOldAge()) {
                    ReleaseReuseScratchAndConclude(
                        handle,
                        index,
                        "FIFO reuse target was claimed by another allocator during rotation");
                    return;
                }

                std::uint32_t releaseArgument = handle;
                releaseHandle(&releaseArgument);
                if (releaseArgument != handle) {
                    Fail("canonical ReleaseHandle modified a FIFO rotation input word");
                    return;
                }
                if (!VerifyReleasedSyntheticState(
                        reuseScratch, handle, index, true) ||
                    !RejectStaleSyntheticHandle(
                        handle,
                        "a released FIFO rotation handle still resolved")) {
                    return;
                }
                heldHandles[reuseHeldIndex] = {};

                // Once our release exposes T at the FIFO head, do not let the
                // outer batch budget yield. This recursive step is at most one
                // level deep: it either retains T or reports a concurrent race.
                if (*freeHead == reuseTarget.index) {
                    ProcessReuseProbe();
                    return;
                }

                if ((reuseRotationsThisCycle % 0x40000ull) == 0) {
                    Log("stress: REUSE PROBE FIFO progress rotations=%llu target=%06X",
                        static_cast<unsigned long long>(reuseRotationsThisCycle),
                        reuseTarget.index);
                }
            }

            [[nodiscard]] bool VerifyReleasedSyntheticState(
                const SyntheticReference* a_reference,
                std::uint32_t a_oldHandle,
                std::uint32_t a_index,
                bool a_requireFreeEntry)
            {
                if (ReadPackedWord(a_reference) != 1 || a_reference->pad2C != 0) {
                    Fail("canonical stock dword invalidation did not restore the owner-only refcount and leave +0x2C padding untouched");
                    return false;
                }

                const HandleEntry& entry = handleTable[a_index];
                const auto* oldSubobject =
                    reinterpret_cast<const std::uint8_t*>(a_reference) + 0x20;
                if (entry.pointer == oldSubobject) {
                    Fail("canonical release left the synthetic pointer published in its entry");
                    return false;
                }
                if (a_requireFreeEntry &&
                    ((entry.bits & InUseMask()) != 0 || entry.pointer != nullptr ||
                     (entry.bits & AgeMask()) != (a_oldHandle & AgeMask()))) {
                    Fail("released synthetic slot was not free with its prior generation intact");
                    return false;
                }
                return true;
            }

            void BeginChurn(SyntheticReference* a_spare)
            {
                if (!releaseHandle || !a_spare || maxIndex != IndexMask()) {
                    Fail("could not prove full-table exhaustion before starting churn");
                    return;
                }
                if (!freeHead || !freeTail || *freeHead != 0xFFFFFFFFu ||
                    *freeTail != 0xFFFFFFFFu) {
                    Fail("zero allocation did not leave both free-list endpoints exhausted");
                    return;
                }
                if (ReadPackedWord(a_spare) != 1 || a_spare->pad2C != 0) {
                    Fail("the exhaustion-probe object was modified despite receiving no handle");
                    return;
                }

                for (std::size_t i = 0; i < heldHandles.size(); ++i) {
                    const HeldHandle& held = heldHandles[i];
                    if (held.index == IndexMask() && IsSyntheticReference(held.expected)) {
                        churnHeldIndex = i;
                        churnCurrent = static_cast<SyntheticReference*>(held.expected);
                        churnNext = a_spare;
                        churnHandle = held.handle;
                        churnIndex = held.index;
                    } else if (held.index == IndexMask() - 1u &&
                               IsSyntheticReference(held.expected)) {
                        churnNeighbor = held;
                    }
                }
                if (!churnCurrent ||
                    churnIndex < kFirstOrdinaryRaisedIndex ||
                    !churnNeighbor.expected) {
                    Fail("the exhausted table did not contain a harness-owned >1M target slot");
                    return;
                }

                churnHistory.reserve(static_cast<std::size_t>(settings.churnCycles) + 1);
                churnHistory.push_back(churnHandle);
                phase = Phase::kChurn;
                Log("stress: CHURN exhaustion proven by a zero allocation after index %06X; "
                    "target=%06X handle=%08X cycles=%u ReleaseHandle=%p",
                    maxIndex,
                    churnIndex,
                    churnHandle,
                    settings.churnCycles,
                    reinterpret_cast<void*>(releaseHandle));
            }

            void FinishChurn()
            {
                if (churnCompleted != settings.churnCycles) {
                    Fail("churn finished before all configured generations completed");
                    return;
                }
                Log("stress: CHURN COMPLETE; cycles=%u target=%06X "
                    "publishedWraps=0; all stale handles rejected and exact "
                    "object identity preserved within the safe reuse limit",
                    churnCompleted,
                    churnIndex);
                Log("stress: CHURN CLEANUP COMPLETE; released %zu synthetic handles and returned "
                    "the synthetic arena; no table entry retains a synthetic pointer",
                    churnCleanupCursor);
                phase = Phase::kDone;
                finished.store(true, std::memory_order_release);
            }

            void ProcessChurn()
            {
                if (churnCompleted >= settings.churnCycles) {
                    churnCleanupCursor = 0;
                    phase = Phase::kChurnCleanup;
                    Log("stress: churn proof passed; releasing %zu synthetic handles through "
                        "Skyrim's canonical manager before returning memory",
                        heldHandles.size());
                    return;
                }

                if (!VerifyLiveSyntheticState(churnCurrent, churnHandle, churnIndex) ||
                    !ResolveSyntheticHandleExactly(
                        churnHandle,
                        churnCurrent,
                        "current churn handle failed exact pre-release resolution") ||
                    !ResolveSyntheticHandleExactly(
                        churnNeighbor.handle,
                        static_cast<const SyntheticReference*>(churnNeighbor.expected),
                        "neighbor handle failed before churn release")) {
                    return;
                }

                const std::uint32_t oldHandle = churnHandle;
                std::uint32_t releaseArgument = oldHandle;
                releaseHandle(&releaseArgument);
                if (releaseArgument != oldHandle) {
                    Fail("canonical ReleaseHandle unexpectedly modified its input word");
                    return;
                }
                if (!VerifyReleasedSyntheticState(
                        churnCurrent, oldHandle, churnIndex, true) ||
                    !RejectStaleSyntheticHandle(
                        oldHandle,
                        "just-released churn handle still resolved before slot reuse")) {
                    return;
                }
                if (*freeHead != churnIndex || *freeTail != churnIndex) {
                    Fail("released churn slot was not the sole free-list entry");
                    return;
                }

                if (!churnNext || ReadPackedWord(churnNext) != 1 || churnNext->pad2C != 0) {
                    Fail("next churn object is not pristine and owner-held");
                    return;
                }

                std::uint32_t newHandle = 0;
                std::uint32_t* returned = getHandle(&newHandle, churnNext);
                if (returned != &newHandle || newHandle == 0) {
                    Fail("churn reacquisition failed after releasing the sole free slot");
                    return;
                }
                const std::uint32_t newIndex = newHandle & IndexMask();
                const std::uint32_t expectedAge =
                    ((oldHandle & AgeMask()) + AgeIncrement()) & AgeMask();
                const std::uint32_t expectedHandle = churnIndex | expectedAge;
                if (newIndex != churnIndex || newHandle != expectedHandle) {
                    Fail("churn did not reuse the exact slot with the next five-bit age");
                    return;
                }
                if (*freeHead != 0xFFFFFFFFu || *freeTail != 0xFFFFFFFFu) {
                    Fail("churn reacquisition did not return the free list to exhaustion");
                    return;
                }
                if (!VerifyLiveSyntheticState(churnNext, newHandle, newIndex) ||
                    !ResolveSyntheticHandleExactly(
                        newHandle,
                        churnNext,
                        "reacquired churn handle did not resolve to its new object") ||
                    !ResolveSyntheticHandleExactly(
                        churnNeighbor.handle,
                        static_cast<const SyntheticReference*>(churnNeighbor.expected),
                        "neighbor handle changed during churn release/reacquisition")) {
                    return;
                }

                std::uint32_t aliasesThisGeneration = 0;
                for (const std::uint32_t prior : churnHistory) {
                    if (prior == newHandle) {
                        ++aliasesThisGeneration;
                        continue;
                    }
                    if (!RejectStaleSyntheticHandle(
                            prior,
                            "an older non-aliased churn handle resolved after slot reuse")) {
                        return;
                    }
                }
                if (aliasesThisGeneration != 0) {
                    Fail("safe-range churn unexpectedly produced a repeated raw handle");
                    return;
                }

                heldHandles[churnHeldIndex] = { churnNext, newHandle, newIndex };
                churnHistory.push_back(newHandle);
                churnCurrent = churnNext;
                churnHandle = newHandle;
                ++churnCompleted;

                if (churnCompleted <= 2 || churnCompleted == settings.churnCycles ||
                    (churnCompleted % 16) == 0) {
                    Log("stress: CHURN cycle %u/%u PASS handle=%08X index=%06X age=%08X",
                        churnCompleted,
                        settings.churnCycles,
                        churnHandle,
                        churnIndex,
                        churnHandle & AgeMask());
                }

                if (churnCompleted < settings.churnCycles) {
                    if (syntheticCursor >= syntheticCapacity) {
                        Fail("synthetic arena has no distinct object for the next churn generation");
                        return;
                    }
                    churnNext = syntheticReferences + syntheticCursor++;
                    churnNext->vtable = &g_syntheticVtable;
                    churnNext->packedRefCount = 1;
                    churnNext->pad2C = 0;
                }
            }

            void ProcessChurnCleanup()
            {
                if (churnCleanupCursor < heldHandles.size()) {
                    const HeldHandle held = heldHandles[churnCleanupCursor];
                    auto* reference = static_cast<SyntheticReference*>(held.expected);
                    std::uint32_t releaseArgument = held.handle;
                    releaseHandle(&releaseArgument);
                    if (releaseArgument != held.handle ||
                        !VerifyReleasedSyntheticState(
                            reference, held.handle, held.index, false)) {
                        return;
                    }
                    if (held.index == churnIndex) {
                        for (const std::uint32_t prior : churnHistory) {
                            if (!RejectStaleSyntheticHandle(
                                    prior,
                                    "a churn generation resolved after the final target release")) {
                                return;
                            }
                        }
                        Log("stress: CHURN final release PASS; all %zu recorded generation "
                            "handles reject while the target slot is free",
                            churnHistory.size());
                    }
                    ++churnCleanupCursor;
                    return;
                }

                churnTableVerifyCursor = 0;
                phase = Phase::kChurnVerifyCleanup;
                Log("stress: all synthetic handles released; scanning the raised table before "
                    "returning synthetic memory");
            }

            [[nodiscard]] bool VerifyManagerFreeList(
                const char* a_label,
                std::uint64_t* a_allocatableFreeEntriesOut = nullptr,
                bool a_requireLivePlayer = false,
                bool* a_playerLiveOut = nullptr,
                LifecycleSnapshot* a_lifecycleSnapshotOut = nullptr)
            {
                if (!lockManager || !unlockManager || !managerLock) {
                    Fail("manager lock metadata is unavailable for final free-list verification");
                    return false;
                }

                const char* failure = nullptr;
                std::uint64_t physicalFreeEntries = 0;
                std::uint64_t allocatableFreeEntries = 0;
                std::uint64_t linkedEntries = 0;
                std::uint32_t head = 0xFFFFFFFFu;
                std::uint32_t tail = 0xFFFFFFFFu;
                const bool reservationApplies = UsesReservedPlayerSlot();
                bool reservedDetached = false;
                bool reservedLive = false;

                lockManager(managerLock);
                head = *freeHead;
                tail = *freeTail;
                for (std::uint32_t i = 0; i < handleEntryCount; ++i) {
                    const HandleEntry& entry = handleTable[i];
                    const bool inUse = (entry.bits & InUseMask()) != 0;
                    if (reservationApplies && i == player_slot::kIndex) {
                        if (!inUse) {
                            ++physicalFreeEntries;
                            reservedDetached = true;
                            if (!player_slot::IsDetached(entry)) {
                                failure = "the detached player reservation does not match its exact sentinel";
                            }
                        } else {
                            reservedLive = true;
                            const std::uint32_t handle =
                                i | (entry.bits & AgeMask());
                            if (!player_slot::IsLiveGenerationZero(entry) ||
                                entry.pad != 0 ||
                                handle != player_slot::kVanillaRawHandle) {
                                failure = "the live player reservation has invalid padding, pointer, or raw handle";
                            } else {
                                // The harness runs after kDataLoaded, unlike the
                                // allocator's early singleton-pointer gate, so
                                // FormID 0x14 is established here.
                                const auto* reference =
                                    static_cast<const std::uint8_t*>(entry.pointer) - 0x20;
                                if (ReadFormID(reference) !=
                                    player_slot::kPlayerFormID) {
                                    failure = "the live reserved slot does not point to FormID 00000014";
                                }
                            }
                        }
                        if (failure)
                            break;
                        continue;
                    }
                    if (!inUse) {
                        ++physicalFreeEntries;
                        ++allocatableFreeEntries;
                        if (entry.pointer != nullptr) {
                            failure = "a free-list entry retained a non-null object pointer";
                            break;
                        }
                    }
                }

                if (!failure) {
                    if (allocatableFreeEntries == 0) {
                        if (head != 0xFFFFFFFFu || tail != 0xFFFFFFFFu)
                            failure = "empty free list has non-empty head/tail endpoints";
                    } else if (head >= handleEntryCount || tail >= handleEntryCount) {
                        failure = "non-empty free list has an out-of-range endpoint";
                    } else if (reservationApplies &&
                               (head == player_slot::kIndex ||
                                tail == player_slot::kIndex)) {
                        failure = "the reserved player slot appears as a free-list endpoint";
                    } else {
                        std::uint32_t current = head;
                        for (;;) {
                            if (current >= handleEntryCount) {
                                failure = "free-list chain contains an out-of-range index";
                                break;
                            }
                            if (reservationApplies &&
                                current == player_slot::kIndex) {
                                failure = "the free-list chain visits the reserved player slot";
                                break;
                            }
                            const HandleEntry& entry = handleTable[current];
                            if ((entry.bits & InUseMask()) != 0 || entry.pointer != nullptr) {
                                failure = "free-list chain visits an in-use or published entry";
                                break;
                            }
                            ++linkedEntries;
                            const std::uint32_t next = entry.bits & IndexMask();
                            if (current == tail) {
                                if (next != tail)
                                    failure = "free-list tail is not self-linked";
                                break;
                            }
                            if (linkedEntries >= allocatableFreeEntries) {
                                failure = "free-list chain cycles or omits its recorded tail";
                                break;
                            }
                            current = next;
                        }
                        if (!failure &&
                            linkedEntries != allocatableFreeEntries) {
                            failure = "free-list chain count differs from the number of allocatable free entries";
                        }
                    }
                }

                if (!failure && a_requireLivePlayer &&
                    (!reservationApplies || !reservedLive)) {
                    failure = "the lifecycle checkpoint did not contain a live reserved player";
                }
                LifecycleSnapshot lifecycleSnapshot{};
                if (!failure && a_lifecycleSnapshotOut) {
                    lifecycleSnapshot.lifecycle =
                        patch::ReadReservedPlayerLifecycleSnapshot();
                    lifecycleSnapshot.assignments =
                        diagnostic::ReservedPlayerAssignmentCount();
                    if (reservedLive) {
                        const HandleEntry& reserved =
                            handleTable[player_slot::kIndex];
                        lifecycleSnapshot.playerObject =
                            static_cast<const std::uint8_t*>(
                                reserved.pointer) - 0x20;
                        if (profile && profile->playerSingletonRva != 0) {
                            std::memcpy(&lifecycleSnapshot.playerSingleton,
                                reinterpret_cast<const void*>(imageBase +
                                    profile->playerSingletonRva),
                                sizeof(lifecycleSnapshot.playerSingleton));
                        }
                        if (lifecycleSnapshot.playerObject !=
                                lifecycleSnapshot.playerSingleton) {
                            failure = "the manager-locked lifecycle snapshot has mismatched player identities";
                        }
                    }
                }
                unlockManager(managerLock);

                if (failure) {
                    Fail(failure);
                    return false;
                }
                if (a_allocatableFreeEntriesOut)
                    *a_allocatableFreeEntriesOut = allocatableFreeEntries;
                if (a_playerLiveOut)
                    *a_playerLiveOut = reservedLive;
                if (a_lifecycleSnapshotOut)
                    *a_lifecycleSnapshotOut = lifecycleSnapshot;
                Log("stress: %s free-list integrity PASS; allocatableFree=%llu "
                    "physicalFree=%llu inUse=%llu head=%06X tail=%06X "
                    "playerReservation=%s playerRawHandle=%s "
                    "reservedSlotInOrdinaryFIFO=no",
                    a_label,
                    static_cast<unsigned long long>(allocatableFreeEntries),
                    static_cast<unsigned long long>(physicalFreeEntries),
                    static_cast<unsigned long long>(
                        handleEntryCount - physicalFreeEntries),
                    head,
                    tail,
                    !reservationApplies ? "n/a" :
                        (reservedDetached ? "detached" :
                            (reservedLive ? "live-player" : "invalid")),
                    reservedLive ? "00100000" : "n/a");
                return true;
            }

            [[nodiscard]] bool VerifyLifecycleCheckpoint(
                const char* a_event,
                std::uint32_t a_ordinal,
                bool a_requireLivePlayer,
                std::uint32_t a_loadAttempt = 0)
            {
                if (enginefixes::WasFormCachingLifecycleOwnerAuthenticated()) {
                    RuntimeContext runtime{};
                    runtime.imageBase = imageBase;
                    runtime.runtimeVersion = profile ?
                        profile->runtimeVersion : 0;
                    if (!enginefixes::RevalidateFormCachingLifecycleOwner(
                            runtime)) {
                        Fail("the authenticated Engine Fixes FormCaching hook chain changed");
                        return false;
                    }
                    Log("lifecycle: EngineFixesFormCaching revalidation PASS "
                        "event=%s ordinal=%u", a_event, a_ordinal);
                }
                char label[96]{};
                std::snprintf(label, sizeof(label),
                    "LIFECYCLE %s #%u", a_event, a_ordinal);
                label[sizeof(label) - 1] = '\0';

                if (a_loadAttempt != 0) {
                    Log("lifecycle: checkpoint BEGIN event=%s ordinal=%u "
                        "loadAttempt=%u",
                        a_event, a_ordinal, a_loadAttempt);
                } else {
                    Log("lifecycle: checkpoint BEGIN event=%s ordinal=%u",
                        a_event, a_ordinal);
                }
                bool playerLive = false;
                LifecycleSnapshot lifecycleSnapshot{};
                if (!VerifyManagerFreeList(
                        label, nullptr, a_requireLivePlayer, &playerLive,
                        &lifecycleSnapshot)) {
                    return false;
                }
                if (a_loadAttempt != 0) {
                    Log("lifecycle: checkpoint PASS event=%s ordinal=%u "
                        "loadAttempt=%u playerReservation=%s "
                        "playerRawHandle=%s reservedSlot=100000 "
                        "ordinaryFIFO=ABSENT",
                        a_event,
                        a_ordinal,
                        a_loadAttempt,
                        playerLive ? "live-player" : "detached",
                        playerLive ? "00100000" : "n/a");
                } else {
                    Log("lifecycle: checkpoint PASS event=%s ordinal=%u "
                        "playerReservation=%s playerRawHandle=%s "
                        "reservedSlot=100000 ordinaryFIFO=ABSENT",
                        a_event,
                        a_ordinal,
                        playerLive ? "live-player" : "detached",
                        playerLive ? "00100000" : "n/a");
                }
                Log("lifecycle: snapshot event=%s ordinal=%u "
                    "constructorAssignments=%llu releaseQuarantines=%llu "
                    "lifecycleAssignments=%u reservation=%s raw=%s "
                    "object=%p singleton=%p",
                    a_event, a_ordinal,
                    static_cast<unsigned long long>(
                        lifecycleSnapshot.lifecycle.constructorAssignments),
                    static_cast<unsigned long long>(
                        lifecycleSnapshot.lifecycle.releaseQuarantines),
                    lifecycleSnapshot.assignments,
                    playerLive ? "live-player" : "detached",
                    playerLive ? "00100000" : "n/a",
                    lifecycleSnapshot.playerObject,
                    lifecycleSnapshot.playerSingleton);
                return true;
            }

            void ProcessChurnVerifyCleanup()
            {
                constexpr std::uint32_t kEntriesPerChunk = 0x10000;
                const std::uint32_t end = (std::min)(
                    handleEntryCount,
                    churnTableVerifyCursor + kEntriesPerChunk);
                const auto beginAddress =
                    reinterpret_cast<std::uintptr_t>(syntheticReferences);
                const auto endAddress = beginAddress +
                    syntheticCapacity * sizeof(SyntheticReference);
                for (; churnTableVerifyCursor < end; ++churnTableVerifyCursor) {
                    const auto pointer = reinterpret_cast<std::uintptr_t>(
                        handleTable[churnTableVerifyCursor].pointer);
                    if (pointer >= beginAddress && pointer < endAddress) {
                        Fail("a raised-table entry still points into the synthetic arena after cleanup");
                        return;
                    }
                }
                if (churnTableVerifyCursor < handleEntryCount)
                    return;

                if (!VerifyManagerFreeList("CHURN"))
                    return;

                std::vector<HeldHandle>().swap(heldHandles);
                std::vector<std::uint32_t>().swap(churnHistory);
                if (!VirtualFree(syntheticReferences, 0, MEM_RELEASE)) {
                    Fail("VirtualFree failed after releasing every synthetic handle");
                    return;
                }
                syntheticReferences = nullptr;
                syntheticCapacity = 0;
                churnCurrent = nullptr;
                churnNext = nullptr;
                FinishChurn();
            }

            void BeginStockCleanup(bool a_passed, const char* a_failureReason)
            {
                stockProbePassed = a_passed;
                stockFailureReason = a_failureReason;
                stockCleanupCursor = 0;
                phase = Phase::kStockCleanup;
                SetTaskWorkReady(true);
                WakeCoordinator();
                Log("stock-control: releasing %zu probe-owned synthetic handles through "
                    "Skyrim's canonical manager API",
                    heldHandles.size());
            }

            void BeginStockOverflow(SyntheticReference* a_exhaustionProbe)
            {
                if (!IsStockControl() || !releaseHandle || !a_exhaustionProbe) {
                    Fail("stock-control exhaustion was reached without complete manager metadata");
                    return;
                }
                if (!freeHead || !freeTail || *freeHead != 0xFFFFFFFFu ||
                    *freeTail != 0xFFFFFFFFu) {
                    BeginStockCleanup(
                        false,
                        "GetHandle returned zero before both stock free-list endpoints were exhausted");
                    return;
                }
                if (ReadPackedWord(a_exhaustionProbe) != 1 ||
                    a_exhaustionProbe->pad2C != 0) {
                    BeginStockCleanup(
                        false,
                        "the first stock overflow object changed despite receiving no handle");
                    return;
                }

                stockOverflowCompleted = 1;
                phase = Phase::kStockOverflow;
                Log("stock-control: STOCK 1M CAP EXHAUSTED; probe owns %zu synthetic handles; "
                    "head=FFFFFFFF tail=FFFFFFFF; overflow attempt 1/%u returned zero",
                    heldHandles.size(),
                    settings.stockOverflowAttempts);
            }

            void FinishStockOverflow()
            {
                if (stockOverflowCompleted != settings.stockOverflowAttempts) {
                    BeginStockCleanup(false, "stock overflow attempt count ended early");
                    return;
                }

                const bool endpointsExhausted = freeHead && freeTail &&
                    *freeHead == 0xFFFFFFFFu && *freeTail == 0xFFFFFFFFu;
                const bool passed = stockUnexpectedSuccesses == 0 && endpointsExhausted;
                Log("stock-control: overflow result: attempts=%u zeroReturns=%u "
                    "unexpectedNonzero=%u endpoints=%s",
                    stockOverflowCompleted,
                    stockOverflowCompleted - stockUnexpectedSuccesses,
                    stockUnexpectedSuccesses,
                    endpointsExhausted ? "EXHAUSTED" : "NOT-EXHAUSTED");

                if (!passed) {
                    BeginStockCleanup(
                        false,
                        stockUnexpectedSuccesses != 0 ?
                            "one or more above-cap attempts unexpectedly acquired a handle" :
                            "stock free-list endpoints changed before overflow proof completed");
                    return;
                }

                if (settings.stockHoldThroughGameLoad) {
                    if (gameLoadSeen.load(std::memory_order_acquire)) {
                        BeginStockCleanup(
                            false,
                            "kPostLoadGame/kNewGame occurred before the stock table was exhausted");
                        return;
                    }
                    phase = Phase::kStockWaitForGameLoad;
                    SetTaskWorkReady(false);
                    Log("stock-control: OVERFLOW PROOF PASS; holding the stock table full through "
                        "the next kPostLoadGame/kNewGame for the throwaway reproduction");
                    Log("stock-control: TAINTED MODE ACTIVE -- failed engine allocations cannot be "
                        "repaired; do not save and exit Skyrim after collecting the result");
                    return;
                }

                Log("stock-control: OVERFLOW PROOF PASS; starting immediate canonical cleanup");
                BeginStockCleanup(true, nullptr);
            }

            void ProcessStockOverflow()
            {
                if (stockOverflowCompleted >= settings.stockOverflowAttempts) {
                    FinishStockOverflow();
                    return;
                }
                if (syntheticCursor >= syntheticCapacity) {
                    BeginStockCleanup(false, "synthetic arena ended before all overflow attempts");
                    return;
                }

                SyntheticReference* reference = syntheticReferences + syntheticCursor++;
                reference->vtable = &g_syntheticVtable;
                reference->packedRefCount = 1;
                reference->pad2C = 0;

                const std::size_t oldHeldSize = heldHandles.size();
                if (!AcquireAndVerify(reference, true, true) || phase == Phase::kFailed)
                    return;

                ++stockOverflowCompleted;
                if (heldHandles.size() != oldHeldSize) {
                    ++stockUnexpectedSuccesses;
                    if (stockUnexpectedSuccesses <= 8) {
                        const HeldHandle& held = heldHandles.back();
                        Log("stock-control: overflow attempt %u unexpectedly acquired "
                            "handle=%08X index=%06X",
                            stockOverflowCompleted,
                            held.handle,
                            held.index);
                    }
                } else if (ReadPackedWord(reference) != 1 || reference->pad2C != 0) {
                    BeginStockCleanup(
                        false,
                        "an expected-zero overflow object was modified by GetHandle");
                    return;
                } else if (!freeHead || !freeTail || *freeHead != 0xFFFFFFFFu ||
                           *freeTail != 0xFFFFFFFFu) {
                    BeginStockCleanup(
                        false,
                        "an expected-zero overflow attempt left non-exhausted endpoints");
                    return;
                }

                if (stockOverflowCompleted <= 2 ||
                    stockOverflowCompleted == settings.stockOverflowAttempts ||
                    (stockOverflowCompleted % 1024u) == 0) {
                    Log("stock-control: overflow progress %u/%u; zero=%u unexpectedNonzero=%u",
                        stockOverflowCompleted,
                        settings.stockOverflowAttempts,
                        stockOverflowCompleted - stockUnexpectedSuccesses,
                        stockUnexpectedSuccesses);
                }
            }

            void ProcessStockCleanup()
            {
                if (stockCleanupCursor < heldHandles.size()) {
                    const HeldHandle held = heldHandles[stockCleanupCursor];
                    auto* reference = static_cast<SyntheticReference*>(held.expected);
                    std::uint32_t releaseArgument = held.handle;
                    releaseHandle(&releaseArgument);
                    if (releaseArgument != held.handle ||
                        !VerifyReleasedSyntheticState(
                            reference, held.handle, held.index, false)) {
                        return;
                    }
                    ++stockCleanupCursor;
                    return;
                }

                stockTableVerifyCursor = 0;
                phase = Phase::kStockVerifyCleanup;
                Log("stock-control: all probe-owned handles released; scanning the stock table "
                    "before returning synthetic memory");
            }

            void ProcessStockVerifyCleanup()
            {
                constexpr std::uint32_t kEntriesPerChunk = 0x10000;
                const std::uint32_t end = (std::min)(
                    handleEntryCount,
                    stockTableVerifyCursor + kEntriesPerChunk);
                const auto beginAddress =
                    reinterpret_cast<std::uintptr_t>(syntheticReferences);
                const auto endAddress = beginAddress +
                    syntheticCapacity * sizeof(SyntheticReference);
                for (; stockTableVerifyCursor < end; ++stockTableVerifyCursor) {
                    const auto pointer = reinterpret_cast<std::uintptr_t>(
                        handleTable[stockTableVerifyCursor].pointer);
                    if (pointer >= beginAddress && pointer < endAddress) {
                        Fail("a stock-table entry retained a pointer into the synthetic arena");
                        return;
                    }
                }
                if (stockTableVerifyCursor < handleEntryCount)
                    return;

                if (!VerifyManagerFreeList("STOCK-CONTROL"))
                    return;

                const std::size_t released = stockCleanupCursor;
                std::vector<HeldHandle>().swap(heldHandles);
                if (!VirtualFree(syntheticReferences, 0, MEM_RELEASE)) {
                    Fail("VirtualFree failed after releasing every stock-control handle");
                    return;
                }
                syntheticReferences = nullptr;
                syntheticCapacity = 0;

                if (stockProbePassed) {
                    Log("stock-control: COMPLETE PASS; exhausted the vanilla 1M table, "
                        "%u/%u above-cap attempts returned zero, released %zu synthetic "
                        "handles, and returned the arena",
                        stockOverflowCompleted - stockUnexpectedSuccesses,
                        stockOverflowCompleted,
                        released);
                    if (stockHeldThroughGameLoad) {
                        Log("stock-control: TAINTED REPRODUCTION COMPLETE; cleanup cannot repair "
                            "engine allocations that failed while full. Exit without saving.");
                    }
                    phase = Phase::kDone;
                } else {
                    Log("stock-control: FAILED after verified cleanup: %s",
                        stockFailureReason ? stockFailureReason : "unknown stock-control failure");
                    phase = Phase::kFailed;
                }
                finished.store(true, std::memory_order_release);
            }

            [[nodiscard]] bool TimeBudgetReached(
                std::uint32_t a_processed,
                const LARGE_INTEGER& a_startedAt) const noexcept
            {
                // Keep a synchronous host logger from turning one otherwise
                // bounded task into a multi-megabyte main-thread write.
                if (detailBuffer.size() >= kMaxDetailBytesPerTask)
                    return true;
                if (a_processed >= ActiveReferencesPerTask())
                    return true;
                if (a_processed == 0 || (a_processed & 0x1F) != 0)
                    return false;

                LARGE_INTEGER now{};
                QueryPerformanceCounter(&now);
                const auto elapsed = static_cast<std::uint64_t>(now.QuadPart - a_startedAt.QuadPart);
                const auto allowed =
                    (static_cast<std::uint64_t>(qpcFrequency.QuadPart) *
                     ActiveTaskMicroseconds()) /
                    1000000ull;
                return elapsed >= allowed;
            }

            void ProcessSynthetic()
            {
                if (syntheticCursor >= syntheticCapacity) {
                    Fail("synthetic filler did not reach the requested index");
                    return;
                }

                SyntheticReference* reference = syntheticReferences + syntheticCursor;
                // VirtualAlloc zero-initializes the region.  Explicitly restore
                // the only fields observed by the handle manager for each block.
                reference->vtable = &g_syntheticVtable;
                reference->packedRefCount = 1;
                reference->pad2C = 0;
                ++syntheticCursor;
                ++fillerAttempted;

                const std::size_t oldHeldSize = heldHandles.size();
                const bool canBeExhaustionProbe = IsStockControl() ||
                    (settings.churnCycles != 0 && maxIndex == IndexMask());
                if (!AcquireAndVerify(reference, true, canBeExhaustionProbe) ||
                    phase == Phase::kFailed) {
                    return;
                }
                if (heldHandles.size() == oldHeldSize) {
                    if (IsStockControl()) {
                        BeginStockOverflow(reference);
                        return;
                    }
                    if (canBeExhaustionProbe) {
                        BeginChurn(reference);
                        return;
                    }
                    Fail("synthetic filler could not acquire and verify a handle");
                    return;
                }

                const std::uint32_t lastIndex = heldHandles.back().index;
                if (IsStockControl()) {
                    if (lastIndex == IndexMask()) {
                        Log("stock-control: acquired final numeric stock slot %06X; "
                            "continuing until GetHandle proves the free list empty",
                            lastIndex);
                    }
                    return;
                }
                if (lastIndex + 1u >= settings.syntheticFillToIndex) {
                    if (settings.churnCycles != 0) {
                        if (lastIndex == IndexMask()) {
                            Log("stress: reached final slot %06X; issuing one additional "
                                "allocation to prove that the free list is empty",
                                lastIndex);
                        }
                        return;
                    }
                    Log("stress: synthetic filler reached index %06X with %zu objects; "
                        "the next newly-used references are above the vanilla cap",
                        lastIndex,
                        syntheticCursor);
                    BeginSyntheticSecondPass();
                }
            }

            void ProcessReal()
            {
                if (realCursor >= realReferences.size()) {
                    FlushDetails();
                    if (settings.verifySecondPass) {
                        Log("stress: allocation pass complete; starting second lookup pass "
                            "over %zu handles",
                            heldHandles.size());
                        phase = Phase::kSecondPass;
                    } else {
                        Complete();
                    }
                    return;
                }

                void* reference = realReferences[realCursor++];
                ++realAttempted;
                static_cast<void>(AcquireAndVerify(reference, false));
            }

            void ProcessSecondPass()
            {
                if (verifyCursor >= heldHandles.size()) {
                    Complete();
                    return;
                }

                const HeldHandle& held = heldHandles[verifyCursor++];
                void* resolved = nullptr;
                const bool lookupOK = getSmartPointer(&held.handle, &resolved);
                if (!lookupOK) {
                    ++secondPassFailures;
                    if (ShouldStopOnFailure())
                        Fail("GetSmartPointer failed during the second lookup pass");
                } else if (resolved != held.expected) {
                    ++secondPassMismatches;
                    if (ShouldStopOnFailure())
                        Fail("second lookup pass resolved a handle to the wrong object");
                }
                if (lookupOK)
                    static_cast<void>(ReleaseLookupReference(resolved));
            }

            void BeginLiveTableSample()
            {
                if (!handleTable || handleEntryCount <= kStockCrossingIndex) {
                    Fail("the relocated handle table was not supplied to the live sampler");
                    return;
                }
                if (IsLiveDiagnostics()) {
                    detailBuffer.clear();
                    sampledHandles.clear();
                    diagnosticPluginCounts.clear();
                    diagnosticSortedPlugins.clear();
                    liveSampleMode = true;
                    liveScanCursor = kStockCrossingIndex;
                    liveScanPasses = 0;
                    liveScanCandidates = 0;
                    liveScanRaces = 0;
                    diagnosticResolved = 0;
                    diagnosticAttributed = 0;
                    diagnosticUnattributed = 0;
                    diagnosticNonReferences = 0;
                    diagnosticDetailedSamples = 0;
                    diagnosticSummaryCursor = 0;
                    diagnosticPassStartedTick = GetTickCount64();
                    diagnosticNextPassTick.store(0, std::memory_order_release);
                    SetTaskWorkReady(true);
                    phase = Phase::kLiveTableSample;
                    Log("diagnostics: beginning recurring read-only scan of slots "
                        "[%06X,%06X], detailedSampleLimit=%u",
                        kStockCrossingIndex,
                        handleEntryCount - 1,
                        settings.diagnosticsDetailedSampleLimit);
                    Log("diagnostics: every in-use candidate is validated by exact-age "
                        "GetSmartPointer lookup; each temporary pin is released before the "
                        "next candidate");
                    return;
                }
                if (settings.maxDetailedLogs == 0) {
                    Fail("MaxDetailedLogs must be nonzero for a live sample");
                    return;
                }

                liveSampleMode = true;
                liveScanCursor = (std::max)(
                    kStockCrossingIndex, settings.detailedLogFromIndex);
                liveScanPasses = 0;
                phase = Phase::kLiveTableSample;
                SetTaskWorkReady(true);
                Log("stress: save/new game is loaded and filler is complete; scanning live "
                    "handles from index %06X for %u attributed plugin/form samples",
                    liveScanCursor,
                    settings.maxDetailedLogs);
            }

            void WaitForLoadedGame()
            {
                phase = Phase::kWaitForGameLoad;
                SetTaskWorkReady(false);
                if (IsLiveDiagnostics())
                    diagnosticNextPassTick.store(0, std::memory_order_release);
                if (!waitingForGameLogged) {
                    waitingForGameLogged = true;
                    if (IsLiveDiagnostics()) {
                        Log("diagnostics: armed read-only; waiting for SKSE "
                            "kPostLoadGame/kNewGame before scanning live references");
                    } else {
                        Log("stress: vanilla cap boundary is ready; waiting for SKSE "
                            "kPostLoadGame/kNewGame before sampling real live references");
                    }
                }
                WakeCoordinator();
            }

            void ScheduleDiagnosticPass()
            {
                phase = Phase::kDiagnosticWait;
                diagnosticNextPassTick.store(
                    GetTickCount64() + kDiagnosticReportIntervalMilliseconds,
                    std::memory_order_release);
                SetTaskWorkReady(false);
                WakeCoordinator();
            }

            void BeginDiagnosticSummary()
            {
                FlushDetails();
                diagnosticSortedPlugins.clear();
                diagnosticSortedPlugins.reserve(diagnosticPluginCounts.size());
                for (const auto& entry : diagnosticPluginCounts)
                    diagnosticSortedPlugins.push_back(entry.first);
                std::sort(
                    diagnosticSortedPlugins.begin(),
                    diagnosticSortedPlugins.end());
                diagnosticSummaryCursor = 0;
                phase = Phase::kDiagnosticSummary;
                Log("diagnostics: HIGH ATTRIBUTION rows follow; references is the distinct "
                    "live-reference count for that source, while role columns may overlap");
            }

            void CompleteDiagnosticSummary()
            {
                FlushDetails();
                Log("diagnostics: HIGH REPORT COMPLETE slotsScanned=%u inUseCandidates=%llu "
                    "validatedReferences=%llu attributed=%llu unattributed=%llu "
                    "nonReferenceObjects=%llu transientRaces=%llu sources=%zu "
                    "detailedSamples=%llu/%u",
                    handleEntryCount - kStockCrossingIndex,
                    static_cast<unsigned long long>(liveScanCandidates),
                    static_cast<unsigned long long>(diagnosticResolved),
                    static_cast<unsigned long long>(diagnosticAttributed),
                    static_cast<unsigned long long>(diagnosticUnattributed),
                    static_cast<unsigned long long>(diagnosticNonReferences),
                    static_cast<unsigned long long>(liveScanRaces),
                    diagnosticPluginCounts.size(),
                    static_cast<unsigned long long>(diagnosticDetailedSamples),
                    settings.diagnosticsDetailedSampleLimit);
                Log("diagnostics: read-only scan complete; no synthetic or real handles were "
                    "created or retained, and every successful lookup pin was balanced");
                if (!gameLoadSeen.load(std::memory_order_acquire)) {
                    WaitForLoadedGame();
                    return;
                }

                const std::uint64_t now = GetTickCount64();
                const std::uint64_t next =
                    diagnosticPassStartedTick + kDiagnosticReportIntervalMilliseconds;
                phase = Phase::kDiagnosticWait;
                diagnosticNextPassTick.store(next, std::memory_order_release);
                SetTaskWorkReady(next <= now);
                WakeCoordinator();
            }

            void ProcessDiagnosticSummary()
            {
                if (diagnosticSummaryCursor >= diagnosticSortedPlugins.size()) {
                    CompleteDiagnosticSummary();
                    return;
                }

                const std::string& name =
                    diagnosticSortedPlugins[diagnosticSummaryCursor++];
                const auto found = diagnosticPluginCounts.find(name);
                if (found == diagnosticPluginCounts.end()) {
                    Fail("an attribution source disappeared while formatting the report");
                    return;
                }
                const PluginAttributionCounts& counts = found->second;
                char line[1024]{};
                std::snprintf(
                    line,
                    sizeof(line),
                    "diagnostics: HIGH ATTRIBUTION source=\"%s\" references=%llu "
                    "refOrigin=%llu refWinner=%llu baseOrigin=%llu baseWinner=%llu\n",
                    name.c_str(),
                    static_cast<unsigned long long>(counts.references),
                    static_cast<unsigned long long>(counts.referenceOrigin),
                    static_cast<unsigned long long>(counts.referenceWinner),
                    static_cast<unsigned long long>(counts.baseOrigin),
                    static_cast<unsigned long long>(counts.baseWinner));
                line[sizeof(line) - 1] = '\0';
                detailBuffer.append(line);
            }

            void ProcessLiveDiagnostics()
            {
                if (liveScanCursor >= handleEntryCount) {
                    BeginDiagnosticSummary();
                    return;
                }

                const std::uint32_t index = liveScanCursor++;
                if (IsReservedPlayerSlot(index))
                    return;
                const HandleEntry& entry = handleTable[index];
                const std::uint32_t bits = entry.bits;
                if ((bits & InUseMask()) == 0)
                    return;

                ++liveScanCandidates;
                const std::uint32_t handle = index | (bits & AgeMask());
                void* resolved = nullptr;
                const bool lookupOK = getSmartPointer(&handle, &resolved);
                if (!lookupOK || !resolved) {
                    ++liveScanRaces;
                    // The reviewed engine implementations leave this null on
                    // failure. Balance it defensively if a future/runtime
                    // variant reports failure after publishing an owned pin.
                    if (resolved)
                        static_cast<void>(ReleaseLookupReference(resolved));
                    return;
                }

                // A successful exact-age lookup pins the object. Recheck the
                // published entry while pinned so attribution never follows a
                // stale/reused candidate captured at the start of this step.
                const HandleEntry& confirmed = handleTable[index];
                const std::uint32_t confirmedBits = confirmed.bits;
                const void* expectedSubobject =
                    static_cast<const std::uint8_t*>(resolved) + 0x20;
                if ((confirmedBits & InUseMask()) == 0 ||
                    (confirmedBits & AgeMask()) != (handle & AgeMask()) ||
                    confirmed.pointer != expectedSubobject) {
                    ++liveScanRaces;
                    static_cast<void>(ReleaseLookupReference(resolved));
                    return;
                }

                const auto formType = static_cast<const std::uint8_t*>(resolved)[0x1A];
                if (formType < 0x3D || formType > 0x46) {
                    ++diagnosticNonReferences;
                    static_cast<void>(ReleaseLookupReference(resolved));
                    return;
                }

                ++diagnosticResolved;
                try {
                    ResolvedNames attribution{};
                    if (callbacks.resolveAttribution) {
                        static_cast<void>(callbacks.resolveAttribution(
                            callbacks.context, resolved, attribution));
                    }
                    SanitizeResolvedNames(attribution);
                    if (RecordDiagnosticAttribution(attribution))
                        ++diagnosticAttributed;
                    else
                        ++diagnosticUnattributed;
                    AppendDiagnosticSample(resolved, handle, index);
                } catch (...) {
                    static_cast<void>(ReleaseLookupReference(resolved));
                    throw;
                }
                static_cast<void>(ReleaseLookupReference(resolved));
            }

            void ProcessLiveTableSample()
            {
                if (IsLiveDiagnostics()) {
                    ProcessLiveDiagnostics();
                    return;
                }
                if (attributedDetailedLogs >= settings.maxDetailedLogs) {
                    Complete();
                    return;
                }

                if (liveScanCursor >= handleEntryCount) {
                    ++liveScanPasses;
                    FlushDetails();
                    if (liveScanPasses <= 3 || (liveScanPasses % 10) == 0) {
                        Log("stress: live scan pass %u complete; attributed=%llu/%u "
                            "candidates=%llu transient-races=%llu; continuing to watch",
                            liveScanPasses,
                            static_cast<unsigned long long>(attributedDetailedLogs),
                            settings.maxDetailedLogs,
                            static_cast<unsigned long long>(liveScanCandidates),
                            static_cast<unsigned long long>(liveScanRaces));
                    }
                    liveScanCursor = (std::max)(
                        kStockCrossingIndex, settings.detailedLogFromIndex);
                    return;
                }

                const std::uint32_t index = liveScanCursor++;
                if (IsReservedPlayerSlot(index))
                    return;
                const HandleEntry& entry = handleTable[index];
                const std::uint32_t bits = entry.bits;
                if ((bits & InUseMask()) == 0)
                    return;

                const std::uint32_t handle = index | (bits & AgeMask());
                if (std::find(sampledHandles.begin(), sampledHandles.end(), handle) !=
                    sampledHandles.end()) {
                    return;
                }

                ++liveScanCandidates;
                void* resolved = nullptr;
                if (!getSmartPointer(&handle, &resolved) || !resolved) {
                    ++liveScanRaces;
                    return;
                }

                if (IsSyntheticReference(resolved)) {
                    static_cast<void>(ReleaseLookupReference(resolved));
                    return;
                }

                const auto formType = static_cast<const std::uint8_t*>(resolved)[0x1A];
                if (formType < 0x3D || formType > 0x46) {
                    static_cast<void>(ReleaseLookupReference(resolved));
                    return;
                }

                ++realAttempted;
                ++nonzeroHandles;
                ++realAboveStock;
                if (index >= kFirstOrdinaryRaisedIndex)
                    ++realWithRaisedIndex;
                maxIndex = (std::max)(maxIndex, index);

                bool attributed = false;
                try {
                    attributed = AppendReferenceDetail(
                        resolved, handle, index, true);
                } catch (...) {
                    static_cast<void>(ReleaseLookupReference(resolved));
                    throw;
                }
                if (attributed)
                    sampledHandles.push_back(handle);
                if (!ReleaseLookupReference(resolved))
                    return;

                if (attributedDetailedLogs >= settings.maxDetailedLogs)
                    Complete();
            }

            void RunOneTask()
            {
                if (finished.load(std::memory_order_acquire) ||
                    stopRequested.load(std::memory_order_acquire) ||
                    !taskWorkReady.load(std::memory_order_acquire)) {
                    return;
                }

                if (phase == Phase::kWaitForGameLoad ||
                    phase == Phase::kStockWaitForGameLoad) {
                    SetTaskWorkReady(false);
                    return;
                }

                LARGE_INTEGER startedAt{};
                QueryPerformanceCounter(&startedAt);
                std::uint32_t processed = 0;

                while (!finished.load(std::memory_order_acquire) &&
                       !stopRequested.load(std::memory_order_acquire) &&
                       taskWorkReady.load(std::memory_order_acquire)) {
                    switch (phase) {
                    case Phase::kSyntheticFill:
                        ProcessSynthetic();
                        break;
                    case Phase::kSyntheticSecondPass:
                        ProcessSyntheticSecondPass();
                        break;
                    case Phase::kRealReferences:
                        ProcessReal();
                        break;
                    case Phase::kSecondPass:
                        ProcessSecondPass();
                        break;
                    case Phase::kWaitForGameLoad:
                        return;
                    case Phase::kDiagnosticWait:
                        if (!gameLoadSeen.load(std::memory_order_acquire)) {
                            WaitForLoadedGame();
                            return;
                        }
                        {
                            const std::uint64_t due = diagnosticNextPassTick.load(
                                std::memory_order_acquire);
                            if (due == 0 || due > GetTickCount64()) {
                                SetTaskWorkReady(false);
                                return;
                            }
                            std::uint64_t expected = due;
                            if (!diagnosticNextPassTick.compare_exchange_strong(
                                    expected, 0, std::memory_order_acq_rel)) {
                                SetTaskWorkReady(false);
                                return;
                            }
                        }
                        BeginLiveTableSample();
                        break;
                    case Phase::kLiveTableSample:
                        ProcessLiveTableSample();
                        break;
                    case Phase::kDiagnosticSummary:
                        ProcessDiagnosticSummary();
                        break;
                    case Phase::kReleaseProbe:
                        ProcessReleaseProbe();
                        break;
                    case Phase::kReuseProbe:
                        ProcessReuseProbe();
                        break;
                    case Phase::kChurn:
                        ProcessChurn();
                        break;
                    case Phase::kChurnCleanup:
                        ProcessChurnCleanup();
                        break;
                    case Phase::kChurnVerifyCleanup:
                        ProcessChurnVerifyCleanup();
                        break;
                    case Phase::kStockOverflow:
                        ProcessStockOverflow();
                        break;
                    case Phase::kStockWaitForGameLoad:
                        return;
                    case Phase::kStockCleanup:
                        ProcessStockCleanup();
                        break;
                    case Phase::kStockVerifyCleanup:
                        ProcessStockVerifyCleanup();
                        break;
                    case Phase::kDone:
                    case Phase::kFailed:
                        finished.store(true, std::memory_order_release);
                        break;
                    }

                    ++processed;
                    if (TimeBudgetReached(processed, startedAt))
                        break;
                }

                FlushDetails();
            }

            [[nodiscard]] bool SnapshotFormArrays()
            {
                auto** singleton = reinterpret_cast<void**>(
                    imageBase + profile->dataHandlerSingletonRva);
                void* handler = *singleton;
                if (!handler) {
                    Log("stress: TESDataHandler singleton is null at kDataLoaded");
                    return false;
                }

                auto* arrays = reinterpret_cast<RawBSTArray*>(
                    static_cast<std::uint8_t*>(handler) + 0x10);

                std::size_t total = 0;
                for (const std::uint8_t formType : kReferenceFormTypes) {
                    const RawBSTArray& array = arrays[formType];
                    if (array.size > array.capacity || (array.size != 0 && !array.data)) {
                        Log("stress: invalid TESDataHandler form array %02X: data=%p "
                            "size=%u capacity=%u",
                            formType,
                            array.data,
                            array.size,
                            array.capacity);
                        return false;
                    }
                    if (total > (std::numeric_limits<std::size_t>::max)() - array.size) {
                        Log("stress: form-array size overflow");
                        return false;
                    }
                    total += array.size;
                    Log("stress: form array %02X contains %u entries", formType, array.size);
                }

                realReferences.reserve(total);
                for (const std::uint8_t formType : kReferenceFormTypes) {
                    const RawBSTArray& array = arrays[formType];
                    if (array.size != 0) {
                        realReferences.insert(
                            realReferences.end(), array.data, array.data + array.size);
                    }
                }
                if (total > (std::numeric_limits<std::size_t>::max)() -
                                settings.syntheticFillToIndex) {
                    Log("stress: held-handle reserve size overflow");
                    return false;
                }
                heldHandles.reserve(
                    total + static_cast<std::size_t>(settings.syntheticFillToIndex));
                Log("stress: snapshotted %zu reference-form pointers (%zu bytes)",
                    realReferences.size(),
                    realReferences.size() * sizeof(void*));
                return true;
            }

            [[nodiscard]] bool AllocateSyntheticRegion()
            {
                if (IsLiveDiagnostics() || settings.syntheticFillToIndex == 0) {
                    if (gameLoadSeen.load(std::memory_order_acquire)) {
                        if (IsLiveDiagnostics())
                            ScheduleDiagnosticPass();
                        else
                            BeginLiveTableSample();
                    } else {
                        WaitForLoadedGame();
                    }
                    return true;
                }

                syntheticCapacity = settings.syntheticFillToIndex;
                if (settings.churnCycles != 0) {
                    const std::size_t extra =
                        static_cast<std::size_t>(settings.churnCycles) + 1;
                    if (syntheticCapacity >
                        (std::numeric_limits<std::size_t>::max)() - extra) {
                        Log("stress: synthetic churn capacity overflow");
                        return false;
                    }
                    syntheticCapacity += extra;
                }
                if (settings.reuseProbeCycles != 0) {
                    const std::size_t extra = settings.reuseProbeCycles;
                    if (syntheticCapacity >
                        (std::numeric_limits<std::size_t>::max)() - extra) {
                        Log("stress: synthetic FIFO reuse capacity overflow");
                        return false;
                    }
                    syntheticCapacity += extra;
                }
                if (IsStockControl()) {
                    const std::size_t extra = settings.stockOverflowAttempts;
                    if (syntheticCapacity >
                        (std::numeric_limits<std::size_t>::max)() - extra) {
                        Log("stock-control: synthetic overflow capacity overflow");
                        return false;
                    }
                    syntheticCapacity += extra;
                }
                if (syntheticCapacity >
                    (std::numeric_limits<std::size_t>::max)() / sizeof(SyntheticReference)) {
                    Log("stress: synthetic allocation size overflow");
                    return false;
                }
                const std::size_t bytes = syntheticCapacity * sizeof(SyntheticReference);
                syntheticReferences = static_cast<SyntheticReference*>(VirtualAlloc(
                    nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
                if (!syntheticReferences) {
                    Log("stress: VirtualAlloc failed for %zu synthetic objects (%zu bytes), "
                        "error=%lu",
                        syntheticCapacity,
                        bytes,
                        GetLastError());
                    return false;
                }
                heldHandles.reserve(syntheticCapacity);
                phase = Phase::kSyntheticFill;
                Log("stress: reserved %zu bytes for up to %zu synthetic filler objects",
                    bytes,
                    syntheticCapacity);
                return true;
            }
        };

        class BatchTask final : public TaskDelegate
        {
        public:
            explicit BatchTask(State* a_state) noexcept : state(a_state) {}

            void Run() override
            {
                try {
                    state->RunOneTask();
                } catch (...) {
                    state->Fail("unhandled C++ exception in a main-thread batch");
                }
                SetEvent(state->taskDoneEvent);
            }

            void Dispose() override
            {
                delete this;
            }

        private:
            State* state;
        };

        DWORD WINAPI CoordinatorThread(void* a_context)
        {
            auto* state = static_cast<State*>(a_context);
            while (!state->finished.load(std::memory_order_acquire) &&
                   !state->stopRequested.load(std::memory_order_acquire)) {
                if (!state->taskWorkReady.load(std::memory_order_acquire)) {
                    DWORD timeout = INFINITE;
                    const std::uint64_t due = state->diagnosticNextPassTick.load(
                        std::memory_order_acquire);
                    if (due != 0) {
                        const std::uint64_t now = GetTickCount64();
                        if (due <= now) {
                            state->SetTaskWorkReady(true);
                            continue;
                        }
                        timeout = static_cast<DWORD>((std::min)(
                            due - now,
                            static_cast<std::uint64_t>(MAXDWORD - 1)));
                    }

                    HANDLE idleWaits[] = {
                        state->stopEvent, state->coordinatorWakeEvent
                    };
                    const DWORD idleResult = WaitForMultipleObjects(
                        2, idleWaits, FALSE, timeout);
                    if (idleResult == WAIT_OBJECT_0) {
                        state->stopRequested.store(true, std::memory_order_release);
                        break;
                    }
                    if (idleResult == WAIT_OBJECT_0 + 1 ||
                        idleResult == WAIT_TIMEOUT) {
                        continue;
                    }
                    state->Fail("coordinator idle wait failed");
                    break;
                }

                BatchTask* task = new (std::nothrow) BatchTask(state);
                if (!task) {
                    state->Fail("could not allocate an SKSE TaskDelegate");
                    break;
                }
                state->tasks->AddTask(task);

                HANDLE waits[] = { state->stopEvent, state->taskDoneEvent };
                const DWORD waitResult = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
                if (waitResult == WAIT_OBJECT_0) {
                    state->stopRequested.store(true, std::memory_order_release);
                    break;
                }
                if (waitResult != WAIT_OBJECT_0 + 1) {
                    state->Fail("coordinator wait for main-thread task failed");
                    break;
                }
                if (state->finished.load(std::memory_order_acquire))
                    break;

                if (!state->taskWorkReady.load(std::memory_order_acquire))
                    continue;

                // SKSE's ProcessTasks loops until its queue is empty, including
                // tasks enqueued from a running task.  Waiting on this separate
                // producer thread prevents successor tasks from chaining inside
                // one queue-drain and monopolizing the main thread.
                HANDLE delayWaits[] = {
                    state->stopEvent, state->coordinatorWakeEvent
                };
                const DWORD delayResult = WaitForMultipleObjects(
                    2, delayWaits, FALSE, state->ActiveDelayMilliseconds());
                if (delayResult == WAIT_OBJECT_0) {
                    state->stopRequested.store(true, std::memory_order_release);
                    break;
                }
                if (delayResult != WAIT_OBJECT_0 + 1 &&
                    delayResult != WAIT_TIMEOUT) {
                    state->Fail("coordinator delay wait failed");
                    break;
                }
            }
            return 0;
        }

        void StartAtDataLoaded(State* a_state)
        {
            if (a_state->started.exchange(true, std::memory_order_acq_rel))
                return;

            if (a_state->IsLifecycleVerification()) {
                // SKSE AE can emit startup save/load notifications before
                // kDataLoaded.  They are not part of the requested one-process
                // lifecycle run, so establish the counter/attempt epoch here.
                a_state->lifecycleDataLoadedSeen = true;
                a_state->lifecycleDataLoadedCount = 0;
                a_state->lifecyclePreLoadCount = 0;
                a_state->lifecyclePostLoadCount = 0;
                a_state->lifecycleNewGameCount = 0;
                a_state->lifecycleLoadAttemptCount = 0;
                a_state->lifecyclePendingLoadAttempt = 0;
                ++a_state->lifecycleDataLoadedCount;
                if (!a_state->VerifyLifecycleCheckpoint(
                        "kDataLoaded",
                        a_state->lifecycleDataLoadedCount,
                        false)) {
                    return;
                }
            }

            if (a_state->IsLiveDiagnostics()) {
                a_state->Log("diagnostics: received SKSE kDataLoaded; arming read-only "
                    "post-load high-handle scan");
            } else {
                a_state->Log("stress: received SKSE kDataLoaded; preparing the vanilla-cap boundary");
            }
            if (a_state->callbacks.preflight &&
                !a_state->callbacks.preflight(a_state->callbacks.context)) {
                a_state->Fail("kDataLoaded preflight rejected the live runtime");
                return;
            }
            if (!a_state->AllocateSyntheticRegion()) {
                a_state->Fail("could not prepare the synthetic vanilla-cap boundary");
                return;
            }

            QueryPerformanceFrequency(&a_state->qpcFrequency);
            if (a_state->qpcFrequency.QuadPart <= 0) {
                a_state->Fail("QueryPerformanceFrequency failed");
                return;
            }

            a_state->stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            a_state->taskDoneEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            a_state->coordinatorWakeEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            if (!a_state->stopEvent || !a_state->taskDoneEvent ||
                !a_state->coordinatorWakeEvent) {
                a_state->Fail("could not create coordinator events");
                return;
            }

            HANDLE thread = CreateThread(
                nullptr, 0, &CoordinatorThread, a_state, 0, nullptr);
            if (!thread) {
                a_state->Fail("could not create the bounded-task coordinator thread");
                return;
            }
            CloseHandle(thread);
        }

        void OnSKSEMessage(SKSEMessage* a_message)
        {
            State* state = g_state.load(std::memory_order_acquire);
            if (!state || !a_message)
                return;
            bool pairedLifecyclePostLoad = false;

            if (a_message->type == kDataLoaded) {
                try {
                    StartAtDataLoaded(state);
                } catch (...) {
                    state->Fail("unhandled C++ exception while preparing kDataLoaded stress run");
                }
                return;
            }

            if (state->IsLifecycleVerification() &&
                !state->lifecycleDataLoadedSeen &&
                (a_message->type == kPreLoadGame ||
                 a_message->type == kPostLoadGame ||
                 a_message->type == kNewGame)) {
                const char* event = a_message->type == kPreLoadGame ?
                    "kPreLoadGame" : a_message->type == kPostLoadGame ?
                    "kPostLoadGame" : "kNewGame";
                state->Log("lifecycle: startup message IGNORED event=%s "
                    "reason=before-kDataLoaded",
                    event);
                return;
            }

            if (a_message->type == kPreLoadGame && state->IsLiveDiagnostics()) {
                if (state->IsLifecycleVerification()) {
                    ++state->lifecyclePreLoadCount;
                    ++state->lifecycleLoadAttemptCount;
                    state->lifecyclePendingLoadAttempt =
                        state->lifecycleLoadAttemptCount;
                    if (!state->VerifyLifecycleCheckpoint(
                            "kPreLoadGame",
                            state->lifecyclePreLoadCount,
                            false,
                            state->lifecyclePendingLoadAttempt)) {
                        return;
                    }
                }
                state->gameLoadSeen.store(false, std::memory_order_release);
                if (state->started.load(std::memory_order_acquire) &&
                    !state->finished.load(std::memory_order_acquire)) {
                    state->Log("diagnostics: received SKSE kPreLoadGame; pausing recurring "
                        "reports until the load succeeds");
                    state->WaitForLoadedGame();
                }
                return;
            }

            if (a_message->type == kPostLoadGame) {
                const std::uintptr_t rawResult =
                    reinterpret_cast<std::uintptr_t>(a_message->data);
                const bool resultIsValid =
                    a_message->dataLen == sizeof(bool) && rawResult <= 1;
                const bool loadSucceeded = resultIsValid && rawResult == 1;
                if (!loadSucceeded) {
                    if (state->IsLifecycleVerification()) {
                        const std::uint32_t attempt =
                            state->lifecyclePendingLoadAttempt;
                        if (attempt != 0) {
                            state->Log("lifecycle: load attempt END loadAttempt=%u "
                                "result=%s",
                                attempt,
                                resultIsValid ? "failure" : "invalid-data");
                        } else {
                            state->Log("lifecycle: kPostLoadGame IGNORED "
                                "reason=no-paired-kPreLoadGame result=%s",
                                resultIsValid ? "failure" : "invalid-data");
                        }
                        state->lifecyclePendingLoadAttempt = 0;
                    }
                    state->Log("%s: received unsuccessful SKSE "
                        "kPostLoadGame; recurring reports remain paused%s",
                        state->IsLiveDiagnostics() ? "diagnostics" :
                            (state->IsStockControl() ? "stock-control" : "stress"),
                        resultIsValid ? "" :
                            " (invalid result payload was ignored)");
                    return;
                }

                if (state->IsLifecycleVerification()) {
                    pairedLifecyclePostLoad =
                        state->lifecyclePendingLoadAttempt != 0;
                    if (pairedLifecyclePostLoad) {
                        state->Log("lifecycle: load attempt END loadAttempt=%u "
                            "result=success",
                            state->lifecyclePendingLoadAttempt);
                    } else {
                        state->Log("lifecycle: kPostLoadGame IGNORED "
                            "reason=no-paired-kPreLoadGame result=success");
                    }
                }
            }

            if (a_message->type == kPostLoadGame || a_message->type == kNewGame) {
                state->gameLoadSeen.store(true, std::memory_order_release);
                if (state->IsStockControl()) {
                    state->Log("stock-control: received SKSE %s%s",
                        a_message->type == kPostLoadGame ? "kPostLoadGame" : "kNewGame",
                        state->phase == Phase::kStockWaitForGameLoad ?
                            "; held-full reproduction boundary reached" :
                            "; stock exhaustion is not yet waiting at the reproduction boundary");
                    if (state->started.load(std::memory_order_acquire) &&
                        state->phase == Phase::kStockWaitForGameLoad) {
                        state->stockHeldThroughGameLoad = true;
                        state->BeginStockCleanup(true, nullptr);
                    }
                    return;
                }
                if (state->IsLiveDiagnostics()) {
                    if (state->finished.load(std::memory_order_acquire))
                        return;
                    if (state->IsLifecycleVerification()) {
                        const bool postLoad =
                            a_message->type == kPostLoadGame;
                        if (postLoad && !pairedLifecyclePostLoad) {
                            state->Log("lifecycle: successful unpaired "
                                "kPostLoadGame is not lifecycle evidence");
                        } else {
                            std::uint32_t& ordinal = postLoad ?
                                state->lifecyclePostLoadCount :
                                state->lifecycleNewGameCount;
                            ++ordinal;
                            const std::uint32_t loadAttempt = postLoad ?
                                state->lifecyclePendingLoadAttempt : 0;
                            if (!state->VerifyLifecycleCheckpoint(
                                    postLoad ? "kPostLoadGame" : "kNewGame",
                                    ordinal,
                                    true,
                                    loadAttempt)) {
                                return;
                            }
                            if (postLoad)
                                state->lifecyclePendingLoadAttempt = 0;
                        }
                    }
                    state->Log("diagnostics: received SKSE %s; first recurring "
                        "high-handle report is scheduled in one minute",
                        a_message->type == kPostLoadGame ? "kPostLoadGame" : "kNewGame");
                    if (state->started.load(std::memory_order_acquire))
                        state->ScheduleDiagnosticPass();
                    return;
                } else {
                    state->Log("stress: received SKSE %s; real-reference sampling will start "
                        "as soon as the vanilla-cap filler is complete",
                        a_message->type == kPostLoadGame ? "kPostLoadGame" : "kNewGame");
                }
                if (state->started.load(std::memory_order_acquire) &&
                    state->phase == Phase::kWaitForGameLoad) {
                    try {
                        state->BeginLiveTableSample();
                        state->WakeCoordinator();
                    } catch (...) {
                        state->Fail("unhandled C++ exception while starting live sampling");
                    }
                }
            }
        }

        [[nodiscard]] const RuntimeProfile* FindProfile(std::uint32_t a_runtime) noexcept
        {
            for (const RuntimeProfile& profile : kProfiles) {
                if (profile.runtimeVersion == a_runtime)
                    return &profile;
            }
            return nullptr;
        }
    }

    bool Initialize(
        const void* a_skseLoadInterface,
        const Settings& a_settings,
        const Callbacks& a_callbacks) noexcept
    {
        if (!a_settings.enabled && !a_settings.liveDiagnosticsEnabled)
            return true;
        if (!a_skseLoadInterface)
            return false;
        if (g_state.load(std::memory_order_acquire))
            return false;

        try {
            // Production diagnostics deliberately cannot share a run with any
            // synthetic stress mode. This also makes dormant [StressTest]
            // values irrelevant to the safe path.
            if (a_settings.enabled && a_settings.liveDiagnosticsEnabled)
                return false;

            const bool diagnostics = a_settings.liveDiagnosticsEnabled;
            if (diagnostics &&
                (a_settings.indexBits != generation::kIndexBits ||
                 a_settings.diagnosticsDetailedSampleLimit >
                     kMaxDiagnosticDetailedSamples ||
                 !a_callbacks.resolveAttribution ||
                 (a_settings.diagnosticsDetailedSampleLimit != 0 &&
                     !a_callbacks.resolveNames))) {
                return false;
            }
            if (!diagnostics &&
                ((a_settings.indexBits != 20 &&
                  a_settings.indexBits != generation::kIndexBits) ||
                 a_settings.maxReferencesPerTask == 0 ||
                 a_settings.maxTaskMicroseconds == 0 ||
                 a_settings.coordinatorDelayMilliseconds == 0)) {
                return false;
            }

            const std::uint32_t entryCount = 1u << a_settings.indexBits;
            if (!a_callbacks.handleTable ||
                a_callbacks.handleEntryCount != entryCount) {
                return false;
            }
            if (!diagnostics &&
                (a_settings.syntheticFillToIndex > entryCount ||
                 a_settings.detailedLogFromIndex > entryCount)) {
                return false;
            }
            if (!diagnostics && a_settings.stockOverflowAttempts != 0 &&
                (a_settings.indexBits != 20 ||
                 a_settings.syntheticFillToIndex != entryCount ||
                 a_settings.releaseProbeCount != 0 ||
                 a_settings.reuseProbeCycles != 0 ||
                 a_settings.churnCycles != 0 ||
                 a_settings.stockOverflowAttempts > entryCount ||
                 !a_settings.stopOnVerificationFailure)) {
                return false;
            }
            if (!diagnostics && a_settings.stockHoldThroughGameLoad &&
                a_settings.stockOverflowAttempts == 0) {
                return false;
            }
            if (!diagnostics && a_settings.churnCycles != 0 &&
                (a_settings.indexBits != generation::kIndexBits ||
                 a_settings.syntheticFillToIndex != entryCount ||
                 a_settings.releaseProbeCount != 0 ||
                 a_settings.reuseProbeCycles != 0 ||
                  a_settings.churnCycles > generation::kSafeReuseLimit ||
                 !a_settings.stopOnVerificationFailure)) {
                return false;
            }
            if (!diagnostics && a_settings.releaseProbeCount != 0 &&
                (a_settings.indexBits != generation::kIndexBits ||
                 a_settings.syntheticFillToIndex <=
                     kFirstOrdinaryRaisedIndex ||
                 a_settings.releaseProbeCount >
                     a_settings.syntheticFillToIndex -
                         kFirstOrdinaryRaisedIndex ||
                 a_settings.churnCycles != 0 ||
                 a_settings.stockOverflowAttempts != 0 ||
                 !a_settings.stopOnVerificationFailure)) {
                return false;
            }
            if (!diagnostics && a_settings.reuseProbeCycles != 0 &&
                (a_settings.indexBits != generation::kIndexBits ||
                 (a_settings.reuseProbeCycles != 1 &&
                  a_settings.reuseProbeCycles != generation::kGenerationCount) ||
                 a_settings.releaseProbeCount == 0 ||
                 a_settings.syntheticFillToIndex <=
                     kFirstOrdinaryRaisedIndex ||
                 a_settings.syntheticFillToIndex >= entryCount ||
                 a_settings.churnCycles != 0 ||
                 a_settings.stockOverflowAttempts != 0 ||
                 !a_settings.stopOnVerificationFailure)) {
                return false;
            }

            const auto* skse = static_cast<const SKSEInterface*>(a_skseLoadInterface);
            if (!skse->QueryInterface || !skse->GetPluginHandle)
                return false;
            const RuntimeProfile* profile = FindProfile(skse->runtimeVersion);
            if (!profile)
                return false;

            const auto* tasks = static_cast<const SKSETaskInterface*>(
                skse->QueryInterface(kTaskInterface));
            const auto* messaging = static_cast<const SKSEMessagingInterface*>(
                skse->QueryInterface(kMessagingInterface));
            if (!tasks || !tasks->AddTask || !messaging || !messaging->RegisterListener)
                return false;

            State* state = new (std::nothrow) State;
            if (!state)
                return false;
            state->settings = a_settings;
            state->callbacks = a_callbacks;
            state->profile = profile;
            state->tasks = tasks;
            state->handleTable = static_cast<const HandleEntry*>(
                a_callbacks.handleTable);
            state->handleEntryCount = a_callbacks.handleEntryCount;
            state->imageBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
            if (!state->imageBase) {
                delete state;
                return false;
            }
            state->createRefHandle = reinterpret_cast<CreateRefHandleFn>(
                state->imageBase + profile->createRefHandleRva);
            state->getHandle = reinterpret_cast<GetHandleFn>(
                state->imageBase + profile->getHandleRva);
            state->getSmartPointer = reinterpret_cast<GetSmartPointerFn>(
                state->imageBase + profile->getSmartPointerRva);
            state->releaseHandle = reinterpret_cast<ReleaseHandleFn>(
                state->imageBase + profile->releaseHandleRva);
            state->freeHead = reinterpret_cast<const volatile std::uint32_t*>(
                state->imageBase + profile->freeHeadRva);
            state->freeTail = reinterpret_cast<const volatile std::uint32_t*>(
                state->imageBase + profile->freeTailRva);
            state->managerLock = reinterpret_cast<void*>(
                state->imageBase + profile->managerLockRva);
            state->lockManager = reinterpret_cast<ManagerLockFn>(
                state->imageBase + profile->lockManagerRva);
            state->unlockManager = reinterpret_cast<ManagerLockFn>(
                state->imageBase + profile->unlockManagerRva);

            g_state.store(state, std::memory_order_release);
            const bool registered = messaging->RegisterListener(
                skse->GetPluginHandle(),
                "SKSE",
                reinterpret_cast<void*>(&OnSKSEMessage));
            if (!registered) {
                g_state.store(nullptr, std::memory_order_release);
                delete state;
                return false;
            }

            if (diagnostics) {
                state->Log("diagnostics: armed for %s: table=%p entries=%u "
                    "GetSmartPointer=%p boundary=%06X detailedSampleLimit=%u "
                    "cadence=60 s taskBounds=%u refs/%u us batchDelay=%u ms",
                    profile->name,
                    state->handleTable,
                    state->handleEntryCount,
                    reinterpret_cast<void*>(state->getSmartPointer),
                    kStockCrossingIndex,
                    a_settings.diagnosticsDetailedSampleLimit,
                    kDiagnosticReferencesPerTask,
                    kDiagnosticTaskMicroseconds,
                    kDiagnosticDelayMilliseconds);
            } else {
                state->Log("stress: armed for %s: table=%p entries=%u singleton=%p CreateRefHandle=%p "
                    "GetHandle=%p GetSmartPointer=%p ReleaseHandle=%p indexBits=%u fillTo=%06X "
                    "detailFrom=%06X releaseProbeCount=%u reuseProbeCycles=%u churnCycles=%u "
                    "stockOverflowAttempts=%u stockHold=%u",
                    profile->name,
                    state->handleTable,
                    state->handleEntryCount,
                    reinterpret_cast<void*>(
                        state->imageBase + profile->dataHandlerSingletonRva),
                    reinterpret_cast<void*>(state->createRefHandle),
                    reinterpret_cast<void*>(state->getHandle),
                    reinterpret_cast<void*>(state->getSmartPointer),
                    reinterpret_cast<void*>(state->releaseHandle),
                    a_settings.indexBits,
                    a_settings.syntheticFillToIndex,
                    a_settings.detailedLogFromIndex,
                    a_settings.releaseProbeCount,
                    a_settings.reuseProbeCycles,
                    a_settings.churnCycles,
                    a_settings.stockOverflowAttempts,
                    a_settings.stockHoldThroughGameLoad ? 1u : 0u);
            }
            return true;
        } catch (...) {
            return false;
        }
    }

    void Shutdown() noexcept
    {
        State* state = g_state.load(std::memory_order_acquire);
        if (!state)
            return;
        state->stopRequested.store(true, std::memory_order_release);
        if (state->stopEvent)
            SetEvent(state->stopEvent);
    }

    bool IsRunning() noexcept
    {
        const State* state = g_state.load(std::memory_order_acquire);
        return state && state->started.load(std::memory_order_acquire) &&
               !state->finished.load(std::memory_order_acquire);
    }
}
