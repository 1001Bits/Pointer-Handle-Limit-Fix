// Starfield Handle Cap Raise — experimental SFSE plugin.
//
// Swaps the engine's fixed 2^21 static reference-handle pool for a larger heap pool and
// rewrites the handle manager's six control fields, raising the cap without touching the save
// format (handles are runtime-only; saves store FormIDs) and without costing refcount bits
// (the TESForm+8 word holds no handle index — see README.md / HANDOVER.md).
//
// TIMING (the load-bearing detail): the manager is constructed in the startup init at
// ~1s, but the first handle is not allocated until content loads (~38s in testing). That
// ~37s gap is a single-threaded quiet window in which the manager is fully built yet
// untouched — no CreateHandle/LookupByHandle/Release on any thread. We swap the pool THERE,
// not at first-use (where the render thread concurrently resolves handles and a non-atomic
// swap causes torn reads → wrong-object crashes). A watcher thread waits for the manager's
// singleton pointer to be published (construction complete), verifies the pool is pristine,
// and swaps immediately.
//
// Release target: Starfield.exe 1.16.244. Built against CommonLibSF (libxse fork).

#include "SFSE/SFSE.h"
#include "REX/REX.h"
#include "REL/Utility.h"
#include "RE/T/TESFile.h"
#include "RE/T/TESForm.h"
#include "RE/T/TESObjectREFR.h"

#include <spdlog/spdlog.h>
#include <fmt/format.h>

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace logger = spdlog;
using namespace std::literals;

namespace
{
    // The manager is a static object; its singleton pointer is the LAST thing the constructor
    // writes, so a non-null value there means the whole manager (pool, threaded free list, all
    // six fields) is fully built. Resolved by Address Library ID 883285 (1.16.244 RVA
    // 0x5e60380). The stock-shape guard below refuses to write if the expected manager layout
    // is not present.
    constexpr std::uint64_t kID_SingletonPtr = 883285;

    // Engine wrapper that resolves a native handle into an owning NiPointer<TESObjectREFR>.
    // Address Library ID 36239 (1.16.244 RVA 0x2cec10). Unlike reading qword0 from the pool,
    // this takes the handle manager's read lock and increments the form refcount before returning,
    // so calling virtual name/source methods cannot race the reference's destruction.
    constexpr std::uint64_t kID_LookupReferenceByHandle = 36239;

    // ---- Verified manager struct field offsets --------------------------------------------
    constexpr std::size_t kOff_PoolPtr     = 0x50;  // T* pool
    constexpr std::size_t kOff_FreeHead    = 0x58;  // free-list head   (stock init 1)
    constexpr std::size_t kOff_FreeTail    = 0x5c;  // free-list tail   (stock init 0x1fffff)
    constexpr std::size_t kOff_FreeCounter = 0x60;  // free counter     (stock init 0x200000)
    constexpr std::size_t kOff_Capacity    = 0x64;  // capacity == generation unit (0x200000)
    constexpr std::size_t kOff_IndexMask   = 0x68;  // index mask       (stock init 0x1fffff)

    constexpr std::uint32_t kStockBits      = 21;
    constexpr std::uint32_t kStockCap       = 1u << kStockBits;   // 0x200000
    constexpr std::uint32_t kStockFreeCount = kStockCap;          // pristine free-counter value
    constexpr std::size_t   kPoolEntrySize  = 16;                 // qword0=object, qword1=next/gen

    constexpr std::uint32_t kTargetBits = 22;  // fixed 2x cap (4.19M, 1024 generations)
    constexpr std::uint32_t kGenerationCount = 1u << (32 - kTargetBits);
    constexpr DWORD kReportTickMilliseconds = 60'000;
    constexpr std::uint64_t kNormalReportMinutes = 5;

    // Starfield 1.16.244: the handle manager's primary vtable and its slot-2 callback. CreateHandle
    // invokes this callback while holding the manager's exclusive lock after assigning a new
    // handle. Hooking the already-existing callback avoids a CreateHandle trampoline and lets the
    // detector do one sidecar load/store per successful assignment.
    constexpr std::uint64_t kID_HandleManagerVtable = 450711;  // 1.16.244 RVA 0x4CB2E98
    constexpr std::uint64_t kID_AssignNativeHandle  = 99517;   // 1.16.244 RVA 0x189F8D0
    constexpr std::size_t kAssignNativeHandleSlot = 2;
    static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

    std::uint8_t* g_newPool = nullptr;         // pre-built before the swap window
    std::uint64_t g_newCap = 0;
    bool g_verboseLogging = false;
    std::size_t g_detailedSampleCount = 16;
    bool g_generationWrapDetection = true;

    // One 16-bit assignment count per slot: 4,194,304 slots = 8 MiB. This measures up to 65,534
    // reuses of one slot (63 complete wraps) before saturating. The callback runs under the engine's
    // exclusive manager lock, so the sidecar itself needs no locked operation. Only new high-water
    // marks and actual wraps touch atomics read by the monitor thread.
    std::uint16_t* g_slotAssignments = nullptr;
    std::atomic<bool> g_generationDetectorActive{ false };
    std::atomic<std::uintptr_t> g_trackedManager{ 0 };
    std::atomic<std::uint64_t> g_hottestHandle{ 0 };  // high dword=reuses, low dword=handle
    std::atomic<std::uint64_t> g_generationWraps{ 0 };
    std::atomic<std::uint64_t> g_lastWrapEvent{ 0 };  // high dword=reuses, low dword=new handle
    std::atomic<std::uint32_t> g_wrapEventSequence{ 0 };
    std::atomic<std::uint32_t> g_saturatedSlot{ 0 };  // slot+1, zero means none

    using AssignNativeHandle_t = void (*)(std::uintptr_t, void*, std::uint32_t);
    std::atomic<AssignNativeHandle_t> g_originalAssignNativeHandle{ nullptr };
    static_assert(std::atomic<AssignNativeHandle_t>::is_always_lock_free);

    template <class T>
    T* At(std::uintptr_t addr) { return reinterpret_cast<T*>(addr); }

    void LoadConfig()
    {
        wchar_t exePath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::wstring ini(exePath);
        const auto slash = ini.find_last_of(L"\\/");
        if (slash != std::wstring::npos) ini.resize(slash + 1);
        ini += L"Data\\SFSE\\Plugins\\StarfieldHandleCapRaise.ini";
        g_verboseLogging =
            ::GetPrivateProfileIntW(L"General", L"VerboseLogging", 0, ini.c_str()) != 0;
        g_generationWrapDetection =
            ::GetPrivateProfileIntW(L"General", L"GenerationWrapDetection", 1, ini.c_str()) != 0;
        int sampleSize = ::GetPrivateProfileIntW(L"General", L"SampleSize", 16, ini.c_str());
        if (sampleSize < 0) sampleSize = 0;
        if (sampleSize > 64) sampleSize = 64;
        g_detailedSampleCount = static_cast<std::size_t>(sampleSize);
    }

    // Build the replacement pool (VirtualAlloc + threaded free list) up front, so the actual
    // manager swap is just six field writes. Runs before the swap window; never freed.
    bool PreparePool()
    {
        g_newCap = 1ull << kTargetBits;
        const std::size_t poolSz = static_cast<std::size_t>(g_newCap) * kPoolEntrySize;
        g_newPool = static_cast<std::uint8_t*>(
            ::VirtualAlloc(nullptr, poolSz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (g_newPool == nullptr) {
            logger::error("VirtualAlloc({} bytes) failed; no resize", poolSz);
            return false;
        }

        // Thread the free list: index 0 = reserved null handle; slots 1..newCap-1 form the list.
        // qword1 (entry+8) low bits = next-free index, generation high bits 0; tail = 0.
        // (Verified against the engine's own construction: MOV [pool + i*16 + 8], i+1.)
        for (std::uint64_t i = 1; i < g_newCap; ++i) {
            *reinterpret_cast<std::uint64_t*>(g_newPool + i * kPoolEntrySize + 8) =
                (i + 1 < g_newCap) ? (i + 1) : 0ull;
        }
        return true;
    }

    void RecordHandleGeneration(std::uint32_t handle) noexcept
    {
        if (handle == 0 || g_slotAssignments == nullptr) return;

        const std::uint32_t index = handle & static_cast<std::uint32_t>(g_newCap - 1);
        const std::uint16_t generation = static_cast<std::uint16_t>(handle >> kTargetBits);
        const std::uint16_t assignments = g_slotAssignments[index];
        if (assignments == 0xffffu) {
            std::uint32_t unset = 0;
            g_saturatedSlot.compare_exchange_strong(
                unset, index + 1, std::memory_order_release, std::memory_order_relaxed);
            return;
        }
        g_slotAssignments[index] = static_cast<std::uint16_t>(assignments + 1);

        // Before this assignment, `assignments` is exactly the number of times the slot has been
        // reused. A non-zero multiple of the generation count is the 1023 -> 0 transition.
        const std::uint32_t reuses = assignments;
        if (reuses != 0 && (reuses % kGenerationCount) == 0) {
            // A tiny seqlock lets the monitor snapshot the total and newest event coherently.
            g_wrapEventSequence.fetch_add(1, std::memory_order_acq_rel);  // odd: writer active
            g_lastWrapEvent.store((static_cast<std::uint64_t>(reuses) << 32) | handle,
                                  std::memory_order_relaxed);
            g_generationWraps.fetch_add(1, std::memory_order_relaxed);
            g_wrapEventSequence.fetch_add(1, std::memory_order_release);  // even: published
        }

        // The observed generation must agree with the tracked reuse count. A mismatch cannot be
        // repaired in-band, so treat it as a detector saturation/failure and surface the slot.
        if (generation != static_cast<std::uint16_t>(reuses % kGenerationCount)) {
            std::uint32_t unset = 0;
            g_saturatedSlot.compare_exchange_strong(
                unset, index + 1, std::memory_order_release, std::memory_order_relaxed);
        }

        // Keep the handle and exact reuse count in one atomic so reports cannot mix slots.
        if (reuses != 0) {
            const std::uint64_t candidate =
                (static_cast<std::uint64_t>(reuses) << 32) | handle;
            std::uint64_t hottest = g_hottestHandle.load(std::memory_order_relaxed);
            while (reuses > static_cast<std::uint32_t>(hottest >> 32) &&
                   !g_hottestHandle.compare_exchange_weak(
                       hottest, candidate, std::memory_order_release, std::memory_order_relaxed)) {
            }
        }
    }

    void AssignNativeHandleHook(std::uintptr_t manager, void* object,
                                std::uint32_t handle) noexcept
    {
        const auto original = g_originalAssignNativeHandle.load(std::memory_order_acquire);
        if (original == nullptr) return;
        original(manager, object, handle);
        if (object != nullptr && manager == g_trackedManager.load(std::memory_order_acquire)) {
            RecordHandleGeneration(handle);
        }
    }

    bool PrepareGenerationDetector()
    {
        if (!g_generationWrapDetection) return true;

        const std::size_t bytes = static_cast<std::size_t>(g_newCap) * sizeof(std::uint16_t);
        g_slotAssignments = static_cast<std::uint16_t*>(
            ::VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (g_slotAssignments == nullptr) {
            logger::error("generation-wrap detector VirtualAlloc({} bytes) failed; detector disabled",
                          bytes);
            g_generationWrapDetection = false;
            return false;
        }
        return true;
    }

    void ReleaseGenerationDetector()
    {
        g_trackedManager.store(0, std::memory_order_release);
        g_generationDetectorActive.store(false, std::memory_order_release);
        if (g_slotAssignments != nullptr) {
            ::VirtualFree(g_slotAssignments, 0, MEM_RELEASE);
            g_slotAssignments = nullptr;
        }
    }

    bool InstallGenerationDetector(std::uintptr_t manager)
    {
        if (!g_generationWrapDetection || g_slotAssignments == nullptr) return false;

        const std::uintptr_t vtable = *At<const std::uintptr_t>(manager);
        const std::uintptr_t expectedVtable = REL::ID(kID_HandleManagerVtable).address();
        const std::uintptr_t expectedCallback = REL::ID(kID_AssignNativeHandle).address();
        if (vtable != expectedVtable) {
            logger::error("generation-wrap detector found unexpected manager vtable ({:#x}, "
                          "expected {:#x}); detector disabled",
                          vtable, expectedVtable);
            return false;
        }

        const std::uintptr_t slot = vtable + kAssignNativeHandleSlot * sizeof(std::uintptr_t);
        const std::uintptr_t original = *At<const std::uintptr_t>(slot);
        if (original != expectedCallback) {
            logger::error("generation-wrap detector found unexpected slot-2 callback ({:#x}, "
                          "expected {:#x}); detector disabled",
                          original, expectedCallback);
            return false;
        }

        g_originalAssignNativeHandle.store(
            reinterpret_cast<AssignNativeHandle_t>(original), std::memory_order_release);
        g_trackedManager.store(manager, std::memory_order_release);
        const std::uintptr_t hook = reinterpret_cast<std::uintptr_t>(&AssignNativeHandleHook);
        const bool protectionRestored = REL::WriteSafeData(slot, hook);
        if (*At<const std::uintptr_t>(slot) != hook) {
            g_trackedManager.store(0, std::memory_order_release);
            g_originalAssignNativeHandle.store(nullptr, std::memory_order_release);
            logger::error("generation-wrap detector could not install its callback; detector disabled");
            return false;
        }
        if (!protectionRestored) {
            logger::warn("generation-wrap detector installed, but restoring vtable page protection "
                         "reported a failure");
        }
        g_generationDetectorActive.store(true, std::memory_order_release);
        return true;
    }

    enum class Commit { Wait, Done, Refused };

    // Commit the swap onto a pristine, fully-built manager, verifying its own work at every
    // step. `manager` is the just-published manager object.
    //   * Wait    - not yet the stock-shaped manager; keep polling.
    //   * Refused - a safe no-op: the manager isn't the exact stock shape we verified against
    //               (so the struct layout may differ on this build), or a write didn't take.
    //               Nothing is changed / everything is reverted.
    //   * Done    - swap applied AND read back correct.
    Commit TryCommit(std::uintptr_t manager)
    {
        // volatile: these alias live engine memory that other threads may touch.
        auto* const pPool = At<volatile std::uint64_t>(manager + kOff_PoolPtr);
        auto* const pHead = At<volatile std::uint32_t>(manager + kOff_FreeHead);
        auto* const pTail = At<volatile std::uint32_t>(manager + kOff_FreeTail);
        auto* const pCtr  = At<volatile std::uint32_t>(manager + kOff_FreeCounter);
        auto* const pCap  = At<volatile std::uint32_t>(manager + kOff_Capacity);
        auto* const pMask = At<volatile std::uint32_t>(manager + kOff_IndexMask);

        // The mask is written mid-construction; until it reads stock the manager isn't built.
        if (*pMask != (kStockCap - 1)) {
            return Commit::Wait;
        }

        // FULL stock-shape fail-safe. Every field must hold its exact stock value. If the
        // struct layout differed on this game version, these would not all line up on the
        // offsets we use — so a mismatch means "refuse", never "write to the wrong place".
        const std::uint64_t oPool = *pPool;
        const std::uint32_t oHead = *pHead, oTail = *pTail, oCtr = *pCtr, oCap = *pCap;
        if (oHead != 1u || oTail != (kStockCap - 1) || oCtr != kStockFreeCount ||
            oCap != kStockCap || oPool == 0) {
            logger::error(
                "manager not in the exact stock shape (head={:#x} tail={:#x} freeCtr={:#x} "
                "cap={:#x} mask={:#x} pool={:#x}); refusing to resize — either handles are "
                "already in use or the struct layout differs on this game version",
                oHead, oTail, oCtr, oCap, kStockCap - 1, oPool);
            return Commit::Refused;
        }

        const std::uint32_t newMask = static_cast<std::uint32_t>(g_newCap - 1);
        const std::uint32_t newCap  = static_cast<std::uint32_t>(g_newCap);
        *pPool = reinterpret_cast<std::uint64_t>(g_newPool);
        *pHead = 1u;
        *pTail = newMask;
        *pCtr  = newCap;
        *pCap  = newCap;
        *pMask = newMask;

        // Coherence check: confirm the six values we just wrote read back consistent before
        // declaring success (and revert to exact stock if not). The real layout-mismatch
        // protection is the stock-shape gate above; this is an additive belt-and-suspenders.
        if (*pPool != reinterpret_cast<std::uint64_t>(g_newPool) || *pHead != 1u ||
            *pTail != newMask || *pCtr != newCap || *pCap != newCap || *pMask != newMask) {
            *pPool = oPool;
            *pHead = oHead;
            *pTail = oTail;
            *pCtr  = oCtr;
            *pCap  = oCap;
            *pMask = static_cast<std::uint32_t>(kStockCap - 1);
            logger::error("read-back mismatch after swap; reverted to the stock pool");
            return Commit::Refused;
        }

        if (g_generationWrapDetection && !InstallGenerationDetector(manager)) {
            ReleaseGenerationDetector();
        }

        logger::info("pool resized (verified): {} index bits, cap {} -> {} ({} generations), "
                     "{} MB @ {:#x}",
                     kTargetBits, kStockCap - 1, g_newCap - 1, kGenerationCount,
                     (g_newCap * kPoolEntrySize) / (1024 * 1024),
                     reinterpret_cast<std::uint64_t>(g_newPool));
        return Commit::Done;
    }

    // ---- "What is using the handles past the old cap" diagnostic ---------------------------
    //
    // Every pooled object is a TESObjectREFR-derived form (the reference-handle manager is
    // instantiated for TESObjectREFR / Actor / Projectile). A pool slot is LIVE iff its object
    // pointer (qword0) is non-null: CreateHandle writes the object there, Release writes 0 back,
    // and VirtualAlloc zeroed the never-touched slots. So the objects occupying indices at or
    // above the old 2^21 cap are exactly the handles that only exist because we raised it — we
    // read each one's FormID and form type and tally what they are and where they came from.

    // Object (TESForm) field offsets verified for the 1.16.244 release target.
    constexpr std::size_t kObj_NativeHandle = 0x24;  // cached handle the engine stored back
    constexpr std::size_t kObj_FormID       = 0x28;
    constexpr std::size_t kObj_FormType     = 0x2e;  // u8 FormType enum
    constexpr std::size_t kObj_SourceIndex  = 0x30;  // u16 index into the form source-file lists

    // Read four fields off a possibly-stale object pointer without ever crashing: a slot can be
    // freed and its object deleted between our qword0 read and this deref. SEH turns that rare
    // use-after-free into a clean "unreadable" instead of a fault. POD-only body so __try is legal.
    bool SafeReadObject(const void* obj, std::uint32_t* handle, std::uint32_t* formID,
                        std::uint8_t* formType, std::uint16_t* sourceIndex) noexcept
    {
        __try {
            const auto* p = static_cast<const std::uint8_t*>(obj);
            *handle      = *reinterpret_cast<const volatile std::uint32_t*>(p + kObj_NativeHandle);
            *formID      = *reinterpret_cast<const volatile std::uint32_t*>(p + kObj_FormID);
            *formType    = *reinterpret_cast<const volatile std::uint8_t*>(p + kObj_FormType);
            *sourceIndex = *reinterpret_cast<const volatile std::uint16_t*>(p + kObj_SourceIndex);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    using ReferencePtr = RE::NiPointer<RE::TESObjectREFR>;
    using LookupReferenceByHandle_t = ReferencePtr* (*)(ReferencePtr*, std::uint32_t*);

    ReferencePtr LookupReference(std::uint32_t handle)
    {
        static REL::Relocation<LookupReferenceByHandle_t> lookup{
            REL::ID(kID_LookupReferenceByHandle)
        };
        ReferencePtr result;
        lookup(std::addressof(result), std::addressof(handle));
        return result;
    }

    // Copy engine-owned text into a bounded, single-line log string. The caller wraps this in
    // SEH because a virtual method can still return a bad pointer if an unsupported layout ever
    // slips past the runtime gates. Quotes are changed to apostrophes so the logged fields remain
    // unambiguous without allocating or escaping inside the exception-protected function.
    void CopyLogText(const char* src, char* dst, std::size_t dstSize) noexcept
    {
        if (dstSize == 0) return;
        dst[0] = '\0';
        if (!src) return;

        std::size_t i = 0;
        for (; i + 1 < dstSize; ++i) {
            const unsigned char c = static_cast<unsigned char>(src[i]);
            if (c == 0) break;
            if (c == '"')
                dst[i] = '\'';
            else if (c < 0x20 || c == 0x7f)
                dst[i] = ' ';
            else
                dst[i] = static_cast<char>(c);
        }
        dst[i] = '\0';
    }

    enum class FormText : std::uint8_t { EditorID, ObjectType, DisplayName };

    // POD-only SEH body: MSVC does not permit C++ objects requiring unwinding in a function that
    // uses __try. The reference/base form is held by an NiPointer in the calling function.
    bool SafeReadFormText(RE::TESForm* form, FormText which, char* dst,
                          std::size_t dstSize) noexcept
    {
        __try {
            const char* text = nullptr;
            switch (which) {
            case FormText::EditorID:   text = form->GetFormEditorID(); break;
            case FormText::ObjectType: text = form->GetObjectTypeName(); break;
            case FormText::DisplayName:
                text = static_cast<RE::TESObjectREFR*>(form)->GetDisplayFullName();
                break;
            }
            CopyLogText(text, dst, dstSize);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (dstSize != 0) dst[0] = '\0';
            return false;
        }
    }

    bool SafeGetSourceFile(RE::TESForm* form, RE::TESFile** file) noexcept
    {
        __try {
            *file = form->GetRevertFile();
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            *file = nullptr;
            return false;
        }
    }

    // CommonLibSF's public TESFile layout predates Starfield 1.16.x; its fileName field is not at
    // the declared +0x38 on the supported runtimes. Locate the stable, NUL-terminated plugin name
    // within the live TESFile object (or one of its header-owned strings) instead of dereferencing
    // that stale field offset.
    bool Readable(const void* ptr, std::size_t bytes) noexcept
    {
        if (!ptr || bytes == 0) return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQuery(ptr, std::addressof(mbi), sizeof(mbi)) == 0 ||
            mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) != 0) {
            return false;
        }
        const DWORD protection = mbi.Protect & 0xff;
        if (protection != PAGE_READONLY && protection != PAGE_READWRITE &&
            protection != PAGE_WRITECOPY && protection != PAGE_EXECUTE_READ &&
            protection != PAGE_EXECUTE_READWRITE && protection != PAGE_EXECUTE_WRITECOPY) {
            return false;
        }
        const auto start = reinterpret_cast<std::uintptr_t>(ptr);
        const auto end = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        return start <= end && bytes <= end - start;
    }

    bool IsPluginNameChar(unsigned char c) noexcept
    {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == ' ' || c == '_' || c == '-' || c == '.' ||
               c == '(' || c == ')' || c == '\'' || c == '!' || c == '+' || c == '&';
    }

    std::string_view MatchPluginName(const std::uint8_t* ptr, std::size_t max) noexcept
    {
        std::size_t len = 0;
        while (len < max && ptr[len] != 0) {
            if (!IsPluginNameChar(ptr[len])) return {};
            ++len;
        }
        if (len < 5 || len >= max || ptr[len - 4] != '.') return {};

        auto lower = [](unsigned char c) noexcept {
            return static_cast<char>((c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c);
        };
        const char a = lower(ptr[len - 3]);
        const char b = lower(ptr[len - 2]);
        const char c = lower(ptr[len - 1]);
        if (a != 'e' || b != 's' || (c != 'm' && c != 'p' && c != 'l')) return {};
        return { reinterpret_cast<const char*>(ptr), len };
    }

    std::string_view FindPluginNameInRange(const std::uint8_t* ptr, std::size_t max) noexcept
    {
        if (!Readable(ptr, max)) return {};
        for (std::size_t offset = 0; offset + 5 < max; ++offset) {
            if (auto match = MatchPluginName(ptr + offset, max - offset); !match.empty()) {
                return match;
            }
        }
        return {};
    }

    std::string PluginFileName(const RE::TESFile* file)
    {
        if (!file) return {};
        const auto* base = reinterpret_cast<const std::uint8_t*>(file);

        // Prefer an inline name. This cannot accidentally select a dependency owned by TESFile.
        if (auto name = FindPluginNameInRange(base, 0x800); !name.empty()) {
            return std::string(name);
        }

        // On layouts with an out-of-line name, follow only plausible readable header pointers.
        for (std::size_t slot = 0x18; slot <= 0x400; slot += 8) {
            if (!Readable(base + slot, sizeof(std::uintptr_t))) continue;
            const auto candidate = *reinterpret_cast<const std::uintptr_t*>(base + slot);
            if (candidate < 0x10000) continue;
            const auto* target = reinterpret_cast<const std::uint8_t*>(candidate);
            if (auto name = FindPluginNameInRange(target, 0x300); !name.empty()) {
                return std::string(name);
            }
        }
        return {};
    }

    std::string PluginForForm(RE::TESForm* form, std::uint32_t formID,
                              std::uint16_t sourceIndex)
    {
        if ((formID >> 24) == 0xffu) return "<runtime-created>";

        RE::TESFile* file = nullptr;
        if (form && SafeGetSourceFile(form, std::addressof(file))) {
            if (auto name = PluginFileName(file); !name.empty()) return name;
        }
        return fmt::format("<source#{:#06x}>", sourceIndex);
    }

    std::string GenerationReuseStatus()
    {
        const std::uint64_t hottest = g_hottestHandle.load(std::memory_order_acquire);
        const std::uint32_t reuses = static_cast<std::uint32_t>(hottest >> 32);
        const std::uint64_t wraps = g_generationWraps.load(std::memory_order_acquire);
        const std::string_view reliability =
            g_saturatedSlot.load(std::memory_order_acquire) == 0 ? ""sv :
                                                                  ", tracking UNRELIABLE"sv;
        if (reuses == 0) {
            return fmt::format("generation reuse: highest 0 / {}, hottest slot n/a, wraps {}{}",
                               kGenerationCount, wraps, reliability);
        }

        const std::uint32_t handle = static_cast<std::uint32_t>(hottest);
        const std::uint32_t slot = handle & static_cast<std::uint32_t>(g_newCap - 1);
        auto ref = LookupReference(handle);
        if (!ref) {
            return fmt::format(
                "generation reuse: highest {} / {} at slot {} (handle {:#010x}, not currently "
                "live), wraps {}{}",
                reuses, kGenerationCount, slot, handle, wraps, reliability);
        }

        std::uint32_t nativeHandle = 0, formID = 0;
        std::uint16_t sourceIndex = 0xffff;
        std::uint8_t formType = 0;
        if (!SafeReadObject(ref.get(), &nativeHandle, &formID, &formType, &sourceIndex) ||
            nativeHandle != handle) {
            return fmt::format(
                "generation reuse: highest {} / {} at slot {} (handle {:#010x}, occupant "
                "changed), wraps {}{}",
                reuses, kGenerationCount, slot, handle, wraps, reliability);
        }

        const std::string plugin = PluginForForm(ref.get(), formID, sourceIndex);
        if ((formID >> 24) == 0xffu) {
            if (auto base = ref->GetBaseObject()) {
                const std::uint32_t baseID = base->GetFormID();
                const std::string basePlugin = PluginForForm(base.get(), baseID, base->loadOrderIndex);
                return fmt::format(
                    "generation reuse: highest {} / {} at slot {} (handle {:#010x}, current ref "
                    "[{:#010x}] \"{}\", base [{:#010x}] \"{}\"), wraps {}{}",
                    reuses, kGenerationCount, slot, handle, formID, plugin, baseID, basePlugin,
                    wraps, reliability);
            }
        }

        return fmt::format(
            "generation reuse: highest {} / {} at slot {} (handle {:#010x}, current ref "
            "[{:#010x}] \"{}\"), wraps {}{}",
            reuses, kGenerationCount, slot, handle, formID, plugin, wraps, reliability);
    }

    // Names for the reference-family form types (everything a pointer handle can hold). Anything
    // else is printed numerically — a non-reference type here would itself be a red flag.
    const char* RefFormTypeName(std::uint8_t t)
    {
        switch (t) {
        case 0x4a: return "REFR";  case 0x4b: return "ACHR";  case 0x4c: return "PMIS";
        case 0x4d: return "PARW";  case 0x4e: return "PGRE";  case 0x4f: return "PBEA";
        case 0x50: return "PFLA";  case 0x51: return "PCON";  case 0x52: return "PPLA";
        case 0x53: return "PBAR";  case 0x54: return "PEMI";  case 0x55: return "PHZD";
        default:   return nullptr;
        }
    }

    struct CapturedReference
    {
        std::uint32_t handle{};
        std::uint32_t formID{};
        std::uint16_t sourceIndex{};
        std::uint8_t  formType{};
    };

    struct SourceBucket
    {
        std::uint32_t count{};
        std::uint32_t sampleHandle{};
        std::uint32_t sampleFormID{};
        std::uint16_t sourceIndex{};
    };

    std::array<SourceBucket, 6> TopSources(const std::vector<std::uint32_t>& counts,
                                           const std::vector<CapturedReference>& samples)
    {
        std::array<SourceBucket, 6> top{};
        for (std::size_t source = 0; source < counts.size(); ++source) {
            const std::uint32_t count = counts[source];
            if (count == 0 || count <= top.back().count) continue;

            SourceBucket bucket{};
            bucket.count = count;
            bucket.sourceIndex = static_cast<std::uint16_t>(source);
            bucket.sampleHandle = samples[source].handle;
            bucket.sampleFormID = samples[source].formID;

            std::size_t pos = top.size() - 1;
            while (pos > 0 && bucket.count > top[pos - 1].count) {
                top[pos] = top[pos - 1];
                --pos;
            }
            top[pos] = bucket;
        }
        return top;
    }

    std::string FormatSourceBuckets(const std::array<SourceBucket, 6>& buckets)
    {
        std::string out;
        for (const auto& bucket : buckets) {
            if (bucket.count == 0) break;
            auto ref = LookupReference(bucket.sampleHandle);
            const std::string plugin = PluginForForm(
                ref ? static_cast<RE::TESForm*>(ref.get()) : nullptr,
                bucket.sampleFormID,
                bucket.sourceIndex);
            out += fmt::format("\"{}\" {}, ", plugin, bucket.count);
        }
        return out;
    }

    void LogDetailedSample(const CapturedReference& sample)
    {
        auto ref = LookupReference(sample.handle);
        if (!ref || ref->GetFormID() != sample.formID) {
            logger::info("past-cap sample: ref=[{:#010x}] handle={:#010x} {} <no longer live>",
                         sample.formID, sample.handle,
                         RefFormTypeName(sample.formType) ? RefFormTypeName(sample.formType) : "unknown");
            return;
        }

        char refEditorID[160]{};
        char refDisplayName[160]{};
        SafeReadFormText(ref.get(), FormText::EditorID, refEditorID, sizeof(refEditorID));
        SafeReadFormText(ref.get(), FormText::DisplayName, refDisplayName, sizeof(refDisplayName));
        const std::string refPlugin = PluginForForm(ref.get(), sample.formID, sample.sourceIndex);

        auto base = ref->GetBaseObject();
        if (!base) {
            logger::info("past-cap sample: ref=[{:#010x}] \"{}\" {} edid=\"{}\" name=\"{}\" | base=<none>",
                         sample.formID, refPlugin,
                         RefFormTypeName(sample.formType) ? RefFormTypeName(sample.formType) : "unknown",
                         refEditorID[0] ? refEditorID : "<none>",
                         refDisplayName[0] ? refDisplayName : "<none>");
            return;
        }

        char baseEditorID[160]{};
        char baseType[80]{};
        SafeReadFormText(base.get(), FormText::EditorID, baseEditorID, sizeof(baseEditorID));
        SafeReadFormText(base.get(), FormText::ObjectType, baseType, sizeof(baseType));
        const std::uint32_t baseID = base->GetFormID();
        const std::string basePlugin = PluginForForm(base.get(), baseID, base->loadOrderIndex);

        logger::info(
            "past-cap sample: ref=[{:#010x}] \"{}\" {} edid=\"{}\" name=\"{}\" | "
            "base=[{:#010x}] \"{}\" {} edid=\"{}\"",
            sample.formID, refPlugin,
            RefFormTypeName(sample.formType) ? RefFormTypeName(sample.formType) : "unknown",
            refEditorID[0] ? refEditorID : "<none>",
            refDisplayName[0] ? refDisplayName : "<none>",
            baseID, basePlugin, baseType[0] ? baseType : "unknown-type",
            baseEditorID[0] ? baseEditorID : "<none>");
    }

    // Format the top `topN` buckets of a 256-wide histogram as "LABEL count, " pieces, largest
    // first. `label(i, buf)` fills a caller buffer with the name for bucket i. Works on a copy so
    // the caller's tallies are untouched.
    template <class LabelFn>
    std::string TopBuckets(const std::uint32_t (&counts)[256], int topN, LabelFn label)
    {
        std::uint32_t work[256];
        for (int i = 0; i < 256; ++i) work[i] = counts[i];
        std::string out;
        for (int pick = 0; pick < topN; ++pick) {
            int best = -1;
            std::uint32_t bestC = 0;
            for (int i = 0; i < 256; ++i) {
                if (work[i] > bestC) { bestC = work[i]; best = i; }
            }
            if (best < 0) break;
            char buf[16];
            label(best, buf);
            out += fmt::format("{} {}, ", buf, bestC);
            work[best] = 0;
        }
        return out;
    }

    // Scan the above-cap index range, classify every live object, and log one compact line:
    // total past the cap, a form-type histogram, a real source-plugin histogram, and detailed
    // reference/base-form samples. Verbose mode runs this once per minute after usage passes the
    // old cap and logs the current samples on every report.
    void ReportPastCap(std::uintptr_t manager)
    {
        const std::uint64_t poolAddr = *At<volatile std::uint64_t>(manager + kOff_PoolPtr);
        const std::uint32_t mask     = *At<volatile std::uint32_t>(manager + kOff_IndexMask);
        if (poolAddr == 0) return;
        const auto* const pool = reinterpret_cast<const std::uint8_t*>(poolAddr);

        std::uint64_t total = 0, unreadable = 0, consistent = 0;
        std::uint32_t byType[256] = {};
        std::vector<std::uint32_t> bySource(1u << 16);
        std::vector<CapturedReference> sourceSamples(1u << 16);
        std::vector<CapturedReference> samples(g_detailedSampleCount);
        std::size_t nSample = 0;

        for (std::uint64_t i = kStockCap; i < g_newCap; ++i) {
            const std::uint64_t obj =
                *reinterpret_cast<const volatile std::uint64_t*>(pool + i * kPoolEntrySize);
            if (obj == 0) continue;                       // free / never-allocated slot
            ++total;
            std::uint32_t nh = 0, fid = 0;
            std::uint16_t source = 0xffff;
            std::uint8_t  ft = 0;
            if (obj < 0x10000 ||
                !SafeReadObject(reinterpret_cast<const void*>(obj), &nh, &fid, &ft, &source)) {
                ++unreadable;
                continue;
            }
            ++byType[ft];
            ++bySource[source];
            if (sourceSamples[source].handle == 0) {
                sourceSamples[source] = CapturedReference{ nh, fid, source, ft };
            }
            if ((nh & mask) == static_cast<std::uint32_t>(i)) ++consistent;  // object agrees it lives here
            if (nSample < samples.size() && fid != 0) {
                samples[nSample++] = CapturedReference{ nh, fid, source, ft };
            }
        }

        if (total == 0) return;

        const std::string typeStr = TopBuckets(byType, 8, [](int t, char* buf) {
            if (const char* nm = RefFormTypeName(static_cast<std::uint8_t>(t)))
                std::snprintf(buf, 16, "%s", nm);
            else
                std::snprintf(buf, 16, "t%#04x", t);
        });
        const auto sourceBuckets = TopSources(bySource, sourceSamples);
        const std::string sourceStr = FormatSourceBuckets(sourceBuckets);

        logger::info("past old cap: {} live handles at index >= {} ({} verified, {} unreadable) | "
                     "types: {}| source plugins: {}",
                     total, kStockCap, consistent, unreadable, typeStr, sourceStr);

        if (nSample != 0) {
            logger::info("past-cap detailed samples ({} shown):", nSample);
            for (std::size_t i = 0; i < nSample; ++i) LogDetailedSample(samples[i]);
        }
    }

    struct WrapSnapshot
    {
        std::uint64_t total{};
        std::uint64_t event{};
    };

    WrapSnapshot ReadWrapSnapshot() noexcept
    {
        WrapSnapshot snapshot{};
        std::uint32_t before = 0, after = 0;
        do {
            before = g_wrapEventSequence.load(std::memory_order_acquire);
            if ((before & 1u) != 0) continue;
            snapshot.total = g_generationWraps.load(std::memory_order_relaxed);
            snapshot.event = g_lastWrapEvent.load(std::memory_order_relaxed);
            after = g_wrapEventSequence.load(std::memory_order_acquire);
        } while (before != after || (after & 1u) != 0);
        return snapshot;
    }

    // After a verified swap, report basic handle usage and generation safety every five minutes.
    // Verbose mode adds an above-cap plugin/reference report every minute. Reads from the free
    // counter are lock-free; an invalid counter stops the monitor instead of logging noise.
    void LivenessLog(std::uintptr_t manager)
    {
        auto* const pCtr = At<volatile std::uint32_t>(manager + kOff_FreeCounter);
        std::uint64_t reportedWraps = 0;
        bool reportedSaturation = false;
        for (std::uint64_t minute = 1;; ++minute) {
            ::Sleep(kReportTickMilliseconds);

            if (g_generationDetectorActive.load(std::memory_order_acquire)) {
                const WrapSnapshot wrap = ReadWrapSnapshot();
                if (wrap.total != reportedWraps) {
                    const std::uint32_t reuses = static_cast<std::uint32_t>(wrap.event >> 32);
                    const std::uint32_t handle = static_cast<std::uint32_t>(wrap.event);
                    const std::uint32_t slot =
                        handle & static_cast<std::uint32_t>(g_newCap - 1);
                    logger::critical(
                        "HANDLE GENERATION WRAP DETECTED: total {}, slot {}, reuse {}, new handle "
                        "{:#010x}; stale-handle aliasing is now possible",
                        wrap.total, slot, reuses, handle);
                    reportedWraps = wrap.total;
                }

                const std::uint32_t saturated =
                    g_saturatedSlot.load(std::memory_order_acquire);
                if (saturated != 0 && !reportedSaturation) {
                    logger::critical(
                        "generation detector lost exact tracking at slot {}; its 16-bit assignment "
                        "counter saturated or disagreed with the engine generation",
                        saturated - 1);
                    reportedSaturation = true;
                }
            }

            const std::uint32_t freeCtr = *pCtr;
            if (freeCtr > g_newCap) {
                // Field no longer looks like our counter — stop rather than log noise.
                return;
            }
            const std::uint64_t used = g_newCap - freeCtr;
            if ((minute % kNormalReportMinutes) == 0) {
                if (g_generationDetectorActive.load(std::memory_order_acquire)) {
                    logger::info("handles in use: {} / {} ({:.1f}%) | {}",
                                 used, g_newCap - 1,
                                 100.0 * static_cast<double>(used) /
                                     static_cast<double>(g_newCap - 1),
                                 GenerationReuseStatus());
                } else {
                    logger::info("handles in use: {} / {} ({:.1f}%)",
                                 used, g_newCap - 1,
                                 100.0 * static_cast<double>(used) /
                                     static_cast<double>(g_newCap - 1));
                }
            }
            if (g_verboseLogging && used > (kStockCap - 1)) {
                // Identify what occupies the above-cap slots once per minute.
                ReportPastCap(manager);
            }
        }
    }

    // Watcher: pre-builds the pool, then waits for the manager to be published (construction
    // complete). At that point the pool is built but untouched — a single-threaded window,
    // ~37 s before any handle is used — so the six-field commit is uncontended.
    void ReleasePool()   // free the pre-built pool on any path that does not keep it
    {
        if (g_newPool) {
            ::VirtualFree(g_newPool, 0, MEM_RELEASE);
            g_newPool = nullptr;
        }
    }

    DWORD WINAPI WatcherThread(LPVOID)
    {
        if (!PreparePool()) return 0;
        PrepareGenerationDetector();

        auto* const singleton = At<std::uintptr_t>(REL::ID(kID_SingletonPtr).address());
        const std::uint64_t deadline = ::GetTickCount64() + 120000;   // wall-clock ~120 s
        while (::GetTickCount64() < deadline) {
            const std::uintptr_t manager = *singleton;
            if (manager != 0) {
                switch (TryCommit(manager)) {
                case Commit::Done:
                    LivenessLog(manager);
                    return 0;  // pool now owned by engine
                case Commit::Refused:
                    ReleaseGenerationDetector();
                    ReleasePool();
                    return 0;
                case Commit::Wait:    break;
                }
            }
            ::Sleep(1);
        }
        logger::warn("manager never became ready within timeout; no resize performed");
        ReleaseGenerationDetector();
        ReleasePool();
        return 0;
    }
}

SFSE_PLUGIN_LOAD(const SFSE::LoadInterface* a_sfse)
{
    SFSE::Init(a_sfse, {
                           .logPattern = "[%H:%M:%S:%e] [%l] %v",
                           .trampoline = false,
    });

    LoadConfig();
    spdlog::default_logger()->flush_on(spdlog::level::info);
    logger::info("StarfieldHandleCapRaise loading; target index bits = {}", kTargetBits);
    if (g_verboseLogging) {
        logger::info("verbose logging enabled; sample size = {}; detailed reports every minute",
                     g_detailedSampleCount);
    }

    // Swap on a watcher thread in the single-threaded window after construction.
    if (auto h = ::CreateThread(nullptr, 0, &WatcherThread, nullptr, 0, nullptr)) {
        ::CloseHandle(h);
    } else {
        logger::error("failed to start watcher thread");
    }
    return true;
}

SFSE_PLUGIN_VERSION = []() noexcept {
    SFSE::PluginVersionData data{};
    data.PluginName("StarfieldHandleCapRaise");
    data.PluginVersion(REL::Version{ 1, 0, 0 });
    data.AuthorName("Starfield Handle Audit"sv);
    data.UsesAddressLibrary(true);    // singleton pointer resolved by Address Library ID
    data.UsesSigScanning(false);
    data.IsLayoutDependent(true);
    data.HasNoStructUse(false);
    data.MinimumRequiredXSEVersion(SFSE::SFSE_PACK_LATEST);
    data.CompatibleVersions({ SFSE::RUNTIME_SF_1_16_244 });
    return data;
}();
