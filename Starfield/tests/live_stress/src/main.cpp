#include "SFSE/SFSE.h"
#include "REL/Utility.h"

#include <spdlog/spdlog.h>

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

namespace logger = spdlog;
using namespace std::literals;

namespace
{
    constexpr std::uint64_t kID_Create = 139362;
    constexpr std::uint64_t kID_Lookup = 139363;
    constexpr std::uint64_t kID_Release = 139364;

    constexpr std::uint32_t kStockCap = 1u << 21;
    constexpr std::uint32_t kBits = 23;
    constexpr std::uint32_t kCapacity = 1u << kBits;
    constexpr std::uint32_t kMask = kCapacity - 1u;
    constexpr std::uint32_t kGenerations = 1u << (32u - kBits);
    constexpr std::uint32_t kTarget = 7'900'000u;
    constexpr std::uint32_t kReuseProbe = 4096u;
    constexpr std::uint32_t kVirginTail = kMask - kTarget;
    constexpr std::uint32_t kProgressStep = 500'000u;

    static_assert(kCapacity == 0x800000u);
    static_assert(kMask == 0x7fffffu);
    static_assert(kGenerations == 512u);
    static_assert(kVirginTail == 488'607u);

    struct PoolEntry
    {
        void* object;
        std::uint64_t state;
    };
    static_assert(sizeof(PoolEntry) == 0x10);
    static_assert(offsetof(PoolEntry, object) == 0);
    static_assert(offsetof(PoolEntry, state) == 8);

    struct alignas(8) ObjectStub
    {
        std::byte prefix[0x24];
        std::uint32_t nativeHandle;
        std::uint32_t formID;
        std::byte pad2c[2];
        std::uint8_t formType;
        std::byte pad2f;
        std::uint16_t sourceIndex;
        std::byte tail[6];
    };
    static_assert(offsetof(ObjectStub, nativeHandle) == 0x24);
    static_assert(offsetof(ObjectStub, formID) == 0x28);
    static_assert(offsetof(ObjectStub, formType) == 0x2e);
    static_assert(offsetof(ObjectStub, sourceIndex) == 0x30);
    static_assert(sizeof(ObjectStub) == 0x38);

    struct Detector;

    struct alignas(8) TestManager
    {
        std::uintptr_t* vtable;        // 00
        std::byte pad08[0x38];         // 08
        std::uint32_t lockState;       // 40
        std::uint32_t readersDone;     // 44
        std::uint32_t sequence;        // 48
        std::uint32_t pad4c;           // 4c
        PoolEntry* pool;               // 50
        std::uint32_t freeHead;        // 58
        std::uint32_t freeTail;        // 5c
        std::uint32_t freeCounter;     // 60
        std::uint32_t capacity;        // 64
        std::uint32_t indexMask;       // 68
        std::uint32_t pad6c;           // 6c
        Detector* detector;            // 70, test-only extension
    };
    static_assert(offsetof(TestManager, lockState) == 0x40);
    static_assert(offsetof(TestManager, readersDone) == 0x44);
    static_assert(offsetof(TestManager, sequence) == 0x48);
    static_assert(offsetof(TestManager, pool) == 0x50);
    static_assert(offsetof(TestManager, freeHead) == 0x58);
    static_assert(offsetof(TestManager, freeTail) == 0x5c);
    static_assert(offsetof(TestManager, freeCounter) == 0x60);
    static_assert(offsetof(TestManager, capacity) == 0x64);
    static_assert(offsetof(TestManager, indexMask) == 0x68);
    static_assert(offsetof(TestManager, detector) == 0x70);

    struct LookupSink
    {
        std::uintptr_t* vtable;
        void* found;
        std::uint32_t observedHandle;
    };

    using Create_t = std::uint32_t (*)(TestManager*, void*);
    // The exact 1.16.236 resolver is a three-argument API. Supplying a fourth zero is harmless
    // and makes the otherwise-unused R9 deterministic for the lock helper it calls.
    using Lookup_t = void (*)(TestManager*, std::uint32_t, LookupSink*, std::uintptr_t);
    using Release_t = void (*)(TestManager*, std::uint32_t);

    class VirtualRegion
    {
    public:
        explicit VirtualRegion(std::size_t bytes) noexcept : _bytes(bytes)
        {
            _data = ::VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        }
        ~VirtualRegion()
        {
            if (_data != nullptr) ::VirtualFree(_data, 0, MEM_RELEASE);
        }
        VirtualRegion(const VirtualRegion&) = delete;
        VirtualRegion& operator=(const VirtualRegion&) = delete;
        void* Get() const noexcept { return _data; }
        std::size_t Size() const noexcept { return _bytes; }
        template <class T> T* As() const noexcept { return static_cast<T*>(_data); }

    private:
        std::size_t _bytes{};
        void* _data{};
    };

    struct Detector
    {
        std::uint16_t* assignments{};
        std::atomic<std::uint64_t> hottest{};   // high dword=reuses, low dword=handle
        std::atomic<std::uint64_t> wraps{};
        std::atomic<std::uint64_t> lastWrap{};  // high dword=reuses, low dword=handle
        std::atomic<std::uint32_t> mismatch{};  // slot+1

        void Reset() noexcept
        {
            std::memset(assignments, 0, static_cast<std::size_t>(kCapacity) * sizeof(std::uint16_t));
            hottest.store(0, std::memory_order_relaxed);
            wraps.store(0, std::memory_order_relaxed);
            lastWrap.store(0, std::memory_order_relaxed);
            mismatch.store(0, std::memory_order_relaxed);
        }

        void Record(std::uint32_t handle) noexcept
        {
            if (handle == 0) return;
            const std::uint32_t index = handle & kMask;
            const std::uint32_t generation = handle >> kBits;
            const std::uint16_t before = assignments[index];
            if (before == 0xffffu) {
                std::uint32_t zero = 0;
                mismatch.compare_exchange_strong(zero, index + 1);
                return;
            }
            assignments[index] = static_cast<std::uint16_t>(before + 1u);
            const std::uint32_t reuses = before;
            if (generation != (reuses % kGenerations)) {
                std::uint32_t zero = 0;
                mismatch.compare_exchange_strong(zero, index + 1);
            }
            if (reuses != 0 && (reuses % kGenerations) == 0) {
                lastWrap.store((static_cast<std::uint64_t>(reuses) << 32) | handle);
                wraps.fetch_add(1);
            }
            if (reuses != 0) {
                const std::uint64_t candidate =
                    (static_cast<std::uint64_t>(reuses) << 32) | handle;
                std::uint64_t current = hottest.load();
                while (reuses > static_cast<std::uint32_t>(current >> 32) &&
                       !hottest.compare_exchange_weak(current, candidate)) {
                }
            }
        }
    };
    static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

    void ManagerClear(TestManager*, void* rawObject) noexcept
    {
        if (rawObject != nullptr) static_cast<ObjectStub*>(rawObject)->nativeHandle = 0;
    }

    std::uint32_t ManagerGet(TestManager*, void* rawObject) noexcept
    {
        return rawObject != nullptr ? static_cast<ObjectStub*>(rawObject)->nativeHandle : 0;
    }

    void ManagerSet(TestManager* manager, void* rawObject, std::uint32_t handle) noexcept
    {
        if (rawObject != nullptr) static_cast<ObjectStub*>(rawObject)->nativeHandle = handle;
        if (manager != nullptr && manager->detector != nullptr) manager->detector->Record(handle);
    }

    void SinkUnused0(LookupSink*) noexcept {}
    void SinkUnused1(LookupSink*) noexcept {}
    void SinkCapture(LookupSink* sink, void* object, std::uint32_t handle) noexcept
    {
        sink->found = object;
        sink->observedHandle = handle;
    }

    std::array<std::uintptr_t, 3> g_managerVtable{
        reinterpret_cast<std::uintptr_t>(&ManagerClear),
        reinterpret_cast<std::uintptr_t>(&ManagerGet),
        reinterpret_cast<std::uintptr_t>(&ManagerSet)
    };
    std::array<std::uintptr_t, 3> g_sinkVtable{
        reinterpret_cast<std::uintptr_t>(&SinkUnused0),
        reinterpret_cast<std::uintptr_t>(&SinkUnused1),
        reinterpret_cast<std::uintptr_t>(&SinkCapture)
    };

    bool SafeCreate(Create_t fn, TestManager* manager, void* object,
                    std::uint32_t* result, DWORD* exception) noexcept
    {
        __try {
            *result = fn(manager, object);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            *exception = static_cast<DWORD>(GetExceptionCode());
            return false;
        }
    }

    bool SafeLookup(Lookup_t fn, TestManager* manager, std::uint32_t handle,
                    LookupSink* sink, DWORD* exception) noexcept
    {
        __try {
            fn(manager, handle, sink, 0);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            *exception = static_cast<DWORD>(GetExceptionCode());
            return false;
        }
    }

    bool SafeRelease(Release_t fn, TestManager* manager, std::uint32_t handle,
                     DWORD* exception) noexcept
    {
        __try {
            fn(manager, handle);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            *exception = static_cast<DWORD>(GetExceptionCode());
            return false;
        }
    }

    bool SafeReadObject(const void* rawObject, std::uint32_t* handle, std::uint32_t* formID,
                        std::uint8_t* formType, std::uint16_t* sourceIndex) noexcept
    {
        __try {
            const auto* bytes = static_cast<const std::uint8_t*>(rawObject);
            *handle = *reinterpret_cast<const volatile std::uint32_t*>(bytes + 0x24);
            *formID = *reinterpret_cast<const volatile std::uint32_t*>(bytes + 0x28);
            *formType = *reinterpret_cast<const volatile std::uint8_t*>(bytes + 0x2e);
            *sourceIndex = *reinterpret_cast<const volatile std::uint16_t*>(bytes + 0x30);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool g_enabled = false;
    std::atomic<bool> g_started{false};

    void Flush() noexcept
    {
        if (auto log = spdlog::default_logger()) log->flush();
    }

    bool Fail(std::string_view phase, std::uint64_t index, std::string_view reason,
              std::uint64_t actual = 0) noexcept
    {
        logger::critical("LIVE STRESS FAIL: phase={} index={} reason={} actual={:#x}",
                         phase, index, reason, actual);
        Flush();
        return false;
    }

    void PrepareObject(ObjectStub& object, std::uint32_t index) noexcept
    {
        object.nativeHandle = 0;
        object.formID = 0xff00'0000u | (index & 0x00ff'ffffu);
        object.formType = static_cast<std::uint8_t>(0x4a + (index & 3u));
        object.sourceIndex = static_cast<std::uint16_t>(index & 15u);
    }

    void Progress(std::string_view phase, std::uint32_t done, std::uint32_t total,
                  const TestManager& manager, ULONGLONG started) noexcept
    {
        if (done != total && (done % kProgressStep) != 0) return;
        const auto elapsed = ::GetTickCount64() - started;
        const double rate = elapsed != 0 ? (1000.0 * static_cast<double>(done) / elapsed) : 0.0;
        logger::info("LIVE STRESS progress: {} {}/{} ({:.1f}%), {:.0f}/s, head={}, tail={}, "
                     "free={}, elapsed={} ms",
                     phase, done, total, 100.0 * done / total, rate, manager.freeHead,
                     manager.freeTail, manager.freeCounter, elapsed);
    }

    bool ResolveOne(Lookup_t lookup, TestManager& manager, std::uint32_t handle,
                    void* expected, std::string_view phase, std::uint32_t index) noexcept
    {
        LookupSink sink{g_sinkVtable.data(), nullptr, 0};
        DWORD exception = 0;
        if (!SafeLookup(lookup, &manager, handle, &sink, &exception))
            return Fail(phase, index, "engine lookup raised SEH", exception);
        if (sink.found != expected || (expected != nullptr && sink.observedHandle != handle))
            return Fail(phase, index, "lookup identity/handle mismatch",
                        reinterpret_cast<std::uintptr_t>(sink.found));
        return true;
    }

    bool RunStress() noexcept
    {
        const ULONGLONG allStarted = ::GetTickCount64();
        ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

        const auto create = reinterpret_cast<Create_t>(REL::ID(kID_Create).address());
        const auto lookup = reinterpret_cast<Lookup_t>(REL::ID(kID_Lookup).address());
        const auto release = reinterpret_cast<Release_t>(REL::ID(kID_Release).address());
        if (create == nullptr || lookup == nullptr || release == nullptr)
            return Fail("resolve", 0, "one or more Address Library IDs resolved null");

        const std::size_t poolBytes = static_cast<std::size_t>(kCapacity) * sizeof(PoolEntry);
        const std::size_t objectBytes = static_cast<std::size_t>(kCapacity) * sizeof(ObjectStub);
        const std::size_t detectorBytes =
            static_cast<std::size_t>(kCapacity) * sizeof(std::uint16_t);
        logger::info("LIVE STRESS starting: exact runtime 1.16.236, target={}, usable={}, "
                     "generations={}, private arena={} MiB; engine create={:#x} lookup={:#x} "
                     "release={:#x}",
                     kTarget, kMask, kGenerations,
                     (poolBytes + objectBytes + detectorBytes) / (1024 * 1024),
                     reinterpret_cast<std::uintptr_t>(create),
                     reinterpret_cast<std::uintptr_t>(lookup),
                     reinterpret_cast<std::uintptr_t>(release));

        VirtualRegion poolRegion(poolBytes);
        VirtualRegion objectRegion(objectBytes);
        VirtualRegion detectorRegion(detectorBytes);
        if (poolRegion.Get() == nullptr || objectRegion.Get() == nullptr ||
            detectorRegion.Get() == nullptr)
            return Fail("allocate", 0, "VirtualAlloc failed", ::GetLastError());

        auto* const pool = poolRegion.As<PoolEntry>();
        auto* const objects = objectRegion.As<ObjectStub>();
        Detector detector{detectorRegion.As<std::uint16_t>()};
        detector.Reset();

        TestManager manager{};
        manager.vtable = g_managerVtable.data();
        manager.pool = pool;
        manager.freeHead = 1;
        manager.freeTail = kMask;
        manager.freeCounter = kCapacity;
        manager.capacity = kCapacity;
        manager.indexMask = kMask;
        manager.detector = &detector;

        for (std::uint64_t i = 1; i < kCapacity; ++i)
            pool[i].state = (i + 1 < kCapacity) ? i + 1 : 0;
        for (std::uint32_t i = 1; i <= kMask; ++i) {
            const std::uint32_t expected = i < kMask ? i + 1 : 0;
            if (pool[i].object != nullptr || static_cast<std::uint32_t>(pool[i].state) != expected)
                return Fail("initializer", i, "threaded free-list mismatch", pool[i].state);
        }
        logger::info("LIVE STRESS phase PASS: exact 23-bit pool initializer");

        DWORD exception = 0;
        ULONGLONG phaseStarted = ::GetTickCount64();
        for (std::uint32_t i = 1; i <= kTarget; ++i) {
            PrepareObject(objects[i], i);
            std::uint32_t handle = 0;
            if (!SafeCreate(create, &manager, &objects[i], &handle, &exception))
                return Fail("create", i, "engine create raised SEH", exception);
            if (handle != i || objects[i].nativeHandle != i)
                return Fail("create", i, "23-bit handle/callback mismatch", handle);
            if (!ResolveOne(lookup, manager, handle, &objects[i], "immediate-lookup", i))
                return false;
            Progress("create+immediate-lookup", i, kTarget, manager, phaseStarted);
        }
        if (manager.freeHead != kTarget + 1u || manager.freeTail != kMask ||
            manager.freeCounter != kCapacity - kTarget)
            return Fail("create", kTarget, "manager counters after 7.9M fill", manager.freeCounter);
        logger::info("LIVE STRESS phase PASS: {} unique simultaneous handles, bit22 boundary "
                     "exercised, wraps=0", kTarget);

        phaseStarted = ::GetTickCount64();
        for (std::uint32_t i = 1; i <= kTarget; ++i) {
            if (!ResolveOne(lookup, manager, objects[i].nativeHandle, &objects[i],
                            "full-lookup", i))
                return false;
            Progress("full identity lookup", i, kTarget, manager, phaseStarted);
        }
        logger::info("LIVE STRESS phase PASS: full {}-handle identity lookup", kTarget);

        std::uint64_t total = 0, unreadable = 0, consistent = 0;
        std::array<std::uint64_t, 256> types{};
        std::array<std::uint64_t, 16> sources{};
        std::array<std::uint32_t, 16> samples{};
        std::size_t sampleCount = 0;
        phaseStarted = ::GetTickCount64();
        for (std::uint32_t i = kStockCap; i < kCapacity; ++i) {
            void* object = pool[i].object;
            if (object == nullptr) continue;
            ++total;
            std::uint32_t handle = 0, formID = 0;
            std::uint8_t type = 0;
            std::uint16_t source = 0;
            if (reinterpret_cast<std::uintptr_t>(object) < 0x10000 ||
                !SafeReadObject(object, &handle, &formID, &type, &source)) {
                ++unreadable;
                continue;
            }
            ++types[type];
            ++sources[source & 15u];
            if ((handle & kMask) == i) ++consistent;
            if (sampleCount < samples.size() && formID != 0) samples[sampleCount++] = handle;
            Progress("verbose above-cap scan", i - kStockCap + 1u,
                     kCapacity - kStockCap, manager, phaseStarted);
        }
        constexpr std::uint64_t expectedPastCap =
            static_cast<std::uint64_t>(kTarget) - kStockCap + 1u;
        if (total != expectedPastCap || unreadable != 0 || consistent != expectedPastCap)
            return Fail("verbose-scan", 0, "total/unreadable/consistency mismatch", consistent);
        logger::info("LIVE STRESS verbose scan PASS: total={} at index >= {}, verified={}, "
                     "unreadable={}, samples={} | types [{},{},{},{}] | sources0-3 [{},{},{},{}]",
                     total, kStockCap, consistent, unreadable, sampleCount,
                     types[0x4a], types[0x4b], types[0x4c], types[0x4d],
                     sources[0], sources[1], sources[2], sources[3]);

        phaseStarted = ::GetTickCount64();
        for (std::uint32_t i = 1; i <= kTarget; ++i) {
            if (!SafeRelease(release, &manager, i, &exception))
                return Fail("release-all", i, "engine release raised SEH", exception);
            if (objects[i].nativeHandle != 0 || pool[i].object != nullptr)
                return Fail("release-all", i, "release callback/pool clear mismatch");
            if (!ResolveOne(lookup, manager, i, nullptr, "stale-after-release", i))
                return false;
            Progress("release+stale rejection", i, kTarget, manager, phaseStarted);
        }
        if (manager.freeHead != kTarget + 1u || manager.freeTail != kTarget ||
            manager.freeCounter != kCapacity)
            return Fail("release-all", kTarget, "manager counters after release", manager.freeCounter);
        logger::info("LIVE STRESS phase PASS: released {}, cached handles cleared, all stale "
                     "generation-0 lookups rejected", kTarget);

        phaseStarted = ::GetTickCount64();
        std::uint32_t waveDone = 0;
        for (std::uint32_t i = kTarget + 1u; i <= kMask; ++i) {
            PrepareObject(objects[i], i);
            std::uint32_t handle = 0;
            if (!SafeCreate(create, &manager, &objects[i], &handle, &exception))
                return Fail("virgin-tail", i, "engine create raised SEH", exception);
            if (handle != i) return Fail("virgin-tail", i, "FIFO virgin allocation mismatch", handle);
            ++waveDone;
            Progress("virgin tail + exact reuse", waveDone, kVirginTail + kReuseProbe,
                     manager, phaseStarted);
        }
        for (std::uint32_t i = 1; i <= kReuseProbe; ++i) {
            PrepareObject(objects[i], i);
            std::uint32_t handle = 0;
            if (!SafeCreate(create, &manager, &objects[i], &handle, &exception))
                return Fail("exact-reuse", i, "engine create raised SEH", exception);
            const std::uint32_t expected = kCapacity | i;
            if (handle != expected) return Fail("exact-reuse", i, "wrong slot/generation", handle);
            if (!ResolveOne(lookup, manager, handle, &objects[i], "reuse-current", i) ||
                !ResolveOne(lookup, manager, i, nullptr, "reuse-stale", i))
                return false;
            ++waveDone;
            Progress("virgin tail + exact reuse", waveDone, kVirginTail + kReuseProbe,
                     manager, phaseStarted);
        }
        const std::uint64_t hot = detector.hottest.load();
        if (static_cast<std::uint32_t>(hot >> 32) != 1u || detector.wraps.load() != 0 ||
            detector.mismatch.load() != 0)
            return Fail("exact-reuse", 0, "generation detector status mismatch", hot);
        logger::info("LIVE STRESS reuse PASS: exact FIFO slots 1..{} returned at generation 1; "
                     "old handles rejected; hottest slot={} reuse={}, wraps=0",
                     kReuseProbe, static_cast<std::uint32_t>(hot) & kMask,
                     static_cast<std::uint32_t>(hot >> 32));

        for (std::uint32_t i = kTarget + 1u; i <= kMask; ++i) {
            if (!SafeRelease(release, &manager, i, &exception))
                return Fail("cleanup-wave", i, "engine release raised SEH", exception);
        }
        for (std::uint32_t i = 1; i <= kReuseProbe; ++i) {
            if (!SafeRelease(release, &manager, kCapacity | i, &exception))
                return Fail("cleanup-wave", i, "engine release raised SEH", exception);
        }
        if (manager.freeHead != kReuseProbe + 1u || manager.freeTail != kReuseProbe ||
            manager.freeCounter != kCapacity)
            return Fail("cleanup-wave", 0, "final free-list header mismatch", manager.freeHead);
        std::uint32_t current = manager.freeHead;
        for (std::uint32_t visited = 0; visited < kMask; ++visited) {
            const std::uint32_t expected =
                visited < (kMask - kReuseProbe) ? kReuseProbe + 1u + visited
                                                : visited - (kMask - kReuseProbe) + 1u;
            if (current != expected || pool[current].object != nullptr)
                return Fail("final-free-list", visited, "chain/object mismatch", current);
            current = static_cast<std::uint32_t>(pool[current].state) & kMask;
        }
        if (current != 0) return Fail("final-free-list", kMask, "chain did not terminate", current);
        logger::info("LIVE STRESS phase PASS: complete private free list restored and verified");

        constexpr std::uint32_t wrapSlot = 1'234'567u;
        detector.Reset();
        manager.lockState = 0;
        manager.readersDone = 0;
        manager.sequence = 0;
        manager.freeHead = wrapSlot;
        manager.freeTail = wrapSlot;
        manager.freeCounter = 1;
        pool[wrapSlot].object = nullptr;
        pool[wrapSlot].state = 0;
        std::uint32_t firstHandle = 0;
        void* firstObject = nullptr;
        for (std::uint32_t assignment = 0; assignment <= kGenerations; ++assignment) {
            ObjectStub* object = &objects[assignment + 1u];
            PrepareObject(*object, assignment + 1u);
            std::uint32_t handle = 0;
            if (!SafeCreate(create, &manager, object, &handle, &exception))
                return Fail("wrap", assignment, "engine create raised SEH", exception);
            const std::uint32_t generation =
                static_cast<std::uint32_t>((static_cast<std::uint64_t>(assignment) * kCapacity) &
                                           0xffff'ffffu);
            if (handle != (generation | wrapSlot))
                return Fail("wrap", assignment, "generation encoding mismatch", handle);
            if (!ResolveOne(lookup, manager, handle, object, "wrap-current", assignment))
                return false;
            if (assignment == 0) {
                firstHandle = handle;
                firstObject = object;
            } else if (assignment < kGenerations) {
                if (!ResolveOne(lookup, manager, firstHandle, nullptr, "wrap-stale", assignment))
                    return false;
            } else {
                if (handle != firstHandle || object == firstObject ||
                    !ResolveOne(lookup, manager, firstHandle, object, "wrap-alias", assignment))
                    return Fail("wrap", assignment, "expected stale alias was not reproduced", handle);
            }
            if (assignment < kGenerations &&
                !SafeRelease(release, &manager, handle, &exception))
                return Fail("wrap", assignment, "engine release raised SEH", exception);
        }
        const std::uint64_t wrap = detector.lastWrap.load();
        const std::uint64_t wrapHot = detector.hottest.load();
        if (detector.wraps.load() != 1u || static_cast<std::uint32_t>(wrap >> 32) != 512u ||
            static_cast<std::uint32_t>(wrapHot >> 32) != 512u || detector.mismatch.load() != 0)
            return Fail("wrap", 512, "detector wrap/hottest status mismatch", wrap);
        if (!SafeRelease(release, &manager, firstHandle, &exception))
            return Fail("wrap-cleanup", 512, "engine release raised SEH", exception);
        if (pool[wrapSlot].object != nullptr || objects[kGenerations + 1u].nativeHandle != 0)
            return Fail("wrap-cleanup", 512, "final aliased occupant was not cleared");
        logger::critical("LIVE STRESS expected boundary confirmed: one stale-handle alias at "
                         "generation wrap; slot={}, reuse=512, handle={:#010x}; detector wraps=1, "
                         "hottest slot={} reuse=512",
                         wrapSlot, firstHandle, static_cast<std::uint32_t>(wrapHot) & kMask);

        logger::info("LIVE STRESS RESULT: PASS — {} unique simultaneous handles; {} clean and "
                     "slot-consistent above-stock entries; real engine create/lookup/release; "
                     "exact FIFO reuse {}; stale rejection; full cleanup; wrap detection; "
                     "elapsed={} ms",
                     kTarget, expectedPastCap, kReuseProbe, ::GetTickCount64() - allStarted);
        Flush();
        return true;
    }

    DWORD WINAPI StressThread(LPVOID)
    {
        const bool passed = RunStress();
        if (!passed) logger::critical("LIVE STRESS RESULT: FAIL; global game handle manager was untouched");
        Flush();
        return passed ? 0u : 1u;
    }

    void MessageHandler(SFSE::MessagingInterface::Message* message)
    {
        if (message == nullptr || message->type != SFSE::MessagingInterface::kPostPostDataLoad ||
            !g_enabled || g_started.exchange(true))
            return;
        logger::warn("LIVE STRESS explicitly enabled; starting private-manager test after data load");
        if (HANDLE thread = ::CreateThread(nullptr, 0, &StressThread, nullptr, 0, nullptr)) {
            ::CloseHandle(thread);
        } else {
            logger::critical("LIVE STRESS could not create worker thread (error {})", ::GetLastError());
        }
    }

    bool LoadEnabled()
    {
        wchar_t exePath[MAX_PATH]{};
        ::GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::wstring ini(exePath);
        const auto slash = ini.find_last_of(L"\\/");
        if (slash != std::wstring::npos) ini.resize(slash + 1);
        ini += L"Data\\SFSE\\Plugins\\StarfieldHandleLiveStress.ini";
        return ::GetPrivateProfileIntW(L"General", L"Enable", 0, ini.c_str()) != 0;
    }
}

SFSE_PLUGIN_LOAD(const SFSE::LoadInterface* sfse)
{
    if (sfse == nullptr || sfse->RuntimeVersion() != SFSE::RUNTIME_SF_1_16_236) return false;
    SFSE::Init(sfse, {.logPattern = "[%H:%M:%S:%e] [%l] %v", .trampoline = false});
    spdlog::default_logger()->flush_on(spdlog::level::info);
    g_enabled = LoadEnabled();
    logger::info("StarfieldHandleLiveStress loading; exact 1.16.236 only; enabled={}", g_enabled);
    if (!g_enabled) {
        logger::info("LIVE STRESS inert: set [General] Enable=1 in its test INI to run");
        return true;
    }
    const auto messaging = SFSE::GetMessagingInterface();
    if (messaging == nullptr || !messaging->RegisterListener(&MessageHandler)) {
        logger::critical("LIVE STRESS failed to register SFSE message listener");
        return false;
    }
    return true;
}

SFSE_PLUGIN_VERSION = []() noexcept {
    SFSE::PluginVersionData data{};
    data.PluginName("StarfieldHandleLiveStress");
    data.PluginVersion(REL::Version{1, 0, 0});
    data.AuthorName("Starfield Handle Audit"sv);
    data.UsesAddressLibrary(true);
    data.UsesSigScanning(false);
    data.IsLayoutDependent(false);
    data.HasNoStructUse(false);
    data.MinimumRequiredXSEVersion(SFSE::SFSE_PACK_LATEST);
    data.CompatibleVersions({SFSE::RUNTIME_SF_1_16_236});
    return data;
}();
