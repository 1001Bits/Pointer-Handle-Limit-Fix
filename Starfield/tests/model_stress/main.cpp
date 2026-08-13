#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <vector>

#pragma comment(lib, "Psapi.lib")

namespace
{
    constexpr std::uint32_t kStockBits = 21;
    constexpr std::uint32_t kTargetBits = 23;
    constexpr std::uint32_t kStockCap = 1u << kStockBits;
    constexpr std::uint32_t kCapacity = 1u << kTargetBits;
    constexpr std::uint32_t kMask = kCapacity - 1u;
    constexpr std::uint32_t kGenerationCount = 1u << (32u - kTargetBits);
    constexpr std::uint32_t kTargetLive = 7'900'000u;
    constexpr std::uint32_t kReleaseCount = 4096u;
    constexpr std::uint32_t kReleaseBase = 1'000'000u;
    constexpr std::size_t kEntrySize = 16;

    static_assert(sizeof(void*) == 8);
    static_assert(kStockCap == 0x20'0000u);
    static_assert(kCapacity == 0x80'0000u);
    static_assert(kMask == 0x7f'ffffu);
    static_assert(kGenerationCount == 512u);
    static_assert(kTargetLive < kMask);
    static_assert(kReleaseBase > 0 && kReleaseBase + kReleaseCount <= kTargetLive);

    struct PoolEntry
    {
        std::uint64_t object;
        std::uint64_t state;
    };
    static_assert(sizeof(PoolEntry) == kEntrySize);
    static_assert(offsetof(PoolEntry, object) == 0);
    static_assert(offsetof(PoolEntry, state) == 8);

    // The test fields deliberately use the same raw offsets read by ReportPastCap.
    struct alignas(4) ObjectStub
    {
        std::byte prefix[0x24];
        std::uint32_t nativeHandle;
        std::uint32_t formID;
        std::byte pad2C[2];
        std::uint8_t formType;
        std::byte pad2F;
        std::uint16_t sourceIndex;
        std::byte pad32[2];
    };
    static_assert(offsetof(ObjectStub, nativeHandle) == 0x24);
    static_assert(offsetof(ObjectStub, formID) == 0x28);
    static_assert(offsetof(ObjectStub, formType) == 0x2e);
    static_assert(offsetof(ObjectStub, sourceIndex) == 0x30);
    static_assert(sizeof(ObjectStub) == 0x34);

    // This image makes offset drift in the six rewritten fields a compile-time failure.
    struct alignas(8) ManagerImage
    {
        std::byte prefix[0x50];
        std::uint64_t pool;
        std::uint32_t freeHead;
        std::uint32_t freeTail;
        std::uint32_t freeCounter;
        std::uint32_t capacity;
        std::uint32_t indexMask;
    };
    static_assert(offsetof(ManagerImage, pool) == 0x50);
    static_assert(offsetof(ManagerImage, freeHead) == 0x58);
    static_assert(offsetof(ManagerImage, freeTail) == 0x5c);
    static_assert(offsetof(ManagerImage, freeCounter) == 0x60);
    static_assert(offsetof(ManagerImage, capacity) == 0x64);
    static_assert(offsetof(ManagerImage, indexMask) == 0x68);

    [[noreturn]] void Fail(const char* message, std::uint64_t value = 0)
    {
        std::fprintf(stderr, "FAIL: %s (value=%llu / 0x%llx)\n", message,
                     static_cast<unsigned long long>(value),
                     static_cast<unsigned long long>(value));
        std::fflush(stderr);
        std::exit(1);
    }

    inline void Require(bool condition, const char* message, std::uint64_t value = 0)
    {
        if (!condition) [[unlikely]] {
            Fail(message, value);
        }
    }

    class VirtualRegion
    {
    public:
        VirtualRegion() = default;

        VirtualRegion(std::size_t bytes, DWORD protection = PAGE_READWRITE)
            : _bytes(bytes),
              _data(::VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, protection))
        {
            if (_data == nullptr) {
                Fail("VirtualAlloc failed", bytes);
            }
        }

        VirtualRegion(const VirtualRegion&) = delete;
        VirtualRegion& operator=(const VirtualRegion&) = delete;

        VirtualRegion(VirtualRegion&& other) noexcept
            : _bytes(other._bytes), _data(other._data)
        {
            other._bytes = 0;
            other._data = nullptr;
        }

        VirtualRegion& operator=(VirtualRegion&& other) noexcept
        {
            if (this != &other) {
                Reset();
                _bytes = other._bytes;
                _data = other._data;
                other._bytes = 0;
                other._data = nullptr;
            }
            return *this;
        }

        ~VirtualRegion() { Reset(); }

        void* Get() const noexcept { return _data; }
        std::size_t Size() const noexcept { return _bytes; }

        template <class T>
        T* As() const noexcept
        {
            return static_cast<T*>(_data);
        }

    private:
        void Reset() noexcept
        {
            if (_data != nullptr) {
                ::VirtualFree(_data, 0, MEM_RELEASE);
                _data = nullptr;
                _bytes = 0;
            }
        }

        std::size_t _bytes{};
        void* _data{};
    };

    using Clock = std::chrono::steady_clock;

    class StageTimer
    {
    public:
        explicit StageTimer(const char* label) : _label(label), _start(Clock::now())
        {
            std::printf("RUN : %s\n", _label);
        }

        ~StageTimer()
        {
            const auto elapsed = std::chrono::duration<double>(Clock::now() - _start).count();
            std::printf("PASS: %-43s %8.3f s\n", _label, elapsed);
        }

    private:
        const char* _label;
        Clock::time_point _start;
    };

    void ReportMemory(const char* label)
    {
        PROCESS_MEMORY_COUNTERS_EX counters{};
        counters.cb = sizeof(counters);
        Require(::GetProcessMemoryInfo(::GetCurrentProcess(),
                                       reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
                                       sizeof(counters)) != FALSE,
                "GetProcessMemoryInfo failed", ::GetLastError());
        constexpr double kMiB = 1024.0 * 1024.0;
        std::printf("MEM : %-43s working=%8.1f MiB peak=%8.1f MiB private=%8.1f MiB\n",
                    label,
                    static_cast<double>(counters.WorkingSetSize) / kMiB,
                    static_cast<double>(counters.PeakWorkingSetSize) / kMiB,
                    static_cast<double>(counters.PrivateUsage) / kMiB);
    }

    struct WrapSnapshot
    {
        std::uint64_t total{};
        std::uint64_t event{};
    };

    class GenerationDetector
    {
    public:
        explicit GenerationDetector(std::uint16_t* assignments) : _assignments(assignments) {}

        void ClearAll()
        {
            std::memset(_assignments, 0, static_cast<std::size_t>(kCapacity) * sizeof(std::uint16_t));
            _hottestHandle.store(0, std::memory_order_relaxed);
            _generationWraps.store(0, std::memory_order_relaxed);
            _lastWrapEvent.store(0, std::memory_order_relaxed);
            _wrapEventSequence.store(0, std::memory_order_relaxed);
            _saturatedSlot.store(0, std::memory_order_relaxed);
        }

        void Record(std::uint32_t handle) noexcept
        {
            if (handle == 0 || _assignments == nullptr) {
                return;
            }

            const std::uint32_t index = handle & kMask;
            const std::uint16_t generation = static_cast<std::uint16_t>(handle >> kTargetBits);
            const std::uint16_t assignments = _assignments[index];
            if (assignments == 0xffffu) {
                std::uint32_t unset = 0;
                _saturatedSlot.compare_exchange_strong(
                    unset, index + 1, std::memory_order_release, std::memory_order_relaxed);
                return;
            }
            _assignments[index] = static_cast<std::uint16_t>(assignments + 1);

            const std::uint32_t reuses = assignments;
            if (reuses != 0 && (reuses % kGenerationCount) == 0) {
                _wrapEventSequence.fetch_add(1, std::memory_order_acq_rel);
                _lastWrapEvent.store((static_cast<std::uint64_t>(reuses) << 32) | handle,
                                     std::memory_order_relaxed);
                _generationWraps.fetch_add(1, std::memory_order_relaxed);
                _wrapEventSequence.fetch_add(1, std::memory_order_release);
            }

            if (generation != static_cast<std::uint16_t>(reuses % kGenerationCount)) {
                std::uint32_t unset = 0;
                _saturatedSlot.compare_exchange_strong(
                    unset, index + 1, std::memory_order_release, std::memory_order_relaxed);
            }

            if (reuses != 0) {
                const std::uint64_t candidate =
                    (static_cast<std::uint64_t>(reuses) << 32) | handle;
                std::uint64_t hottest = _hottestHandle.load(std::memory_order_relaxed);
                while (reuses > static_cast<std::uint32_t>(hottest >> 32) &&
                       !_hottestHandle.compare_exchange_weak(
                           hottest, candidate, std::memory_order_release,
                           std::memory_order_relaxed)) {
                }
            }
        }

        WrapSnapshot Snapshot() const noexcept
        {
            WrapSnapshot snapshot{};
            std::uint32_t before = 0;
            std::uint32_t after = 0;
            do {
                before = _wrapEventSequence.load(std::memory_order_acquire);
                if ((before & 1u) != 0) {
                    continue;
                }
                snapshot.total = _generationWraps.load(std::memory_order_relaxed);
                snapshot.event = _lastWrapEvent.load(std::memory_order_relaxed);
                after = _wrapEventSequence.load(std::memory_order_acquire);
            } while (before != after || (after & 1u) != 0);
            return snapshot;
        }

        std::uint16_t Assignments(std::uint32_t index) const noexcept
        {
            return _assignments[index];
        }

        std::uint64_t Hottest() const noexcept
        {
            return _hottestHandle.load(std::memory_order_acquire);
        }

        std::uint32_t SaturatedSlot() const noexcept
        {
            return _saturatedSlot.load(std::memory_order_acquire);
        }

    private:
        std::uint16_t* _assignments{};
        std::atomic<std::uint64_t> _hottestHandle{0};
        std::atomic<std::uint64_t> _generationWraps{0};
        std::atomic<std::uint64_t> _lastWrapEvent{0};
        std::atomic<std::uint32_t> _wrapEventSequence{0};
        std::atomic<std::uint32_t> _saturatedSlot{0};
    };

    static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

    void PreparePool(ManagerImage& manager, PoolEntry* pool)
    {
        // Mirrors the plugin initializer: slot 0 is null; 1..capacity-1 are a FIFO free chain.
        for (std::uint64_t i = 1; i < kCapacity; ++i) {
            pool[i].state = (i + 1 < kCapacity) ? i + 1 : 0;
        }
        manager.pool = reinterpret_cast<std::uint64_t>(pool);
        manager.freeHead = 1;
        manager.freeTail = kMask;
        manager.freeCounter = kCapacity;
        manager.capacity = kCapacity;
        manager.indexMask = kMask;
    }

    class EngineModel
    {
    public:
        EngineModel(ManagerImage& manager, GenerationDetector& detector)
            : _manager(manager), _detector(detector)
        {
        }

        PoolEntry* Pool() const noexcept
        {
            return reinterpret_cast<PoolEntry*>(_manager.pool);
        }

        void* Lookup(std::uint32_t handle) const noexcept
        {
            const std::uint32_t index = handle & _manager.indexMask;
            if (index == 0) {
                return nullptr;
            }
            const PoolEntry& entry = Pool()[index];
            const std::uint32_t state = static_cast<std::uint32_t>(entry.state);
            if (entry.object != 0 &&
                (state & ~_manager.indexMask) == (handle & ~_manager.indexMask)) {
                return reinterpret_cast<void*>(entry.object);
            }
            return nullptr;
        }

        std::uint32_t Create(ObjectStub* object) noexcept
        {
            if (object->nativeHandle != 0 && Lookup(object->nativeHandle) == object) {
                return object->nativeHandle;
            }

            const std::uint32_t index = _manager.freeHead;
            std::uint32_t handle = 0;
            if (index != 0) {
                PoolEntry& entry = Pool()[index];
                const std::uint32_t state = static_cast<std::uint32_t>(entry.state);
                _manager.freeHead = state & _manager.indexMask;
                const std::uint32_t generation = state & ~_manager.indexMask;
                entry.state = generation;
                entry.object = reinterpret_cast<std::uint64_t>(object);
                handle = index | generation;
                --_manager.freeCounter;
            }

            // This is the manager vtable slot-2 callback hooked by the production detector.
            object->nativeHandle = handle;
            _detector.Record(handle);
            return handle;
        }

        bool Release(std::uint32_t handle) noexcept
        {
            const std::uint32_t index = handle & _manager.indexMask;
            if (index == 0) {
                return false;
            }
            const std::uint32_t generation = handle & ~_manager.indexMask;
            PoolEntry& entry = Pool()[index];
            const std::uint32_t state = static_cast<std::uint32_t>(entry.state);
            auto* const object = reinterpret_cast<ObjectStub*>(entry.object);
            if ((state & ~_manager.indexMask) != generation || object == nullptr ||
                object->nativeHandle != handle) {
                return false;
            }

            if (_manager.freeHead == 0) {
                _manager.freeHead = index;
            } else {
                PoolEntry& tail = Pool()[_manager.freeTail];
                const std::uint32_t tailState = static_cast<std::uint32_t>(tail.state);
                tail.state = (tailState & ~_manager.indexMask) | index;
            }
            entry.object = 0;
            entry.state = static_cast<std::uint32_t>(_manager.capacity + generation);
            _manager.freeTail = index;
            ++_manager.freeCounter;

            // The manager vtable slot-0 callback clears the object's cached native handle.
            object->nativeHandle = 0;
            return true;
        }

    private:
        ManagerImage& _manager;
        GenerationDetector& _detector;
    };

    constexpr std::array<std::uint8_t, 4> kFormTypes{0x4a, 0x4b, 0x50, 0x55};

    void PrepareObject(ObjectStub& object, std::uint32_t index)
    {
        object.nativeHandle = 0;
        object.formID = 0xff00'0000u | (index & 0x00ff'ffffu);
        object.formType = kFormTypes[index & 3u];
        object.sourceIndex = static_cast<std::uint16_t>(index & 15u);
    }

    struct CapturedReference
    {
        std::uint32_t handle{};
        std::uint32_t formID{};
        std::uint16_t sourceIndex{};
        std::uint8_t formType{};
    };

    // Kept POD-only just like the production SEH helper.
    bool SafeReadObject(const void* object, std::uint32_t* handle, std::uint32_t* formID,
                        std::uint8_t* formType, std::uint16_t* sourceIndex) noexcept
    {
        __try {
            const auto* bytes = static_cast<const std::uint8_t*>(object);
            *handle = *reinterpret_cast<const volatile std::uint32_t*>(bytes + 0x24);
            *formID = *reinterpret_cast<const volatile std::uint32_t*>(bytes + 0x28);
            *formType = *reinterpret_cast<const volatile std::uint8_t*>(bytes + 0x2e);
            *sourceIndex = *reinterpret_cast<const volatile std::uint16_t*>(bytes + 0x30);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    struct ScanResult
    {
        std::uint64_t total{};
        std::uint64_t unreadable{};
        std::uint64_t consistent{};
        std::array<std::uint64_t, 256> byType{};
        std::vector<std::uint64_t> bySource = std::vector<std::uint64_t>(1u << 16);
        std::vector<CapturedReference> samples;
    };

    ScanResult ScanPastStockCap(const ManagerImage& manager, std::size_t sampleLimit)
    {
        ScanResult result;
        result.samples.reserve(sampleLimit);
        const auto* const pool = reinterpret_cast<const PoolEntry*>(manager.pool);

        for (std::uint64_t i = kStockCap; i < manager.capacity; ++i) {
            const std::uint64_t object =
                *reinterpret_cast<const volatile std::uint64_t*>(&pool[i].object);
            if (object == 0) {
                continue;
            }
            ++result.total;
            std::uint32_t nativeHandle = 0;
            std::uint32_t formID = 0;
            std::uint16_t source = 0xffffu;
            std::uint8_t formType = 0;
            if (object < 0x10000u ||
                !SafeReadObject(reinterpret_cast<const void*>(object), &nativeHandle, &formID,
                                &formType, &source)) {
                ++result.unreadable;
                continue;
            }
            ++result.byType[formType];
            ++result.bySource[source];
            if ((nativeHandle & manager.indexMask) == static_cast<std::uint32_t>(i)) {
                ++result.consistent;
            }
            if (result.samples.size() < sampleLimit && formID != 0) {
                result.samples.push_back({nativeHandle, formID, source, formType});
            }
        }
        return result;
    }

    std::uint64_t CountResidue(std::uint32_t first, std::uint32_t last,
                               std::uint32_t modulus, std::uint32_t residue)
    {
        Require(first <= last && residue < modulus, "invalid residue-count request");
        const std::uint32_t delta = (residue + modulus - (first % modulus)) % modulus;
        const std::uint64_t firstMatch = static_cast<std::uint64_t>(first) + delta;
        if (firstMatch > last) {
            return 0;
        }
        return 1u + (static_cast<std::uint64_t>(last) - firstMatch) / modulus;
    }

    std::size_t ClampSampleSize(int value)
    {
        if (value < 0) {
            value = 0;
        }
        if (value > 64) {
            value = 64;
        }
        return static_cast<std::size_t>(value);
    }

    void ValidateCleanScan(const ScanResult& scan)
    {
        constexpr std::uint64_t kExpected =
            static_cast<std::uint64_t>(kTargetLive) - kStockCap + 1u;
        Require(kExpected == 5'802'849u, "expected above-cap count constant drift", kExpected);
        Require(scan.total == kExpected, "clean scan total", scan.total);
        Require(scan.unreadable == 0, "clean scan unreadable", scan.unreadable);
        Require(scan.consistent == kExpected, "clean scan consistency", scan.consistent);
        Require(scan.samples.size() == 16, "clean scan sample count", scan.samples.size());

        std::array<std::uint64_t, 256> expectedTypes{};
        for (std::uint32_t residue = 0; residue < 4; ++residue) {
            expectedTypes[kFormTypes[residue]] =
                CountResidue(kStockCap, kTargetLive, 4, residue);
        }
        for (std::size_t i = 0; i < expectedTypes.size(); ++i) {
            Require(scan.byType[i] == expectedTypes[i], "clean type histogram", i);
        }

        for (std::uint32_t source = 0; source < (1u << 16); ++source) {
            const std::uint64_t expected = source < 16
                ? CountResidue(kStockCap, kTargetLive, 16, source)
                : 0;
            Require(scan.bySource[source] == expected, "clean source histogram", source);
        }

        for (std::uint32_t sample = 0; sample < 16; ++sample) {
            const std::uint32_t index = kStockCap + sample;
            const CapturedReference& captured = scan.samples[sample];
            Require(captured.handle == index, "clean sample handle", sample);
            Require(captured.formID == (0xff00'0000u | (index & 0x00ff'ffffu)),
                    "clean sample formID", sample);
            Require(captured.formType == kFormTypes[index & 3u],
                    "clean sample form type", sample);
            Require(captured.sourceIndex == (index & 15u),
                    "clean sample source", sample);
        }
    }

    void ValidateFaultScan(const ScanResult& scan, std::uint32_t lowPointerIndex,
                           std::uint32_t noAccessIndex)
    {
        constexpr std::uint64_t kExpected =
            static_cast<std::uint64_t>(kTargetLive) - kStockCap + 1u;
        Require(scan.total == kExpected, "fault scan total", scan.total);
        Require(scan.unreadable == 2, "fault scan unreadable", scan.unreadable);
        Require(scan.consistent == kExpected - 3u, "fault scan consistency", scan.consistent);
        Require(scan.samples.size() == 64, "fault scan sample count", scan.samples.size());

        std::array<std::uint64_t, 256> expectedTypes{};
        for (std::uint32_t residue = 0; residue < 4; ++residue) {
            expectedTypes[kFormTypes[residue]] =
                CountResidue(kStockCap, kTargetLive, 4, residue);
        }
        --expectedTypes[kFormTypes[lowPointerIndex & 3u]];
        --expectedTypes[kFormTypes[noAccessIndex & 3u]];
        for (std::size_t i = 0; i < expectedTypes.size(); ++i) {
            Require(scan.byType[i] == expectedTypes[i], "fault type histogram", i);
        }

        for (std::uint32_t source = 0; source < (1u << 16); ++source) {
            std::uint64_t expected = source < 16
                ? CountResidue(kStockCap, kTargetLive, 16, source)
                : 0;
            if (source == (lowPointerIndex & 15u)) {
                --expected;
            }
            if (source == (noAccessIndex & 15u)) {
                --expected;
            }
            Require(scan.bySource[source] == expected, "fault source histogram", source);
        }
    }
}

int main()
{
    const auto totalStarted = Clock::now();
    std::printf("Starfield 23-bit handle-pool exact-model stress\n");
    std::printf("Model: Create 0x1428d0e40 | Lookup 0x1428d0ff0 | Release 0x1428d1090\n");
    std::printf("Target: %u live / %u usable (%.3f%%), generations=%u\n",
                kTargetLive, kMask,
                100.0 * static_cast<double>(kTargetLive) / static_cast<double>(kMask),
                kGenerationCount);

    Require(ClampSampleSize(-1) == 0, "negative sample clamp");
    Require(ClampSampleSize(16) == 16, "normal sample clamp");
    Require(ClampSampleSize(65) == 64, "high sample clamp");

    const std::size_t poolBytes = static_cast<std::size_t>(kCapacity) * sizeof(PoolEntry);
    const std::size_t objectBytes = static_cast<std::size_t>(kCapacity) * sizeof(ObjectStub);
    const std::size_t detectorBytes = static_cast<std::size_t>(kCapacity) * sizeof(std::uint16_t);
    std::printf("Commit request: pool=%zu MiB objects=%zu MiB detector=%zu MiB total=%zu MiB\n",
                poolBytes / (1024u * 1024u), objectBytes / (1024u * 1024u),
                detectorBytes / (1024u * 1024u),
                (poolBytes + objectBytes + detectorBytes) / (1024u * 1024u));

    VirtualRegion poolRegion(poolBytes);
    VirtualRegion objectRegion(objectBytes);
    VirtualRegion detectorRegion(detectorBytes);
    auto* const pool = poolRegion.As<PoolEntry>();
    auto* const objects = objectRegion.As<ObjectStub>();
    auto* const assignments = detectorRegion.As<std::uint16_t>();

    ManagerImage manager{};
    GenerationDetector detector(assignments);
    detector.ClearAll();
    EngineModel engine(manager, detector);

    {
        StageTimer stage("23-bit production-shape pool initializer");
        PreparePool(manager, pool);
        Require(manager.pool == reinterpret_cast<std::uint64_t>(pool), "pool pointer");
        Require(manager.freeHead == 1, "initial free head", manager.freeHead);
        Require(manager.freeTail == kMask, "initial free tail", manager.freeTail);
        Require(manager.freeCounter == kCapacity, "initial free counter", manager.freeCounter);
        Require(manager.capacity == kCapacity, "initial capacity", manager.capacity);
        Require(manager.indexMask == kMask, "initial mask", manager.indexMask);
        Require(pool[0].object == 0 && pool[0].state == 0, "reserved slot zero");
        for (std::uint32_t i = 1; i <= kMask; ++i) {
            const std::uint32_t expected = i < kMask ? i + 1 : 0;
            Require(pool[i].object == 0, "initial free object", i);
            Require(static_cast<std::uint32_t>(pool[i].state) == expected,
                    "initial threaded next index", i);
        }
    }
    ReportMemory("after pool/object/sidecar commit");

    {
        StageTimer stage("create + immediate lookup to index 7,900,000");
        for (std::uint32_t i = 1; i <= kTargetLive; ++i) {
            PrepareObject(objects[i], i);
            const std::uint32_t handle = engine.Create(&objects[i]);
            Require(handle == i, "first-generation handle encoding", i);
            Require(engine.Lookup(handle) == &objects[i], "immediate lookup identity", i);
        }
        Require(manager.freeHead == kTargetLive + 1u, "7.9M free head", manager.freeHead);
        Require(manager.freeTail == kMask, "7.9M free tail", manager.freeTail);
        Require(manager.freeCounter == kCapacity - kTargetLive,
                "7.9M free counter", manager.freeCounter);
        Require(detector.Hottest() == 0, "unexpected reuse during linear fill", detector.Hottest());
        Require(detector.Snapshot().total == 0, "wrap during linear fill");
        Require(detector.SaturatedSlot() == 0, "detector mismatch during linear fill");
    }
    ReportMemory("at 7.9M simultaneously live handles");

    {
        StageTimer stage("full 7.9M owning-identity lookup pass");
        for (std::uint32_t i = 1; i <= kTargetLive; ++i) {
            const std::uint32_t handle = objects[i].nativeHandle;
            Require(handle == i, "cached native handle after fill", i);
            Require(engine.Lookup(handle) == &objects[i], "second-pass lookup identity", i);
        }
        Require(engine.Lookup(0) == nullptr, "zero handle resolved");
        Require(engine.Lookup(kCapacity) == nullptr, "generation-only handle resolved");
        Require(engine.Lookup(kCapacity | 1u) == nullptr,
                "wrong-generation handle resolved");
        Require(engine.Lookup(kTargetLive + 1u) == nullptr, "free slot resolved");
    }

    {
        StageTimer stage("verbose above-stock-cap clean scanner");
        const ScanResult scan = ScanPastStockCap(manager, ClampSampleSize(16));
        ValidateCleanScan(scan);
        std::printf("SCAN: total=%llu unreadable=%llu consistent=%llu samples=%zu\n",
                    static_cast<unsigned long long>(scan.total),
                    static_cast<unsigned long long>(scan.unreadable),
                    static_cast<unsigned long long>(scan.consistent), scan.samples.size());
    }

    {
        StageTimer stage("verbose scanner low/unmapped/mismatch paths");
        constexpr std::uint32_t lowPointerIndex = kStockCap + 7u;
        constexpr std::uint32_t noAccessIndex = kStockCap + 11u;
        constexpr std::uint32_t mismatchIndex = kStockCap + 13u;
        const std::uint64_t savedLow = pool[lowPointerIndex].object;
        const std::uint64_t savedNoAccess = pool[noAccessIndex].object;
        const std::uint32_t savedNative = objects[mismatchIndex].nativeHandle;
        VirtualRegion noAccessPage(4096, PAGE_NOACCESS);
        pool[lowPointerIndex].object = 1;
        pool[noAccessIndex].object = reinterpret_cast<std::uint64_t>(noAccessPage.Get());
        objects[mismatchIndex].nativeHandle = mismatchIndex + 1u;

        const ScanResult scan = ScanPastStockCap(manager, ClampSampleSize(999));
        ValidateFaultScan(scan, lowPointerIndex, noAccessIndex);
        std::printf("SCAN: injected total=%llu unreadable=%llu consistent=%llu samples=%zu\n",
                    static_cast<unsigned long long>(scan.total),
                    static_cast<unsigned long long>(scan.unreadable),
                    static_cast<unsigned long long>(scan.consistent), scan.samples.size());

        pool[lowPointerIndex].object = savedLow;
        pool[noAccessIndex].object = savedNoAccess;
        objects[mismatchIndex].nativeHandle = savedNative;
    }

    std::vector<std::uint32_t> releaseOrder;
    releaseOrder.reserve(kReleaseCount);
    {
        StageTimer stage("release sample + stale-handle rejection");
        for (std::uint32_t n = 0; n < kReleaseCount; ++n) {
            const std::uint32_t index = kReleaseBase + kReleaseCount - 1u - n;
            releaseOrder.push_back(index);
            Require(engine.Release(index), "sample release failed", index);
            Require(objects[index].nativeHandle == 0, "release did not clear native handle", index);
            Require(engine.Lookup(index) == nullptr, "stale released handle resolved", index);
        }
        Require(!engine.Release(releaseOrder.front()), "double release succeeded");
        Require(manager.freeHead == kTargetLive + 1u, "post-release free head", manager.freeHead);
        Require(manager.freeTail == releaseOrder.back(), "post-release free tail", manager.freeTail);
        Require(manager.freeCounter == kCapacity - kTargetLive + kReleaseCount,
                "post-release free counter", manager.freeCounter);
    }

    {
        StageTimer stage("consume virgin tail + FIFO exact-slot reuse");
        for (std::uint32_t i = kTargetLive + 1u; i <= kMask; ++i) {
            PrepareObject(objects[i], i);
            const std::uint32_t handle = engine.Create(&objects[i]);
            Require(handle == i, "virgin-tail allocation order", i);
        }
        Require(manager.freeHead == releaseOrder.front(),
                "released FIFO did not follow virgin tail", manager.freeHead);

        for (std::uint32_t n = 0; n < kReleaseCount; ++n) {
            const std::uint32_t index = releaseOrder[n];
            PrepareObject(objects[index], index);
            const std::uint32_t handle = engine.Create(&objects[index]);
            const std::uint32_t expected = kCapacity | index;
            Require(handle == expected, "released slot not reused in FIFO order", index);
            Require(engine.Lookup(handle) == &objects[index], "reused handle lookup", index);
            Require(engine.Lookup(index) == nullptr, "old generation survived exact-slot reuse", index);
            Require(detector.Assignments(index) == 2, "reuse detector count", index);
        }
        Require(manager.freeHead == 0, "full pool head", manager.freeHead);
        Require(manager.freeTail == releaseOrder.back(), "full pool tail", manager.freeTail);
        Require(manager.freeCounter == 1, "full pool counter", manager.freeCounter);
        Require(detector.Snapshot().total == 0, "wrap before generation boundary");
        Require(static_cast<std::uint32_t>(detector.Hottest() >> 32) == 1,
                "hottest reuse count after FIFO reuse", detector.Hottest() >> 32);
        Require(detector.SaturatedSlot() == 0, "detector mismatch during FIFO reuse");

        PrepareObject(objects[0], 0);
        const ManagerImage beforeExhaustion = manager;
        Require(engine.Create(&objects[0]) == 0, "exhausted pool returned a handle");
        Require(manager.freeHead == beforeExhaustion.freeHead &&
                    manager.freeTail == beforeExhaustion.freeTail &&
                    manager.freeCounter == beforeExhaustion.freeCounter,
                "exhausted create changed free-list state");
    }
    ReportMemory("at all 8,388,607 usable slots live");

    {
        StageTimer stage("full release + exact free-list restoration");
        for (std::uint32_t i = 1; i <= kMask; ++i) {
            const std::uint32_t handle = objects[i].nativeHandle;
            Require(handle != 0, "missing handle before full release", i);
            Require(engine.Lookup(handle) == &objects[i], "pre-release full lookup", i);
            Require(engine.Release(handle), "full release failed", i);
            Require(engine.Lookup(handle) == nullptr, "released handle remained live", i);
        }
        Require(manager.freeHead == 1, "restored head", manager.freeHead);
        Require(manager.freeTail == kMask, "restored tail", manager.freeTail);
        Require(manager.freeCounter == kCapacity, "restored counter", manager.freeCounter);

        for (std::uint32_t i = 1; i <= kMask; ++i) {
            const std::uint32_t state = static_cast<std::uint32_t>(pool[i].state);
            const std::uint32_t expectedNext = i < kMask ? i + 1u : 0u;
            const bool reused = i >= kReleaseBase && i < kReleaseBase + kReleaseCount;
            const std::uint32_t expectedGeneration = reused ? 2u * kCapacity : kCapacity;
            Require(pool[i].object == 0, "restored slot still owns object", i);
            Require((state & kMask) == expectedNext, "restored FIFO next link", i);
            Require((state & ~kMask) == expectedGeneration,
                    "restored generation bits", i);
            Require(objects[i].nativeHandle == 0, "restored object cached handle", i);
        }
    }

    {
        StageTimer stage("512-generation wrap boundary microcycle");
        constexpr std::uint32_t wrapSlot = 1'234'567u;
        detector.ClearAll();
        manager.freeHead = wrapSlot;
        manager.freeTail = wrapSlot;
        manager.freeCounter = 1;
        manager.capacity = kCapacity;
        manager.indexMask = kMask;
        pool[wrapSlot].object = 0;
        pool[wrapSlot].state = 0;

        std::uint32_t firstHandle = 0;
        ObjectStub* firstObject = nullptr;
        for (std::uint32_t assignment = 0; assignment <= kGenerationCount; ++assignment) {
            ObjectStub* const object = &objects[assignment + 1u];
            PrepareObject(*object, assignment + 1u);
            const std::uint32_t handle = engine.Create(object);
            const std::uint32_t expectedGeneration =
                static_cast<std::uint32_t>((static_cast<std::uint64_t>(assignment) * kCapacity) &
                                           0xffff'ffffu);
            Require(handle == (expectedGeneration | wrapSlot),
                    "microcycle generation encoding", assignment);
            Require(engine.Lookup(handle) == object, "microcycle current lookup", assignment);
            if (assignment == 0) {
                firstHandle = handle;
                firstObject = object;
            } else if (assignment < kGenerationCount) {
                Require(engine.Lookup(firstHandle) == nullptr,
                        "stale handle resolved before full generation wrap", assignment);
            } else {
                Require(handle == firstHandle, "512-generation handle did not wrap", handle);
                Require(object != firstObject, "wrap test reused the same synthetic object");
                Require(engine.Lookup(firstHandle) == object,
                        "wrapped stale handle did not alias current object");
            }

            if (assignment < kGenerationCount) {
                Require(engine.Release(handle), "microcycle release", assignment);
            }
        }

        const WrapSnapshot wrap = detector.Snapshot();
        Require(wrap.total == 1, "detector did not report one generation wrap", wrap.total);
        Require(static_cast<std::uint32_t>(wrap.event >> 32) == kGenerationCount,
                "wrap event reuse count", wrap.event >> 32);
        Require(static_cast<std::uint32_t>(wrap.event) == firstHandle,
                "wrap event handle", static_cast<std::uint32_t>(wrap.event));
        Require(static_cast<std::uint32_t>(detector.Hottest() >> 32) == kGenerationCount,
                "wrap hottest reuse count", detector.Hottest() >> 32);
        Require(detector.SaturatedSlot() == 0, "valid wrap flagged detector mismatch");

        detector.Record((2u * kCapacity) | wrapSlot);
        Require(detector.SaturatedSlot() == wrapSlot + 1u,
                "fabricated generation mismatch was not surfaced", detector.SaturatedSlot());
        std::printf("WRAP: total=%llu reuse=%u handle=0x%08x staleAliasConfirmed=1\n",
                    static_cast<unsigned long long>(wrap.total),
                    static_cast<std::uint32_t>(wrap.event >> 32),
                    static_cast<std::uint32_t>(wrap.event));
    }

    ReportMemory("final peak with all assertions complete");
    const double totalSeconds =
        std::chrono::duration<double>(Clock::now() - totalStarted).count();
    std::printf("RESULT: PASS targetLive=%u pastCap=%u exactFifoReuse=%u wrapsAtReuse=%u "
                "elapsed=%.3f s\n",
                kTargetLive, kTargetLive - kStockCap + 1u, kReleaseCount,
                kGenerationCount, totalSeconds);
    return 0;
}
