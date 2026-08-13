#include "GenerationDiagnostic.h"

#include "RuntimeTypes.h"

#include "REL/Utility.h"
#include "SFSE/SFSE.h"

#include <Windows.h>

#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <cstddef>

namespace logger = spdlog;

namespace
{
    std::atomic<sfhcr::GenerationDiagnostic*> g_installedDiagnostic{ nullptr };
}

namespace sfhcr
{
    bool GenerationTracker::Prepare(const GenerationTrackerConfig& config)
    {
        Release();
        if (!config.IsValid()) {
            logger::error(
                "generation detector received invalid geometry (capacity {}, index bits {}, "
                "generations {}); detector disabled",
                config.capacity,
                config.indexBits,
                config.generationCount);
            return false;
        }

        const std::size_t bytes =
            static_cast<std::size_t>(config.capacity) * sizeof(std::uint16_t);
        slotAssignments_ = static_cast<std::uint16_t*>(
            ::VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (slotAssignments_ == nullptr) {
            logger::error(
                "generation detector VirtualAlloc({} bytes) failed; detector disabled", bytes);
            return false;
        }

        config_ = config;
        return true;
    }

    void GenerationTracker::Release() noexcept
    {
        if (slotAssignments_ != nullptr) {
            ::VirtualFree(slotAssignments_, 0, MEM_RELEASE);
            slotAssignments_ = nullptr;
        }
        config_ = {};
        hottestHandle_.store(0, std::memory_order_relaxed);
        generationWraps_.store(0, std::memory_order_relaxed);
        lastWrapEvent_.store(0, std::memory_order_relaxed);
        wrapEventSequence_.store(0, std::memory_order_relaxed);
        unreliableSlotPlusOne_.store(0, std::memory_order_relaxed);
    }

    void GenerationTracker::RecordAssignment(std::uint32_t handle) noexcept
    {
        if (handle == 0 || slotAssignments_ == nullptr) return;

        const std::uint32_t index =
            handle & static_cast<std::uint32_t>(config_.capacity - 1);
        const std::uint16_t generation =
            static_cast<std::uint16_t>(handle >> config_.indexBits);
        const std::uint16_t assignments = slotAssignments_[index];
        if (assignments == 0xffffu) {
            std::uint32_t unset = 0;
            unreliableSlotPlusOne_.compare_exchange_strong(
                unset, index + 1, std::memory_order_release, std::memory_order_relaxed);
            return;
        }
        slotAssignments_[index] = static_cast<std::uint16_t>(assignments + 1);

        // Before this assignment, assignments is exactly the number of previous uses of this
        // slot. A non-zero multiple of the generation count is a wrap.
        const std::uint32_t reuses = assignments;
        if (reuses != 0 && (reuses % config_.generationCount) == 0) {
            wrapEventSequence_.fetch_add(1, std::memory_order_acq_rel);
            lastWrapEvent_.store(
                (static_cast<std::uint64_t>(reuses) << 32) | handle,
                std::memory_order_relaxed);
            generationWraps_.fetch_add(1, std::memory_order_relaxed);
            wrapEventSequence_.fetch_add(1, std::memory_order_release);
        }

        if (generation !=
            static_cast<std::uint16_t>(reuses % config_.generationCount)) {
            std::uint32_t unset = 0;
            unreliableSlotPlusOne_.compare_exchange_strong(
                unset, index + 1, std::memory_order_release, std::memory_order_relaxed);
        }

        if (reuses != 0) {
            const std::uint64_t candidate =
                (static_cast<std::uint64_t>(reuses) << 32) | handle;
            std::uint64_t hottest = hottestHandle_.load(std::memory_order_relaxed);
            while (reuses > static_cast<std::uint32_t>(hottest >> 32) &&
                   !hottestHandle_.compare_exchange_weak(
                       hottest,
                       candidate,
                       std::memory_order_release,
                       std::memory_order_relaxed)) {
            }
        }
    }

    bool GenerationTracker::IsPrepared() const noexcept
    {
        return slotAssignments_ != nullptr;
    }

    const GenerationTrackerConfig& GenerationTracker::Config() const noexcept
    {
        return config_;
    }

    GenerationWrapSnapshot GenerationTracker::ReadWrapSnapshot() const noexcept
    {
        GenerationWrapSnapshot snapshot{};
        std::uint32_t before = 0;
        std::uint32_t after = 0;
        do {
            before = wrapEventSequence_.load(std::memory_order_acquire);
            if ((before & 1u) != 0) continue;
            snapshot.total = generationWraps_.load(std::memory_order_relaxed);
            snapshot.event = lastWrapEvent_.load(std::memory_order_relaxed);
            after = wrapEventSequence_.load(std::memory_order_acquire);
        } while (before != after || (after & 1u) != 0);
        return snapshot;
    }

    GenerationReuseSnapshot GenerationTracker::ReadReuseSnapshot() const noexcept
    {
        const std::uint64_t hottest = hottestHandle_.load(std::memory_order_acquire);
        const std::uint32_t handle = static_cast<std::uint32_t>(hottest);
        return {
            .highestReuse = static_cast<std::uint32_t>(hottest >> 32),
            .hottestHandle = handle,
            .hottestSlot = config_.capacity == 0 ? 0 :
                handle & static_cast<std::uint32_t>(config_.capacity - 1),
            .wraps = generationWraps_.load(std::memory_order_acquire),
            .unreliableSlotPlusOne =
                unreliableSlotPlusOne_.load(std::memory_order_acquire),
        };
    }

    bool GenerationDiagnostic::Prepare(
        std::uint64_t capacity,
        std::uint32_t indexBits,
        std::uint32_t generationCount)
    {
        if (active_.load(std::memory_order_acquire)) {
            logger::error("generation detector is already installed; prepare refused");
            return false;
        }
        return tracker_.Prepare({ capacity, indexBits, generationCount });
    }

    bool GenerationDiagnostic::Install(const GenerationInstallConfig& config)
    {
        const GenerationTrackerConfig expected{
            config.capacity, config.indexBits, config.generationCount
        };
        if (config.manager == 0 || !expected.IsValid() || !tracker_.IsPrepared() ||
            tracker_.Config().capacity != config.capacity ||
            tracker_.Config().indexBits != config.indexBits ||
            tracker_.Config().generationCount != config.generationCount) {
            logger::error(
                "generation detector install geometry disagrees with prepared storage; detector "
                "disabled");
            return false;
        }

        GenerationDiagnostic* unset = nullptr;
        if (!g_installedDiagnostic.compare_exchange_strong(
                unset, this, std::memory_order_acq_rel, std::memory_order_acquire)) {
            logger::error("another generation detector is already installed; detector disabled");
            return false;
        }

        const std::uintptr_t vtable =
            *reinterpret_cast<const std::uintptr_t*>(config.manager);
        const std::uintptr_t expectedVtable =
            REL::ID(kID_HandleManagerVtable).address();
        const std::uintptr_t expectedCallback =
            REL::ID(kID_AssignNativeHandle).address();
        if (vtable != expectedVtable) {
            logger::error(
                "generation detector found unexpected manager vtable ({:#x}, expected {:#x}); "
                "detector disabled",
                vtable,
                expectedVtable);
            g_installedDiagnostic.store(nullptr, std::memory_order_release);
            return false;
        }

        const std::uintptr_t slot =
            vtable + kAssignNativeHandleSlot * sizeof(std::uintptr_t);
        const std::uintptr_t original =
            *reinterpret_cast<const std::uintptr_t*>(slot);
        if (original != expectedCallback) {
            logger::error(
                "generation detector found unexpected slot-2 callback ({:#x}, expected {:#x}); "
                "detector disabled",
                original,
                expectedCallback);
            g_installedDiagnostic.store(nullptr, std::memory_order_release);
            return false;
        }

        originalAssignNativeHandle_.store(
            reinterpret_cast<AssignNativeHandle>(original), std::memory_order_release);
        trackedManager_.store(config.manager, std::memory_order_release);
        const std::uintptr_t hook =
            reinterpret_cast<std::uintptr_t>(&AssignNativeHandleHook);
        const bool protectionRestored = REL::WriteSafeData(slot, hook);
        if (*reinterpret_cast<const std::uintptr_t*>(slot) != hook) {
            trackedManager_.store(0, std::memory_order_release);
            originalAssignNativeHandle_.store(nullptr, std::memory_order_release);
            g_installedDiagnostic.store(nullptr, std::memory_order_release);
            logger::error(
                "generation detector could not install its callback; detector disabled");
            return false;
        }
        if (!protectionRestored) {
            logger::warn(
                "generation detector installed, but restoring vtable page protection reported "
                "a failure");
        }
        active_.store(true, std::memory_order_release);
        return true;
    }

    void GenerationDiagnostic::ReleasePreparedStorage() noexcept
    {
        // An installed vtable hook is process-lifetime state and cannot safely be torn down while
        // engine calls may be in flight. Only uninstalled prepared storage is releasable.
        if (active_.load(std::memory_order_acquire)) return;
        trackedManager_.store(0, std::memory_order_release);
        originalAssignNativeHandle_.store(nullptr, std::memory_order_release);
        GenerationDiagnostic* expected = this;
        g_installedDiagnostic.compare_exchange_strong(
            expected, nullptr, std::memory_order_acq_rel, std::memory_order_acquire);
        tracker_.Release();
    }

    bool GenerationDiagnostic::IsActive() const noexcept
    {
        return active_.load(std::memory_order_acquire);
    }

    GenerationWrapSnapshot GenerationDiagnostic::ReadWrapSnapshot() const noexcept
    {
        return tracker_.ReadWrapSnapshot();
    }

    GenerationReuseSnapshot GenerationDiagnostic::ReadReuseSnapshot() const noexcept
    {
        return tracker_.ReadReuseSnapshot();
    }

    std::string GenerationDiagnostic::ReuseStatus(
        const AttributionCallback& attribution) const
    {
        const GenerationReuseSnapshot snapshot = tracker_.ReadReuseSnapshot();
        const std::uint32_t generations = tracker_.Config().generationCount;
        const char* reliability =
            snapshot.unreliableSlotPlusOne == 0 ? "" : ", tracking UNRELIABLE";
        if (snapshot.highestReuse == 0) {
            return fmt::format(
                "generation reuse: highest 0 / {}, hottest slot n/a, wraps {}{}",
                generations,
                snapshot.wraps,
                reliability);
        }

        std::string attributionText;
        if (attribution) {
            attributionText = attribution(snapshot.hottestHandle);
        }
        if (attributionText.empty()) {
            attributionText = "not currently attributed";
        }
        return fmt::format(
            "generation reuse: highest {} / {} at slot {} (handle {:#010x}, {}), wraps {}{}",
            snapshot.highestReuse,
            generations,
            snapshot.hottestSlot,
            snapshot.hottestHandle,
            attributionText,
            snapshot.wraps,
            reliability);
    }

    void GenerationDiagnostic::AssignNativeHandleHook(
        std::uintptr_t manager,
        void* object,
        std::uint32_t handle) noexcept
    {
        GenerationDiagnostic* diagnostic =
            g_installedDiagnostic.load(std::memory_order_acquire);
        if (diagnostic == nullptr) return;

        const AssignNativeHandle original =
            diagnostic->originalAssignNativeHandle_.load(std::memory_order_acquire);
        if (original == nullptr) return;
        original(manager, object, handle);
        if (object != nullptr &&
            manager == diagnostic->trackedManager_.load(std::memory_order_acquire)) {
            diagnostic->tracker_.RecordAssignment(handle);
        }
    }
}
