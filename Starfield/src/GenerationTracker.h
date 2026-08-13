#pragma once

#include <atomic>
#include <cstdint>

namespace sfhcr
{
    struct GenerationTrackerConfig
    {
        std::uint64_t capacity{};
        std::uint32_t indexBits{};
        std::uint32_t generationCount{};

        [[nodiscard]] constexpr bool IsValid() const noexcept
        {
            return capacity >= 2 && capacity <= (1ull << 31) &&
                   (capacity & (capacity - 1)) == 0 &&
                   indexBits > 0 && indexBits < 32 &&
                   capacity == (1ull << indexBits) &&
                   generationCount == (1u << (32u - indexBits));
        }
    };

    struct GenerationWrapSnapshot
    {
        std::uint64_t total{};
        std::uint64_t event{};  // high dword = reuse count, low dword = new handle
    };

    struct GenerationReuseSnapshot
    {
        std::uint32_t highestReuse{};
        std::uint32_t hottestHandle{};
        std::uint32_t hottestSlot{};
        std::uint64_t wraps{};
        std::uint32_t unreliableSlotPlusOne{};
    };

    // Owns one 16-bit assignment count per handle slot. RecordAssignment is intentionally
    // lock-free: the engine invokes it while holding the handle manager's exclusive lock.
    class GenerationTracker
    {
    public:
        GenerationTracker() = default;
        GenerationTracker(const GenerationTracker&) = delete;
        GenerationTracker& operator=(const GenerationTracker&) = delete;
        // Storage is explicitly released on uninstalled/refused paths. Once the engine callback
        // is installed, both the tracker and its sidecar intentionally live for the process.
        ~GenerationTracker() = default;

        [[nodiscard]] bool Prepare(const GenerationTrackerConfig& config);
        void Release() noexcept;
        void RecordAssignment(std::uint32_t handle) noexcept;

        [[nodiscard]] bool IsPrepared() const noexcept;
        [[nodiscard]] const GenerationTrackerConfig& Config() const noexcept;
        [[nodiscard]] GenerationWrapSnapshot ReadWrapSnapshot() const noexcept;
        [[nodiscard]] GenerationReuseSnapshot ReadReuseSnapshot() const noexcept;

    private:
        GenerationTrackerConfig config_{};
        std::uint16_t* slotAssignments_{};
        std::atomic<std::uint64_t> hottestHandle_{ 0 };
        std::atomic<std::uint64_t> generationWraps_{ 0 };
        std::atomic<std::uint64_t> lastWrapEvent_{ 0 };
        std::atomic<std::uint32_t> wrapEventSequence_{ 0 };
        std::atomic<std::uint32_t> unreliableSlotPlusOne_{ 0 };
    };

    static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
}
