#pragma once

#include "GenerationTracker.h"

#include <cstdint>
#include <functional>
#include <string>

namespace sfhcr
{
    using AttributionCallback = std::function<std::string(std::uint32_t handle)>;

    struct GenerationInstallConfig
    {
        std::uintptr_t manager{};
        std::uint64_t capacity{};
        std::uint32_t indexBits{};
        std::uint32_t generationCount{};
    };

    // Best-effort observer. Failure to allocate or validate/install the callback disables only
    // generation diagnostics; callers may continue the cap raise without it.
    class GenerationDiagnostic
    {
    public:
        GenerationDiagnostic() = default;
        GenerationDiagnostic(const GenerationDiagnostic&) = delete;
        GenerationDiagnostic& operator=(const GenerationDiagnostic&) = delete;

        [[nodiscard]] bool Prepare(
            std::uint64_t capacity,
            std::uint32_t indexBits,
            std::uint32_t generationCount);
        [[nodiscard]] bool Install(const GenerationInstallConfig& config);
        void ReleasePreparedStorage() noexcept;

        [[nodiscard]] bool IsActive() const noexcept;
        [[nodiscard]] GenerationWrapSnapshot ReadWrapSnapshot() const noexcept;
        [[nodiscard]] GenerationReuseSnapshot ReadReuseSnapshot() const noexcept;
        [[nodiscard]] std::string ReuseStatus(
            const AttributionCallback& attribution = {}) const;

    private:
        using AssignNativeHandle = void (*)(std::uintptr_t, void*, std::uint32_t);
        static_assert(std::atomic<AssignNativeHandle>::is_always_lock_free);

        static void AssignNativeHandleHook(
            std::uintptr_t manager,
            void* object,
            std::uint32_t handle) noexcept;

        GenerationTracker tracker_{};
        std::atomic<bool> active_{ false };
        std::atomic<std::uintptr_t> trackedManager_{ 0 };
        std::atomic<AssignNativeHandle> originalAssignNativeHandle_{ nullptr };
    };

}
