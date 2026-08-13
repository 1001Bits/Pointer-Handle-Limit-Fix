#include "PatchTransaction.h"

#include "RuntimeTypes.h"

#include "REL/ID.h"

#include <spdlog/spdlog.h>

#include <Windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace logger = spdlog;

namespace sfhcr::patch
{
    namespace
    {
        constexpr std::uint64_t kSlowStartupWarningMilliseconds = 120'000;

        enum class Commit
        {
            Done,
            Refused
        };

        struct State
        {
            HandleLayout layout{};
            Lifecycle lifecycle{};
            std::uint8_t* newPool = nullptr;
        };

        State g_state;
        std::atomic<bool> g_started{ false };

        template <class T>
        [[nodiscard]] T* At(std::uintptr_t a_address) noexcept
        {
            return reinterpret_cast<T*>(a_address);
        }

        [[nodiscard]] bool PreparePool() noexcept
        {
            const std::size_t poolSize =
                static_cast<std::size_t>(g_state.layout.capacity) * kPoolEntrySize;
            g_state.newPool = static_cast<std::uint8_t*>(
                ::VirtualAlloc(
                    nullptr,
                    poolSize,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE));
            if (g_state.newPool == nullptr) {
                logger::error("VirtualAlloc({} bytes) failed; no resize", poolSize);
                return false;
            }

            // Index zero remains the reserved null handle. Slots 1..capacity-1
            // form the same FIFO threaded free list as the engine's stock pool.
            for (std::uint64_t index = 1; index < g_state.layout.capacity; ++index) {
                *reinterpret_cast<std::uint64_t*>(
                    g_state.newPool + index * kPoolEntrySize + 8) =
                    (index + 1 < g_state.layout.capacity) ? index + 1 : 0;
            }
            return true;
        }

        void ReleasePool() noexcept
        {
            if (g_state.newPool != nullptr) {
                ::VirtualFree(g_state.newPool, 0, MEM_RELEASE);
                g_state.newPool = nullptr;
            }
        }

        [[nodiscard]] Commit TryCommit(std::uintptr_t a_manager) noexcept
        {
            auto* const pool = At<volatile std::uint64_t>(a_manager + kOff_PoolPtr);
            auto* const head = At<volatile std::uint32_t>(a_manager + kOff_FreeHead);
            auto* const tail = At<volatile std::uint32_t>(a_manager + kOff_FreeTail);
            auto* const counter = At<volatile std::uint32_t>(a_manager + kOff_FreeCounter);
            auto* const capacity = At<volatile std::uint32_t>(a_manager + kOff_Capacity);
            auto* const mask = At<volatile std::uint32_t>(a_manager + kOff_IndexMask);

            const std::uint64_t oldPool = *pool;
            const std::uint32_t oldHead = *head;
            const std::uint32_t oldTail = *tail;
            const std::uint32_t oldCounter = *counter;
            const std::uint32_t oldCapacity = *capacity;
            const std::uint32_t oldMask = *mask;

            if (oldHead != 1 || oldTail != kStockCap - 1 ||
                oldCounter != kStockFreeCount || oldCapacity != kStockCap ||
                oldMask != kStockCap - 1 || oldPool == 0) {
                logger::error(
                    "manager not in the exact stock shape (head={:#x} tail={:#x} "
                    "freeCtr={:#x} cap={:#x} mask={:#x} pool={:#x}); refusing to "
                    "resize — either handles are already in use or the struct layout "
                    "differs on this game version",
                    oldHead,
                    oldTail,
                    oldCounter,
                    oldCapacity,
                    oldMask,
                    oldPool);
                return Commit::Refused;
            }

            const std::uint32_t newMask = g_state.layout.IndexMask();
            const std::uint32_t newCapacity =
                static_cast<std::uint32_t>(g_state.layout.capacity);

            *pool = reinterpret_cast<std::uint64_t>(g_state.newPool);
            *head = 1;
            *tail = newMask;
            *counter = newCapacity;
            *capacity = newCapacity;
            *mask = newMask;

            if (*pool != reinterpret_cast<std::uint64_t>(g_state.newPool) ||
                *head != 1 || *tail != newMask || *counter != newCapacity ||
                *capacity != newCapacity || *mask != newMask) {
                *pool = oldPool;
                *head = oldHead;
                *tail = oldTail;
                *counter = oldCounter;
                *capacity = oldCapacity;
                *mask = oldMask;
                logger::error(
                    "read-back mismatch after swap; reverted to the stock pool");
                return Commit::Refused;
            }

            return Commit::Done;
        }

        DWORD WINAPI WatcherThread(void*)
        {
            if (!PreparePool())
                return 0;

            if (g_state.lifecycle.onPrepared != nullptr) {
                g_state.lifecycle.onPrepared(
                    g_state.lifecycle.context,
                    g_state.layout);
            }

            auto* const singleton = At<volatile std::uintptr_t>(
                REL::ID(kID_SingletonPtr).address());
            const std::uint64_t warningAt =
                ::GetTickCount64() + kSlowStartupWarningMilliseconds;
            bool warningLogged = false;

            for (;;) {
                const std::uintptr_t manager = *singleton;
                if (manager != 0) {
                    if (TryCommit(manager) == Commit::Done) {
                        const HandleTableView table{
                            manager,
                            g_state.newPool,
                            g_state.layout
                        };
                        if (g_state.lifecycle.onCommitted != nullptr) {
                            g_state.lifecycle.onCommitted(
                                g_state.lifecycle.context,
                                table);
                        }
                        return 0;
                    }

                    if (g_state.lifecycle.onAborted != nullptr) {
                        g_state.lifecycle.onAborted(g_state.lifecycle.context);
                    }
                    ReleasePool();
                    return 0;
                }

                if (!warningLogged && ::GetTickCount64() >= warningAt) {
                    logger::warn(
                        "handle manager not ready after 120 seconds; continuing to "
                        "wait without a timeout");
                    warningLogged = true;
                }
                ::Sleep(1);
            }
        }
    }

    bool Start(
        const HandleLayout& a_layout,
        const Lifecycle& a_lifecycle) noexcept
    {
        bool expected = false;
        if (!g_started.compare_exchange_strong(
                expected,
                true,
                std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            logger::error("handle-manager watcher was already started");
            return false;
        }

        g_state.layout = a_layout;
        g_state.lifecycle = a_lifecycle;

        if (HANDLE thread =
                ::CreateThread(nullptr, 0, &WatcherThread, nullptr, 0, nullptr)) {
            ::CloseHandle(thread);
            return true;
        }

        g_started.store(false, std::memory_order_release);
        logger::error("failed to start watcher thread");
        return false;
    }
}
