#pragma once

#include "HandleTable.h"

namespace sfhcr::patch
{
    struct Lifecycle
    {
        void* context = nullptr;

        // Runs on the watcher after the replacement pool has been prepared,
        // but before the manager is published. This is where optional
        // sidecars can reserve their storage.
        void (*onPrepared)(void* a_context, const HandleLayout& a_layout) = nullptr;

        // Runs on the watcher after the six-field commit has read back
        // successfully. The replacement pool is engine-owned from this point.
        // This callback may block for the process lifetime (the monitor does).
        void (*onCommitted)(void* a_context, const HandleTableView& a_table) = nullptr;

        // Runs before prepared state is discarded after a safe refusal.
        void (*onAborted)(void* a_context) noexcept = nullptr;
    };

    // Starts the one-shot watcher thread. The layout and lifecycle are copied
    // into process-lifetime storage before the thread is created.
    [[nodiscard]] bool Start(
        const HandleLayout& a_layout,
        const Lifecycle& a_lifecycle) noexcept;
}
