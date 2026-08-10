#pragma once

#include "RuntimeTypes.h"
#include "StressTest.h"

#include <cstddef>

namespace shcr
{
    struct AttributionContext
    {
        const RuntimeContext* runtime = nullptr;
    };

    void CopyAttributionText(
        char* a_out,
        std::size_t a_capacity,
        const char* a_source,
        std::size_t a_sourceLimit) noexcept;

    bool ResolveStressAttribution(
        void* a_context,
        const void* a_reference,
        stress::ResolvedNames& a_names) noexcept;

    bool ResolveStressNames(
        void* a_context,
        const void* a_reference,
        stress::ResolvedNames& a_names) noexcept;

    void StressLog(void* a_context, const char* a_message) noexcept;
}
