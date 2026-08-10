#pragma once

#include "RuntimeTypes.h"

namespace shcr
{
    [[nodiscard]] bool DetectRuntime(RuntimeContext& a_context) noexcept;
    void LogEngineFixesCompatibility() noexcept;
}
