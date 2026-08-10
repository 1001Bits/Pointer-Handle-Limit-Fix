#pragma once

#include "StressTest.h"

namespace shcr
{
    struct Settings
    {
        bool generationWrapDetection = true;
        stress::Settings stress;
    };

    [[nodiscard]] Settings LoadSettings() noexcept;
}
