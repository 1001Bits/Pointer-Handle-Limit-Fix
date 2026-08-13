#pragma once

#include "EngineAccess.h"

#include <cstdint>
#include <string>

namespace sfhcr
{
    struct CapturedReference
    {
        std::uint32_t handle = 0;
        std::uint32_t formID = 0;
        std::uint16_t sourceIndex = 0xffff;
        std::uint8_t formType = 0;
    };

    // Returns the source plugin, "<runtime-created>", or the stable numeric
    // source-index fallback used by the existing reports.
    [[nodiscard]] std::string PluginForForm(
        RE::TESForm* a_form,
        std::uint32_t a_formID,
        std::uint16_t a_sourceIndex);

    [[nodiscard]] const char* RefFormTypeName(
        std::uint8_t a_formType) noexcept;

    // Re-resolves the sample through Starfield's owning lookup before calling
    // any virtual form/name method, then emits the existing detailed log row.
    void LogDetailedSample(const CapturedReference& a_sample);
}
