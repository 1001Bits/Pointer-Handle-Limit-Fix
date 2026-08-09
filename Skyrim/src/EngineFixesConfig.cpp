#include "EngineFixesConfig.h"

#include <iterator>

namespace shcr::enginefixes
{
    bool ParseVersionString(
        std::wstring_view a_text, FileVersion& a_version) noexcept
    {
        a_version = {};
        std::uint16_t components[4]{};
        std::size_t position = 0;

        for (std::size_t component = 0; component < std::size(components);
             ++component) {
            if (position == a_text.size() ||
                a_text[position] < L'0' || a_text[position] > L'9') {
                return false;
            }

            std::uint32_t value = 0;
            do {
                value = value * 10u +
                    static_cast<std::uint32_t>(a_text[position] - L'0');
                if (value > UINT16_MAX)
                    return false;
                ++position;
            } while (position < a_text.size() &&
                     a_text[position] >= L'0' && a_text[position] <= L'9');
            components[component] = static_cast<std::uint16_t>(value);

            if (component + 1 < std::size(components)) {
                if (position == a_text.size() || a_text[position] != L'.')
                    return false;
                ++position;
            }
        }

        if (position != a_text.size())
            return false;
        a_version = { components[0], components[1], components[2], components[3] };
        return true;
    }
}
