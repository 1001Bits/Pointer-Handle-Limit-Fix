#pragma once

#include <cstdint>

namespace shcr
{
#pragma pack(push, 1)
    struct HandleEntry
    {
        std::uint32_t bits;
        std::uint32_t pad;
        void*         pointer;
    };
#pragma pack(pop)
    static_assert(sizeof(HandleEntry) == 0x10, "handle entry must be 16 bytes");

    struct HandleTableView
    {
        HandleEntry*  entries = nullptr;
        std::uint32_t count = 0;
    };
}
