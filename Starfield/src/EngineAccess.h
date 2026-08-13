#pragma once

#include "RE/T/TESObjectREFR.h"

#include <cstdint>

namespace sfhcr
{
    using ReferencePtr = RE::NiPointer<RE::TESObjectREFR>;

    // Raw fields captured from a TESObjectREFR-family object.  Keeping this
    // type POD lets SafeReadObject isolate the volatile engine-memory reads in
    // an MSVC SEH body without introducing objects that require unwinding.
    struct ObjectFields
    {
        std::uint32_t nativeHandle = 0;
        std::uint32_t formID = 0;
        std::uint16_t sourceIndex = 0xffff;
        std::uint8_t formType = 0;
    };

    // Resolves through Starfield's owning handle lookup.  The relocation is
    // initialized lazily on first use, after SFSE::Init has run.
    [[nodiscard]] ReferencePtr LookupReference(std::uint32_t a_handle);

    // Reads the four audited object fields without allowing a stale pool
    // pointer to fault the reporting thread.
    [[nodiscard]] bool SafeReadObject(
        const void* a_object,
        ObjectFields& a_fields) noexcept;
}
