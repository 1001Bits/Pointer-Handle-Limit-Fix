#include "EngineAccess.h"

#include "RuntimeTypes.h"

#include "REL/ID.h"
#include "REL/Relocation.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <memory>

namespace sfhcr
{
    namespace
    {
        // TESObjectREFR-family field offsets audited on both supported
        // runtimes.
        constexpr std::size_t kObjectNativeHandle = 0x24;
        constexpr std::size_t kObjectFormID = 0x28;
        constexpr std::size_t kObjectFormType = 0x2e;
        constexpr std::size_t kObjectSourceIndex = 0x30;

        using LookupReferenceByHandle = ReferencePtr* (*)(
            ReferencePtr*, std::uint32_t*);
    }

    ReferencePtr LookupReference(std::uint32_t a_handle)
    {
        // Address Library ID kID_LookupReferenceByHandle resolves to RVA
        // 0x2cf360 on 1.16.236 and 0x2cec10 on 1.16.244.  Unlike reading qword0
        // from the pool, this takes the manager read lock and pins the form.
        // Deliberately function-local: constructing this relocation before
        // SFSE::Init would make module initialization depend on loader order.
        static REL::Relocation<LookupReferenceByHandle> lookup{
            REL::ID(kID_LookupReferenceByHandle)
        };
        ReferencePtr result;
        lookup(std::addressof(result), std::addressof(a_handle));
        return result;
    }

    bool SafeReadObject(
        const void* a_object,
        ObjectFields& a_fields) noexcept
    {
        // POD-only SEH body: MSVC does not permit C++ objects requiring
        // unwinding in a function that uses __try.
        __try {
            const auto* object = static_cast<const std::uint8_t*>(a_object);
            a_fields.nativeHandle =
                *reinterpret_cast<const volatile std::uint32_t*>(
                    object + kObjectNativeHandle);
            a_fields.formID =
                *reinterpret_cast<const volatile std::uint32_t*>(
                    object + kObjectFormID);
            a_fields.formType =
                *reinterpret_cast<const volatile std::uint8_t*>(
                    object + kObjectFormType);
            a_fields.sourceIndex =
                *reinterpret_cast<const volatile std::uint16_t*>(
                    object + kObjectSourceIndex);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }
}
