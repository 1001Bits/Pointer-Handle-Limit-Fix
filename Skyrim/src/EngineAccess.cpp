#include "EngineAccess.h"

#include "PatchTable.g.h"

#include <windows.h>

#include <cstdint>

namespace shcr
{
    namespace
    {
        using ManagerLockFunction = void (__fastcall*)(void*);
        using GetSmartPointerFunction = bool (__fastcall*)(
            const std::uint32_t*, void**);
    }

    void LockManager(
        const RuntimeContext& a_runtime,
        const Profile& a_profile) noexcept
    {
        const auto function = reinterpret_cast<ManagerLockFunction>(
            a_runtime.imageBase + a_profile.lockWriteRva);
        function(reinterpret_cast<void*>(
            a_runtime.imageBase + a_profile.lockRva));
    }

    void UnlockManager(
        const RuntimeContext& a_runtime,
        const Profile& a_profile) noexcept
    {
        const auto function = reinterpret_cast<ManagerLockFunction>(
            a_runtime.imageBase + a_profile.unlockWriteRva);
        function(reinterpret_cast<void*>(
            a_runtime.imageBase + a_profile.lockRva));
    }

    bool ResolveSmartPointer(
        const RuntimeContext& a_runtime,
        std::uint32_t a_handle,
        void*& a_reference) noexcept
    {
        a_reference = nullptr;
        if (a_runtime.offsets.getSmartPointerRva == 0)
            return false;
        const auto function = reinterpret_cast<GetSmartPointerFunction>(
            a_runtime.imageBase +
            a_runtime.offsets.getSmartPointerRva);
        return function(&a_handle, &a_reference);
    }

    void ReleasePinnedReference(void* a_reference) noexcept
    {
        if (!a_reference)
            return;
        auto* word = reinterpret_cast<volatile LONG*>(
            static_cast<std::uint8_t*>(a_reference) + 0x28);
        const std::uint32_t after = static_cast<std::uint32_t>(
            InterlockedDecrement(word));
        if ((after & 0x3FFu) != 0)
            return;
        auto* subobject = static_cast<std::uint8_t*>(a_reference) + 0x20;
        auto** vtable = *reinterpret_cast<void***>(subobject);
        if (vtable && vtable[1]) {
            using DeleteThisFunction = void (__fastcall*)(void*);
            reinterpret_cast<DeleteThisFunction>(vtable[1])(subobject);
        }
    }
}
