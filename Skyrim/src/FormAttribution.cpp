#include "FormAttribution.h"

#include "Logging.h"

#include <algorithm>
#include <cstdint>
#include <cstring>

namespace shcr
{
    namespace
    {
        struct RawStaticArray
        {
            void**       data;
            std::uint32_t size;
            std::uint32_t pad0C;
        };
        static_assert(sizeof(RawStaticArray) == 0x10);

        template <std::size_t N>
        void CopyGameText(
            char (&a_out)[N],
            const char* a_source,
            std::size_t a_sourceLimit = N - 1) noexcept
        {
            CopyAttributionText(a_out, N, a_source, a_sourceLimit);
        }

        template <std::size_t N>
        void CopyPluginName(char (&a_out)[N], const void* a_file) noexcept
        {
            if (!a_file) {
                a_out[0] = '\0';
                return;
            }
            CopyGameText(
                a_out, static_cast<const char*>(a_file) + 0x58, 260);
        }

        template <std::size_t A, std::size_t B>
        bool ResolvePlugins(
            const void* a_form,
            char (&a_origin)[A],
            char (&a_winner)[B]) noexcept
        {
            if (!a_form)
                return false;
            const auto* bytes = static_cast<const std::uint8_t*>(a_form);
            const auto* files = *reinterpret_cast<RawStaticArray* const*>(
                bytes + 0x08);
            if (!files || !files->data || files->size == 0 ||
                files->size > 0x1000) {
                return false;
            }
            CopyPluginName(a_origin, files->data[0]);
            CopyPluginName(a_winner, files->data[files->size - 1]);
            return a_origin[0] != '\0' || a_winner[0] != '\0';
        }

        template <std::size_t N>
        void ResolveEditorID(const void* a_form, char (&a_out)[N]) noexcept
        {
            if (!a_form)
                return;
            auto** vtable = *reinterpret_cast<void***>(
                const_cast<void*>(a_form));
            if (!vtable)
                return;
            using Function = const char* (__fastcall*)(const void*);
            const auto function = reinterpret_cast<Function>(vtable[0x32]);
            if (function)
                CopyGameText(a_out, function(a_form));
        }

        template <std::size_t N>
        void ResolveDetailedName(void* a_form, char (&a_out)[N]) noexcept
        {
            if (!a_form)
                return;
            auto** vtable = *reinterpret_cast<void***>(a_form);
            if (!vtable)
                return;
            using Function = void (__fastcall*)(void*, char*, std::uint32_t);
            const auto function = reinterpret_cast<Function>(vtable[0x16]);
            if (function)
                function(a_form, a_out, static_cast<std::uint32_t>(N));
            a_out[N - 1] = '\0';
        }
    }

    void CopyAttributionText(
        char* a_out,
        std::size_t a_capacity,
        const char* a_source,
        std::size_t a_sourceLimit) noexcept
    {
        if (!a_out || a_capacity == 0)
            return;
        if (!a_source) {
            a_out[0] = '\0';
            return;
        }
        const std::size_t length = strnlen_s(
            a_source, (std::min)(a_sourceLimit, a_capacity - 1));
        std::memcpy(a_out, a_source, length);
        a_out[length] = '\0';
    }

    bool ResolveStressAttribution(
        void*,
        const void* a_reference,
        stress::ResolvedNames& a_names) noexcept
    {
        if (!a_reference)
            return false;
        bool attributed = ResolvePlugins(
            a_reference, a_names.originPlugin, a_names.winningPlugin);
        const std::uint32_t referenceFormId =
            *reinterpret_cast<const std::uint32_t*>(
                static_cast<const std::uint8_t*>(a_reference) + 0x14);
        if (a_names.originPlugin[0] == '\0' &&
            (referenceFormId >> 24) == 0xFF) {
            CopyGameText(a_names.originPlugin, "<dynamic>");
            attributed = true;
        }

        const void* base = *reinterpret_cast<void* const*>(
            static_cast<const std::uint8_t*>(a_reference) + 0x40);
        if (base) {
            a_names.baseFormID = *reinterpret_cast<const std::uint32_t*>(
                static_cast<const std::uint8_t*>(base) + 0x14);
            attributed = ResolvePlugins(base,
                a_names.baseOriginPlugin, a_names.baseWinningPlugin) ||
                attributed;
            if (a_names.baseOriginPlugin[0] == '\0' &&
                (a_names.baseFormID >> 24) == 0xFF) {
                CopyGameText(a_names.baseOriginPlugin, "<dynamic>");
                attributed = true;
            }
        }
        return attributed;
    }

    bool ResolveStressNames(
        void* a_context,
        const void* a_reference,
        stress::ResolvedNames& a_names) noexcept
    {
        if (!a_reference)
            return false;
        const bool attributed = ResolveStressAttribution(
            a_context, a_reference, a_names);
        auto* reference = const_cast<void*>(a_reference);
        ResolveDetailedName(reference, a_names.formName);
        ResolveEditorID(a_reference, a_names.editorID);

        const auto* attribution = static_cast<const AttributionContext*>(
            a_context);
        if (!attribution || !attribution->runtime ||
            attribution->runtime->offsets.displayNameRva == 0) {
            return false;
        }
        using DisplayNameFunction = const char* (__fastcall*)(void*);
        const auto displayName = reinterpret_cast<DisplayNameFunction>(
            attribution->runtime->imageBase +
            attribution->runtime->offsets.displayNameRva);
        CopyGameText(a_names.displayName, displayName(reference));

        void* base = *reinterpret_cast<void**>(
            static_cast<std::uint8_t*>(reference) + 0x40);
        if (base) {
            ResolveDetailedName(base, a_names.baseName);
            ResolveEditorID(base, a_names.baseEditorID);
        }
        const bool hasIdentity = a_names.formName[0] != '\0' ||
            a_names.editorID[0] != '\0' ||
            a_names.displayName[0] != '\0' ||
            a_names.baseName[0] != '\0' ||
            a_names.baseEditorID[0] != '\0';
        return attributed && hasIdentity;
    }

    void StressLog(void*, const char* a_message) noexcept
    {
        Log("%s", a_message ? a_message : "");
    }
}
