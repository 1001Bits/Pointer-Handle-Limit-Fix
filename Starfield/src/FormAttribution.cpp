#include "FormAttribution.h"

#include "RE/T/TESFile.h"
#include "RE/T/TESForm.h"

#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace logger = spdlog;

namespace sfhcr
{
    namespace
    {
        enum class FormText : std::uint8_t
        {
            EditorID,
            ObjectType,
            DisplayName
        };

        // Copy engine-owned text into a bounded, single-line log string.  The
        // caller wraps this in SEH because a virtual method can still return a
        // bad pointer if an unsupported layout ever slips past the runtime
        // gates.  Quotes become apostrophes so fields remain unambiguous.
        void CopyLogText(
            const char* a_source,
            char* a_destination,
            std::size_t a_destinationSize) noexcept
        {
            if (a_destinationSize == 0)
                return;
            a_destination[0] = '\0';
            if (!a_source)
                return;

            std::size_t i = 0;
            for (; i + 1 < a_destinationSize; ++i) {
                const unsigned char character =
                    static_cast<unsigned char>(a_source[i]);
                if (character == 0)
                    break;
                if (character == '"')
                    a_destination[i] = '\'';
                else if (character < 0x20 || character == 0x7f)
                    a_destination[i] = ' ';
                else
                    a_destination[i] = static_cast<char>(character);
            }
            a_destination[i] = '\0';
        }

        // POD-only SEH body.  The reference/base form is pinned by an
        // NiPointer in the calling function.
        bool SafeReadFormText(
            RE::TESForm* a_form,
            FormText a_which,
            char* a_destination,
            std::size_t a_destinationSize) noexcept
        {
            __try {
                const char* text = nullptr;
                switch (a_which) {
                case FormText::EditorID:
                    text = a_form->GetFormEditorID();
                    break;
                case FormText::ObjectType:
                    text = a_form->GetObjectTypeName();
                    break;
                case FormText::DisplayName:
                    text = static_cast<RE::TESObjectREFR*>(a_form)->
                        GetDisplayFullName();
                    break;
                }
                CopyLogText(text, a_destination, a_destinationSize);
                return true;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                if (a_destinationSize != 0)
                    a_destination[0] = '\0';
                return false;
            }
        }

        bool SafeGetSourceFile(
            RE::TESForm* a_form,
            RE::TESFile** a_file) noexcept
        {
            __try {
                *a_file = a_form->GetRevertFile();
                return true;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                *a_file = nullptr;
                return false;
            }
        }

        [[nodiscard]] bool Readable(
            const void* a_pointer,
            std::size_t a_bytes) noexcept
        {
            if (!a_pointer || a_bytes == 0)
                return false;

            MEMORY_BASIC_INFORMATION memory{};
            if (::VirtualQuery(
                    a_pointer, std::addressof(memory), sizeof(memory)) == 0 ||
                memory.State != MEM_COMMIT ||
                (memory.Protect & PAGE_GUARD) != 0) {
                return false;
            }

            const DWORD protection = memory.Protect & 0xff;
            if (protection != PAGE_READONLY &&
                protection != PAGE_READWRITE &&
                protection != PAGE_WRITECOPY &&
                protection != PAGE_EXECUTE_READ &&
                protection != PAGE_EXECUTE_READWRITE &&
                protection != PAGE_EXECUTE_WRITECOPY) {
                return false;
            }

            const auto start = reinterpret_cast<std::uintptr_t>(a_pointer);
            const auto end =
                reinterpret_cast<std::uintptr_t>(memory.BaseAddress) +
                memory.RegionSize;
            return start <= end && a_bytes <= end - start;
        }

        [[nodiscard]] bool IsPluginNameCharacter(
            unsigned char a_character) noexcept
        {
            return (a_character >= 'A' && a_character <= 'Z') ||
                (a_character >= 'a' && a_character <= 'z') ||
                (a_character >= '0' && a_character <= '9') ||
                a_character == ' ' || a_character == '_' ||
                a_character == '-' || a_character == '.' ||
                a_character == '(' || a_character == ')' ||
                a_character == '\'' || a_character == '!' ||
                a_character == '+' || a_character == '&';
        }

        [[nodiscard]] std::string_view MatchPluginName(
            const std::uint8_t* a_pointer,
            std::size_t a_maximum) noexcept
        {
            std::size_t length = 0;
            while (length < a_maximum && a_pointer[length] != 0) {
                if (!IsPluginNameCharacter(a_pointer[length]))
                    return {};
                ++length;
            }
            if (length < 5 || length >= a_maximum ||
                a_pointer[length - 4] != '.') {
                return {};
            }

            const auto lower = [](unsigned char a_character) noexcept {
                return static_cast<char>(
                    (a_character >= 'A' && a_character <= 'Z') ?
                        a_character + ('a' - 'A') :
                        a_character);
            };
            const char first = lower(a_pointer[length - 3]);
            const char second = lower(a_pointer[length - 2]);
            const char third = lower(a_pointer[length - 1]);
            if (first != 'e' || second != 's' ||
                (third != 'm' && third != 'p' && third != 'l')) {
                return {};
            }
            return { reinterpret_cast<const char*>(a_pointer), length };
        }

        [[nodiscard]] std::string_view FindPluginNameInRange(
            const std::uint8_t* a_pointer,
            std::size_t a_maximum) noexcept
        {
            if (!Readable(a_pointer, a_maximum))
                return {};
            for (std::size_t offset = 0; offset + 5 < a_maximum; ++offset) {
                if (auto match = MatchPluginName(
                        a_pointer + offset, a_maximum - offset);
                    !match.empty()) {
                    return match;
                }
            }
            return {};
        }

        // CommonLibSF's public TESFile layout predates Starfield 1.16.x; its
        // declared fileName field is stale.  Find the stable NUL-terminated
        // plugin name in the live object or one of its header strings.
        [[nodiscard]] std::string PluginFileName(const RE::TESFile* a_file)
        {
            if (!a_file)
                return {};
            const auto* base =
                reinterpret_cast<const std::uint8_t*>(a_file);

            // Prefer an inline name so a dependency owned by TESFile cannot be
            // selected accidentally.
            if (auto name = FindPluginNameInRange(base, 0x800);
                !name.empty()) {
                return std::string(name);
            }

            // For layouts with an out-of-line name, follow only plausible,
            // readable header pointers.
            for (std::size_t slot = 0x18; slot <= 0x400; slot += 8) {
                if (!Readable(base + slot, sizeof(std::uintptr_t)))
                    continue;
                const auto candidate =
                    *reinterpret_cast<const std::uintptr_t*>(base + slot);
                if (candidate < 0x10000)
                    continue;
                const auto* target =
                    reinterpret_cast<const std::uint8_t*>(candidate);
                if (auto name = FindPluginNameInRange(target, 0x300);
                    !name.empty()) {
                    return std::string(name);
                }
            }
            return {};
        }
    }

    std::string PluginForForm(
        RE::TESForm* a_form,
        std::uint32_t a_formID,
        std::uint16_t a_sourceIndex)
    {
        if ((a_formID >> 24) == 0xffu)
            return "<runtime-created>";

        RE::TESFile* file = nullptr;
        if (a_form && SafeGetSourceFile(a_form, std::addressof(file))) {
            if (auto name = PluginFileName(file); !name.empty())
                return name;
        }
        return fmt::format("<source#{:#06x}>", a_sourceIndex);
    }

    const char* RefFormTypeName(std::uint8_t a_formType) noexcept
    {
        switch (a_formType) {
        case 0x4a: return "REFR";
        case 0x4b: return "ACHR";
        case 0x4c: return "PMIS";
        case 0x4d: return "PARW";
        case 0x4e: return "PGRE";
        case 0x4f: return "PBEA";
        case 0x50: return "PFLA";
        case 0x51: return "PCON";
        case 0x52: return "PPLA";
        case 0x53: return "PBAR";
        case 0x54: return "PEMI";
        case 0x55: return "PHZD";
        default: return nullptr;
        }
    }

    void LogDetailedSample(const CapturedReference& a_sample)
    {
        auto reference = LookupReference(a_sample.handle);
        const char* const formType = RefFormTypeName(a_sample.formType);
        if (!reference || reference->GetFormID() != a_sample.formID) {
            logger::info(
                "past-cap sample: ref=[{:#010x}] handle={:#010x} {} "
                "<no longer live>",
                a_sample.formID, a_sample.handle,
                formType ? formType : "unknown");
            return;
        }

        char referenceEditorID[160]{};
        char referenceDisplayName[160]{};
        SafeReadFormText(reference.get(), FormText::EditorID,
            referenceEditorID, sizeof(referenceEditorID));
        SafeReadFormText(reference.get(), FormText::DisplayName,
            referenceDisplayName, sizeof(referenceDisplayName));
        const std::string referencePlugin = PluginForForm(
            reference.get(), a_sample.formID, a_sample.sourceIndex);

        auto base = reference->GetBaseObject();
        if (!base) {
            logger::info(
                "past-cap sample: ref=[{:#010x}] \"{}\" {} edid=\"{}\" "
                "name=\"{}\" | base=<none>",
                a_sample.formID, referencePlugin,
                formType ? formType : "unknown",
                referenceEditorID[0] ? referenceEditorID : "<none>",
                referenceDisplayName[0] ?
                    referenceDisplayName : "<none>");
            return;
        }

        char baseEditorID[160]{};
        char baseType[80]{};
        SafeReadFormText(base.get(), FormText::EditorID,
            baseEditorID, sizeof(baseEditorID));
        SafeReadFormText(base.get(), FormText::ObjectType,
            baseType, sizeof(baseType));
        const std::uint32_t baseID = base->GetFormID();
        const std::string basePlugin = PluginForForm(
            base.get(), baseID, base->loadOrderIndex);

        logger::info(
            "past-cap sample: ref=[{:#010x}] \"{}\" {} edid=\"{}\" "
            "name=\"{}\" | base=[{:#010x}] \"{}\" {} edid=\"{}\"",
            a_sample.formID, referencePlugin,
            formType ? formType : "unknown",
            referenceEditorID[0] ? referenceEditorID : "<none>",
            referenceDisplayName[0] ? referenceDisplayName : "<none>",
            baseID, basePlugin, baseType[0] ? baseType : "unknown-type",
            baseEditorID[0] ? baseEditorID : "<none>");
    }
}
