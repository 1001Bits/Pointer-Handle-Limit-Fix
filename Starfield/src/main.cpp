// Pointer Handle Limit Fix for Starfield.
//
// The handle manager is published after construction and before the first handle is allocated.
// PatchTransaction owns that timing-sensitive six-field commit. This file deliberately remains
// orchestration-only, following the source layout used by the Skyrim implementation.

#include "Configuration.h"
#include "EngineAccess.h"
#include "FormAttribution.h"
#include "GenerationDiagnostic.h"
#include "HandleTable.h"
#include "PatchTransaction.h"
#include "RuntimeTypes.h"
#include "TableMonitor.h"

#include "SFSE/SFSE.h"

#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace logger = spdlog;
using namespace std::literals;

namespace sfhcr
{
    namespace
    {
        struct PluginState
        {
            Settings settings{};
            GenerationDiagnostic generation{};
            bool generationPrepared = false;
        };

        [[nodiscard]] PluginState& State()
        {
            // The installed vtable callback is process-lifetime state. Deliberately keep its
            // owner alive rather than running static destructors while the callback can exist.
            static PluginState* const state = new PluginState;
            return *state;
        }

        [[nodiscard]] std::string DescribeHandle(std::uint32_t a_handle)
        {
            auto reference = LookupReference(a_handle);
            if (!reference)
                return "not currently live";

            ObjectFields fields{};
            if (!SafeReadObject(reference.get(), fields) ||
                fields.nativeHandle != a_handle) {
                return "occupant changed";
            }

            const std::string plugin = PluginForForm(
                reference.get(), fields.formID, fields.sourceIndex);
            if ((fields.formID >> 24) == 0xffu) {
                if (auto base = reference->GetBaseObject()) {
                    const std::uint32_t baseID = base->GetFormID();
                    const std::string basePlugin = PluginForForm(
                        base.get(), baseID, base->loadOrderIndex);
                    return fmt::format(
                        "current ref [{:#010x}] \"{}\", base [{:#010x}] \"{}\"",
                        fields.formID,
                        plugin,
                        baseID,
                        basePlugin);
                }
            }
            return fmt::format(
                "current ref [{:#010x}] \"{}\"", fields.formID, plugin);
        }

        void OnTablePrepared(void* a_context, const HandleLayout& a_layout)
        {
            auto& state = *static_cast<PluginState*>(a_context);
            if (!state.settings.generationWrapDetection)
                return;

            state.generationPrepared = state.generation.Prepare(
                a_layout.capacity,
                a_layout.indexBits,
                a_layout.generationCount);
            if (!state.generationPrepared &&
                a_layout.indexBits == kHighCapIndexBits) {
                logger::warn(
                    "8M mode will continue without generation-wrap tracking because "
                    "the detector allocation failed");
            }
        }

        void OnTableCommitted(void* a_context, const HandleTableView& a_table)
        {
            auto& state = *static_cast<PluginState*>(a_context);
            if (state.generationPrepared &&
                !state.generation.Install({
                    a_table.manager,
                    a_table.layout.capacity,
                    a_table.layout.indexBits,
                    a_table.layout.generationCount
                })) {
                state.generation.ReleasePreparedStorage();
                state.generationPrepared = false;
                if (a_table.layout.indexBits == kHighCapIndexBits) {
                    logger::warn(
                        "8M mode is active without generation-wrap tracking because "
                        "the detector could not be installed");
                }
            }

            logger::info(
                "pool resized (verified): {} index bits, cap {} -> {} ({} "
                "generations), {} MiB @ {:#x}",
                a_table.layout.indexBits,
                kStockCap - 1,
                a_table.layout.UsableCapacity(),
                a_table.layout.generationCount,
                (a_table.layout.capacity * kPoolEntrySize) / (1024 * 1024),
                reinterpret_cast<std::uintptr_t>(a_table.pool));

            monitor::Run(a_table, state.settings, state.generation, &DescribeHandle);
        }

        void OnPatchAborted(void* a_context) noexcept
        {
            auto& state = *static_cast<PluginState*>(a_context);
            state.generation.ReleasePreparedStorage();
            state.generationPrepared = false;
        }
    }
}

SFSE_PLUGIN_LOAD(const SFSE::LoadInterface* a_sfse)
{
    if (a_sfse == nullptr ||
        (a_sfse->RuntimeVersion() != SFSE::RUNTIME_SF_1_16_236 &&
         a_sfse->RuntimeVersion() != SFSE::RUNTIME_SF_1_16_244)) {
        return false;
    }

    SFSE::Init(a_sfse, {
                           .logPattern = "[%H:%M:%S:%e] [%l] %v",
                           .trampoline = false,
    });

    auto& state = sfhcr::State();
    state.settings = sfhcr::LoadSettings();
    const sfhcr::HandleLayout layout =
        sfhcr::MakeHandleLayout(state.settings.targetIndexBits);

    spdlog::default_logger()->flush_on(spdlog::level::info);
    logger::info(
        "StarfieldHandleCapRaise loading; target index bits = {}, usable cap = {}, "
        "generations = {}",
        layout.indexBits,
        layout.UsableCapacity(),
        layout.generationCount);
    if (layout.indexBits == sfhcr::kHighCapIndexBits) {
        logger::warn(
            "8M mode enabled; replacement pool = 128 MiB, generations = 512");
        if (!state.settings.generationWrapDetection) {
            logger::warn("8M mode enabled without generation-wrap tracking");
        }
    }
    if (state.settings.verboseLogging) {
        logger::info(
            "verbose logging enabled; sample size = {}; detailed reports every minute",
            state.settings.detailedSampleCount);
    }

    return sfhcr::patch::Start(
        layout,
        {
            &state,
            &sfhcr::OnTablePrepared,
            &sfhcr::OnTableCommitted,
            &sfhcr::OnPatchAborted
        });
}

SFSE_PLUGIN_VERSION = []() noexcept {
    SFSE::PluginVersionData data{};
    data.PluginName("StarfieldHandleCapRaise");
    data.PluginVersion(REL::Version{ 1, 0, 1 });
    data.AuthorName("Starfield Handle Audit"sv);
    data.UsesAddressLibrary(true);
    data.UsesSigScanning(false);
    // Keep structure-independence flags clear so SFSE consults this exact whitelist.
    data.IsLayoutDependent(false);
    data.HasNoStructUse(false);
    data.MinimumRequiredXSEVersion(SFSE::SFSE_PACK_LATEST);
    data.CompatibleVersions({
        SFSE::RUNTIME_SF_1_16_236,
        SFSE::RUNTIME_SF_1_16_244
    });
    return data;
}();
