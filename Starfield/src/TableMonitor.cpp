#include "TableMonitor.h"

#include "EngineAccess.h"
#include "FormAttribution.h"
#include "RuntimeTypes.h"

#include <Windows.h>

#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace logger = spdlog;

namespace sfhcr::monitor
{
    namespace
    {
        constexpr DWORD kReportTickMilliseconds = 60'000;
        constexpr std::uint64_t kNormalReportMinutes = 5;

        struct SourceBucket
        {
            std::uint32_t count{};
            std::uint32_t sampleHandle{};
            std::uint32_t sampleFormID{};
            std::uint16_t sourceIndex{};
        };

        [[nodiscard]] std::array<SourceBucket, 6> TopSources(
            const std::vector<std::uint32_t>& counts,
            const std::vector<CapturedReference>& samples)
        {
            std::array<SourceBucket, 6> top{};
            for (std::size_t source = 0; source < counts.size(); ++source) {
                const std::uint32_t count = counts[source];
                if (count == 0 || count <= top.back().count)
                    continue;

                SourceBucket bucket{};
                bucket.count = count;
                bucket.sourceIndex = static_cast<std::uint16_t>(source);
                bucket.sampleHandle = samples[source].handle;
                bucket.sampleFormID = samples[source].formID;

                std::size_t position = top.size() - 1;
                while (position > 0 && bucket.count > top[position - 1].count) {
                    top[position] = top[position - 1];
                    --position;
                }
                top[position] = bucket;
            }
            return top;
        }

        [[nodiscard]] std::string FormatSourceBuckets(
            const std::array<SourceBucket, 6>& buckets)
        {
            std::string output;
            for (const auto& bucket : buckets) {
                if (bucket.count == 0)
                    break;
                auto reference = LookupReference(bucket.sampleHandle);
                const std::string plugin = PluginForForm(
                    reference ? static_cast<RE::TESForm*>(reference.get()) : nullptr,
                    bucket.sampleFormID,
                    bucket.sourceIndex);
                output += fmt::format("\"{}\" {}, ", plugin, bucket.count);
            }
            return output;
        }

        template <class Label>
        [[nodiscard]] std::string TopBuckets(
            const std::uint32_t (&counts)[256],
            int topCount,
            Label label)
        {
            std::uint32_t working[256];
            for (int index = 0; index < 256; ++index)
                working[index] = counts[index];

            std::string output;
            for (int pick = 0; pick < topCount; ++pick) {
                int best = -1;
                std::uint32_t bestCount = 0;
                for (int index = 0; index < 256; ++index) {
                    if (working[index] > bestCount) {
                        bestCount = working[index];
                        best = index;
                    }
                }
                if (best < 0)
                    break;

                char buffer[16];
                label(best, buffer);
                output += fmt::format("{} {}, ", buffer, bestCount);
                working[best] = 0;
            }
            return output;
        }

        void ReportPastCap(
            const HandleTableView& table,
            std::size_t detailedSampleCount)
        {
            if (table.pool == nullptr)
                return;

            std::uint64_t total = 0;
            std::uint64_t unreadable = 0;
            std::uint64_t consistent = 0;
            std::uint32_t byType[256]{};
            std::vector<std::uint32_t> bySource(1u << 16);
            std::vector<CapturedReference> sourceSamples(1u << 16);
            std::vector<CapturedReference> samples(detailedSampleCount);
            std::size_t sampleCount = 0;
            const std::uint32_t mask = table.layout.IndexMask();

            for (std::uint64_t index = kStockCap;
                 index < table.layout.capacity;
                 ++index) {
                const std::uint64_t object =
                    *reinterpret_cast<const volatile std::uint64_t*>(
                        table.pool + index * kPoolEntrySize);
                if (object == 0)
                    continue;
                ++total;

                ObjectFields fields{};
                if (object < 0x10000 ||
                    !SafeReadObject(reinterpret_cast<const void*>(object), fields)) {
                    ++unreadable;
                    continue;
                }

                ++byType[fields.formType];
                ++bySource[fields.sourceIndex];
                if (sourceSamples[fields.sourceIndex].handle == 0) {
                    sourceSamples[fields.sourceIndex] = CapturedReference{
                        fields.nativeHandle,
                        fields.formID,
                        fields.sourceIndex,
                        fields.formType
                    };
                }
                if ((fields.nativeHandle & mask) == static_cast<std::uint32_t>(index))
                    ++consistent;
                if (sampleCount < samples.size() && fields.formID != 0) {
                    samples[sampleCount++] = CapturedReference{
                        fields.nativeHandle,
                        fields.formID,
                        fields.sourceIndex,
                        fields.formType
                    };
                }
            }

            if (total == 0)
                return;

            const std::string typeSummary = TopBuckets(
                byType,
                8,
                [](int type, char* buffer) {
                    if (const char* name =
                            RefFormTypeName(static_cast<std::uint8_t>(type))) {
                        std::snprintf(buffer, 16, "%s", name);
                    } else {
                        std::snprintf(buffer, 16, "t%#04x", type);
                    }
                });
            const auto sourceBuckets = TopSources(bySource, sourceSamples);
            const std::string sourceSummary = FormatSourceBuckets(sourceBuckets);

            logger::info(
                "past old cap: {} live handles at index >= {} ({} verified, {} unreadable) | "
                "types: {}| source plugins: {}",
                total,
                kStockCap,
                consistent,
                unreadable,
                typeSummary,
                sourceSummary);

            if (sampleCount != 0) {
                logger::info("past-cap detailed samples ({} shown):", sampleCount);
                for (std::size_t index = 0; index < sampleCount; ++index)
                    LogDetailedSample(samples[index]);
            }
        }
    }

    void Run(
        const HandleTableView& table,
        const Settings& settings,
        GenerationDiagnostic& diagnostic,
        const AttributionCallback& attribution)
    {
        if (table.manager == 0 || table.pool == nullptr ||
            table.layout.capacity < 2) {
            logger::error("table monitor received an invalid committed table");
            return;
        }

        auto* const freeCounter = reinterpret_cast<volatile std::uint32_t*>(
            table.manager + kOff_FreeCounter);
        std::uint64_t reportedWraps = 0;
        bool reportedUnreliable = false;

        for (std::uint64_t minute = 1;; ++minute) {
            ::Sleep(kReportTickMilliseconds);

            if (diagnostic.IsActive()) {
                const GenerationWrapSnapshot wrap = diagnostic.ReadWrapSnapshot();
                if (wrap.total != reportedWraps) {
                    const std::uint32_t reuses =
                        static_cast<std::uint32_t>(wrap.event >> 32);
                    const std::uint32_t handle =
                        static_cast<std::uint32_t>(wrap.event);
                    const std::uint32_t slot = handle & table.layout.IndexMask();
                    logger::critical(
                        "HANDLE GENERATION WRAP DETECTED: total {}, slot {}, reuse {}, new handle "
                        "{:#010x}; stale-handle aliasing is now possible",
                        wrap.total,
                        slot,
                        reuses,
                        handle);
                    reportedWraps = wrap.total;
                }

                const GenerationReuseSnapshot reuse = diagnostic.ReadReuseSnapshot();
                if (reuse.unreliableSlotPlusOne != 0 && !reportedUnreliable) {
                    logger::critical(
                        "generation detector lost exact tracking at slot {}; its 16-bit "
                        "assignment counter saturated or disagreed with the engine generation",
                        reuse.unreliableSlotPlusOne - 1);
                    reportedUnreliable = true;
                }
            }

            const std::uint32_t free = *freeCounter;
            if (free > table.layout.capacity)
                return;

            const std::uint64_t used = table.layout.capacity - free;
            if ((minute % kNormalReportMinutes) == 0) {
                if (diagnostic.IsActive()) {
                    logger::info(
                        "handles in use: {} / {} ({:.1f}%) | {}",
                        used,
                        table.layout.UsableCapacity(),
                        100.0 * static_cast<double>(used) /
                            static_cast<double>(table.layout.UsableCapacity()),
                        diagnostic.ReuseStatus(attribution));
                } else {
                    logger::info(
                        "handles in use: {} / {} ({:.1f}%)",
                        used,
                        table.layout.UsableCapacity(),
                        100.0 * static_cast<double>(used) /
                            static_cast<double>(table.layout.UsableCapacity()));
                }
            }

            if (settings.verboseLogging && used > (kStockCap - 1))
                ReportPastCap(table, settings.detailedSampleCount);
        }
    }
}
