#include "PatchTransaction.h"

#include "EngineAccess.h"
#include "Logging.h"
#include "PatchTable.g.h"
#include "RuntimeDetection.h"

#include <windows.h>

#include <cstdint>
#include <cstring>

namespace shcr::patch
{
    namespace
    {
        [[nodiscard]] std::size_t CountDispRefs(
            const RuntimeContext& a_runtime,
            std::uintptr_t a_target) noexcept
        {
            std::size_t count = 0;
            const std::uint8_t* bytes = a_runtime.text.begin;
            if (a_runtime.text.size < 4)
                return 0;
            const std::size_t limit = a_runtime.text.size - 4;
            for (std::size_t index = 0; index <= limit; ++index) {
                std::int32_t displacement = 0;
                std::memcpy(&displacement, bytes + index, 4);
                const std::uintptr_t end = reinterpret_cast<std::uintptr_t>(
                    bytes + index + 4);
                if (static_cast<std::uintptr_t>(
                        static_cast<std::int64_t>(end) + displacement) ==
                    a_target) {
                    ++count;
                }
            }
            return count;
        }

        void LogByteMismatch(
            const char* a_kind,
            std::uint32_t a_rva,
            const std::uint8_t* a_wanted,
            const std::uint8_t* a_actual,
            std::size_t a_mismatchNumber) noexcept
        {
            if (a_mismatchNumber < 8) {
                Log("  MISMATCH %s at rva %08x: expected first byte %02x, "
                    "found %02x", a_kind, a_rva, a_wanted[0], a_actual[0]);
            }
        }

        [[nodiscard]] bool VerifyStockCode(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            std::size_t& a_mismatches) noexcept
        {
            a_mismatches = 0;
            for (std::uint32_t index = 0;
                 index < a_profile.fieldCount; ++index) {
                const FieldPatch& field = a_profile.fields[index];
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + field.rva);
                if (field.len == 0 || field.len > sizeof(field.orig) ||
                    field.fieldW == 0 ||
                    field.fieldOff + field.fieldW > field.len ||
                    std::memcmp(address, field.orig, field.len) != 0) {
                    LogByteMismatch(CategoryName(field.cat), field.rva,
                        field.orig, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            for (std::uint32_t index = 0;
                 index < a_profile.bytePatchCount; ++index) {
                const BytePatch& patch = a_profile.bytePatches[index];
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + patch.rva);
                if (patch.len == 0 || patch.len > sizeof(patch.orig) ||
                    std::memcmp(address, patch.orig, patch.len) != 0) {
                    LogByteMismatch(CategoryName(patch.cat), patch.rva,
                        patch.orig, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            for (std::uint32_t index = 0;
                 index < a_profile.tableRefCount; ++index) {
                const TableRef& reference = a_profile.tableRefs[index];
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + reference.rva);
                bool bad = reference.len == 0 ||
                    reference.len > sizeof(reference.orig) ||
                    reference.dispOff + sizeof(std::int32_t) != reference.len ||
                    std::memcmp(
                        address, reference.orig, reference.len) != 0;
                if (!bad) {
                    std::int32_t displacement = 0;
                    std::memcpy(&displacement,
                        address + reference.dispOff, sizeof(displacement));
                    const std::uintptr_t target =
                        static_cast<std::uintptr_t>(
                            static_cast<std::int64_t>(a_runtime.imageBase +
                                reference.rva + reference.len) + displacement);
                    bad = target !=
                        a_runtime.imageBase + a_profile.tableRva;
                }
                if (bad) {
                    LogByteMismatch("table reference", reference.rva,
                        reference.orig, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            for (std::uint32_t index = 0;
                 index < a_profile.initPatchCount; ++index) {
                const BytePatch& patch = a_profile.initPatches[index];
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + patch.rva);
                if (patch.len == 0 || patch.len > sizeof(patch.orig) ||
                    std::memcmp(address, patch.orig, patch.len) != 0) {
                    LogByteMismatch("initialiser guard", patch.rva,
                        patch.orig, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            for (std::uint32_t index = 0;
                 index < a_profile.releaseSiteCount; ++index) {
                const ExactSite& site = a_profile.releaseSites[index];
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + site.rva);
                if (site.len == 0 || site.len > sizeof(site.orig) ||
                    std::memcmp(address, site.orig, site.len) != 0) {
                    LogByteMismatch("sidecar release gate", site.rva,
                        site.orig, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            return a_mismatches == 0;
        }

        [[nodiscard]] bool VerifyPatchedCode(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            std::uintptr_t a_table,
            bool a_patchedInitPatches,
            std::size_t& a_mismatches) noexcept
        {
            a_mismatches = 0;
            std::uint8_t wanted[15]{};
            for (std::uint32_t index = 0;
                 index < a_profile.fieldCount; ++index) {
                const FieldPatch& field = a_profile.fields[index];
                std::memcpy(wanted, field.orig, field.len);
                if (field.fieldW == 4) {
                    std::memcpy(wanted + field.fieldOff,
                        &field.newVal, sizeof(field.newVal));
                } else {
                    wanted[field.fieldOff] =
                        static_cast<std::uint8_t>(field.newVal);
                }
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + field.rva);
                if (std::memcmp(address, wanted, field.len) != 0) {
                    LogByteMismatch(CategoryName(field.cat), field.rva,
                        wanted, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            for (std::uint32_t index = 0;
                 index < a_profile.bytePatchCount; ++index) {
                const BytePatch& patch = a_profile.bytePatches[index];
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + patch.rva);
                if (std::memcmp(address, patch.repl, patch.len) != 0) {
                    LogByteMismatch(CategoryName(patch.cat), patch.rva,
                        patch.repl, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            for (std::uint32_t index = 0;
                 index < a_profile.tableRefCount; ++index) {
                const TableRef& reference = a_profile.tableRefs[index];
                std::memcpy(wanted, reference.orig, reference.len);
                const std::int64_t delta =
                    static_cast<std::int64_t>(a_table) -
                    static_cast<std::int64_t>(a_runtime.imageBase +
                        reference.rva + reference.len);
                const std::int32_t displacement =
                    static_cast<std::int32_t>(delta);
                std::memcpy(wanted + reference.dispOff,
                    &displacement, sizeof(displacement));
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + reference.rva);
                if (std::memcmp(address, wanted, reference.len) != 0) {
                    LogByteMismatch("table reference", reference.rva,
                        wanted, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            for (std::uint32_t index = 0;
                 index < a_profile.initPatchCount; ++index) {
                const BytePatch& patch = a_profile.initPatches[index];
                const std::uint8_t* wantedPatch = a_patchedInitPatches ?
                    patch.repl : patch.orig;
                const auto* address = reinterpret_cast<const std::uint8_t*>(
                    a_runtime.imageBase + patch.rva);
                if (std::memcmp(address, wantedPatch, patch.len) != 0) {
                    LogByteMismatch("initialiser guard", patch.rva,
                        wantedPatch, address, a_mismatches);
                    ++a_mismatches;
                }
            }
            return a_mismatches == 0;
        }

        [[nodiscard]] bool VerifyPristine(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            bool& a_stockFreeListInitialized) noexcept
        {
            const std::uint32_t head =
                *reinterpret_cast<std::uint32_t*>(
                    a_runtime.imageBase + a_profile.headRva);
            const std::uint32_t tail =
                *reinterpret_cast<std::uint32_t*>(
                    a_runtime.imageBase + a_profile.tailRva);
            const std::uint32_t stockTail = a_profile.stockEntries - 1;
            auto* table = reinterpret_cast<HandleEntry*>(
                a_runtime.imageBase + a_profile.tableRva);

            const bool zeroState = head == 0 && tail == 0;
            const bool stockState = head == 0 && tail == stockTail;
            if (!zeroState && !stockState) {
                Log("  pool is not pristine: head=%08x tail=%08x "
                    "(expected 0/0 or 0/%08x)", head, tail, stockTail);
                return false;
            }

            std::size_t bad = 0;
            for (std::uint32_t index = 0;
                 index < a_profile.stockEntries; ++index) {
                const std::uint32_t wantedBits = zeroState ? 0u :
                    (index + 1 < a_profile.stockEntries ? index + 1 : index);
                if (table[index].bits != wantedBits ||
                    table[index].pad != 0 ||
                    table[index].pointer != nullptr) {
                    if (bad < 8) {
                        Log("  entry %u is not pristine: bits=%08x "
                            "(want %08x), pad=%08x, pointer=%p", index,
                            table[index].bits, wantedBits,
                            table[index].pad, table[index].pointer);
                    }
                    ++bad;
                }
            }
            if (bad) {
                Log("  refusing to patch: %zu stock-table entries differ "
                    "from the exact %s state", bad,
                    zeroState ? "zero-filled" : "initial free-list");
                return false;
            }
            a_stockFreeListInitialized = stockState;
            return true;
        }

        [[nodiscard]] std::uint8_t* AllocateTableNear(
            const RuntimeContext& a_runtime,
            std::size_t a_bytes) noexcept
        {
            for (std::uintptr_t offset = 0x10000000;
                 offset <= 0x40000000; offset += 0x04000000) {
                if (auto* allocation = static_cast<std::uint8_t*>(VirtualAlloc(
                        reinterpret_cast<void*>(
                            a_runtime.imageBase + offset),
                        a_bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
                    return allocation;
                }
            }
            return static_cast<std::uint8_t*>(VirtualAlloc(
                nullptr, a_bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        }

        [[nodiscard]] bool InDispRange(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            std::uintptr_t a_table) noexcept
        {
            for (std::uint32_t index = 0;
                 index < a_profile.tableRefCount; ++index) {
                const TableRef& reference = a_profile.tableRefs[index];
                const std::uintptr_t instructionEnd =
                    a_runtime.imageBase + reference.rva + reference.len;
                const std::int64_t delta =
                    static_cast<std::int64_t>(a_table) -
                    static_cast<std::int64_t>(instructionEnd);
                if (delta < INT32_MIN || delta > INT32_MAX)
                    return false;
            }
            return true;
        }

        void InitializeTable(
            const Profile& a_profile, std::uint8_t* a_table) noexcept
        {
            auto* entries = reinterpret_cast<HandleEntry*>(a_table);
            const std::uint32_t last = a_profile.raisedEntries - 1;
            for (std::uint32_t index = 0;
                 index < a_profile.raisedEntries; ++index) {
                entries[index].bits = index < last ? index + 1 : index;
                entries[index].pad = 0;
                entries[index].pointer = nullptr;
            }
        }

        [[nodiscard]] bool VerifyNewTable(
            const Profile& a_profile,
            const std::uint8_t* a_table) noexcept
        {
            const auto* entries =
                reinterpret_cast<const HandleEntry*>(a_table);
            const std::uint32_t last = a_profile.raisedEntries - 1;
            for (std::uint32_t index = 0;
                 index < a_profile.raisedEntries; ++index) {
                const std::uint32_t wanted =
                    index < last ? index + 1 : index;
                if (entries[index].bits != wanted ||
                    entries[index].pad != 0 ||
                    entries[index].pointer != nullptr) {
                    Log("  new-table verification failed at entry %u: "
                        "bits=%08x (want %08x), pad=%08x, pointer=%p", index,
                        entries[index].bits, wanted, entries[index].pad,
                        entries[index].pointer);
                    return false;
                }
            }
            return true;
        }

        void ApplyCode(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            std::uintptr_t a_table,
            bool a_patchInitPatches) noexcept
        {
            for (std::uint32_t index = 0;
                 index < a_profile.fieldCount; ++index) {
                const FieldPatch& field = a_profile.fields[index];
                auto* address = reinterpret_cast<std::uint8_t*>(
                    a_runtime.imageBase + field.rva) + field.fieldOff;
                if (field.fieldW == 4)
                    std::memcpy(address, &field.newVal, sizeof(field.newVal));
                else
                    *address = static_cast<std::uint8_t>(field.newVal);
            }
            for (std::uint32_t index = 0;
                 index < a_profile.bytePatchCount; ++index) {
                const BytePatch& patch = a_profile.bytePatches[index];
                std::memcpy(reinterpret_cast<void*>(
                        a_runtime.imageBase + patch.rva),
                    patch.repl, patch.len);
            }
            for (std::uint32_t index = 0;
                 index < a_profile.tableRefCount; ++index) {
                const TableRef& reference = a_profile.tableRefs[index];
                const std::int64_t delta =
                    static_cast<std::int64_t>(a_table) -
                    static_cast<std::int64_t>(a_runtime.imageBase +
                        reference.rva + reference.len);
                const std::int32_t displacement =
                    static_cast<std::int32_t>(delta);
                std::memcpy(reinterpret_cast<void*>(a_runtime.imageBase +
                        reference.rva + reference.dispOff),
                    &displacement, sizeof(displacement));
            }
            if (a_patchInitPatches) {
                for (std::uint32_t index = 0;
                     index < a_profile.initPatchCount; ++index) {
                    const BytePatch& patch = a_profile.initPatches[index];
                    std::memcpy(reinterpret_cast<void*>(
                            a_runtime.imageBase + patch.rva),
                        patch.repl, patch.len);
                }
            }
        }

        void RestoreStockCode(
            const RuntimeContext& a_runtime,
            const Profile& a_profile) noexcept
        {
            for (std::uint32_t index = 0;
                 index < a_profile.fieldCount; ++index) {
                const FieldPatch& field = a_profile.fields[index];
                std::memcpy(reinterpret_cast<void*>(
                        a_runtime.imageBase + field.rva),
                    field.orig, field.len);
            }
            for (std::uint32_t index = 0;
                 index < a_profile.bytePatchCount; ++index) {
                const BytePatch& patch = a_profile.bytePatches[index];
                std::memcpy(reinterpret_cast<void*>(
                        a_runtime.imageBase + patch.rva),
                    patch.orig, patch.len);
            }
            for (std::uint32_t index = 0;
                 index < a_profile.tableRefCount; ++index) {
                const TableRef& reference = a_profile.tableRefs[index];
                std::memcpy(reinterpret_cast<void*>(
                        a_runtime.imageBase + reference.rva),
                    reference.orig, reference.len);
            }
            for (std::uint32_t index = 0;
                 index < a_profile.initPatchCount; ++index) {
                const BytePatch& patch = a_profile.initPatches[index];
                std::memcpy(reinterpret_cast<void*>(
                        a_runtime.imageBase + patch.rva),
                    patch.orig, patch.len);
            }
        }

        [[noreturn]] void FatalStop(const char* a_reason) noexcept
        {
            Log("FATAL: %s", a_reason);
            Log("The patch could not prove a complete rollback. Terminating "
                "Skyrim before engine state or a save can be corrupted.");
            TerminateProcess(GetCurrentProcess(), 0x53484352u);
            ExitProcess(0x52u);
        }

        void RollBackOrStop(
            const RuntimeContext& a_runtime,
            const Profile& a_profile,
            DWORD a_oldProtection,
            std::uint32_t a_oldHead,
            std::uint32_t a_oldTail,
            const char* a_reason) noexcept
        {
            Log("ABORT after writes: %s; restoring every stock instruction.",
                a_reason);
            DWORD currentProtection = 0;
            if (!VirtualProtect(a_runtime.text.begin, a_runtime.text.size,
                    PAGE_EXECUTE_READWRITE, &currentProtection)) {
                FatalStop("could not make .text writable for rollback");
            }
            *reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + a_profile.headRva) = a_oldHead;
            *reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + a_profile.tailRva) = a_oldTail;
            RestoreStockCode(a_runtime, a_profile);

            std::size_t mismatches = 0;
            const bool bytesRestored = VerifyStockCode(
                a_runtime, a_profile, mismatches);
            const std::size_t stockRefs = CountDispRefs(
                a_runtime, a_runtime.imageBase + a_profile.tableRva);
            const bool globalsRestored =
                *reinterpret_cast<const std::uint32_t*>(
                    a_runtime.imageBase + a_profile.headRva) == a_oldHead &&
                *reinterpret_cast<const std::uint32_t*>(
                    a_runtime.imageBase + a_profile.tailRva) == a_oldTail;
            bool restoredStockFreeListInitialized = false;
            const bool poolRestored = globalsRestored &&
                VerifyPristine(a_runtime, a_profile,
                    restoredStockFreeListInitialized) &&
                restoredStockFreeListInitialized ==
                    (a_oldTail == a_profile.stockEntries - 1);
            const bool cacheFlushed = FlushInstructionCache(
                GetCurrentProcess(), a_runtime.text.begin,
                a_runtime.text.size) != FALSE;
            DWORD ignored = 0;
            const bool protectionRestored = VirtualProtect(
                a_runtime.text.begin, a_runtime.text.size,
                a_oldProtection, &ignored) != FALSE;
            if (!bytesRestored || stockRefs != a_profile.tableRefCount ||
                !poolRestored || !cacheFlushed || !protectionRestored) {
                FatalStop("stock bytes, table references, manager globals/pool, "
                    "cache, or page protection did not verify after rollback");
            }
            Log("rollback verified: all stock bytes, %u stock table references, "
                "manager globals, and the complete pristine pool were restored; "
                "no cap raise remains active.", a_profile.tableRefCount);
        }
    }

    Result Raise(
        const RuntimeContext& a_runtime,
        const Lifecycle& a_lifecycle) noexcept
    {
        Result result;
        bool lifecyclePrepared = false;
        const auto notifyAbort = [&]() noexcept {
            if (lifecyclePrepared && a_lifecycle.onPatchAborted) {
                a_lifecycle.onPatchAborted(a_lifecycle.context);
                lifecyclePrepared = false;
            }
        };

        if (!a_runtime.text.begin) {
            Log("could not locate the executable's .text section; no changes made");
            return result;
        }

        const std::uint32_t version = a_runtime.runtimeVersion;
        const Profile* profile = a_runtime.profile;
        Log("runtime version %u.%u.%u.%u, image base %016llx, "
            ".text %016llx + %zu",
            (version >> 24) & 0xFF, (version >> 16) & 0xFF,
            (version >> 4) & 0xFFF, version & 0xF,
            static_cast<unsigned long long>(a_runtime.imageBase),
            static_cast<unsigned long long>(
                reinterpret_cast<std::uintptr_t>(a_runtime.text.begin)),
            a_runtime.text.size);

        if (!profile) {
            Log("no verified patch profile for this runtime; no changes made.");
            Log("supported: Skyrim SE 1.5.97, Skyrim AE 1.6.1170, "
                "Skyrim GOG 1.6.1179, and Skyrim VR 1.4.15.");
            return result;
        }
        Log("profile: %s -- %u field rewrites + %u sidecar rewrites + %u "
            "table references, slots %u -> %u", profile->name,
            profile->fieldCount, profile->bytePatchCount,
            profile->tableRefCount, profile->stockEntries,
            profile->raisedEntries);

        LogEngineFixesCompatibility();

        std::size_t mismatches = 0;
        if (!VerifyStockCode(a_runtime, *profile, mismatches)) {
            Log("ABORT: %zu instructions or audited release sites do not "
                "match their expected stock bytes.", mismatches);
            Log("The executable is not the build this profile was built from, "
                "or another mod patched the same code. No changes made.");
            return result;
        }

        const std::size_t liveRefs = CountDispRefs(
            a_runtime, a_runtime.imageBase + profile->tableRva);
        if (liveRefs != profile->tableRefCount) {
            Log("ABORT: this executable contains %zu references to the handle "
                "table but the profile knows %u. Patching a partial set "
                "resolves handles to the wrong object silently, so no changes "
                "were made.", liveRefs, profile->tableRefCount);
            return result;
        }
        Log("verified stock bytes: %u fields, %u sidecar rewrites, %u table "
            "references, %u initialiser guards, and %u release gates",
            profile->fieldCount, profile->bytePatchCount,
            profile->tableRefCount, profile->initPatchCount,
            profile->releaseSiteCount);

        const std::size_t tableBytes =
            static_cast<std::size_t>(profile->raisedEntries) *
            profile->entrySize;
        std::uint8_t* table = AllocateTableNear(a_runtime, tableBytes);
        if (!table) {
            Log("ABORT: could not allocate %zu bytes for the new handle table.",
                tableBytes);
            return result;
        }
        if (!InDispRange(a_runtime, *profile,
                reinterpret_cast<std::uintptr_t>(table))) {
            Log("ABORT: the allocation at %016llx is out of 32-bit "
                "displacement range of the code that must address it.",
                static_cast<unsigned long long>(
                    reinterpret_cast<std::uintptr_t>(table)));
            VirtualFree(table, 0, MEM_RELEASE);
            return result;
        }
        InitializeTable(*profile, table);
        if (!VerifyNewTable(*profile, table)) {
            Log("ABORT: the new table's complete free-list chain did not verify.");
            VirtualFree(table, 0, MEM_RELEASE);
            return result;
        }
        Log("new handle table: %zu MB at %016llx",
            tableBytes / (1024 * 1024),
            static_cast<unsigned long long>(
                reinterpret_cast<std::uintptr_t>(table)));
        Log("new free list verified through final index %08x",
            profile->raisedEntries - 1);

        const HandleTableView tableView{
            reinterpret_cast<HandleEntry*>(table), profile->raisedEntries
        };
        if (a_lifecycle.onTablePrepared) {
            a_lifecycle.onTablePrepared(
                a_lifecycle.context, a_runtime, tableView);
            lifecyclePrepared = true;
        }

        LockManager(a_runtime, *profile);
        bool stockFreeListInitialized = false;
        if (!VerifyPristine(
                a_runtime, *profile, stockFreeListInitialized)) {
            UnlockManager(a_runtime, *profile);
            Log("ABORT: the handle pool is not exactly pristine. No changes made.");
            VirtualFree(table, 0, MEM_RELEASE);
            notifyAbort();
            return result;
        }
        Log("pool is pristine (free-list initializer %s run)",
            stockFreeListInitialized ? "has" : "has not");

        const std::uint32_t oldHead =
            *reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + profile->headRva);
        const std::uint32_t oldTail =
            *reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + profile->tailRva);
        DWORD oldProtection = 0;
        if (!VirtualProtect(a_runtime.text.begin, a_runtime.text.size,
                PAGE_EXECUTE_READWRITE, &oldProtection)) {
            Log("ABORT: could not make .text writable (error %lu).",
                GetLastError());
            UnlockManager(a_runtime, *profile);
            VirtualFree(table, 0, MEM_RELEASE);
            notifyAbort();
            return result;
        }

        const bool patchInitPatches = !stockFreeListInitialized;
        ApplyCode(a_runtime, *profile,
            reinterpret_cast<std::uintptr_t>(table), patchInitPatches);
        const std::uint32_t last = profile->raisedEntries - 1;
        *reinterpret_cast<std::uint32_t*>(
            a_runtime.imageBase + profile->headRva) = 0;
        *reinterpret_cast<std::uint32_t*>(
            a_runtime.imageBase + profile->tailRva) = last;

        std::size_t patchedMismatches = 0;
        const bool codeGood = VerifyPatchedCode(a_runtime, *profile,
            reinterpret_cast<std::uintptr_t>(table), patchInitPatches,
            patchedMismatches);
        const std::size_t staleRefs = CountDispRefs(
            a_runtime, a_runtime.imageBase + profile->tableRva);
        const std::size_t newRefs = CountDispRefs(
            a_runtime, reinterpret_cast<std::uintptr_t>(table));
        const bool globalsGood =
            *reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + profile->headRva) == 0 &&
            *reinterpret_cast<std::uint32_t*>(
                a_runtime.imageBase + profile->tailRva) == last;
        const bool tableGood = VerifyNewTable(*profile, table);
        if (!codeGood || staleRefs != 0 ||
            newRefs != profile->tableRefCount || !globalsGood || !tableGood) {
            Log("post-write verification: mismatches=%zu oldRefs=%zu "
                "newRefs=%zu globals=%s table=%s", patchedMismatches,
                staleRefs, newRefs, globalsGood ? "PASS" : "FAIL",
                tableGood ? "PASS" : "FAIL");
            RollBackOrStop(a_runtime, *profile, oldProtection,
                oldHead, oldTail, "post-write verification failed");
            UnlockManager(a_runtime, *profile);
            VirtualFree(table, 0, MEM_RELEASE);
            notifyAbort();
            return result;
        }

        if (!FlushInstructionCache(GetCurrentProcess(),
                a_runtime.text.begin, a_runtime.text.size)) {
            RollBackOrStop(a_runtime, *profile, oldProtection,
                oldHead, oldTail,
                "FlushInstructionCache failed before commit");
            UnlockManager(a_runtime, *profile);
            VirtualFree(table, 0, MEM_RELEASE);
            notifyAbort();
            return result;
        }
        DWORD ignored = 0;
        if (!VirtualProtect(a_runtime.text.begin, a_runtime.text.size,
                oldProtection, &ignored)) {
            RollBackOrStop(a_runtime, *profile, oldProtection,
                oldHead, oldTail,
                "could not restore executable page protection before commit");
            UnlockManager(a_runtime, *profile);
            VirtualFree(table, 0, MEM_RELEASE);
            notifyAbort();
            return result;
        }

        Log("SUCCESS: reference handle slots raised %u -> %u (index 22 bits, "
            "age still 6 bits / 64 generations, reference count and valid bit "
            "remain stock-compatible).", profile->stockEntries,
            profile->raisedEntries);
        Log("post-patch verification: 0 stale references, %zu/%u new "
            "references, all rewrites/free-list/globals verified%s.", newRefs,
            profile->tableRefCount, patchInitPatches ?
                "; future stock initialisation disabled" : "");

        result = { true, tableView, profile };
        if (a_lifecycle.onCommittedWhileManagerLocked) {
            a_lifecycle.onCommittedWhileManagerLocked(
                a_lifecycle.context, a_runtime, tableView);
        }
        UnlockManager(a_runtime, *profile);
        lifecyclePrepared = false;
        return result;
    }
}
