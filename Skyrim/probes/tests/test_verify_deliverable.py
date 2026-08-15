from __future__ import annotations

import copy
import json
import pathlib
import struct
import sys
import types
import unittest


PROBES = pathlib.Path(__file__).resolve().parents[1]
ROOT = PROBES.parent
if str(PROBES) not in sys.path:
    sys.path.insert(0, str(PROBES))

import verify_deliverable as verifier  # noqa: E402


class _FakeSection:
    def __init__(
            self, virtual_address: int, raw_offset: int, raw_size: int,
            characteristics: int) -> None:
        self.VirtualAddress = virtual_address
        self.PointerToRawData = raw_offset
        self.SizeOfRawData = raw_size
        self.Misc_VirtualSize = raw_size
        self.Characteristics = characteristics


class _FakePE:
    def __init__(self, symbols: list[object]) -> None:
        self.OPTIONAL_HEADER = types.SimpleNamespace(ImageBase=0x180000000)
        self.sections = [
            _FakeSection(0x1000, 0x000, 0x400, 0x60000020),
            _FakeSection(0x2000, 0x400, 0x400, 0xC0000040),
        ]
        self.DIRECTORY_ENTRY_EXPORT = types.SimpleNamespace(symbols=symbols)

    def parse_data_directories(self, *, directories: list[int]) -> None:
        if not directories:
            raise ValueError("export directory was not requested")


def _symbol(name: str | None, address: int, *, forwarder: bytes | None = None):
    return types.SimpleNamespace(
        name=None if name is None else name.encode("ascii"),
        address=address,
        forwarder=forwarder,
        ordinal=1,
    )


def _compiled_skse_fixture() -> tuple[bytes, _FakePE]:
    version = bytearray(verifier.SKSE_VERSION_DATA_SIZE)
    struct.pack_into(
        "<II", version, 0,
        verifier.EXPECTED_SKSE_DATA_VERSION,
        verifier.EXPECTED_SKSE_PLUGIN_VERSION,
    )
    version[0x008:0x008 + len(verifier.EXPECTED_SKSE_NAME)] = \
        verifier.EXPECTED_SKSE_NAME.encode("ascii")
    version[0x108:0x108 + len(verifier.EXPECTED_SKSE_AUTHOR)] = \
        verifier.EXPECTED_SKSE_AUTHOR.encode("ascii")
    struct.pack_into(
        "<II", version, 0x304,
        verifier.EXPECTED_SKSE_VERSION_INDEPENDENCE_EX,
        verifier.EXPECTED_SKSE_ADDRESS_INDEPENDENCE,
    )
    struct.pack_into("<16I", version, 0x30C, *verifier.EXPECTED_SKSE_RUNTIMES)
    struct.pack_into("<I", version, 0x34C, 0)
    dll = bytearray(0x800)
    dll[0x400:0x400 + len(version)] = version
    symbols = [
        _symbol("SKSEPlugin_Load", 0x1000),
        _symbol("SKSEPlugin_Query", 0x1010),
        _symbol("SKSEPlugin_Version", 0x2000),
    ]
    return bytes(dll), _FakePE(symbols)


class DeliverableArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profiles = {
            tag: json.loads(
                (ROOT / "artifacts" / f"patch_{tag}.json").read_text(
                    encoding="utf-8"))
            for tag, *_ in verifier.EXPECTED
        }

    def test_all_profiles_have_exact_2m_counts_and_schema(self) -> None:
        for tag, _refs, _fields, _funcs, mandatory_expected in verifier.EXPECTED:
            with self.subTest(runtime=tag):
                profile = self.profiles[tag]
                core, guards, total = verifier._validate_2m_architecture(
                    profile, tag)
                self.assertEqual(core, mandatory_expected)
                self.assertEqual(guards, verifier.MANDATORY_ASSIGNMENT_REDIRECTS)
                self.assertEqual(total, verifier.EXPECTED_TOTAL_MUTATIONS[tag])
                self.assertTrue(
                    verifier.RETIRED_PROFILE_KEYS.isdisjoint(profile))
                verifier._independent_patch_doc_ids(profile, tag)

        self.assertEqual(
            sum(row[4] for row in verifier.EXPECTED),
            verifier.EXPECTED_AGGREGATE_CORE_MUTATIONS,
        )
        self.assertEqual(
            sum(verifier.EXPECTED_TOTAL_MUTATIONS.values()),
            verifier.EXPECTED_AGGREGATE_TOTAL_MUTATIONS,
        )

    def test_every_assignment_redirect_is_mandatory(self) -> None:
        for tag, *_ in verifier.EXPECTED:
            with self.subTest(runtime=tag):
                profile = copy.deepcopy(self.profiles[tag])
                profile["assignment_hooks"]["sites"].pop()
                with self.assertRaisesRegex(
                        ValueError, "mandatory assignment-guard redirects"):
                    verifier._validate_2m_architecture(profile, tag)

    def test_all_four_profiles_are_bound_to_independent_input_pins(self) -> None:
        self.assertEqual(set(verifier.EXACT_RUNTIME_INPUTS), set(self.profiles))
        for tag, profile in self.profiles.items():
            with self.subTest(runtime=tag):
                verifier._validate_exact_runtime_profile_input(profile, tag)
                for field, replacement in (
                    ("exe_size", profile["exe_size"] + 1),
                    ("exe_sha256", "0" * 64),
                ):
                    mutated = copy.deepcopy(profile)
                    mutated[field] = replacement
                    with self.assertRaisesRegex(
                            ValueError, "independently reviewed exact executable"):
                        verifier._validate_exact_runtime_profile_input(mutated, tag)

        with self.assertRaisesRegex(ValueError, "no independent generation-input pin"):
            verifier._validate_exact_runtime_profile_input({}, "UNKNOWN")

    def test_retired_4m_schema_is_rejected_even_when_empty(self) -> None:
        for retired in sorted(verifier.RETIRED_PROFILE_KEYS):
            with self.subTest(key=retired):
                profile = copy.deepcopy(self.profiles["SE"])
                profile[retired] = []
                with self.assertRaisesRegex(ValueError, "retired 4M schema"):
                    verifier._validate_2m_architecture(profile, "SE")
                with self.assertRaisesRegex(ValueError, "profile keys differ"):
                    verifier._independent_patch_doc_ids(profile, "SE")

    def test_unreviewed_or_in_use_rewrite_is_rejected(self) -> None:
        profile = copy.deepcopy(self.profiles["AE"])
        profile["patches"][0]["new"] ^= verifier.IN_USE_MASK
        with self.assertRaisesRegex(ValueError, "exclusive immediate rewrite"):
            verifier._validate_2m_architecture(profile, "AE")

    def test_reservation_window_derivation_needs_no_raw_patch_collection(self) -> None:
        field_orig = bytes.fromhex("25ffff0f00")
        field_profile = {
            "patches": [{
                "rva": 0x100,
                "orig": field_orig.hex(),
                "field_off": 1,
                "field_w": 4,
                "new": verifier.INDEX_MASK,
            }],
            "table_refs": [],
            "init_patches": [],
        }
        raised = verifier._derive_raised_reservation_window(
            field_profile, 0x100, field_orig, "field fixture")
        self.assertEqual(raised, b"\x25" + verifier.INDEX_MASK.to_bytes(4, "little"))
        with self.assertRaisesRegex(ValueError, "partially overlaps field patch"):
            verifier._derive_raised_reservation_window(
                field_profile, 0x101, field_orig[1:], "partial fixture")

        table_orig = bytes.fromhex("488d0500000000")
        table_profile = {
            "patches": [],
            "table_refs": [{
                "rva": 0x200,
                "len": len(table_orig),
                "disp_off": 3,
                "orig": table_orig.hex(),
            }],
            "init_patches": [],
        }
        raised = verifier._derive_raised_reservation_window(
            table_profile, 0x200, table_orig, "table fixture")
        self.assertEqual(
            raised[3:], struct.pack("<i", 0x10000000 - (0x200 + 7)))

    def test_compiled_blob_set_matches_smaller_profile(self) -> None:
        expected_labels = {
            "fields",
            "table references",
            "initialiser guards",
            "assignment-hook sites",
            "player-selector sites",
            "player-release metadata",
            "player-lifecycle metadata",
            "player teardown zero-source sites",
        }
        for tag, *_ in verifier.EXPECTED:
            with self.subTest(runtime=tag):
                profile = self.profiles[tag]
                blobs = verifier.compiled_array_blobs(profile)
                self.assertEqual(set(blobs), expected_labels)
                self.assertTrue(all(blobs.values()))
                self.assertEqual(
                    len(blobs["fields"]),
                    len(profile["patches"]) *
                    struct.calcsize("<IBBBBII15sx"))
                self.assertEqual(
                    len(blobs["table references"]),
                    len(profile["table_refs"]) *
                    struct.calcsize("<IBB15s3x"))
                self.assertEqual(
                    len(blobs["initialiser guards"]),
                    3 * struct.calcsize("<IBB15s15s"))

    def test_live_lifecycle_generic_critical_contract_and_mutations(self) -> None:
        source = (PROBES / "verify_live_lifecycle.py").read_text(encoding="utf-8")
        verifier._validate_live_lifecycle_failure_contract(source)

        narrow = source.replace(
            '"CRITICAL:",',
            '"CRITICAL: HANDLE GENERATION WRAP DETECTED:",',
            1,
        )
        with self.assertRaisesRegex(ValueError, "generically forbid"):
            verifier._validate_live_lifecycle_failure_contract(narrow)

        unapplied = source.replace("if forbidden in text:", "if False:", 1)
        with self.assertRaisesRegex(ValueError, "does not apply"):
            verifier._validate_live_lifecycle_failure_contract(unapplied)

    def test_mandatory_no_wrap_source_contract_and_mutations(self) -> None:
        source_dir = ROOT / "src"
        baseline = {
            name: (source_dir / name).read_text(encoding="utf-8")
            for name in (
                "main.cpp", "GenerationDiagnostic.cpp",
                "GenerationDiagnostic.h", "GenerationTracker.h",
                "TableMonitor.cpp", "ReservedPlayerSlot.h",
            )
        }

        def validate(sources: dict[str, str]) -> None:
            verifier._validate_no_wrap_source_contract(
                sources["main.cpp"], sources["GenerationDiagnostic.cpp"],
                sources["GenerationDiagnostic.h"],
                sources["GenerationTracker.h"], sources["TableMonitor.cpp"],
                sources["ReservedPlayerSlot.h"],
            )

        validate(baseline)
        mutations = (
            (
                "config bypass",
                "main.cpp",
                "if (!state.settings.generationWrapDetection)",
                "if (false && !state.settings.generationWrapDetection)",
                "GenerationWrapDetection=0",
            ),
            (
                "publisher ordering",
                "GenerationDiagnostic.cpp",
                "PrepareAssignment(a_destination, a_subobject)",
                "PrepareAssignmentAfterPublisher(a_destination, a_subobject)",
                "one guarded stock publisher",
            ),
            (
                "original helper ordering",
                "GenerationDiagnostic.cpp",
                "g_originalAssignmentHelper.store(original, std::memory_order_release)",
                "g_originalAssignmentHelper.store(original, std::memory_order_relaxed)",
                "before redirect writes",
            ),
            (
                "prevented boundary",
                "GenerationDiagnostic.cpp",
                "PreventRepeatedGeneration(index, bits, priorAssignments);",
                "PublishRepeatedGeneration(index, bits, priorAssignments);",
                "direct repeated-generation fail-stop",
            ),
            (
                "post-wrap detector",
                "TableMonitor.cpp",
                "namespace shcr::monitor",
                "// HANDLE GENERATION WRAP DETECTED\nnamespace shcr::monitor",
                "post-publication wrap",
            ),
            (
                "exact player bits",
                "TableMonitor.cpp",
                "player_slot::IsLiveGenerationZero(entry)",
                "snapshot.bits == player_slot::kLiveBits",
                "masked 0x07E00000/0x04000000",
            ),
        )
        for label, filename, old, new, error in mutations:
            with self.subTest(mutation=label):
                mutated = dict(baseline)
                self.assertIn(old, mutated[filename])
                mutated[filename] = mutated[filename].replace(old, new, 1)
                with self.assertRaisesRegex(ValueError, error):
                    validate(mutated)

        adversarial_mutations = (
            (
                "nonconstant early lifecycle success",
                "main.cpp",
                "            auto& state = *static_cast<PluginState*>(a_context);\n",
                "            auto& state = *static_cast<PluginState*>(a_context);\n"
                "            if (state.settings.generationWrapDetection)\n"
                "                return true;\n",
                "return structure",
            ),
            (
                "indirect stock-helper bypass",
                "GenerationDiagnostic.cpp",
                "            const PendingAssignment pending =\n",
                "            if (g_generationDetectorActive.load(\n"
                "                    std::memory_order_acquire)) {\n"
                "                return (*original)(a_destination, a_subobject);\n"
                "            }\n"
                "            const PendingAssignment pending =\n",
                "one guarded stock publisher",
            ),
            (
                "repeat predicate forced false",
                "GenerationTracker.h",
                "            (a_priorAssignments & (kGenerationCount - 1u)) == 0u;",
                "            false && (a_priorAssignments &\n"
                "                (kGenerationCount - 1u)) == 0u;",
                "boundary predicate",
            ),
            (
                "native boundary assertion removed",
                "GenerationTracker.h",
                "    static_assert(ObserveAssignment(32u, 1u).abaWrap);\n",
                "",
                "compile-time no-wrap boundary proofs",
            ),
            (
                "short-circuited guard install",
                "main.cpp",
                "state.diagnosticInstalled = diagnostic::Install();",
                "state.diagnosticInstalled = true || diagnostic::Install();",
                "exact diagnostic::Install assignment",
            ),
            (
                "guard setting cleared before install",
                "main.cpp",
                "            // Install the requested guard before starting the detached\n",
                "            state.settings.generationWrapDetection = false;\n"
                "            // Install the requested guard before starting the detached\n",
                "exact diagnostic::Install assignment",
            ),
            (
                "repeat fail-stop branch disabled",
                "GenerationDiagnostic.cpp",
                "if (transition.abaWrap) {",
                "if (transition.abaWrap && false /* if (transition.abaWrap) */) {",
                "direct repeated-generation fail-stop",
            ),
            (
                "ordinary assignment returns before repeat stop",
                "GenerationDiagnostic.cpp",
                "            if (transition.abaWrap) {\n",
                "            if (transition.generationMatches)\n"
                "                return { index, bits, transition, false };\n"
                "            if (transition.abaWrap) {\n",
                "ordinary assignment return structure",
            ),
            (
                "committed counter truncated at generation width",
                "GenerationDiagnostic.cpp",
                "                a_pending.transition.assignmentCount);",
                "                a_pending.transition.assignmentCount & 31u);",
                "stores the full counter",
            ),
            (
                "successful high-water update disabled",
                "GenerationDiagnostic.cpp",
                "            UpdateHottest(a_pending.transition.reuseCount, handle, true);",
                "            if (false)\n"
                "                UpdateHottest(a_pending.transition.reuseCount, handle, true);",
                "directly updates the hottest-slot",
            ),
            (
                "hook successful commit disabled",
                "GenerationDiagnostic.cpp",
                "            CommitAssignment(pending, a_destination, a_subobject, result);",
                "            if (false)\n"
                "                CommitAssignment(pending, a_destination, a_subobject, result);",
                "one direct successful commit",
            ),
            (
                "slot counter store itself truncates",
                "GenerationDiagnostic.cpp",
                "            counter.store(a_count, std::memory_order_release);",
                "            counter.store(a_count & 31u, std::memory_order_release);",
                "full count",
            ),
            (
                "strict hottest comparison weakened",
                "GenerationDiagnostic.cpp",
                "            while (a_reuseCount >\n",
                "            while (a_reuseCount >=\n",
                "strict atomic high-water",
            ),
            (
                "periodic status attribution disabled",
                "TableMonitor.cpp",
                "                diagnostic::LogStatus(context->skipAttribution,\n",
                "                if (false)\n"
                "                    diagnostic::LogStatus(context->skipAttribution,\n",
                "periodic monitor no longer directly reports",
            ),
            (
                "production assignment count skips one generation cycle",
                "GenerationTracker.h",
                "a_priorAssignments + 1u",
                "a_priorAssignments + 33u",
                "transition arithmetic",
            ),
            (
                "production generation comparison inverted",
                "GenerationTracker.h",
                "a_observedGeneration == expectedGeneration",
                "a_observedGeneration != expectedGeneration",
                "transition arithmetic",
            ),
            (
                "prepared assignment ignores entry age",
                "GenerationDiagnostic.cpp",
                "generation::GenerationFromEntryBits(bits));",
                "generation::GenerationFromEntryBits(bits) & 0u);",
                "exact entry-generation observation",
            ),
            (
                "repeat termination disabled",
                "GenerationDiagnostic.cpp",
                "            TerminateForAssignmentGuard();\n"
                "        }\n\n"
                "        [[nodiscard]] PendingAssignment PrepareAssignment",
                "            if (false) TerminateForAssignmentGuard();\n"
                "        }\n\n"
                "        [[nodiscard]] PendingAssignment PrepareAssignment",
                "direct non-returning process exit",
            ),
            (
                "invariant-fatal termination disabled",
                "GenerationDiagnostic.cpp",
                "            TerminateForAssignmentGuard();\n"
                "        }\n\n"
                "        [[noreturn]] void PreventRepeatedGeneration",
                "            if (false) TerminateForAssignmentGuard();\n"
                "        }\n\n"
                "        [[noreturn]] void PreventRepeatedGeneration",
                "direct non-returning process exit",
            ),
            (
                "diagnostic install claims early success",
                "GenerationDiagnostic.cpp",
                "    bool Install() noexcept\n    {\n",
                "    bool Install() noexcept\n    {\n"
                "        if (g_profile) return true;\n",
                "exact refusal/success structure",
            ),
            (
                "assignment-call rollback is a no-op",
                "GenerationDiagnostic.cpp",
                "        void RestoreAssignmentCallsOrStop(\n"
                "            const Profile& a_profile) noexcept\n"
                "        {\n",
                "        void RestoreAssignmentCallsOrStop(\n"
                "            const Profile& a_profile) noexcept\n"
                "        {\n"
                "            return;\n",
                "all-five-call rollback",
            ),
            (
                "periodic attribution logger always returns",
                "GenerationDiagnostic.cpp",
                "        if (!IsActive())\n            return;",
                "        if (true)\n            return;",
                "identity/attribution logger can be bypassed",
            ),
            (
                "ordinary slots classified as reserved player",
                "GenerationDiagnostic.cpp",
                "            if (index == player_slot::kIndex) {",
                "            if (index == player_slot::kIndex || true) {",
                "ordinary assignment return structure",
            ),
            (
                "ordinary commits classified as reserved player",
                "GenerationDiagnostic.cpp",
                "            if (a_pending.reservedPlayer) {",
                "            if (a_pending.reservedPlayer || true) {",
                "successful assignment commit",
            ),
            (
                "masked player-state predicate bypassed",
                "ReservedPlayerSlot.h",
                "    {\n        // Stock allocation retains",
                "    {\n        if (a_bits) return true;\n"
                "        // Stock allocation retains",
                "masked 0x07E00000/0x04000000",
            ),
            (
                "monitor accepts any live player entry",
                "TableMonitor.cpp",
                "            if (player_slot::IsLiveGenerationZero(entry) &&",
                "            if ((player_slot::IsLiveGenerationZero(entry) || true) &&",
                "TableMonitor reserved-player snapshot",
            ),
            (
                "prevented-event identity store disabled",
                "GenerationDiagnostic.cpp",
                "            g_lastPreventedEvent.store(event, std::memory_order_relaxed);",
                "            if (false)\n"
                "                g_lastPreventedEvent.store(event, std::memory_order_relaxed);",
                "exact atomic prevented event",
            ),
            (
                "prevented-attempt counter adds zero",
                "GenerationDiagnostic.cpp",
                "                    1, std::memory_order_release) + 1u;",
                "                    0, std::memory_order_release) + 0u;",
                "exact atomic prevented event",
            ),
            (
                "slot-counter allocation is undersized",
                "GenerationDiagnostic.cpp",
                "            nullptr, counterBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));",
                "            nullptr, counterBytes / 32u, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));",
                "exact zero-initialized full-width",
            ),
            (
                "periodic hottest capture always returns empty",
                "GenerationDiagnostic.cpp",
                "            CurrentReferenceSnapshot snapshot;\n"
                "            if (!g_profile)",
                "            CurrentReferenceSnapshot snapshot;\n"
                "            if (true) return snapshot;\n"
                "            if (!g_profile)",
                "hottest-slot capture no longer",
            ),
            (
                "periodic prevented count is forced to zero",
                "GenerationDiagnostic.cpp",
                "            g_preventedWrapAttempts.load(std::memory_order_acquire);",
                "            0; // g_preventedWrapAttempts.load(std::memory_order_acquire);",
                "event snapshot no longer acquire-loads",
            ),
        )
        for label, filename, old, new, error in adversarial_mutations:
            with self.subTest(mutation=label):
                mutated = dict(baseline)
                self.assertIn(old, mutated[filename])
                mutated[filename] = mutated[filename].replace(old, new, 1)
                with self.assertRaisesRegex(ValueError, error):
                    validate(mutated)


class CompiledSKSEContractTests(unittest.TestCase):
    def test_exact_compiled_contract_passes(self) -> None:
        dll, pe = _compiled_skse_fixture()
        contract = verifier.validate_compiled_skse_contract(dll, pe)
        self.assertEqual(
            contract["exports"],
            ("SKSEPlugin_Load", "SKSEPlugin_Query", "SKSEPlugin_Version"),
        )
        self.assertEqual(contract["dataVersion"], 1)
        self.assertEqual(contract["pluginVersion"], 0x020200)
        self.assertEqual(contract["name"], "SkyrimHandleCapRaise")
        self.assertEqual(contract["author"], "Skyrim Handle Audit")
        self.assertEqual(contract["addressIndependence"], 0)
        self.assertEqual(
            contract["compatibleVersions"],
            (
                0x01050610,
                0x01064920,
                0x010649B1,
                0x010400F0,
                *([0] * 12),
            ),
        )

    def test_missing_renamed_extra_or_forwarded_export_fails_closed(self) -> None:
        cases = {}
        dll, missing = _compiled_skse_fixture()
        missing.DIRECTORY_ENTRY_EXPORT.symbols.pop(1)
        cases["missing"] = (dll, missing, "must be exactly")

        dll, renamed = _compiled_skse_fixture()
        renamed.DIRECTORY_ENTRY_EXPORT.symbols[1].name = b"SKSEPlugin_Queri"
        cases["renamed"] = (dll, renamed, "must be exactly")

        dll, extra = _compiled_skse_fixture()
        extra.DIRECTORY_ENTRY_EXPORT.symbols.append(_symbol("Unexpected", 0x1020))
        cases["extra"] = (dll, extra, "must be exactly")

        dll, forwarded = _compiled_skse_fixture()
        forwarded.DIRECTORY_ENTRY_EXPORT.symbols[0].forwarder = b"other.Load"
        cases["forwarded"] = (dll, forwarded, "is forwarded")

        for label, (image, pe, message) in cases.items():
            with self.subTest(mutation=label):
                with self.assertRaisesRegex(ValueError, message):
                    verifier.validate_compiled_skse_contract(image, pe)

    def test_stale_or_malformed_version_data_fails_closed(self) -> None:
        mutations = (
            ("dataVersion", 0x400, "<I", 2, "dataVersion"),
            ("pluginVersion", 0x404, "<I", 0x020100, "pluginVersion"),
            ("name", 0x408, "<B", ord("X"), "name is"),
            ("author", 0x508, "<B", ord("X"), "author is"),
            ("supportEmail", 0x608, "<B", ord("X"), "supportEmail is"),
            ("versionIndependenceEx", 0x704, "<I", 1, "versionIndependenceEx"),
            ("addressIndependence", 0x708, "<I", 1, "addressIndependence"),
            ("GOG storefront tag", 0x70C + 2 * 4, "<I", 0x010649B0,
             "compatible runtime list differs"),
            ("seVersionRequired", 0x74C, "<I", 1, "seVersionRequired"),
        )
        for label, offset, fmt, replacement, message in mutations:
            with self.subTest(mutation=label):
                original, pe = _compiled_skse_fixture()
                image = bytearray(original)
                struct.pack_into(fmt, image, offset, replacement)
                with self.assertRaisesRegex(ValueError, message):
                    verifier.validate_compiled_skse_contract(bytes(image), pe)

        image, pe = _compiled_skse_fixture()
        malformed = bytearray(image)
        malformed[0x408:0x508] = b"X" * 256
        with self.assertRaisesRegex(ValueError, "name is not NUL-terminated"):
            verifier.validate_compiled_skse_contract(bytes(malformed), pe)

    def test_metadata_must_be_file_backed_writable_non_executable_data(self) -> None:
        dll, pe = _compiled_skse_fixture()
        pe.sections[1].SizeOfRawData = 0x300
        with self.assertRaisesRegex(ValueError, "not wholly backed"):
            verifier.validate_compiled_skse_contract(dll, pe)

        dll, pe = _compiled_skse_fixture()
        pe.sections[1].Characteristics = 0x60000020
        with self.assertRaisesRegex(ValueError, "readable, writable, non-executable"):
            verifier.validate_compiled_skse_contract(dll, pe)

    def test_current_release_dll_and_in_memory_mutations(self) -> None:
        dll_path = ROOT / "build" / "Release" / "SkyrimHandleCapRaise.dll"
        if not dll_path.is_file():
            self.skipTest("Release DLL has not been built")
        dll = dll_path.read_bytes()
        pe = verifier.pefile.PE(data=dll, fast_load=True)
        contract = verifier.validate_compiled_skse_contract(dll, pe)
        version_offset = int(contract["versionFileOffset"])
        self.assertEqual(contract["pluginVersion"], 0x020200)
        self.assertIn(0x010649B1, contract["compatibleVersions"])

        mutations = (
            ("stale plugin", version_offset + 4, "<I", 0x020100,
             "pluginVersion"),
            ("untagged GOG", version_offset + 0x30C + 2 * 4, "<I", 0x010649B0,
             "compatible runtime list differs"),
        )
        for label, offset, fmt, replacement, message in mutations:
            with self.subTest(mutation=label):
                mutated = bytearray(dll)
                struct.pack_into(fmt, mutated, offset, replacement)
                mutated_pe = verifier.pefile.PE(data=bytes(mutated), fast_load=True)
                with self.assertRaisesRegex(ValueError, message):
                    verifier.validate_compiled_skse_contract(
                        bytes(mutated), mutated_pe)

        query = next(
            symbol for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols
            if symbol.name == b"SKSEPlugin_Query")
        renamed = bytearray(dll)
        renamed[int(query.name_offset)] = ord("X")
        renamed_pe = verifier.pefile.PE(data=bytes(renamed), fast_load=True)
        with self.assertRaisesRegex(ValueError, "must be exactly"):
            verifier.validate_compiled_skse_contract(bytes(renamed), renamed_pe)


if __name__ == "__main__":
    unittest.main()
