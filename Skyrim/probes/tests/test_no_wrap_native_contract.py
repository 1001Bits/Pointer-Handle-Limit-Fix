from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INDEX_BITS = 21
GENERATION_COUNT = 32
SAFE_REUSE_LIMIT = 31
INDEX_MASK = 0x001F_FFFF
GENERATION_MASK = 0x03E0_0000
IN_USE_MASK = 0x0400_0000
PLAYER_INDEX = 0x0010_0000


def transition(prior_assignments: int, observed_generation: int) -> tuple[int, int, bool, bool]:
    assignment_count = prior_assignments + 1
    expected_generation = assignment_count & (GENERATION_COUNT - 1)
    generation_matches = observed_generation == expected_generation
    would_repeat = (
        generation_matches
        and prior_assignments != 0
        and (prior_assignments & (GENERATION_COUNT - 1)) == 0
    )
    return assignment_count, prior_assignments, generation_matches, would_repeat


class NoWrapStateModelTests(unittest.TestCase):
    def test_all_32_distinct_generations_publish_then_first_repeat_is_prevented(self) -> None:
        issued: list[int] = []
        counter = 0
        hottest_successful_reuse = 0
        published_wraps = 0
        prevented_attempts = 0

        for _ in range(GENERATION_COUNT):
            observed = (counter + 1) & (GENERATION_COUNT - 1)
            assignment_count, reuse, matches, would_repeat = transition(counter, observed)
            self.assertTrue(matches)
            self.assertFalse(would_repeat)
            issued.append(observed)
            counter = assignment_count
            hottest_successful_reuse = max(hottest_successful_reuse, reuse)

        self.assertEqual(len(set(issued)), GENERATION_COUNT)
        self.assertEqual(issued, list(range(1, GENERATION_COUNT)) + [0])
        self.assertEqual(counter, GENERATION_COUNT)
        self.assertEqual(hottest_successful_reuse, SAFE_REUSE_LIMIT)

        observed = (counter + 1) & (GENERATION_COUNT - 1)
        assignment_count, reuse, matches, would_repeat = transition(counter, observed)
        self.assertTrue(matches)
        self.assertTrue(would_repeat)
        self.assertEqual(assignment_count, GENERATION_COUNT + 1)
        self.assertEqual(reuse, GENERATION_COUNT)
        self.assertEqual(observed, issued[0])

        # The production guard records this attempt separately and exits. It
        # never commits assignment_count, hottest reuse, or a published wrap.
        prevented_attempts += 1
        self.assertEqual(counter, GENERATION_COUNT)
        self.assertEqual(hottest_successful_reuse, SAFE_REUSE_LIMIT)
        self.assertEqual(published_wraps, 0)
        self.assertEqual(prevented_attempts, 1)

    def test_reserved_player_retains_successor_without_changing_raw_identity(self) -> None:
        detached_generation = SAFE_REUSE_LIMIT << INDEX_BITS
        for successor in (0, 1, 0x000F_FFFF, 0x0010_0001, INDEX_MASK):
            with self.subTest(successor=successor):
                injected_bits = detached_generation | successor
                live_bits = IN_USE_MASK | successor
                self.assertEqual(injected_bits & INDEX_MASK, successor)
                self.assertEqual(live_bits & (GENERATION_MASK | IN_USE_MASK), IN_USE_MASK)
                raw_handle = PLAYER_INDEX | (live_bits & GENERATION_MASK)
                self.assertEqual(raw_handle, PLAYER_INDEX)


class NativeSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.diagnostic = (ROOT / "src" / "GenerationDiagnostic.cpp").read_text(
            encoding="utf-8"
        )
        cls.diagnostic_header = (ROOT / "src" / "GenerationDiagnostic.h").read_text(
            encoding="utf-8"
        )
        cls.tracker = (ROOT / "src" / "GenerationTracker.h").read_text(
            encoding="utf-8"
        )
        cls.player = (ROOT / "src" / "ReservedPlayerSlot.h").read_text(
            encoding="utf-8"
        )
        cls.patch = (ROOT / "src" / "PatchTransaction.cpp").read_text(
            encoding="utf-8"
        )
        cls.main = (ROOT / "src" / "main.cpp").read_text(encoding="utf-8")
        cls.generator = (ROOT / "probes" / "gen_patchtable.py").read_text(
            encoding="utf-8"
        )

    @staticmethod
    def body(source: str, start_marker: str, end_marker: str) -> str:
        start = source.index(start_marker)
        end = source.index(end_marker, start)
        return source[start:end]

    def test_geometry_names_the_exact_safe_and_prevented_boundaries(self) -> None:
        self.assertIn("kSafeReuseLimit = kGenerationCount - 1u", self.tracker)
        self.assertIn("kFirstPreventedReuse = kGenerationCount", self.tracker)
        self.assertIn("static_assert(kSafeReuseLimit == 31u)", self.tracker)
        self.assertIn("static_assert(kFirstPreventedReuse == 32u)", self.tracker)

    def test_hook_prepares_before_stock_pointer_publisher_and_commits_after(self) -> None:
        hook = self.body(
            self.diagnostic,
            "void* __fastcall AssignmentHelperHook(",
            "[[nodiscard]] bool TextContains(",
        )
        prepare = hook.index("PrepareAssignment(a_destination, a_subobject)")
        publish = hook.index("original(a_destination, a_subobject)")
        commit = hook.index("CommitAssignment(pending")
        self.assertLess(prepare, publish)
        self.assertLess(publish, commit)

    def test_all_profile_hook_sites_are_lock_bracketed_before_cache_publication(self) -> None:
        for name in ("SE", "AE", "GOG", "VR"):
            with self.subTest(runtime=name):
                artifact = json.loads(
                    (ROOT / "artifacts" / f"patch_{name}.json").read_text(
                        encoding="utf-8"
                    )
                )
                hooks = artifact["assignment_hooks"]
                self.assertEqual(len(hooks["sites"]), 5)
                self.assertEqual(
                    hooks["helper_bytes"],
                    "40534883ec20488bd9488b09483bca74",
                )
                for site in hooks["sites"]:
                    self.assertEqual(site["call_target_rva"], hooks["helper_rva"])
                    self.assertEqual(site["setup_rva"] + 11, site["call_rva"])
                    self.assertLess(site["lock_call_rva"], site["call_rva"])
                    self.assertLess(site["call_rva"], site["writer_rva"])
                    self.assertLess(site["writer_rva"], site["unlock_call_rva"])

    def test_generator_proves_manager_lock_and_stock_publisher_abi(self) -> None:
        for contract in (
            "if not (lock_pos < call_pos < unlock_pos)",
            '"mov", "rbx, rcx"',
            '"mov", "qword ptr [rbx], rdx"',
            '"mov", "rax, rbx"',
            'helper_insns[-1].mnemonic != "ret"',
            "not (call_rva < clear_rva < writer_rva)",
        ):
            self.assertIn(contract, self.generator)

    def test_authenticated_stock_helper_is_published_before_any_call_patch(self) -> None:
        install = self.body(
            self.diagnostic,
            "bool Install() noexcept",
            "bool IsActive() noexcept",
        )
        original = install.index("g_originalAssignmentHelper.store(original")
        make_writable = install.index("VirtualProtect(g_runtime.text.begin")
        first_hook_write = install.index(
            "g_runtime.imageBase + site.callRva),\n                call"
        )
        self.assertLess(original, make_writable)
        self.assertLess(original, first_hook_write)

    def test_install_failure_restores_calls_before_clearing_stock_helper(self) -> None:
        install = self.body(
            self.diagnostic,
            "bool Install() noexcept",
            "bool IsActive() noexcept",
        )
        cache_start = install.index("if (!cacheGood)")
        cache_restore = install.index("RestoreAssignmentCallsOrStop", cache_start)
        cache_clear = install.index(
            "g_originalAssignmentHelper.store(nullptr", cache_restore
        )
        self.assertLess(
            cache_restore,
            cache_clear,
        )
        cache_return = install.index("return false;", cache_clear)
        final_restore_start = install.index("DWORD ignored = 0;", cache_return)
        protection_failure = install[final_restore_start:]
        self.assertLess(
            protection_failure.index("RestoreAssignmentCallsOrStop"),
            protection_failure.index("g_originalAssignmentHelper.store(nullptr"),
        )

    def test_counter_access_is_atomic_and_boundary_does_not_commit_it(self) -> None:
        self.assertIn("std::atomic_ref<std::uint32_t>", self.diagnostic)
        self.assertIn("counter.load(std::memory_order_acquire)", self.diagnostic)
        self.assertIn("counter.store(a_count, std::memory_order_release)", self.diagnostic)
        prevented = self.body(
            self.diagnostic,
            "[[noreturn]] void PreventRepeatedGeneration(",
            "[[nodiscard]] PendingAssignment PrepareAssignment(",
        )
        self.assertNotIn("StoreAssignmentCount", prevented)
        self.assertNotIn("UpdateHottest", prevented)
        self.assertIn("g_lastPreventedEvent.store", prevented)
        self.assertIn("g_preventedWrapAttempts.fetch_add", prevented)

    def test_no_post_publication_wrap_counter_mutation_exists(self) -> None:
        for forbidden in (
            "g_generationWraps",
            "g_lastWrapEvent",
            "g_wrapEventSequence",
            "snapshot.totalWraps =",
            "snapshot.lastWrapEvent =",
        ):
            self.assertNotIn(forbidden, self.diagnostic)
        self.assertIn("publishedWraps=0", self.diagnostic)
        self.assertIn("preventedWrapAttempts", self.diagnostic_header)

    def test_successful_high_water_is_low_noise_and_boundary_is_separate(self) -> None:
        hottest = self.body(
            self.diagnostic,
            "void UpdateHottest(",
            "[[noreturn]] void TerminateForAssignmentGuard(",
        )
        self.assertIn("compare_exchange_weak", hottest)
        self.assertIn("generation reuse high-water:", hottest)
        self.assertIn("safeReuseLimit=%u guard=active", hottest)
        self.assertIn("publishedWraps=0", hottest)
        self.assertEqual(
            hottest.count("WARNING: generation reuse reached safe limit:"), 1
        )
        self.assertIn(
            "a_reuseCount == generation::kSafeReuseLimit", hottest
        )
        self.assertIn("the next reuse of this slot", hottest)
        commit = self.body(
            self.diagnostic,
            "void CommitAssignment(",
            "void* __fastcall AssignmentHelperHook(",
        )
        self.assertIn("UpdateHottest(a_pending.transition.reuseCount, handle, true)", commit)

    def test_boundary_log_is_self_authenticating_and_exit_code_is_named(self) -> None:
        for field in (
            "tablePointer=null",
            "objectCachePublished=0",
            "assignmentReturned=0",
            "managerUnlocked=0",
            "safeReuseLimit=%u",
            "publishedWraps=0",
            "preventedWrapAttempts=%llu",
        ):
            self.assertIn(field, self.diagnostic)
        self.assertIn("kGenerationGuardExitCode = 0x53485752u", self.diagnostic)
        self.assertIn(
            "TerminateProcess(GetCurrentProcess(), kGenerationGuardExitCode)",
            self.diagnostic,
        )
        self.assertIn("ExitProcess(kGenerationGuardExitCode)", self.diagnostic)
        self.assertNotIn("raw handle can be published", self.diagnostic)
        terminate = self.body(
            self.diagnostic,
            "[[noreturn]] void TerminateForAssignmentGuard(",
            "[[noreturn]] void FatalAssignmentGuard(",
        )
        self.assertIn("preceding FATAL line records the exact publication stage", terminate)
        self.assertNotIn("before the table pointer", terminate)
        self.assertIn("tablePointer=null keeps the repeated handle unresolvable", self.diagnostic)

    def test_periodic_hottest_log_keeps_identity_and_attribution_fields(self) -> None:
        status = self.body(
            self.diagnostic,
            "void LogStatus(",
            "\n    }\n}",
        )
        for field in (
            "highest=%u safeReuseLimit=%u guard=active",
            "hottestSlot=%06X currentHandle=%08X",
            "currentReference=%p",
            r'FormID=%08X source=\"%s\"',
            "publishedWraps=%llu preventedWrapAttempts=%llu",
        ):
            self.assertIn(field, status)

    def test_reserved_player_uses_successor_bits_but_generation_only_live_mask(self) -> None:
        selector = self.body(
            self.patch,
            "std::uint32_t __fastcall SelectPlayerFreeHead(",
            "[[nodiscard]] bool ReservationRelayIsReachable(",
        )
        self.assertIn(
            "(emptyHead ? player_slot::kIndex : ordinaryHead)", selector
        )
        self.assertNotIn("ordinaryHead & generation::kIndexMask", selector)
        self.assertIn("kLiveGenerationZeroMask", self.player)
        self.assertIn(
            "(a_bits & kLiveGenerationZeroMask) ==\n            generation::kInUseMask",
            self.player,
        )

    def test_reserved_player_is_counted_separately_from_ordinary_wrap_guard(self) -> None:
        prepare = self.body(
            self.diagnostic,
            "[[nodiscard]] PendingAssignment PrepareAssignment(",
            "void CommitAssignment(",
        )
        player_branch = prepare.index("if (index == player_slot::kIndex)")
        ordinary_counter = prepare.index("LoadAssignmentCount(index)")
        self.assertLess(player_branch, ordinary_counter)
        self.assertIn("HasLiveGenerationZeroState(bits)", prepare)
        self.assertIn("return { index, bits, {}, true };", prepare)

    def test_callback_has_no_failure_path_after_guard_install_succeeds(self) -> None:
        callback = self.body(
            self.main,
            "bool OnCommittedWhileManagerLocked(",
            "void OnPatchAborted(",
        )
        installed = callback.index("state.diagnosticInstalled = diagnostic::Install()")
        reporter = callback.index("monitor::Start(")
        final_success = callback.rindex("return true;")
        self.assertLess(installed, reporter)
        self.assertLess(reporter, final_success)
        self.assertNotIn("return false;", callback[reporter:final_success])

    def test_transaction_invokes_commit_callback_under_lock_and_rolls_back_on_false(self) -> None:
        raise_body = self.body(
            self.patch,
            "Result Raise(",
            "\n    }\n}",
        )
        lock = raise_body.index("LockManager(a_runtime, *profile)")
        callback = raise_body.index("onCommittedWhileManagerLocked")
        rollback = raise_body.index("RollBackOrStop", callback)
        cancel = raise_body.index("CancelReservationRelays", rollback)
        unlock = raise_body.index("UnlockManager", cancel)
        free = raise_body.index("VirtualFree(table", unlock)
        notify = raise_body.index("notifyAbort()", free)
        self.assertLess(lock, callback)
        self.assertLess(callback, rollback)
        self.assertLess(rollback, cancel)
        self.assertLess(cancel, unlock)
        self.assertLess(unlock, free)
        self.assertLess(free, notify)


if __name__ == "__main__":
    unittest.main()
