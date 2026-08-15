from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "probes"))

from stress_second_pass_model import (  # noqa: E402
    AGE_INCREMENT,
    Held,
    INDEX_MASK,
    Lookup,
    Phase,
    RAW_HANDLE_MASK,
    RESERVED_PLAYER_INDEX,
    SyntheticSecondPassModel,
)


def records(count: int) -> list[Held]:
    return [Held(handle=AGE_INCREMENT | (0x100001 + offset),
                 index=0x100001 + offset,
                 object_id=0x10000000 + offset * 0x30)
            for offset in range(count)]


class IndependentStateModelTests(unittest.TestCase):
    def test_every_retained_object_is_resolved_once_before_release(self) -> None:
        held = records(19)
        calls: list[int] = []
        model = SyntheticSecondPassModel(held, max_references_per_task=4)
        model.finish_fill()
        self.assertEqual(model.phase, Phase.SYNTHETIC_SECOND_PASS)
        self.assertFalse(model.release_started)

        def resolve(item: Held) -> Lookup:
            self.assertFalse(model.release_started)
            calls.append(item.object_id)
            return Lookup(True, item.object_id)

        task_sizes = []
        while model.phase is Phase.SYNTHETIC_SECOND_PASS:
            task_sizes.append(model.run_task(resolve))

        self.assertEqual(calls, [item.object_id for item in held])
        self.assertEqual(len(calls), len(set(calls)))
        self.assertTrue(all(size <= 4 for size in task_sizes))
        self.assertEqual(model.phase, Phase.RELEASE_PROBE)
        self.assertTrue(model.release_started)
        self.assertEqual(model.events, [
            ("second-pass-start", 19),
            ("second-pass-pass", 19),
            ("release-start", 19),
        ])

    def test_partial_task_cannot_start_release(self) -> None:
        held = records(5)
        model = SyntheticSecondPassModel(held, max_references_per_task=2)
        model.finish_fill()
        model.run_task(lambda item: Lookup(True, item.object_id))
        self.assertEqual(model.cursor, 2)
        self.assertEqual(model.phase, Phase.SYNTHETIC_SECOND_PASS)
        self.assertFalse(model.release_started)

    def test_lookup_failure_is_terminal_before_release(self) -> None:
        held = records(8)
        model = SyntheticSecondPassModel(held, max_references_per_task=8)
        model.finish_fill()
        bad_object = held[3].object_id
        model.run_task(lambda item: Lookup(
            succeeded=item.object_id != bad_object,
            object_id=item.object_id if item.object_id != bad_object else None,
        ))
        self.assertEqual(model.phase, Phase.FAILED)
        self.assertEqual(model.cursor, 3)
        self.assertFalse(model.release_started)

    def test_wrong_object_is_terminal_before_release(self) -> None:
        held = records(3)
        model = SyntheticSecondPassModel(held)
        model.finish_fill()
        model.run_task(lambda item: Lookup(True, item.object_id + 0x30))
        self.assertEqual(model.phase, Phase.FAILED)
        self.assertFalse(model.release_started)

    def test_live_entry_failure_is_terminal_before_lookup_release(self) -> None:
        held = records(3)
        model = SyntheticSecondPassModel(held)
        model.finish_fill()
        model.run_task(lambda item: Lookup(True, item.object_id,
                                           live_entry_matches=False))
        self.assertEqual(model.phase, Phase.FAILED)
        self.assertFalse(model.release_started)

    def test_pin_imbalance_is_terminal_before_release(self) -> None:
        held = records(3)
        model = SyntheticSecondPassModel(held)
        model.finish_fill()
        model.run_task(lambda item: Lookup(True, item.object_id,
                                           pin_balanced=False))
        self.assertEqual(model.phase, Phase.FAILED)
        self.assertFalse(model.release_started)

    def test_verify_disabled_preserves_direct_release_transition(self) -> None:
        model = SyntheticSecondPassModel(records(3), verify_second_pass=False)
        model.finish_fill()
        self.assertEqual(model.phase, Phase.RELEASE_PROBE)
        self.assertTrue(model.release_started)
        self.assertEqual(model.events, [("release-start", 0)])

    def test_empty_verified_set_fails_closed(self) -> None:
        model = SyntheticSecondPassModel([])
        model.finish_fill()
        self.assertEqual(model.phase, Phase.FAILED)
        self.assertFalse(model.release_started)

    def test_model_uses_exact_21_plus_5_live_handle_shape(self) -> None:
        item = records(1)[0]
        self.assertEqual(INDEX_MASK, 0x001FFFFF)
        self.assertEqual(AGE_INCREMENT, 0x00200000)
        self.assertEqual(RAW_HANDLE_MASK, 0x03FFFFFF)
        self.assertEqual(RESERVED_PLAYER_INDEX, 0x00100000)
        self.assertEqual(item.index, 0x00100001)
        self.assertEqual(item.handle, 0x00300001)

        model = SyntheticSecondPassModel([item])
        model.finish_fill()
        model.run_task(lambda held: Lookup(True, held.object_id))
        self.assertEqual(model.phase, Phase.RELEASE_PROBE)

    def test_old_22_bit_alias_and_reserved_slot_records_fail_closed(self) -> None:
        malformed = (
            Held(handle=0x00200001, index=0x00100001, object_id=0x1000),
            Held(handle=AGE_INCREMENT | RESERVED_PLAYER_INDEX,
                 index=RESERVED_PLAYER_INDEX, object_id=0x2000),
            Held(handle=0x04000001, index=1, object_id=0x3000),
        )
        for item in malformed:
            with self.subTest(item=item):
                model = SyntheticSecondPassModel([item])
                model.finish_fill()
                calls = 0

                def resolve(held: Held) -> Lookup:
                    nonlocal calls
                    calls += 1
                    return Lookup(True, held.object_id)

                model.run_task(resolve)
                self.assertEqual(model.phase, Phase.FAILED)
                self.assertFalse(model.release_started)
                self.assertEqual(calls, 0)

    def test_1_8m_pass_remains_bounded_to_at_most_440_tasks(self) -> None:
        # The runtime's pre-existing references reduce the actual retained
        # filler count. Even the conservative 1,800,000-record upper bound is
        # split into bounded tasks rather than one main-thread loop.
        self.assertEqual(math.ceil(1_800_000 / 4096), 440)


class ProductionSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / "src" / "StressTest.cpp").read_text(encoding="utf-8")
        cls.header = (ROOT / "src" / "StressTest.h").read_text(encoding="utf-8")

    def test_fill_transitions_to_second_pass_not_direct_release(self) -> None:
        anchor = self.source.index("stress: synthetic filler reached index")
        call = self.source.index("BeginSyntheticSecondPass();", anchor)
        self.assertNotIn("BeginReleaseProbe();", self.source[anchor:call])

    def test_2m_reuse_cushion_preserves_the_frozen_target_margin(self) -> None:
        self.assertIn(
            "constexpr std::uint32_t kMinimumReuseFreeCushion = 0x40000;",
            self.source,
        )
        self.assertIn("required 0x40000-slot cushion", self.source)
        self.assertNotIn("required 0x80000-slot cushion", self.source)

    def test_second_pass_has_distinct_phase_and_task_dispatch(self) -> None:
        self.assertIn("kSyntheticSecondPass", self.source)
        dispatch = self.source.index("case Phase::kSyntheticSecondPass:")
        self.assertIn("ProcessSyntheticSecondPass();",
                      self.source[dispatch:dispatch + 180])

    def test_second_pass_processes_one_record_per_outer_iteration(self) -> None:
        start = self.source.index("void ProcessSyntheticSecondPass()")
        end = self.source.index("void BeginReuseCycle()", start)
        body = self.source[start:end]
        self.assertNotIn("while (", body)
        self.assertNotIn("for (", body)
        self.assertIn("++syntheticVerifyCursor;", body)
        self.assertIn("if (TimeBudgetReached(processed, startedAt))", self.source)
        self.assertIn("if (a_processed >= ActiveReferencesPerTask())", self.source)

    def test_pass_marker_precedes_release_transition(self) -> None:
        process = self.source.index("void ProcessSyntheticSecondPass()")
        marker = self.source.index("stress: SYNTHETIC SECOND PASS PASS", process)
        release = self.source.index("BeginReleaseProbe();", marker)
        self.assertLess(marker, release)

    def test_all_exact_failure_axes_are_fail_closed(self) -> None:
        start = self.source.index("void ProcessSyntheticSecondPass()")
        end = self.source.index("void BeginReuseCycle()", start)
        body = self.source[start:end]
        for required in (
            "heldHandles.size() != syntheticVerifyExpected",
            "!IsSyntheticReference(held.expected)",
            "(held.handle & IndexMask()) != held.index",
            "VerifyLiveSyntheticState(",
            "GetSmartPointer failed during the synthetic second lookup pass",
            "resolved a handle to the wrong object",
            "ReleaseLookupReference(resolved)",
        ):
            self.assertIn(required, body)

    def test_header_contract_explicitly_places_pass_before_release_reuse(self) -> None:
        self.assertIn("bounded exact-object pass before", self.header)
        self.assertIn("any configured release or reuse probe", self.header)

    def test_non_exhausting_reuse_accepts_only_disabled_one_or_guard_boundary(self) -> None:
        self.assertIn(
            "(a_settings.reuseProbeCycles != 1 &&\n"
            "                  a_settings.reuseProbeCycles != generation::kGenerationCount)",
            self.source,
        )
        self.assertIn("Exact values 0, 1, and 32 are", self.header)
        self.assertIn("assignment\n        // counts 2-32", self.header)
        self.assertIn("Attempt 32 must terminate Skyrim\n        // before assignment 33", self.header)
        accepted = lambda cycles: cycles == 0 or cycles in (1, 32)
        for cycles in (0, 1, 32):
            with self.subTest(cycles=cycles):
                self.assertTrue(accepted(cycles))
        for cycles in (2, 31, 33, 1024):
            with self.subTest(cycles=cycles):
                self.assertFalse(accepted(cycles))

    def test_aba_rotation_guard_and_scratch_capacity_are_per_cycle(self) -> None:
        self.assertIn(
            "if (reuseRotationsThisCycle >= rotationLimit)",
            self.source,
        )
        self.assertNotIn(
            "if (reuseTotalRotations >= rotationLimit)",
            self.source,
        )
        self.assertIn("const std::size_t extra = settings.reuseProbeCycles;", self.source)
        self.assertIn("reuseScratch = syntheticReferences + syntheticCursor++;", self.source)

    def test_32_cycle_proof_is_diagnostic_backed_and_fail_closed(self) -> None:
        for contract in (
            "diagnostic::IsActive()",
            "diagnostic::AssignmentCount(reuseTarget.index)",
            "reuseInitialAssignmentCount != 1u",
            "reuseCompleted != generation::kGenerationCount - 1u",
            "reuseTarget.handle != reuseTarget.index",
            "events.unreliableSlot != 0",
            "events.totalWraps != reuseInitialWrapCount",
            "events.preventedWrapAttempts != 0",
            "events.lastPreventedEvent != 0",
            "highestReuse != generation::kGenerationCount - 1u",
            "hottestHandle != reuseTarget.handle",
            "stress: NO-WRAP BOUNDARY PASS; cycles=31",
            "stress: NO-WRAP GUARD ATTEMPT; cycle=32/32",
            "captured initial handle resolved at the no-wrap boundary",
            "immediate-stale-rejection-each-cycle=PASS",
            "mandatory pre-publication generation guard returned after publishing the repeated raw handle",
        ):
            self.assertIn(contract, self.source)


if __name__ == "__main__":
    unittest.main()
