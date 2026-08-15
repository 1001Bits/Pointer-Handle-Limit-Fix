from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROBES = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROBES))

import verify_live_lifecycle as verifier  # noqa: E402


def _checkpoint(
    event: str,
    ordinal: int,
    live: bool = True,
    load_attempt: int | None = None,
    lifecycle: tuple[int, int, int] | None = None,
    object_address: str | None = None,
    singleton_address: str | None = None,
) -> str:
    reservation = "live-player" if live else "detached"
    handle = "00100000" if live else "n/a"
    attempt = f" loadAttempt={load_attempt}" if load_attempt is not None else ""
    checkpoint = (
        f"lifecycle: EngineFixesFormCaching revalidation PASS "
        f"event={event} ordinal={ordinal}\n"
        f"lifecycle: checkpoint BEGIN event={event} ordinal={ordinal}{attempt}\n"
        f"lifecycle: checkpoint PASS event={event} ordinal={ordinal}{attempt} "
        f"playerReservation={reservation} playerRawHandle={handle} "
        "reservedSlot=100000 ordinaryFIFO=ABSENT"
    )
    if lifecycle is None:
        lifecycle = (1, 0, 1) if live else (0, 0, 0)
    if object_address is None:
        object_address = "0000010000000000" if live else "0000000000000000"
    if singleton_address is None:
        singleton_address = object_address
    return checkpoint + "\n" + _lifecycle_snapshot(
        event,
        ordinal,
        *lifecycle,
        object_address,
        singleton_address,
        live=live,
    )


def _load_attempt(
    attempt: int,
    pre_ordinal: int,
    post_ordinal: int,
    pre_live: bool,
    post_live: bool = True,
    lifecycle: tuple[int, int, int] | None = None,
    object_address: str | None = None,
    singleton_address: str | None = None,
) -> str:
    return "\n".join(
        (
            _checkpoint(
                "kPreLoadGame", pre_ordinal, pre_live, attempt,
                lifecycle, object_address, singleton_address,
            ),
            f"lifecycle: load attempt END loadAttempt={attempt} result=success",
            _checkpoint(
                "kPostLoadGame", post_ordinal, post_live, attempt,
                lifecycle, object_address, singleton_address,
            ),
        )
    )


def _live_reservation(object_address: str, singleton_address: str) -> str:
    return (
        "player reservation: live-player PASS; slot=100000 "
        f"rawHandle=00100000 object={object_address} singleton={singleton_address} "
        "generation=0."
    )


def _player_lifecycle_transition(
    constructors: int,
    releases: int,
    object_address: str,
) -> str:
    return (
        "player lifecycle transition: "
        f"constructorAssignments={constructors} "
        f"releaseQuarantines={releases} "
        "reservedSlot=100000 raw=00100000 "
        f"object={object_address}"
    )


def _lifecycle_counters(
    constructors: int,
    releases: int,
    assignments: int,
    constructor_delta: int,
    release_delta: int,
    assignment_delta: int,
) -> str:
    return (
        "player lifecycle counters: "
        f"constructorAssignments={constructors} (+{constructor_delta}) "
        f"releaseQuarantines={releases} (+{release_delta}) "
        f"lifecycleAssignments={assignments} (+{assignment_delta}) "
        "tracking=active reservation=live-player raw=00100000"
    )


def _lifecycle_snapshot(
    event: str,
    ordinal: int,
    constructors: int,
    releases: int,
    assignments: int,
    object_address: str,
    singleton_address: str,
    live: bool = True,
) -> str:
    reservation = "live-player" if live else "detached"
    raw = "00100000" if live else "n/a"
    return (
        f"lifecycle: snapshot event={event} ordinal={ordinal} "
        f"constructorAssignments={constructors} releaseQuarantines={releases} "
        f"lifecycleAssignments={assignments} reservation={reservation} raw={raw} "
        f"object={object_address} singleton={singleton_address}"
    )


def _valid_log() -> str:
    return "\n".join(
        (
            "configuration: GenerationWrapDetection=1 VerboseLogging=1 LifecycleVerification=1 SampleSize=16",
            verifier.ENGINE_FIXES_INTEROP_LINE,
            verifier.CAP_SUCCESS_LINE,
            _checkpoint("kDataLoaded", 1, False),
            _checkpoint("kNewGame", 1),
            _load_attempt(1, 1, 1, True),
            _player_lifecycle_transition(2, 1, "0000020000000000"),
            _load_attempt(
                2, 2, 2, True, lifecycle=(2, 1, 2),
                object_address="0000020000000000",
                singleton_address="0000020000000000",
            ),
            _checkpoint(
                "kNewGame", 2, lifecycle=(2, 1, 2),
                object_address="0000020000000000",
                singleton_address="0000020000000000",
            ),
        )
    )


def _valid_orchestrator() -> dict[str, object]:
    return {
        "result": "PASS",
        "noFocusOrInputApisUsed": True,
        "secondSave": "LifecycleB",
        "events": [
            {
                "kind": "devbench",
                "data": {
                    "tool": "papyrus",
                    "arguments": {
                        "action": "call",
                        "script": "Game",
                        "function": "QuitToMainMenu",
                        "args": [],
                        "timeoutMs": 5000,
                    },
                },
            },
            {
                "kind": "quit-issued-once",
                "data": {
                    "requestOrdinal": 1,
                    "requestTotal": 2,
                    "phase": "before-force-reset",
                    "script": "Game",
                    "function": "QuitToMainMenu",
                    "statusCode": 200,
                    "transportOk": True,
                },
            },
            {
                "kind": "stable-main-menu-before-force-reset",
                "data": {
                    "requestOrdinal": 1,
                    "requestTotal": 2,
                    "phase": "before-force-reset",
                    "detachedPlayerRequired": False,
                },
            },
            {
                "kind": "devbench",
                "data": {
                    "tool": "console",
                    "arguments": {
                        "action": "exec",
                        "command": "ForceReset",
                        "capture": False,
                    },
                },
            },
            {
                "kind": "force-reset-issued-once",
                "data": {"command": "ForceReset", "eventHeadBefore": 4},
            },
            {
                "kind": "force-reset-console-event",
                "data": {
                    "seq": 5,
                    "topic": "console.command",
                    "command": "ForceReset",
                },
            },
            {
                "kind": "force-reset-recreation",
                "data": {
                    "before": {
                        "constructorAssignments": 1,
                        "releaseQuarantines": 0,
                        "object": "0000010000000000",
                    },
                    "after": {
                        "constructorAssignments": 2,
                        "releaseQuarantines": 1,
                        "object": "0000020000000000",
                        "rawHandle": "00100000",
                    },
                },
            },
            {
                "kind": "stable-main-menu-after-force-reset",
                "data": {
                    "detachedPlayerRequired": False,
                    "liveReservedPlayerRequired": True,
                },
            },
            {
                "kind": "load-complete",
                "data": {
                    "name": "LifecycleB",
                    "attempt": 2,
                    "pre": "live-player",
                    "post": "live-player",
                },
            },
            {
                "kind": "force-reset-transition",
                "data": {
                    "before": {
                        "constructorAssignments": 1,
                        "releaseQuarantines": 0,
                        "lifecycleAssignments": 1,
                        "object": "0000010000000000",
                        "singleton": "0000010000000000",
                    },
                    "immediate": {
                        "constructorAssignments": 2,
                        "releaseQuarantines": 1,
                        "object": "0000020000000000",
                        "rawHandle": "00100000",
                    },
                    "preLoad": {
                        "event": "kPreLoadGame",
                        "ordinal": 2,
                        "loadAttempt": 2,
                        "constructorAssignments": 2,
                        "releaseQuarantines": 1,
                        "lifecycleAssignments": 2,
                        "object": "0000020000000000",
                        "singleton": "0000020000000000",
                        "rawHandle": "00100000",
                        "ordinaryFIFO": "ABSENT",
                    },
                    "postLoad": {
                        "event": "kPostLoadGame",
                        "ordinal": 2,
                        "loadAttempt": 2,
                        "constructorAssignments": 2,
                        "releaseQuarantines": 1,
                        "lifecycleAssignments": 2,
                        "object": "0000020000000000",
                        "singleton": "0000020000000000",
                        "rawHandle": "00100000",
                        "ordinaryFIFO": "ABSENT",
                    },
                },
            },
            {
                "kind": "devbench",
                "data": {
                    "tool": "papyrus",
                    "arguments": {
                        "action": "call",
                        "script": "Game",
                        "function": "QuitToMainMenu",
                        "args": [],
                        "timeoutMs": 5000,
                    },
                },
            },
            {
                "kind": "quit-issued-once",
                "data": {
                    "requestOrdinal": 2,
                    "requestTotal": 2,
                    "phase": "after-load-b",
                    "script": "Game",
                    "function": "QuitToMainMenu",
                    "statusCode": 200,
                    "transportOk": True,
                },
            },
            {
                "kind": "stable-main-menu-after-load-b",
                "data": {
                    "requestOrdinal": 2,
                    "requestTotal": 2,
                    "phase": "after-load-b",
                    "detachedPlayerRequired": False,
                },
            },
            {
                "kind": "quit-to-main-menu-request-contract",
                "data": {
                    "request": "Game.QuitToMainMenu",
                    "expectedCount": 2,
                    "observedCount": 2,
                    "phases": ["before-force-reset", "after-load-b"],
                    "eachPhaseExactlyOnce": True,
                    "retries": 0,
                },
            },
        ],
    }


def _valid_observations() -> dict[str, object]:
    document = verifier.observation_template()
    document["runtime"] = "Skyrim AE 1.6.1170"
    document["plugin_sha256"] = "a" * 64
    document["mod_versions"]["Precision"] = "2.0.4"
    document["mod_versions"]["OpenAnimationReplacer"] = "2.3.6"
    for name in verifier.REQUIRED_COMPATIBILITY_CASES:
        document["cases"][name] = {
            "result": "pass",
            "notes": "Observed in game.",
        }
    document["cases"]["alternate_conversation_camera"] = {
        "result": "not-applicable",
        "notes": "Not supported on this runtime.",
    }
    return document


class VerifyLogTests(unittest.TestCase):
    def test_accepts_required_single_process_sequence(self) -> None:
        result = verifier.verify_log(_valid_log())
        self.assertTrue(result.passed, result.errors)

    def test_rejects_any_critical_line(self) -> None:
        for critical_line in (
            "CRITICAL: HANDLE GENERATION WRAP DETECTED: index=100001",
            "CRITICAL: unexpected compatibility failure",
        ):
            with self.subTest(critical_line=critical_line):
                result = verifier.verify_log(f"{_valid_log()}\n{critical_line}")
                self.assertFalse(result.passed)
                self.assertIn(
                    "failure marker present: CRITICAL:",
                    result.errors,
                )

    def test_rejects_historical_4m_transaction_identity(self) -> None:
        text = _valid_log().replace(
            verifier.CAP_SUCCESS_LINE,
            "SUCCESS: reference handle slots raised 1048576 -> 4194304",
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("2M/21+5" in error for error in result.errors))

    def test_rejects_force_reset_counter_jump(self) -> None:
        text = _valid_log().replace(
            _player_lifecycle_transition(2, 1, "0000020000000000"),
            _player_lifecycle_transition(3, 1, "0000020000000000"),
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("immediate ForceReset" in x for x in result.errors))

    def test_ignores_stale_periodic_monitor_records(self) -> None:
        transition = _player_lifecycle_transition(2, 1, "0000020000000000")
        text = _valid_log().replace(
            transition,
            "\n".join(
                (
                    _live_reservation(
                        "0000DEAD00000020", "0000DEAD00000000"
                    ),
                    _lifecycle_counters(99, 88, 77, 9, 8, 7),
                    transition,
                )
            ),
        )
        result = verifier.verify_log(text)
        self.assertTrue(result.passed, result.errors)

    def test_rejects_missing_immediate_force_reset_recreation(self) -> None:
        transition = _player_lifecycle_transition(2, 1, "0000020000000000")
        result = verifier.verify_log(_valid_log().replace(transition + "\n", ""))
        self.assertFalse(result.passed)
        self.assertTrue(any("immediate post-load" in x for x in result.errors))

    def test_rejects_unchanged_immediate_player_identity(self) -> None:
        text = _valid_log().replace(
            _player_lifecycle_transition(2, 1, "0000020000000000"),
            _player_lifecycle_transition(2, 1, "0000010000000000"),
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("changed non-null" in x for x in result.errors))

    def test_rejects_post_reset_preload_assignment_count(self) -> None:
        text = _valid_log().replace(
            "lifecycle: snapshot event=kPreLoadGame ordinal=2 "
            "constructorAssignments=2 releaseQuarantines=1 "
            "lifecycleAssignments=2",
            "lifecycle: snapshot event=kPreLoadGame ordinal=2 "
            "constructorAssignments=2 releaseQuarantines=1 "
            "lifecycleAssignments=3",
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("kPreLoadGame snapshot" in x for x in result.errors))

    def test_rejects_post_reset_snapshot_identity_mismatch(self) -> None:
        text = _valid_log().replace(
            "lifecycle: snapshot event=kPostLoadGame ordinal=2 "
            "constructorAssignments=2 releaseQuarantines=1 "
            "lifecycleAssignments=2 reservation=live-player raw=00100000 "
            "object=0000020000000000 singleton=0000020000000000",
            "lifecycle: snapshot event=kPostLoadGame ordinal=2 "
            "constructorAssignments=2 releaseQuarantines=1 "
            "lifecycleAssignments=2 reservation=live-player raw=00100000 "
            "object=0000030000000000 singleton=0000030000000000",
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("immediate recreated" in x for x in result.errors))

    def test_rejects_missing_fresh_post_load_snapshot(self) -> None:
        snapshot = _lifecycle_snapshot(
            "kPostLoadGame", 1, 1, 0, 1,
            "0000010000000000", "0000010000000000",
        )
        result = verifier.verify_log(_valid_log().replace(snapshot + "\n", ""))
        self.assertFalse(result.passed)
        self.assertTrue(any("no following exact live lifecycle snapshot" in x for x in result.errors))

    def test_rejects_checkpoint_snapshot_reservation_disagreement(self) -> None:
        text = _valid_log().replace(
            "lifecycle: snapshot event=kNewGame ordinal=1 "
            "constructorAssignments=1 releaseQuarantines=0 "
            "lifecycleAssignments=1 reservation=live-player raw=00100000",
            "lifecycle: snapshot event=kNewGame ordinal=1 "
            "constructorAssignments=1 releaseQuarantines=0 "
            "lifecycleAssignments=1 reservation=detached raw=n/a",
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("disagrees with its PASS" in x for x in result.errors))

    def test_rejects_duplicate_checkpoint_snapshot(self) -> None:
        snapshot = _lifecycle_snapshot(
            "kNewGame", 1, 1, 0, 1,
            "0000010000000000", "0000010000000000",
        )
        result = verifier.verify_log(_valid_log().replace(snapshot, snapshot + "\n" + snapshot, 1))
        self.assertFalse(result.passed)
        self.assertTrue(any("2 lifecycle snapshots" in x for x in result.errors))

    def test_rejects_checkpoint_snapshot_separated_from_pass(self) -> None:
        snapshot = _lifecycle_snapshot(
            "kNewGame", 1, 1, 0, 1,
            "0000010000000000", "0000010000000000",
        )
        result = verifier.verify_log(
            _valid_log().replace(snapshot, "unrelated log line\n" + snapshot, 1)
        )
        self.assertFalse(result.passed)
        self.assertTrue(any("not immediately after its PASS" in x for x in result.errors))

    def test_rejects_force_reset_without_stable_new_player_identity(self) -> None:
        text = _valid_log().replace(
            "object=0000020000000000 singleton=0000020000000000",
            "object=0000010000000000 singleton=0000010000000000",
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("immediate recreated" in x for x in result.errors))

    def test_accepts_live_player_at_data_loaded(self) -> None:
        text = _valid_log().replace(
            _checkpoint("kDataLoaded", 1, False),
            _checkpoint("kDataLoaded", 1, True),
        )
        result = verifier.verify_log(text)
        self.assertTrue(result.passed, result.errors)

    def test_rejects_invalid_data_loaded_reservation_states(self) -> None:
        base = _valid_log()
        mutations = (
            (
                "playerReservation=detached playerRawHandle=n/a",
                "playerReservation=detached playerRawHandle=00100000",
                "detached reservation reported raw handle",
            ),
            (
                "playerReservation=detached playerRawHandle=n/a",
                "playerReservation=live-player playerRawHandle=00400000",
                "live player handle was 00400000",
            ),
            (
                "playerReservation=detached playerRawHandle=n/a",
                "playerReservation=ordinary playerRawHandle=n/a",
                "unknown player reservation ordinary",
            ),
        )
        for old, new, expected_error in mutations:
            with self.subTest(replacement=new):
                text = base.replace(old, new, 1)
                result = verifier.verify_log(text)
                self.assertFalse(result.passed)
                self.assertTrue(
                    any(expected_error in error for error in result.errors),
                    result.errors,
                )

    def test_rejects_invalid_live_data_loaded_slot_or_fifo(self) -> None:
        base = _valid_log().replace(
            _checkpoint("kDataLoaded", 1, False),
            _checkpoint("kDataLoaded", 1, True),
        )
        mutations = (
            (
                "reservedSlot=100000",
                "reservedSlot=100001",
                "reserved slot was 100001",
            ),
            (
                "ordinaryFIFO=ABSENT",
                "ordinaryFIFO=PRESENT",
                "FIFO result was PRESENT",
            ),
        )
        for old, new, expected_error in mutations:
            with self.subTest(replacement=new):
                text = base.replace(old, new, 1)
                result = verifier.verify_log(text)
                self.assertFalse(result.passed)
                self.assertTrue(
                    any(expected_error in error for error in result.errors),
                    result.errors,
                )

    def test_rejects_missing_authenticated_engine_fixes_chain(self) -> None:
        text = _valid_log().replace(verifier.ENGINE_FIXES_INTEROP_LINE + "\n", "")
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("Engine Fixes FormCaching" in x for x in result.errors))

    def test_rejects_mutated_engine_fixes_identity(self) -> None:
        text = _valid_log().replace("destinationRva=000711F0", "destinationRva=000711F1")
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("Engine Fixes FormCaching" in x for x in result.errors))

    def test_rejects_decorated_engine_fixes_identity_line(self) -> None:
        text = _valid_log().replace(
            verifier.ENGINE_FIXES_INTEROP_LINE,
            "PREFIX " + verifier.ENGINE_FIXES_INTEROP_LINE + " SUFFIX",
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("Engine Fixes FormCaching" in x for x in result.errors))

    def test_rejects_missing_checkpoint_chain_revalidation(self) -> None:
        text = _valid_log().replace(
            "lifecycle: EngineFixesFormCaching revalidation PASS "
            "event=kNewGame ordinal=2\n",
            "",
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("expected one" in x for x in result.errors))

    def test_rejects_mutated_checkpoint_chain_revalidation_key(self) -> None:
        text = _valid_log().replace(
            "revalidation PASS event=kPostLoadGame ordinal=2",
            "revalidation PASS event=kPostLoadGame ordinal=7",
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("orphan" in x for x in result.errors))

    def test_rejects_revalidation_after_checkpoint_begin(self) -> None:
        revalidation = (
            "lifecycle: EngineFixesFormCaching revalidation PASS "
            "event=kDataLoaded ordinal=1"
        )
        begin = "lifecycle: checkpoint BEGIN event=kDataLoaded ordinal=1"
        text = _valid_log().replace(
            f"{revalidation}\n{begin}", f"{begin}\n{revalidation}"
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("not immediately ordered" in x for x in result.errors))

    def test_rejects_decorated_checkpoint_chain_revalidation(self) -> None:
        text = _valid_log().replace(
            "lifecycle: EngineFixesFormCaching revalidation PASS "
            "event=kDataLoaded ordinal=1",
            "PREFIX lifecycle: EngineFixesFormCaching revalidation PASS "
            "event=kDataLoaded ordinal=1 SUFFIX",
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("expected one" in x for x in result.errors))

    def test_rejects_wrong_player_handle(self) -> None:
        text = _valid_log().replace(
            "event=kPostLoadGame ordinal=2 loadAttempt=2 playerReservation=live-player "
            "playerRawHandle=00100000",
            "event=kPostLoadGame ordinal=2 loadAttempt=2 playerReservation=live-player "
            "playerRawHandle=00400000",
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("00400000" in error for error in result.errors))

    def test_rejects_fifo_presence(self) -> None:
        text = _valid_log().replace(
            "ordinaryFIFO=ABSENT", "ordinaryFIFO=PRESENT", 1
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("FIFO" in error for error in result.errors))

    def test_rejects_missing_second_load(self) -> None:
        lines = [
            line
            for line in _valid_log().splitlines()
            if not (
                "kPostLoadGame ordinal=2" in line or
                "loadAttempt=2 result=success" in line
            )
        ]
        result = verifier.verify_log("\n".join(lines))
        self.assertFalse(result.passed)
        self.assertTrue(
            any("post-ForceReset live-to-live" in error for error in result.errors),
            result.errors,
        )

    def test_rejects_unfinished_checkpoint(self) -> None:
        result = verifier.verify_log(
            _valid_log()
            + "\nlifecycle: checkpoint BEGIN event=kNewGame ordinal=3"
        )
        self.assertFalse(result.passed)
        self.assertTrue(any("did not pass" in error for error in result.errors))

    def test_rejects_duplicate_checkpoint_begin(self) -> None:
        begin = "lifecycle: checkpoint BEGIN event=kDataLoaded ordinal=1"
        text = _valid_log().replace(begin, begin + "\n" + begin, 1)
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("duplicate lifecycle BEGIN" in x for x in result.errors))

    def test_accepts_ae_startup_pair_without_shifting_semantic_sequence(self) -> None:
        text = "\n".join(
            (
                "configuration: GenerationWrapDetection=1 VerboseLogging=1 "
                "LifecycleVerification=1 SampleSize=16",
                verifier.ENGINE_FIXES_INTEROP_LINE,
                verifier.CAP_SUCCESS_LINE,
                _load_attempt(1, 1, 1, False, False),
                _checkpoint("kDataLoaded", 1, False),
                _checkpoint("kNewGame", 1),
                _load_attempt(2, 2, 2, True),
                _player_lifecycle_transition(2, 1, "0000020000000000"),
                _load_attempt(
                    3, 3, 3, True, lifecycle=(2, 1, 2),
                    object_address="0000020000000000",
                    singleton_address="0000020000000000",
                ),
                _checkpoint(
                    "kNewGame", 2, lifecycle=(2, 1, 2),
                    object_address="0000020000000000",
                    singleton_address="0000020000000000",
                ),
            )
        )
        result = verifier.verify_log(text)
        self.assertTrue(result.passed, result.errors)

    def test_failed_load_attempt_does_not_consume_successful_pair(self) -> None:
        lines = _valid_log().splitlines()
        first_pre = next(
            index
            for index, line in enumerate(lines)
            if "revalidation PASS event=kPreLoadGame ordinal=1" in line
        )
        failed = (
            _checkpoint("kPreLoadGame", 9, True, 9).splitlines()
            + ["lifecycle: load attempt END loadAttempt=9 result=failure"]
        )
        lines[first_pre:first_pre] = failed
        result = verifier.verify_log("\n".join(lines))
        self.assertTrue(result.passed, result.errors)

    def test_rejects_failed_attempt_with_postload_pass(self) -> None:
        text = _valid_log().replace(
            "loadAttempt=1 result=success",
            "loadAttempt=1 result=failure",
        )
        result = verifier.verify_log(text)
        self.assertFalse(result.passed)
        self.assertTrue(any("reported failure" in error for error in result.errors))

    def test_accepts_extra_successful_load_between_required_transitions(self) -> None:
        lines = _valid_log().splitlines()
        second_pre = next(
            index
            for index, line in enumerate(lines)
            if "revalidation PASS event=kPreLoadGame ordinal=2" in line
        )
        lines[second_pre:second_pre] = _load_attempt(
            8, 8, 8, True, lifecycle=(2, 1, 2),
            object_address="0000020000000000",
            singleton_address="0000020000000000",
        ).splitlines()
        result = verifier.verify_log("\n".join(lines))
        self.assertTrue(result.passed, result.errors)

    def test_rejects_pass_without_begin(self) -> None:
        lines = _valid_log().splitlines()
        lines = [
            line
            for line in lines
            if "checkpoint BEGIN event=kPostLoadGame ordinal=1" not in line
        ]
        result = verifier.verify_log("\n".join(lines))
        self.assertFalse(result.passed)
        self.assertTrue(any("without BEGIN" in error for error in result.errors))


class ObservationTests(unittest.TestCase):
    def test_template_is_intentionally_not_a_pass(self) -> None:
        errors = verifier.verify_observations(verifier.observation_template())
        self.assertTrue(errors)

    def test_accepts_passes_and_documented_acc_exclusion(self) -> None:
        self.assertEqual(verifier.verify_observations(_valid_observations()), ())

    def test_rejects_non_hex_or_short_plugin_hash(self) -> None:
        document = _valid_observations()
        document["plugin_sha256"] = "not-a-sha256"
        errors = verifier.verify_observations(document)
        self.assertTrue(any("64 hexadecimal" in error for error in errors), errors)

    def test_requires_exact_ae_runtime(self) -> None:
        document = _valid_observations()
        document["runtime"] = "Skyrim SE 1.5.97"
        errors = verifier.verify_observations(document)
        self.assertTrue(any("Skyrim AE 1.6.1170" in error for error in errors), errors)

    def test_requires_precision_and_oar_versions(self) -> None:
        document = _valid_observations()
        document["mod_versions"]["Precision"] = ""
        document["mod_versions"]["OpenAnimationReplacer"] = "unknown"
        errors = verifier.verify_observations(document)
        self.assertTrue(any("Precision" in error for error in errors), errors)
        self.assertTrue(
            any("OpenAnimationReplacer" in error for error in errors), errors
        )

    def test_requires_acc_version_when_case_passes(self) -> None:
        document = _valid_observations()
        document["cases"]["alternate_conversation_camera"] = {
            "result": "pass",
            "notes": "Conversation camera visibly activated.",
        }
        errors = verifier.verify_observations(document)
        self.assertTrue(
            any("AlternateConversationCamera" in error for error in errors), errors
        )

        document["mod_versions"]["AlternateConversationCamera"] = "1.2.0"
        self.assertEqual(verifier.verify_observations(document), ())


class OrchestratorTests(unittest.TestCase):
    @staticmethod
    def _event(
        document: dict[str, object], kind: str, occurrence: int = 0
    ) -> dict[str, object]:
        events = [item for item in document["events"] if item["kind"] == kind]
        return events[occurrence]

    def test_accepts_exact_force_reset_transcript(self) -> None:
        self.assertEqual(verifier.verify_orchestrator(_valid_orchestrator()), ())

    def test_rejects_duplicate_force_reset_request(self) -> None:
        document = _valid_orchestrator()
        request = self._event(document, "devbench", 1)
        document["events"].insert(document["events"].index(request), request.copy())
        errors = verifier.verify_orchestrator(document)
        self.assertTrue(any("exactly one DevBench" in x for x in errors), errors)

    def test_rejects_case_mutated_console_event(self) -> None:
        document = _valid_orchestrator()
        self._event(document, "force-reset-console-event")["data"]["command"] = (
            "forcereset"
        )
        errors = verifier.verify_orchestrator(document)
        self.assertTrue(any("console.command" in x for x in errors), errors)

    def test_rejects_non_unit_lifecycle_delta(self) -> None:
        document = _valid_orchestrator()
        self._event(document, "force-reset-recreation")["data"]["after"][
            "releaseQuarantines"
        ] = 2
        errors = verifier.verify_orchestrator(document)
        self.assertTrue(any("releaseQuarantines" in x for x in errors), errors)

    def test_rejects_locked_assignment_delta_mismatch(self) -> None:
        document = _valid_orchestrator()
        self._event(document, "force-reset-transition")["data"]["preLoad"][
            "lifecycleAssignments"
        ] = 3
        errors = verifier.verify_orchestrator(document)
        self.assertTrue(any("preLoad lifecycleAssignments" in x for x in errors), errors)

    def test_rejects_locked_fifo_presence(self) -> None:
        document = _valid_orchestrator()
        self._event(document, "force-reset-transition")["data"]["postLoad"][
            "ordinaryFIFO"
        ] = "PRESENT"
        errors = verifier.verify_orchestrator(document)
        self.assertTrue(any("ordinaryFIFO=ABSENT" in x for x in errors), errors)

    def test_rejects_locked_identity_mismatch(self) -> None:
        document = _valid_orchestrator()
        self._event(document, "force-reset-transition")["data"]["preLoad"][
            "singleton"
        ] = (
            "0000030000000000"
        )
        errors = verifier.verify_orchestrator(document)
        self.assertTrue(any("recreated PlayerCharacter" in x for x in errors), errors)

    def test_rejects_second_save_attempt_mismatch(self) -> None:
        document = _valid_orchestrator()
        self._event(document, "load-complete")["data"]["attempt"] = 9
        errors = verifier.verify_orchestrator(document)
        self.assertTrue(any("completed secondSave" in x for x in errors), errors)

    def test_rejects_transition_before_second_load_completion(self) -> None:
        document = _valid_orchestrator()
        transition = self._event(document, "force-reset-transition")
        document["events"].remove(transition)
        load = self._event(document, "load-complete")
        document["events"].insert(document["events"].index(load), transition)
        errors = verifier.verify_orchestrator(document)
        self.assertTrue(any("out of order" in x for x in errors), errors)

    def test_rejects_force_reset_before_first_main_menu_gate(self) -> None:
        document = _valid_orchestrator()
        stable = self._event(document, "stable-main-menu-before-force-reset")
        document["events"].remove(stable)
        force = self._event(document, "force-reset-issued-once")
        document["events"].insert(document["events"].index(force) + 1, stable)
        errors = verifier.verify_orchestrator(document)
        self.assertTrue(any("out of order" in x for x in errors), errors)

    def test_rejects_duplicate_quit_phase(self) -> None:
        document = _valid_orchestrator()
        second = self._event(document, "quit-issued-once", 1)
        second["data"]["phase"] = "before-force-reset"
        errors = verifier.verify_orchestrator(document)
        self.assertTrue(any("after-load-b" in x for x in errors), errors)

    def test_rejects_detached_main_menu_oracle(self) -> None:
        document = _valid_orchestrator()
        document["events"].append(
            {"kind": "detached-main-menu", "data": {"samples": 3}}
        )
        errors = verifier.verify_orchestrator(document)
        self.assertTrue(any("obsolete" in x for x in errors), errors)


if __name__ == "__main__":
    unittest.main()
