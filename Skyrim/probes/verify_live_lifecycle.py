#!/usr/bin/env python3
"""Verify one prerelease Skyrim lifecycle/compatibility run from its log.

The DLL emits lifecycle checkpoint lines only after a manager-locked scan has
validated the reserved entry and walked the complete ordinary free-list chain.
Compatibility behavior still needs a human observation, supplied as JSON; this
tool deliberately does not turn "the DLL loaded" into evidence that a gameplay
condition or camera branch worked.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CHECKPOINT_RE = re.compile(
    r"lifecycle: checkpoint PASS event=(?P<event>k[A-Za-z]+) "
    r"ordinal=(?P<ordinal>\d+) "
    r"(?:loadAttempt=(?P<attempt>\d+) )?"
    r"playerReservation=(?P<reservation>\S+) "
    r"playerRawHandle=(?P<handle>\S+) "
    r"reservedSlot=(?P<slot>[0-9A-Fa-f]+) "
    r"ordinaryFIFO=(?P<fifo>\S+)"
)
BEGIN_RE = re.compile(
    r"lifecycle: checkpoint BEGIN event=(?P<event>k[A-Za-z]+) "
    r"ordinal=(?P<ordinal>\d+)"
    r"(?: loadAttempt=(?P<attempt>\d+))?"
)
LOAD_RESULT_RE = re.compile(
    r"lifecycle: load attempt END loadAttempt=(?P<attempt>\d+) "
    r"result=(?P<result>success|failure|invalid-data)"
)
PLAYER_LIFECYCLE_TRANSITION_RE = re.compile(
    r"player lifecycle transition: "
    r"constructorAssignments=(?P<constructors>\d+) "
    r"releaseQuarantines=(?P<releases>\d+) "
    r"reservedSlot=100000 raw=00100000 "
    r"object=(?P<object>[0-9A-Fa-f]+)"
)
LIFECYCLE_SNAPSHOT_RE = re.compile(
    r"lifecycle: snapshot event=(?P<event>k[A-Za-z]+) "
    r"ordinal=(?P<ordinal>\d+) "
    r"constructorAssignments=(?P<constructors>\d+) "
    r"releaseQuarantines=(?P<releases>\d+) "
    r"lifecycleAssignments=(?P<assignments>\d+) "
    r"reservation=(?P<reservation>\S+) raw=(?P<handle>\S+) "
    r"object=(?P<object>\S+) singleton=(?P<singleton>\S+)"
)
ENGINE_FIXES_INTEROP_LINE = (
    "compatibility: EngineFixesFormCaching PASS "
    "runtime=1.6.1170.0 version=7.0.20.0 "
    "sha256=5D1384ACFB523ABD1333F5AF71AF0B7D131B6EBB1A0EE6B3EDFF86FB4C93ADF3 "
    "destinationRva=000711F0 safetyHookChain=PASS originalCall=PASS"
)
CAP_SUCCESS_LINE = (
    "SUCCESS: reference handle slots raised 1048576 -> 2097152 "
    "(index 21 bits, age 5 bits / 32 generations, in-use bit 26 and the "
    "complete _refCount index cache remain stock-shaped)."
)
ENGINE_FIXES_REVALIDATION_RE = re.compile(
    r"lifecycle: EngineFixesFormCaching revalidation PASS "
    r"event=(?P<event>k[A-Za-z]+) ordinal=(?P<ordinal>\d+)"
)
REQUIRED_RUNTIME = "Skyrim AE 1.6.1170"

REQUIRED_COMPATIBILITY_CASES = (
    "precision_first_person_attack",
    "precision_third_person_attack",
    "precision_enemy_melee_hits_player",
    "oar_is_greeting_player",
)
OPTIONAL_COMPATIBILITY_CASES = ("alternate_conversation_camera",)

FORBIDDEN_LOG_TEXT = (
    "CRITICAL:",
    "diagnostics: FAILED:",
    "ABORT:",
    "FATAL:",
)


@dataclass(frozen=True)
class Checkpoint:
    event: str
    ordinal: int
    reservation: str
    handle: str
    slot: str
    fifo: str
    line_number: int
    load_attempt: int | None


@dataclass(frozen=True)
class LoadResult:
    attempt: int
    result: str
    line_number: int


@dataclass(frozen=True)
class PlayerLifecycleTransition:
    constructors: int
    releases: int
    object_address: str
    line_number: int


@dataclass(frozen=True)
class LifecycleSnapshot:
    event: str
    ordinal: int
    constructors: int
    releases: int
    assignments: int
    reservation: str
    handle: str
    object_address: str
    singleton_address: str
    line_number: int


@dataclass(frozen=True)
class VerificationResult:
    errors: tuple[str, ...]
    checkpoints: tuple[Checkpoint, ...]

    @property
    def passed(self) -> bool:
        return not self.errors


def verify_log(text: str) -> VerificationResult:
    errors: list[str] = []
    checkpoints: list[Checkpoint] = []
    load_results: list[LoadResult] = []
    player_lifecycle_transitions: list[PlayerLifecycleTransition] = []
    lifecycle_snapshots: list[LifecycleSnapshot] = []
    begins: set[tuple[str, int, int]] = set()
    begin_lines: dict[tuple[str, int, int], list[int]] = {}
    passes: set[tuple[str, int, int]] = set()
    interop_revalidations: list[tuple[str, int, int]] = []
    lines = text.splitlines()

    if sum(line == CAP_SUCCESS_LINE for line in lines) != 1:
        errors.append(
            "exact 2M/21+5 cap-raise transaction SUCCESS line is missing or duplicated"
        )
    if sum(line == ENGINE_FIXES_INTEROP_LINE for line in lines) != 1:
        errors.append(
            "exact authenticated Engine Fixes FormCaching PASS line is missing or duplicated"
        )
    if not re.search(
        r"configuration: .*VerboseLogging=1 .*LifecycleVerification=1",
        text,
    ):
        errors.append(
            "run was not logged with VerboseLogging=1 and LifecycleVerification=1"
        )

    for forbidden in FORBIDDEN_LOG_TEXT:
        if forbidden in text:
            errors.append(f"failure marker present: {forbidden}")

    for line_number, line in enumerate(lines, 1):
        match = LIFECYCLE_SNAPSHOT_RE.fullmatch(line)
        if match:
            lifecycle_snapshots.append(
                LifecycleSnapshot(
                    event=match.group("event"),
                    ordinal=int(match.group("ordinal")),
                    constructors=int(match.group("constructors")),
                    releases=int(match.group("releases")),
                    assignments=int(match.group("assignments")),
                    reservation=match.group("reservation"),
                    handle=match.group("handle").upper(),
                    object_address=match.group("object").upper(),
                    singleton_address=match.group("singleton").upper(),
                    line_number=line_number,
                )
            )
            continue

        match = PLAYER_LIFECYCLE_TRANSITION_RE.fullmatch(line)
        if match:
            player_lifecycle_transitions.append(
                PlayerLifecycleTransition(
                    constructors=int(match.group("constructors")),
                    releases=int(match.group("releases")),
                    object_address=match.group("object").upper(),
                    line_number=line_number,
                )
            )
            continue

        match = ENGINE_FIXES_REVALIDATION_RE.fullmatch(line)
        if match:
            interop_revalidations.append(
                (match.group("event"), int(match.group("ordinal")), line_number)
            )
            continue

        match = BEGIN_RE.fullmatch(line)
        if match:
            key = (
                match.group("event"),
                int(match.group("ordinal")),
                int(match.group("attempt") or 0),
            )
            if key in begins:
                errors.append(
                    f"duplicate lifecycle BEGIN for {key[0]} ordinal {key[1]} "
                    f"load attempt {key[2]}"
                )
            begins.add(key)
            begin_lines.setdefault(key, []).append(line_number)
            continue

        match = CHECKPOINT_RE.fullmatch(line)
        if match:
            checkpoint = Checkpoint(
                event=match.group("event"),
                ordinal=int(match.group("ordinal")),
                reservation=match.group("reservation"),
                handle=match.group("handle").upper(),
                slot=match.group("slot").upper(),
                fifo=match.group("fifo").upper(),
                line_number=line_number,
                load_attempt=(
                    int(match.group("attempt"))
                    if match.group("attempt") is not None
                    else None
                ),
            )
            key = (
                checkpoint.event,
                checkpoint.ordinal,
                checkpoint.load_attempt or 0,
            )
            if key in passes:
                errors.append(
                    f"duplicate lifecycle PASS for {checkpoint.event} "
                    f"ordinal {checkpoint.ordinal} load attempt "
                    f"{checkpoint.load_attempt or 0}"
                )
            passes.add(key)
            checkpoints.append(checkpoint)
            continue

        match = LOAD_RESULT_RE.fullmatch(line)
        if match:
            load_results.append(
                LoadResult(
                    attempt=int(match.group("attempt")),
                    result=match.group("result"),
                    line_number=line_number,
                )
            )

    checkpoint_keys = {(item.event, item.ordinal) for item in checkpoints}
    for checkpoint in checkpoints:
        matching = [
            line_number
            for event, ordinal, line_number in interop_revalidations
            if event == checkpoint.event and ordinal == checkpoint.ordinal
        ]
        begin_key = (
            checkpoint.event,
            checkpoint.ordinal,
            checkpoint.load_attempt or 0,
        )
        matching_begins = begin_lines.get(begin_key, [])
        if len(matching) != 1:
            errors.append(
                f"{checkpoint.event} ordinal {checkpoint.ordinal} has "
                f"{len(matching)} Engine Fixes chain revalidation lines; expected one"
            )
        elif len(matching_begins) != 1:
            errors.append(
                f"{checkpoint.event} ordinal {checkpoint.ordinal} has "
                f"{len(matching_begins)} checkpoint BEGIN lines; expected one"
            )
        elif not (matching[0] + 1 == matching_begins[0] < checkpoint.line_number):
            errors.append(
                f"Engine Fixes chain revalidation for {checkpoint.event} "
                f"ordinal {checkpoint.ordinal} is not immediately ordered before its checkpoint"
            )
    for event, ordinal, _line_number in interop_revalidations:
        if (event, ordinal) not in checkpoint_keys:
            errors.append(
                f"orphan Engine Fixes chain revalidation for {event} ordinal {ordinal}"
            )

    snapshot_keys = {(item.event, item.ordinal) for item in lifecycle_snapshots}
    for checkpoint in checkpoints:
        matching_snapshots = [
            item
            for item in lifecycle_snapshots
            if item.event == checkpoint.event and item.ordinal == checkpoint.ordinal
        ]
        if len(matching_snapshots) != 1:
            errors.append(
                f"{checkpoint.event} ordinal {checkpoint.ordinal} has "
                f"{len(matching_snapshots)} lifecycle snapshots; expected one"
            )
            continue
        snapshot = matching_snapshots[0]
        if snapshot.line_number != checkpoint.line_number + 1:
            errors.append(
                f"lifecycle snapshot for {checkpoint.event} ordinal "
                f"{checkpoint.ordinal} is not immediately after its PASS"
            )
        if (
            snapshot.reservation != checkpoint.reservation
            or snapshot.handle != checkpoint.handle
        ):
            errors.append(
                f"lifecycle snapshot for {checkpoint.event} ordinal "
                f"{checkpoint.ordinal} disagrees with its PASS reservation/handle"
            )
        if snapshot.reservation == "live-player":
            addresses = (snapshot.object_address, snapshot.singleton_address)
            if not all(re.fullmatch(r"[0-9A-F]+", value) for value in addresses):
                errors.append(
                    f"live lifecycle snapshot for {checkpoint.event} ordinal "
                    f"{checkpoint.ordinal} has a malformed player address"
                )
            elif (
                int(snapshot.object_address, 16) == 0
                or int(snapshot.singleton_address, 16) == 0
                or snapshot.object_address != snapshot.singleton_address
            ):
                errors.append(
                    f"live lifecycle snapshot for {checkpoint.event} ordinal "
                    f"{checkpoint.ordinal} does not identify one non-null PlayerCharacter"
                )
        elif snapshot.reservation == "detached":
            try:
                detached_addresses_zero = (
                    int(snapshot.object_address, 16) == 0
                    and int(snapshot.singleton_address, 16) == 0
                )
            except ValueError:
                detached_addresses_zero = False
            if not detached_addresses_zero:
                errors.append(
                    f"detached lifecycle snapshot for {checkpoint.event} ordinal "
                    f"{checkpoint.ordinal} contains a player identity"
                )
    for event, ordinal in sorted(snapshot_keys - checkpoint_keys):
        errors.append(f"orphan lifecycle snapshot for {event} ordinal {ordinal}")

    unfinished = sorted(begins - passes)
    for event, ordinal, attempt in unfinished:
        errors.append(
            f"checkpoint began but did not pass: {event} ordinal {ordinal} "
            f"load attempt {attempt}"
        )
    for event, ordinal, attempt in sorted(passes - begins):
        errors.append(
            f"checkpoint passed without BEGIN: {event} ordinal {ordinal} "
            f"load attempt {attempt}"
        )

    for checkpoint in checkpoints:
        if checkpoint.slot != "100000":
            errors.append(
                f"line {checkpoint.line_number}: reserved slot was {checkpoint.slot}"
            )
        if checkpoint.fifo != "ABSENT":
            errors.append(
                f"line {checkpoint.line_number}: ordinary FIFO result was {checkpoint.fifo}"
            )
        if checkpoint.reservation == "live-player" and checkpoint.handle != "00100000":
            errors.append(
                f"line {checkpoint.line_number}: live player handle was {checkpoint.handle}"
            )
        elif checkpoint.reservation == "detached" and checkpoint.handle != "N/A":
            errors.append(
                f"line {checkpoint.line_number}: detached reservation reported "
                f"raw handle {checkpoint.handle}"
            )
        elif checkpoint.reservation not in {"live-player", "detached"}:
            errors.append(
                f"line {checkpoint.line_number}: unknown player reservation "
                f"{checkpoint.reservation}"
            )

    data_loaded = [item for item in checkpoints if item.event == "kDataLoaded"]
    if not data_loaded:
        errors.append("missing kDataLoaded lifecycle checkpoint")
        return VerificationResult(tuple(errors), tuple(checkpoints))
    # The runtime deliberately calls this checkpoint with requireLive=false.
    # The common validation above still requires one exact legal representation:
    # detached/N/A or live-player/00100000, with the reserved slot outside FIFO.
    data_anchor = data_loaded[0]

    new_games = [
        item
        for item in checkpoints
        if item.event == "kNewGame" and item.line_number > data_anchor.line_number
    ]
    if not new_games:
        errors.append("missing first kNewGame checkpoint after kDataLoaded")
        return VerificationResult(tuple(errors), tuple(checkpoints))
    for checkpoint in new_games:
        if checkpoint.reservation != "live-player" or checkpoint.handle != "00100000":
            errors.append(
                f"kNewGame ordinal {checkpoint.ordinal} did not contain the live "
                "vanilla player handle"
            )
    first_new_game = new_games[0]

    pre_by_attempt: dict[int, Checkpoint] = {}
    post_by_attempt: dict[int, Checkpoint] = {}
    result_by_attempt: dict[int, LoadResult] = {}
    for checkpoint in checkpoints:
        if checkpoint.event not in {"kPreLoadGame", "kPostLoadGame"}:
            continue
        if not checkpoint.load_attempt:
            if checkpoint.line_number > first_new_game.line_number:
                errors.append(
                    f"line {checkpoint.line_number}: {checkpoint.event} after the "
                    "lifecycle anchor has no loadAttempt"
                )
            continue
        destination = (
            pre_by_attempt
            if checkpoint.event == "kPreLoadGame"
            else post_by_attempt
        )
        if checkpoint.load_attempt in destination:
            errors.append(
                f"duplicate {checkpoint.event} checkpoint for load attempt "
                f"{checkpoint.load_attempt}"
            )
        destination[checkpoint.load_attempt] = checkpoint

    for result in load_results:
        if result.attempt == 0:
            continue
        if result.attempt in result_by_attempt:
            errors.append(f"duplicate result for load attempt {result.attempt}")
        result_by_attempt[result.attempt] = result

    successful_pairs: list[tuple[Checkpoint, Checkpoint]] = []
    all_attempts = sorted(
        set(pre_by_attempt) | set(post_by_attempt) | set(result_by_attempt)
    )
    for attempt in all_attempts:
        pre = pre_by_attempt.get(attempt)
        post = post_by_attempt.get(attempt)
        result = result_by_attempt.get(attempt)
        after_anchor = any(
            item is not None and item.line_number > first_new_game.line_number
            for item in (pre, post, result)
        )
        if result is None:
            if after_anchor:
                errors.append(f"load attempt {attempt} has no PostLoad result")
            continue
        if result.result != "success":
            if post is not None:
                errors.append(
                    f"load attempt {attempt} reported {result.result} but has a "
                    "kPostLoadGame PASS"
                )
            continue
        if pre is None or post is None:
            if after_anchor:
                errors.append(
                    f"successful load attempt {attempt} is missing its paired "
                    "PreLoad or PostLoad checkpoint"
                )
            continue
        if not (pre.line_number < result.line_number < post.line_number):
            errors.append(f"load attempt {attempt} messages are out of order")
            continue
        if post.line_number > first_new_game.line_number:
            if post.reservation != "live-player" or post.handle != "00100000":
                errors.append(
                    f"successful load attempt {attempt} did not publish the live "
                    "vanilla player handle"
                )
            successful_pairs.append((pre, post))

    successful_pairs.sort(key=lambda pair: pair[0].line_number)
    first_pair = next(
        (
            pair
            for pair in successful_pairs
            if pair[0].reservation == "live-player"
            and pair[0].handle == "00100000"
            and pair[1].reservation == "live-player"
            and pair[1].handle == "00100000"
        ),
        None,
    )
    if first_pair is None:
        errors.append(
            "the live-to-live successful load transition was not observed after "
            "the first new game"
        )
        return VerificationResult(tuple(errors), tuple(checkpoints))

    first_pre, first_post = first_pair
    baseline_snapshot = next(
        (
            item
            for item in lifecycle_snapshots
            if item.event == "kPostLoadGame"
            and item.ordinal == first_post.ordinal
            and item.line_number > first_post.line_number
            and item.reservation == "live-player"
            and item.handle == "00100000"
            and re.fullmatch(r"[0-9A-F]+", item.object_address)
            and re.fullmatch(r"[0-9A-F]+", item.singleton_address)
        ),
        None,
    )
    if baseline_snapshot is None:
        errors.append(
            "the first live-to-live load has no following exact live lifecycle "
            "snapshot for the ForceReset baseline"
        )
        return VerificationResult(tuple(errors), tuple(checkpoints))

    reset_transition = next(
        (
            item
            for item in player_lifecycle_transitions
            if item.line_number > baseline_snapshot.line_number
        ),
        None,
    )
    if reset_transition is None:
        errors.append(
            "the immediate post-load ForceReset recreation was not observed: "
            "expected the exact player lifecycle transition with "
            "constructorAssignments +1, releaseQuarantines +1, a changed "
            "PlayerCharacter base, and raw handle 00100000"
        )
        return VerificationResult(tuple(errors), tuple(checkpoints))

    if (
        reset_transition.constructors != baseline_snapshot.constructors + 1
        or reset_transition.releases != baseline_snapshot.releases + 1
    ):
        errors.append(
            "the immediate ForceReset player lifecycle transition did not "
            "advance constructorAssignments and releaseQuarantines by exactly one"
        )
    if (
        int(reset_transition.object_address, 16) == 0
        or int(reset_transition.object_address, 16)
        == int(baseline_snapshot.object_address, 16)
    ):
        errors.append(
            "the immediate ForceReset player lifecycle transition did not "
            "publish a changed non-null PlayerCharacter base"
        )

    second_pair = next(
        (
            pair
            for pair in successful_pairs
            if pair[0].line_number > reset_transition.line_number
            and pair[0].reservation == "live-player"
            and pair[0].handle == "00100000"
            and pair[1].reservation == "live-player"
            and pair[1].handle == "00100000"
        ),
        None,
    )
    if second_pair is None:
        errors.append(
            "the post-ForceReset live-to-live successful load transition was not "
            "observed"
        )
        return VerificationResult(tuple(errors), tuple(checkpoints))
    second_pre, second_post = second_pair

    extra_recreations = [
        item
        for item in player_lifecycle_transitions
        if reset_transition.line_number < item.line_number < second_pre.line_number
    ]
    if extra_recreations:
        errors.append(
            "an extra player lifecycle recreation occurred before the first "
            "post-ForceReset load"
        )

    second_pre_snapshot = next(
        (
            item
            for item in lifecycle_snapshots
            if item.event == "kPreLoadGame"
            and item.ordinal == second_pre.ordinal
            and item.line_number > second_pre.line_number
        ),
        None,
    )
    second_post_snapshot = next(
        (
            item
            for item in lifecycle_snapshots
            if item.event == "kPostLoadGame"
            and item.ordinal == second_post.ordinal
            and item.line_number > second_post.line_number
        ),
        None,
    )
    if second_pre_snapshot is None or second_post_snapshot is None:
        errors.append(
            "the first post-ForceReset load lacks its manager-locked "
            "kPreLoadGame/kPostLoadGame lifecycle snapshots"
        )
    else:
        expected_lifecycle = (
            baseline_snapshot.constructors + 1,
            baseline_snapshot.releases + 1,
            baseline_snapshot.assignments + 1,
        )
        for label, snapshot in (
            ("kPreLoadGame", second_pre_snapshot),
            ("kPostLoadGame", second_post_snapshot),
        ):
            observed_lifecycle = (
                snapshot.constructors,
                snapshot.releases,
                snapshot.assignments,
            )
            if observed_lifecycle != expected_lifecycle:
                errors.append(
                    f"the post-ForceReset {label} snapshot did not contain "
                    "exact C+1/R+1/A+1 lifecycle counters"
                )
            if (
                snapshot.object_address != reset_transition.object_address
                or snapshot.singleton_address != reset_transition.object_address
            ):
                errors.append(
                    f"the post-ForceReset {label} snapshot did not retain the "
                    "immediate recreated PlayerCharacter identity"
                )

    later_new_games = [
        item for item in new_games if item.line_number > second_post.line_number
    ]
    if not later_new_games:
        errors.append("missing second kNewGame checkpoint after the post-ForceReset load")

    return VerificationResult(tuple(errors), tuple(checkpoints))


def verify_orchestrator(document: Any) -> tuple[str, ...]:
    """Verify the two menu returns around one observed ForceReset.

    The core log proves the resulting release/recreate transition.  This
    transcript supplies the independent DevBench event-bus proof that the
    transition was deliberately caused by exactly one case-sensitive
    ``ForceReset`` console command without input or focus APIs.
    """

    errors: list[str] = []
    if not isinstance(document, dict):
        return ("orchestrator transcript must be a JSON object",)
    if document.get("result") != "PASS":
        errors.append("orchestrator transcript result must be PASS")
    if document.get("noFocusOrInputApisUsed") is not True:
        errors.append("orchestrator did not attest no-focus/no-input execution")
    events = document.get("events")
    if not isinstance(events, list):
        return tuple(errors + ["orchestrator transcript must contain an events array"])

    def matching(kind: str) -> list[tuple[int, dict[str, Any]]]:
        found: list[tuple[int, dict[str, Any]]] = []
        for index, event in enumerate(events):
            if not isinstance(event, dict) or event.get("kind") != kind:
                continue
            data = event.get("data")
            if isinstance(data, dict):
                found.append((index, data))
        return found

    issued = matching("force-reset-issued-once")
    observed = matching("force-reset-console-event")
    recreations = matching("force-reset-recreation")
    transitions = matching("force-reset-transition")
    stable_before_reset_menus = matching("stable-main-menu-before-force-reset")
    stable_force_reset_menus = matching("stable-main-menu-after-force-reset")
    stable_after_load_menus = matching("stable-main-menu-after-load-b")
    quit_contracts = matching("quit-to-main-menu-request-contract")
    if len(issued) != 1 or issued[0][1].get("command") != "ForceReset":
        errors.append("expected exactly one force-reset-issued-once event for ForceReset")
    if (
        len(observed) != 1
        or observed[0][1].get("topic") != "console.command"
        or observed[0][1].get("command") != "ForceReset"
    ):
        errors.append(
            "expected exactly one exact console.command event for ForceReset"
        )

    console_requests: list[tuple[int, dict[str, Any]]] = []
    for index, data in matching("devbench"):
        arguments = data.get("arguments")
        if data.get("tool") == "console" and isinstance(arguments, dict):
            console_requests.append((index, arguments))
    if (
        len(console_requests) != 1
        or console_requests[0][1].get("action") != "exec"
        or console_requests[0][1].get("command") != "ForceReset"
        or console_requests[0][1].get("capture") is not False
    ):
        errors.append(
            "expected exactly one DevBench console exec request for ForceReset "
            "with capture=false"
        )

    expected_quit_phases = ("before-force-reset", "after-load-b")
    quit_requests: list[tuple[int, dict[str, Any]]] = []
    for index, data in matching("devbench"):
        arguments = data.get("arguments")
        if (
            data.get("tool") == "papyrus"
            and isinstance(arguments, dict)
            and arguments.get("action") == "call"
            and arguments.get("script") == "Game"
            and arguments.get("function") == "QuitToMainMenu"
        ):
            quit_requests.append((index, arguments))
    quit_issued = matching("quit-issued-once")
    if len(quit_requests) != 2:
        errors.append("expected exactly two DevBench Game.QuitToMainMenu requests")
    else:
        for ordinal, (_, arguments) in enumerate(quit_requests, 1):
            if arguments.get("args") != [] or arguments.get("timeoutMs") != 5000:
                errors.append(
                    f"QuitToMainMenu request {ordinal}/2 did not use exact "
                    "empty args and timeoutMs=5000"
                )
    if len(quit_issued) != 2:
        errors.append("expected exactly two quit-issued-once events")
    else:
        for ordinal, phase in enumerate(expected_quit_phases, 1):
            data = quit_issued[ordinal - 1][1]
            if (
                data.get("requestOrdinal") != ordinal
                or data.get("requestTotal") != 2
                or data.get("phase") != phase
                or data.get("script") != "Game"
                or data.get("function") != "QuitToMainMenu"
            ):
                errors.append(
                    f"quit-issued-once event {ordinal}/2 does not match phase {phase}"
                )
    if len(quit_contracts) != 1:
        errors.append("expected exactly one QuitToMainMenu request contract event")
    else:
        contract = quit_contracts[0][1]
        if (
            contract.get("request") != "Game.QuitToMainMenu"
            or contract.get("expectedCount") != 2
            or contract.get("observedCount") != 2
            or contract.get("phases") != list(expected_quit_phases)
            or contract.get("eachPhaseExactlyOnce") is not True
            or contract.get("retries") != 0
        ):
            errors.append("QuitToMainMenu request contract is not exact")

    recreation_before: dict[str, Any] | None = None
    recreation_after: dict[str, Any] | None = None
    if len(recreations) != 1:
        errors.append("expected exactly one force-reset-recreation event")
    else:
        recreation = recreations[0][1]
        before = recreation.get("before")
        after = recreation.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict):
            errors.append("force-reset-recreation must contain before/after objects")
        else:
            recreation_before = before
            recreation_after = after
            for field in ("constructorAssignments", "releaseQuarantines"):
                try:
                    exact = int(after[field]) == int(before[field]) + 1
                except (KeyError, TypeError, ValueError):
                    exact = False
                if not exact:
                    errors.append(
                        f"force-reset-recreation {field} did not increment by one"
                    )
            if after.get("rawHandle") != "00100000":
                errors.append(
                    "force-reset-recreation did not retain raw handle 00100000"
                )
            if not before.get("object") or before.get("object") == after.get("object"):
                errors.append(
                    "ForceReset immediate recreation did not change the player object identity"
                )

    transition_before: dict[str, Any] | None = None
    transition_immediate: dict[str, Any] | None = None
    transition_pre: dict[str, Any] | None = None
    transition_post: dict[str, Any] | None = None
    if len(transitions) != 1:
        errors.append("expected exactly one force-reset-transition event")
    else:
        transition = transitions[0][1]
        before = transition.get("before")
        immediate = transition.get("immediate")
        pre_load = transition.get("preLoad")
        post_load = transition.get("postLoad")
        if not all(
            isinstance(item, dict)
            for item in (before, immediate, pre_load, post_load)
        ):
            errors.append(
                "force-reset-transition must contain before/immediate/preLoad/postLoad objects"
            )
        else:
            transition_before = before
            transition_immediate = immediate
            transition_pre = pre_load
            transition_post = post_load
            if recreation_before is not None:
                for field in (
                    "constructorAssignments",
                    "releaseQuarantines",
                    "object",
                ):
                    if before.get(field) != recreation_before.get(field):
                        errors.append(
                            f"force-reset-transition baseline {field} disagrees "
                            "with the immediate recreation event"
                        )
            if recreation_after is not None:
                for field in (
                    "constructorAssignments",
                    "releaseQuarantines",
                    "object",
                    "rawHandle",
                ):
                    if immediate.get(field) != recreation_after.get(field):
                        errors.append(
                            f"force-reset-transition immediate {field} disagrees "
                            "with the recreation event"
                        )
            for phase_name, phase, expected_event in (
                ("preLoad", pre_load, "kPreLoadGame"),
                ("postLoad", post_load, "kPostLoadGame"),
            ):
                for field in (
                    "constructorAssignments",
                    "releaseQuarantines",
                    "lifecycleAssignments",
                ):
                    try:
                        exact = int(phase[field]) == int(before[field]) + 1
                    except (KeyError, TypeError, ValueError):
                        exact = False
                    if not exact:
                        errors.append(
                            f"force-reset-transition {phase_name} {field} "
                            "did not increment by one"
                        )
                if phase.get("event") != expected_event:
                    errors.append(
                        f"force-reset-transition {phase_name} has the wrong event"
                    )
                if phase.get("rawHandle") != "00100000":
                    errors.append(
                        f"force-reset-transition {phase_name} did not retain "
                        "raw handle 00100000"
                    )
                if phase.get("ordinaryFIFO") != "ABSENT":
                    errors.append(
                        f"force-reset-transition {phase_name} did not prove "
                        "ordinaryFIFO=ABSENT"
                    )
                if (
                    not immediate.get("object")
                    or phase.get("object") != immediate.get("object")
                    or phase.get("singleton") != immediate.get("object")
                ):
                    errors.append(
                        f"force-reset-transition {phase_name} did not retain "
                        "the immediate recreated PlayerCharacter identity"
                    )
            if pre_load.get("loadAttempt") != post_load.get("loadAttempt"):
                errors.append(
                    "force-reset-transition preLoad/postLoad attempts disagree"
                )

    second_save = document.get("secondSave")
    second_loads = [
        item
        for item in matching("load-complete")
        if item[1].get("name") == second_save
    ]
    if not isinstance(second_save, str) or not second_save:
        errors.append("orchestrator transcript is missing secondSave")
    elif len(second_loads) != 1:
        errors.append("expected exactly one completed secondSave load")
    elif transition_pre is not None and transition_post is not None:
        attempt = second_loads[0][1].get("attempt")
        if (
            transition_pre.get("loadAttempt") != attempt
            or transition_post.get("loadAttempt") != attempt
        ):
            errors.append(
                "force-reset-transition snapshots do not belong to the completed secondSave load"
            )

    if (
        len(stable_before_reset_menus) != 1
        or stable_before_reset_menus[0][1].get("requestOrdinal") != 1
        or stable_before_reset_menus[0][1].get("requestTotal") != 2
        or stable_before_reset_menus[0][1].get("phase") != "before-force-reset"
        or stable_before_reset_menus[0][1].get("detachedPlayerRequired") is not False
    ):
        errors.append(
            "expected one stable Main Menu event before ForceReset with no "
            "detached-player requirement"
        )
    if (
        len(stable_force_reset_menus) != 1
        or stable_force_reset_menus[0][1].get("detachedPlayerRequired") is not False
        or stable_force_reset_menus[0][1].get("liveReservedPlayerRequired") is not True
    ):
        errors.append(
            "expected one stable post-ForceReset Main Menu event with a live "
            "reserved player and no detached-player requirement"
        )
    if (
        len(stable_after_load_menus) != 1
        or stable_after_load_menus[0][1].get("requestOrdinal") != 2
        or stable_after_load_menus[0][1].get("requestTotal") != 2
        or stable_after_load_menus[0][1].get("phase") != "after-load-b"
        or stable_after_load_menus[0][1].get("detachedPlayerRequired") is not False
    ):
        errors.append(
            "expected one stable Main Menu event after load B with no "
            "detached-player requirement"
        )

    ordered = [
        quit_requests[0][0] if len(quit_requests) == 2 else None,
        quit_issued[0][0] if len(quit_issued) == 2 else None,
        stable_before_reset_menus[0][0]
        if len(stable_before_reset_menus) == 1
        else None,
        console_requests[0][0] if len(console_requests) == 1 else None,
        issued[0][0] if len(issued) == 1 else None,
        observed[0][0] if len(observed) == 1 else None,
        recreations[0][0] if len(recreations) == 1 else None,
        stable_force_reset_menus[0][0] if len(stable_force_reset_menus) == 1 else None,
        second_loads[0][0] if len(second_loads) == 1 else None,
        transitions[0][0] if len(transitions) == 1 else None,
        quit_requests[1][0] if len(quit_requests) == 2 else None,
        quit_issued[1][0] if len(quit_issued) == 2 else None,
        stable_after_load_menus[0][0]
        if len(stable_after_load_menus) == 1
        else None,
        quit_contracts[0][0] if len(quit_contracts) == 1 else None,
    ]
    if all(index is not None for index in ordered) and ordered != sorted(ordered):
        errors.append(
            "ordinary Main Menu/ForceReset/locked-load/second Main Menu proof "
            "is out of order"
        )
    if matching("detached-main-menu"):
        errors.append("obsolete detached-main-menu evidence is present")
    return tuple(errors)


def _read_observation_case(
    cases: dict[str, Any],
    name: str,
    allow_not_applicable: bool,
    errors: list[str],
) -> None:
    value = cases.get(name)
    if not isinstance(value, dict):
        errors.append(f"compatibility observation is missing: {name}")
        return
    result = str(value.get("result", "")).strip().lower()
    notes = str(value.get("notes", "")).strip()
    allowed = {"pass"}
    if allow_not_applicable:
        allowed.add("not-applicable")
    if result not in allowed:
        errors.append(
            f"{name} result must be " + " or ".join(sorted(allowed)) + f"; got {result or 'missing'}"
        )
    if not notes:
        errors.append(f"{name} must include concise observation notes")


def verify_observations(document: Any) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ("observation document must be a JSON object",)
    runtime = str(document.get("runtime", "")).strip()
    if runtime != REQUIRED_RUNTIME:
        errors.append(
            "observation document runtime must be exactly "
            f"{REQUIRED_RUNTIME}; got {runtime or 'missing'}"
        )
    plugin_sha256 = str(document.get("plugin_sha256", "")).strip()
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", plugin_sha256):
        errors.append(
            "observation document must record the tested DLL SHA-256 as "
            "exactly 64 hexadecimal characters"
        )

    mod_versions = document.get("mod_versions")
    if not isinstance(mod_versions, dict):
        errors.append("observation document must contain a mod_versions object")
        mod_versions = {}
    placeholders = {"", "n/a", "na", "not-applicable", "unknown", "latest"}
    for mod_name in ("Precision", "OpenAnimationReplacer"):
        version = str(mod_versions.get(mod_name, "")).strip()
        if version.lower() in placeholders:
            errors.append(f"mod_versions must record the exact {mod_name} version")

    cases = document.get("cases")
    if not isinstance(cases, dict):
        return tuple(errors + ["observation document must contain a cases object"])
    for name in REQUIRED_COMPATIBILITY_CASES:
        _read_observation_case(cases, name, False, errors)
    for name in OPTIONAL_COMPATIBILITY_CASES:
        _read_observation_case(cases, name, True, errors)

    acc_case = cases.get("alternate_conversation_camera")
    acc_result = ""
    if isinstance(acc_case, dict):
        acc_result = str(acc_case.get("result", "")).strip().lower()
    acc_version = str(
        mod_versions.get("AlternateConversationCamera", "")
    ).strip()
    if acc_result == "pass" and acc_version.lower() in placeholders:
        errors.append(
            "mod_versions must record the exact AlternateConversationCamera "
            "version when that case passes"
        )
    return tuple(errors)


def observation_template() -> dict[str, Any]:
    cases: dict[str, Any] = {}
    for name in REQUIRED_COMPATIBILITY_CASES + OPTIONAL_COMPATIBILITY_CASES:
        cases[name] = {"result": "pending", "notes": ""}
    return {
        "runtime": "",
        "plugin_sha256": "",
        "mod_versions": {
            "Precision": "",
            "OpenAnimationReplacer": "",
            "AlternateConversationCamera": "",
        },
        "cases": cases,
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", type=Path, help="SkyrimHandleCapRaise.log")
    parser.add_argument(
        "--observations",
        type=Path,
        help="JSON file containing the manual Precision/OAR/ACC results",
    )
    parser.add_argument(
        "--orchestrator",
        type=Path,
        help="background runner orchestrator.json with exact ForceReset event evidence",
    )
    parser.add_argument(
        "--write-observation-template",
        type=Path,
        metavar="PATH",
        help="write a blank observation JSON template and exit",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    if args.write_observation_template:
        args.write_observation_template.write_text(
            json.dumps(observation_template(), indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"WROTE {args.write_observation_template}")
        return 0
    if not args.log or not args.observations or not args.orchestrator:
        print(
            "ERROR: log, --observations, and --orchestrator are required",
            file=sys.stderr,
        )
        return 2

    try:
        log_text = args.log.read_text(encoding="utf-8", errors="replace")
        observations = json.loads(args.observations.read_text(encoding="utf-8"))
        orchestrator = json.loads(args.orchestrator.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    log_result = verify_log(log_text)
    errors = list(log_result.errors)
    errors.extend(verify_observations(observations))
    errors.extend(verify_orchestrator(orchestrator))
    if errors:
        print("LIVE PRERELEASE VERIFICATION: FAIL")
        for error in errors:
            print(f"- {error}")
        return 1

    print("LIVE PRERELEASE VERIFICATION: PASS")
    print(
        f"- {len(log_result.checkpoints)} full FIFO/player checkpoints passed in one process"
    )
    print("- every loaded-game player checkpoint used raw handle 0x00100000")
    print(
        "- exactly one observed ForceReset produced immediate C+1/R+1 "
        "recreation plus locked LifecycleB C+1/R+1/A+1 identity/FIFO proof"
    )
    print("- Precision, OAR, and applicable ACC observations are recorded as passing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
