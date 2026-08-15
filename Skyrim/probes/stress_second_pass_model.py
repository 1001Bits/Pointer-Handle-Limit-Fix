#!/usr/bin/env python3
"""Independent model of the synthetic stress second-pass release gate.

This model deliberately contains no C++ parsing.  It expresses the required
observable state machine: a retained synthetic set is visited once in bounded
tasks, and release/reuse cannot begin unless every exact lookup, live-entry
check, and temporary-pin balance succeeds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Sequence


class Phase(Enum):
    SYNTHETIC_FILL = auto()
    SYNTHETIC_SECOND_PASS = auto()
    RELEASE_PROBE = auto()
    FAILED = auto()


@dataclass(frozen=True)
class Held:
    handle: int
    index: int
    object_id: int


@dataclass(frozen=True)
class Lookup:
    succeeded: bool
    object_id: int | None
    live_entry_matches: bool = True
    pin_balanced: bool = True


Resolver = Callable[[Held], Lookup]

INDEX_MASK = 0x001FFFFF
AGE_INCREMENT = 0x00200000
RAW_HANDLE_MASK = 0x03FFFFFF
RESERVED_PLAYER_INDEX = 0x00100000


@dataclass
class SyntheticSecondPassModel:
    retained: Sequence[Held]
    verify_second_pass: bool = True
    max_references_per_task: int = 4096
    phase: Phase = Phase.SYNTHETIC_FILL
    cursor: int = 0
    release_started: bool = False
    failure: str = ""
    events: list[tuple[str, int]] = field(default_factory=list)

    def finish_fill(self) -> None:
        if self.phase is not Phase.SYNTHETIC_FILL:
            raise RuntimeError("fill can finish only once")
        if not self.verify_second_pass:
            self._begin_release()
            return
        if not self.retained:
            self._fail("no retained handles")
            return
        self.cursor = 0
        self.phase = Phase.SYNTHETIC_SECOND_PASS
        self.events.append(("second-pass-start", len(self.retained)))

    def run_task(self, resolve: Resolver) -> int:
        if self.phase is not Phase.SYNTHETIC_SECOND_PASS:
            return 0
        if self.max_references_per_task <= 0:
            raise ValueError("task bound must be positive")

        processed = 0
        while self.phase is Phase.SYNTHETIC_SECOND_PASS:
            if self.cursor == len(self.retained):
                self.events.append(("second-pass-pass", self.cursor))
                self._begin_release()
                break

            held = self.retained[self.cursor]
            if (held.object_id == 0 or
                    held.index < 0 or held.index > INDEX_MASK or
                    held.index == RESERVED_PLAYER_INDEX or
                    held.handle <= 0 or
                    (held.handle & ~RAW_HANDLE_MASK) != 0 or
                    (held.handle & INDEX_MASK) != held.index):
                self._fail("invalid retained record")
                break
            result = resolve(held)
            if not result.live_entry_matches:
                self._fail("live entry mismatch")
                break
            if not result.succeeded:
                self._fail("lookup failure")
                break
            if result.object_id != held.object_id:
                self._fail("object identity mismatch")
                break
            if not result.pin_balanced:
                self._fail("temporary pin imbalance")
                break

            self.cursor += 1
            processed += 1
            if processed >= self.max_references_per_task:
                break
        return processed

    def _begin_release(self) -> None:
        self.release_started = True
        self.phase = Phase.RELEASE_PROBE
        self.events.append(("release-start", self.cursor))

    def _fail(self, reason: str) -> None:
        self.failure = reason
        self.phase = Phase.FAILED
        self.events.append(("failure", self.cursor))
