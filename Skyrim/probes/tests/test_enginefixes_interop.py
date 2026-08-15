from __future__ import annotations

import copy
import hashlib
import struct
import unittest
from dataclasses import dataclass


STOCK = bytes.fromhex("40555356574154415541564157488d6c")
FILE_SHA = "5d1384acfb523abd1333f5af71af0b7d131b6ebb1a0ee6b3edff86fb4c93adf3"
WRAPPER_SHA = "9d9527245b187e31d067f2ccf77e8cb81dd4615dea263d7608f10f9fc3ee2be0"
AE_RUNTIME = 0x01064920
OWNER_RVA = 0x1B9AB0
WRAPPER_RVA = 0x711F0


def _e9(source: int, target: int) -> bytes:
    displacement = target - (source + 5)
    return b"\xE9" + struct.pack("<i", displacement)


@dataclass
class Fixture:
    runtime: int
    skyrim_base: int
    engine_base: int
    owner: int
    destination_stub: int
    entry: bytes
    trampoline: bytes
    region_state: str
    region_type: str
    region_protection: str
    module_name: str
    version: tuple[int, int, int, int]
    file_sha: str
    image_size: int
    timestamp: int
    destination: int
    wrapper_sha: str
    hook_target: int
    hook_destination: int
    hook_trampoline: int
    hook_trampoline_size: int


def fixture(skyrim_base: int, engine_base: int) -> Fixture:
    owner = skyrim_base + OWNER_RVA
    trampoline = skyrim_base - 0x10000
    destination_stub = trampoline + 10
    destination = engine_base + WRAPPER_RVA
    relay = (
        STOCK[:5]
        + _e9(trampoline + 5, owner + 5)
        + b"\xFF\x25\x00\x00\x00\x00"
        + struct.pack("<Q", destination)
    )
    return Fixture(
        runtime=AE_RUNTIME,
        skyrim_base=skyrim_base,
        engine_base=engine_base,
        owner=owner,
        destination_stub=destination_stub,
        entry=_e9(owner, destination_stub) + STOCK[5:],
        trampoline=relay,
        region_state="MEM_COMMIT",
        region_type="MEM_PRIVATE",
        region_protection="PAGE_EXECUTE_READWRITE",
        module_name="EngineFixes.dll",
        version=(7, 0, 20, 0),
        file_sha=FILE_SHA,
        image_size=0x2A4000,
        timestamp=0x699FC3BA,
        destination=destination,
        wrapper_sha=WRAPPER_SHA,
        hook_target=owner,
        hook_destination=destination,
        hook_trampoline=trampoline,
        hook_trampoline_size=24,
    )


def validate(value: Fixture) -> bool:
    if (
        value.runtime != AE_RUNTIME
        or value.owner != value.skyrim_base + OWNER_RVA
        or value.module_name.casefold() != "enginefixes.dll"
        or value.version != (7, 0, 20, 0)
        or value.file_sha != FILE_SHA
        or value.image_size != 0x2A4000
        or value.timestamp != 0x699FC3BA
    ):
        return False
    if len(value.entry) != 16 or value.entry[0] != 0xE9 or value.entry[5:] != STOCK[5:]:
        return False
    entry_target = value.owner + 5 + struct.unpack("<i", value.entry[1:5])[0]
    if entry_target != value.destination_stub:
        return False
    if (
        value.region_state != "MEM_COMMIT"
        or value.region_type != "MEM_PRIVATE"
        or value.region_protection != "PAGE_EXECUTE_READWRITE"
        or len(value.trampoline) != 24
        or value.trampoline[:5] != STOCK[:5]
        or value.trampoline[5] != 0xE9
        or value.trampoline[10:16] != b"\xFF\x25\x00\x00\x00\x00"
    ):
        return False
    back_target = value.hook_trampoline + 10 + struct.unpack(
        "<i", value.trampoline[6:10]
    )[0]
    relay_destination = struct.unpack("<Q", value.trampoline[16:24])[0]
    if back_target != value.owner + 5 or relay_destination != value.destination:
        return False
    if (
        value.destination != value.engine_base + WRAPPER_RVA
        or value.wrapper_sha != WRAPPER_SHA
        or value.hook_target != value.owner
        or value.hook_destination != value.destination
        or value.hook_trampoline != value.destination_stub - 10
        or value.hook_trampoline_size != 24
    ):
        return False
    return True


class EngineFixesInteropFixtureTests(unittest.TestCase):
    def test_accepts_same_authenticated_chain_at_distinct_aslr_bases(self) -> None:
        cases = (
            fixture(0x00007FF64F170000, 0x00007FFD90E30000),
            fixture(0x0000014000000000, 0x00007FFA12340000),
        )
        for case in cases:
            with self.subTest(skyrim=hex(case.skyrim_base), engine=hex(case.engine_base)):
                self.assertTrue(validate(case))

    def test_rejects_every_mutated_identity_or_chain_component(self) -> None:
        base = fixture(0x00007FF64F170000, 0x00007FFD90E30000)
        mutations = {
            "runtime": lambda x: setattr(x, "runtime", 0x010649B1),
            "entry opcode": lambda x: setattr(x, "entry", b"\xFF" + x.entry[1:]),
            "owner tail": lambda x: setattr(x, "entry", x.entry[:8] + b"\x00" + x.entry[9:]),
            "entry target": lambda x: setattr(x, "entry", _e9(x.owner, x.destination_stub + 1) + STOCK[5:]),
            "copied prologue": lambda x: setattr(x, "trampoline", b"\x90" + x.trampoline[1:]),
            "back edge": lambda x: setattr(x, "trampoline", x.trampoline[:5] + _e9(x.hook_trampoline + 5, x.owner + 6) + x.trampoline[10:]),
            "FF25 stub": lambda x: setattr(x, "trampoline", x.trampoline[:10] + b"\xFF\x15" + x.trampoline[12:]),
            "relay destination": lambda x: setattr(x, "trampoline", x.trampoline[:16] + struct.pack("<Q", x.destination + 1)),
            "region state": lambda x: setattr(x, "region_state", "MEM_RESERVE"),
            "region type": lambda x: setattr(x, "region_type", "MEM_IMAGE"),
            "region protection": lambda x: setattr(x, "region_protection", "PAGE_EXECUTE_READ"),
            "module name": lambda x: setattr(x, "module_name", "EngineFixesVR.dll"),
            "version": lambda x: setattr(x, "version", (7, 0, 21, 0)),
            "file hash": lambda x: setattr(x, "file_sha", "00" * 32),
            "image size": lambda x: setattr(x, "image_size", 0x2A5000),
            "timestamp": lambda x: setattr(x, "timestamp", 0),
            "wrapper RVA": lambda x: setattr(x, "destination", x.engine_base + WRAPPER_RVA + 1),
            "wrapper hash": lambda x: setattr(x, "wrapper_sha", hashlib.sha256(b"changed").hexdigest()),
            "hook target": lambda x: setattr(x, "hook_target", x.owner + 1),
            "hook destination": lambda x: setattr(x, "hook_destination", x.destination + 1),
            "hook trampoline": lambda x: setattr(x, "hook_trampoline", x.hook_trampoline + 1),
            "hook trampoline size": lambda x: setattr(x, "hook_trampoline_size", 26),
        }
        for name, mutate in mutations.items():
            candidate = copy.deepcopy(base)
            mutate(candidate)
            with self.subTest(name=name):
                self.assertFalse(validate(candidate))


if __name__ == "__main__":
    unittest.main()
