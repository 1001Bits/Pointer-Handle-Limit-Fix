"""Offline simulation of the patch the plugin applies, then re-verify.

Applies the generated patch table to an in-memory copy of the game image
exactly as the DLL would, then disassembles the patched regions again and
checks the result is a coherent 21-bit table encoding that retains Skyrim's
legacy object-word ABI directly:

  * every index mask reads 0x1FFFFF and no 0xFFFFF survives in the regions
  * every age mask reads 0x3E00000 and no 0x3F00000 survives ANYWHERE in .text
  * every in-use mask/test remains byte-for-byte at bit 26
  * every table reference resolves to the new table, none to the old one
  * the existing 21-bit object cache and 10-bit refcount ABI remain unchanged
  * instruction lengths and boundaries are unchanged (in-place edit)

Run: python test_patch.py --runtime SE|AE|GOG|VR
"""

from __future__ import annotations

import argparse
import json
import struct
import sys

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from image import open_runtime

NEW_TABLE_RVA = 0x10000000  # stand-in for the plugin's VirtualAlloc result
RESERVATION_RELAY_RVA = 0x18000000
CONSTRUCTOR_RELAY_RVA = RESERVATION_RELAY_RVA + 0x200
ASSIGNMENT_GUARD_RELAY_RVA = RESERVATION_RELAY_RVA + 0x800
FAKE_CONSTRUCTOR_WRAPPER_VA = 0x1122334455667788
FAKE_CONSTRUCTING_PLAYER_ATOMIC_VA = 0x2233445566778899
FAKE_SELECTOR_HELPER_VA = 0x33445566778899AA
FAKE_RELEASE_COUNTER_VA = 0x445566778899AAB8

CONSTRUCTOR_POST_CALL_SIZES = {
    "SE": 35,
    "AE": 37,
    "GOG": 37,
    "VR": 35,
}

EXPECTED_CORE_MUTATIONS = {
    "SE": 399,
    "AE": 519,
    "GOG": 519,
    "VR": 419,
}
EXPECTED_TOTAL_MUTATIONS = {
    "SE": 404,
    "AE": 524,
    "GOG": 524,
    "VR": 424,
}

INDEX_MASK = 0x001FFFFF
GENERATION_MASK = 0x03E00000
IN_USE_MASK = 0x04000000
RESERVED_INDEX = 0x00100000
DETACHED_BITS = 0x03F00000
NO_INDEX = 0xFFFFFFFF


def build_selector_relay(object_register: str, relay_rva: int,
                         singleton_rva: int, head_rva: int,
                         constructing_atomic_va: int,
                         helper_va: int) -> bytes:
    out = bytearray((
        0x48, 0x3B, 0x1D if object_register == "rbx" else 0x3D,
    ))
    out.extend(struct.pack("<i", singleton_rva - (relay_rva + 7)))
    out.extend((0x74, 0x16, 0x48, 0xB8))
    out.extend(struct.pack("<Q", constructing_atomic_va))
    out.extend((0x48, 0x3B, 0x18 if object_register == "rbx" else 0x38,
                0x74, 0x07, 0x8B, 0x05))
    out.extend(struct.pack("<i", head_rva - (relay_rva + 30)))
    out.append(0xC3)
    out.extend((
        0x48, 0x8B, 0xCB if object_register == "rbx" else 0xCF,
        0x48, 0xB8,
    ))
    out.extend(struct.pack("<Q", helper_va))
    out.extend((0xFF, 0xE0))
    return bytes(out)


def build_release_relay(relay_rva: int, tail_rva: int,
                        table_rva: int, scratch_rva: int,
                        release_counter_va: int) -> bytes:
    out = bytearray((0x8B, 0x05))
    out.extend(struct.pack("<i", tail_rva - (relay_rva + 6)))
    out.extend((
        0x81, 0xFF, 0x00, 0x00, 0x10, 0x00, 0x74, 0x01, 0xC3,
        0x48, 0xC7, 0x03, 0x00, 0x00, 0xF0, 0x03,
        0x8B, 0xF8, 0x48, 0xB8,
    ))
    out.extend(struct.pack("<Q", release_counter_va))
    out.extend((
        0xF0, 0x48, 0xFF, 0x00, 0x8B, 0xC7,
        0x83, 0xF8, 0xFF, 0x74, 0x16,
        0x8B, 0xD8, 0x48, 0xC1, 0xE3, 0x04, 0x48, 0xB8,
    ))
    out.extend(struct.pack("<Q", table_rva))
    out.extend((0x48, 0x03, 0xD8, 0x8B, 0xC7, 0xC3, 0x48, 0xBB))
    out.extend(struct.pack("<Q", scratch_rva))
    out.append(0xC3)
    return bytes(out)


def build_constructor_relay(wrapper_va: int) -> bytes:
    """Register-neutral absolute tail jump used behind the near CALL hook."""
    return b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", wrapper_va)


def run_relay_layout_tests(profile: dict, md, fails: list[str]) -> None:
    object_register = profile["player_reservation"]["selectors"][0]["object_register"]
    selector_rva = RESERVATION_RELAY_RVA
    selector = build_selector_relay(
        object_register, selector_rva,
        profile["player_reservation"]["singleton_rva"], profile["head_rva"],
        FAKE_CONSTRUCTING_PLAYER_ATOMIC_VA, FAKE_SELECTOR_HELPER_VA)
    if len(selector) != 46:
        fails.append(f"selector relay is {len(selector)} bytes, expected 46")
        return
    insns = list(md.disasm(selector, selector_rva))
    mnemonics = [x.mnemonic for x in insns]
    if not insns or sum(x.size for x in insns) != len(selector) or \
            mnemonics != ["cmp", "je", "movabs", "cmp", "je", "mov", "ret",
                         "mov", "movabs", "jmp"]:
        fails.append("selector relay is not the stack-neutral leaf/tail-jump shape")
    if rel_target_for_blob(selector_rva, selector[0:7], 3, 7) != \
            profile["player_reservation"]["singleton_rva"] or \
            struct.unpack_from("<Q", selector, 11)[0] != \
                FAKE_CONSTRUCTING_PLAYER_ATOMIC_VA or \
            rel_target_for_blob(selector_rva + 24, selector[24:30], 2, 6) != \
            profile["head_rva"] or \
            selector_rva + 9 + struct.unpack("<b", selector[8:9])[0] != \
                selector_rva + 31 or \
            selector_rva + 24 + struct.unpack("<b", selector[23:24])[0] != \
                selector_rva + 31 or \
            struct.unpack_from("<Q", selector, 36)[0] != FAKE_SELECTOR_HELPER_VA:
        fails.append("selector ordinary leaf path targets are incorrect")
    fast_mnemonics = [x.mnemonic for x in insns if x.address < selector_rva + 31]
    if fast_mnemonics != ["cmp", "je", "movabs", "cmp", "je", "mov", "ret"]:
        fails.append("selector ordinary path is not the intended no-call leaf")
    wanted_move = f"rcx, {object_register}"
    if not any((x.mnemonic, x.op_str) == ("mov", wanted_move) for x in insns):
        fails.append("selector relay does not pass the candidate through RCX")
    if selector[-2:] != b"\xFF\xE0" or any(
            mnemonic in mnemonics for mnemonic in ("push", "pop", "call")):
        fails.append("selector player path is not a stack-neutral tail jump")

    release_meta = profile["player_reservation"]["release"]
    relay_rva = RESERVATION_RELAY_RVA + 0x100
    release = build_release_relay(
        relay_rva, profile["tail_rva"], NEW_TABLE_RVA,
        RESERVATION_RELAY_RVA + 0x400, FAKE_RELEASE_COUNTER_VA)
    if len(release) != 78:
        fails.append(f"release relay is {len(release)} bytes, expected 78")
        return
    release_insns = list(md.disasm(release, relay_rva))
    release_mnemonics = [x.mnemonic for x in release_insns]
    if sum(x.size for x in release_insns) != len(release) or \
            release_mnemonics.count("ret") != 3 or any(
                mnemonic in release_mnemonics
                for mnemonic in ("push", "pop", "call", "jmp")):
        fails.append("release relay is not stack-neutral on all paths")
    if rel_target_for_blob(relay_rva, release[0:6], 2, 6) != \
            profile["tail_rva"] or \
            relay_rva + 14 + struct.unpack("<b", release[13:14])[0] != \
            relay_rva + 15 or \
            relay_rva + 45 + struct.unpack("<b", release[44:45])[0] != \
            relay_rva + 67:
        fails.append("release relay relative target offsets are incorrect")
    if release[15:22] != b"\x48\xC7\x03\x00\x00\xF0\x03" or \
            struct.unpack_from("<Q", release, 26)[0] != \
                FAKE_RELEASE_COUNTER_VA or \
            release[34:40] != b"\xF0\x48\xFF\x00\x8B\xC7" or \
            struct.unpack_from("<Q", release, 53)[0] != NEW_TABLE_RVA or \
            struct.unpack_from("<Q", release, 69)[0] != \
                RESERVATION_RELAY_RVA + 0x400:
        fails.append(
            "release relay does not quarantine atomically, count it, and restore EAX")

    constructor = build_constructor_relay(FAKE_CONSTRUCTOR_WRAPPER_VA)
    constructor_insns = list(md.disasm(constructor[:6], CONSTRUCTOR_RELAY_RVA))
    if len(constructor) != 14 or len(constructor_insns) != 1 or \
            constructor_insns[0].size != 6 or \
            (constructor_insns[0].mnemonic, constructor_insns[0].op_str) != \
                ("jmp", "qword ptr [rip]") or \
            struct.unpack_from("<Q", constructor, 6)[0] != \
                FAKE_CONSTRUCTOR_WRAPPER_VA:
        fails.append(
            "constructor relay is not the exact FF25 + qword register-neutral tail jump")
    constructor_call = profile["player_reservation"]["lifecycle"]["creation"][
        "constructor_call"]
    return_stack = [constructor_call["rva"] + 5]
    relay_destination = struct.unpack_from("<Q", constructor, 6)[0]
    if relay_destination != FAKE_CONSTRUCTOR_WRAPPER_VA or \
            return_stack.pop() != constructor_call["rva"] + 5 or return_stack:
        fails.append(
            "constructor CALL/relay/wrapper RET model does not round-trip to stock call+5")


def rel_target_for_blob(rva: int, raw: bytes, offset: int, length: int) -> int:
    return rva + length + struct.unpack_from("<i", raw, offset)[0]


def run_reservation_state_model(fails: list[str]) -> None:
    ordinary_candidate = object()
    published_player = object()
    constructing_player = object()

    def selector_treats_as_player(candidate, published, constructing) -> bool:
        return candidate is published or candidate is constructing

    if selector_treats_as_player(ordinary_candidate, published_player,
                                 constructing_player) or \
            not selector_treats_as_player(published_player, published_player,
                                          constructing_player) or \
            not selector_treats_as_player(constructing_player, None,
                                          constructing_player) or \
            selector_treats_as_player(ordinary_candidate, None, None):
        fails.append(
            "selector candidate model does not distinguish ordinary, published, "
            "and constructor-armed objects")

    class Entry:
        def __init__(self, bits: int, pointer=None, pad: int = 0):
            self.bits, self.pad, self.pointer = bits, pad, pointer

    class Pool:
        def __init__(self, nodes: list[int]):
            self.entries = {RESERVED_INDEX: Entry(DETACHED_BITS)}
            self.constructor_assignments = 0
            self.release_quarantines = 0
            for pos, index in enumerate(nodes):
                nxt = nodes[pos + 1] if pos + 1 < len(nodes) else index
                self.entries[index] = Entry(nxt)
            self.head = nodes[0] if nodes else NO_INDEX
            self.tail = nodes[-1] if nodes else NO_INDEX

        def select(self, player: bool) -> int:
            ordinary = self.head
            if not player:
                return ordinary
            reserved = self.entries[RESERVED_INDEX]
            if (reserved.bits, reserved.pad, reserved.pointer) != \
                    (DETACHED_BITS, 0, None):
                raise ValueError("reserved slot not detached")
            if (self.head == NO_INDEX) != (self.tail == NO_INDEX):
                raise ValueError("endpoint mismatch")
            reserved.bits = (31 << 21) | (
                RESERVED_INDEX if ordinary == NO_INDEX else ordinary)
            self.head = RESERVED_INDEX
            if ordinary == NO_INDEX:
                self.tail = RESERVED_INDEX
            return RESERVED_INDEX

        def allocate(self, player: bool) -> int:
            index = self.select(player)
            if index == NO_INDEX:
                return 0
            entry = self.entries[index]
            nxt = entry.bits & INDEX_MASK
            generation = (((entry.bits & GENERATION_MASK) >> 21) + 1) & 31
            entry.bits = nxt | (generation << 21) | IN_USE_MASK
            entry.pointer = object()
            raw = index | (generation << 21)
            if nxt == self.head:
                self.head = self.tail = NO_INDEX
            else:
                self.head = nxt
            return raw

        def ordinary_release(self, raw: int) -> None:
            index = raw & INDEX_MASK
            entry = self.entries[index]
            entry.bits &= ~IN_USE_MASK
            entry.pointer = None
            if self.tail == NO_INDEX:
                self.head = index
            else:
                tail_entry = self.entries[self.tail]
                tail_entry.bits = (tail_entry.bits & ~INDEX_MASK) | index
            entry.bits = (entry.bits & ~INDEX_MASK) | index
            self.tail = index

        def observe_constructor_result(self, cached_valid: bool,
                                       cached_index: int) -> None:
            reserved = self.entries[RESERVED_INDEX]
            assignment_good = \
                (reserved.bits & (GENERATION_MASK | IN_USE_MASK)) == \
                    IN_USE_MASK and \
                reserved.pad == 0 and reserved.pointer is not None
            if cached_valid and (cached_index != RESERVED_INDEX or
                                 not assignment_good):
                raise ValueError("constructor cached a malformed handle")
            if assignment_good:
                self.constructor_assignments += 1

        def free_chain(self) -> list[int]:
            if self.head == NO_INDEX:
                if self.tail != NO_INDEX:
                    raise ValueError("empty free-list has a tail")
                return []
            result = []
            seen = set()
            index = self.head
            while True:
                if index in seen or index == RESERVED_INDEX:
                    raise ValueError("free-list loop or reserved-node exposure")
                seen.add(index)
                result.append(index)
                nxt = self.entries[index].bits & INDEX_MASK
                if index == self.tail:
                    if nxt != index:
                        raise ValueError("free-list tail is not self-linked")
                    return result
                index = nxt

        def quarantine_player(self) -> None:
            self.entries[RESERVED_INDEX] = Entry(DETACHED_BITS)

        def release_player_via_stock_noop(self) -> Entry:
            old_head, old_tail = self.head, self.tail
            self.entries[RESERVED_INDEX] = Entry(DETACHED_BITS)
            self.release_quarantines += 1
            scratch = Entry(0)
            redirected = scratch if old_tail == NO_INDEX else self.entries[old_tail]
            edi = old_tail
            if old_tail == NO_INDEX:
                self.head = edi
                eax = edi & INDEX_MASK
            else:
                tail_entry = self.entries[old_tail]
                tail_entry.bits = (tail_entry.bits & ~INDEX_MASK) | \
                    (edi & INDEX_MASK)
                eax = edi & INDEX_MASK
            redirected.bits = (redirected.bits & ~INDEX_MASK) | eax
            self.tail = edi
            if (self.head, self.tail) != (old_head, old_tail):
                raise ValueError("reserved stock continuation changed endpoints")
            return scratch

    # Initial raised chain physically bypasses R.
    raised_entries = 0x200000
    predecessor_next = RESERVED_INDEX + 1
    ordinary_free_count = raised_entries - 1
    if predecessor_next != RESERVED_INDEX - 1 + 2 or \
            ordinary_free_count != RESERVED_INDEX + \
            (raised_entries - RESERVED_INDEX - 1) or \
            DETACHED_BITS != (31 << 21) | RESERVED_INDEX:
        fails.append("reserved initializer boundary algebra failed")

    multi = Pool([0x20, 0x21, 0x22])
    if multi.allocate(True) != RESERVED_INDEX or \
            (multi.head, multi.tail) != (0x20, 0x22):
        fails.append("multi-node player injection did not preserve ordinary FIFO")
    # The allocator consumes the injected reserved node exactly like any stock
    # free entry: its low index field remains the ordinary successor (0x20),
    # not the reserved physical index.  Player validation must therefore mask
    # the generation/in-use state instead of requiring exact bits 0x04100000.
    if multi.entries[RESERVED_INDEX].bits != IN_USE_MASK | 0x20 or \
            multi.entries[RESERVED_INDEX].bits == IN_USE_MASK | RESERVED_INDEX:
        fails.append("live player entry did not retain its ordinary FIFO successor")
    try:
        multi.observe_constructor_result(True, RESERVED_INDEX)
    except ValueError:
        fails.append("constructor rejected a valid reserved cache with a retained FIFO successor")
    if multi.constructor_assignments != 1:
        fails.append("constructor did not count the masked live reserved assignment")

    one = Pool([0x30])
    if one.allocate(True) != RESERVED_INDEX or \
            (one.head, one.tail) != (0x30, 0x30):
        fails.append("one-node player injection stranded the ordinary node")

    empty = Pool([])
    if empty.allocate(True) != RESERVED_INDEX or \
            (empty.head, empty.tail) != (NO_INDEX, NO_INDEX):
        fails.append("empty-list player injection did not consume the seeded singleton")

    ordinary = Pool([0x40, 0x41])
    if ordinary.allocate(False) == RESERVED_INDEX or \
            ordinary.entries[RESERVED_INDEX].bits != DETACHED_BITS or \
            ordinary.head != 0x41:
        fails.append("non-player allocation consumed or modified the reserved slot")
    released = Pool([0x60, 0x61])
    released_raw = released.allocate(False)
    released.ordinary_release(released_raw)
    if released.free_chain() != [0x61, 0x60] or \
            (released.head, released.tail) != (0x61, 0x60) or \
            released.release_quarantines != 0:
        fails.append("ordinary release did not append its slot to the FIFO tail")

    recreate = Pool([0x50, 0x51])
    first = recreate.allocate(True)
    recreate.observe_constructor_result(True, RESERVED_INDEX)
    endpoints = (recreate.head, recreate.tail)
    recreate.release_player_via_stock_noop()
    if (recreate.head, recreate.tail) != endpoints:
        fails.append("player release quarantine modified ordinary FIFO endpoints")
    second = recreate.allocate(True)
    if first != RESERVED_INDEX or second != RESERVED_INDEX or \
            recreate.constructor_assignments != 1 or \
            recreate.release_quarantines != 1:
        fails.append("player quarantine/recreation did not reissue vanilla raw handle")

    for nodes in ([], [0x70], [0x80, 0x81, 0x82]):
        released_player = Pool(nodes)
        released_player.allocate(True)
        expected_chain = list(nodes)
        before = {
            index: (released_player.entries[index].bits,
                    released_player.entries[index].pad,
                    released_player.entries[index].pointer)
            for index in nodes
        }
        scratch = released_player.release_player_via_stock_noop()
        after = {
            index: (released_player.entries[index].bits,
                    released_player.entries[index].pad,
                    released_player.entries[index].pointer)
            for index in nodes
        }
        reserved_entry = released_player.entries[RESERVED_INDEX]
        if (reserved_entry.bits, reserved_entry.pad, reserved_entry.pointer) != \
                (DETACHED_BITS, 0, None) or \
                released_player.free_chain() != expected_chain or before != after or \
                (nodes and scratch.bits != 0) or \
                (not nodes and scratch.bits != INDEX_MASK) or \
                released_player.release_quarantines != 1 or \
                (nodes and (released_player.entries[nodes[-1]].bits & INDEX_MASK) !=
                 nodes[-1]):
            fails.append(
                "reserved release CALL relay did not no-op empty/one/many FIFO")
            break


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", required=True)
    ap.add_argument("--patch", required=True)
    a = ap.parse_args()

    pt = json.load(open(a.patch))
    if "player_reservation" not in pt:
        raise ValueError("patch profile has no generated player reservation metadata")
    img, _ = open_runtime(a.runtime)
    regions = [tuple(r) for r in pt["regions"]]
    old_table = pt["table_rva"]

    # ---- build a mutable copy of .text ---------------------------------- #
    lo, hi = img.text_ranges()[0]
    text = bytearray(img.read(lo, hi - lo))

    def put(rva: int, data: bytes) -> None:
        text[rva - lo : rva - lo + len(data)] = data

    def get(rva: int, n: int) -> bytes:
        return bytes(text[rva - lo : rva - lo + n])

    fails: list[str] = []

    # The pre-publication no-wrap guard is mandatory for the 2M transaction.
    # Prove that its five callsites name complete stock instructions and one
    # shared helper before simulating any writes.
    assignment = pt.get("assignment_hooks", {})
    assignment_sites = assignment.get("sites", [])
    helper_rva = assignment.get("helper_rva", -1)
    helper_bytes = bytes.fromhex(assignment.get("helper_bytes", ""))
    if len(assignment_sites) != 5:
        fails.append(f"expected five assignment-hook sites, found {len(assignment_sites)}")
    if len(helper_bytes) != 16 or img.read(helper_rva, 16) != helper_bytes:
        fails.append("assignment helper fingerprint does not match the exact executable")
    writer_rvas = {p.get("writer_rva") for p in assignment_sites}
    if len(writer_rvas) != 5:
        fails.append(
            "assignment hooks do not map one-to-one to five allocation publishers")
    for writer_rva in sorted(writer_rvas):
        decoded = img.disasm(writer_rva, 8) if isinstance(writer_rva, int) else []
        if len(decoded) < 2 or decoded[0].mnemonic != "shl" or \
                decoded[0].operands[-1].type != X86_OP_IMM or \
                decoded[0].operands[-1].imm != 0x0B or \
                decoded[1].mnemonic != "bts" or \
                decoded[1].operands[-1].type != X86_OP_IMM or \
                decoded[1].operands[-1].imm != 0x0A:
            fails.append(
                f"assignment publisher differs at {img.base + int(writer_rva or 0):#x}")
    if len({p.get("function_rva") for p in assignment_sites}) != 5:
        fails.append("assignment hooks do not have five distinct owning functions")
    for p in assignment_sites:
        call = bytes.fromhex(p.get("call_bytes", ""))
        setup = bytes.fromhex(p.get("setup_bytes", ""))
        function = bytes.fromhex(p.get("function_bytes", ""))
        call_rva = p.get("call_rva", -1)
        function_rva = p.get("function_rva", -1)
        if len(call) != 5 or call[:1] != b"\xE8" or img.read(call_rva, 5) != call:
            fails.append(f"assignment call bytes differ at {img.base + call_rva:#x}")
            continue
        target = call_rva + 5 + struct.unpack("<i", call[1:])[0]
        if target != helper_rva or p.get("call_target_rva") != helper_rva:
            fails.append(f"assignment call at {img.base + call_rva:#x} targets {target:#x}, "
                         f"not helper {helper_rva:#x}")
        if len(setup) != 11 or p.get("setup_rva") != call_rva - 11 or \
                img.read(call_rva - 11, 11) != setup:
            fails.append(f"assignment setup bytes differ at {img.base + call_rva - 11:#x}")
        if len(function) != 16 or img.read(function_rva, 16) != function:
            fails.append(f"assignment owner bytes differ at {img.base + function_rva:#x}")
        fn = img.func_containing(call_rva) if hasattr(img, "func_containing") else None
        owner_good = fn.begin == function_rva if fn is not None else \
            function_rva < call_rva
        if not owner_good or not \
                (p.get("lock_call_rva", call_rva) < call_rva <
                 p.get("unlock_call_rva", call_rva)):
            fails.append(f"assignment call at {img.base + call_rva:#x} lost its owner/lock bracket")

    reservation = pt["player_reservation"]
    selectors = reservation.get("selectors", [])
    release_hook = reservation.get("release", {})
    if reservation.get("handle_rva", -1) + 4 != reservation.get("singleton_rva"):
        fails.append("player handle and singleton globals are not adjacent")
    if len(selectors) != 5 or len({p.get("function_rva") for p in selectors}) != 5:
        fails.append("player reservation does not name five selector owners")

    def rel_target(rva: int, raw: bytes, disp_offset: int, length: int) -> int:
        return rva + length + struct.unpack_from("<i", raw, disp_offset)[0]

    selector_registers = set()
    for p in selectors:
        rva = int(p.get("hook_rva", -1))
        hook = bytes.fromhex(p.get("hook_bytes", ""))
        owner = bytes.fromhex(p.get("function_bytes", ""))
        setup = bytes.fromhex(p.get("object_setup_bytes", ""))
        lock = bytes.fromhex(p.get("lock_call_bytes", ""))
        unlock = bytes.fromhex(p.get("unlock_call_bytes", ""))
        pre_hook = bytes.fromhex(p.get("pre_hook_bytes", ""))
        continuation = bytes.fromhex(p.get("continuation_bytes", ""))
        selector_registers.add(p.get("object_register"))
        if len(hook) != 6 or hook[:2] != b"\x8b\x05" or \
                img.read(rva, 6) != hook or \
                rel_target(rva, hook, 2, 6) != pt["head_rva"]:
            fails.append(f"player selector at {img.base + rva:#x} is not exact free-head load")
        if len(owner) != 16 or img.read(p.get("function_rva", -1), 16) != owner:
            fails.append(f"player selector owner differs at {img.base + p.get('function_rva', -1):#x}")
        wanted_setup = {"rbx": b"\x48\x8b\xda", "rdi": b"\x48\x8b\xfa"}.get(
            p.get("object_register"))
        if len(setup) != 3 or setup != wanted_setup or \
                img.read(p.get("object_setup_rva", -1), 3) != setup:
            fails.append(f"player selector candidate ABI differs at {img.base + rva:#x}")
        if len(lock) != 5 or lock[:1] != b"\xe8" or \
                img.read(p.get("lock_call_rva", -1), 5) != lock or \
                rel_target(p["lock_call_rva"], lock, 1, 5) != pt["lock_write_rva"]:
            fails.append(f"player selector lock call differs at {img.base + rva:#x}")
        if len(unlock) != 5 or unlock[:1] != b"\xe8" or \
                img.read(p.get("unlock_call_rva", -1), 5) != unlock or \
                rel_target(p["unlock_call_rva"], unlock, 1, 5) != pt["unlock_write_rva"]:
            fails.append(f"player selector unlock call differs at {img.base + rva:#x}")
        if p.get("stack_allocation") != 0x30 or \
                p.get("pre_hook_rva") != p.get("function_rva") or \
                p.get("pre_hook_rva", -1) + len(pre_hook) != rva or \
                not (0 < len(pre_hook) <= 256) or \
                img.read(p.get("pre_hook_rva", -1), len(pre_hook)) != pre_hook or \
                pre_hook[:15] != bytes.fromhex("41564883ec3048c7442420feffffff"):
            fails.append(f"player selector pre-hook shadow-space proof differs at {img.base + rva:#x}")
        if p.get("continuation_rva") != rva + 6 or \
                not (0 < len(continuation) <= 256) or \
                img.read(p.get("continuation_rva", -1), len(continuation)) != continuation or \
                continuation[:3] != b"\x83\xF8\xFF":
            fails.append(f"player selector continuation proof differs at {img.base + rva:#x}")
    if selector_registers not in ({"rbx"}, {"rdi"}):
        fails.append("player selector clones disagree on candidate register")

    release_rva = int(release_hook.get("hook_rva", -1))
    release_bytes = bytes.fromhex(release_hook.get("hook_bytes", ""))
    release_owner = bytes.fromhex(release_hook.get("function_bytes", ""))
    release_unlock = bytes.fromhex(release_hook.get("unlock_call_bytes", ""))
    release_pre_hook = bytes.fromhex(release_hook.get("pre_hook_bytes", ""))
    release_continuation = bytes.fromhex(
        release_hook.get("continuation_bytes", ""))
    if len(release_bytes) != 6 or release_bytes[:2] != b"\x8b\x05" or \
            img.read(release_rva, 6) != release_bytes or \
            rel_target(release_rva, release_bytes, 2, 6) != pt["tail_rva"] or \
            release_hook.get("resume_rva") != release_rva + 6:
        fails.append("canonical player release hook is not the exact free-tail load")
    if len(release_owner) != 16 or \
            img.read(release_hook.get("function_rva", -1), 16) != release_owner:
        fails.append("canonical player release owner fingerprint differs")
    if len(release_unlock) != 5 or release_unlock[:1] != b"\xe8" or \
            img.read(release_hook.get("unlock_call_rva", -1), 5) != release_unlock or \
            rel_target(release_hook["unlock_call_rva"], release_unlock, 1, 5) != \
                pt["unlock_write_rva"]:
        fails.append("canonical player release unlock call differs")
    if release_hook.get("pre_hook_rva") != release_hook.get("function_rva") or \
            release_hook.get("pre_hook_rva", -1) + len(release_pre_hook) != \
                release_rva or not (0 < len(release_pre_hook) <= 256) or \
            img.read(release_hook.get("pre_hook_rva", -1),
                     len(release_pre_hook)) != release_pre_hook:
        fails.append("canonical player release pre-hook ABI proof differs")
    if release_hook.get("continuation_rva") != release_rva + 6 or \
            not (0 < len(release_continuation) <= 128) or \
            img.read(release_hook.get("continuation_rva", -1),
                     len(release_continuation)) != release_continuation or \
            release_continuation[:3] != b"\x83\xF8\xFF":
        fails.append("canonical player release continuation/epilogue proof differs")

    lifecycle = reservation.get("lifecycle", {})
    for phase in ("creation", "teardown"):
        section = lifecycle.get(phase, {})
        function_rva = int(section.get("function_rva", -1))
        function = bytes.fromhex(section.get("function_bytes", ""))
        if len(function) != 16 or img.read(function_rva, 16) != function:
            fails.append(f"player {phase} owner fingerprint differs")
        for role, record in section.items():
            if role in ("function_rva", "function_bytes",
                        "constructor_function_rva",
                        "constructor_function_bytes",
                        "constructor_pre_hook_rva",
                        "constructor_pre_hook_bytes",
                        "constructor_post_call_rva",
                        "constructor_post_call_bytes"):
                continue
            records = record if role == "zero_sources" else [record]
            for item in records:
                raw = bytes.fromhex(item.get("bytes", ""))
                if not raw or img.read(item.get("rva", -1), len(raw)) != raw:
                    fails.append(f"player {phase} {role} exact bytes differ")
    creation = lifecycle.get("creation", {})
    teardown = lifecycle.get("teardown", {})
    creation_order = [creation.get(key, {}).get("rva", -1) for key in
                      ("constructor_call", "singleton_store", "candidate_load", "allocator_call",
                       "handle_store", "formid_setup", "formid_call")]
    teardown_order = [teardown.get(key, {}).get("rva", -1) for key in
                      ("handle_load", "release_call", "singleton_clear")]
    if creation_order != sorted(creation_order) or teardown_order != sorted(teardown_order):
        fails.append("player lifecycle publication/release ordering changed")
    constructor_raw = bytes.fromhex(
        creation.get("constructor_call", {}).get("bytes", ""))
    constructor_function_rva = creation.get("constructor_function_rva", -1)
    constructor_function = bytes.fromhex(
        creation.get("constructor_function_bytes", ""))
    constructor_pre_hook_rva = creation.get("constructor_pre_hook_rva", -1)
    constructor_pre_hook = bytes.fromhex(
        creation.get("constructor_pre_hook_bytes", ""))
    constructor_post_call_rva = creation.get(
        "constructor_post_call_rva", -1)
    constructor_post_call = bytes.fromhex(
        creation.get("constructor_post_call_bytes", ""))
    allocator_raw = bytes.fromhex(creation.get("allocator_call", {}).get("bytes", ""))
    teardown_raw = bytes.fromhex(teardown.get("release_call", {}).get("bytes", ""))
    if len(constructor_raw) != 5 or constructor_raw[:1] != b"\xe8" or \
            rel_target(creation_order[0], constructor_raw, 1, 5) != \
                constructor_function_rva or \
            img.read(creation_order[0] - 3, 3) != b"\x48\x8b\xc8":
        fails.append("player constructor hook is not the direct CALL after MOV RCX,RAX")
    constructor_fn = img.func_containing(constructor_function_rva) \
        if hasattr(img, "func_containing") else None
    if len(constructor_function) != 16 or \
            img.read(constructor_function_rva, 16) != constructor_function or \
            (constructor_fn is not None and
             constructor_fn.begin != constructor_function_rva):
        fails.append("player constructor entry fingerprint/function boundary differs")
    if not (0 < len(constructor_pre_hook) <= 256) or \
            constructor_pre_hook_rva != creation.get("function_rva") or \
            constructor_pre_hook_rva + len(constructor_pre_hook) != \
                creation_order[0] or \
            img.read(constructor_pre_hook_rva, len(constructor_pre_hook)) != \
                constructor_pre_hook or \
            constructor_pre_hook[:16] != bytes.fromhex(
                creation.get("function_bytes", "")):
        fails.append("player constructor full pre-hook ABI fingerprint differs")
    if len(constructor_post_call) != CONSTRUCTOR_POST_CALL_SIZES[a.runtime] or \
            constructor_post_call_rva != creation_order[0] + 5 or \
            constructor_post_call_rva + len(constructor_post_call) != \
                creation_order[1] or \
            img.read(constructor_post_call_rva,
                     len(constructor_post_call)) != constructor_post_call:
        fails.append("player constructor post-call publication fingerprint differs")
    else:
        post_insns = list(img.md.disasm(
            constructor_post_call, img.base + constructor_post_call_rva))
        if not post_insns or sum(ins.size for ins in post_insns) != \
                len(constructor_post_call):
            fails.append(
                "player constructor post-call publication window is not contiguous")
        equality_edges = []
        for index in range(max(0, len(post_insns) - 2)):
            singleton_load, compare, branch = post_insns[index:index + 3]
            if singleton_load.mnemonic != "mov" or \
                    singleton_load.op_str.split(",", 1)[0] != "rcx" or \
                    len(singleton_load.operands) != 2 or \
                    singleton_load.operands[1].type != X86_OP_MEM or \
                    singleton_load.operands[1].mem.base != X86_REG_RIP or \
                    singleton_load.address - img.base + singleton_load.size + \
                        singleton_load.operands[1].mem.disp != \
                        reservation["singleton_rva"] or \
                    (compare.mnemonic, compare.op_str) != ("cmp", "rcx, rax") or \
                    branch.mnemonic not in ("je", "jz") or \
                    len(branch.operands) != 1 or \
                    branch.operands[0].type != X86_OP_IMM:
                continue
            equality_edges.append(branch)
        if len(equality_edges) != 1:
            fails.append(
                "player constructor publication gap lost its unique singleton==RAX edge")
        else:
            equality_edge = equality_edges[0]
            published_join_rva = equality_edge.operands[0].imm - img.base
            if not (creation_order[1] +
                    len(bytes.fromhex(creation["singleton_store"]["bytes"])) <
                    published_join_rva < creation_order[3]):
                fails.append(
                    "player constructor equality edge no longer joins post-publication")
            post_store_insns = list(img.md.disasm(
                img.read(creation_order[1], creation_order[3] - creation_order[1]),
                img.base + creation_order[1]))
            if not any(ins.mnemonic not in ("jmp", "ljmp") and
                       ins.mnemonic.startswith("j") and
                       len(ins.operands) == 1 and
                       ins.operands[0].type == X86_OP_IMM and
                       ins.operands[0].imm - img.base == published_join_rva
                       for ins in post_store_insns):
                fails.append(
                    "player constructor equality edge lost the stock post-store join")
            exceptional_control = {
                "loop", "loope", "loopne", "jecxz", "jrcxz",
                "syscall", "sysenter", "sysret", "sysexit",
                "int", "int1", "int3", "into", "iret", "iretd", "iretq",
            }
            for ins in post_insns:
                rva = ins.address - img.base
                if ins.mnemonic.startswith("call") or \
                        ins.mnemonic.startswith("ret") or \
                        ins.mnemonic in exceptional_control:
                    fails.append(
                        f"player constructor publication gap transfers control at "
                        f"{ins.address:#x}")
                    continue
                if not ins.mnemonic.startswith("j"):
                    continue
                if len(ins.operands) != 1 or \
                        ins.operands[0].type != X86_OP_IMM:
                    fails.append(
                        f"player constructor publication gap has indirect branch at "
                        f"{ins.address:#x}")
                    continue
                target_rva = ins.operands[0].imm - img.base
                if target_rva <= rva or not (
                        constructor_post_call_rva <= target_rva <= creation_order[1] or
                        ins.address == equality_edge.address and
                        target_rva == published_join_rva):
                    fails.append(
                        f"player constructor publication gap escapes before publication "
                        f"at {ins.address:#x}")
    if len(allocator_raw) != 5 or rel_target(creation_order[3], allocator_raw, 1, 5) != \
            selectors[0].get("function_rva"):
        fails.append("player lifecycle allocator call does not target selector owner")
    if len(teardown_raw) != 5 or rel_target(teardown_order[1], teardown_raw, 1, 5) != \
            release_hook.get("function_rva"):
        fails.append("player lifecycle release call does not target canonical release")

    # No two independent generated writes may overlap.  Field patches own a
    # sub-field, while byte patches and table references own whole records.
    owners: dict[int, str] = {}

    def claim(rva: int, n: int, owner: str) -> None:
        for q in range(rva, rva + n):
            if q in owners:
                fails.append(f"overlap at {img.base + q:#x}: {owners[q]} vs {owner}")
            owners[q] = owner

    def raised_window(rva: int, stock: bytes, label: str) -> bytes:
        expected = bytearray(stock)
        end = rva + len(stock)

        def overlap(site: int, length: int) -> bool:
            return site < end and rva < site + length

        def contained(site: int, length: int) -> bool:
            return rva <= site and site + length <= end

        for patch in pt["patches"]:
            if not overlap(patch["rva"], patch["len"]):
                continue
            if not contained(patch["rva"], patch["len"]):
                fails.append(f"{label} partially overlaps field patch at {patch['rva']:#x}")
                continue
            offset = patch["rva"] - rva + patch["field_off"]
            width = patch["field_w"]
            expected[offset:offset + width] = \
                int(patch["new"]).to_bytes(width, "little")
        for reference in pt["table_refs"]:
            if not overlap(reference["rva"], reference["len"]):
                continue
            if not contained(reference["rva"], reference["len"]):
                fails.append(
                    f"{label} partially overlaps table ref at {reference['rva']:#x}")
                continue
            offset = reference["rva"] - rva + reference["disp_off"]
            displacement = NEW_TABLE_RVA - \
                (reference["rva"] + reference["len"])
            expected[offset:offset + 4] = struct.pack("<i", displacement)
        for patch in pt["init_patches"]:
            if overlap(patch["rva"], patch["len"]):
                fails.append(f"{label} unexpectedly overlaps initializer guard")
        return bytes(expected)

    # ---- apply exactly what the DLL applies ----------------------------- #
    for p in pt["patches"]:
        cur = get(p["rva"], p["len"])
        if cur != bytes.fromhex(p["orig"]):
            fails.append(f"pre-check: bytes at {img.base + p['rva']:#x} differ from the table")
            continue
        off = p["rva"] + p["field_off"]
        claim(off, p["field_w"], f"field {p['cat']} at {p['rva']:#x}")
        if p["field_w"] == 4:
            put(off, struct.pack("<I", p["new"]))
        else:
            put(off, bytes([p["new"] & 0xFF]))

    for p in pt["init_patches"]:
        cur = get(p["rva"], p["len"])
        if cur != bytes.fromhex(p["orig"]):
            fails.append(f"pre-check: raw bytes at {img.base + p['rva']:#x} differ from the table")
            continue
        claim(p["rva"], p["len"], f"byte patch {p['cat']} at {p['rva']:#x}")
        put(p["rva"], bytes.fromhex(p["new"]))

    for p in pt["table_refs"]:
        cur = get(p["rva"], p["len"])
        if cur != bytes.fromhex(p["orig"]):
            fails.append(f"pre-check: table-ref instruction at {img.base + p['rva']:#x} differs from the table")
            continue
        d = p["rva"] + p["disp_off"]
        claim(d, 4, f"table reference at {p['rva']:#x}")
        disp = NEW_TABLE_RVA - (p["rva"] + p["len"])
        put(d, struct.pack("<i", disp))

    selector_relay = RESERVATION_RELAY_RVA
    release_relay = RESERVATION_RELAY_RVA + 0x100
    for p in selectors:
        rva = p["hook_rva"]
        stock = bytes.fromhex(p["hook_bytes"])
        for window_name in ("pre_hook", "continuation"):
            window_rva = p[f"{window_name}_rva"]
            window_stock = bytes.fromhex(p[f"{window_name}_bytes"])
            if get(window_rva, len(window_stock)) != raised_window(
                    window_rva, window_stock,
                    f"selector {window_name} at {rva:#x}"):
                fails.append(
                    f"player selector {window_name} raised expectation differs "
                    f"at {img.base + window_rva:#x}")
        if get(rva, 6) != stock:
            fails.append(f"cap simulation changed player selector at {img.base + rva:#x}")
        claim(rva, 6, f"player selector hook at {rva:#x}")
        displacement = selector_relay - (rva + 5)
        patched = b"\xE8" + struct.pack("<i", displacement) + b"\x90"
        put(rva, patched)
        if get(rva, 1) != b"\xE8" or \
                rel_target(rva, get(rva, 6), 1, 5) != selector_relay or \
                get(rva + 5, 1) != b"\x90":
            fails.append(f"player selector patched target differs at {img.base + rva:#x}")
        guards = (
            (p["function_rva"], 16, "owner"),
            (p["object_setup_rva"], 3, "candidate setup"),
            (p["lock_call_rva"], 5, "lock call"),
            (p["unlock_call_rva"], 5, "unlock call"),
        )
        for guard_rva, guard_len, guard_name in guards:
            if any(q in owners and not (rva <= q < rva + 6)
                   for q in range(guard_rva, guard_rva + guard_len)):
                fails.append(
                    f"player selector {guard_name} at {img.base + guard_rva:#x} overlaps a mutation")

    for window_name in ("pre_hook", "continuation"):
        window_rva = release_hook[f"{window_name}_rva"]
        window_stock = bytes.fromhex(release_hook[f"{window_name}_bytes"])
        if get(window_rva, len(window_stock)) != raised_window(
                window_rva, window_stock, f"release {window_name}"):
            fails.append(
                f"player release {window_name} raised expectation differs")
    if get(release_rva, 6) != release_bytes:
        fails.append(f"cap simulation changed player release hook at {img.base + release_rva:#x}")
    claim(release_rva, 6, f"player release hook at {release_rva:#x}")
    displacement = release_relay - (release_rva + 5)
    patched_release = b"\xE8" + struct.pack("<i", displacement) + b"\x90"
    put(release_rva, patched_release)
    if get(release_rva, 1) != b"\xE8" or \
            rel_target(release_rva, get(release_rva, 6), 1, 5) != release_relay or \
            get(release_rva + 5, 1) != b"\x90":
        fails.append("player release patched target differs")
    for guard_rva, guard_len, guard_name in (
            (release_hook["function_rva"], 16, "owner"),
            (release_hook["unlock_call_rva"], 5, "unlock call")):
        if any(q in owners and not (release_rva <= q < release_rva + 6)
               for q in range(guard_rva, guard_rva + guard_len)):
            fails.append(
                f"player release {guard_name} at {img.base + guard_rva:#x} overlaps a mutation")

    constructor_rva = creation["constructor_call"]["rva"]
    constructor_stock = bytes.fromhex(creation["constructor_call"]["bytes"])

    def constructor_hook_state(raw: bytes) -> str:
        if raw == constructor_stock:
            return "stock"
        if len(raw) == 5 and raw[:1] == b"\xE8" and \
                rel_target(constructor_rva, raw, 1, 5) == CONSTRUCTOR_RELAY_RVA:
            return "patched"
        return "invalid"

    if constructor_hook_state(get(constructor_rva, 5)) != "stock":
        fails.append("cap simulation changed the authenticated constructor CALL")
    if get(constructor_pre_hook_rva, len(constructor_pre_hook)) != \
            constructor_pre_hook or raised_window(
                constructor_pre_hook_rva, constructor_pre_hook,
                "constructor pre-hook ABI window") != constructor_pre_hook:
        fails.append(
            "cap simulation changed or overlaps the constructor pre-hook ABI window")
    if get(constructor_post_call_rva, len(constructor_post_call)) != \
            constructor_post_call or raised_window(
                constructor_post_call_rva, constructor_post_call,
                "constructor post-call publication ABI window") != \
            constructor_post_call:
        fails.append(
            "cap simulation changed or overlaps the constructor post-call "
            "publication ABI window")
    for guard_rva, guard_len, guard_name in (
            (constructor_pre_hook_rva, len(constructor_pre_hook),
             "full pre-hook ABI window"),
            (constructor_post_call_rva, len(constructor_post_call),
             "post-call publication ABI window"),
            (creation["constructor_function_rva"], 16, "constructor entry"),
            (constructor_rva - 3, 3, "RCX setup")):
        if any(q in owners for q in range(guard_rva, guard_rva + guard_len)):
            fails.append(
                f"player constructor {guard_name} at {img.base + guard_rva:#x} "
                "overlaps a cap mutation")
    claim(constructor_rva, 5,
          f"player constructor hook at {constructor_rva:#x}")
    constructor_patched = b"\xE8" + struct.pack(
        "<i", CONSTRUCTOR_RELAY_RVA - (constructor_rva + 5))
    put(constructor_rva, constructor_patched)
    if constructor_hook_state(get(constructor_rva, 5)) != "patched":
        fails.append("player constructor patched target differs")
    malformed_constructor = bytearray(constructor_patched)
    malformed_constructor[-1] ^= 0x40
    if constructor_hook_state(bytes(malformed_constructor)) != "invalid":
        fails.append("player constructor state model accepted a non-stock/non-relay CALL")

    # Model transaction rollback and a subsequent clean retry. Both states
    # must be byte-exact; there is no permissive opcode-only third state.
    put(constructor_rva, constructor_stock)
    if constructor_hook_state(get(constructor_rva, 5)) != "stock":
        fails.append("player constructor rollback did not restore the exact stock CALL")
    put(constructor_rva, constructor_patched)
    if constructor_hook_state(get(constructor_rva, 5)) != "patched":
        fails.append("player constructor hook did not survive a clean post-rollback retry")

    # The authenticated stock publisher target is staged before the first
    # redirect is written, matching production's fail-closed install order.
    original_assignment_helper = helper_rva if \
        get(helper_rva, 16) == helper_bytes else None
    if original_assignment_helper is None:
        fails.append("stock assignment helper was not staged before guard redirects")

    def assignment_hook_state(raw: bytes, call_rva: int) -> str:
        stock = next(
            bytes.fromhex(site["call_bytes"])
            for site in assignment_sites if site["call_rva"] == call_rva)
        if raw == stock:
            return "stock"
        if len(raw) == 5 and raw[:1] == b"\xE8" and \
                rel_target(call_rva, raw, 1, 5) == ASSIGNMENT_GUARD_RELAY_RVA:
            return "patched"
        return "invalid"

    assignment_stock: dict[int, bytes] = {}
    assignment_patched: dict[int, bytes] = {}
    for p in assignment_sites:
        call_rva = p["call_rva"]
        function_rva = p["function_rva"]
        if any(q in owners for q in range(call_rva - 11, call_rva + 5)):
            fails.append(f"assignment hook window at {img.base + call_rva - 11:#x} overlaps a cap rewrite")
        if any(q in owners for q in range(function_rva, function_rva + 16)):
            fails.append(f"assignment owner fingerprint at {img.base + function_rva:#x} overlaps a cap rewrite")
        if get(call_rva, 5) != bytes.fromhex(p["call_bytes"]) or \
                get(call_rva - 11, 11) != bytes.fromhex(p["setup_bytes"]):
            fails.append(f"cap simulation changed assignment-hook bytes at {img.base + call_rva:#x}")
        if get(function_rva, 16) != bytes.fromhex(p["function_bytes"]):
            fails.append(f"cap simulation changed assignment owner at {img.base + function_rva:#x}")
        stock = bytes.fromhex(p["call_bytes"])
        patched = b"\xE8" + struct.pack(
            "<i", ASSIGNMENT_GUARD_RELAY_RVA - (call_rva + 5))
        assignment_stock[call_rva] = stock
        assignment_patched[call_rva] = patched
        claim(call_rva, 5,
              f"mandatory assignment guard at {call_rva:#x}")
        put(call_rva, patched)
        if original_assignment_helper is None or \
                assignment_hook_state(get(call_rva, 5), call_rva) != "patched":
            fails.append(
                f"mandatory assignment guard target differs at {img.base + call_rva:#x}")
    if any(q in owners for q in range(helper_rva, helper_rva + 16)):
        fails.append(f"assignment helper fingerprint at {img.base + helper_rva:#x} overlaps a cap rewrite")
    if get(helper_rva, 16) != helper_bytes:
        fails.append("cap simulation changed the assignment helper fingerprint")

    if assignment_sites:
        malformed = bytearray(assignment_patched[assignment_sites[0]["call_rva"]])
        malformed[-1] ^= 0x40
        if assignment_hook_state(
                bytes(malformed), assignment_sites[0]["call_rva"]) != "invalid":
            fails.append("assignment guard state model accepted a foreign CALL target")

    # Model a failed install restoring all five exact stock calls, clearing the
    # staged helper, then a clean retry that stages the helper before redirects.
    for call_rva, stock in assignment_stock.items():
        put(call_rva, stock)
    original_assignment_helper = None
    if any(assignment_hook_state(get(call_rva, 5), call_rva) != "stock"
           for call_rva in assignment_stock):
        fails.append("assignment guard rollback did not restore all stock calls")
    original_assignment_helper = helper_rva
    for call_rva, patched in assignment_patched.items():
        put(call_rva, patched)
    if original_assignment_helper != helper_rva or any(
            assignment_hook_state(get(call_rva, 5), call_rva) != "patched"
            for call_rva in assignment_patched):
        fails.append(
            "assignment guard did not survive a helper-first clean install retry")

    core_mutations = (len(pt["patches"]) + len(pt["init_patches"]) +
                      len(pt["table_refs"]) + len(selectors) + 2)
    total_mutations = core_mutations + len(assignment_sites)
    if core_mutations != EXPECTED_CORE_MUTATIONS[a.runtime] or \
            total_mutations != EXPECTED_TOTAL_MUTATIONS[a.runtime]:
        fails.append(
            f"mandatory mutation census differs: core={core_mutations} "
            f"total={total_mutations}")

    print(f"applied {len(pt['patches'])} field rewrites, "
          f"{len(pt['init_patches'])} initializer guards, "
          f"{len(pt['table_refs'])} table references, "
          f"{len(selectors) + 2} mandatory player hooks, and "
          f"{len(assignment_sites)} mandatory assignment guards "
          f"({core_mutations} core / {total_mutations} total mutations)")

    # ---- re-verify ------------------------------------------------------ #
    md = img.md
    counts = {
        "index_mask_new": 0, "index_mask_old": 0,
        "age_mask_new": 0, "age_mask_old": 0,
        "bt26": 0, "bt28": 0,
        "table_new": 0, "table_old": 0,
        "refcount_mask": 0, "valid_bit": 0, "shift11": 0,
        "inuse_mask": 0, "clear_inuse": 0,
        "age_inc_new": 0, "age_inc_old": 0,
        "clear_next_new": 0, "clear_age_new": 0,
    }

    for begin, end in sorted(regions):
        for ins in md.disasm(get(begin, end - begin), img.base + begin):
            rva = ins.address - img.base
            if rva >= end:
                break
            for op in ins.operands:
                if op.type == X86_OP_IMM:
                    v = op.imm & 0xFFFFFFFF
                elif op.type == X86_OP_MEM:
                    if op.mem.base == X86_REG_RIP:
                        tgt = rva + ins.size + op.mem.disp
                        if tgt == NEW_TABLE_RVA:
                            counts["table_new"] += 1
                        elif tgt == old_table:
                            counts["table_old"] += 1
                        continue
                    v = op.mem.disp & 0xFFFFFFFF
                else:
                    continue
                if ins.mnemonic in ("bt", "bts", "btr", "btc") and op.type == X86_OP_IMM:
                    if v == 0x1A:
                        counts["bt26"] += 1
                    elif v == 0x1C:
                        counts["bt28"] += 1
                    continue
                if v == 0x001FFFFF:
                    counts["index_mask_new"] += 1
                elif v == 0x000FFFFF:
                    counts["index_mask_old"] += 1
                elif v == 0x03E00000:
                    counts["age_mask_new"] += 1
                elif v == 0x03F00000:
                    counts["age_mask_old"] += 1
                elif v == 0x00200000:
                    counts["age_inc_new"] += 1
                elif v == 0x00100000:
                    counts["age_inc_old"] += 1
                elif v == 0xFFE00000:
                    counts["clear_next_new"] += 1
                elif v == 0xFC1FFFFF:
                    counts["clear_age_new"] += 1
                elif v == 0x04000000:
                    counts["inuse_mask"] += 1
                elif v == 0xFBFFFFFF:
                    counts["clear_inuse"] += 1
                elif v == 0x3FF:
                    counts["refcount_mask"] += 1
                elif v == 0x400:
                    counts["valid_bit"] += 1
            if ins.mnemonic in ("shr", "shl") and ins.operands[-1].type == X86_OP_IMM \
                    and ins.operands[-1].imm == 0x0B:
                counts["shift11"] += 1

    for k, v in counts.items():
        print(f"  {k:<18} {v}")

    # ---- assertions ----------------------------------------------------- #
    def check(cond: bool, msg: str) -> None:
        if not cond:
            fails.append(msg)

    run_relay_layout_tests(pt, md, fails)
    run_reservation_state_model(fails)

    expected_rewrites = {
        0x000FFFFF: 0x001FFFFF,
        0x03F00000: 0x03E00000,
        0x00100000: 0x00200000,
        0x01000000: 0x02000000,
        0xFC0FFFFF: 0xFC1FFFFF,
        0xFFF00000: 0xFFE00000,
    }
    expected_categories = {
        "index_mask", "age_mask", "age_inc_or_count", "table_bytes",
        "clear_age", "clear_next",
    }
    check(pt.get("stock_entries") == 0x100000 and
          pt.get("raised_entries") == 0x200000 and
          pt.get("entry_size") == 0x10,
          "profile does not describe a fixed 2M-entry, 16-byte table")
    check(pt.get("raised_entries", 0) * pt.get("entry_size", 0) == 0x02000000,
          "profile table extent is not exactly 32 MiB")
    check(not ({"raw_patches", "release_sites", "excluded_shift11"} & set(pt)),
          "profile still exposes a 4M sidecar/release-window schema")
    check({p.get("cat") for p in pt["patches"]} == expected_categories,
          "field patch categories do not exactly match the 21+5 layout")
    for p in pt["patches"]:
        check(expected_rewrites.get(p.get("old")) == p.get("new"),
              f"unexpected layout rewrite {p.get('old', -1):#x} -> "
              f"{p.get('new', -1):#x} at {p.get('rva', -1):#x}")

    check(counts["index_mask_old"] == 0, "a 20-bit index mask survived inside a patched region")
    check(counts["age_mask_old"] == 0, "a stock age mask survived inside a patched region")
    check(counts["bt28"] == 0, "a former 4M in-use test still targets bit 28")
    check(counts["table_old"] == 0, "a reference to the OLD table survived")
    check(counts["table_new"] == len(pt["table_refs"]),
          f"expected {len(pt['table_refs'])} references to the new table, "
          f"found {counts['table_new']}")

    # The 21-bit design must leave the entire object cache and bit-26 in-use
    # protocol byte-for-byte stock.  Compare semantic-instruction censuses on
    # both sides in addition to the mutation-overlap checks above.
    orig_counts = {
        "refcount_mask": 0, "valid_bit": 0, "shift11": 0,
        "bt26": 0, "bt28": 0, "inuse_mask": 0, "clear_inuse": 0,
    }
    for begin, end in sorted(regions):
        for ins in md.disasm(img.read(begin, end - begin), img.base + begin):
            if ins.address - img.base >= end:
                break
            for op in ins.operands:
                if op.type == X86_OP_IMM:
                    v = op.imm & 0xFFFFFFFF
                elif op.type == X86_OP_MEM and op.mem.base != X86_REG_RIP:
                    v = op.mem.disp & 0xFFFFFFFF
                else:
                    continue
                if ins.mnemonic in ("bt", "bts", "btr", "btc") and \
                        op.type == X86_OP_IMM:
                    if v == 0x1A:
                        orig_counts["bt26"] += 1
                    elif v == 0x1C:
                        orig_counts["bt28"] += 1
                    continue
                if v == 0x3FF:
                    orig_counts["refcount_mask"] += 1
                elif v == 0x400:
                    orig_counts["valid_bit"] += 1
                elif v == 0x04000000:
                    orig_counts["inuse_mask"] += 1
                elif v == 0xFBFFFFFF:
                    orig_counts["clear_inuse"] += 1
            if ins.mnemonic in ("shr", "shl") and \
                    ins.operands[-1].type == X86_OP_IMM and \
                    ins.operands[-1].imm == 0x0B:
                orig_counts["shift11"] += 1

    for k in orig_counts:
        check(counts[k] == orig_counts[k],
              f"{k} changed ({orig_counts[k]} -> {counts[k]}); "
              "the 21-bit layout must retain the stock object/in-use ABI")

    # The existing cache stores valid at bit 10 and the complete index in
    # bits 11-31.  Prove the boundary values round-trip without extra state.
    for index in (0, 1, RESERVED_INDEX, INDEX_MASK):
        cached = (index << 11) | 0x400
        check(cached <= 0xFFFFFFFF and
              ((cached >> 11) & INDEX_MASK) == index and
              (cached & 0x400) != 0,
              f"stock object cache does not round-trip index {index:#x}")

    # Five-bit ages occupy raw bits 21-25; bit 26 is table-only in-use state.
    for age in (0, 1, 30, 31):
        raw = INDEX_MASK | (age << 21)
        check(raw <= 0x03FFFFFF and (raw & IN_USE_MASK) == 0 and
              (raw & INDEX_MASK) == INDEX_MASK and
              ((raw & GENERATION_MASK) >> 21) == age,
              f"21+5 raw handle algebra fails at age {age}")
    check((((31 + 1) & 31) << 21) == 0,
          "five-bit numeric age rolls 31 -> 0")

    # Pristine initialization has never issued age zero. Therefore assignment
    # 32 (reuse 31) may safely roll the numeric field 31 -> 0 and completes the
    # set of 32 distinct handles. Assignment 33 (reuse 32) would repeat age 1;
    # the mandatory guard records that attempt and does not publish it.
    published_ages: list[int] = []
    hottest_successful_reuse = 0
    prevented_repeats = 0
    published_wraps = 0
    first_prevented_reuse = None
    for prior_assignments in range(33):
        observed_age = (prior_assignments + 1) & 31
        if observed_age in published_ages:
            prevented_repeats += 1
            first_prevented_reuse = prior_assignments
            break
        published_ages.append(observed_age)
        hottest_successful_reuse = prior_assignments
    check(len(published_ages) == 32 and set(published_ages) == set(range(32)) and
          published_ages[-2:] == [31, 0] and
          hottest_successful_reuse == 31 and
          first_prevented_reuse == 32 and prevented_repeats == 1 and
          published_wraps == 0,
          "guard model must publish 32 distinct ages through safe reuse 31, "
          "then prevent repeated-generation/ABA reuse 32")

    for call_rva in assignment_patched:
        check(assignment_hook_state(get(call_rva, 5), call_rva) == "patched",
              f"mandatory assignment guard is not committed at "
              f"{img.base + call_rva:#x}")

    for p in pt["init_patches"]:
        check(get(p["rva"], p["len"]) == bytes.fromhex(p["new"]),
              f"initializer guard {img.base + p['rva']:#x} has the wrong replacement")

    # Whole-image sweep: no stock age mask may survive anywhere in .text.
    survivors = 0
    pat = (0x03F00000).to_bytes(4, "little")
    frozen_text = bytes(text)
    start = 0
    while True:
        i = frozen_text.find(pat, start)
        if i < 0:
            break
        survivors += 1
        start = i + 1
    check(survivors == 0, f"{survivors} stock age-mask literals survive somewhere in .text")

    # Instruction endpoints preserved: field edits remain one same-length
    # instruction; initializer guards consume exactly their declared window.
    for p in pt["patches"]:
        old = list(md.disasm(bytes.fromhex(p["orig"]), img.base + p["rva"]))
        new = list(md.disasm(get(p["rva"], p["len"]), img.base + p["rva"]))
        check(len(old) == len(new) == 1 and old[0].size == new[0].size == p["len"],
              f"field instruction boundary changed at {img.base + p['rva']:#x}")
    for p in pt["init_patches"]:
        dec = list(md.disasm(get(p["rva"], p["len"]), img.base + p["rva"]))
        check(sum(x.size for x in dec) == p["len"],
              f"byte patch does not end on its original boundary at {img.base + p['rva']:#x}")

    print()
    if fails:
        print(f"FAILED ({len(fails)}):")
        for f in fails[:30]:
            print("   -", f)
        return 1
    print("PASS: patched image is a coherent 21-bit/2M table encoding; bit 26 and "
          "the stock 21-bit object cache/10-bit refcount ABI remain intact; all "
          "five guard redirects are mandatory, safe reuse 31 publishes age 0, "
          "and repeated-generation/ABA reuse 32 is prevented.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
