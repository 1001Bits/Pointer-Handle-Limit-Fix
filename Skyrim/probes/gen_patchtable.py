"""Generate the Skyrim handle-cap patch table for one runtime.

Method
------
1. Byte-scan `.text` for every dword that could encode a RIP-relative `disp32`
   to the handle entry table. This is decoder independent, so it is a strict
   superset of all table references and cannot miss one.
2. Map each site to a code REGION:
     * inside a `.pdata` function -> that function's LOGICAL extent, i.e. all
       chunks rejoined through UNWIND_INFO chaining;
     * otherwise -> a region synthesised from the surrounding `int3` padding.
       Skyrim compiles seven `IsValid`-style handle validators and one
       array-destructor thunk as leaf functions with no unwind data, so this
       branch is load bearing: `.pdata` grouping alone silently misses them.
3. Disassemble every region and classify each instruction carrying a
   handle-encoding literal into a same-length field rewrite.
4. Cross-check the region set two independent ways (table reference vs.
   index-mask+age-mask co-occurrence) and byte-scan the whole of `.text` for
   the rare age-mask fingerprint, reporting anything found outside the set.
5. Emit JSON plus a C++ header.

Nothing is patched here; this only produces reviewable data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import defaultdict

import numpy as np
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_EAX,
    X86_REG_RBX,
    X86_REG_RCX,
    X86_REG_RDX,
    X86_REG_RDI,
    X86_REG_RIP,
    X86_REG_RSI,
)

from image import open_runtime
from logical_funcs import build_chunk_to_root, logical_ranges

# Same-length imm32 rewrites: old -> (new, category).  Two million entries
# consume the 21 index bits that already exist in BSHandleRefObject's public
# object-side cache.  The generation field consequently shrinks to five bits
# and moves from bits 20-25 to bits 21-25.  Bit 26 remains the in-use bit.
IMM32 = {
    0x000FFFFF: (0x001FFFFF, "index_mask"),
    0x03F00000: (0x03E00000, "age_mask"),
    0x00100000: (0x00200000, "age_inc_or_count"),
    0x01000000: (0x02000000, "table_bytes"),
    0xFC0FFFFF: (0xFC1FFFFF, "clear_age"),
    0xFFF00000: (0xFFE00000, "clear_next"),
}

# Object-side fields whose widths the raise does not change; never rewritten.
UNTOUCHED = {
    0x3FF: "refcount mask",
    0x400: "handle-valid bit",
    0x0B: "index shift",
    0x04000000: "in-use bit",
    0xFBFFFFFF: "clear in-use mask",
}

AGE_MASK_BYTES = (0x03F00000).to_bytes(4, "little")

PROFILE_METADATA = {
    "SE": {
        "table_bytes_rvas": (0x000125DD, 0x005BCCCE),
        "excluded_literals": (),
        "init_patches": (
            # C++ static initializer: zero the stock image table, then
            # construct its 1,048,576 entries.
            (0x000125E3, "e8e6973301", "9090909090",
             "disable C++ static initializer: zero 16 MiB handle table"),
            (0x0001260D, "e8c2883301", "9090909090",
             "disable C++ static initializer: construct 1,048,576 table entries"),
            # A subsequent one-shot handle-table/free-list initializer builds
            # the stock pool.
            (0x005AE243, "e868ea0000", "9090909090",
             "disable subsequent one-shot handle-table/free-list initialization"),
        ),
        "lock_write_rva": 0x00C07350,
        "unlock_write_rva": 0x00C075A0,
        "player_reservation": {
            "singleton_rva": 0x02F26EF8,
            "handle_rva": 0x02F26EF4,
            "selector_rvas": (
                0x00132012, 0x001321A2, 0x0054A8D2,
                0x005A8FA2, 0x0073D2C2,
            ),
            "object_register": "rbx",
            "release_function_rva": 0x001774E0,
            "release_hook_rva": 0x0017758F,
            "release_resume_rva": 0x00177595,
            "release_reserved_exit_rva": 0x001775D3,
            "lifecycle": {
                "creation_function_rva": 0x005B6BC0,
                "creation_constructor_call_rva": 0x005B6C3A,
                "creation_constructor_function_rva": 0x00699040,
                "creation_singleton_store_rva": 0x005B6C62,
                "creation_allocator_call_rva": 0x005B6CA8,
                "creation_handle_store_rva": 0x005B6CAF,
                "creation_formid_call_rva": 0x005B6CC7,
                "teardown_function_rva": 0x0016EA00,
                "teardown_handle_load_rva": 0x0016ED5B,
                "teardown_release_call_rva": 0x0016ED68,
                "teardown_singleton_clear_rva": 0x0016ED79,
                "teardown_zero_rvas": (0x0016ED15, 0x0016ED20),
            },
        },
    },
    "AE": {
        "table_bytes_rvas": (0x0001292D, 0x00640461),
        "excluded_literals": (),
        "init_patches": (
            # C++ static initializer: zero the stock image table, then
            # construct its 1,048,576 entries.
            (0x00012933, "e810a65201", "9090909090",
             "disable C++ static initializer: zero 16 MiB handle table"),
            (0x0001295D, "e8b28d5201", "9090909090",
             "disable C++ static initializer: construct 1,048,576 table entries"),
            # AE inlines the subsequent handle-table/free-list initializer.
            # Jump from its first store to the instruction after tail publication.
            (0x00640458, "44893d8dc1ab01", "e9560000009090",
             "skip subsequent inlined handle-table/free-list initialization"),
        ),
        "lock_write_rva": 0x00CC9140,
        "unlock_write_rva": 0x00CC9390,
        "player_reservation": {
            "singleton_rva": 0x031874F8,
            "handle_rva": 0x031874F4,
            "selector_rvas": (
                0x00178F72, 0x00179102, 0x005B9FF2,
                0x0063A052, 0x007D51D2,
            ),
            "object_register": "rdi",
            "release_function_rva": 0x001C24F0,
            "release_hook_rva": 0x001C25A1,
            "release_resume_rva": 0x001C25A7,
            "release_reserved_exit_rva": 0x001C25E3,
            "lifecycle": {
                "creation_function_rva": 0x0064A860,
                "creation_constructor_call_rva": 0x0064A8E1,
                "creation_constructor_function_rva": 0x0072CB40,
                "creation_singleton_store_rva": 0x0064A90B,
                "creation_allocator_call_rva": 0x0064A954,
                "creation_handle_store_rva": 0x0064A95B,
                "creation_formid_call_rva": 0x0064A973,
                "teardown_function_rva": 0x001B9AB0,
                "teardown_handle_load_rva": 0x001B9DEA,
                "teardown_release_call_rva": 0x001B9DF7,
                "teardown_singleton_clear_rva": 0x001B9E08,
                "teardown_zero_rvas": (0x001B9D92,),
            },
        },
    },
    "GOG": {
        "table_bytes_rvas": (0x0001292D, 0x006426C1),
        "excluded_literals": (),
        "init_patches": (
            # GOG 1.6.1179 has AE's C++ static-initializer layout but different
            # call targets.
            (0x00012933, "e870b25201", "9090909090",
             "disable C++ static initializer: zero 16 MiB handle table"),
            (0x0001295D, "e8129a5201", "9090909090",
             "disable C++ static initializer: construct 1,048,576 table entries"),
            # Its subsequent handle-table/free-list initializer is inlined
            # like AE's.
            (0x006426B8, "44893d2db3ab01", "e9560000009090",
             "skip subsequent inlined handle-table/free-list initialization"),
        ),
        "lock_write_rva": 0x00CCAC00,
        "unlock_write_rva": 0x00CCAE50,
        "player_reservation": {
            "singleton_rva": 0x03188918,
            "handle_rva": 0x03188914,
            "selector_rvas": (
                0x00178DA2, 0x00178F32, 0x005BC472,
                0x0063C2B2, 0x007D7402,
            ),
            "object_register": "rdi",
            "release_function_rva": 0x001C2320,
            "release_hook_rva": 0x001C23D1,
            "release_resume_rva": 0x001C23D7,
            "release_reserved_exit_rva": 0x001C2413,
            "lifecycle": {
                "creation_function_rva": 0x0064CAC0,
                "creation_constructor_call_rva": 0x0064CB41,
                "creation_constructor_function_rva": 0x0072ED70,
                "creation_singleton_store_rva": 0x0064CB6B,
                "creation_allocator_call_rva": 0x0064CBB4,
                "creation_handle_store_rva": 0x0064CBBB,
                "creation_formid_call_rva": 0x0064CBD3,
                "teardown_function_rva": 0x001B98E0,
                "teardown_handle_load_rva": 0x001B9C1A,
                "teardown_release_call_rva": 0x001B9C27,
                "teardown_singleton_clear_rva": 0x001B9C38,
                "teardown_zero_rvas": (0x001B9BC2,),
            },
        },
    },
    "VR": {
        "table_bytes_rvas": (0x000126ED, 0x005C512E),
        "excluded_literals": (
            # PlayerCharacter::Revert contains a real handle lookup much later
            # in the same large logical function. This unaligned store is a
            # coalesced initialization of adjacent player-state bytes, not the
            # handle-table byte extent: changing it turns the byte at +0x9BC
            # from 1 into 4.
            (0x006CB0F3, 0x01000000,
             "unrelated PlayerCharacter+0x9B9 packed-state initialization"),
        ),
        "init_patches": (
            # Skyrim VR 1.4.15 C++ static initializer for the stock image table.
            (0x000126F3, "e8e0933701", "9090909090",
             "disable C++ static initializer: zero 16 MiB handle table"),
            (0x0001271D, "e8c2843701", "9090909090",
             "disable C++ static initializer: construct 1,048,576 table entries"),
            # The subsequent one-shot handle-table/free-list initializer calls
            # the same builder shape as SE 1.5.97 (VR target RVA 0x005C5110).
            (0x005B5AC5, "e846f60000", "9090909090",
             "disable subsequent one-shot handle-table/free-list initialization"),
        ),
        "lock_write_rva": 0x00C421D0,
        "unlock_write_rva": 0x00C42420,
        "player_reservation": {
            "singleton_rva": 0x02FEB9F0,
            "handle_rva": 0x02FEB9EC,
            "selector_rvas": (
                0x001427C2, 0x00142952, 0x0054EAE2,
                0x005B0662, 0x00767E62,
            ),
            "object_register": "rbx",
            "release_function_rva": 0x001873F0,
            "release_hook_rva": 0x0018749F,
            "release_resume_rva": 0x001874A5,
            "release_reserved_exit_rva": 0x001874E3,
            "lifecycle": {
                "creation_function_rva": 0x005BEC40,
                "creation_constructor_call_rva": 0x005BECBA,
                "creation_constructor_function_rva": 0x006A26A0,
                "creation_singleton_store_rva": 0x005BECE2,
                "creation_allocator_call_rva": 0x005BED28,
                "creation_handle_store_rva": 0x005BED2F,
                "creation_formid_call_rva": 0x005BED47,
                "teardown_function_rva": 0x0017F350,
                "teardown_handle_load_rva": 0x0017F69B,
                "teardown_release_call_rva": 0x0017F6A8,
                "teardown_singleton_clear_rva": 0x0017F6B9,
                "teardown_zero_rvas": (0x0017F655, 0x0017F660),
            },
        },
    },
}


# --------------------------------------------------------------------------- #


def field_offset(ins, value: int, width: int) -> int | None:
    raw = bytes(ins.bytes)
    enc = struct.pack("<I", value & 0xFFFFFFFF) if width == 4 else bytes([value & 0xFF])
    hits = [i for i in range(len(raw) - width + 1) if raw[i : i + width] == enc]
    return hits[0] if len(hits) == 1 else None


def table_ref_sites(img, table_rva: int) -> list[int]:
    """RVAs of dword positions in .text holding a disp32 that targets the table."""
    out: set[int] = set()
    for lo, hi in img.text_ranges():
        data = np.frombuffer(img.read(lo, hi - lo), dtype=np.uint8)
        if data.size < 8:
            continue
        w = np.lib.stride_tricks.sliding_window_view(data, 4).astype(np.uint32)
        vals = w[:, 0] | (w[:, 1] << 8) | (w[:, 2] << 16) | (w[:, 3] << 24)
        pos = np.arange(vals.size, dtype=np.uint32)
        # A RIP-relative displacement is relative to the END of the whole
        # instruction, which includes any trailing immediate. `lea` has none,
        # but `mov dword [rip+d], imm32` (C7 05) has four more bytes after the
        # displacement -- testing only tail=0 would silently miss such a site.
        for tail in (0, 1, 2, 4):
            want = (np.uint32(table_rva) -
                    (np.uint32(lo) + pos + np.uint32(4 + tail))).astype(np.uint32)
            out.update(lo + int(p) for p in np.flatnonzero(vals == want))

    # Widening the search admits coincidences, and a false positive would be
    # patched as if it were a displacement -- corrupting four bytes of
    # unrelated code. So every candidate must be confirmed as a real
    # RIP-relative operand that actually resolves to the table.
    confirmed: list[int] = []
    for c in sorted(out):
        if confirm_rip(img, c, table_rva):
            confirmed.append(c)
    return confirmed


def confirm_rip(img, disp_rva: int, target_rva: int):
    """True if a real instruction has its RIP operand at disp_rva -> target.

    Decoding backwards, the shortest candidate starts one byte late and eats
    the REX prefix, so all candidates are tried and the earliest start wins.
    """
    best = None
    for back in range(2, 16):
        start = disp_rva - back
        try:
            ins_list = img.disasm(start, back + 12)
        except ValueError:
            continue
        if not ins_list:
            continue
        ins = ins_list[0]
        if ins.address - img.base != start or not (start < disp_rva < start + ins.size):
            continue
        for t in img.rip_targets(ins):
            if t == target_rva and (best is None or ins.size > best.size):
                best = ins
    return best


def byte_hits(img, pattern: bytes) -> list[int]:
    out: list[int] = []
    pat = np.frombuffer(pattern, dtype=np.uint8)
    for lo, hi in img.text_ranges():
        data = np.frombuffer(img.read(lo, hi - lo), dtype=np.uint8)
        if data.size < pat.size:
            continue
        cand = np.flatnonzero(data[: data.size - pat.size + 1] == pat[0])
        for k in range(1, pat.size):
            if cand.size == 0:
                break
            cand = cand[data[cand + k] == pat[k]]
        out.extend(lo + int(p) for p in cand)
    return out


def synth_region(img, rva: int, back: int = 0x400, fwd: int = 0x400) -> tuple[int, int]:
    """Bound a non-.pdata leaf function using the int3 padding around it."""
    pre = img.read(rva - back, back)
    start = rva - 0x40
    for i in range(back - 1, 0, -1):
        if pre[i - 1] == 0xCC and pre[i] != 0xCC:
            start = rva - back + i
            break
    post = img.read(rva, fwd)
    end = rva + 0x40
    for i in range(4, fwd - 4):
        if post[i] == 0xCC and post[i + 1] == 0xCC and post[i + 2] == 0xCC:
            end = rva + i
            break
    return start, end


# --------------------------------------------------------------------------- #
# Object-side cache publisher authentication


def reg_number(md, reg: int) -> int | None:
    """Return the architectural GPR number for a 32/64-bit register."""
    name = md.reg_name(reg)
    low32 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
    low64 = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi")
    if name in low32:
        return low32.index(name)
    if name in low64:
        return low64.index(name)
    for n in range(8, 16):
        if name in (f"r{n}d", f"r{n}"):
            return n
    return None


def reg_root(md, reg: int) -> int | None:
    """Alias-insensitive GPR identity (eax and rax both become 0)."""
    return reg_number(md, reg)


def allocation_publishers(img, regions: list[tuple[int, int]]) -> list[dict]:
    """Find and authenticate the five stock object-index publishers.

    A 21-bit physical index fits the existing object-side cache exactly, so
    these instructions remain byte-for-byte stock.  They are still the
    independent anchors used to derive the mandatory pre-publication
    assignment-guard hooks.
    """
    publishers: list[dict] = []
    for begin, end in sorted(regions):
        insns = [x for x in img.disasm(begin, end - begin)
                 if x.address - img.base < end]
        for i, shl in enumerate(insns):
            ops = shl.operands
            if not (shl.mnemonic == "shl" and len(ops) == 2 and
                    ops[0].type == X86_OP_REG and ops[0].size == 4 and
                    ops[1].type == X86_OP_IMM and ops[1].imm == 0x0B):
                continue
            if i + 1 >= len(insns):
                raise ValueError(
                    f"unterminated object-index publisher at {shl.address:#x}")
            bts = insns[i + 1]
            bo = bts.operands
            if not (bts.mnemonic == "bts" and len(bo) == 2 and
                    bo[0].type == X86_OP_REG and
                    reg_root(img.md, bo[0].reg) ==
                        reg_root(img.md, ops[0].reg) and
                    bo[1].type == X86_OP_IMM and bo[1].imm == 0x0A):
                raise ValueError(
                    f"unrecognised object-index publisher at {shl.address:#x}")

            pre = None
            for j in range(i - 1, max(-1, i - 7), -1):
                candidate = insns[j]
                candidate_ops = candidate.operands
                if (candidate.mnemonic == "and" and
                        len(candidate_ops) == 2 and
                        candidate_ops[0].type == X86_OP_MEM and
                        candidate_ops[0].size == 4 and
                        candidate_ops[0].mem.base not in (0, X86_REG_RIP) and
                        candidate_ops[0].mem.index == 0 and
                        candidate_ops[0].mem.disp in (0x08, 0x28) and
                        candidate_ops[1].type == X86_OP_IMM and
                        (candidate_ops[1].imm & 0xFFFFFFFF) == 0x3FF):
                    pre = candidate
                    break
            if pre is None:
                raise ValueError(
                    f"object-index publisher lacks its defensive clear at "
                    f"{shl.address:#x}")

            target = pre.operands[0]
            post = None
            for k in range(i + 2, min(len(insns), i + 5)):
                candidate = insns[k]
                candidate_ops = candidate.operands
                if (candidate.mnemonic == "or" and
                        len(candidate_ops) == 2 and
                        candidate_ops[0].type == X86_OP_MEM and
                        candidate_ops[1].type == X86_OP_REG and
                        reg_root(img.md, candidate_ops[1].reg) ==
                            reg_root(img.md, ops[0].reg)):
                    post = candidate_ops[0]
                    break
            if post is None or post.mem.base != target.mem.base or \
                    post.mem.disp != target.mem.disp:
                raise ValueError(
                    f"object-index publisher lacks its publish OR at "
                    f"{shl.address:#x}")
            publishers.append({
                "rva": shl.address - img.base,
                "clear_rva": pre.address - img.base,
            })

    publishers.sort(key=lambda item: item["rva"])
    if len(publishers) != 5 or \
            len({item["rva"] for item in publishers}) != 5:
        raise ValueError(
            f"expected five distinct stock object-index publishers, found "
            f"{len(publishers)}")
    return publishers


def exact_table_refs(img, disp_sites: list[int], table: int) -> list[dict]:
    out = []
    for disp in disp_sites:
        ins = confirm_rip(img, disp, table)
        if ins is None:
            raise ValueError(f"table displacement at {img.base + disp:#x} stopped decoding")
        rva = ins.address - img.base
        off = disp - rva
        if not (0 <= off <= ins.size - 4):
            raise ValueError(f"table displacement lies outside instruction at {ins.address:#x}")
        out.append({
            "rva": rva,
            "len": ins.size,
            "disp_off": off,
            "orig": bytes(ins.bytes).hex(),
            "asm": f"{ins.mnemonic} {ins.op_str}",
        })
    if len({x["rva"] for x in out}) != len(out):
        raise ValueError("more than one handle-table displacement was found in one instruction")
    return sorted(out, key=lambda x: x["rva"])


def init_guard_patches(img, runtime: str) -> list[dict]:
    out = []
    for rva, orig_hex, new_hex, description in PROFILE_METADATA[runtime]["init_patches"]:
        orig = bytes.fromhex(orig_hex)
        repl = bytes.fromhex(new_hex)
        if len(orig) != len(repl) or not (0 < len(orig) <= 15):
            raise ValueError(f"initializer guard {img.base + rva:#x} is not a same-length x64 window")
        actual = img.read(rva, len(orig))
        if actual != orig:
            raise ValueError(
                f"initializer guard {img.base + rva:#x} bytes are {actual.hex()}, "
                f"expected {orig.hex()}")
        old_insns = list(img.md.disasm(orig, img.base + rva))
        new_insns = list(img.md.disasm(repl, img.base + rva))
        if sum(x.size for x in old_insns) != len(orig) or \
                sum(x.size for x in new_insns) != len(repl):
            raise ValueError(f"initializer guard {img.base + rva:#x} splits an instruction")
        out.append({
            "rva": rva,
            "len": len(orig),
            "orig": orig.hex(),
            "new": repl.hex(),
            "cat": "init_guard",
            "asm": description,
        })
    return out


def direct_call_target(img, ins) -> int | None:
    """Return the RVA of one direct near CALL, or ``None``."""
    if ins.mnemonic != "call" or len(ins.operands) != 1 or \
            ins.operands[0].type != X86_OP_IMM:
        return None
    return ins.operands[0].imm - img.base


def assignment_hook_metadata(
        img,
        publishers: list[dict],
        lock_rva: int,
        lock_write_rva: int,
        unlock_write_rva: int,
        root_map: dict[int, int],
        logical: dict[int, list[tuple[int, int]]]) -> dict:
    """Derive the five successful handle-publication callbacks.

    Skyrim has no Starfield-style manager vtable callback.  Its reference
    table has five compiler clones of the allocator.  In every clone the one
    call immediately before object-side publication assigns the newly chosen
    ``BSHandleRefObject`` into ``Entry[index].pointer``.  Hooking these five
    calls covers successful assignments only and avoids detouring the shared
    NiPointer helper for unrelated engine traffic.

    This routine deliberately derives the sites from the independently
    authenticated stock object-side publishers and then proves their ABI and
    lock coverage from the instruction stream.  A compiler-layout change
    therefore fails generation rather than quietly emitting a guessed hook.
    """
    if len(publishers) != 5:
        raise ValueError(
            f"assignment-hook derivation expected five publishers, found "
            f"{len(publishers)}")

    rcx_root = reg_root(img.md, X86_REG_RCX)
    rdx_root = reg_root(img.md, X86_REG_RDX)
    sites: list[dict] = []
    helper_targets: set[int] = set()
    owner_roots: set[int] = set()

    def last_rcx_source(insns, call_pos: int) -> int | None:
        for j in range(call_pos - 1, max(-1, call_pos - 7), -1):
            ops = insns[j].operands
            if not ops or ops[0].type != X86_OP_REG or \
                    reg_root(img.md, ops[0].reg) != rcx_root:
                continue
            if insns[j].mnemonic == "mov" and len(ops) == 2 and \
                    ops[1].type == X86_OP_REG:
                return reg_root(img.md, ops[1].reg)
            return None
        return None

    for writer in sorted(publishers, key=lambda p: p["rva"]):
        writer_rva = writer["rva"]
        fn = img.func_containing(writer_rva)
        if fn is None:
            raise ValueError(
                f"assignment publisher {img.base + writer_rva:#x} has no pdata owner")
        root = root_map.get(fn.begin, fn.begin)
        ranges = logical.get(root, [(fn.begin, fn.end)])
        owner_fn = img.func_containing(root)
        if owner_fn is None or owner_fn.begin != root:
            raise ValueError(
                f"assignment owner {img.base + root:#x} is not a pdata function entry")
        owner_roots.add(root)

        insns = []
        for begin, end in ranges:
            insns.extend(
                x for x in img.disasm(begin, end - begin)
                if x.address - img.base < end)
        insns.sort(key=lambda x: x.address)
        positions = {x.address - img.base: i for i, x in enumerate(insns)}
        if writer_rva not in positions:
            raise ValueError(
                f"assignment publisher {img.base + writer_rva:#x} stopped decoding")
        writer_pos = positions[writer_rva]

        candidates = []
        for i in range(max(0, writer_pos - 12), writer_pos):
            target = direct_call_target(img, insns[i])
            if target is not None and writer_rva - (insns[i].address - img.base) <= 0x30:
                candidates.append((i, target))
        if len(candidates) != 1:
            raise ValueError(
                f"assignment publisher {img.base + writer_rva:#x} has "
                f"{len(candidates)} candidate pointer-assignment calls")
        call_pos, helper_rva = candidates[0]
        call = insns[call_pos]
        call_rva = call.address - img.base
        if call.size != 5 or bytes(call.bytes)[0] != 0xE8:
            raise ValueError(
                f"assignment callback {call.address:#x} is not one rel32 CALL")

        setup_rva = call_rva - 11
        setup = [
            x for x in img.disasm(setup_rva, 11)
            if x.address - img.base < call_rva
        ]
        if len(setup) != 3 or sum(x.size for x in setup) != 11 or \
                setup[-1].address + setup[-1].size != call.address:
            raise ValueError(
                f"assignment callback {call.address:#x} lacks its exact 11-byte setup")

        table_base = index_reg = object_base = None
        for x in setup:
            ops = x.operands
            if x.mnemonic == "lea" and len(ops) == 2 and \
                    ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM and \
                    ops[1].mem.index == 0:
                dst = reg_root(img.md, ops[0].reg)
                if dst == rcx_root and ops[1].mem.disp == 8:
                    table_base = reg_root(img.md, ops[1].mem.base)
                elif dst == rdx_root and ops[1].mem.disp == 0x20:
                    object_base = reg_root(img.md, ops[1].mem.base)
            elif x.mnemonic == "add" and len(ops) == 2 and \
                    ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG and \
                    reg_root(img.md, ops[0].reg) == rcx_root:
                index_reg = reg_root(img.md, ops[1].reg)
        if None in (table_base, index_reg, object_base):
            raise ValueError(
                f"assignment callback {call.address:#x} does not form "
                "RCX=&Entry[index].pointer and RDX=object+0x20")

        # The table bits store immediately before the setup must use the same
        # table-base and scaled-index registers used to form RCX.
        entry_store = None
        for x in reversed(insns[max(0, call_pos - 12):call_pos]):
            ops = x.operands
            if x.mnemonic == "mov" and len(ops) == 2 and \
                    ops[0].type == X86_OP_MEM and ops[0].size == 4 and \
                    ops[1].type == X86_OP_REG and \
                    {reg_root(img.md, ops[0].mem.base),
                     reg_root(img.md, ops[0].mem.index)} == {table_base, index_reg}:
                entry_store = x
                break
        if entry_store is None:
            raise ValueError(
                f"assignment callback {call.address:#x} is not preceded by its entry publish")

        clear_rva = writer["clear_rva"]
        clear = img.disasm(clear_rva, 15)
        if not clear or clear[0].address - img.base != clear_rva or \
                clear[0].mnemonic != "and" or \
                clear[0].operands[0].type != X86_OP_MEM or \
                reg_root(img.md, clear[0].operands[0].mem.base) != object_base or \
                not (call_rva < clear_rva < writer_rva):
            raise ValueError(
                f"assignment callback {call.address:#x} is not followed by publication "
                "to the same object")

        lock_calls = [(i, x) for i, x in enumerate(insns)
                      if direct_call_target(img, x) == lock_write_rva]
        unlock_calls = [(i, x) for i, x in enumerate(insns)
                        if direct_call_target(img, x) == unlock_write_rva]
        if len(lock_calls) != 1 or len(unlock_calls) != 1:
            raise ValueError(
                f"assignment owner {img.base + root:#x} does not have one lock bracket")
        lock_pos, lock_call = lock_calls[0]
        unlock_pos, unlock_call = unlock_calls[0]
        if not (lock_pos < call_pos < unlock_pos):
            raise ValueError(
                f"assignment callback {call.address:#x} is outside the manager lock")

        lock_refs = []
        for x in insns[:lock_pos]:
            if x.mnemonic == "lea" and lock_rva in img.rip_targets(x) and \
                    x.operands and x.operands[0].type == X86_OP_REG:
                lock_refs.append(reg_root(img.md, x.operands[0].reg))
        if len(lock_refs) != 1 or \
                last_rcx_source(insns, lock_pos) != lock_refs[0] or \
                last_rcx_source(insns, unlock_pos) != lock_refs[0]:
            raise ValueError(
                f"assignment owner {img.base + root:#x} does not lock and unlock "
                "the declared manager lock")

        helper_targets.add(helper_rva)
        sites.append({
            "call_rva": call_rva,
            "call_bytes": bytes(call.bytes).hex(),
            "call_target_rva": helper_rva,
            "setup_rva": setup_rva,
            "setup_bytes": img.read(setup_rva, 11).hex(),
            "function_rva": root,
            "function_bytes": img.read(root, 16).hex(),
            "writer_rva": writer_rva,
            "lock_call_rva": lock_call.address - img.base,
            "unlock_call_rva": unlock_call.address - img.base,
        })

    if len(owner_roots) != 5 or len(helper_targets) != 1:
        raise ValueError(
            f"assignment-hook derivation found {len(owner_roots)} owners and "
            f"{len(helper_targets)} helpers; expected five and one")

    helper_rva = next(iter(helper_targets))
    helper_fn = img.func_containing(helper_rva)
    if helper_fn is None or helper_fn.begin != helper_rva:
        raise ValueError(f"assignment helper {img.base + helper_rva:#x} lacks a pdata entry")
    helper_insns = img.disasm(helper_rva, helper_fn.end - helper_rva)
    # Prove the helper's ABI/return semantics without relying on a symbol:
    # it preserves destination in RBX, installs RDX through it, returns RBX.
    helper_text = [(x.mnemonic, x.op_str) for x in helper_insns]
    required = [
        ("mov", "rbx, rcx"),
        ("mov", "qword ptr [rbx], rdx"),
        ("mov", "rax, rbx"),
    ]
    positions = []
    for item in required:
        try:
            positions.append(helper_text.index(item))
        except ValueError as exc:
            raise ValueError(
                f"assignment helper {img.base + helper_rva:#x} ABI shape changed: "
                f"missing {item}") from exc
    if positions != sorted(positions) or not helper_insns or helper_insns[-1].mnemonic != "ret":
        raise ValueError(
            f"assignment helper {img.base + helper_rva:#x} no longer returns destination")

    return {
        "helper_rva": helper_rva,
        "helper_bytes": img.read(helper_rva, 16).hex(),
        "sites": sites,
    }


def player_lifecycle_metadata(
        img,
        runtime: str,
        singleton_rva: int,
        handle_rva: int,
        selector_owner_rva: int,
        release_function_rva: int,
        root_map: dict[int, int],
        logical: dict[int, list[tuple[int, int]]]) -> dict:
    """Prove the singleton/handle publication and teardown ordering.

    FormID 0x14 is not available when the allocator runs.  The player object
    is instead published through the singleton first, loaded into RDX for the
    allocator, and registered as FormID 0x14 only after the handle is stored.
    Teardown releases the saved raw handle before clearing that singleton.
    """
    cfg = PROFILE_METADATA[runtime]["player_reservation"]["lifecycle"]

    def owner_insns(site_rva: int):
        fn = img.func_containing(site_rva)
        if fn is None:
            raise ValueError(f"player lifecycle site {img.base + site_rva:#x} has no owner")
        root = root_map.get(fn.begin, fn.begin)
        out = []
        for begin, end in logical.get(root, [(fn.begin, fn.end)]):
            out.extend(x for x in img.disasm(begin, end - begin)
                       if x.address - img.base < end)
        out.sort(key=lambda x: x.address)
        return root, out, {x.address - img.base: x for x in out}

    creation_sites = (
        cfg["creation_constructor_call_rva"],
        cfg["creation_singleton_store_rva"],
        cfg["creation_allocator_call_rva"],
        cfg["creation_handle_store_rva"],
        cfg["creation_formid_call_rva"],
    )
    creation_root, creation, creation_by_rva = owner_insns(creation_sites[0])
    if creation_root != cfg["creation_function_rva"]:
        raise ValueError("player creation owner fingerprint RVA changed")
    if any(root_map.get(img.func_containing(rva).begin,
                        img.func_containing(rva).begin) != creation_root
           for rva in creation_sites):
        raise ValueError("player creation lifecycle sites do not share one logical owner")
    try:
        constructor_call = creation_by_rva[creation_sites[0]]
        singleton_store = creation_by_rva[creation_sites[1]]
        allocator_call = creation_by_rva[creation_sites[2]]
        handle_store = creation_by_rva[creation_sites[3]]
        formid_call = creation_by_rva[creation_sites[4]]
    except KeyError as exc:
        raise ValueError("player creation lifecycle site stopped decoding") from exc
    positions = {x.address - img.base: i for i, x in enumerate(creation)}
    ordered = [positions[rva] for rva in creation_sites]
    if ordered != sorted(ordered):
        raise ValueError("player creation lifecycle ordering changed")

    constructor_call_pos = positions[creation_sites[0]]
    constructor_setup = creation[constructor_call_pos - 1] \
        if constructor_call_pos else None
    constructor_target = cfg["creation_constructor_function_rva"]
    if constructor_setup is None or \
            (constructor_setup.mnemonic, constructor_setup.op_str) != \
                ("mov", "rcx, rax") or \
            constructor_call.size != 5 or \
            direct_call_target(img, constructor_call) != constructor_target:
        raise ValueError(
            "player creation no longer invokes its direct constructor with RCX=RAX")
    constructor_pre_hook_len = creation_sites[0] - creation_root
    constructor_pre_hook_insns = [
        ins for ins in creation
        if creation_root <= ins.address - img.base < creation_sites[0]
    ]
    if not (0 < constructor_pre_hook_len <= 256) or \
            not constructor_pre_hook_insns or \
            constructor_pre_hook_insns[0].address - img.base != creation_root or \
            constructor_pre_hook_insns[-1].address - img.base + \
                constructor_pre_hook_insns[-1].size != creation_sites[0] or \
            sum(ins.size for ins in constructor_pre_hook_insns) != \
                constructor_pre_hook_len:
        raise ValueError(
            "player constructor pre-hook owner/stack ABI window is not contiguous")
    constructor_fn = img.func_containing(constructor_target)
    if img.section_of(constructor_target) != ".text" or \
            constructor_fn is None or constructor_fn.begin != constructor_target:
        raise ValueError(
            "player constructor target is no longer an exact .text function entry")
    constructor = img.disasm(
        constructor_target, constructor_fn.end - constructor_target)
    if not constructor or constructor[-1].address - img.base + \
            constructor[-1].size != constructor_fn.end:
        raise ValueError("player constructor function stopped decoding contiguously")
    constructor_rets = [i for i, ins in enumerate(constructor)
                        if ins.mnemonic.startswith("ret")]
    captures = [i for i, ins in enumerate(constructor)
                if (ins.mnemonic, ins.op_str) == ("mov", "rsi, rcx")]
    returns = [i for i, ins in enumerate(constructor)
               if (ins.mnemonic, ins.op_str) == ("mov", "rax, rsi")]
    if len(constructor_rets) != 1 or len(captures) != 1 or len(returns) != 1 or \
            not (captures[0] < returns[0] < constructor_rets[0]):
        raise ValueError("player constructor no longer returns its RCX object in RAX")
    rsi_number = reg_root(img.md, X86_REG_RSI)
    rax_number = reg_root(img.md, X86_REG_EAX)
    for ins in constructor[captures[0] + 1:returns[0]]:
        _, writes = ins.regs_access()
        if any(reg_root(img.md, reg) == rsi_number for reg in writes):
            raise ValueError(
                f"player constructor overwrites its saved this pointer at {ins.address:#x}")
    for ins in constructor[returns[0] + 1:constructor_rets[0]]:
        _, writes = ins.regs_access()
        if any(reg_root(img.md, reg) == rax_number for reg in writes):
            raise ValueError(
                f"player constructor overwrites its RAX return at {ins.address:#x}")

    # The successful construction edge jumps over the null fallback and feeds
    # the returned object through the existing RAX-based publication flow.
    constructor_success = creation[constructor_call_pos + 1] \
        if constructor_call_pos + 1 < len(creation) else None
    if constructor_success is None or constructor_success.mnemonic != "jmp" or \
            len(constructor_success.operands) != 1 or \
            constructor_success.operands[0].type != X86_OP_IMM:
        raise ValueError("player constructor return no longer enters the creation flow")
    success_rva = constructor_success.operands[0].imm - img.base
    success_pos = positions.get(success_rva)
    singleton_pos = positions[creation_sites[1]]
    if success_pos is None or not (constructor_call_pos < success_pos < singleton_pos):
        raise ValueError("player constructor success edge no longer precedes publication")

    # Authenticate every instruction the wrapper returns through before the
    # PlayerCharacter singleton is published.  Ordinary forward branches may
    # remain inside this gap.  The one edge that skips the store is safe only
    # because it is the exact `singleton == constructor-result` edge into the
    # already-published join used by the stock post-store path.
    constructor_post_call_rva = creation_sites[0] + constructor_call.size
    constructor_post_call_len = creation_sites[1] - constructor_post_call_rva
    constructor_post_call_insns = [
        ins for ins in creation
        if constructor_post_call_rva <= ins.address - img.base < creation_sites[1]
    ]
    if not (0 < constructor_post_call_len <= 64) or \
            not constructor_post_call_insns or \
            constructor_post_call_insns[0].address - img.base != \
                constructor_post_call_rva or \
            constructor_post_call_insns[-1].address - img.base + \
                constructor_post_call_insns[-1].size != creation_sites[1] or \
            sum(ins.size for ins in constructor_post_call_insns) != \
                constructor_post_call_len:
        raise ValueError(
            "player constructor post-call publication window is not contiguous")

    rcx_number = reg_root(img.md, X86_REG_RCX)
    equality_edges = []
    for index in range(len(constructor_post_call_insns) - 2):
        singleton_load, compare, branch = \
            constructor_post_call_insns[index:index + 3]
        if singleton_load.mnemonic != "mov" or \
                len(singleton_load.operands) != 2 or \
                singleton_load.operands[0].type != X86_OP_REG or \
                reg_root(img.md, singleton_load.operands[0].reg) != rcx_number or \
                singleton_load.operands[1].type != X86_OP_MEM or \
                img.rip_targets(singleton_load) != [singleton_rva] or \
                compare.mnemonic != "cmp" or len(compare.operands) != 2 or \
                compare.operands[0].type != X86_OP_REG or \
                compare.operands[1].type != X86_OP_REG or \
                reg_root(img.md, compare.operands[0].reg) != rcx_number or \
                reg_root(img.md, compare.operands[1].reg) != rax_number or \
                branch.mnemonic not in ("je", "jz") or \
                len(branch.operands) != 1 or \
                branch.operands[0].type != X86_OP_IMM:
            continue
        equality_edges.append(branch)
    if len(equality_edges) != 1:
        raise ValueError(
            "player constructor publication gap lost its unique singleton==RAX edge")
    equality_edge = equality_edges[0]
    published_join_rva = equality_edge.operands[0].imm - img.base
    singleton_end_rva = creation_sites[1] + singleton_store.size
    if published_join_rva not in positions or \
            not (singleton_end_rva < published_join_rva < creation_sites[2]):
        raise ValueError(
            "player constructor singleton-equality edge no longer joins post-publication")
    post_store_join_edges = []
    for ins in creation[singleton_pos + 1:positions[creation_sites[2]]]:
        if ins.mnemonic in ("jmp", "ljmp") or \
                not ins.mnemonic.startswith("j") or \
                len(ins.operands) != 1 or ins.operands[0].type != X86_OP_IMM:
            continue
        if ins.operands[0].imm - img.base == published_join_rva:
            post_store_join_edges.append(ins)
    if not post_store_join_edges:
        raise ValueError(
            "player constructor equality edge lost the stock post-store join")

    exceptional_control = {
        "loop", "loope", "loopne", "jecxz", "jrcxz",
        "syscall", "sysenter", "sysret", "sysexit",
        "int", "int1", "int3", "into", "iret", "iretd", "iretq",
    }
    for ins in constructor_post_call_insns:
        rva = ins.address - img.base
        if ins.mnemonic.startswith("call") or ins.mnemonic.startswith("ret") or \
                ins.mnemonic in exceptional_control:
            raise ValueError(
                f"player constructor publication gap transfers control at {ins.address:#x}")
        if not ins.mnemonic.startswith("j"):
            continue
        if len(ins.operands) != 1 or ins.operands[0].type != X86_OP_IMM:
            raise ValueError(
                f"player constructor publication gap has indirect branch at {ins.address:#x}")
        target_rva = ins.operands[0].imm - img.base
        if target_rva <= rva:
            raise ValueError(
                f"player constructor publication gap has a backward edge at {ins.address:#x}")
        if constructor_post_call_rva <= target_rva <= creation_sites[1]:
            continue
        if ins.address == equality_edge.address and \
                target_rva == published_join_rva:
            continue
        raise ValueError(
            f"player constructor publication gap escapes before publication at "
            f"{ins.address:#x}")

    for ins in creation[success_pos:singleton_pos]:
        _, writes = ins.regs_access()
        if any(reg_root(img.md, reg) == rax_number for reg in writes):
            raise ValueError(
                f"player creation overwrites the constructor result at {ins.address:#x}")
    if singleton_store.mnemonic != "mov" or len(singleton_store.operands) != 2 or \
            singleton_store.operands[0].type != X86_OP_MEM or \
            singleton_store.operands[1].type != X86_OP_REG or \
            reg_root(img.md, singleton_store.operands[1].reg) != rax_number or \
            img.rip_targets(singleton_store) != [singleton_rva]:
        raise ValueError("player singleton is no longer published before allocation")
    if allocator_call.size != 5 or direct_call_target(img, allocator_call) != \
            selector_owner_rva:
        raise ValueError("player creation no longer calls the verified allocator clone")
    call_pos = positions[creation_sites[2]]
    candidate_loads = [x for x in creation[max(0, call_pos - 4):call_pos]
                       if x.mnemonic == "mov" and len(x.operands) == 2 and
                       x.operands[0].type == X86_OP_REG and
                       reg_root(img.md, x.operands[0].reg) ==
                           reg_root(img.md, X86_REG_RDX) and
                       x.operands[1].type == X86_OP_MEM and
                       img.rip_targets(x) == [singleton_rva]]
    if len(candidate_loads) != 1 or \
            creation.index(candidate_loads[0]) != call_pos - 2:
        raise ValueError("player allocator candidate is no longer loaded from the singleton")
    candidate_load = candidate_loads[0]
    if handle_store.mnemonic != "mov" or len(handle_store.operands) != 2 or \
            handle_store.operands[0].type != X86_OP_MEM or \
            img.rip_targets(handle_store) != [handle_rva]:
        raise ValueError("player raw handle is no longer stored after allocation")
    formid_pos = positions[creation_sites[4]]
    formid_setup = creation[formid_pos - 1] if formid_pos else None
    if formid_setup is None or \
            (formid_setup.mnemonic, formid_setup.op_str) != ("mov", "edx, 0x14") or \
            formid_call.mnemonic != "call" or len(formid_call.operands) != 1 or \
            formid_call.operands[0].type != X86_OP_MEM or \
            formid_call.operands[0].mem.disp != 0x1C0:
        raise ValueError("player FormID 0x14 registration is no longer after handle publication")

    teardown_sites = (
        cfg["teardown_handle_load_rva"],
        cfg["teardown_release_call_rva"],
        cfg["teardown_singleton_clear_rva"],
    )
    teardown_root, teardown, teardown_by_rva = owner_insns(teardown_sites[0])
    if teardown_root != cfg["teardown_function_rva"]:
        raise ValueError("player teardown owner fingerprint RVA changed")
    if any(root_map.get(img.func_containing(rva).begin,
                        img.func_containing(rva).begin) != teardown_root
           for rva in teardown_sites):
        raise ValueError("player teardown lifecycle sites do not share one logical owner")
    try:
        handle_load = teardown_by_rva[teardown_sites[0]]
        release_call = teardown_by_rva[teardown_sites[1]]
        singleton_clear = teardown_by_rva[teardown_sites[2]]
    except KeyError as exc:
        raise ValueError("player teardown lifecycle site stopped decoding") from exc
    teardown_positions = {x.address - img.base: i for i, x in enumerate(teardown)}
    teardown_order = [teardown_positions[rva] for rva in teardown_sites]
    if teardown_order != sorted(teardown_order):
        raise ValueError("player teardown no longer releases before singleton clear")
    if handle_load.mnemonic != "mov" or len(handle_load.operands) != 2 or \
            handle_load.operands[0].type != X86_OP_REG or \
            reg_root(img.md, handle_load.operands[0].reg) != \
                reg_root(img.md, X86_REG_EAX) or \
            handle_load.operands[1].type != X86_OP_MEM or \
            img.rip_targets(handle_load) != [handle_rva]:
        raise ValueError("player teardown no longer loads the saved raw handle")
    if release_call.size != 5 or direct_call_target(img, release_call) != \
            release_function_rva:
        raise ValueError("player teardown no longer calls canonical handle release")
    if singleton_clear.mnemonic != "mov" or len(singleton_clear.operands) != 2 or \
            singleton_clear.operands[0].type != X86_OP_MEM or \
            singleton_clear.operands[1].type != X86_OP_REG or \
            img.rip_targets(singleton_clear) != [singleton_rva]:
        raise ValueError("player teardown no longer clears the singleton")
    clear_register = reg_root(img.md, singleton_clear.operands[1].reg)
    zero_insns = []
    for rva in cfg["teardown_zero_rvas"]:
        zero = teardown_by_rva.get(rva)
        if zero is None or zero.mnemonic != "xor" or len(zero.operands) != 2 or \
                zero.operands[0].type != X86_OP_REG or \
                zero.operands[1].type != X86_OP_REG or \
                reg_root(img.md, zero.operands[0].reg) != clear_register or \
                reg_root(img.md, zero.operands[1].reg) != clear_register:
            raise ValueError("player singleton clear source is no longer proven zero")
        zero_insns.append(zero)
    first_zero = min(teardown_positions[x.address - img.base] for x in zero_insns)
    clear_pos = teardown_positions[teardown_sites[2]]
    for x in teardown[first_zero:clear_pos]:
        if x in zero_insns or not x.operands or x.operands[0].type != X86_OP_REG:
            continue
        if reg_root(img.md, x.operands[0].reg) == clear_register:
            raise ValueError(
                f"player singleton zero register is overwritten at {x.address:#x}")

    def record(ins) -> dict:
        return {
            "rva": ins.address - img.base,
            "bytes": bytes(ins.bytes).hex(),
        }

    return {
        "creation": {
            "function_rva": creation_root,
            "function_bytes": img.read(creation_root, 16).hex(),
            "constructor_function_rva": constructor_target,
            "constructor_function_bytes": img.read(constructor_target, 16).hex(),
            "constructor_call": record(constructor_call),
            "constructor_pre_hook_rva": creation_root,
            "constructor_pre_hook_bytes": img.read(
                creation_root, constructor_pre_hook_len).hex(),
            "constructor_post_call_rva": constructor_post_call_rva,
            "constructor_post_call_bytes": img.read(
                constructor_post_call_rva, constructor_post_call_len).hex(),
            "singleton_store": record(singleton_store),
            "candidate_load": record(candidate_load),
            "allocator_call": record(allocator_call),
            "handle_store": record(handle_store),
            "formid_setup": record(formid_setup),
            "formid_call": record(formid_call),
        },
        "teardown": {
            "function_rva": teardown_root,
            "function_bytes": img.read(teardown_root, 16).hex(),
            "handle_load": record(handle_load),
            "release_call": record(release_call),
            "zero_sources": [record(x) for x in zero_insns],
            "singleton_clear": record(singleton_clear),
        },
    }


def player_reservation_metadata(
        img,
        runtime: str,
        table_rva: int,
        head_rva: int,
        tail_rva: int,
        lock_rva: int,
        root_map: dict[int, int],
        logical: dict[int, list[tuple[int, int]]]) -> dict:
    """Verify and emit the player-slot selector and release quarantine ABI.

    The stock allocator exists as five compiler clones.  Their first free-head
    load is the earliest point after the manager lock and the existing-handle
    recheck where a reserved node can safely be selected.  The canonical
    release routine is intercepted only after it has invalidated the entry and
    released the pointed object, but before it appends the index to the FIFO.

    Every executable assumption used by the relays is proved here and emitted
    with byte fingerprints.  A runtime layout change must therefore fail
    generation/preflight instead of installing a guessed hook.
    """
    cfg = PROFILE_METADATA[runtime]["player_reservation"]
    singleton_rva = cfg["singleton_rva"]
    handle_rva = cfg["handle_rva"]
    if handle_rva + 4 != singleton_rva:
        raise ValueError("player handle and singleton globals are no longer adjacent")
    if img.section_of(handle_rva) is None or img.section_of(singleton_rva) is None:
        raise ValueError("player handle/singleton metadata is outside the image")

    object_name = cfg["object_register"]
    object_reg = {"rbx": X86_REG_RBX, "rdi": X86_REG_RDI}.get(object_name)
    if object_reg is None:
        raise ValueError(f"unsupported player selector object register {object_name!r}")
    object_number = reg_root(img.md, object_reg)
    eax_number = reg_root(img.md, X86_REG_EAX)
    rdx_number = reg_root(img.md, X86_REG_RDX)

    selectors: list[dict] = []
    owners: set[int] = set()
    for hook_rva in cfg["selector_rvas"]:
        decoded = img.disasm(hook_rva, 6)
        if len(decoded) != 1 or decoded[0].size != 6:
            raise ValueError(
                f"player selector {img.base + hook_rva:#x} is not one six-byte instruction")
        hook = decoded[0]
        ops = hook.operands
        if hook.mnemonic != "mov" or len(ops) != 2 or \
                ops[0].type != X86_OP_REG or \
                reg_root(img.md, ops[0].reg) != eax_number or \
                ops[1].type != X86_OP_MEM or ops[1].mem.base != X86_REG_RIP or \
                img.rip_targets(hook) != [head_rva]:
            raise ValueError(
                f"player selector {hook.address:#x} is no longer MOV EAX,[free-head]")

        fn = img.func_containing(hook_rva)
        if fn is None:
            raise ValueError(f"player selector {hook.address:#x} has no pdata owner")
        owner = root_map.get(fn.begin, fn.begin)
        owner_fn = img.func_containing(owner)
        if owner_fn is None or owner_fn.begin != owner:
            raise ValueError(f"player selector owner {img.base + owner:#x} is invalid")
        if hook_rva - owner != 0xB2:
            raise ValueError(
                f"player selector {hook.address:#x} moved within owner {img.base + owner:#x}")
        owners.add(owner)

        insns = []
        for begin, end in logical.get(owner, [(fn.begin, fn.end)]):
            insns.extend(x for x in img.disasm(begin, end - begin)
                         if x.address - img.base < end)
        insns.sort(key=lambda x: x.address)
        hook_pos = next((i for i, x in enumerate(insns)
                         if x.address - img.base == hook_rva), None)
        if hook_pos is None:
            raise ValueError(f"player selector {hook.address:#x} stopped decoding in owner")

        object_setup = None
        for x in insns[:hook_pos]:
            xops = x.operands
            if x.mnemonic == "mov" and x.size == 3 and len(xops) == 2 and \
                    xops[0].type == X86_OP_REG and xops[1].type == X86_OP_REG and \
                    reg_root(img.md, xops[0].reg) == object_number and \
                    reg_root(img.md, xops[1].reg) == rdx_number:
                object_setup = x
                break
        if object_setup is None or object_setup.address - img.base != owner + 0x1E:
            raise ValueError(
                f"player selector owner {img.base + owner:#x} no longer preserves "
                f"candidate in {object_name.upper()}")

        lock_calls = [(i, x) for i, x in enumerate(insns)
                      if direct_call_target(img, x) ==
                      PROFILE_METADATA[runtime]["lock_write_rva"]]
        unlock_calls = [(i, x) for i, x in enumerate(insns)
                        if direct_call_target(img, x) ==
                        PROFILE_METADATA[runtime]["unlock_write_rva"]]
        if len(lock_calls) != 1 or len(unlock_calls) != 1 or \
                not (lock_calls[0][0] < hook_pos < unlock_calls[0][0]):
            raise ValueError(
                f"player selector {hook.address:#x} is not inside one manager lock bracket")
        lock_call, unlock_call = lock_calls[0][1], unlock_calls[0][1]
        if lock_call.size != 5 or unlock_call.size != 5:
            raise ValueError("player selector lock bracket is not rel32-call based")

        # The hook becomes CALL relay.  A non-player relay is a leaf; an exact
        # singleton match tail-jumps to a normal C++ helper, which returns
        # through the hook CALL's return address and uses the stock owner's
        # outgoing shadow space.  Prove that space from the exact prologue and
        # prove every helper-clobbered volatile/flag is dead on every
        # continuation path before emitting the fingerprint used at runtime.
        owner_prefix = img.read(owner, 16)
        reviewed_prologue = bytes.fromhex("41564883ec3048c7442420feffffff")
        if owner_prefix[:len(reviewed_prologue)] != reviewed_prologue:
            raise ValueError(
                f"player selector owner {img.base + owner:#x} no longer has "
                "the reviewed nonvolatile save and outgoing shadow-space frame")
        stack_allocation = owner_prefix[5]
        for prologue_ins in insns[:hook_pos]:
            if prologue_ins.mnemonic == "call":
                continue
            _, prologue_writes = prologue_ins.regs_access()
            written_names = {
                img.md.reg_name(reg).lower() for reg in prologue_writes
            }
            if prologue_ins.address - img.base > owner + 5 and \
                    ("rsp" in written_names or
                     prologue_ins.mnemonic in ("push", "pop", "enter", "leave")):
                raise ValueError(
                    f"player selector owner changes RSP again before hook at "
                    f"{prologue_ins.address:#x}")
        continuation_rva = hook_rva + hook.size
        continuation = next((x for x in insns
                             if x.address - img.base == continuation_rva), None)
        if continuation is None or \
                (continuation.mnemonic, continuation.op_str) != ("cmp", "eax, -1"):
            raise ValueError(
                f"player selector {hook.address:#x} no longer kills relay flags "
                "with CMP EAX,-1 at its continuation")

        aliases = {
            "rcx": {"rcx", "ecx", "cx", "ch", "cl"},
            "rdx": {"rdx", "edx", "dx", "dh", "dl"},
            "r8": {"r8", "r8d", "r8w", "r8b"},
            "r9": {"r9", "r9d", "r9w", "r9b"},
            "r10": {"r10", "r10d", "r10w", "r10b"},
            "r11": {"r11", "r11d", "r11w", "r11b"},
            "flags": {"eflags", "rflags"},
        }
        for xmm in range(6):
            aliases[f"xmm{xmm}"] = {
                f"xmm{xmm}", f"ymm{xmm}", f"zmm{xmm}"
            }
        full_writes = {
            "rcx": {"rcx", "ecx"}, "rdx": {"rdx", "edx"},
            "r8": {"r8", "r8d"}, "r9": {"r9", "r9d"},
            "r10": {"r10", "r10d"}, "r11": {"r11", "r11d"},
            "flags": {"eflags", "rflags"},
        }
        for xmm in range(6):
            full_writes[f"xmm{xmm}"] = {
                f"xmm{xmm}", f"ymm{xmm}", f"zmm{xmm}"
            }

        def roots_for(regs, table):
            names = {img.md.reg_name(reg).lower() for reg in regs}
            return {root for root, choices in table.items()
                    if names & choices}

        by_address = {x.address: x for x in insns}
        assignment_argument_roots = {"rcx", "rdx"}
        if runtime in ("AE", "GOG"):
            assignment_argument_roots.add("r8")
        initial_dirty = frozenset(aliases)
        pending = [(img.base + continuation_rva, initial_dirty)]
        seen = set()
        while pending:
            address, frozen_dirty = pending.pop()
            state = (address, frozen_dirty)
            if state in seen:
                continue
            seen.add(state)
            dirty = set(frozen_dirty)
            ins = by_address.get(address)
            if ins is None:
                raise ValueError(
                    f"player selector continuation escapes decoded owner at {address:#x}")
            reads, writes = ins.regs_access()
            read_roots = roots_for(reads, aliases)
            write_roots = roots_for(writes, full_writes)
            # Capstone reports XOR reg,reg as a read; architecturally it is a
            # self-contained full definition and does not consume the old value.
            if ins.mnemonic in ("xor", "pxor", "xorps", "xorpd") and \
                    len(ins.operands) >= 2 and \
                    ins.operands[0].type == X86_OP_REG and \
                    ins.operands[1].type == X86_OP_REG and \
                    ins.operands[0].reg == ins.operands[1].reg:
                read_roots -= write_roots
            if read_roots & dirty:
                raise ValueError(
                    f"player selector continuation reads helper-clobbered "
                    f"{sorted(read_roots & dirty)} at {ins.address:#x}")
            dirty -= write_roots

            target = direct_call_target(img, ins)
            if ins.mnemonic == "call":
                required_clean = {"rcx"} if target == \
                    PROFILE_METADATA[runtime]["unlock_write_rva"] else \
                    assignment_argument_roots
                if dirty & required_clean:
                    raise ValueError(
                        f"player selector continuation call at {ins.address:#x} "
                        f"would consume helper-clobbered "
                        f"{sorted(dirty & required_clean)}")
                # Any remaining dirty values are neither arguments nor read
                # by this path; the call itself may freely clobber them.
                continue
            if ins.mnemonic.startswith("ret"):
                continue

            successors = []
            if ins.mnemonic == "jmp":
                if not ins.operands or ins.operands[0].type != X86_OP_IMM:
                    raise ValueError("indirect jump in player selector continuation")
                successors.append(ins.operands[0].imm)
            elif ins.mnemonic.startswith("j"):
                if not ins.operands or ins.operands[0].type != X86_OP_IMM:
                    raise ValueError("indirect branch in player selector continuation")
                successors.extend((ins.operands[0].imm, ins.address + ins.size))
            else:
                successors.append(ins.address + ins.size)
            pending.extend((successor, frozenset(dirty))
                           for successor in successors)

        continuation_len = owner_fn.end - continuation_rva
        if not (0 < continuation_len <= 256):
            raise ValueError("player selector continuation fingerprint is too wide")

        selectors.append({
            "hook_rva": hook_rva,
            "hook_bytes": bytes(hook.bytes).hex(),
            "function_rva": owner,
            "function_bytes": img.read(owner, 16).hex(),
            "object_register": object_name,
            "object_setup_rva": object_setup.address - img.base,
            "object_setup_bytes": bytes(object_setup.bytes).hex(),
            "lock_call_rva": lock_call.address - img.base,
            "lock_call_bytes": bytes(lock_call.bytes).hex(),
            "unlock_call_rva": unlock_call.address - img.base,
            "unlock_call_bytes": bytes(unlock_call.bytes).hex(),
            "stack_allocation": stack_allocation,
            "pre_hook_rva": owner,
            "pre_hook_bytes": img.read(owner, hook_rva - owner).hex(),
            "continuation_rva": continuation_rva,
            "continuation_bytes": img.read(
                continuation_rva, continuation_len).hex(),
        })

    if len(selectors) != 5 or len(owners) != 5:
        raise ValueError(
            f"player reservation expected five selector owners, got {len(owners)}")

    release_function_rva = cfg["release_function_rva"]
    release_hook_rva = cfg["release_hook_rva"]
    release_resume_rva = cfg["release_resume_rva"]
    release_exit_rva = cfg["release_reserved_exit_rva"]
    release_fn = img.func_containing(release_hook_rva)
    if release_fn is None or release_fn.begin != release_function_rva:
        raise ValueError("canonical player release hook lost its declared pdata owner")
    release_insns = img.disasm(
        release_function_rva, release_fn.end - release_function_rva)
    release_by_rva = {x.address - img.base: x for x in release_insns}
    release_hook = release_by_rva.get(release_hook_rva)
    if release_hook is None or release_hook.size != 6 or \
            release_hook.mnemonic != "mov" or \
            len(release_hook.operands) != 2 or \
            release_hook.operands[0].type != X86_OP_REG or \
            reg_root(img.md, release_hook.operands[0].reg) != eax_number or \
            release_hook.operands[1].type != X86_OP_MEM or \
            release_hook.operands[1].mem.base != X86_REG_RIP or \
            img.rip_targets(release_hook) != [tail_rva]:
        raise ValueError("canonical release hook is no longer MOV EAX,[free-tail]")
    resume = release_by_rva.get(release_resume_rva)
    if release_resume_rva != release_hook_rva + 6 or resume is None or \
            resume.mnemonic != "cmp" or resume.op_str != "eax, -1":
        raise ValueError("canonical release ordinary continuation is no longer CMP EAX,-1")
    exit_mov = release_by_rva.get(release_exit_rva)
    exit_pos = next((i for i, x in enumerate(release_insns)
                     if x.address - img.base == release_exit_rva), None)
    if exit_pos is None or exit_mov is None or \
            (exit_mov.mnemonic, exit_mov.op_str) != ("mov", "rcx, rsi") or \
            exit_pos + 1 >= len(release_insns):
        raise ValueError("canonical release reserved exit no longer prepares the manager unlock")
    release_unlock = release_insns[exit_pos + 1]
    if release_unlock.size != 5 or direct_call_target(img, release_unlock) != \
            PROFILE_METADATA[runtime]["unlock_write_rva"]:
        raise ValueError("canonical release reserved exit no longer calls manager unlock")

    # Prove the register ABI consumed by the tiny no-call release relay.
    release_text = [(x.mnemonic, x.op_str) for x in release_insns]
    required = [
        ("mov", "edi, edx"),
        ("mov", "ebx, edi"),
        ("shl", "rbx, 4"),
        ("add", "rbx, rbp"),
    ]
    positions = []
    for item in required:
        try:
            positions.append(release_text.index(item))
        except ValueError as exc:
            raise ValueError(
                f"canonical release ABI changed: missing {item}") from exc
    if positions != sorted(positions) or positions[-1] >= release_insns.index(release_hook):
        raise ValueError("canonical release index/entry setup no longer precedes the hook")
    table_loads = [x for x in release_insns[:positions[-1] + 1]
                   if x.mnemonic == "lea" and x.op_str.startswith("rbp, ") and
                   img.rip_targets(x) == [table_rva]]
    lock_loads = [x for x in release_insns[:positions[0]]
                  if x.mnemonic == "lea" and x.op_str.startswith("rsi, ") and
                  img.rip_targets(x) == [lock_rva]]
    if len(table_loads) != 1 or len(lock_loads) != 1:
        raise ValueError("canonical release no longer establishes RBP=table and RSI=lock")

    # The release hook becomes CALL relay.  For the reserved index the relay
    # quarantines the original RBX entry, substitutes EDI=oldTail, and points
    # RBX either at that old-tail entry or at permanent writable scratch.  The
    # following stock FIFO block must therefore be the reviewed self-link
    # no-op and the owner must restore RBX/RDI before returning.
    resume_pos = release_insns.index(resume)
    tail_code = release_insns[resume_pos:]
    epilogue = [
        "rbx, qword ptr [rsp + 0x48]",
        "rbp, qword ptr [rsp + 0x50]",
        "rsi, qword ptr [rsp + 0x58]",
        "rsp, 0x30", "rdi", "",
    ]
    if runtime in ("SE", "VR"):
        wanted_core = [
            "cmp", "jne", "mov", "jmp", "mov", "shl", "add", "and",
            "mov", "and", "or", "and", "mov", "and", "or", "mov",
            "mov", "call", "nop", "mov", "mov", "mov", "add", "pop", "ret",
        ]
        good_tail = [x.mnemonic for x in tail_code] == wanted_core and \
            tail_code[0].op_str == "eax, -1" and \
            tail_code[2].op_str.split(", ")[-1] == "edi" and \
            img.rip_targets(tail_code[2]) == [head_rva] and \
            tail_code[4].op_str.split(", ")[0] == "edx" and \
            img.rip_targets(tail_code[4]) == [tail_rva] and \
            tail_code[5].op_str == "rdx, 4" and \
            tail_code[6].op_str == "rdx, rbp" and \
            tail_code[7].op_str == "dword ptr [rdx], 0xfff00000" and \
            tail_code[8].op_str == "eax, edi" and \
            tail_code[9].op_str == "eax, 0xfffff" and \
            tail_code[10].op_str == "dword ptr [rdx], eax" and \
            tail_code[11].op_str == "dword ptr [rbx], 0xfff00000" and \
            tail_code[12].op_str == "eax, edi" and \
            tail_code[13].op_str == "eax, 0xfffff" and \
            tail_code[14].op_str == "dword ptr [rbx], eax" and \
            tail_code[15].op_str.split(", ")[-1] == "edi" and \
            img.rip_targets(tail_code[15]) == [tail_rva] and \
            tail_code[16] is exit_mov and tail_code[17] is release_unlock and \
            [x.op_str for x in tail_code[19:]] == epilogue and \
            tail_code[1].operands[0].imm == tail_code[4].address and \
            tail_code[3].operands[0].imm == tail_code[11].address
    else:
        wanted_core = [
            "cmp", "mov", "jne", "mov", "and", "jmp", "mov", "shl",
            "add", "and", "and", "or", "and", "or", "mov", "mov",
            "call", "nop", "mov", "mov", "mov", "add", "pop", "ret",
        ]
        good_tail = [x.mnemonic for x in tail_code] == wanted_core and \
            tail_code[0].op_str == "eax, -1" and \
            tail_code[1].op_str == "eax, edi" and \
            tail_code[3].op_str.split(", ")[-1] == "edi" and \
            img.rip_targets(tail_code[3]) == [head_rva] and \
            tail_code[4].op_str == "eax, 0xfffff" and \
            tail_code[6].op_str.split(", ")[0] == "edx" and \
            img.rip_targets(tail_code[6]) == [tail_rva] and \
            tail_code[7].op_str == "rdx, 4" and \
            tail_code[8].op_str == "rdx, rbp" and \
            tail_code[9].op_str == "eax, 0xfffff" and \
            tail_code[10].op_str == "dword ptr [rdx], 0xfff00000" and \
            tail_code[11].op_str == "dword ptr [rdx], eax" and \
            tail_code[12].op_str == "dword ptr [rbx], 0xfff00000" and \
            tail_code[13].op_str == "dword ptr [rbx], eax" and \
            tail_code[14].op_str.split(", ")[-1] == "edi" and \
            img.rip_targets(tail_code[14]) == [tail_rva] and \
            tail_code[15] is exit_mov and tail_code[16] is release_unlock and \
            [x.op_str for x in tail_code[18:]] == epilogue and \
            tail_code[2].operands[0].imm == tail_code[6].address and \
            tail_code[5].operands[0].imm == tail_code[12].address
    if not good_tail:
        raise ValueError("canonical release CALL-relay no-op assumptions changed")
    release_continuation_len = release_fn.end - release_resume_rva
    if not (0 < release_continuation_len <= 128):
        raise ValueError("canonical release continuation fingerprint is too wide")

    lifecycle = player_lifecycle_metadata(
        img, runtime, singleton_rva, handle_rva,
        selectors[0]["function_rva"], release_function_rva,
        root_map, logical)

    return {
        "singleton_rva": singleton_rva,
        "handle_rva": handle_rva,
        "selectors": selectors,
        "release": {
            "function_rva": release_function_rva,
            "function_bytes": img.read(release_function_rva, 16).hex(),
            "hook_rva": release_hook_rva,
            "hook_bytes": bytes(release_hook.bytes).hex(),
            "pre_hook_rva": release_function_rva,
            "pre_hook_bytes": img.read(
                release_function_rva,
                release_hook_rva - release_function_rva).hex(),
            "resume_rva": release_resume_rva,
            "reserved_exit_rva": release_exit_rva,
            "unlock_call_rva": release_unlock.address - img.base,
            "unlock_call_bytes": bytes(release_unlock.bytes).hex(),
            "continuation_rva": release_resume_rva,
            "continuation_bytes": img.read(
                release_resume_rva, release_continuation_len).hex(),
        },
        "lifecycle": lifecycle,
    }


# --------------------------------------------------------------------------- #


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", required=True)
    ap.add_argument("--table", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--tail", required=True)
    ap.add_argument("--lock", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    img, _ = open_runtime(a.runtime)
    table = int(a.table, 16)
    head, tail, lock = int(a.head, 16), int(a.tail, 16), int(a.lock, 16)

    root_map = build_chunk_to_root(img)
    lranges = logical_ranges(img, root_map)

    # ---- 1/2. table references -> regions -------------------------------- #
    disp_sites = table_ref_sites(img, table)
    regions: set[tuple[int, int]] = set()
    n_pdata = n_leaf = 0
    leaf_starts = []
    for d in disp_sites:
        fn = img.func_containing(d)
        if fn is not None:
            n_pdata += 1
            for r in lranges.get(root_map.get(fn.begin, fn.begin), [(fn.begin, fn.end)]):
                regions.add(r)
        else:
            n_leaf += 1
            r = synth_region(img, d)
            regions.add(r)
            leaf_starts.append(r[0])

    print(f"table disp32 sites: {len(disp_sites)}  (in .pdata: {n_pdata}, leaf/thunk: {n_leaf})")
    print(f"code regions to patch: {len(regions)}")
    for s in sorted(set(leaf_starts)):
        print(f"  leaf region at {img.base + s:#x}")

    # ---- 3. classify field rewrites -------------------------------------- #
    covered: set[int] = set()
    patches: list[dict] = []
    per_cat: dict[str, int] = defaultdict(int)
    untouched_seen: dict[int, int] = defaultdict(int)
    excluded_literal_sites: list[dict] = []
    expected_table_bytes = set(PROFILE_METADATA[a.runtime]["table_bytes_rvas"])
    expected_exclusions = {
        (rva, value): reason
        for rva, value, reason in PROFILE_METADATA[a.runtime]["excluded_literals"]
    }
    seen_exclusions: set[tuple[int, int]] = set()

    for begin, end in sorted(regions):
        for ins in img.disasm(begin, end - begin):
            rva = ins.address - img.base
            if rva >= end:
                break
            covered.add(rva)
            for op in ins.operands:
                # The age increment appears as a memory DISPLACEMENT
                # (`lea ecx, [rax + 0x100000]`), not an immediate, so both
                # operand kinds have to be classified or the increment is
                # silently left at its stock value.
                if op.type == X86_OP_IMM:
                    v = op.imm & 0xFFFFFFFF
                elif op.type == X86_OP_MEM and op.mem.base != X86_REG_RIP and op.mem.disp:
                    v = op.mem.disp & 0xFFFFFFFF
                else:
                    continue
                if v in IMM32:
                    new, cat, w = IMM32[v][0], IMM32[v][1], 4
                else:
                    if v in UNTOUCHED:
                        untouched_seen[v] += 1
                    continue
                if cat == "table_bytes" and rva not in expected_table_bytes:
                    key = (rva, v)
                    if key not in expected_exclusions:
                        raise ValueError(
                            f"unreviewed table-bytes-shaped literal at {ins.address:#x}: "
                            f"{ins.mnemonic} {ins.op_str}")
                    excluded_literal_sites.append({
                        "rva": rva,
                        "value": v,
                        "cat": cat,
                        "asm": f"{ins.mnemonic} {ins.op_str}",
                        "why": expected_exclusions[key],
                    })
                    seen_exclusions.add(key)
                    continue
                off = field_offset(ins, v, w)
                if off is None:
                    print(f"  !! AMBIGUOUS field at {img.base + rva:#x}: {ins.mnemonic} {ins.op_str}")
                    continue
                patches.append(
                    {
                        "rva": rva,
                        "len": ins.size,
                        "orig": bytes(ins.bytes).hex(),
                        "field_off": off,
                        "field_w": w,
                        "old": v,
                        "new": new,
                        "cat": cat,
                        "asm": f"{ins.mnemonic} {ins.op_str}",
                    }
                )
                per_cat[cat] += 1

    actual_table_bytes = {p["rva"] for p in patches if p["cat"] == "table_bytes"}
    if actual_table_bytes != expected_table_bytes:
        raise ValueError(
            f"reviewed table-byte sites changed: got {sorted(actual_table_bytes)}, "
            f"expected {sorted(expected_table_bytes)}")
    if seen_exclusions != set(expected_exclusions):
        raise ValueError(
            f"reviewed literal exclusions changed: got {sorted(seen_exclusions)}, "
            f"expected {sorted(expected_exclusions)}")

    print("\nfield rewrites inside the handle-manager regions:")
    for c, n in sorted(per_cat.items()):
        print(f"  {c:<18} {n}")
    print(f"  {'lea disp32 -> table':<18} {len(disp_sites)}")
    print(f"  TOTAL {len(patches) + len(disp_sites)}")
    print("\nliterals deliberately left alone (observed inside the regions):")
    for v, n in sorted(untouched_seen.items()):
        print(f"  {v:#x} {UNTOUCHED[v]:<20} {n}")
    for item in excluded_literal_sites:
        print(f"  EXCLUDED {img.base + item['rva']:#x}: {item['asm']} -- {item['why']}")

    # Full-instruction records make table relocation byte-exact, rather than
    # trusting a bare list of disp32 RVAs.  The 21-bit layout needs no
    # object-side byte substitutions.
    table_refs = exact_table_refs(img, disp_sites, table)
    publishers = allocation_publishers(img, sorted(regions))
    init_patches = init_guard_patches(img, a.runtime)
    assignment_hooks = assignment_hook_metadata(
        img,
        publishers,
        lock,
        PROFILE_METADATA[a.runtime]["lock_write_rva"],
        PROFILE_METADATA[a.runtime]["unlock_write_rva"],
        root_map,
        lranges)
    player_reservation = player_reservation_metadata(
        img, a.runtime, table, head, tail, lock, root_map, lranges)
    cap_write_bytes: set[int] = set()
    for p in patches:
        cap_write_bytes.update(range(
            p["rva"] + p["field_off"],
            p["rva"] + p["field_off"] + p["field_w"]))
    for p in init_patches:
        cap_write_bytes.update(range(p["rva"], p["rva"] + p["len"]))
    for p in table_refs:
        cap_write_bytes.update(range(
            p["rva"] + p["disp_off"], p["rva"] + p["disp_off"] + 4))
    assignment_guard_bytes = set(range(
        assignment_hooks["helper_rva"], assignment_hooks["helper_rva"] + 16))
    for p in assignment_hooks["sites"]:
        assignment_guard_bytes.update(range(p["call_rva"] - 11, p["call_rva"] + 5))
        assignment_guard_bytes.update(range(p["function_rva"], p["function_rva"] + 16))
    overlap = sorted(cap_write_bytes & assignment_guard_bytes)
    if overlap:
        raise ValueError(
            f"assignment verification window overlaps cap rewrites at "
            f"{', '.join(hex(img.base + x) for x in overlap[:8])}")
    reservation_guard_bytes: set[int] = set()
    for p in player_reservation["selectors"]:
        reservation_guard_bytes.update(range(p["hook_rva"], p["hook_rva"] + 6))
        reservation_guard_bytes.update(range(
            p["function_rva"], p["function_rva"] + 16))
        reservation_guard_bytes.update(range(
            p["object_setup_rva"], p["object_setup_rva"] + 3))
        reservation_guard_bytes.update(range(
            p["lock_call_rva"], p["lock_call_rva"] + 5))
        reservation_guard_bytes.update(range(
            p["unlock_call_rva"], p["unlock_call_rva"] + 5))
    release_hook = player_reservation["release"]
    reservation_guard_bytes.update(range(
        release_hook["hook_rva"], release_hook["hook_rva"] + 6))
    reservation_guard_bytes.update(range(
        release_hook["function_rva"], release_hook["function_rva"] + 16))
    reservation_guard_bytes.update(range(
        release_hook["unlock_call_rva"], release_hook["unlock_call_rva"] + 5))
    creation_lifecycle = player_reservation["lifecycle"]["creation"]
    constructor_call = creation_lifecycle["constructor_call"]
    reservation_guard_bytes.update(range(
        constructor_call["rva"],
        constructor_call["rva"] + len(bytes.fromhex(constructor_call["bytes"]))))
    reservation_guard_bytes.update(range(
        creation_lifecycle["constructor_function_rva"],
        creation_lifecycle["constructor_function_rva"] + 16))
    constructor_pre_hook = bytes.fromhex(
        creation_lifecycle["constructor_pre_hook_bytes"])
    reservation_guard_bytes.update(range(
        creation_lifecycle["constructor_pre_hook_rva"],
        creation_lifecycle["constructor_pre_hook_rva"] +
        len(constructor_pre_hook)))
    constructor_post_call = bytes.fromhex(
        creation_lifecycle["constructor_post_call_bytes"])
    reservation_guard_bytes.update(range(
        creation_lifecycle["constructor_post_call_rva"],
        creation_lifecycle["constructor_post_call_rva"] +
        len(constructor_post_call)))
    overlap = sorted(cap_write_bytes & reservation_guard_bytes)
    if overlap:
        raise ValueError(
            f"player-reservation verification window overlaps cap rewrites at "
            f"{', '.join(hex(img.base + x) for x in overlap[:8])}")
    print("\nbyte-exact non-field rewrites:")
    print(f"  {'initializer guards':<18} {len(init_patches)}")
    print(f"  {'stock publishers':<18} {len(publishers)} "
          "(object-side cache retained byte-for-byte)")
    print(f"  {'assignment hooks':<18} {len(assignment_hooks['sites'])} "
          f"(shared helper {img.base + assignment_hooks['helper_rva']:#x})")
    print(f"  {'player selectors':<18} {len(player_reservation['selectors'])} "
          f"(singleton RVA {player_reservation['singleton_rva']:#x})")
    print(f"  {'player release':<18} canonical hook "
          f"{img.base + player_reservation['release']['hook_rva']:#x}")
    print(f"  {'player constructor':<18} mandatory call hook "
          f"{img.base + player_reservation['lifecycle']['creation']['constructor_call']['rva']:#x}")

    # ---- 4. completeness cross-checks ------------------------------------ #
    # Coverage is a byte-range question: a literal's bytes sit *inside* an
    # instruction, not at its start address.
    rsorted = sorted(regions)

    def in_region(rva: int) -> bool:
        return any(b <= rva < e for b, e in rsorted)

    fp = byte_hits(img, AGE_MASK_BYTES)
    outside = [h for h in fp if not in_region(h)]
    print(f"\nage-mask fingerprint {0x03F00000:#x}: {len(fp)} raw hits in .text, "
          f"{len(fp) - len(outside)} inside patched regions, {len(outside)} OUTSIDE")
    for h in outside:
        print(f"  OUTSIDE {img.base + h:#x}  section={img.section_of(h)}  -- review")

    idx = byte_hits(img, (0x000FFFFF).to_bytes(4, "little"))
    idx_out = [h for h in idx if not in_region(h)]
    print(f"index-mask bytes {0x000FFFFF:#x}: {len(idx)} raw hits, {len(idx_out)} outside patched regions "
          f"(most are unrelated -- reviewed via the age-mask fingerprint above)")

    out = {
        "runtime": a.runtime,
        "exe_size": img.path.stat().st_size,
        "exe_sha256": hashlib.sha256(img.path.read_bytes()).hexdigest(),
        "image_base": img.base,
        "table_rva": table,
        "head_rva": head,
        "tail_rva": tail,
        "lock_rva": lock,
        "lock_write_rva": PROFILE_METADATA[a.runtime]["lock_write_rva"],
        "unlock_write_rva": PROFILE_METADATA[a.runtime]["unlock_write_rva"],
        "stock_entries": 0x100000,
        "raised_entries": 0x200000,
        "entry_size": 0x10,
        "regions": sorted(regions),
        # Kept for human diffs and older research scripts.  Runtime code uses
        # the byte-exact `table_refs` records below.
        "lea_disp_rvas": sorted(disp_sites),
        "table_refs": table_refs,
        "patches": sorted(patches, key=lambda p: p["rva"]),
        "excluded_literals": sorted(excluded_literal_sites, key=lambda p: p["rva"]),
        "init_patches": init_patches,
        "assignment_hooks": assignment_hooks,
        "player_reservation": player_reservation,
        "fingerprint_outside": outside,
    }
    with open(a.out, "w") as fh:
        json.dump(out, fh, indent=1)
    print(f"\nwrote {a.out}")


if __name__ == "__main__":
    main()
