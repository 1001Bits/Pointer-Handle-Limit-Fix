"""Offline simulation of the patch the plugin applies, then re-verify.

Applies the generated patch table to an in-memory copy of the game image
exactly as the DLL would, then disassembles the patched regions again and
checks the result is a coherent 22-bit table encoding with the legacy
object-word ABI preserved by a padding-dword sidecar:

  * every index mask reads 0x3FFFFF and no 0xFFFFF survives in the regions
  * every age mask reads 0xFC00000 and no 0x3F00000 survives ANYWHERE in .text
  * every in-use bit test is bit 28, none at bit 26 in the regions
  * every table reference resolves to the new table, none to the old one
  * every object-index reader consumes the sidecar and each allocator writer
    saves full22 before publishing the unchanged valid/refcount object word
  * every release clears the legacy word and sidecar with one 64-bit mask
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", required=True)
    ap.add_argument("--patch", required=True)
    a = ap.parse_args()

    img, _ = open_runtime(a.runtime)
    pt = json.load(open(a.patch))
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

    # The generation-wrap diagnostic is installed separately from the cap
    # rewrite, but its five callsites are generated from the same exact image.
    # Prove that the metadata still names complete stock instructions and one
    # shared helper before simulating any writes.
    assignment = pt.get("assignment_hooks", {})
    assignment_sites = assignment.get("sites", [])
    helper_rva = assignment.get("helper_rva", -1)
    helper_bytes = bytes.fromhex(assignment.get("helper_bytes", ""))
    if len(assignment_sites) != 5:
        fails.append(f"expected five assignment-hook sites, found {len(assignment_sites)}")
    if len(helper_bytes) != 16 or img.read(helper_rva, 16) != helper_bytes:
        fails.append("assignment helper fingerprint does not match the exact executable")
    writer_rvas = {p["rva"] for p in pt["raw_patches"] if p["cat"] == "sidecar_write"}
    if {p.get("writer_rva") for p in assignment_sites} != writer_rvas:
        fails.append("assignment hooks do not map one-to-one to all five allocation writers")
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
        fn = img.func_containing(call_rva)
        if fn is None or fn.begin != function_rva or not \
                (p.get("lock_call_rva", call_rva) < call_rva <
                 p.get("unlock_call_rva", call_rva)):
            fails.append(f"assignment call at {img.base + call_rva:#x} lost its owner/lock bracket")

    # No two independent generated writes may overlap.  Field patches own a
    # sub-field, while byte patches and table references own whole records.
    owners: dict[int, str] = {}

    def claim(rva: int, n: int, owner: str) -> None:
        for q in range(rva, rva + n):
            if q in owners:
                fails.append(f"overlap at {img.base + q:#x}: {owners[q]} vs {owner}")
            owners[q] = owner

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

    for p in pt["raw_patches"] + pt["init_patches"]:
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
    if any(q in owners for q in range(helper_rva, helper_rva + 16)):
        fails.append(f"assignment helper fingerprint at {img.base + helper_rva:#x} overlaps a cap rewrite")
    if get(helper_rva, 16) != helper_bytes:
        fails.append("cap simulation changed the assignment helper fingerprint")

    print(f"applied {len(pt['patches'])} field rewrites, {len(pt['raw_patches'])} sidecar rewrites, "
          f"{len(pt['init_patches'])} initializer guards, {len(pt['table_refs'])} table references, "
          f"and verified {len(assignment_sites)} assignment hooks")

    # ---- re-verify ------------------------------------------------------ #
    md = img.md
    counts = {
        "index_mask_new": 0, "index_mask_old": 0,
        "age_mask_new": 0, "age_mask_old": 0,
        "bt28": 0, "bt26": 0,
        "table_new": 0, "table_old": 0,
        "refcount_mask": 0, "valid_bit": 0, "shift11": 0,
        "age_inc_new": 0, "age_inc_old": 0,
        "clear_next_new": 0, "clear_age_new": 0, "clear_inuse_new": 0,
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
                    if v == 0x1C:
                        counts["bt28"] += 1
                    elif v == 0x1A:
                        counts["bt26"] += 1
                    continue
                if v == 0x003FFFFF:
                    counts["index_mask_new"] += 1
                elif v == 0x000FFFFF:
                    counts["index_mask_old"] += 1
                elif v == 0x0FC00000:
                    counts["age_mask_new"] += 1
                elif v == 0x03F00000:
                    counts["age_mask_old"] += 1
                elif v == 0x00400000:
                    counts["age_inc_new"] += 1
                elif v == 0x00100000:
                    counts["age_inc_old"] += 1
                elif v == 0xFFC00000:
                    counts["clear_next_new"] += 1
                elif v == 0xF03FFFFF:
                    counts["clear_age_new"] += 1
                elif v == 0xEFFFFFFF:
                    counts["clear_inuse_new"] += 1
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

    check(counts["index_mask_old"] == 0, "a 20-bit index mask survived inside a patched region")
    check(counts["age_mask_old"] == 0, "a stock age mask survived inside a patched region")
    check(counts["bt26"] == 0, "an in-use test still targets bit 26")
    check(counts["table_old"] == 0, "a reference to the OLD table survived")
    check(counts["table_new"] == len(pt["table_refs"]),
          f"expected {len(pt['table_refs'])} references to the new table, "
          f"found {counts['table_new']}")

    # Refcount masks are byte-identical.  Valid/index *semantics* are checked
    # below because writer BTS and reader SHR instructions intentionally turn
    # into sidecar operations.
    orig_counts = {"refcount_mask": 0}
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
                if ins.mnemonic in ("bt", "bts", "btr", "btc") and op.type == X86_OP_IMM:
                    continue
                if v == 0x3FF:
                    orig_counts["refcount_mask"] += 1

    for k in orig_counts:
        check(counts[k] == orig_counts[k],
              f"{k} changed ({orig_counts[k]} -> {counts[k]}); the raise must retain 10 refcount bits")

    # Every raw reader becomes one direct dword load from +0x0c/+0x2c, into
    # the same register that the stock SHR wrote.
    for p in (x for x in pt["raw_patches"] if x["cat"] == "sidecar_read"):
        old = list(md.disasm(bytes.fromhex(p["orig"]), img.base + p["rva"]))
        new = list(md.disasm(bytes.fromhex(p["new"]), img.base + p["rva"]))
        if p["mode"] == "redirect_load":
            check(len(old) == 2 and [x.mnemonic for x in old] == ["mov", "shr"],
                  f"reader {p['rva']:#x} stock bytes are not MOV; SHR")
            check(new and new[0].mnemonic == "mov" and all(x.mnemonic == "nop" for x in new[1:]),
                  f"reader {p['rva']:#x} replacement is not MOV-sidecar plus NOPs")
            old_dst = old[-1].operands[0].reg if old else 0
        else:
            check(len(old) == 1 and old[0].mnemonic == "shr",
                  f"reader {p['rva']:#x} stock bytes are one SHR")
            check(len(new) == 1 and new[0].mnemonic == "mov",
                  f"reader {p['rva']:#x} replacement is one MOV")
            old_dst = old[0].operands[0].reg if old else 0
        if new and new[0].mnemonic == "mov":
            check(old_dst == new[0].operands[0].reg,
                  f"reader {p['rva']:#x} changes its destination register")
            mem = new[0].operands[1]
            check(mem.type == X86_OP_MEM and mem.mem.disp == p["sidecar_disp"],
                  f"reader {p['rva']:#x} does not load its declared sidecar")

    # Algebraic proof for the exact same-length writer substitution:
    #   CF:EAX = 1:index; RCL 11 -> CF=high(index),
    #   EAX=(low21(index)<<11)|0x400.
    for index in (0, 1, 0x1FFFFF, 0x200000, 0x3FFFFF):
        ring = ((1 << 32) | index) & ((1 << 33) - 1)
        rotated = ((ring << 11) | (ring >> (33 - 11))) & ((1 << 33) - 1)
        got = rotated & 0xFFFFFFFF
        want = ((index & 0x1FFFFF) << 11) | 0x400
        check(got == want, f"writer RCL encoding fails for index {index:#x}: {got:#x} != {want:#x}")
    for p in (x for x in pt["raw_patches"] if x["cat"] == "sidecar_write"):
        new = list(md.disasm(bytes.fromhex(p["new"]), img.base + p["rva"]))
        check([x.mnemonic for x in new] == ["mov", "stc", "rcl"],
              f"writer {p['rva']:#x} is not MOV-sidecar; STC; RCL")
        check(sum(x.size for x in new) == p["len"], f"writer {p['rva']:#x} replacement length drifted")

    # Releases promote the stock dword mask to a qword mask, then replace the
    # following redundant entry reload with a register move to remain exactly
    # the same length.  This preserves stock invalidation order for lock-free
    # readers instead of leaving a stale sidecar during entry unpublish.
    release_patches = [x for x in pt["raw_patches"] if x["cat"] == "sidecar_release"]
    for p in pt["release_sites"]:
        check(img.read(p["rva"], p["len"]) == bytes.fromhex(p["orig"]),
              f"release audit bytes differ at {img.base + p['rva']:#x}")
        check(any(x["clear_rva"] == p["rva"] and x["rva"] == p["raw_patch_rva"] for x in release_patches),
              f"release audit at {img.base + p['rva']:#x} has no generated byte patch")
    check(len(release_patches) == len(pt["release_sites"]),
          "release audit/byte-patch counts differ")
    for p in release_patches:
        new = list(md.disasm(bytes.fromhex(p["new"]), img.base + p["rva"]))
        check([x.mnemonic for x in new] == ["mov", "and", "mov"],
              f"release {p['rva']:#x} is not pointer-load; qword-AND; register-move")
        if len(new) == 3:
            check(new[1].operands[0].type == X86_OP_MEM and new[1].operands[0].size == 8 and
                  (new[1].operands[1].imm & 0xFFFFFFFF) == 0x3FF,
                  f"release {p['rva']:#x} does not clear word+sidecar with qword mask 0x3ff")
    check(sum(x["cat"] == "sidecar_write" for x in pt["raw_patches"]) == 5,
          "expected five allocation writers")

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
    # instruction; arbitrary rewrites consume exactly their declared window.
    for p in pt["patches"]:
        old = list(md.disasm(bytes.fromhex(p["orig"]), img.base + p["rva"]))
        new = list(md.disasm(get(p["rva"], p["len"]), img.base + p["rva"]))
        check(len(old) == len(new) == 1 and old[0].size == new[0].size == p["len"],
              f"field instruction boundary changed at {img.base + p['rva']:#x}")
    for p in pt["raw_patches"] + pt["init_patches"]:
        dec = list(md.disasm(get(p["rva"], p["len"]), img.base + p["rva"]))
        check(sum(x.size for x in dec) == p["len"],
              f"byte patch does not end on its original boundary at {img.base + p['rva']:#x}")

    print()
    if fails:
        print(f"FAILED ({len(fails)}):")
        for f in fails[:30]:
            print("   -", f)
        return 1
    print("PASS: patched image is a coherent 22-bit/4M table encoding; full indices use "
          "the object padding sidecar while the 10-bit refcount ABI remains intact.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
