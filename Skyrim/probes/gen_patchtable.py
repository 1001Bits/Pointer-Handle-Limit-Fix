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
    X86_REG_RCX,
    X86_REG_RDX,
    X86_REG_RIP,
)

from image import open_runtime
from logical_funcs import build_chunk_to_root, logical_ranges

# Same-length imm32 rewrites: old -> (new, category).  Four million entries
# consume 22 index bits in the table word.  The object-side word retains its
# public 10-bit-refcount/valid/21-bit-index layout; the full index is mirrored
# into NiRefObject's padding dword by the raw patches generated below.
IMM32 = {
    0x000FFFFF: (0x003FFFFF, "index_mask"),
    0x03F00000: (0x0FC00000, "age_mask"),
    0x00100000: (0x00400000, "age_inc_or_count"),
    0x01000000: (0x04000000, "table_bytes"),
    0xFC0FFFFF: (0xF03FFFFF, "clear_age"),
    0xFFF00000: (0xFFC00000, "clear_next"),
    0xFBFFFFFF: (0xEFFFFFFF, "clear_inuse"),
    0x04000000: (0x10000000, "inuse_bit"),
}
BITPOS = {0x1A: (0x1C, "inuse_bitpos")}

# Object-side fields whose widths the raise does not change; never rewritten.
UNTOUCHED = {0x3FF: "refcount mask", 0x400: "handle-valid bit", 0x0B: "index shift"}

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
# Object-side 22-bit-index sidecar synthesis


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


def encode_mov_r32_mem(md, dst: int, base: int, disp: int) -> bytes:
    """Encode ``mov r32, dword ptr [base + disp8]``."""
    d, b = reg_number(md, dst), reg_number(md, base)
    if d is None or b is None or not (-0x80 <= disp <= 0x7F):
        raise ValueError("sidecar load is outside the supported GPR/disp8 form")
    out = bytearray()
    rex = 0x40 | (0x04 if d >= 8 else 0) | (0x01 if b >= 8 else 0)
    if rex != 0x40:
        out.append(rex)
    out.append(0x8B)
    out.append(0x40 | ((d & 7) << 3) | (b & 7))
    if (b & 7) == 4:  # rsp/r12 requires a no-index SIB byte
        out.append(0x24)
    out.append(disp & 0xFF)
    return bytes(out)


def encode_mov_mem_r32(md, base: int, disp: int, src: int) -> bytes:
    """Encode ``mov dword ptr [base + disp8], r32``."""
    s, b = reg_number(md, src), reg_number(md, base)
    if s is None or b is None or not (-0x80 <= disp <= 0x7F):
        raise ValueError("sidecar store is outside the supported GPR/disp8 form")
    out = bytearray()
    rex = 0x40 | (0x04 if s >= 8 else 0) | (0x01 if b >= 8 else 0)
    if rex != 0x40:
        out.append(rex)
    out.append(0x89)
    out.append(0x40 | ((s & 7) << 3) | (b & 7))
    if (b & 7) == 4:
        out.append(0x24)
    out.append(disp & 0xFF)
    return bytes(out)


def encode_rcl_r32_imm(md, reg: int, count: int) -> bytes:
    n = reg_number(md, reg)
    if n is None:
        raise ValueError("sidecar writer does not use a GPR")
    out = bytearray()
    if n >= 8:
        out.append(0x41)
    out.extend((0xC1, 0xD0 | (n & 7), count & 0xFF))  # C1 /2 ib
    return bytes(out)


def encode_and_mem64_imm32(md, base: int, disp: int, imm: int) -> bytes:
    """Encode ``and qword ptr [base + disp8], sign_extended_imm32``."""
    b = reg_number(md, base)
    if b is None or not (-0x80 <= disp <= 0x7F):
        raise ValueError("sidecar release is outside the supported GPR/disp8 form")
    out = bytearray((0x48 | (0x01 if b >= 8 else 0), 0x81))
    out.append(0x40 | (4 << 3) | (b & 7))  # mod=disp8, /4 AND
    if (b & 7) == 4:
        out.append(0x24)
    out.append(disp & 0xFF)
    out.extend(struct.pack("<I", imm & 0xFFFFFFFF))
    return bytes(out)


def encode_mov_r64_r64(md, dst: int, src: int) -> bytes:
    d, s = reg_number(md, dst), reg_number(md, src)
    if d is None or s is None:
        raise ValueError("sidecar release register move does not use GPRs")
    rex = 0x48 | (0x04 if d >= 8 else 0) | (0x01 if s >= 8 else 0)
    return bytes((rex, 0x8B, 0xC0 | ((d & 7) << 3) | (s & 7)))


def previous_reg_definition(img, insns, pos: int, reg: int, limit: int = 32):
    """Find the straight-line definition feeding one shift operand.

    The object-index readers in both supported runtimes are compiler inlines:
    a dword load followed by a shift, occasionally with a valid-bit check in
    between.  Refuse anything more complicated rather than guessing through
    calls, branches, arithmetic, or a register merge.
    """
    wanted = reg_root(img.md, reg)
    for j in range(pos - 1, max(-1, pos - limit - 1), -1):
        ins = insns[j]
        if ins.mnemonic in ("call", "ret", "jmp"):
            return None
        ops = ins.operands
        if not ops or ops[0].type != X86_OP_REG or reg_root(img.md, ops[0].reg) != wanted:
            continue
        if ins.mnemonic != "mov" or len(ops) != 2:
            return None
        if ops[1].type == X86_OP_MEM:
            return j, ins, ops[1]
        if ops[1].type == X86_OP_REG:
            wanted = reg_root(img.md, ops[1].reg)
            continue
        return None
    return None


def raw_patch(img, insns, begin: int, end: int, replacement: bytes, cat: str, **extra) -> dict:
    orig = b"".join(bytes(x.bytes) for x in insns[begin:end])
    if len(orig) != len(replacement) or not orig or len(orig) > 15:
        raise ValueError(f"raw patch {cat} must be a non-empty same-length <=15-byte rewrite")
    out = {
        "rva": insns[begin].address - img.base,
        "len": len(orig),
        "orig": orig.hex(),
        "new": replacement.hex(),
        "cat": cat,
        "asm": "; ".join(f"{x.mnemonic} {x.op_str}" for x in insns[begin:end]),
    }
    out.update(extra)
    return out


def sidecar_sites(img, regions: list[tuple[int, int]]) -> tuple[list[dict], list[dict], list[dict]]:
    """Generate proven same-length sidecar readers/writers and audit releases."""
    raw: list[dict] = []
    releases: list[dict] = []
    excluded_shifts: list[dict] = []
    writer_preclears: set[int] = set()

    decoded: list[list] = []
    for begin, end in sorted(regions):
        insns = [x for x in img.disasm(begin, end - begin) if x.address - img.base < end]
        decoded.append(insns)

        # Allocation writer, stock:
        #   and [object+word], 0x3ff
        #   shl index, 11
        #   bts index, 10
        #   or  [object+word], index
        # Replacement stores the full index first, then uses the carry bit as
        # the public valid bit while rotating only low 21 index bits into the
        # legacy object word.  STC; RCL in a 33-bit CF:r32 ring is exactly
        # (low21(index)<<11)|0x400 for a 22-bit input.
        for i, shl in enumerate(insns):
            ops = shl.operands
            if not (shl.mnemonic == "shl" and len(ops) == 2 and
                    ops[0].type == X86_OP_REG and ops[0].size == 4 and
                    ops[1].type == X86_OP_IMM and ops[1].imm == 0x0B):
                continue
            if i + 1 >= len(insns):
                raise ValueError(f"unterminated object-index writer at {shl.address:#x}")
            bts = insns[i + 1]
            bo = bts.operands
            if not (bts.mnemonic == "bts" and len(bo) == 2 and
                    bo[0].type == X86_OP_REG and reg_root(img.md, bo[0].reg) == reg_root(img.md, ops[0].reg) and
                    bo[1].type == X86_OP_IMM and bo[1].imm == 0x0A):
                raise ValueError(f"unrecognised object-index writer at {shl.address:#x}")

            pre = None
            for j in range(i - 1, max(-1, i - 7), -1):
                x = insns[j]
                xo = x.operands
                if (x.mnemonic == "and" and len(xo) == 2 and xo[0].type == X86_OP_MEM and
                        xo[0].size == 4 and xo[0].mem.base not in (0, X86_REG_RIP) and
                        xo[0].mem.index == 0 and xo[0].mem.disp in (0x08, 0x28) and
                        xo[1].type == X86_OP_IMM and (xo[1].imm & 0xFFFFFFFF) == 0x3FF):
                    pre = j, x, xo[0]
                    break
            if pre is None:
                raise ValueError(f"object-index writer lacks its defensive clear at {shl.address:#x}")
            j, clear, mem = pre

            post = None
            for k in range(i + 2, min(len(insns), i + 5)):
                x = insns[k]
                xo = x.operands
                if (x.mnemonic == "or" and len(xo) == 2 and xo[0].type == X86_OP_MEM and
                        xo[1].type == X86_OP_REG and reg_root(img.md, xo[1].reg) == reg_root(img.md, ops[0].reg)):
                    post = xo[0]
                    break
            if post is None or post.mem.base != mem.mem.base or post.mem.disp != mem.mem.disp:
                raise ValueError(f"object-index writer lacks its publish OR at {shl.address:#x}")

            store = encode_mov_mem_r32(img.md, mem.mem.base, mem.mem.disp + 4, ops[0].reg)
            replacement = store + b"\xF9" + encode_rcl_r32_imm(img.md, ops[0].reg, 0x0B)
            p = raw_patch(img, insns, i, i + 2, replacement, "sidecar_write",
                          clear_rva=clear.address - img.base,
                          sidecar_disp=mem.mem.disp + 4)
            p["rva"] = shl.address - img.base
            raw.append(p)
            writer_preclears.add(clear.address - img.base)

    direct_jump_targets = {
        x.operands[0].imm - img.base
        for block in decoded for x in block
        if x.mnemonic.startswith("j") and x.operands and x.operands[0].type == X86_OP_IMM
    }

    for insns in decoded:
        for i, shr in enumerate(insns):
            ops = shr.operands
            if not (shr.mnemonic == "shr" and len(ops) == 2 and
                    ops[0].type == X86_OP_REG and ops[0].size == 4 and
                    ops[1].type == X86_OP_IMM and ops[1].imm == 0x0B):
                continue
            src = previous_reg_definition(img, insns, i, ops[0].reg)
            if src is None:
                excluded_shifts.append({"rva": shr.address - img.base, "why": "no straight-line memory definition"})
                continue
            _, source, mem = src
            if not (mem.mem.base not in (0, X86_REG_RIP) and mem.mem.index == 0 and
                    mem.size == 4 and mem.mem.disp in (0x08, 0x28)):
                excluded_shifts.append({
                    "rva": shr.address - img.base,
                    "source_rva": source.address - img.base,
                    "source_disp": mem.mem.disp,
                    "why": "not a BSHandleRefObject refcount displacement",
                })
                continue
            # The common validator shape is ``mov word; shr 11``.  Redirect
            # that existing load and NOP the shift so validation pays no extra
            # memory operation.  GetCurrentHandle also consumes the stock word
            # for its valid-bit test; those less frequent shapes keep the stock
            # load and replace only SHR with a sidecar load.
            src_i = src[0]
            if src_i == i - 1 and reg_root(img.md, source.operands[0].reg) == reg_root(img.md, ops[0].reg):
                new_load = encode_mov_r32_mem(img.md, ops[0].reg, mem.mem.base, mem.mem.disp + 4)
                replacement = new_load + (b"\x90" * shr.size)
                p = raw_patch(img, insns, src_i, i + 1, replacement, "sidecar_read",
                              source_rva=source.address - img.base,
                              shift_rva=shr.address - img.base,
                              mode="redirect_load",
                              sidecar_disp=mem.mem.disp + 4)
            else:
                replacement = encode_mov_r32_mem(img.md, ops[0].reg, mem.mem.base, mem.mem.disp + 4)
                p = raw_patch(img, insns, i, i + 1, replacement, "sidecar_read",
                              source_rva=source.address - img.base,
                              shift_rva=shr.address - img.base,
                              mode="replace_shift",
                              sidecar_disp=mem.mem.disp + 4)
            raw.append(p)

        # Release clears the public word before unpublishing the entry.  Clear
        # the adjacent sidecar in the same operation so a lock-free validator
        # cannot accept a stale full index during that short stock ordering
        # window.  Every reviewed site has a redundant entry-pointer reload:
        #
        #   mov rax, [entry+8]       mov rax, [entry+8]
        #   and dword [rax+8],3ff -> and qword [rax+8],3ff
        #   mov rcx, [entry+8]       mov rcx, rax
        #
        # The promoted AND costs one byte; the register move saves one, giving
        # a full-instruction, same-length 15-byte rewrite.
        for i, ins in enumerate(insns):
            ops = ins.operands
            if not (ins.mnemonic == "and" and len(ops) == 2 and
                    ops[0].type == X86_OP_MEM and ops[0].size == 4 and
                    ops[0].mem.base not in (0, X86_REG_RIP) and ops[0].mem.index == 0 and
                    ops[0].mem.disp in (0x08, 0x28) and ops[1].type == X86_OP_IMM and
                    (ops[1].imm & 0xFFFFFFFF) == 0x3FF):
                continue
            rva = ins.address - img.base
            if rva in writer_preclears:
                continue
            if i == 0 or i + 1 >= len(insns):
                raise ValueError(f"release clear at {ins.address:#x} lacks its pointer-load window")
            prev, nxt = insns[i - 1], insns[i + 1]
            po, no = prev.operands, nxt.operands
            if not (prev.mnemonic == "mov" and len(po) == 2 and
                    po[0].type == X86_OP_REG and po[0].size == 8 and po[1].type == X86_OP_MEM and
                    nxt.mnemonic == "mov" and len(no) == 2 and
                    no[0].type == X86_OP_REG and no[0].size == 8 and no[1].type == X86_OP_MEM and
                    po[1].mem.base == no[1].mem.base and po[1].mem.index == no[1].mem.index and
                    po[1].mem.scale == no[1].mem.scale and po[1].mem.disp == no[1].mem.disp and
                    reg_root(img.md, po[0].reg) == reg_root(img.md, ops[0].mem.base)):
                raise ValueError(f"unrecognised sidecar release window at {ins.address:#x}")
            if nxt.address - img.base in direct_jump_targets:
                raise ValueError(f"release reload at {nxt.address:#x} is a direct branch target; "
                                 "the one-byte boundary shift is unsafe")
            qword_clear = encode_and_mem64_imm32(img.md, ops[0].mem.base, ops[0].mem.disp, 0x3FF)
            reg_move = encode_mov_r64_r64(img.md, no[0].reg, po[0].reg)
            replacement = bytes(prev.bytes) + qword_clear + reg_move
            window_len = prev.size + ins.size + nxt.size
            if len(replacement) > window_len:
                raise ValueError(f"sidecar release replacement grew at {ins.address:#x}")
            replacement += b"\x90" * (window_len - len(replacement))
            rp = raw_patch(img, insns, i - 1, i + 2, replacement, "sidecar_release",
                           clear_rva=rva, sidecar_disp=ops[0].mem.disp + 4)
            raw.append(rp)
            releases.append({
                "rva": rva,
                "len": ins.size,
                "orig": bytes(ins.bytes).hex(),
                "asm": f"{ins.mnemonic} {ins.op_str}",
                "raw_patch_rva": rp["rva"],
                "policy": "64-bit mask clears the legacy word and sidecar before entry unpublish",
            })

    # Any other shift-by-11 in the selected regions is reported explicitly.
    # The known exclusions are TESForm flag tests at +0x10, not object-index
    # readers; a new compiler shape must fail review rather than be patched by
    # resemblance.
    unexpected = [x for x in excluded_shifts if x.get("source_disp") != 0x10]
    if unexpected:
        detail = ", ".join(f"{img.base + x['rva']:#x}: {x['why']}" for x in unexpected)
        raise ValueError(f"unclassified shift-by-11 sites: {detail}")

    raw.sort(key=lambda p: p["rva"])
    releases.sort(key=lambda p: p["rva"])
    return raw, releases, excluded_shifts


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
        raw_patches: list[dict],
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

    This routine deliberately derives the sites from the independently found
    object-side writers and then proves their ABI and lock coverage from the
    instruction stream.  A compiler-layout change therefore fails generation
    rather than quietly emitting a guessed hook.
    """
    writers = [p for p in raw_patches if p["cat"] == "sidecar_write"]
    if len(writers) != 5:
        raise ValueError(
            f"assignment-hook derivation expected five publishers, found {len(writers)}")

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

    for writer in sorted(writers, key=lambda p: p["rva"]):
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
                if ins.mnemonic in ("bt", "bts", "btr", "btc") and op.type == X86_OP_IMM and v in BITPOS:
                    new, cat, w = BITPOS[v][0], BITPOS[v][1], 1
                elif v in IMM32:
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
    # trusting a bare list of disp32 RVAs.  Sidecar rewrites are likewise full
    # same-length byte substitutions.
    table_refs = exact_table_refs(img, disp_sites, table)
    raw_patches, release_sites, excluded_shifts = sidecar_sites(img, sorted(regions))
    init_patches = init_guard_patches(img, a.runtime)
    assignment_hooks = assignment_hook_metadata(
        img,
        raw_patches,
        lock,
        PROFILE_METADATA[a.runtime]["lock_write_rva"],
        PROFILE_METADATA[a.runtime]["unlock_write_rva"],
        root_map,
        lranges)
    cap_write_bytes: set[int] = set()
    for p in patches:
        cap_write_bytes.update(range(
            p["rva"] + p["field_off"],
            p["rva"] + p["field_off"] + p["field_w"]))
    for p in raw_patches + init_patches:
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
    raw_counts = defaultdict(int)
    for p in raw_patches:
        raw_counts[p["cat"]] += 1
    print("\nbyte-exact non-field rewrites:")
    for cat, n in sorted(raw_counts.items()):
        print(f"  {cat:<18} {n}")
    print(f"  {'initializer guards':<18} {len(init_patches)}")
    print(f"  {'release audits':<18} {len(release_sites)} (covered by qword-clear patches)")
    print(f"  {'excluded shr 11':<18} {len(excluded_shifts)} (non-refcount +0x10 flag tests)")
    print(f"  {'assignment hooks':<18} {len(assignment_hooks['sites'])} "
          f"(shared helper {img.base + assignment_hooks['helper_rva']:#x})")

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
        "raised_entries": 0x400000,
        "entry_size": 0x10,
        "regions": sorted(regions),
        # Kept for human diffs and older research scripts.  Runtime code uses
        # the byte-exact `table_refs` records below.
        "lea_disp_rvas": sorted(disp_sites),
        "table_refs": table_refs,
        "patches": sorted(patches, key=lambda p: p["rva"]),
        "excluded_literals": sorted(excluded_literal_sites, key=lambda p: p["rva"]),
        "raw_patches": raw_patches,
        "init_patches": init_patches,
        "release_sites": release_sites,
        "assignment_hooks": assignment_hooks,
        "excluded_shift11": excluded_shifts,
        "fingerprint_outside": outside,
    }
    with open(a.out, "w") as fh:
        json.dump(out, fh, indent=1)
    print(f"\nwrote {a.out}")


if __name__ == "__main__":
    main()
