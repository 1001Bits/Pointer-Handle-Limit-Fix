"""Walk the SKSE call graph up from the plugin loader to its roots, and find
the game addresses SKSE detours."""
from __future__ import annotations

import bisect
import struct
import sys
from collections import defaultdict
from pathlib import Path

import capstone
import pefile

OUT = Path(sys.argv[1])
DLL = r"C:\Games\Skyrim SE\skse64_1_5_97.dll"

pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
BASE = pe.OPTIONAL_HEADER.ImageBase
raw = pe.__data__
secs = [(s.Name.rstrip(b"\x00").decode(errors="replace"), s.VirtualAddress,
         max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData, s.SizeOfRawData)
        for s in pe.sections]
funcs = sorted({(e.struct.BeginAddress, e.struct.EndAddress)
                for e in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", [])
                if e.struct.EndAddress > e.struct.BeginAddress})
fstarts = [b for b, _ in funcs]

L = []
def p(s=""):
    L.append(str(s))

def read(rva, n):
    for _, va, vsz, praw, rsz in secs:
        if va <= rva < va + vsz:
            off = rva - va
            if off >= rsz:
                return b"\x00" * n
            take = max(0, min(n, rsz - off))
            return bytes(raw[praw + off: praw + off + take]) + b"\x00" * (n - take)
    raise ValueError(hex(rva))

def func_of(rva):
    i = bisect.bisect_right(fstarts, rva) - 1
    if i < 0:
        return None
    b, e = funcs[i]
    return b if b <= rva < e else None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

callers = defaultdict(set)   # callee_rva -> {caller_func_rva}
calls = defaultdict(set)
insn_by_func = {}
for b, e in funcs:
    ins_list = list(md.disasm(read(b, e - b), BASE + b))
    insn_by_func[b] = ins_list
    for ins in ins_list:
        if ins.mnemonic in ("call", "jmp") and ins.operands and ins.operands[0].type == capstone.x86.X86_OP_IMM:
            t = ins.operands[0].imm - BASE
            callers[t].add(b)
            calls[b].add(t)

# also: pointers to functions stored anywhere (vtables, thunks, trampoline args)
def abs_ptr_refs(rva):
    needle = struct.pack("<Q", BASE + rva)
    out = []
    for n, va, vsz, praw, rsz in secs:
        if not rsz:
            continue
        d = bytes(raw[praw:praw + rsz])
        s = 0
        while True:
            i = d.find(needle, s)
            if i < 0:
                break
            out.append((va + i, n))
            s = i + 1
    return out

def riprefs_to(rva):
    out = []
    for b, ins_list in insn_by_func.items():
        for ins in ins_list:
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    if ins.address + ins.size + op.mem.disp - BASE == rva:
                        out.append((ins.address, ins.mnemonic, ins.op_str, b))
    return out

p("== call-graph ancestry of the plugin loader 0x180080750")
seen = set()
frontier = [0x80750]
level = 0
while frontier and level < 8:
    nxt = []
    p(f"-- level {level}")
    for f in frontier:
        cs = sorted(callers.get(f, ()))
        p(f"   {BASE+f:#x} <- {[hex(BASE+c) for c in cs] or 'ROOT'}")
        if not cs:
            for a, n in abs_ptr_refs(f):
                p(f"        ptr-to {BASE+f:#x} stored at {BASE+a:#x} ({n})")
            for a, mn, ops, cf in riprefs_to(f):
                p(f"        rip-ref {a:#x} {mn} {ops} in func {BASE+cf:#x}")
        for c in cs:
            if c not in seen:
                seen.add(c)
                nxt.append(c)
    frontier = nxt
    level += 1

p("\n== disasm of plugin loader root chain (first 2 roots)")
OUT.write_text("\n".join(L), encoding="utf-8")
print("wrote", OUT, len(L))
