"""End-to-end consistency check across the whole deliverable.

Guards against the drift that matters: a patch table regenerated without
regenerating the C++ header, a header edited by hand, a DLL built from a stale
header, or a rewrite creeping into the object-side reference-count fields that
the raise is supposed to leave alone.

Run from probes/:  python verify_deliverable.py
Exit code 0 = consistent.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import io
import json
import pathlib
import re
import struct
import sys
import zipfile

from gen_cpp import CATS, render as render_header
from gen_patch_docs import render_all as render_patch_docs

# (runtime, table references, field rewrites, .pdata functions referencing
#  the table, sidecar readers, sidecar writers, audited releases, excluded
#  non-handle shift-by-11 flag tests)
EXPECTED = (
    ("SE", 96, 390, 73, 89, 5, 6, 2),
    ("AE", 115, 519, 98, 91, 5, 19, 4),
    ("GOG", 115, 519, 98, 91, 5, 19, 4),
    ("VR", 102, 410, 79, 95, 5, 6, 2),
)

LOCKS = {
    "SE": (0x00C07350, 0x00C075A0),
    "AE": (0x00CC9140, 0x00CC9390),
    "GOG": (0x00CCAC00, 0x00CCAE50),
    "VR": (0x00C421D0, 0x00C42420),
}

TABLE_BYTES_RVAS = {
    "SE": {0x000125DD, 0x005BCCCE},
    "AE": {0x0001292D, 0x00640461},
    "GOG": {0x0001292D, 0x006426C1},
    "VR": {0x000126ED, 0x005C512E},
}

EXCLUDED_LITERALS = {
    "SE": set(),
    "AE": set(),
    "GOG": set(),
    "VR": {(0x006CB0F3, 0x01000000)},
}

ASSIGNMENT_HOOKS = {
    "SE": {
        "helper_rva": 0x0012F6F0,
        "helper_bytes": "40534883ec20488bd9488b09483bca74",
        "setup_bytes": "498d4e084803ca488d5320",
        "sites": (
            (0x0013206C, "e87fd6ffff", 0x00131F60, 0x0013207E, 0x00131FDC, 0x001320C4),
            (0x001321FC, "e8efd4ffff", 0x001320F0, 0x0013220E, 0x0013216C, 0x00132254),
            (0x0054A92C, "e8bf4dbeff", 0x0054A820, 0x0054A93E, 0x0054A89C, 0x0054A984),
            (0x005A8FFC, "e8ef66b8ff", 0x005A8EF0, 0x005A900E, 0x005A8F6C, 0x005A9054),
            (0x0073D31C, "e8cf239fff", 0x0073D210, 0x0073D32E, 0x0073D28C, 0x0073D374),
        ),
    },
    "AE": {
        "helper_rva": 0x001767C0,
        "helper_bytes": "40534883ec20488bd9488b09483bca74",
        "setup_bytes": "488d5720498d4e084903c8",
        "sites": (
            (0x00178FCD, "e8eed7ffff", 0x00178EC0, 0x00178FDF, 0x00178F3C, 0x00179025),
            (0x0017915D, "e85ed6ffff", 0x00179050, 0x0017916F, 0x001790CC, 0x001791B5),
            (0x005BA04D, "e86ec7bbff", 0x005B9F40, 0x005BA05F, 0x005B9FBC, 0x005BA0A5),
            (0x0063A0AD, "e80ec7b3ff", 0x00639FA0, 0x0063A0BF, 0x0063A01C, 0x0063A105),
            (0x007D522D, "e88e159aff", 0x007D5120, 0x007D523F, 0x007D519C, 0x007D5285),
        ),
    },
    "GOG": {
        "helper_rva": 0x001765F0,
        "helper_bytes": "40534883ec20488bd9488b09483bca74",
        "setup_bytes": "488d5720498d4e084903c8",
        "sites": (
            (0x00178DFD, "e8eed7ffff", 0x00178CF0, 0x00178E0F, 0x00178D6C, 0x00178E55),
            (0x00178F8D, "e85ed6ffff", 0x00178E80, 0x00178F9F, 0x00178EFC, 0x00178FE5),
            (0x005BC4CD, "e81ea1bbff", 0x005BC3C0, 0x005BC4DF, 0x005BC43C, 0x005BC525),
            (0x0063C30D, "e8dea2b3ff", 0x0063C200, 0x0063C31F, 0x0063C27C, 0x0063C365),
            (0x007D745D, "e88ef199ff", 0x007D7350, 0x007D746F, 0x007D73CC, 0x007D74B5),
        ),
    },
    "VR": {
        "helper_rva": 0x0013FE50,
        "helper_bytes": "40534883ec20488bd9488b09483bca74",
        "setup_bytes": "498d4e084803ca488d5320",
        "sites": (
            (0x0014281C, "e82fd6ffff", 0x00142710, 0x0014282E, 0x0014278C, 0x00142874),
            (0x001429AC, "e89fd4ffff", 0x001428A0, 0x001429BE, 0x0014291C, 0x00142A04),
            (0x0054EB3C, "e80f13bfff", 0x0054EA30, 0x0054EB4E, 0x0054EAAC, 0x0054EB94),
            (0x005B06BC, "e88ff7b8ff", 0x005B05B0, 0x005B06CE, 0x005B062C, 0x005B0714),
            (0x00767EBC, "e88f7f9dff", 0x00767DB0, 0x00767ECE, 0x00767E2C, 0x00767F14),
        ),
    },
}

ASSIGNMENT_OWNER_BYTES = "41564883ec3048c7442420feffffff48"

# Generation inputs that establish the two newly added profiles.  Keeping
# these independent of the generated JSON prevents a locally substituted
# executable/database pair from silently redefining what "GOG 1.6.1179" or
# "VR 1.4.15" means to this verifier.
EXACT_NEW_RUNTIME_INPUTS = {
    "GOG": {
        "exe_size": 36_958_208,
        "exe_sha256": "9b0fc7880c4b12d436bfb59bcae64868f176dbc04010adbd9bc2ecb64bc8ed3f",
        "db_size": 796_422,
        "db_sha256": "3ee46b2f3a8a24b9cda1f2aa63b0f0f47dea347e52701a6739327e5ea1b5838e",
    },
    "VR": {
        "exe_size": 35_531_264,
        "exe_sha256": "3de757b7f52f82551fc73c5ff1d0592f69d03ecc7f492b712a24c6a957cc2e24",
        "db_size": 221_460,
        "db_sha256": "a911a457eb05be52560e591b7d310d0097fc42c414d13c3d4362481b8bea42ac",
    },
}

# Object-side fields the raise must never touch: widening the index does not
# move them, and rewriting one would cost reference-count bits.
OBJECT_SIDE = (0x3FF, 0x400, 0xFFFFF800)

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Keep this mapping independent of gen_patch_docs.py. If either the JSON
# schema or the renderer's collection coverage changes, this verifier must be
# reviewed explicitly rather than inheriting the same omission.
PATCH_DOC_PROFILE_SCALARS = {
    "runtime": str,
    "exe_size": int,
    "exe_sha256": str,
    "image_base": int,
    "table_rva": int,
    "head_rva": int,
    "tail_rva": int,
    "lock_rva": int,
    "lock_write_rva": int,
    "unlock_write_rva": int,
    "stock_entries": int,
    "raised_entries": int,
    "entry_size": int,
}

PATCH_DOC_RUNTIME_SPECS = (
    ("SE", "Skyrim SE", "1.5.97.0", "SE-1.5.97.md"),
    ("AE", "Skyrim AE", "1.6.1170.0", "AE-1.6.1170.md"),
    ("GOG", "Skyrim GOG", "1.6.1179.0", "GOG-1.6.1179.md"),
    ("VR", "Skyrim VR", "1.4.15.0", "VR-1.4.15.md"),
)

PATCH_DOC_MUTATION_COLLECTIONS = (
    (("patches",), "field", "rva"),
    (("raw_patches",), "byte", "rva"),
    (("table_refs",), "table-ref", "rva"),
    (("init_patches",), "init", "rva"),
    (("assignment_hooks", "sites"), "assignment-hook", "call_rva"),
)

PATCH_DOC_EVIDENCE_COLLECTIONS = (
    (("release_sites",), "release-alias", "rva"),
    (("excluded_literals",), "excluded-literal", "rva"),
    (("excluded_shift11",), "excluded-shift", "rva"),
)

PATCH_DOC_AUXILIARY_COLLECTIONS = {"regions", "lea_disp_rvas"}
PATCH_DOC_FINGERPRINT_COLLECTION = "fingerprint_outside"
PATCH_DOC_SITE_ID_RE = re.compile(r'<a id="([a-z0-9-]+)"></a>')

PATCH_DOC_RECORD_SCHEMAS = {
    "patches": {
        "rva": int, "len": int, "orig": str, "field_off": int,
        "field_w": int, "old": int, "new": int, "cat": str, "asm": str,
    },
    "table_refs": {
        "rva": int, "len": int, "disp_off": int, "orig": str, "asm": str,
    },
    "init_patches": {
        "rva": int, "len": int, "orig": str, "new": str,
        "cat": str, "asm": str,
    },
    "assignment_hook_sites": {
        "call_rva": int, "call_bytes": str, "call_target_rva": int,
        "setup_rva": int, "setup_bytes": str, "function_rva": int,
        "function_bytes": str, "writer_rva": int, "lock_call_rva": int,
        "unlock_call_rva": int,
    },
    "release_sites": {
        "rva": int, "len": int, "orig": str, "asm": str,
        "raw_patch_rva": int, "policy": str,
    },
    "excluded_literals": {
        "rva": int, "value": int, "cat": str, "asm": str, "why": str,
    },
    "excluded_shift11": {
        "rva": int, "source_rva": int, "source_disp": int, "why": str,
    },
}

PATCH_DOC_RAW_SCHEMAS = {
    "sidecar_read": {
        "rva": int, "len": int, "orig": str, "new": str, "cat": str,
        "asm": str, "source_rva": int, "shift_rva": int, "mode": str,
        "sidecar_disp": int,
    },
    "sidecar_write": {
        "rva": int, "len": int, "orig": str, "new": str, "cat": str,
        "asm": str, "clear_rva": int, "sidecar_disp": int,
    },
    "sidecar_release": {
        "rva": int, "len": int, "orig": str, "new": str, "cat": str,
        "asm": str, "clear_rva": int, "sidecar_disp": int,
    },
}


def _require_exact_mapping(value, schema: dict[str, type], context: str) -> None:
    if type(value) is not dict:
        raise ValueError(f"{context} is {type(value).__name__}, expected object")
    actual_keys = set(value)
    expected_keys = set(schema)
    if actual_keys != expected_keys:
        raise ValueError(
            f"{context} keys differ: got {sorted(actual_keys)}, "
            f"expected {sorted(expected_keys)}")
    for key, expected_type in schema.items():
        if type(value[key]) is not expected_type:
            raise ValueError(
                f"{context}.{key} is {type(value[key]).__name__}, "
                f"expected {expected_type.__name__}")


def _patch_doc_collection(profile: dict, path: tuple[str, ...], context: str) -> list:
    value = profile
    for part in path:
        if type(value) is not dict or part not in value:
            raise ValueError(f"{context} has no {'.'.join(path)} collection")
        value = value[part]
    if type(value) is not list:
        raise ValueError(f"{context}.{'.'.join(path)} is not an array")
    return value


def _independent_patch_doc_ids(profile: dict, tag: str) -> tuple[list[str], list[str]]:
    """Validate the exact JSON schema and independently derive documented IDs."""
    collection_roots = {
        path[0]
        for path, _prefix, _key in (
            *PATCH_DOC_MUTATION_COLLECTIONS, *PATCH_DOC_EVIDENCE_COLLECTIONS)
    } | PATCH_DOC_AUXILIARY_COLLECTIONS | {PATCH_DOC_FINGERPRINT_COLLECTION}
    expected_top_level = set(PATCH_DOC_PROFILE_SCALARS) | collection_roots
    actual_top_level = set(profile) if type(profile) is dict else set()
    if actual_top_level != expected_top_level:
        raise ValueError(
            f"{tag} profile keys differ: got {sorted(actual_top_level)}, "
            f"expected {sorted(expected_top_level)}")
    for key, expected_type in PATCH_DOC_PROFILE_SCALARS.items():
        if type(profile[key]) is not expected_type:
            raise ValueError(
                f"{tag}.{key} is {type(profile[key]).__name__}, "
                f"expected {expected_type.__name__}")

    regions = _patch_doc_collection(profile, ("regions",), tag)
    if not all(type(region) is list and len(region) == 2 and
               all(type(value) is int for value in region) for region in regions):
        raise ValueError(f"{tag}.regions is not an array of two-integer ranges")
    lea_displacements = _patch_doc_collection(profile, ("lea_disp_rvas",), tag)
    if not all(type(value) is int for value in lea_displacements):
        raise ValueError(f"{tag}.lea_disp_rvas contains a non-integer RVA")
    fingerprints = _patch_doc_collection(
        profile, (PATCH_DOC_FINGERPRINT_COLLECTION,), tag)
    if not all(type(value) is int for value in fingerprints):
        raise ValueError(f"{tag}.fingerprint_outside contains a non-integer RVA")

    _require_exact_mapping(
        profile["assignment_hooks"],
        {"helper_rva": int, "helper_bytes": str, "sites": list},
        f"{tag}.assignment_hooks")

    for collection_name in (
            "patches", "table_refs", "init_patches", "release_sites",
            "excluded_literals", "excluded_shift11"):
        records = _patch_doc_collection(profile, (collection_name,), tag)
        schema = PATCH_DOC_RECORD_SCHEMAS[collection_name]
        for index, record in enumerate(records):
            _require_exact_mapping(record, schema, f"{tag}.{collection_name}[{index}]")
    raw_patches = _patch_doc_collection(profile, ("raw_patches",), tag)
    for index, record in enumerate(raw_patches):
        if type(record) is not dict or type(record.get("cat")) is not str or \
                record["cat"] not in PATCH_DOC_RAW_SCHEMAS:
            raise ValueError(f"{tag}.raw_patches[{index}] has an unknown category/schema")
        _require_exact_mapping(
            record, PATCH_DOC_RAW_SCHEMAS[record["cat"]],
            f"{tag}.raw_patches[{index}]")
    for index, record in enumerate(profile["assignment_hooks"]["sites"]):
        _require_exact_mapping(
            record, PATCH_DOC_RECORD_SCHEMAS["assignment_hook_sites"],
            f"{tag}.assignment_hooks.sites[{index}]")
    expected_disp_rvas = sorted(
        record["rva"] + record["disp_off"] for record in profile["table_refs"])
    if lea_displacements != expected_disp_rvas:
        raise ValueError(
            f"{tag}.lea_disp_rvas is not the exact displacement-field projection "
            "of table_refs")

    def ids_for(mappings) -> list[str]:
        out: list[str] = []
        for path, prefix, key in mappings:
            records = _patch_doc_collection(profile, path, tag)
            out.extend(
                f"{prefix}-{record[key]:08x}"
                for record in sorted(records, key=lambda item: item[key]))
        return out

    mutation_ids = ids_for(PATCH_DOC_MUTATION_COLLECTIONS)
    evidence_ids = ids_for(PATCH_DOC_EVIDENCE_COLLECTIONS)
    evidence_ids.extend(
        f"fingerprint-outside-{rva:08x}" for rva in sorted(fingerprints))
    all_ids = [*mutation_ids, *evidence_ids]
    if len(all_ids) != len(set(all_ids)):
        raise ValueError(f"{tag} profile produces duplicate patch-document record IDs")
    return mutation_ids, evidence_ids


def _bytes15(value: str) -> bytes:
    raw = bytes.fromhex(value)
    if len(raw) > 15:
        raise ValueError("generated instruction exceeds the 15-byte x64 maximum")
    return raw.ljust(15, b"\0")


def compiled_array_blobs(profile: dict) -> dict[str, bytes]:
    """Serialize generated records with the exact MSVC x64 POD layout."""
    fields = b"".join(struct.pack(
        "<IBBBBII15sx", p["rva"], p["len"], p["field_off"], p["field_w"],
        CATS.index(p["cat"]), p["old"], p["new"], _bytes15(p["orig"]))
        for p in profile["patches"])
    byte_patches = b"".join(struct.pack(
        "<IBB15s15s", p["rva"], p["len"], CATS.index(p["cat"]),
        _bytes15(p["orig"]), _bytes15(p["new"]))
        for p in profile["raw_patches"])
    table_refs = b"".join(struct.pack(
        "<IBB15s3x", p["rva"], p["len"], p["disp_off"], _bytes15(p["orig"]))
        for p in profile["table_refs"])
    init_patches = b"".join(struct.pack(
        "<IBB15s15s", p["rva"], p["len"], CATS.index(p["cat"]),
        _bytes15(p["orig"]), _bytes15(p["new"]))
        for p in profile["init_patches"])
    releases = b"".join(struct.pack(
        "<IB15s", p["rva"], p["len"], _bytes15(p["orig"]))
        for p in profile["release_sites"])
    assignment_hooks = b"".join(struct.pack(
        "<II5s11s16s", p["call_rva"], p["function_rva"],
        bytes.fromhex(p["call_bytes"]), bytes.fromhex(p["setup_bytes"]),
        bytes.fromhex(p["function_bytes"]))
        for p in profile["assignment_hooks"]["sites"])
    return {
        "fields": fields,
        "byte patches": byte_patches,
        "table references": table_refs,
        "initialiser guards": init_patches,
        "release census": releases,
        "assignment-hook sites": assignment_hooks,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true",
                    help="verify generated profiles/header only; skip DLL/package freshness")
    a = ap.parse_args()
    ok = True
    if not a.offline:
        from addrlib import RUNTIMES

    def chk(cond: bool, msg: str) -> None:
        nonlocal ok
        print(("  OK   " if cond else "  FAIL ") + msg)
        ok = ok and bool(cond)

    hdr_path = ROOT / "src" / "PatchTable.g.h"
    hdr = io.open(hdr_path, encoding="utf-8").read()
    profiles: dict[str, dict] = {}

    for tag, exp_refs, exp_fields, exp_funcs, exp_readers, exp_writers, exp_releases, exp_excluded in EXPECTED:
        patch = json.loads((ROOT / "artifacts" / f"patch_{tag}.json").read_text())
        profiles[tag] = patch
        sites = json.loads((ROOT / "artifacts" / f"sites_{tag}.json").read_text())
        table = patch["table_rva"]
        print(f"== {tag}")

        exact_input = EXACT_NEW_RUNTIME_INPUTS.get(tag)
        if exact_input:
            chk(patch["exe_size"] == exact_input["exe_size"] and
                patch["exe_sha256"] == exact_input["exe_sha256"],
                "JSON is bound to the reviewed exact executable size and SHA-256")

        if not a.offline:
            exe = pathlib.Path(RUNTIMES[tag]["exe"])
            chk(exe.exists() and exe.stat().st_size == patch["exe_size"],
                "profile executable size matches the installed exact runtime")
            chk(exe.exists() and
                hashlib.sha256(exe.read_bytes()).hexdigest() == patch["exe_sha256"],
                "profile SHA-256 matches the installed exact runtime")
            if exact_input:
                db = pathlib.Path(RUNTIMES[tag]["db"])
                chk(db.exists() and db.stat().st_size == exact_input["db_size"] and
                    hashlib.sha256(db.read_bytes()).hexdigest() == exact_input["db_sha256"],
                    "Address Library input matches the reviewed exact size and SHA-256")

        chk(len(patch["table_refs"]) == exp_refs,
            f"{exp_refs} byte-exact table references (got {len(patch['table_refs'])})")
        chk(len(patch["patches"]) == exp_fields,
            f"{exp_fields} field rewrites (got {len(patch['patches'])})")
        chk({p["rva"] for p in patch["patches"] if p["cat"] == "table_bytes"} ==
            TABLE_BYTES_RVAS[tag],
            "only the two reviewed table-byte initializers are rewritten")
        chk({(p["rva"], p["value"]) for p in patch.get("excluded_literals", [])} ==
            EXCLUDED_LITERALS[tag],
            "all table-bytes-shaped non-handle literals are explicitly reviewed")
        chk(len(patch["fingerprint_outside"]) == 0,
            "0 age-mask fingerprints outside the patched regions")

        tabfns = {f["func_rva"] for f in sites["functions"]
                  if any(d[1] == table for d in f["data"])}
        chk(len(tabfns) == exp_funcs,
            f"{exp_funcs} .pdata functions reference the table (got {len(tabfns)})")

        fields_block = hdr.split(f"k{tag}Fields[]")[1].split("};")[0]
        byte_block = hdr.split(f"k{tag}BytePatches[]")[1].split("};")[0]
        refs_block = hdr.split(f"k{tag}TableRefs[]")[1].split("};")[0]
        init_block = hdr.split(f"k{tag}InitPatches[]")[1].split("};")[0]
        release_block = hdr.split(f"k{tag}ReleaseSites[]")[1].split("};")[0]
        assignment_block = hdr.split(f"k{tag}AssignmentHookSites[]")[1].split("};")[0]
        n_fields = len(re.findall(r"\{ 0x[0-9a-f]{8}, \d+, \d+, \d+, \d+,", fields_block))
        n_bytes = len(re.findall(r"\{ 0x[0-9a-f]{8}, \d+, \d+, \{", byte_block))
        n_refs = len(re.findall(r"\{ 0x[0-9a-f]{8}, \d+, \d+, \{", refs_block))
        n_init = len(re.findall(r"\{ 0x[0-9a-f]{8}, \d+, \d+, \{", init_block))
        n_releases = len(re.findall(r"\{ 0x[0-9a-f]{8}, \d+, \{", release_block))
        n_assignment = len(re.findall(
            r"\{ 0x[0-9a-f]{8}, 0x[0-9a-f]{8}, \{ (?:0x[0-9a-f]{2}, ){4}0x[0-9a-f]{2} \}, \{",
            assignment_block))
        chk(n_fields == len(patch["patches"]),
            f"header k{tag}Fields matches the JSON ({n_fields})")
        chk(n_bytes == len(patch["raw_patches"]),
            f"header k{tag}BytePatches matches the JSON ({n_bytes})")
        chk(n_refs == len(patch["table_refs"]),
            f"header k{tag}TableRefs matches the JSON ({n_refs})")
        chk(n_init == len(patch["init_patches"]),
            f"header k{tag}InitPatches matches the JSON ({n_init})")
        chk(n_releases == len(patch["release_sites"]),
            f"header k{tag}ReleaseSites matches the JSON ({n_releases})")
        chk(n_assignment == len(patch.get("assignment_hooks", {}).get("sites", [])),
            f"header k{tag}AssignmentHookSites matches the JSON ({n_assignment})")

        expected_assignment = ASSIGNMENT_HOOKS[tag]
        assignment = patch.get("assignment_hooks", {})
        assignment_sites = assignment.get("sites", [])
        actual_assignment = tuple(
            (p.get("call_rva"), p.get("call_bytes"), p.get("function_rva"),
             p.get("writer_rva"), p.get("lock_call_rva"), p.get("unlock_call_rva"))
            for p in assignment_sites)
        chk(assignment.get("helper_rva") == expected_assignment["helper_rva"] and
            assignment.get("helper_bytes") == expected_assignment["helper_bytes"],
            "assignment helper RVA and 16-byte fingerprint match the reviewed runtime")
        chk(actual_assignment == expected_assignment["sites"],
            "all five assignment call bytes, owners, writers, and lock brackets are exact")
        chk(all(p.get("function_bytes") == ASSIGNMENT_OWNER_BYTES and
                len(bytes.fromhex(p.get("function_bytes", ""))) == 16
                for p in assignment_sites),
            "all five assignment owners have the reviewed 16-byte entry fingerprint")
        chk(len(assignment_sites) == 5 and
            all(p.get("setup_rva") == p.get("call_rva") - 11 and
                p.get("setup_bytes") == expected_assignment["setup_bytes"]
                for p in assignment_sites),
            "five exact 11-byte assignment ABI setup windows precede their calls")
        chk(all(p.get("call_target_rva") == assignment.get("helper_rva") and
                len(bytes.fromhex(p.get("call_bytes", ""))) == 5 and
                bytes.fromhex(p.get("call_bytes", ""))[:1] == b"\xE8"
                for p in assignment_sites),
            "all assignment sites are rel32 calls to the one shared helper")
        chk({p.get("writer_rva") for p in assignment_sites} ==
            {p["rva"] for p in patch["raw_patches"] if p["cat"] == "sidecar_write"},
            "assignment hooks cover every allocation publisher exactly once")
        cap_write_bytes: set[int] = set()
        for p in patch["patches"]:
            cap_write_bytes.update(range(
                p["rva"] + p["field_off"],
                p["rva"] + p["field_off"] + p["field_w"]))
        for p in patch["raw_patches"] + patch["init_patches"]:
            cap_write_bytes.update(range(p["rva"], p["rva"] + p["len"]))
        for p in patch["table_refs"]:
            cap_write_bytes.update(range(
                p["rva"] + p["disp_off"], p["rva"] + p["disp_off"] + 4))
        assignment_guard_bytes = set(range(
            assignment.get("helper_rva", 0), assignment.get("helper_rva", 0) + 16))
        for p in assignment_sites:
            assignment_guard_bytes.update(range(p["call_rva"] - 11, p["call_rva"] + 5))
            assignment_guard_bytes.update(range(
                p["function_rva"], p["function_rva"] + 16))
        chk(not (cap_write_bytes & assignment_guard_bytes),
            "assignment owners/setup/calls/helper fingerprint do not overlap any cap rewrite")

        readers = [p for p in patch["raw_patches"] if p["cat"] == "sidecar_read"]
        writers = [p for p in patch["raw_patches"] if p["cat"] == "sidecar_write"]
        release_patches = [p for p in patch["raw_patches"] if p["cat"] == "sidecar_release"]
        chk(len(readers) == exp_readers, f"{exp_readers} sidecar readers (got {len(readers)})")
        chk(len(writers) == exp_writers, f"{exp_writers} sidecar writers (got {len(writers)})")
        chk(len(patch["release_sites"]) == exp_releases,
            f"{exp_releases} audited release sites (got {len(patch['release_sites'])})")
        chk(len(release_patches) == exp_releases,
            f"{exp_releases} sidecar release byte patches (got {len(release_patches)})")
        chk({p["clear_rva"] for p in release_patches} == {p["rva"] for p in patch["release_sites"]},
            "every audited release clear is covered exactly once")
        chk(len(patch["excluded_shift11"]) == exp_excluded,
            f"{exp_excluded} reviewed non-handle SHR11 exclusions (got {len(patch['excluded_shift11'])})")
        chk(all(p.get("source_disp") == 0x10 for p in patch["excluded_shift11"]),
            "every excluded SHR11 is sourced from the TESForm flag dword at +0x10")
        expected_init = {
            "SE": {
                0x000125E3: "9090909090",
                0x0001260D: "9090909090",
                0x005AE243: "9090909090",
            },
            "AE": {
                0x00012933: "9090909090",
                0x0001295D: "9090909090",
                0x00640458: "e9560000009090",
            },
            "GOG": {
                0x00012933: "9090909090",
                0x0001295D: "9090909090",
                0x006426B8: "e9560000009090",
            },
            "VR": {
                0x000126F3: "9090909090",
                0x0001271D: "9090909090",
                0x005B5AC5: "9090909090",
            },
        }[tag]
        chk({p["rva"]: p["new"] for p in patch["init_patches"]} == expected_init,
            "three exact guards cover C++ static and subsequent pool initialization")
        chk((patch["lock_write_rva"], patch["unlock_write_rva"]) == LOCKS[tag],
            "write-lock helper metadata matches the reviewed runtime RVAs")
        chk(patch["raised_entries"] == 0x400000 and patch["entry_size"] == 0x10,
            "profile allocates 4,194,304 16-byte entries (64 MiB)")

        chk(not [p for p in patch["patches"] if p["old"] in OBJECT_SIDE],
            "no object-side reference-count field is rewritten")
        chk(all(p["field_off"] + p["field_w"] <= p["len"] for p in patch["patches"]),
            "every rewritten field lies inside its instruction")
        chk(all(p["len"] == len(bytes.fromhex(p["orig"])) == len(bytes.fromhex(p["new"])) <= 15
                for p in patch["raw_patches"] + patch["init_patches"]),
            "every arbitrary byte rewrite is exact, same-length, and <=15 bytes")
        chk(all(p["len"] == len(bytes.fromhex(p["orig"])) <= 15 and
                p["disp_off"] + 4 <= p["len"] for p in patch["table_refs"]),
            "every table reference carries a complete instruction and in-bounds disp32")

    print("== generated header")
    chk(hdr == render_header(profiles),
        "PatchTable.g.h is the exact deterministic rendering of all four JSON profiles")

    print("== generated patch documentation")
    independent_document_ids: dict[str, tuple[list[str], list[str]]] = {}
    for tag, _label, _version, _filename in PATCH_DOC_RUNTIME_SPECS:
        try:
            independent_document_ids[tag] = _independent_patch_doc_ids(profiles[tag], tag)
        except ValueError as exc:
            chk(False, f"{tag} patch-document JSON schema is exact: {exc}")
            independent_document_ids[tag] = ([], [])
        else:
            chk(True,
                f"{tag} profile has the exact independently mapped patch-document schema")
    expected_documents = render_patch_docs(profiles)
    expected_document_names = {
        "README.md", *(filename for _tag, _label, _version, filename
                       in PATCH_DOC_RUNTIME_SPECS)
    }
    chk(set(expected_documents) == expected_document_names,
        "patch-document renderer emits the exact independent runtime file set")
    patch_doc_root = ROOT / "docs" / "patch-sites"
    actual_names = {
        path.name for path in patch_doc_root.glob("*.md")
        if path.is_file()
    } if patch_doc_root.is_dir() else set()
    chk(actual_names == expected_document_names,
        "patch-site directory contains exactly the five generated Markdown files")
    actual_documents: dict[str, str] = {}
    for relative, expected_text in expected_documents.items():
        path = patch_doc_root / relative
        actual_text = path.read_text(encoding="utf-8") if path.is_file() else ""
        actual_documents[relative] = actual_text
        chk(actual_text == expected_text,
            f"{relative} is the exact deterministic rendering of the JSON profiles")
    for tag, _label, _version, filename in PATCH_DOC_RUNTIME_SPECS:
        expected_mutations, expected_evidence = independent_document_ids[tag]
        expected_ids = [*expected_mutations, *expected_evidence]
        actual_ids = PATCH_DOC_SITE_ID_RE.findall(actual_documents.get(filename, ""))
        actual_mutations = actual_ids[:len(expected_mutations)]
        chk(actual_ids == expected_ids and len(actual_ids) == len(set(actual_ids)),
            f"{tag} document renders every mutation, release alias, and exclusion exactly once")
        chk(actual_mutations == expected_mutations,
            f"{tag} document has exact one-to-one coverage of all "
            f"{len(expected_mutations)} executable mutation records")

    source_dir = ROOT / "src"
    maintained_source_paths = sorted(
        [*source_dir.glob("*.cpp"), *source_dir.glob("*.h")],
        key=lambda path: path.name.casefold())
    maintained_source = "\n".join(
        path.read_text(encoding="utf-8") for path in maintained_source_paths)
    main_source = (source_dir / "main.cpp").read_text(encoding="utf-8")
    runtime_source = (source_dir / "RuntimeDetection.cpp").read_text(encoding="utf-8")
    chk(runtime_source.count("ReadProductVersion(executable, version)") == 1 and
        runtime_source.count("ReadFixedFileVersion(versionPath, fileVersion)") == 1 and
        maintained_source.count("LogEngineFixesCompatibility();") == 1 and
        "ReadProductVersion" not in main_source and
        "VerifyEngineFixes" not in maintained_source,
        "RuntimeDetection owns ProductVersion and informational Engine Fixes handling")
    stock_source = (ROOT / "src" / "StockProbe.cpp").read_text(encoding="utf-8")
    stress_source = (ROOT / "src" / "StressTest.cpp").read_text(encoding="utf-8")
    chk("RUNTIME_VERSION(1, 6, 1179, 1)" in main_source and
        "RUNTIME_VERSION(1, 6, 1179, 0)" not in
        main_source[main_source.index("SKSEPlugin_Version"):],
        "production SKSE metadata advertises GOG's storefront-tagged 1.6.1179.1 runtime")
    chk("STOCK_RUNTIME_VERSION(1, 6, 1179, 1)" in stock_source,
        "stock-probe SKSE metadata advertises GOG's storefront-tagged 1.6.1179.1 runtime")
    chk("PackRuntime(1, 6, 1179, 1)" in stress_source,
        "verbose/stress diagnostics select GOG using SKSE's storefront-tagged runtime")
    chk(stock_source.count("a_runtime == 0x010649B1u") == 2 and
        "a_runtime = 0x010649B0u;" in stock_source,
        "stock probe logs to the GOG folder and normalizes SKSE's tag for patch-profile lookup")

    if not a.offline:
        print("== package")
        dll = ROOT / "build" / "Release" / "SkyrimHandleCapRaise.dll"
        pkg = ROOT / "package" / "Data" / "SKSE" / "Plugins" / "SkyrimHandleCapRaise.dll"
        root_ini = ROOT / "SkyrimHandleCapRaise.ini"
        pkg_ini = ROOT / "package" / "Data" / "SKSE" / "Plugins" / "SkyrimHandleCapRaise.ini"
        dll_data = dll.read_bytes() if dll.exists() else b""
        pkg_data = pkg.read_bytes() if pkg.exists() else b""
        chk(bool(dll_data) and hashlib.sha256(dll_data).digest() ==
            hashlib.sha256(pkg_data).digest(),
            "staged DLL SHA-256 matches the build output")
        chk(root_ini.exists() and pkg_ini.exists() and
            hashlib.sha256(root_ini.read_bytes()).digest() ==
            hashlib.sha256(pkg_ini.read_bytes()).digest(),
            "staged INI SHA-256 matches the safe root configuration")
        config = configparser.ConfigParser(strict=True)
        config.read(root_ini, encoding="utf-8")
        chk(config.sections() == ["General"] and not config.defaults() and
            set(config.options("General")) ==
            {"verboselogging", "generationwrapdetection", "samplesize"} and
            config.getint("General", "VerboseLogging") == 0 and
            config.getint("General", "GenerationWrapDetection") == 1 and
            config.getint("General", "SampleSize") == 16,
            "shipping INI exposes exactly VerboseLogging=0, "
            "GenerationWrapDetection=1, and SampleSize=16")
        archive = ROOT / "package" / "Data" / "Pointer Handle Limit Fix.zip"
        archive_names: list[str] = []
        archive_payloads: dict[str, bytes] = {}
        try:
            with zipfile.ZipFile(archive, "r") as package_zip:
                infos = package_zip.infolist()
                archive_names = [x.filename.replace("\\", "/") for x in infos]
                archive_payloads = {
                    x.filename.replace("\\", "/"): package_zip.read(x)
                    for x in infos if not x.is_dir()
                }
        except (OSError, zipfile.BadZipFile, KeyError):
            infos = []
        expected_archive_names = [
            "SKSE/Plugins/SkyrimHandleCapRaise.dll",
            "SKSE/Plugins/SkyrimHandleCapRaise.ini",
        ]
        chk(len(infos) == 2 and sorted(archive_names) == sorted(expected_archive_names) and
            len(set(archive_names)) == 2,
            "release ZIP contains exactly the DLL and INI paths once, with no extra entries")
        chk(archive_payloads.get(expected_archive_names[0], b"") == pkg_data and
            archive_payloads.get(expected_archive_names[1], b"") == pkg_ini.read_bytes(),
            "release ZIP DLL/INI payloads exactly match the staged package files")
        build_inputs = [*maintained_source_paths, ROOT / "CMakeLists.txt"]
        newest_input = max(path.stat().st_mtime for path in build_inputs)
        chk(dll.exists() and dll.stat().st_mtime >= newest_input,
            "DLL is newer than every maintained src/*.cpp, src/*.h, and CMake input")
        for tag, *_ in EXPECTED:
            for label, blob in compiled_array_blobs(profiles[tag]).items():
                chk(bool(blob) and dll_data.count(blob) == 1,
                    f"compiled DLL contains the exact {tag} {label} array once")

    print()
    print("ALL CONSISTENT" if ok else "INCONSISTENCIES FOUND")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
