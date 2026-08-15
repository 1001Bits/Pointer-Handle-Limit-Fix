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

import pefile

from gen_cpp import CATS, render as render_header
from gen_patch_docs import render_all as render_patch_docs

# (runtime, table references, field rewrites, .pdata functions referencing
#  the table, core executable mutations).  Core mutations are the
#  field rewrites, table-reference displacements, three initializer guards,
#  and seven player-reservation hooks (five selectors, release, constructor).
#  Five mandatory assignment-guard redirects are then added to obtain the
#  complete executable mutation count.
EXPECTED = (
    ("SE", 96, 293, 73, 399),
    ("AE", 115, 394, 98, 519),
    ("GOG", 115, 394, 98, 519),
    ("VR", 102, 307, 79, 419),
)

EXPECTED_BY_TAG = {row[0]: row[1:] for row in EXPECTED}
MANDATORY_ASSIGNMENT_REDIRECTS = 5
EXPECTED_TOTAL_MUTATIONS = {
    "SE": 404,
    "AE": 524,
    "GOG": 524,
    "VR": 424,
}
EXPECTED_AGGREGATE_CORE_MUTATIONS = 1856
EXPECTED_AGGREGATE_TOTAL_MUTATIONS = 1876

# This is the complete and exclusive set of stock immediate rewrites for the
# compatibility-first layout.  In particular, bit 26 is unchanged: Skyrim's
# table-only in-use flag remains 0x04000000 and its clear mask remains
# 0xFBFFFFFF.  No object-side or arbitrary-byte sidecar rewrite is needed.
FIELD_REWRITE_CONTRACT = {
    "index_mask": (0x000FFFFF, 0x001FFFFF, 4),
    "age_mask": (0x03F00000, 0x03E00000, 4),
    "age_inc_or_count": (0x00100000, 0x00200000, 4),
    "table_bytes": (0x01000000, 0x02000000, 4),
    "clear_age": (0xFC0FFFFF, 0xFC1FFFFF, 4),
    "clear_next": (0xFFF00000, 0xFFE00000, 4),
}

RETIRED_PROFILE_KEYS = {
    "raw_patches", "release_sites", "excluded_shift11",
}

INDEX_BITS = 21
AGE_BITS = 5
INDEX_MASK = 0x001FFFFF
AGE_MASK = 0x03E00000
AGE_INCREMENT = 0x00200000
IN_USE_MASK = 0x04000000
CLEAR_IN_USE_MASK = 0xFBFFFFFF
CLEAR_AGE_MASK = 0xFC1FFFFF
CLEAR_NEXT_MASK = 0xFFE00000
PLAYER_SLOT = 0x00100000
PLAYER_DETACHED_BITS = 0x03F00000
PLAYER_LIVE_STATE_MASK = 0x07E00000
RAISED_ENTRIES = 0x00200000
TABLE_BYTES = 0x02000000

# Compiled SKSE loader ABI contract.  These values are read from the exported
# PE data object; source spellings are deliberately not a trust anchor.
SKSE_EXPORT_NAMES = frozenset({
    "SKSEPlugin_Load", "SKSEPlugin_Query", "SKSEPlugin_Version",
})
SKSE_VERSION_DATA_SIZE = 0x350
EXPECTED_SKSE_DATA_VERSION = 1
EXPECTED_SKSE_PLUGIN_VERSION = 0x020200
EXPECTED_SKSE_NAME = "SkyrimHandleCapRaise"
EXPECTED_SKSE_AUTHOR = "Skyrim Handle Audit"
EXPECTED_SKSE_VERSION_INDEPENDENCE_EX = 0
# SKSE names this field versionIndependence; CommonLib exposes the same loader
# bit field as address independence.  Zero is required because this plugin
# advertises an exact compatible-runtime list rather than a version-independent
# Address Library/signature-scanning claim.
EXPECTED_SKSE_ADDRESS_INDEPENDENCE = 0
EXPECTED_SKSE_RUNTIMES = (
    0x01050610,  # Skyrim SE 1.5.97.0
    0x01064920,  # Skyrim AE 1.6.1170.0
    0x010649B1,  # Skyrim GOG 1.6.1179.1 (storefront tag is required)
    0x010400F0,  # Skyrim VR 1.4.15.0
    *([0] * 12),
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

# Independent trust anchors for every generation input. Keeping these outside
# the generated JSON prevents a locally substituted executable/database pair
# plus regenerated JSON/header/docs from redefining a supported runtime.
EXACT_RUNTIME_INPUTS = {
    "SE": {
        "exe_size": 34_769_792,
        "exe_sha256": "5666e1bddd01bcab31ecf11691ef1a3f22e1541af79f2bc0e55318533cfe5d12",
        "db_size": 1_490_796,
        "db_sha256": "1d7530d001139ca58f462ea0210a8055868159057ba8b5ebc624fc5e9c4f5e9a",
    },
    "AE": {
        "exe_size": 36_950_016,
        "exe_sha256": "80c1ea737d33c6bfac09b101b8d77ab0f9f6630128c3ed052f9d945bed54e7e4",
        "db_size": 795_129,
        "db_sha256": "c4093c569a3c83b26587f4b9ea4c55de9ae6e73b84a2af9fb3fbd30e2fe0d452",
    },
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


def _validate_exact_runtime_profile_input(patch: dict, tag: str) -> None:
    exact = EXACT_RUNTIME_INPUTS.get(tag)
    if exact is None:
        raise ValueError(f"no independent generation-input pin for {tag}")
    if (type(patch.get("exe_size")) is not int or
            patch["exe_size"] != exact["exe_size"] or
            type(patch.get("exe_sha256")) is not str or
            patch["exe_sha256"] != exact["exe_sha256"]):
        raise ValueError(
            f"{tag} JSON is not bound to the independently reviewed exact executable"
        )


def _validate_live_lifecycle_failure_contract(source: str) -> None:
    if type(source) is not str or not source:
        raise ValueError("live lifecycle verifier source is empty")
    if re.search(
            r'FORBIDDEN_LOG_TEXT\s*=\s*\(\s*"CRITICAL:",', source) is None:
        raise ValueError(
            'live lifecycle verifier does not generically forbid "CRITICAL:"')
    if '"CRITICAL: HANDLE GENERATION WRAP DETECTED:",' in source:
        raise ValueError(
            "live lifecycle verifier still uses the retired narrow CRITICAL marker")
    if ("for forbidden in FORBIDDEN_LOG_TEXT:" not in source or
            "if forbidden in text:" not in source or
            'errors.append(f"failure marker present: {forbidden}")' not in source):
        raise ValueError(
            "live lifecycle verifier does not apply every generic forbidden marker")


def _validate_no_wrap_source_contract(
        main_source: str,
        diagnostic_source: str,
        diagnostic_header: str,
        generation_header: str,
        table_monitor_source: str,
        player_slot_header: str) -> None:
    """Fail closed if production source can commit without the no-wrap guard."""

    sources = (
        main_source, diagnostic_source, diagnostic_header, generation_header,
        table_monitor_source, player_slot_header,
    )
    if not all(type(source) is str and source for source in sources):
        raise ValueError("no-wrap source contract received an empty source file")

    prepared = main_source.find("bool OnTablePrepared(")
    committed = main_source.find("bool OnCommittedWhileManagerLocked(")
    aborted = main_source.find("void OnPatchAborted(")
    if not (0 <= prepared < committed < aborted):
        raise ValueError("mandatory guard lifecycle callbacks are missing or reordered")
    prepare_body = main_source[prepared:committed]
    commit_body = main_source[committed:aborted]
    prepare_returns = re.findall(r"\breturn\s+([^;]+);", prepare_body)
    if not (
            "if (!state.settings.generationWrapDetection)" in prepare_body and
            "GenerationWrapDetection=0 is incompatible with" in prepare_body and
            "cap raise refused." in prepare_body and
            re.search(r"diagnostic::Prepare\(\s*a_runtime,\s*a_table,\s*true,",
                      prepare_body) is not None and
            prepare_body.find("return false;") <
                prepare_body.find("diagnostic::Prepare(") and
            prepare_returns == ["false", "state.diagnosticPrepared"] and
            prepare_body.count("state.settings.generationWrapDetection") == 1 and
            prepare_body.count(
                "state.diagnosticPrepared = diagnostic::Prepare(") == 1 and
            "goto " not in prepare_body):
        raise ValueError(
            "GenerationWrapDetection=0 refusal/prepare return structure changed")
    exact_install = "state.diagnosticInstalled = diagnostic::Install();"
    install_pos = commit_body.find(exact_install)
    reporter_pos = commit_body.find("monitor::Start(")
    commit_returns = re.findall(r"\breturn\s+([^;]+);", commit_body)
    if not (0 <= install_pos < reporter_pos and
            commit_body.count(exact_install) == 1 and
            commit_body.count("diagnostic::Install()") == 1 and
            commit_body.count("state.settings.generationWrapDetection") == 1 and
            "if (!state.diagnosticInstalled)" in commit_body and
            "cap raise will roll back." in commit_body and
            commit_returns == ["false", "false", "true"] and
            commit_body.count("return true;") == 1 and
            commit_body.rfind("return true;") > reporter_pos and
            "return false;" in commit_body[install_pos:reporter_pos] and
            "goto " not in commit_body):
        raise ValueError(
            "mandatory assignment guard exact diagnostic::Install assignment "
            "or commit return structure changed")
    if "diagnostic::CancelPrepared();" not in main_source[aborted:]:
        raise ValueError("prepared guard resources are not cancelled on transaction abort")

    abi_tokens = (
        "using AssignmentHelperFunction = void* (__fastcall*)(void**, void*);",
        "void* __fastcall AssignmentHelperHook(",
        "VerifyAssignmentHookTargets(*g_profile, true)",
        "a_profile.assignmentHookSiteCount != 5",
        "site.functionBytes",
        "site.setupBytes",
        "site.callBytes",
        "a_profile.assignmentHelperBytes",
    )
    if not all(token in diagnostic_source for token in abi_tokens):
        raise ValueError(
            "assignment helper ABI or exact owner/setup/call/helper authentication is missing")

    hook_begin = diagnostic_source.find("void* __fastcall AssignmentHelperHook(")
    hook_end = diagnostic_source.find("[[nodiscard]] bool TextContains(", hook_begin)
    hook_body = diagnostic_source[hook_begin:hook_end]
    prepare_pos = hook_body.find("PrepareAssignment(a_destination, a_subobject)")
    publisher_pos = hook_body.find("original(a_destination, a_subobject)")
    commit_pos = hook_body.find("CommitAssignment(pending")
    publisher_calls = re.findall(
        r"(?:\(\s*\*\s*)?original(?:\s*\))?\s*\(\s*"
        r"a_destination\s*,\s*a_subobject\s*\)", hook_body)
    hook_returns = re.findall(r"\breturn\s+([^;]+);", hook_body)
    exact_hook_tail = re.search(
        r"const\s+PendingAssignment\s+pending\s*=\s*"
        r"PrepareAssignment\(\s*a_destination\s*,\s*a_subobject\s*\)\s*;\s*"
        r"void\*\s+const\s+result\s*=\s*"
        r"original\(\s*a_destination\s*,\s*a_subobject\s*\)\s*;\s*"
        r"CommitAssignment\(\s*pending\s*,\s*a_destination\s*,\s*"
        r"a_subobject\s*,\s*result\s*\)\s*;\s*"
        r"return\s+result\s*;\s*\}\s*$",
        hook_body) is not None
    if not (0 <= prepare_pos < publisher_pos < commit_pos and
            len(publisher_calls) == 1 and hook_returns == ["result"] and
            hook_body.count("CommitAssignment(") == 1 and
            exact_hook_tail and "goto " not in hook_body):
        raise ValueError(
            "assignment hook no longer has one guarded stock publisher, "
            "one direct successful commit, and one final return")

    prepare_assignment_begin = diagnostic_source.find(
        "[[nodiscard]] PendingAssignment PrepareAssignment(")
    prepare_assignment_end = diagnostic_source.find(
        "void CommitAssignment(", prepare_assignment_begin)
    prepare_assignment_body = diagnostic_source[
        prepare_assignment_begin:prepare_assignment_end]
    assignment_returns = [
        re.sub(r"\s+", " ", expression).strip()
        for expression in re.findall(
            r"\breturn\s+([^;]+);", prepare_assignment_body)
    ]
    direct_repeat_stop = re.search(
        r"if\s*\(\s*transition\.abaWrap\s*\)\s*\{\s*"
        r"PreventRepeatedGeneration\(\s*index\s*,\s*bits\s*,\s*"
        r"priorAssignments\s*\)\s*;\s*\}",
        prepare_assignment_body) is not None
    exact_observation = re.search(
        r"generation::ObserveAssignment\(\s*priorAssignments\s*,\s*"
        r"generation::GenerationFromEntryBits\(\s*bits\s*\)\s*\)\s*;",
        prepare_assignment_body) is not None
    player_branch = prepare_assignment_body.find(
        "if (index == player_slot::kIndex)")
    ordinary_counter = prepare_assignment_body.find(
        "LoadAssignmentCount(index)")
    if not (
            0 <= prepare_assignment_begin < prepare_assignment_end and
            assignment_returns == [
                "{ index, bits, {}, true }",
                "{ index, bits, transition, false }",
            ] and
            prepare_assignment_body.count(
                "generation::ObserveAssignment(") == 1 and
            exact_observation and
            prepare_assignment_body.count(
                "if (index == player_slot::kIndex)") == 1 and
            0 <= player_branch < ordinary_counter and
            "if (!player_slot::HasLiveGenerationZeroState(bits) ||" in
                prepare_assignment_body and
            "handle != player_slot::kVanillaRawHandle" in
                prepare_assignment_body and
            prepare_assignment_body.count("transition.abaWrap") == 1 and
            direct_repeat_stop and "goto " not in prepare_assignment_body):
        raise ValueError(
            "ordinary assignment return structure, exact entry-generation "
            "observation, or direct repeated-generation fail-stop changed")

    install_begin = diagnostic_source.find("bool Install() noexcept")
    install_end = diagnostic_source.find("bool IsActive() noexcept", install_begin)
    install_body = diagnostic_source[install_begin:install_end]
    original_pos = install_body.find(
        "g_originalAssignmentHelper.store(original, std::memory_order_release)")
    writable_pos = install_body.find("VirtualProtect(")
    redirect_pos = install_body.find("std::memcpy(reinterpret_cast<void*>(")
    active_pos = install_body.find(
        "g_generationDetectorActive.store(true, std::memory_order_release)")
    install_returns = re.findall(r"\breturn\s+([^;]+);", install_body)
    direct_activation = re.search(
        r"\n\s*g_generationDetectorActive\.store\(\s*true\s*,\s*"
        r"std::memory_order_release\s*\)\s*;\s*\n\s*Log\(",
        install_body) is not None
    if not (0 <= original_pos < writable_pos < redirect_pos < active_pos and
            install_returns == ["false", "false", "false", "false", "true"] and
            install_body.count(
                "index < g_profile->assignmentHookSiteCount; ++index") == 2 and
            direct_activation and install_body.rstrip().endswith(
                "return true;\n    }")):
        raise ValueError(
            "stock assignment helper is not published before redirect "
            "writes/activation, or guard Install no longer has exact "
            "refusal/success structure and two all-site passes")
    if (install_body.count("RestoreAssignmentCallsOrStop(*g_profile);") < 2 or
            "OriginalAssignmentCallsMatch" not in diagnostic_source or
            "g_originalAssignmentHelper.store(nullptr" not in install_body):
        raise ValueError(
            "assignment redirect failure no longer restores all stock calls and helper state")

    original_calls_begin = diagnostic_source.find(
        "[[nodiscard]] bool OriginalAssignmentCallsMatch(")
    restore_begin = diagnostic_source.find(
        "void RestoreAssignmentCallsOrStop(", original_calls_begin)
    restore_end = diagnostic_source.find(
        "struct CurrentReferenceSnapshot", restore_begin)
    original_calls_body = re.sub(
        r"\s+", " ", diagnostic_source[
            original_calls_begin:restore_begin]).strip()
    restore_body = re.sub(
        r"\s+", " ", diagnostic_source[restore_begin:restore_end]).strip()
    expected_original_calls = (
        "[[nodiscard]] bool OriginalAssignmentCallsMatch( const Profile& "
        "a_profile) noexcept { for (std::uint32_t index = 0; index < "
        "a_profile.assignmentHookSiteCount; ++index) { const "
        "AssignmentHookSite& site = a_profile.assignmentHookSites[index]; if "
        "(std::memcmp(reinterpret_cast<const void*>( g_runtime.imageBase + "
        "site.callRva), site.callBytes, sizeof(site.callBytes)) != 0) { return "
        "false; } } return true; }"
    )
    expected_restore = (
        "void RestoreAssignmentCallsOrStop( const Profile& a_profile) noexcept "
        "{ for (std::uint32_t index = 0; index < "
        "a_profile.assignmentHookSiteCount; ++index) { const "
        "AssignmentHookSite& site = a_profile.assignmentHookSites[index]; "
        "std::memcpy(reinterpret_cast<void*>( g_runtime.imageBase + "
        "site.callRva), site.callBytes, sizeof(site.callBytes)); } if "
        "(!OriginalAssignmentCallsMatch(a_profile) || "
        "!FlushInstructionCache(GetCurrentProcess(), g_runtime.text.begin, "
        "g_runtime.text.size)) { FatalAssignmentHookRollback(); } }"
    )
    if not (
            0 <= original_calls_begin < restore_begin < restore_end and
            original_calls_body == expected_original_calls and
            restore_body == expected_restore):
        raise ValueError(
            "all-five-call rollback no longer byte-restores, verifies, "
            "flushes, and fail-stops exactly")

    rollback_stop_begin = diagnostic_source.find(
        "[[noreturn]] void FatalAssignmentHookRollback()")
    rollback_stop_end = diagnostic_source.find(
        "[[nodiscard]] bool OriginalAssignmentCallsMatch(", rollback_stop_begin)
    rollback_stop_body = diagnostic_source[
        rollback_stop_begin:rollback_stop_end]
    if not (
            re.search(
                r"\n\s*TerminateProcess\(\s*GetCurrentProcess\(\)\s*,\s*"
                r"0x53484744u\s*\)\s*;\s*\n\s*"
                r"ExitProcess\(\s*0x44u\s*\)\s*;\s*\}\s*$",
                rollback_stop_body) is not None and
            re.search(
                r"(?m)^\s*return(?:\s+[^;]+)?;\s*$",
                rollback_stop_body) is None and
            "goto " not in rollback_stop_body):
        raise ValueError("assignment-call rollback fatal path no longer exits directly")

    load_begin = diagnostic_source.find(
        "[[nodiscard]] std::uint32_t LoadAssignmentCount(")
    store_begin = diagnostic_source.find(
        "void StoreAssignmentCount(", load_begin)
    hottest_begin = diagnostic_source.find("void UpdateHottest(", store_begin)
    hottest_end = diagnostic_source.find(
        "[[noreturn]] void TerminateForAssignmentGuard()", hottest_begin)
    if not (0 <= load_begin < store_begin < hottest_begin < hottest_end):
        raise ValueError("exact per-slot counter/high-water functions are missing")
    load_body = diagnostic_source[load_begin:store_begin]
    store_body = diagnostic_source[store_begin:hottest_begin]
    hottest_body = diagnostic_source[hottest_begin:hottest_end]
    exact_load = re.fullmatch(
        r"\s*\[\[nodiscard\]\]\s+std::uint32_t\s+LoadAssignmentCount\(\s*"
        r"std::uint32_t\s+a_index\s*\)\s+noexcept\s*\{\s*"
        r"std::atomic_ref<std::uint32_t>\s+counter\(\s*"
        r"g_slotAssignments\[a_index\]\s*\)\s*;\s*"
        r"return\s+counter\.load\(\s*std::memory_order_acquire\s*\)\s*;\s*"
        r"\}\s*",
        load_body) is not None
    exact_store = re.fullmatch(
        r"\s*void\s+StoreAssignmentCount\(\s*"
        r"std::uint32_t\s+a_index\s*,\s*std::uint32_t\s+a_count\s*\)\s*"
        r"noexcept\s*\{\s*std::atomic_ref<std::uint32_t>\s+counter\(\s*"
        r"g_slotAssignments\[a_index\]\s*\)\s*;\s*"
        r"counter\.store\(\s*a_count\s*,\s*std::memory_order_release\s*\)\s*;\s*"
        r"\}\s*",
        store_body) is not None
    if not (exact_load and exact_store):
        raise ValueError(
            "per-slot assignment counter is no longer an exact acquire/load "
            "and release/store of the full count")

    terminate_begin = diagnostic_source.find(
        "[[noreturn]] void TerminateForAssignmentGuard()")
    fatal_begin = diagnostic_source.find(
        "[[noreturn]] void FatalAssignmentGuard(", terminate_begin)
    prevent_begin = diagnostic_source.find(
        "[[noreturn]] void PreventRepeatedGeneration(", fatal_begin)
    prevent_end = diagnostic_source.find(
        "[[nodiscard]] PendingAssignment PrepareAssignment(", prevent_begin)
    terminate_body = diagnostic_source[terminate_begin:fatal_begin]
    fatal_body = diagnostic_source[fatal_begin:prevent_begin]
    prevent_body = diagnostic_source[prevent_begin:prevent_end]
    direct_guard_exit = re.search(
        r"\n\s*TerminateProcess\(\s*GetCurrentProcess\(\)\s*,\s*"
        r"kGenerationGuardExitCode\s*\)\s*;\s*\n\s*"
        r"ExitProcess\(\s*kGenerationGuardExitCode\s*\)\s*;\s*\}\s*$",
        terminate_body) is not None
    direct_fatal_stop = re.search(
        r"\n\s*TerminateForAssignmentGuard\(\s*\)\s*;\s*\}\s*$",
        fatal_body) is not None
    direct_repeat_stop_function = re.search(
        r"\n\s*TerminateForAssignmentGuard\(\s*\)\s*;\s*\}\s*$",
        prevent_body) is not None
    exact_prevented_event = re.search(
        r"const\s+std::uint64_t\s+event\s*=\s*"
        r"\(\s*static_cast<std::uint64_t>\(\s*a_priorAssignments\s*\)\s*"
        r"<<\s*32\s*\)\s*\|\s*handle\s*;.*"
        r"\n\s*g_lastPreventedEvent\.store\(\s*event\s*,\s*"
        r"std::memory_order_relaxed\s*\)\s*;\s*"
        r"const\s+std::uint64_t\s+prevented\s*=\s*"
        r"g_preventedWrapAttempts\.fetch_add\(\s*1\s*,\s*"
        r"std::memory_order_release\s*\)\s*\+\s*1u\s*;",
        prevent_body, re.DOTALL) is not None
    if not (
            0 <= terminate_begin < fatal_begin < prevent_begin < prevent_end and
            direct_guard_exit and direct_fatal_stop and
            direct_repeat_stop_function and exact_prevented_event and
            prevent_body.count("g_lastPreventedEvent.store(") == 1 and
            prevent_body.count("g_preventedWrapAttempts.fetch_add(") == 1 and
            re.search(r"\bif\s*\(\s*(?:true|false)\b", prevent_body) is None and
            all(re.search(
                    r"(?m)^\s*return(?:\s+[^;]+)?;\s*$", body) is None and
                "goto " not in body
                for body in (terminate_body, fatal_body, prevent_body))):
        raise ValueError(
            "pre-publication fatal/repeat guard no longer records the exact "
            "atomic prevented event and reaches the direct non-returning "
            "process exit")

    hottest_returns = [
        expression.strip()
        for expression in re.findall(r"\breturn\s*([^;]*);", hottest_body)
    ]
    zero_reuse_return = re.search(
        r"if\s*\(\s*a_reuseCount\s*==\s*0\s*\)\s*return\s*;",
        hottest_body) is not None
    exact_candidate = re.search(
        r"const\s+std::uint64_t\s+candidate\s*=\s*"
        r"\(\s*static_cast<std::uint64_t>\(\s*a_reuseCount\s*\)\s*"
        r"<<\s*32\s*\)\s*\|\s*a_handle\s*;",
        hottest_body) is not None
    strict_high_water = re.search(
        r"while\s*\(\s*a_reuseCount\s*>\s*"
        r"static_cast<std::uint32_t>\(\s*hottest\s*>>\s*32\s*\)\s*\)",
        hottest_body) is not None
    exact_cas = re.search(
        r"g_hottestHandle\.compare_exchange_weak\(\s*hottest\s*,\s*"
        r"candidate\s*,\s*std::memory_order_release\s*,\s*"
        r"std::memory_order_relaxed\s*\)", hottest_body) is not None
    high_water_log = hottest_body.find("if (a_logHighWater)")
    safe_limit_log = hottest_body.find(
        "if (a_reuseCount == generation::kSafeReuseLimit)")
    if not (
            hottest_returns == ["", ""] and zero_reuse_return and
            exact_candidate and strict_high_water and exact_cas and
            hottest_body.count("g_hottestHandle.compare_exchange_weak(") == 1 and
            0 <= high_water_log < safe_limit_log and
            "generation reuse high-water:" in hottest_body and
            "WARNING: generation reuse reached safe limit:" in hottest_body and
            "goto " not in hottest_body and
            re.search(r"\bif\s*\(\s*false\b", hottest_body) is None):
        raise ValueError(
            "hottest-slot strict atomic high-water update or immediate "
            "reuse/safe-limit logging changed")

    commit_begin = diagnostic_source.find(
        "void CommitAssignment(", prepare_assignment_end)
    commit_end = diagnostic_source.find(
        "void* __fastcall AssignmentHelperHook(", commit_begin)
    commit_body = diagnostic_source[commit_begin:commit_end]
    commit_returns = [
        expression.strip()
        for expression in re.findall(r"\breturn\s*([^;]*);", commit_body)
    ]
    exact_commit_tail = re.search(
        r"\}\s*StoreAssignmentCount\(\s*a_pending\.index\s*,\s*"
        r"a_pending\.transition\.assignmentCount\s*\)\s*;\s*"
        r"const\s+std::uint32_t\s+handle\s*=\s*"
        r"generation::HandleFromEntryBits\(\s*a_pending\.index\s*,\s*"
        r"entry\.bits\s*\)\s*;\s*"
        r"UpdateHottest\(\s*a_pending\.transition\.reuseCount\s*,\s*"
        r"handle\s*,\s*true\s*\)\s*;\s*\}\s*$",
        commit_body) is not None
    if not (
            0 <= commit_begin < commit_end and commit_returns == [""] and
            commit_body.count("StoreAssignmentCount(") == 1 and
            commit_body.count("UpdateHottest(") == 1 and exact_commit_tail and
            commit_body.count("if (a_pending.reservedPlayer)") == 1 and
            "g_reservedPlayerAssignments.fetch_add(" in commit_body and
            "stock pointer publisher did not preserve the prepared assignment" in
                commit_body and
            "goto " not in commit_body):
        raise ValueError(
            "successful assignment commit no longer stores the full counter "
            "then directly updates the hottest-slot high water")

    guard_tokens = (
        "if (transition.abaWrap)",
        "PreventRepeatedGeneration(index, bits, priorAssignments);",
        '"FATAL: pre-publication generation guard: generation repeat "',
        '"prevented before table-pointer publication;',
        "tablePointer=null objectCachePublished=0",
        "assignmentReturned=0 managerUnlocked=0",
        "g_preventedWrapAttempts.fetch_add(",
        "g_lastPreventedEvent.store(",
        "TerminateForAssignmentGuard();",
        "StoreAssignmentCount(a_pending.index,",
        "UpdateHottest(a_pending.transition.reuseCount, handle, true);",
    )
    if not all(token in diagnostic_source for token in guard_tokens):
        raise ValueError(
            "pre-publication prevention, separate prevented state, or successful high-water commit is missing")
    generation_tokens = (
        "kSafeReuseLimit = kGenerationCount - 1u;",
        "kFirstPreventedReuse = kGenerationCount;",
        "static_assert(kSafeReuseLimit == 31u);",
        "static_assert(kFirstPreventedReuse == 32u);",
    )
    if not all(token in generation_header for token in generation_tokens):
        raise ValueError("successful reuse 31 / prevented reuse 32 boundary drifted")
    observe_begin = generation_header.find(
        "[[nodiscard]] constexpr Transition ObserveAssignment(")
    observe_end = generation_header.find(
        "// Compile the exact release boundary", observe_begin)
    observe_body = re.sub(
        r"\s+", " ", generation_header[observe_begin:observe_end]).strip()
    expected_observe = (
        "[[nodiscard]] constexpr Transition ObserveAssignment( std::uint32_t "
        "a_priorAssignments, std::uint32_t a_observedGeneration) noexcept { if "
        "(a_priorAssignments == (std::numeric_limits<std::uint32_t>::max)()) { "
        "return { a_priorAssignments, a_priorAssignments, false, false, true, "
        "}; } const std::uint32_t assignmentCount = a_priorAssignments + 1u; "
        "const std::uint32_t expectedGeneration = assignmentCount & "
        "(kGenerationCount - 1u); const bool generationMatches = "
        "a_observedGeneration == expectedGeneration; const bool abaWrap = "
        "generationMatches && a_priorAssignments != 0u && "
        "(a_priorAssignments & (kGenerationCount - 1u)) == 0u; return { "
        "assignmentCount, a_priorAssignments, generationMatches, abaWrap, "
        "false, }; }"
    )
    if not (0 <= observe_begin < observe_end and observe_body == expected_observe):
        raise ValueError(
            "production assignment transition arithmetic/return/boundary "
            "predicate contract drifted")
    if re.search(
            r"const bool abaWrap\s*=\s*generationMatches\s*&&\s*"
            r"a_priorAssignments\s*!=\s*0u\s*&&\s*"
            r"\(a_priorAssignments\s*&\s*"
            r"\(kGenerationCount\s*-\s*1u\)\)\s*==\s*0u\s*;",
            generation_header) is None:
        raise ValueError("production repeated-generation boundary predicate drifted")
    boundary_assertions = (
        "static_assert(ObserveAssignment(0u, 1u).assignmentCount == 1u);",
        "static_assert(ObserveAssignment(0u, 1u).reuseCount == 0u);",
        "static_assert(ObserveAssignment(0u, 1u).generationMatches);",
        "static_assert(!ObserveAssignment(0u, 1u).abaWrap);",
        "static_assert(ObserveAssignment(31u, 0u).assignmentCount == 32u);",
        "static_assert(ObserveAssignment(31u, 0u).reuseCount == kSafeReuseLimit);",
        "static_assert(ObserveAssignment(31u, 0u).generationMatches);",
        "static_assert(!ObserveAssignment(31u, 0u).abaWrap);",
        "static_assert(ObserveAssignment(32u, 1u).assignmentCount == 33u);",
        "static_assert(ObserveAssignment(32u, 1u).reuseCount ==\n"
        "                  kFirstPreventedReuse);",
        "static_assert(ObserveAssignment(32u, 1u).generationMatches);",
        "static_assert(ObserveAssignment(32u, 1u).abaWrap);",
    )
    if not all(token in generation_header for token in boundary_assertions):
        raise ValueError("native compile-time no-wrap boundary proofs drifted")
    event_tokens = (
        "std::uint64_t totalWraps = 0;",
        "std::uint64_t lastWrapEvent = 0;",
        "std::uint64_t preventedWrapAttempts = 0;",
        "std::uint64_t lastPreventedEvent = 0;",
        "std::uint64_t hottestHandle = 0;",
    )
    if not all(token in diagnostic_header for token in event_tokens):
        raise ValueError("published, prevented, and hottest event states are not separated")

    prepare_guard_begin = diagnostic_source.find("bool Prepare(")
    prepare_guard_end = diagnostic_source.find(
        "void CancelPrepared()", prepare_guard_begin)
    prepare_guard_body = diagnostic_source[
        prepare_guard_begin:prepare_guard_end]
    prepare_guard_returns = re.findall(
        r"\breturn\s+([^;]+);", prepare_guard_body)
    exact_counter_allocation = re.search(
        r"const\s+std::size_t\s+counterBytes\s*=\s*"
        r"static_cast<std::size_t>\(\s*a_table\.count\s*\)\s*\*\s*"
        r"sizeof\(\s*std::uint32_t\s*\)\s*;\s*"
        r"g_slotAssignments\s*=\s*static_cast<std::uint32_t\*>\(\s*"
        r"VirtualAlloc\(\s*nullptr\s*,\s*counterBytes\s*,\s*"
        r"MEM_RESERVE\s*\|\s*MEM_COMMIT\s*,\s*PAGE_READWRITE\s*\)\s*\)\s*;",
        prepare_guard_body) is not None
    if not (
            0 <= prepare_guard_begin < prepare_guard_end and
            prepare_guard_returns == [
                "false", "false", "false", "false", "false", "false", "true",
            ] and exact_counter_allocation and
            "g_generationTable = a_table.entries;" in prepare_guard_body and
            "g_generationEntryCount = a_table.count;" in prepare_guard_body and
            "static_assert(std::atomic_ref<std::uint32_t>::is_always_lock_free);" in
                diagnostic_source and
            "std::atomic_ref<std::uint32_t>::required_alignment" in
                diagnostic_source):
        raise ValueError(
            "mandatory guard preparation no longer allocates the exact "
            "zero-initialized full-width lock-free per-slot counter array")
    forbidden_mutation_tokens = (
        "g_totalWraps", "g_lastWrapEvent", "snapshot.totalWraps =",
        "snapshot.lastWrapEvent =", "events.totalWraps !=",
        "events.lastWrapEvent", "HANDLE GENERATION WRAP DETECTED",
        "reportedWraps",
    )
    combined_runtime = diagnostic_source + table_monitor_source
    if any(token in combined_runtime for token in forbidden_mutation_tokens):
        raise ValueError(
            "a reachable post-publication wrap counter/detector path remains")
    reporter_begin = table_monitor_source.find(
        "DWORD WINAPI ReporterThread(void* a_rawContext)")
    reporter_end = table_monitor_source.find(
        "\n    }\n\n    bool Start(", reporter_begin)
    reporter_body = table_monitor_source[reporter_begin:reporter_end]
    exact_periodic_status = re.search(
        r"\}\s*diagnostic::LogStatus\(\s*context->skipAttribution\s*,\s*"
        r"trackedAssignments\s*,\s*trackedSlots\s*,\s*untrackedLive\s*\)\s*;\s*"
        r"\}\s*\}\s*$", reporter_body) is not None
    if (not (0 <= reporter_begin < reporter_end) or
            reporter_body.count("diagnostic::LogStatus(") != 1 or
            not exact_periodic_status or
            "hottest successful reuse" not in table_monitor_source or
            "publishedWraps=0" not in table_monitor_source or
            "prevented-attempt state" not in table_monitor_source):
        raise ValueError(
            "periodic monitor no longer directly reports exact "
            "hottest/prevented zero-wrap attribution state")

    status_begin = diagnostic_source.find("void LogStatus(")
    status_end = diagnostic_source.find("\n    }\n}", status_begin)
    status_body = diagnostic_source[status_begin:status_end]
    status_returns = [
        expression.strip()
        for expression in re.findall(r"\breturn\s*([^;]*);", status_body)
    ]
    direct_active_gate = re.search(
        r"\{\s*if\s*\(\s*!IsActive\(\s*\)\s*\)\s*return\s*;\s*"
        r"const\s+CurrentReferenceSnapshot\s+snapshot\s*=\s*"
        r"CaptureCurrentHottest\(\s*a_skipAttribution\s*\)\s*;",
        status_body) is not None
    if not (
            0 <= status_begin < status_end and status_returns == [""] and
            direct_active_gate and
            status_body.count("CaptureCurrentHottest(") == 1 and
            status_body.count("ReadEventSnapshot()") == 1 and
            status_body.count("Log(") == 7 and
            status_body.count("else if") == 4 and
            re.search(r"\bif\s*\(\s*(?:true|false)\b", status_body) is None and
            "goto " not in status_body):
        raise ValueError(
            "periodic hottest-slot identity/attribution logger can be bypassed "
            "or its exact outcome branches drifted")

    capture_begin = diagnostic_source.find(
        "[[nodiscard]] CurrentReferenceSnapshot CaptureCurrentHottest(")
    capture_end = diagnostic_source.find(
        "\n    }\n\n    void MarkUnreliable", capture_begin)
    capture_body = diagnostic_source[capture_begin:capture_end]
    capture_returns = re.findall(r"\breturn\s+([^;]+);", capture_body)
    capture_order = tuple(capture_body.find(token) for token in (
        "LockManager(g_runtime, *g_profile);",
        "g_hottestHandle.load(std::memory_order_acquire)",
        "UnlockManager(g_runtime, *g_profile);",
        "ResolveSmartPointer(",
        "ResolveStressAttribution(",
        "ReleasePinnedReference(reference);",
    ))
    if not (
            0 <= capture_begin < capture_end and
            capture_returns == ["snapshot", "snapshot", "snapshot", "snapshot"] and
            all(left < right for left, right in
                zip(capture_order, capture_order[1:])) and
            capture_body.count("LockManager(g_runtime, *g_profile);") == 1 and
            capture_body.count("UnlockManager(g_runtime, *g_profile);") == 1 and
            capture_body.count("ResolveSmartPointer(") == 1 and
            capture_body.count("ResolveStressAttribution(") == 1 and
            capture_body.count("ReleasePinnedReference(reference);") == 1 and
            "reference == snapshot.expectedReference" in capture_body and
            "snapshot.formID = *reinterpret_cast<const std::uint32_t*>" in
                capture_body and
            re.search(r"\bif\s*\(\s*(?:true|false)\b", capture_body) is None and
            "goto " not in capture_body):
        raise ValueError(
            "periodic hottest-slot capture no longer lock-snapshots, resolves, "
            "attributes, and releases the exact current reference")

    event_snapshot_begin = diagnostic_source.find(
        "EventSnapshot ReadEventSnapshot()")
    event_snapshot_end = diagnostic_source.find(
        "void LogStatus(", event_snapshot_begin)
    event_snapshot_body = diagnostic_source[
        event_snapshot_begin:event_snapshot_end]
    event_snapshot_loads = (
        ("snapshot.preventedWrapAttempts", "g_preventedWrapAttempts"),
        ("snapshot.lastPreventedEvent", "g_lastPreventedEvent"),
        ("snapshot.hottestHandle", "g_hottestHandle"),
        ("snapshot.unreliableSlot", "g_unreliableSlot"),
        ("snapshot.reservedPlayerAssignments", "g_reservedPlayerAssignments"),
    )
    if not (
            re.findall(r"\breturn\s+([^;]+);", event_snapshot_body) ==
                ["snapshot"] and
            all(re.search(
                re.escape(destination) + r"\s*=\s*" + re.escape(source) +
                r"\.load\(\s*std::memory_order_acquire\s*\)\s*;",
                event_snapshot_body) is not None
                for destination, source in event_snapshot_loads)):
        raise ValueError(
            "periodic event snapshot no longer acquire-loads exact prevented, "
            "hottest, reliability, and player counters")

    player_state_begin = player_slot_header.find(
        "[[nodiscard]] constexpr bool HasLiveGenerationZeroState(")
    player_state_end = player_slot_header.find(
        "static_assert(HasLiveGenerationZeroState", player_state_begin)
    player_state_body = player_slot_header[
        player_state_begin:player_state_end]
    player_state_returns = [
        re.sub(r"\s+", " ", expression).strip()
        for expression in re.findall(
            r"\breturn\s+([^;]+);", player_state_body)
    ]
    if not (
            "inline constexpr std::uint32_t kIndex = 0x00100000u;" in
                player_slot_header and
            "inline constexpr std::uint32_t kVanillaRawHandle = 0x00100000u;" in
                player_slot_header and
            player_state_returns == [
                "(a_bits & kLiveGenerationZeroMask) == generation::kInUseMask",
            ] and
            re.search(
                r"kLiveGenerationZeroMask\s*=\s*"
                r"generation::kGenerationMask\s*\|\s*generation::kInUseMask",
                player_slot_header) is not None and
            "static_assert(kLiveGenerationZeroMask == 0x07E00000u);" in
                player_slot_header and
            re.search(
                r"\(a_bits\s*&\s*kLiveGenerationZeroMask\)\s*==\s*"
                r"generation::kInUseMask", player_slot_header) is not None and
            "player_slot::IsLiveGenerationZero(entry)" in table_monitor_source and
            "snapshot.bits == player_slot::kLiveBits" not in table_monitor_source):
        raise ValueError(
            "live player validation is not the masked 0x07E00000/0x04000000 state predicate")

    reservation_begin = table_monitor_source.find(
        "[[nodiscard]] PlayerReservationSnapshot CapturePlayerReservation(")
    reservation_end = table_monitor_source.find(
        "[[nodiscard]] bool SameReservationObservation(", reservation_begin)
    reservation_body = table_monitor_source[reservation_begin:reservation_end]
    reservation_returns = re.findall(
        r"\breturn\s+([^;]+);", reservation_body)
    exact_live_player = re.search(
        r"if\s*\(\s*player_slot::IsLiveGenerationZero\(\s*entry\s*\)\s*&&\s*"
        r"snapshot\.pad\s*==\s*0\s*&&\s*"
        r"snapshot\.pointer\s*==\s*expectedSubobject\s*&&\s*"
        r"snapshot\.rawHandle\s*==\s*player_slot::kVanillaRawHandle\s*\)",
        reservation_body) is not None
    if not (
            reservation_returns == [
                "snapshot", "snapshot", "snapshot", "snapshot", "snapshot",
            ] and
            reservation_body.count("LockManager(") == 1 and
            reservation_body.count("UnlockManager(") == 1 and
            reservation_body.find("LockManager(") <
                reservation_body.find("UnlockManager(") and
            exact_live_player and
            re.search(r"\bif\s*\(\s*(?:true|false)\b", reservation_body) is None and
            "goto " not in reservation_body):
        raise ValueError(
            "TableMonitor reserved-player snapshot no longer uses the exact "
            "locked masked-live/raw-handle/singleton classification")

# Exact reservation/lifecycle locations are kept independent of both
# gen_patchtable.py's PROFILE_METADATA and the generated JSON. Selector owners
# and lock brackets are cross-checked against ASSIGNMENT_HOOKS below.
PLAYER_RESERVATION_SITES = {
    "SE": {
        "singleton_rva": 0x02F26EF8,
        "handle_rva": 0x02F26EF4,
        "object_register": "rbx",
        "selector_hook_rvas": (
            0x00132012, 0x001321A2, 0x0054A8D2, 0x005A8FA2, 0x0073D2C2),
        "release": (0x001774E0, 0x0017758F, 0x00177595,
                    0x001775D3, 0x001775D6),
        "creation": (0x005B6BC0, 0x005B6C3A, 0x005B6C62, 0x005B6C9C, 0x005B6CA8,
                     0x005B6CAF, 0x005B6CC2, 0x005B6CC7),
        "constructor_function_rva": 0x00699040,
        "constructor_post_call_size": 35,
        "teardown": (0x0016EA00, 0x0016ED5B, 0x0016ED68,
                     (0x0016ED15, 0x0016ED20), 0x0016ED79),
        "creation_function_bytes": "405356574883ec3048c7442420feffff",
        "selector_continuation_size": 203,
        "release_continuation_size": 92,
    },
    "AE": {
        "singleton_rva": 0x031874F8,
        "handle_rva": 0x031874F4,
        "object_register": "rdi",
        "selector_hook_rvas": (
            0x00178F72, 0x00179102, 0x005B9FF2, 0x0063A052, 0x007D51D2),
        "release": (0x001C24F0, 0x001C25A1, 0x001C25A7,
                    0x001C25E3, 0x001C25E6),
        "creation": (0x0064A860, 0x0064A8E1, 0x0064A90B, 0x0064A945, 0x0064A954,
                     0x0064A95B, 0x0064A96E, 0x0064A973),
        "constructor_function_rva": 0x0072CB40,
        "constructor_post_call_size": 37,
        "teardown": (0x001B9AB0, 0x001B9DEA, 0x001B9DF7,
                     (0x001B9D92,), 0x001B9E08),
        "creation_function_bytes": "40535556574883ec5848c7442428feff",
        "selector_continuation_size": 204,
        "release_continuation_size": 90,
    },
    "GOG": {
        "singleton_rva": 0x03188918,
        "handle_rva": 0x03188914,
        "object_register": "rdi",
        "selector_hook_rvas": (
            0x00178DA2, 0x00178F32, 0x005BC472, 0x0063C2B2, 0x007D7402),
        "release": (0x001C2320, 0x001C23D1, 0x001C23D7,
                    0x001C2413, 0x001C2416),
        "creation": (0x0064CAC0, 0x0064CB41, 0x0064CB6B, 0x0064CBA5, 0x0064CBB4,
                     0x0064CBBB, 0x0064CBCE, 0x0064CBD3),
        "constructor_function_rva": 0x0072ED70,
        "constructor_post_call_size": 37,
        "teardown": (0x001B98E0, 0x001B9C1A, 0x001B9C27,
                     (0x001B9BC2,), 0x001B9C38),
        "creation_function_bytes": "40535556574883ec5848c7442428feff",
        "selector_continuation_size": 204,
        "release_continuation_size": 90,
    },
    "VR": {
        "singleton_rva": 0x02FEB9F0,
        "handle_rva": 0x02FEB9EC,
        "object_register": "rbx",
        "selector_hook_rvas": (
            0x001427C2, 0x00142952, 0x0054EAE2, 0x005B0662, 0x00767E62),
        "release": (0x001873F0, 0x0018749F, 0x001874A5,
                    0x001874E3, 0x001874E6),
        "creation": (0x005BEC40, 0x005BECBA, 0x005BECE2, 0x005BED1C, 0x005BED28,
                     0x005BED2F, 0x005BED42, 0x005BED47),
        "constructor_function_rva": 0x006A26A0,
        "constructor_post_call_size": 35,
        "teardown": (0x0017F350, 0x0017F69B, 0x0017F6A8,
                     (0x0017F655, 0x0017F660), 0x0017F6B9),
        "creation_function_bytes": "405356574883ec3048c7442420feffff",
        "selector_continuation_size": 203,
        "release_continuation_size": 92,
    },
}

PLAYER_RELEASE_FUNCTION_BYTES = "40574883ec3048c7442420feffffff48"
PLAYER_TEARDOWN_FUNCTION_BYTES = "40555356574154415541564157488d6c"
PLAYER_CONSTRUCTOR_FUNCTION_BYTES = "48894c24085553565741544155415641"

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
    (("table_refs",), "table-ref", "rva"),
    (("init_patches",), "init", "rva"),
    (("player_reservation", "selectors"), "player-selector", "hook_rva"),
    (("player_reservation", "release"), "player-release", "hook_rva"),
    (("player_reservation", "lifecycle", "creation", "constructor_call"),
     "player-constructor", "rva"),
    (("assignment_hooks", "sites"), "assignment-hook", "call_rva"),
)

PATCH_DOC_EVIDENCE_COLLECTIONS = (
    (("excluded_literals",), "excluded-literal", "rva"),
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
    "excluded_literals": {
        "rva": int, "value": int, "cat": str, "asm": str, "why": str,
    },
}

PLAYER_RESERVATION_SCHEMA = {
    "singleton_rva": int,
    "handle_rva": int,
    "selectors": list,
    "release": dict,
    "lifecycle": dict,
}

PLAYER_SELECTOR_SCHEMA = {
    "hook_rva": int,
    "hook_bytes": str,
    "function_rva": int,
    "function_bytes": str,
    "object_register": str,
    "object_setup_rva": int,
    "object_setup_bytes": str,
    "lock_call_rva": int,
    "lock_call_bytes": str,
    "unlock_call_rva": int,
    "unlock_call_bytes": str,
    "stack_allocation": int,
    "pre_hook_rva": int,
    "pre_hook_bytes": str,
    "continuation_rva": int,
    "continuation_bytes": str,
}

PLAYER_RELEASE_SCHEMA = {
    "function_rva": int,
    "function_bytes": str,
    "hook_rva": int,
    "hook_bytes": str,
    "resume_rva": int,
    "reserved_exit_rva": int,
    "unlock_call_rva": int,
    "unlock_call_bytes": str,
    "pre_hook_rva": int,
    "pre_hook_bytes": str,
    "continuation_rva": int,
    "continuation_bytes": str,
}

PLAYER_LIFECYCLE_SCHEMA = {"creation": dict, "teardown": dict}
PLAYER_CREATION_SCHEMA = {
    "function_rva": int,
    "function_bytes": str,
    "constructor_function_rva": int,
    "constructor_function_bytes": str,
    "constructor_call": dict,
    "constructor_pre_hook_rva": int,
    "constructor_pre_hook_bytes": str,
    "constructor_post_call_rva": int,
    "constructor_post_call_bytes": str,
    "singleton_store": dict,
    "candidate_load": dict,
    "allocator_call": dict,
    "handle_store": dict,
    "formid_setup": dict,
    "formid_call": dict,
}
PLAYER_TEARDOWN_SCHEMA = {
    "function_rva": int,
    "function_bytes": str,
    "handle_load": dict,
    "release_call": dict,
    "zero_sources": list,
    "singleton_clear": dict,
}
PLAYER_EXACT_SITE_SCHEMA = {"rva": int, "bytes": str}

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


def _canonical_bytes(value: str, context: str,
                     expected_size: int | None = None) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{context} is not hexadecimal") from exc
    if value != raw.hex():
        raise ValueError(f"{context} is not canonical lowercase hexadecimal")
    if expected_size is not None and len(raw) != expected_size:
        raise ValueError(
            f"{context} is {len(raw)} bytes, expected {expected_size}")
    return raw


def _relative_target(rva: int, raw: bytes, displacement_offset: int) -> int:
    return rva + len(raw) + struct.unpack_from(
        "<i", raw, displacement_offset)[0]


def _player_lifecycle_records(profile: dict) -> list[tuple[str, str, dict]]:
    """Return lifecycle records in the schema-defined documentation order."""
    lifecycle = profile["player_reservation"]["lifecycle"]
    out: list[tuple[str, str, dict]] = []
    for phase, roles in (
        ("creation", ("constructor_call", "singleton_store", "candidate_load", "allocator_call",
                      "handle_store", "formid_setup", "formid_call")),
        ("teardown", ("handle_load", "release_call", "zero_sources",
                      "singleton_clear")),
    ):
        section = lifecycle[phase]
        out.append((phase, "owner", {
            "rva": section["function_rva"],
            "bytes": section["function_bytes"],
        }))
        if phase == "creation":
            out.append((phase, "constructor_owner", {
                "rva": section["constructor_function_rva"],
                "bytes": section["constructor_function_bytes"],
            }))
        for role in roles:
            value = section[role]
            if role == "zero_sources":
                out.extend((phase, "zero_source", record) for record in value)
            else:
                out.append((phase, role, value))
    return out


def _player_relay_abi_records(
        profile: dict) -> list[tuple[str, str, str, dict]]:
    reservation = profile["player_reservation"]
    out: list[tuple[str, str, str, dict]] = []
    for selector in sorted(
            reservation["selectors"], key=lambda record: record["hook_rva"]):
        out.append(("selector", "pre", "hook_rva", selector))
        out.append(("selector", "continuation", "hook_rva", selector))
    release = reservation["release"]
    out.append(("release", "pre", "hook_rva", release))
    out.append(("release", "continuation", "hook_rva", release))
    creation = reservation["lifecycle"]["creation"]
    out.append(("constructor", "pre", "hook_rva", {
        "hook_rva": creation["constructor_call"]["rva"],
        "pre_hook_rva": creation["constructor_pre_hook_rva"],
        "pre_hook_bytes": creation["constructor_pre_hook_bytes"],
    }))
    out.append(("constructor", "post", "hook_rva", {
        "hook_rva": creation["constructor_call"]["rva"],
        "continuation_rva": creation["constructor_post_call_rva"],
        "continuation_bytes": creation["constructor_post_call_bytes"],
    }))
    return out


def _reservation_code_records(profile: dict) -> list[tuple[int, bytes, str]]:
    reservation = profile["player_reservation"]
    records: list[tuple[int, bytes, str]] = []
    for selector in reservation["selectors"]:
        records.extend((
            (selector["hook_rva"], bytes.fromhex(selector["hook_bytes"]),
             "player selector"),
            (selector["function_rva"], bytes.fromhex(selector["function_bytes"]),
             "player selector owner"),
            (selector["object_setup_rva"],
             bytes.fromhex(selector["object_setup_bytes"]),
             "player selector candidate setup"),
            (selector["lock_call_rva"], bytes.fromhex(selector["lock_call_bytes"]),
             "player selector lock"),
            (selector["unlock_call_rva"],
             bytes.fromhex(selector["unlock_call_bytes"]),
             "player selector unlock"),
            (selector["pre_hook_rva"], bytes.fromhex(selector["pre_hook_bytes"]),
             "player selector pre-hook ABI window"),
            (selector["continuation_rva"],
             bytes.fromhex(selector["continuation_bytes"]),
             "player selector continuation ABI window"),
        ))
    release = reservation["release"]
    records.extend((
        (release["function_rva"], bytes.fromhex(release["function_bytes"]),
         "player release owner"),
        (release["hook_rva"], bytes.fromhex(release["hook_bytes"]),
         "player release"),
        (release["unlock_call_rva"], bytes.fromhex(release["unlock_call_bytes"]),
         "player release unlock"),
        (release["pre_hook_rva"], bytes.fromhex(release["pre_hook_bytes"]),
         "player release pre-hook ABI window"),
        (release["continuation_rva"],
         bytes.fromhex(release["continuation_bytes"]),
         "player release continuation ABI window"),
    ))
    records.extend(
        (record["rva"], bytes.fromhex(record["bytes"]),
         f"player lifecycle {phase}/{role}")
        for phase, role, record in _player_lifecycle_records(profile))
    creation = reservation["lifecycle"]["creation"]
    records.append((
        creation["constructor_pre_hook_rva"],
        bytes.fromhex(creation["constructor_pre_hook_bytes"]),
        "player constructor pre-hook ABI window"))
    records.append((
        creation["constructor_post_call_rva"],
        bytes.fromhex(creation["constructor_post_call_bytes"]),
        "player constructor post-call ABI window"))
    return records


def _cap_write_bytes(profile: dict) -> set[int]:
    written: set[int] = set()
    for record in profile["patches"]:
        written.update(range(
            record["rva"] + record["field_off"],
            record["rva"] + record["field_off"] + record["field_w"]))
    for record in profile["init_patches"]:
        written.update(range(record["rva"], record["rva"] + record["len"]))
    for record in profile["table_refs"]:
        written.update(range(
            record["rva"] + record["disp_off"],
            record["rva"] + record["disp_off"] + 4))
    return written


def _derive_raised_reservation_window(
        profile: dict, rva: int, stock: bytes, context: str) -> bytes:
    """Validate a full stock ABI window and derive its post-cap bytes.

    Reservation preflight can run before or after the cap transaction. Every
    overlapping generated instruction must therefore be wholly contained and
    its stock bytes must agree with the window before the raised expectation is
    derived from the independent patch collections.
    """
    raised = bytearray(stock)
    end = rva + len(stock)

    def overlaps(site: int, size: int) -> bool:
        return site < end and rva < site + size

    def require_contained(site: int, raw: bytes, kind: str) -> int:
        if not (rva <= site and site + len(raw) <= end):
            raise ValueError(
                f"{context} partially overlaps {kind} at {site:#x}")
        offset = site - rva
        if stock[offset:offset + len(raw)] != raw:
            raise ValueError(
                f"{context} disagrees with {kind} stock bytes at {site:#x}")
        return offset

    for record in profile["patches"]:
        raw = bytes.fromhex(record["orig"])
        if not overlaps(record["rva"], len(raw)):
            continue
        offset = require_contained(record["rva"], raw, "field patch")
        field = offset + record["field_off"]
        raised[field:field + record["field_w"]] = int(record["new"]).to_bytes(
            record["field_w"], "little")
    for record in profile["table_refs"]:
        raw = bytes.fromhex(record["orig"])
        if not overlaps(record["rva"], len(raw)):
            continue
        offset = require_contained(record["rva"], raw, "table reference")
        displacement = 0x10000000 - (record["rva"] + record["len"])
        field = offset + record["disp_off"]
        raised[field:field + 4] = struct.pack("<i", displacement)
    for record in profile["init_patches"]:
        raw = bytes.fromhex(record["orig"])
        if overlaps(record["rva"], len(raw)):
            raise ValueError(
                f"{context} unexpectedly overlaps initializer at {record['rva']:#x}")
    return bytes(raised)


def _validate_player_reservation(profile: dict, tag: str) -> None:
    reservation = profile.get("player_reservation")
    _require_exact_mapping(
        reservation, PLAYER_RESERVATION_SCHEMA, f"{tag}.player_reservation")
    expected = PLAYER_RESERVATION_SITES[tag]
    if (reservation["singleton_rva"], reservation["handle_rva"]) != \
            (expected["singleton_rva"], expected["handle_rva"]):
        raise ValueError(f"{tag} player globals differ from the reviewed exact RVAs")
    if reservation["handle_rva"] + 4 != reservation["singleton_rva"]:
        raise ValueError(f"{tag} player handle/singleton globals are not adjacent")

    selectors = reservation["selectors"]
    if len(selectors) != 5:
        raise ValueError(f"{tag} has {len(selectors)} player selectors, expected five")
    assignment_sites = ASSIGNMENT_HOOKS[tag]["sites"]
    expected_setup = {"rbx": b"\x48\x8b\xda", "rdi": b"\x48\x8b\xfa"}[
        expected["object_register"]]
    for index, (selector, hook_rva, assignment) in enumerate(zip(
            selectors, expected["selector_hook_rvas"], assignment_sites,
            strict=True)):
        context = f"{tag}.player_reservation.selectors[{index}]"
        _require_exact_mapping(selector, PLAYER_SELECTOR_SCHEMA, context)
        expected_site = (
            hook_rva, assignment[2], assignment[2] + 0x1E,
            assignment[4], assignment[5], expected["object_register"])
        actual_site = (
            selector["hook_rva"], selector["function_rva"],
            selector["object_setup_rva"], selector["lock_call_rva"],
            selector["unlock_call_rva"], selector["object_register"])
        if actual_site != expected_site:
            raise ValueError(f"{context} does not name the reviewed exact site/ABI")
        hook = _canonical_bytes(selector["hook_bytes"], f"{context}.hook_bytes", 6)
        owner = _canonical_bytes(
            selector["function_bytes"], f"{context}.function_bytes", 16)
        setup = _canonical_bytes(
            selector["object_setup_bytes"], f"{context}.object_setup_bytes", 3)
        lock = _canonical_bytes(
            selector["lock_call_bytes"], f"{context}.lock_call_bytes", 5)
        unlock = _canonical_bytes(
            selector["unlock_call_bytes"], f"{context}.unlock_call_bytes", 5)
        pre_hook = _canonical_bytes(
            selector["pre_hook_bytes"], f"{context}.pre_hook_bytes")
        continuation = _canonical_bytes(
            selector["continuation_bytes"], f"{context}.continuation_bytes")
        if hook[:2] != b"\x8b\x05" or \
                _relative_target(selector["hook_rva"], hook, 2) != profile["head_rva"]:
            raise ValueError(f"{context} is not the exact free-head load")
        if owner.hex() != ASSIGNMENT_OWNER_BYTES or setup != expected_setup:
            raise ValueError(f"{context} owner/candidate fingerprint differs")
        if lock[:1] != b"\xe8" or \
                _relative_target(selector["lock_call_rva"], lock, 1) != \
                profile["lock_write_rva"] or unlock[:1] != b"\xe8" or \
                _relative_target(selector["unlock_call_rva"], unlock, 1) != \
                profile["unlock_write_rva"]:
            raise ValueError(f"{context} manager lock bracket differs")
        if selector["stack_allocation"] != 0x30 or \
                selector["pre_hook_rva"] != selector["function_rva"] or \
                selector["pre_hook_rva"] + len(pre_hook) != \
                selector["hook_rva"] or not (0 < len(pre_hook) <= 256) or \
                pre_hook[:16] != owner:
            raise ValueError(f"{context} full pre-hook/stack-allocation proof differs")
        if selector["continuation_rva"] != selector["hook_rva"] + 6 or \
                len(continuation) != expected["selector_continuation_size"] or \
                not (0 < len(continuation) <= 256) or \
                continuation[:3] != b"\x83\xf8\xff" or \
                not continuation.endswith(b"\x48\x83\xc4\x30\x41\x5e\xc3"):
            raise ValueError(f"{context} full continuation/epilogue proof differs")
        for guard_rva, guard, guard_name in (
                (selector["function_rva"], owner, "owner"),
                (selector["object_setup_rva"], setup, "candidate setup"),
                (selector["lock_call_rva"], lock, "lock call")):
            offset = guard_rva - selector["pre_hook_rva"]
            if offset < 0 or pre_hook[offset:offset + len(guard)] != guard:
                raise ValueError(f"{context} pre-hook disagrees with {guard_name}")
        unlock_offset = selector["unlock_call_rva"] - selector["continuation_rva"]
        if unlock_offset < 0 or \
                continuation[unlock_offset:unlock_offset + len(unlock)] != unlock:
            raise ValueError(f"{context} continuation disagrees with unlock call")
        _derive_raised_reservation_window(
            profile, selector["pre_hook_rva"], pre_hook,
            f"{context} pre-hook window")
        _derive_raised_reservation_window(
            profile, selector["continuation_rva"], continuation,
            f"{context} continuation window")

    release = reservation["release"]
    _require_exact_mapping(
        release, PLAYER_RELEASE_SCHEMA, f"{tag}.player_reservation.release")
    actual_release = (
        release["function_rva"], release["hook_rva"], release["resume_rva"],
        release["reserved_exit_rva"], release["unlock_call_rva"])
    if actual_release != expected["release"]:
        raise ValueError(f"{tag} player release does not name the reviewed exact site")
    release_owner = _canonical_bytes(
        release["function_bytes"], f"{tag}.player_reservation.release.function_bytes", 16)
    release_hook = _canonical_bytes(
        release["hook_bytes"], f"{tag}.player_reservation.release.hook_bytes", 6)
    release_unlock = _canonical_bytes(
        release["unlock_call_bytes"],
        f"{tag}.player_reservation.release.unlock_call_bytes", 5)
    release_pre_hook = _canonical_bytes(
        release["pre_hook_bytes"],
        f"{tag}.player_reservation.release.pre_hook_bytes")
    release_continuation = _canonical_bytes(
        release["continuation_bytes"],
        f"{tag}.player_reservation.release.continuation_bytes")
    if release_owner.hex() != PLAYER_RELEASE_FUNCTION_BYTES or \
            release_hook[:2] != b"\x8b\x05" or \
            _relative_target(release["hook_rva"], release_hook, 2) != \
            profile["tail_rva"] or release["resume_rva"] != release["hook_rva"] + 6:
        raise ValueError(f"{tag} canonical player release ABI differs")
    if release_unlock[:1] != b"\xe8" or \
            _relative_target(release["unlock_call_rva"], release_unlock, 1) != \
            profile["unlock_write_rva"]:
        raise ValueError(f"{tag} canonical player release unlock differs")
    if release["pre_hook_rva"] != release["function_rva"] or \
            release["pre_hook_rva"] + len(release_pre_hook) != \
            release["hook_rva"] or not (0 < len(release_pre_hook) <= 256) or \
            release_pre_hook[:16] != release_owner:
        raise ValueError(f"{tag} canonical player release pre-hook proof differs")
    if release["continuation_rva"] != release["resume_rva"] or \
            len(release_continuation) != expected["release_continuation_size"] or \
            not (0 < len(release_continuation) <= 128) or \
            release_continuation[:3] != b"\x83\xf8\xff" or \
            not release_continuation.endswith(b"\x48\x83\xc4\x30\x5f\xc3"):
        raise ValueError(f"{tag} canonical player release continuation proof differs")
    release_unlock_offset = release["unlock_call_rva"] - release["continuation_rva"]
    if release_unlock_offset < 0 or release_continuation[
            release_unlock_offset:release_unlock_offset + len(release_unlock)] != \
            release_unlock:
        raise ValueError(f"{tag} release continuation disagrees with unlock call")
    _derive_raised_reservation_window(
        profile, release["pre_hook_rva"], release_pre_hook,
        f"{tag} player release pre-hook window")
    _derive_raised_reservation_window(
        profile, release["continuation_rva"], release_continuation,
        f"{tag} player release continuation window")

    lifecycle = reservation["lifecycle"]
    _require_exact_mapping(
        lifecycle, PLAYER_LIFECYCLE_SCHEMA, f"{tag}.player_reservation.lifecycle")
    creation = lifecycle["creation"]
    teardown = lifecycle["teardown"]
    _require_exact_mapping(
        creation, PLAYER_CREATION_SCHEMA,
        f"{tag}.player_reservation.lifecycle.creation")
    _require_exact_mapping(
        teardown, PLAYER_TEARDOWN_SCHEMA,
        f"{tag}.player_reservation.lifecycle.teardown")
    creation_roles = (
        "constructor_call", "singleton_store", "candidate_load", "allocator_call",
        "handle_store", "formid_setup", "formid_call")
    teardown_roles = ("handle_load", "release_call", "singleton_clear")
    for role in creation_roles:
        _require_exact_mapping(
            creation[role], PLAYER_EXACT_SITE_SCHEMA,
            f"{tag}.player_reservation.lifecycle.creation.{role}")
    if type(teardown["zero_sources"]) is not list:
        raise ValueError(f"{tag} teardown.zero_sources is not an array")
    for role in teardown_roles:
        _require_exact_mapping(
            teardown[role], PLAYER_EXACT_SITE_SCHEMA,
            f"{tag}.player_reservation.lifecycle.teardown.{role}")
    for index, record in enumerate(teardown["zero_sources"]):
        _require_exact_mapping(
            record, PLAYER_EXACT_SITE_SCHEMA,
            f"{tag}.player_reservation.lifecycle.teardown.zero_sources[{index}]")

    creation_sites = (
        creation["function_rva"],
        *(creation[role]["rva"] for role in creation_roles))
    teardown_sites = (
        teardown["function_rva"], teardown["handle_load"]["rva"],
        teardown["release_call"]["rva"],
        tuple(record["rva"] for record in teardown["zero_sources"]),
        teardown["singleton_clear"]["rva"])
    if creation_sites != expected["creation"] or teardown_sites != expected["teardown"]:
        raise ValueError(f"{tag} player lifecycle does not name the reviewed exact sites")
    if _canonical_bytes(
            creation["function_bytes"],
            f"{tag}.player_reservation.lifecycle.creation.function_bytes", 16
            ).hex() != expected["creation_function_bytes"]:
        raise ValueError(f"{tag} player creation owner fingerprint differs")
    if creation["constructor_function_rva"] != \
            expected["constructor_function_rva"] or _canonical_bytes(
                creation["constructor_function_bytes"],
                f"{tag}.player_reservation.lifecycle.creation."
                "constructor_function_bytes", 16
            ).hex() != PLAYER_CONSTRUCTOR_FUNCTION_BYTES:
        raise ValueError(f"{tag} player constructor entry fingerprint differs")
    constructor_pre_hook = _canonical_bytes(
        creation["constructor_pre_hook_bytes"],
        f"{tag}.player_reservation.lifecycle.creation."
        "constructor_pre_hook_bytes")
    if not (0 < len(constructor_pre_hook) <= 256) or \
            creation["constructor_pre_hook_rva"] != creation["function_rva"] or \
            creation["constructor_pre_hook_rva"] + len(constructor_pre_hook) != \
                creation["constructor_call"]["rva"] or \
            constructor_pre_hook[:16] != bytes.fromhex(
                creation["function_bytes"]):
        raise ValueError(f"{tag} player constructor pre-hook ABI window differs")
    if _derive_raised_reservation_window(
            profile, creation["constructor_pre_hook_rva"],
            constructor_pre_hook,
            f"{tag} player constructor pre-hook ABI window") != \
            constructor_pre_hook:
        raise ValueError(
            f"{tag} player constructor pre-hook ABI window overlaps a cap mutation")
    if _canonical_bytes(
            teardown["function_bytes"],
            f"{tag}.player_reservation.lifecycle.teardown.function_bytes", 16
            ).hex() != PLAYER_TEARDOWN_FUNCTION_BYTES:
        raise ValueError(f"{tag} player teardown owner fingerprint differs")

    exact: dict[str, bytes] = {}
    for role in creation_roles:
        exact[f"creation.{role}"] = _canonical_bytes(
            creation[role]["bytes"],
            f"{tag}.player_reservation.lifecycle.creation.{role}.bytes")
    for role in teardown_roles:
        exact[f"teardown.{role}"] = _canonical_bytes(
            teardown[role]["bytes"],
            f"{tag}.player_reservation.lifecycle.teardown.{role}.bytes")
    zero_opcode = b"\x33\xff" if expected["object_register"] == "rbx" else b"\x33\xf6"
    zero_sources = [
        _canonical_bytes(
            record["bytes"],
            f"{tag}.player_reservation.lifecycle.teardown.zero_sources[{index}].bytes",
            2)
        for index, record in enumerate(teardown["zero_sources"])
    ]
    if any(raw != zero_opcode for raw in zero_sources):
        raise ValueError(f"{tag} player teardown zero-source opcode differs")

    constructor_call = exact["creation.constructor_call"]
    singleton_store = exact["creation.singleton_store"]
    candidate_load = exact["creation.candidate_load"]
    allocator_call = exact["creation.allocator_call"]
    handle_store = exact["creation.handle_store"]
    formid_setup = exact["creation.formid_setup"]
    formid_call = exact["creation.formid_call"]
    if len(constructor_call) != 5 or constructor_call[:1] != b"\xe8" or \
            _relative_target(creation["constructor_call"]["rva"],
                             constructor_call, 1) != \
                creation["constructor_function_rva"]:
        raise ValueError(f"{tag} player constructor call target differs")
    constructor_post_call = _canonical_bytes(
        creation["constructor_post_call_bytes"],
        f"{tag}.player_reservation.lifecycle.creation."
        "constructor_post_call_bytes",
        expected["constructor_post_call_size"])
    if creation["constructor_post_call_rva"] != \
            creation["constructor_call"]["rva"] + len(constructor_call) or \
            creation["constructor_post_call_rva"] + len(constructor_post_call) != \
                creation["singleton_store"]["rva"]:
        raise ValueError(
            f"{tag} player constructor post-call publication window differs")
    if _derive_raised_reservation_window(
            profile, creation["constructor_post_call_rva"],
            constructor_post_call,
            f"{tag} player constructor post-call ABI window") != \
            constructor_post_call:
        raise ValueError(
            f"{tag} player constructor post-call ABI window overlaps a cap mutation")
    if len(singleton_store) != 7 or singleton_store[:3] != b"\x48\x89\x05" or \
            _relative_target(creation["singleton_store"]["rva"], singleton_store, 3) != \
            reservation["singleton_rva"] or len(candidate_load) != 7 or \
            candidate_load[:3] != b"\x48\x8b\x15" or \
            _relative_target(creation["candidate_load"]["rva"], candidate_load, 3) != \
            reservation["singleton_rva"]:
        raise ValueError(f"{tag} player creation singleton evidence differs")
    if len(allocator_call) != 5 or allocator_call[:1] != b"\xe8" or \
            _relative_target(creation["allocator_call"]["rva"], allocator_call, 1) != \
            selectors[0]["function_rva"] or len(handle_store) != 6 or \
            handle_store[:2] != b"\x89\x0d" or \
            _relative_target(creation["handle_store"]["rva"], handle_store, 2) != \
            reservation["handle_rva"]:
        raise ValueError(f"{tag} player creation allocator/handle evidence differs")
    if formid_setup != b"\xba\x14\x00\x00\x00" or \
            formid_call != b"\xff\x90\xc0\x01\x00\x00":
        raise ValueError(f"{tag} player FormID registration evidence differs")

    handle_load = exact["teardown.handle_load"]
    release_call = exact["teardown.release_call"]
    singleton_clear = exact["teardown.singleton_clear"]
    clear_opcode = b"\x48\x89\x3d" if expected["object_register"] == "rbx" else \
        b"\x48\x89\x35"
    if len(handle_load) != 6 or handle_load[:2] != b"\x8b\x05" or \
            _relative_target(teardown["handle_load"]["rva"], handle_load, 2) != \
            reservation["handle_rva"] or len(release_call) != 5 or \
            release_call[:1] != b"\xe8" or \
            _relative_target(teardown["release_call"]["rva"], release_call, 1) != \
            release["function_rva"] or len(singleton_clear) != 7 or \
            singleton_clear[:3] != clear_opcode or \
            _relative_target(teardown["singleton_clear"]["rva"], singleton_clear, 3) != \
            reservation["singleton_rva"]:
        raise ValueError(f"{tag} player teardown release/clear evidence differs")

    protected = set()
    for rva, raw, kind in _reservation_code_records(profile):
        if kind.endswith("ABI window") and not \
                kind.startswith("player constructor"):
            continue
        protected.update(range(rva, rva + len(raw)))
    if protected & _cap_write_bytes(profile):
        raise ValueError(f"{tag} player reservation evidence overlaps a cap rewrite")


def _patch_doc_collection(profile: dict, path: tuple[str, ...], context: str) -> list:
    value = profile
    for part in path:
        if type(value) is not dict or part not in value:
            raise ValueError(f"{context} has no {'.'.join(path)} collection")
        value = value[part]
    if type(value) is not list:
        raise ValueError(f"{context}.{'.'.join(path)} is not an array")
    return value


def _patch_doc_records(profile: dict, path: tuple[str, ...], context: str) -> list:
    """Return an ID-producing array, or wrap one mandatory hook record."""
    value = profile
    for part in path:
        if type(value) is not dict or part not in value:
            raise ValueError(f"{context} has no {'.'.join(path)} records")
        value = value[part]
    if type(value) is list:
        return value
    singleton_records = {
        ("player_reservation", "release"),
        ("player_reservation", "lifecycle", "creation", "constructor_call"),
    }
    if path in singleton_records and type(value) is dict:
        return [value]
    raise ValueError(f"{context}.{'.'.join(path)} is not an array")


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
    _validate_player_reservation(profile, tag)

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
            "patches", "table_refs", "init_patches", "excluded_literals"):
        records = _patch_doc_collection(profile, (collection_name,), tag)
        schema = PATCH_DOC_RECORD_SCHEMAS[collection_name]
        for index, record in enumerate(records):
            _require_exact_mapping(record, schema, f"{tag}.{collection_name}[{index}]")
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
            records = _patch_doc_records(profile, path, tag)
            out.extend(
                f"{prefix}-{record[key]:08x}"
                for record in sorted(records, key=lambda item: item[key]))
        return out

    mutation_ids = ids_for(PATCH_DOC_MUTATION_COLLECTIONS)
    evidence_ids = ids_for(PATCH_DOC_EVIDENCE_COLLECTIONS)
    evidence_ids.extend(
        f"fingerprint-outside-{rva:08x}" for rva in sorted(fingerprints))
    evidence_ids.extend(
        f"player-lifecycle-{phase}-{role.replace('_', '-')}-{record['rva']:08x}"
        for phase, role, record in _player_lifecycle_records(profile))
    evidence_ids.extend(
        f"player-abi-{owner}-{role}-{record[key]:08x}"
        for owner, role, key, record in _player_relay_abi_records(profile))
    all_ids = [*mutation_ids, *evidence_ids]
    if len(all_ids) != len(set(all_ids)):
        raise ValueError(f"{tag} profile produces duplicate patch-document record IDs")
    return mutation_ids, evidence_ids


def _validate_2m_architecture(profile: dict, tag: str) -> tuple[int, int, int]:
    """Validate the exclusive 2M/21+5 executable-mutation contract.

    Return ``(core_mutations, assignment_guard_redirects, total_mutations)``.
    The core count remains independently visible, but all five assignment
    redirects are mandatory for a committed cap raise.
    """
    if tag not in EXPECTED_BY_TAG:
        raise ValueError(f"unknown runtime tag {tag!r}")
    if type(profile) is not dict:
        raise ValueError(f"{tag} profile is not an object")
    present_retired = sorted(RETIRED_PROFILE_KEYS & set(profile))
    if present_retired:
        raise ValueError(
            f"{tag} retains retired 4M schema keys: {present_retired}")

    exp_refs, exp_fields, _exp_funcs, exp_mandatory = EXPECTED_BY_TAG[tag]
    if (profile.get("stock_entries"), profile.get("raised_entries"),
            profile.get("entry_size")) != (0x00100000, RAISED_ENTRIES, 0x10):
        raise ValueError(
            f"{tag} is not exactly 1M -> 2M with 16-byte physical entries")
    if profile["raised_entries"] * profile["entry_size"] != TABLE_BYTES:
        raise ValueError(f"{tag} table reservation is not exactly 32 MiB")

    fields = profile.get("patches")
    refs = profile.get("table_refs")
    init = profile.get("init_patches")
    if not all(type(records) is list for records in (fields, refs, init)):
        raise ValueError(f"{tag} mutation collections are not arrays")
    if len(fields) != exp_fields or len(refs) != exp_refs or len(init) != 3:
        raise ValueError(
            f"{tag} mutation counts differ: fields={len(fields)}, "
            f"refs={len(refs)}, init={len(init)}")

    for index, record in enumerate(fields):
        if type(record) is not dict:
            raise ValueError(f"{tag}.patches[{index}] is not an object")
        category = record.get("cat")
        expected = FIELD_REWRITE_CONTRACT.get(category)
        actual = (record.get("old"), record.get("new"), record.get("field_w"))
        if expected is None or actual != expected:
            raise ValueError(
                f"{tag}.patches[{index}] violates the exclusive immediate "
                f"rewrite contract: {category!r} {actual!r}")
        if ((record["old"] ^ record["new"]) & IN_USE_MASK) != 0:
            raise ValueError(
                f"{tag}.patches[{index}] relocates Skyrim's bit-26 in-use state")
    if {record["cat"] for record in fields} != set(FIELD_REWRITE_CONTRACT):
        raise ValueError(f"{tag} does not exercise every reviewed rewrite category")

    _validate_player_reservation(profile, tag)
    selectors = profile["player_reservation"]["selectors"]
    player_mutations = len(selectors) + 2  # release plus constructor call
    if player_mutations != 7:
        raise ValueError(
            f"{tag} has {player_mutations} player mutations, expected seven")
    core = len(fields) + len(refs) + len(init) + player_mutations
    if core != exp_mandatory:
        raise ValueError(
            f"{tag} has {core} core mutations, expected {exp_mandatory}")

    assignment = profile.get("assignment_hooks")
    if type(assignment) is not dict or type(assignment.get("sites")) is not list:
        raise ValueError(f"{tag} assignment-hook metadata is malformed")
    guards = len(assignment["sites"])
    if guards != MANDATORY_ASSIGNMENT_REDIRECTS:
        raise ValueError(
            f"{tag} has {guards} mandatory assignment-guard redirects, "
            f"expected {MANDATORY_ASSIGNMENT_REDIRECTS}")
    total = core + guards
    if total != EXPECTED_TOTAL_MUTATIONS[tag]:
        raise ValueError(
            f"{tag} has {total} total mandatory mutations, expected "
            f"{EXPECTED_TOTAL_MUTATIONS[tag]}")
    return core, guards, total


def _fixed_bytes(value: str, size: int) -> bytes:
    raw = bytes.fromhex(value)
    if len(raw) > size:
        raise ValueError(f"generated byte window exceeds its {size}-byte POD field")
    return raw.ljust(size, b"\0")


def _bytes15(value: str) -> bytes:
    return _fixed_bytes(value, 15)


def _exact_fixed_ascii(field: bytes, expected: str, label: str) -> str:
    encoded = expected.encode("ascii")
    if len(encoded) >= len(field):
        raise AssertionError(f"internal {label} contract does not fit its ABI field")
    exact = encoded + b"\0" * (len(field) - len(encoded))
    if field != exact:
        terminator = field.find(b"\0")
        if terminator < 0:
            raise ValueError(f"compiled SKSEPlugin_Version {label} is not NUL-terminated")
        try:
            observed = field[:terminator].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError(
                f"compiled SKSEPlugin_Version {label} is not ASCII") from exc
        if observed != expected:
            raise ValueError(
                f"compiled SKSEPlugin_Version {label} is {observed!r}, "
                f"expected {expected!r}")
        raise ValueError(
            f"compiled SKSEPlugin_Version {label} has nonzero trailing padding")
    return expected


def _file_backed_section_for_rva(
        pe: pefile.PE, rva: int, size: int, label: str):
    if type(rva) is not int or rva < 0 or type(size) is not int or size <= 0:
        raise ValueError(f"{label} has an invalid RVA/range")
    end = rva + size
    if end <= rva:
        raise ValueError(f"{label} RVA/range overflows")
    for section in pe.sections:
        virtual_begin = int(section.VirtualAddress)
        raw_size = int(section.SizeOfRawData)
        virtual_end = virtual_begin + raw_size
        if virtual_begin <= rva and end <= virtual_end:
            file_offset = int(section.PointerToRawData) + (rva - virtual_begin)
            return section, file_offset
    raise ValueError(f"{label} is not wholly backed by one PE section")


def validate_compiled_skse_contract(
        dll_data: bytes, pe: pefile.PE) -> dict[str, object]:
    """Validate the loader-visible exports and version data in compiled bytes."""
    if not isinstance(dll_data, bytes) or not dll_data:
        raise ValueError("compiled DLL bytes are empty or malformed")
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    except (AttributeError, KeyError, TypeError, ValueError, pefile.PEFormatError) as exc:
        raise ValueError("compiled DLL export directory is malformed") from exc
    export_directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    symbols = getattr(export_directory, "symbols", None)
    if not isinstance(symbols, list):
        raise ValueError("compiled DLL has no parseable PE export directory")

    exports: dict[str, object] = {}
    observed: list[str] = []
    for symbol in symbols:
        raw_name = getattr(symbol, "name", None)
        if not isinstance(raw_name, bytes):
            observed.append(f"<ordinal:{getattr(symbol, 'ordinal', '?')}>")
            continue
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("compiled DLL contains a non-ASCII PE export name") from exc
        observed.append(name)
        if name in exports:
            raise ValueError(f"compiled DLL contains duplicate PE export {name!r}")
        exports[name] = symbol

    if len(symbols) != len(SKSE_EXPORT_NAMES) or set(exports) != SKSE_EXPORT_NAMES:
        raise ValueError(
            "compiled DLL PE exports must be exactly "
            f"{sorted(SKSE_EXPORT_NAMES)!r}; observed {sorted(observed)!r}")

    export_rvas: dict[str, int] = {}
    for name, symbol in exports.items():
        if getattr(symbol, "forwarder", None) is not None:
            raise ValueError(f"compiled DLL PE export {name!r} is forwarded")
        address = getattr(symbol, "address", None)
        if type(address) is not int or address <= 0:
            raise ValueError(f"compiled DLL PE export {name!r} has an invalid RVA")
        export_rvas[name] = address
    if len(set(export_rvas.values())) != len(export_rvas):
        raise ValueError("compiled DLL PE exports do not have distinct RVAs")

    read_flag = 0x40000000
    write_flag = 0x80000000
    execute_flag = 0x20000000
    for name in ("SKSEPlugin_Load", "SKSEPlugin_Query"):
        section, _ = _file_backed_section_for_rva(pe, export_rvas[name], 1, name)
        characteristics = int(section.Characteristics)
        if characteristics & (read_flag | execute_flag) != (read_flag | execute_flag):
            raise ValueError(f"compiled DLL PE export {name!r} is not executable code")

    version_rva = export_rvas["SKSEPlugin_Version"]
    if version_rva & 3:
        raise ValueError("compiled SKSEPlugin_Version export is not uint32-aligned")
    version_section, version_offset = _file_backed_section_for_rva(
        pe, version_rva, SKSE_VERSION_DATA_SIZE, "SKSEPlugin_Version")
    characteristics = int(version_section.Characteristics)
    if characteristics & (read_flag | write_flag) != (read_flag | write_flag) or \
            characteristics & execute_flag:
        raise ValueError(
            "compiled SKSEPlugin_Version is not in readable, writable, non-executable data")
    if version_offset < 0 or version_offset + SKSE_VERSION_DATA_SIZE > len(dll_data):
        raise ValueError("compiled SKSEPlugin_Version extends beyond the DLL bytes")
    version = dll_data[version_offset:version_offset + SKSE_VERSION_DATA_SIZE]
    if len(version) != SKSE_VERSION_DATA_SIZE:
        raise ValueError("compiled SKSEPlugin_Version data is truncated")

    data_version, plugin_version = struct.unpack_from("<II", version, 0)
    if data_version != EXPECTED_SKSE_DATA_VERSION:
        raise ValueError(
            f"compiled SKSEPlugin_Version dataVersion is {data_version:#x}, "
            f"expected {EXPECTED_SKSE_DATA_VERSION:#x}")
    if plugin_version != EXPECTED_SKSE_PLUGIN_VERSION:
        raise ValueError(
            f"compiled SKSEPlugin_Version pluginVersion is {plugin_version:#x}, "
            f"expected {EXPECTED_SKSE_PLUGIN_VERSION:#x}")
    name = _exact_fixed_ascii(version[0x008:0x108], EXPECTED_SKSE_NAME, "name")
    author = _exact_fixed_ascii(
        version[0x108:0x208], EXPECTED_SKSE_AUTHOR, "author")
    _exact_fixed_ascii(version[0x208:0x304], "", "supportEmail")
    version_independence_ex, address_independence = struct.unpack_from(
        "<II", version, 0x304)
    if version_independence_ex != EXPECTED_SKSE_VERSION_INDEPENDENCE_EX:
        raise ValueError(
            "compiled SKSEPlugin_Version versionIndependenceEx is "
            f"{version_independence_ex:#x}, expected "
            f"{EXPECTED_SKSE_VERSION_INDEPENDENCE_EX:#x}")
    if address_independence != EXPECTED_SKSE_ADDRESS_INDEPENDENCE:
        raise ValueError(
            "compiled SKSEPlugin_Version addressIndependence is "
            f"{address_independence:#x}, expected "
            f"{EXPECTED_SKSE_ADDRESS_INDEPENDENCE:#x}")
    compatible_versions = struct.unpack_from("<16I", version, 0x30C)
    if compatible_versions != EXPECTED_SKSE_RUNTIMES:
        observed_versions = [f"{value:08X}" for value in compatible_versions]
        expected_versions = [f"{value:08X}" for value in EXPECTED_SKSE_RUNTIMES]
        raise ValueError(
            "compiled SKSEPlugin_Version compatible runtime list differs: "
            f"observed {observed_versions!r}, expected {expected_versions!r}")
    se_version_required = struct.unpack_from("<I", version, 0x34C)[0]
    if se_version_required != 0:
        raise ValueError(
            "compiled SKSEPlugin_Version seVersionRequired is nonzero: "
            f"{se_version_required:#x}")

    return {
        "exports": tuple(sorted(exports)),
        "exportRvas": export_rvas,
        "versionRva": version_rva,
        "versionFileOffset": version_offset,
        "dataVersion": data_version,
        "pluginVersion": plugin_version,
        "name": name,
        "author": author,
        "versionIndependenceEx": version_independence_ex,
        "addressIndependence": address_independence,
        "compatibleVersions": compatible_versions,
        "seVersionRequired": se_version_required,
    }


def compiled_array_blobs(
        profile: dict,
        *,
        teardown_zero_sources_va: int = 0) -> dict[str, bytes]:
    """Serialize generated records with the exact MSVC x64 POD layout."""
    def exact_site_blob(record: dict) -> bytes:
        raw = bytes.fromhex(record["bytes"])
        return struct.pack("<IB15s", record["rva"], len(raw),
                           _bytes15(record["bytes"]))

    fields = b"".join(struct.pack(
        "<IBBBBII15sx", p["rva"], p["len"], p["field_off"], p["field_w"],
        CATS.index(p["cat"]), p["old"], p["new"], _bytes15(p["orig"]))
        for p in profile["patches"])
    table_refs = b"".join(struct.pack(
        "<IBB15s3x", p["rva"], p["len"], p["disp_off"], _bytes15(p["orig"]))
        for p in profile["table_refs"])
    init_patches = b"".join(struct.pack(
        "<IBB15s15s", p["rva"], p["len"], CATS.index(p["cat"]),
        _bytes15(p["orig"]), _bytes15(p["new"]))
        for p in profile["init_patches"])
    assignment_hooks = b"".join(struct.pack(
        "<II5s11s16s", p["call_rva"], p["function_rva"],
        bytes.fromhex(p["call_bytes"]), bytes.fromhex(p["setup_bytes"]),
        bytes.fromhex(p["function_bytes"]))
        for p in profile["assignment_hooks"]["sites"])
    player_selectors = b"".join(struct.pack(
        "<IIIIIB6s16s3s5s5sHHI256sH2xI256s",
        p["hook_rva"], p["function_rva"],
        p["object_setup_rva"], p["lock_call_rva"], p["unlock_call_rva"],
        {"rbx": 3, "rdi": 7}[p["object_register"]],
        bytes.fromhex(p["hook_bytes"]), bytes.fromhex(p["function_bytes"]),
        bytes.fromhex(p["object_setup_bytes"]),
        bytes.fromhex(p["lock_call_bytes"]),
        bytes.fromhex(p["unlock_call_bytes"]), p["stack_allocation"],
        len(bytes.fromhex(p["pre_hook_bytes"])), p["pre_hook_rva"],
        _fixed_bytes(p["pre_hook_bytes"], 256),
        len(bytes.fromhex(p["continuation_bytes"])), p["continuation_rva"],
        _fixed_bytes(p["continuation_bytes"], 256))
        for p in profile["player_reservation"]["selectors"])
    release = profile["player_reservation"]["release"]
    player_release = struct.pack(
        "<IIIII6s16s5sxH2xI256sH2xI128s",
        release["hook_rva"], release["resume_rva"],
        release["reserved_exit_rva"], release["function_rva"],
        release["unlock_call_rva"], bytes.fromhex(release["hook_bytes"]),
        bytes.fromhex(release["function_bytes"]),
        bytes.fromhex(release["unlock_call_bytes"]),
        len(bytes.fromhex(release["pre_hook_bytes"])), release["pre_hook_rva"],
        _fixed_bytes(release["pre_hook_bytes"], 256),
        len(bytes.fromhex(release["continuation_bytes"])),
        release["continuation_rva"],
        _fixed_bytes(release["continuation_bytes"], 128))
    teardown_zero_sources = b"".join(struct.pack(
        "<IB15s", p["rva"], len(bytes.fromhex(p["bytes"])),
        _bytes15(p["bytes"]))
        for p in profile["player_reservation"]["lifecycle"]["teardown"][
            "zero_sources"])
    lifecycle = profile["player_reservation"]["lifecycle"]
    creation = lifecycle["creation"]
    teardown = lifecycle["teardown"]
    player_lifecycle = struct.pack(
        "<I16sI16s",
        creation["function_rva"], bytes.fromhex(creation["function_bytes"]),
        creation["constructor_function_rva"],
        bytes.fromhex(creation["constructor_function_bytes"]))
    player_lifecycle += exact_site_blob(creation["constructor_call"])
    constructor_pre_hook = bytes.fromhex(creation["constructor_pre_hook_bytes"])
    player_lifecycle += struct.pack(
        "<H2xI256s", len(constructor_pre_hook),
        creation["constructor_pre_hook_rva"],
        _fixed_bytes(creation["constructor_pre_hook_bytes"], 256))
    constructor_post_call = bytes.fromhex(
        creation["constructor_post_call_bytes"])
    player_lifecycle += struct.pack(
        "<H2xI64s", len(constructor_post_call),
        creation["constructor_post_call_rva"],
        _fixed_bytes(creation["constructor_post_call_bytes"], 64))
    player_lifecycle += b"".join(
        exact_site_blob(creation[role]) for role in (
            "singleton_store", "candidate_load", "allocator_call",
            "handle_store", "formid_setup", "formid_call"))
    player_lifecycle += struct.pack(
        "<I16s", teardown["function_rva"],
        bytes.fromhex(teardown["function_bytes"]))
    player_lifecycle += exact_site_blob(teardown["handle_load"])
    player_lifecycle += exact_site_blob(teardown["release_call"])
    player_lifecycle += struct.pack(
        "<QI", teardown_zero_sources_va, len(teardown["zero_sources"]))
    player_lifecycle += exact_site_blob(teardown["singleton_clear"])
    return {
        "fields": fields,
        "table references": table_refs,
        "initialiser guards": init_patches,
        "assignment-hook sites": assignment_hooks,
        "player-selector sites": player_selectors,
        "player-release metadata": player_release,
        "player-lifecycle metadata": player_lifecycle,
        "player teardown zero-source sites": teardown_zero_sources,
    }


def _preferred_va_for_file_offset(pe: pefile.PE, file_offset: int) -> int:
    """Translate one section-backed PE file offset to its preferred VA."""
    for section in pe.sections:
        raw_begin = int(section.PointerToRawData)
        raw_size = int(section.SizeOfRawData)
        if raw_begin <= file_offset < raw_begin + raw_size:
            section_offset = file_offset - raw_begin
            mapped_size = max(int(section.Misc_VirtualSize), raw_size)
            if section_offset >= mapped_size:
                break
            return (int(pe.OPTIONAL_HEADER.ImageBase) +
                    int(section.VirtualAddress) + section_offset)
    raise ValueError(
        f"file offset {file_offset:#x} is not backed by a mapped PE section")


def _file_offset_for_preferred_va(pe: pefile.PE, preferred_va: int) -> int:
    """Reverse the preferred-VA mapping, requiring file-backed section data."""
    rva = preferred_va - int(pe.OPTIONAL_HEADER.ImageBase)
    if rva < 0:
        raise ValueError(f"preferred VA {preferred_va:#x} precedes the image base")
    for section in pe.sections:
        virtual_begin = int(section.VirtualAddress)
        raw_size = int(section.SizeOfRawData)
        if virtual_begin <= rva < virtual_begin + raw_size:
            return int(section.PointerToRawData) + (rva - virtual_begin)
    raise ValueError(
        f"preferred VA {preferred_va:#x} is not backed by PE file data")


def compiled_array_blobs_for_pe(
        profile: dict, dll_data: bytes, pe: pefile.PE) -> dict[str, bytes]:
    """Serialize PODs with the lifecycle pointer bound to its exact PE array.

    `PlayerLifecycleMetadata::teardownZeroSources` is a real absolute pointer,
    not an all-zero placeholder. Locate that profile's unique generated array,
    translate its raw-file position to the image's preferred VA, prove the
    mapping round-trips to the same bytes, and only then serialize the parent
    lifecycle aggregate.
    """
    placeholder_blobs = compiled_array_blobs(profile)
    zero_sources = placeholder_blobs["player teardown zero-source sites"]
    positions = [
        offset for offset in range(len(dll_data) - len(zero_sources) + 1)
        if dll_data.startswith(zero_sources, offset)
    ]
    if len(positions) != 1:
        raise ValueError(
            "compiled teardown-zero-source array is not unique "
            f"(found {len(positions)})")
    zero_sources_offset = positions[0]
    zero_sources_va = _preferred_va_for_file_offset(pe, zero_sources_offset)
    round_trip_offset = _file_offset_for_preferred_va(pe, zero_sources_va)
    if round_trip_offset != zero_sources_offset or dll_data[
            round_trip_offset:round_trip_offset + len(zero_sources)] != \
            zero_sources:
        raise ValueError(
            "teardown-zero-source pointer mapping does not round-trip exactly")

    blobs = compiled_array_blobs(
        profile, teardown_zero_sources_va=zero_sources_va)
    lifecycle = blobs["player-lifecycle metadata"]
    if len(lifecycle) != 608 or struct.unpack_from("<Q", lifecycle, 576)[0] != \
            zero_sources_va or zero_sources_va == 0:
        raise ValueError(
            "serialized lifecycle metadata does not contain the exact array pointer")
    return blobs


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
    chk(sum(row[4] for row in EXPECTED) ==
            EXPECTED_AGGREGATE_CORE_MUTATIONS and
        sum(EXPECTED_TOTAL_MUTATIONS.values()) ==
            EXPECTED_AGGREGATE_TOTAL_MUTATIONS,
        "release mutation census retains 1,856 core sites and includes all "
        "20 mandatory guard redirects for 1,876 total mutations")

    for tag, exp_refs, exp_fields, exp_funcs, exp_mandatory in EXPECTED:
        print(f"== {tag}")
        patch = json.loads(
            (ROOT / "artifacts" / f"patch_{tag}.json").read_text(encoding="utf-8"))
        profiles[tag] = patch
        sites = json.loads((ROOT / "artifacts" / f"sites_{tag}.json").read_text())
        table = patch["table_rva"]

        exact_input = EXACT_RUNTIME_INPUTS[tag]
        try:
            _validate_exact_runtime_profile_input(patch, tag)
        except ValueError as exc:
            chk(False, f"independent exact generation-input contract: {exc}")
        else:
            chk(True,
                "JSON is bound to the independently reviewed exact executable size and SHA-256")

        try:
            core_mutations, guard_redirects, total_mutations = \
                _validate_2m_architecture(patch, tag)
        except ValueError as exc:
            chk(False, f"exclusive 2M/21+5 architecture contract: {exc}")
        else:
            chk(core_mutations == exp_mandatory and
                guard_redirects == MANDATORY_ASSIGNMENT_REDIRECTS and
                total_mutations == EXPECTED_TOTAL_MUTATIONS[tag],
                f"exclusive 2M/21+5 architecture retains {exp_mandatory} core "
                f"mutations and includes five mandatory assignment guards "
                f"for {EXPECTED_TOTAL_MUTATIONS[tag]} total mutations")

        if not a.offline:
            exe = pathlib.Path(RUNTIMES[tag]["exe"])
            exe_data = exe.read_bytes() if exe.is_file() else b""
            chk(bool(exe_data) and len(exe_data) == exact_input["exe_size"],
                "installed executable size matches the independent runtime pin")
            chk(bool(exe_data) and hashlib.sha256(exe_data).hexdigest() ==
                exact_input["exe_sha256"],
                "installed executable SHA-256 matches the independent runtime pin")
            db = pathlib.Path(RUNTIMES[tag]["db"])
            db_data = db.read_bytes() if db.is_file() else b""
            chk(bool(db_data) and len(db_data) == exact_input["db_size"] and
                hashlib.sha256(db_data).hexdigest() == exact_input["db_sha256"],
                "Address Library input matches the independent exact size and SHA-256")

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
        refs_block = hdr.split(f"k{tag}TableRefs[]")[1].split("};")[0]
        init_block = hdr.split(f"k{tag}InitPatches[]")[1].split("};")[0]
        assignment_block = hdr.split(f"k{tag}AssignmentHookSites[]")[1].split("};")[0]
        selector_block = hdr.split(
            f"k{tag}PlayerSelectorHookSites[]")[1].split("};")[0]
        zero_source_block = hdr.split(
            f"k{tag}PlayerTeardownZeroSources[]")[1].split("};")[0]
        n_fields = len(re.findall(r"\{ 0x[0-9a-f]{8}, \d+, \d+, \d+, \d+,", fields_block))
        n_refs = len(re.findall(r"\{ 0x[0-9a-f]{8}, \d+, \d+, \{", refs_block))
        n_init = len(re.findall(r"\{ 0x[0-9a-f]{8}, \d+, \d+, \{", init_block))
        n_assignment = len(re.findall(
            r"\{ 0x[0-9a-f]{8}, 0x[0-9a-f]{8}, \{ (?:0x[0-9a-f]{2}, ){4}0x[0-9a-f]{2} \}, \{",
            assignment_block))
        n_selectors = len(re.findall(
            r"\{ 0x[0-9a-f]{8}, 0x[0-9a-f]{8}, 0x[0-9a-f]{8}, "
            r"0x[0-9a-f]{8}, 0x[0-9a-f]{8}, [37], \{",
            selector_block))
        n_zero_sources = len(re.findall(
            r"\{ 0x[0-9a-f]{8}, \d+, \{", zero_source_block))
        chk(n_fields == len(patch["patches"]),
            f"header k{tag}Fields matches the JSON ({n_fields})")
        chk(n_refs == len(patch["table_refs"]),
            f"header k{tag}TableRefs matches the JSON ({n_refs})")
        chk(n_init == len(patch["init_patches"]),
            f"header k{tag}InitPatches matches the JSON ({n_init})")
        chk(n_assignment == len(patch.get("assignment_hooks", {}).get("sites", [])),
            f"header k{tag}AssignmentHookSites matches the JSON ({n_assignment})")
        chk(n_selectors == len(patch["player_reservation"]["selectors"]),
            f"header k{tag}PlayerSelectorHookSites matches the JSON ({n_selectors})")
        chk(n_zero_sources == len(
                patch["player_reservation"]["lifecycle"]["teardown"]["zero_sources"]),
            f"header k{tag}PlayerTeardownZeroSources matches the JSON "
            f"({n_zero_sources})")
        try:
            pod_blobs = compiled_array_blobs(patch)
        except (KeyError, TypeError, ValueError, struct.error) as exc:
            chk(False, f"{tag} reservation POD metadata packs exactly: {exc}")
        else:
            selector_pod_size = struct.calcsize(
                "<IIIIIB6s16s3s5s5sHHI256sH2xI256s")
            release_pod_size = struct.calcsize(
                "<IIIII6s16s5sxH2xI256sH2xI128s")
            chk(selector_pod_size == 584 and
                len(pod_blobs["player-selector sites"]) ==
                len(patch["player_reservation"]["selectors"]) * selector_pod_size,
                f"header player-selector POD layout is 584 bytes per exact site")
            chk(release_pod_size == 448 and
                len(pod_blobs["player-release metadata"]) == release_pod_size,
                "header player-release POD layout is the exact 448-byte aggregate")
            chk(len(pod_blobs["player-lifecycle metadata"]) == 608,
                "header player-lifecycle POD layout is the exact 608-byte aggregate")

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
        chk(len({p.get("writer_rva") for p in assignment_sites}) == 5 and
            all(p.get("function_rva") < p.get("writer_rva") <
                p.get("unlock_call_rva") for p in assignment_sites),
            "mandatory assignment guards name five distinct stock allocation publishers")
        cap_write_bytes: set[int] = set()
        for p in patch["patches"]:
            cap_write_bytes.update(range(
                p["rva"] + p["field_off"],
                p["rva"] + p["field_off"] + p["field_w"]))
        for p in patch["init_patches"]:
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
        chk(patch["raised_entries"] == RAISED_ENTRIES and
            patch["entry_size"] == 0x10 and
            patch["raised_entries"] * patch["entry_size"] == TABLE_BYTES,
            "profile allocates 2,097,152 physical 16-byte entries (32 MiB)")

        chk(not [p for p in patch["patches"] if p["old"] in OBJECT_SIDE],
            "no object-side reference-count field is rewritten")
        chk(all(p["field_off"] + p["field_w"] <= p["len"] for p in patch["patches"]),
            "every rewritten field lies inside its instruction")
        chk(all(p["len"] == len(bytes.fromhex(p["orig"])) ==
                len(bytes.fromhex(p["new"])) <= 15
                for p in patch["init_patches"]),
            "every initializer guard rewrite is exact, same-length, and <=15 bytes")
        chk(all(p["len"] == len(bytes.fromhex(p["orig"])) <= 15 and
                p["disp_off"] + 4 <= p["len"] for p in patch["table_refs"]),
            "every table reference carries a complete instruction and in-bounds disp32")

    print("== generated header")
    chk(hdr == render_header(profiles),
        "PatchTable.g.h is the exact deterministic rendering of all four JSON profiles")
    profile_match = re.search(r"\n    struct Profile\s*\{(.*?)\n    \};", hdr,
                              re.DOTALL)
    profile_body = profile_match.group(1) if profile_match else ""
    retired_header_tokens = (
        "bytePatches", "bytePatchCount", "releaseSites", "releaseSiteCount",
        *(f"k{tag}BytePatches" for tag, *_ in EXPECTED),
        *(f"k{tag}ReleaseSites" for tag, *_ in EXPECTED),
    )
    profile_tail_tokens = (
        "const FieldPatch* fields;", "uint32_t          fieldCount;",
        "const TableRef*   tableRefs;", "uint32_t          tableRefCount;",
        "const BytePatch*  initPatches;", "uint32_t          initPatchCount;",
    )
    chk(bool(profile_match) and
        not any(token in hdr for token in retired_header_tokens) and
        profile_body.count("const BytePatch*") == 1 and
        all(token in profile_body for token in profile_tail_tokens) and
        [profile_body.index(token) for token in profile_tail_tokens] == sorted(
            profile_body.index(token) for token in profile_tail_tokens),
        "generated Profile has the smaller 2M layout with only field, table-ref, "
        "and initializer mutation arrays")

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
    index_document = expected_documents.get("README.md", "")
    chk(
        "mandatory pre-publication assignment-guard redirect" in index_document and
        "**1,856** | **20** | **1,876**" in index_document and
        "Optional redirects" not in index_document and
        "optional generation-wrap call redirect" not in index_document,
        "patch-document index retains the core census and counts every guard "
        "redirect in the 1,876 mandatory mutations")
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
            f"{tag} document renders every mutation, lifecycle/relay ABI site, "
            "fingerprint, and exclusion exactly once")
        chk(actual_mutations == expected_mutations,
            f"{tag} document has exact one-to-one coverage of all "
            f"{len(expected_mutations)} executable mutation records")
        runtime_document = actual_documents.get(filename, "")
        core = EXPECTED_BY_TAG[tag][3]
        total = EXPECTED_TOTAL_MUTATIONS[tag]
        chk(
            f"| Core cap/player mutation records | {core:,} |" in
                runtime_document and
            "| Mandatory assignment-guard redirects | 5 |" in
                runtime_document and
            f"| Total mandatory mutation records | {total:,} |" in
                runtime_document and
            "published wrap means a repeated-generation/ABA publication" in
                runtime_document and
            "assignment 32 / reuse 31 legitimately advances age 31 to age 0" in
                runtime_document and
            "Assignment 33 / reuse 32 would repeat age 1 and is prevented" in
                runtime_document and
            "GenerationWrapDetection=0 therefore refuses the cap raise" in
                runtime_document,
            f"{tag} audit defines safe numeric rollover separately from "
            "prevented repeated-generation publication and the no-bypass guard")

    source_dir = ROOT / "src"
    maintained_source_paths = sorted(
        [*source_dir.glob("*.cpp"), *source_dir.glob("*.h")],
        key=lambda path: path.name.casefold())
    maintained_source = "\n".join(
        path.read_text(encoding="utf-8") for path in maintained_source_paths)
    main_source = (source_dir / "main.cpp").read_text(encoding="utf-8")
    runtime_source = (source_dir / "RuntimeDetection.cpp").read_text(encoding="utf-8")
    interop_source = (source_dir / "EngineFixesInterop.cpp").read_text(
        encoding="utf-8")
    interop_header = (source_dir / "EngineFixesInterop.h").read_text(
        encoding="utf-8")
    patch_transaction_source = (source_dir / "PatchTransaction.cpp").read_text(
        encoding="utf-8")
    patch_transaction_header = (source_dir / "PatchTransaction.h").read_text(
        encoding="utf-8")
    table_monitor_source = (source_dir / "TableMonitor.cpp").read_text(
        encoding="utf-8")
    diagnostic_source = (source_dir / "GenerationDiagnostic.cpp").read_text(
        encoding="utf-8")
    diagnostic_header = (source_dir / "GenerationDiagnostic.h").read_text(
        encoding="utf-8")
    generation_header = (source_dir / "GenerationTracker.h").read_text(
        encoding="utf-8")
    player_slot_header = (source_dir / "ReservedPlayerSlot.h").read_text(
        encoding="utf-8")
    stress_contract_source = (source_dir / "StressTest.cpp").read_text(
        encoding="utf-8")
    patch_simulator_source = (ROOT / "probes" / "test_patch.py").read_text(
        encoding="utf-8")
    cmake_source = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    try:
        _validate_no_wrap_source_contract(
            main_source, diagnostic_source, diagnostic_header,
            generation_header, table_monitor_source, player_slot_header)
    except ValueError as exc:
        chk(False, f"mandatory pre-publication no-wrap source contract: {exc}")
    else:
        chk(True,
            "mandatory guard has no config bypass, publishes the stock helper "
            "before redirects, rolls back exactly, stops reuse 32 before the "
            "publisher, and reports hottest/prevented state with zero published wraps")
    generation_contract_tokens = (
        "kHandleValueBits = 26;",
        "kIndexBits = 21;",
        "kGenerationBits = 5;",
        "kEntryCount == 0x00200000u",
        "kIndexMask == 0x001FFFFFu",
        "kGenerationCount == 32u",
        "kGenerationMask == 0x03E00000u",
        "kInUseMask == 0x04000000u",
        "kIndexBits + kGenerationBits == kHandleValueBits",
    )
    player_identity_tokens = (
        "kIndex = 0x00100000u;",
        "kVanillaRawHandle = 0x00100000u;",
        "kDetachedBits == 0x03F00000u",
        "kLiveGenerationZeroMask == 0x07E00000u",
        "HasLiveGenerationZeroState(",
        "generation::kInUseMask | kVanillaRawHandle",
    )
    object_cache_tokens = (
        "kCachedHandleIndexShift = 11;",
        "generation::kIndexMask << kCachedHandleIndexShift",
        "0xFFFFF800u",
        "candidateBytes + 0x28",
        "cachedState >> kCachedHandleIndexShift",
        "cachedIndex == player_slot::kIndex",
    )
    stress_cache_tokens = (
        "kObjectIndexMask = 0x1FFFFF;",
        "((a_index & kObjectIndexMask) << 11)",
        "(packed & ~kReferenceCountMask) != expectedMetadata",
        "a_reference->pad2C != 0",
        "ReadPackedWord(a_reference) != 1",
    )
    chk(all(token in generation_header for token in generation_contract_tokens) and
        all(token in player_slot_header for token in player_identity_tokens) and
        all(token in patch_transaction_source for token in object_cache_tokens) and
        all(token in stress_contract_source for token in stress_cache_tokens),
        "native constants preserve 26 handle bits as 21 index + 5 age, reserve "
        "raw player 0x00100000, validate live state with mask 0x07E00000 / "
        "value 0x04000000, and use the complete stock _refCount[31:11] cache")
    mutation_layer = patch_transaction_source + profile_body
    retired_mutation_tokens = (
        "bytePatches", "bytePatchCount", "releaseSites", "releaseSiteCount",
        "rawPatches", "rawPatchCount", "sidecar", "Sidecar", "+ 0x2C",
        "+0x2C",
    )
    chk(not any(token in mutation_layer for token in retired_mutation_tokens) and
        tuple(CATS) == (*FIELD_REWRITE_CONTRACT.keys(), "init_guard"),
        "production mutation layer contains no sidecar/+0x2C or in-use-relocation "
        "rewrite path")
    chk('project(SkyrimHandleCapRaise VERSION 2.2.0 LANGUAGES CXX)' in
            cmake_source and
        'Log("SkyrimHandleCapRaise 2.2.0 (2M compatibility build)")' in
            main_source,
        "CMake and native log identity advertise the 2.2.0 compatibility build")
    chk("/Brepro" in cmake_source and
        'set(SHCR_SOURCE_DATE_EPOCH "1704067200")' in cmake_source and
        '"SOURCE_DATE_EPOCH=${SHCR_SOURCE_DATE_EPOCH}"' in cmake_source,
        "Release DLL and package use deterministic linker/archive metadata")
    chk(runtime_source.count("ReadProductVersion(executable, version)") == 1 and
        runtime_source.count("ReadFixedFileVersion(versionPath, fileVersion)") == 1 and
        maintained_source.count("LogEngineFixesCompatibility();") == 1 and
        "ReadProductVersion" not in main_source and
        "VerifyEngineFixes" not in maintained_source,
        "RuntimeDetection owns ProductVersion and broad informational Engine Fixes reporting")

    def cpp_digest(name: str) -> bytes:
        match = re.search(
            rf"constexpr\s+std::uint8_t\s+{name}\s*\[[^]]+\]\s*\{{(.*?)\}};",
            interop_source,
            re.DOTALL,
        )
        if not match:
            return b""
        return bytes(int(value, 16) for value in re.findall(
            r"0x([0-9A-Fa-f]{2})", match.group(1)))

    expected_engine_fixes_sha = bytes.fromhex(
        "5D1384ACFB523ABD1333F5AF71AF0B7D131B6EBB1A0EE6B3EDFF86FB4C93ADF3")
    expected_wrapper_sha = bytes.fromhex(
        "9D9527245B187E31D067F2CCF77E8CB81DD4615DEA263D7608F10F9FC3EE2BE0")
    interop_constants = (
        "kAeTeardownOwnerRva = 0x001B9AB0u",
        "kImageSize = 0x002A4000u",
        "kTimeDateStamp = 0x699FC3BAu",
        "kWrapperRva = 0x000711F0u",
        "kWrapperEndRva = 0x00071403u",
        "kHookTargetRva = 0x0023EAC0u",
        "kHookDestinationRva = 0x0023EAC8u",
        "kHookTrampolineRva = 0x0023EAE0u",
        "kHookTrampolineSizeRva = 0x0023EAE8u",
        "kSafetyHookTrampolineBytes = 24u",
    )
    interop_chain_tokens = (
        "a_runtime.runtimeVersion != kRuntimeAE",
        "ownerBytes[0] != 0xE9",
        "std::memcmp(ownerBytes + 5, a_stockBytes + 5",
        "std::memcmp(trampoline, a_stockBytes, 5)",
        "RelativeTarget5(backJump) != owner + 5",
        'std::memcmp(stub, "\\xFF\\x25\\x00\\x00\\x00\\x00", 6)',
        "info.State != MEM_COMMIT",
        "info.Type != MEM_PRIVATE",
        "info.Protect != PAGE_EXECUTE_READWRITE",
        "ExactExecutableWrapper(module, destination)",
        "ReadValue<std::uintptr_t>(moduleBase + kHookTargetRva)",
        "ReadValue<std::uintptr_t>(moduleBase + kHookDestinationRva)",
        "ReadValue<std::uintptr_t>(moduleBase + kHookTrampolineRva)",
        "kHookTrampolineSizeRva) == kSafetyHookTrampolineBytes",
    )
    chk(cpp_digest("kFileDigest") == expected_engine_fixes_sha and
        cpp_digest("kWrapperDigest") == expected_wrapper_sha and
        all(token in interop_source for token in interop_constants) and
        all(token in interop_source for token in interop_chain_tokens) and
        "constexpr FileVersion kFileVersion{ 7, 0, 20, 0 }" in interop_source and
        'constexpr wchar_t kModuleName[] = L"EngineFixes.dll"' in interop_source and
        "kRuntimeSE" not in interop_source and
        "kRuntimeGOG" not in interop_source and
        "kRuntimeVR" not in interop_source and
        "EngineFixesVR.dll" not in interop_source,
        "Engine Fixes allowance is pinned to the exact reviewed AE 7.0.20 binary, wrapper, and SafetyHook chain")
    deep_lifecycle_sites = (
        "exactSiteGood(lifecycle.singletonStore)",
        "exactSiteGood(lifecycle.candidateLoad)",
        "exactSiteGood(lifecycle.allocatorCall)",
        "exactSiteGood(lifecycle.handleStore)",
        "exactSiteGood(lifecycle.formIDSetup)",
        "exactSiteGood(lifecycle.formIDCall)",
        "exactSiteGood(lifecycle.teardownHandleLoad)",
        "exactSiteGood(lifecycle.teardownReleaseCall)",
        "exactSiteGood(lifecycle.singletonClear)",
    )
    chk(patch_transaction_source.count(
            "IsAuthenticatedFormCachingLifecycleOwner(") == 1 and
        patch_transaction_source.count(
            "LogAuthenticatedFormCachingLifecycleOwner();") == 1 and
        "lifecycle.teardownFunctionRva" in
            patch_transaction_source[patch_transaction_source.index(
                "IsAuthenticatedFormCachingLifecycleOwner("):
                patch_transaction_source.index(
                    "IsAuthenticatedFormCachingLifecycleOwner(") + 300] and
        "lifecycle.creationFunctionRva" not in
            patch_transaction_source[patch_transaction_source.index(
                "IsAuthenticatedFormCachingLifecycleOwner("):
                patch_transaction_source.index(
                    "IsAuthenticatedFormCachingLifecycleOwner(") + 300] and
        all(token in patch_transaction_source for token in deep_lifecycle_sites) and
        "else if (teardownOwnerInterop)" in patch_transaction_source and
        "every exact deep" in patch_transaction_source,
        "only the teardown owner entry is relaxed and PASS logging remains gated by all deep lifecycle checks")
    constructor_contract_tokens = (
        "constexpr std::size_t kSelectorRelayBytes = 46;",
        "constexpr std::size_t kConstructorRelayBytes = 14;",
        "alignas(void*) std::atomic<void*> g_constructingPlayer{ nullptr };",
        "static_assert(std::atomic<void*>::is_always_lock_free);",
        "__declspec(noinline) PlayerCharacter* __fastcall\n        ConstructReservedPlayer",
        "g_constructingPlayer.compare_exchange_strong",
        "constructorPreHookRva ==",
        "constructorPreHookLen == constructorCall.rva",
        "const bool constructorPostCallGood =",
        "lifecycle.constructorPostCallRva ==",
        "lifecycle.constructorPostCallLen ==\n                        lifecycle.singletonStore.rva",
        "const bool livePostCallWindowGood =",
        "const bool constructorGood = constructorPreHookGood &&",
        "RelativeTargetAt(constructorCall.orig",
        "lifecycle.constructorFunctionRva",
        "const std::uint8_t constructorPrefix[] = {\n                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,",
        "reinterpret_cast<std::uintptr_t>(&ConstructReservedPlayer)",
        "std::uint8_t constructorPatch[5]{};",
        "BuildCallBranch(\n                    a_runtime.imageBase + constructorCall.rva",
        "constructorCall.orig, constructorCall.len",
    )
    chk(all(token in patch_transaction_source
            for token in constructor_contract_tokens) and
        patch_transaction_source.count(
            "const bool constructorGood = constructorPreHookGood &&") == 1 and
        patch_transaction_source.count(
            "const bool constructorPostCallGood =") == 1 and
        patch_transaction_source.count(
            "const bool livePostCallWindowGood =") == 1 and
        patch_transaction_source.count(
            "std::uint8_t constructorPatch[5]{};") == 1 and
        "constructorGood &&" in patch_transaction_source and
        "a_expectPatchedHooks" in patch_transaction_source and
        "g_reservation.constructorBytes, kConstructorRelayBytes" in
            patch_transaction_source,
        "mandatory constructor CALL is exact in stock/patched states, uses the "
        "authenticated full pre-hook and post-call publication ABI windows, "
        "and round-trips through the register-neutral FF25 wrapper relay")
    lifecycle_counter_contract = (
        "constexpr std::size_t kReleaseRelayBytes = 78;",
        "std::atomic<std::uint64_t> g_reservedPlayerConstructorAssignments{ 0 };",
        "std::atomic<std::uint64_t> g_reservedPlayerReleaseQuarantines{ 0 };",
        "&g_reservedPlayerReleaseQuarantines",
        "0xF0, 0x48, 0xFF, 0x00,",
        "g_reservedPlayerConstructorAssignments.fetch_add(",
        "player lifecycle transition: constructorAssignments=%llu",
        "ReadReservedPlayerLifecycleSnapshot() noexcept",
    )
    simulator_counter_contract = (
        "FAKE_RELEASE_COUNTER_VA",
        "if len(release) != 78:",
        "release[34:40] != b\"\\xF0\\x48\\xFF\\x00\\x8B\\xC7\"",
        "self.release_quarantines += 1",
        "released_player.release_quarantines != 1",
    )
    chk(all(token in patch_transaction_source
            for token in lifecycle_counter_contract) and
        "struct ReservedPlayerLifecycleSnapshot" in patch_transaction_header and
        "constructorAssignments" in patch_transaction_header and
        "releaseQuarantines" in patch_transaction_header and
        "player lifecycle counters: constructorAssignments=%llu" in
            table_monitor_source and
        all(token in patch_simulator_source
            for token in simulator_counter_contract),
        "reserved-player constructor/release counters are lock-free, emitted by "
        "the exact 78-byte quarantine relay, reported by the monitor, and "
        "modeled by the empty/one/many offline simulator")
    stress_source = (ROOT / "src" / "StressTest.cpp").read_text(encoding="utf-8")
    stress_header = (ROOT / "src" / "StressTest.h").read_text(encoding="utf-8")
    stress_model_source = (ROOT / "probes" /
        "stress_second_pass_model.py").read_text(encoding="utf-8")
    stress_model_tests = (ROOT / "probes" / "tests" /
        "test_stress_second_pass.py").read_text(encoding="utf-8")
    stress_fill_pos = stress_source.find("stress: synthetic filler reached index")
    stress_begin_pos = stress_source.find(
        "BeginSyntheticSecondPass();", stress_fill_pos)
    stress_process_pos = stress_source.find(
        "void ProcessSyntheticSecondPass()")
    stress_process_end = stress_source.find(
        "void BeginReuseCycle()", stress_process_pos)
    stress_pass_pos = stress_source.find(
        "stress: SYNTHETIC SECOND PASS PASS", stress_process_pos)
    stress_release_pos = stress_source.find(
        "BeginReleaseProbe();", stress_pass_pos)
    stress_process_body = stress_source[
        stress_process_pos:stress_process_end]
    chk(stress_fill_pos >= 0 and
        stress_begin_pos > stress_fill_pos and
        "BeginReleaseProbe();" not in
            stress_source[stress_fill_pos:stress_begin_pos] and
        stress_process_pos >= 0 and
        stress_process_end > stress_process_pos and
        stress_pass_pos > stress_process_pos and
        stress_release_pos > stress_pass_pos and
        "kSyntheticSecondPass" in stress_source and
        "case Phase::kSyntheticSecondPass:" in stress_source and
        "ProcessSyntheticSecondPass();" in stress_source and
        "heldHandles.size() != syntheticVerifyExpected" in
            stress_process_body and
        "VerifyLiveSyntheticState(" in stress_process_body and
        "(held.handle & IndexMask()) != held.index" in stress_process_body and
        "GetSmartPointer failed during the synthetic second lookup pass" in
            stress_process_body and
        "resolved a handle to the wrong object" in stress_process_body and
        "ReleaseLookupReference(resolved)" in stress_process_body and
        "++syntheticVerifyCursor;" in stress_process_body and
        "while (" not in stress_process_body and
        "for (" not in stress_process_body and
        "before any configured release or reuse probe" in
            " ".join(stress_header.replace("//", "").split()) and
        "class SyntheticSecondPassModel" in stress_model_source and
        "INDEX_MASK = 0x001FFFFF" in stress_model_source and
        "AGE_INCREMENT = 0x00200000" in stress_model_source and
        "RAW_HANDLE_MASK = 0x03FFFFFF" in stress_model_source and
        "RESERVED_PLAYER_INDEX = 0x00100000" in stress_model_source and
        "(held.handle & INDEX_MASK) != held.index" in stress_model_source and
        "(held.handle & ~RAW_HANDLE_MASK) != 0" in stress_model_source and
        "if processed >= self.max_references_per_task" in stress_model_source and
        "self._begin_release()" in stress_model_source and
        "test_every_retained_object_is_resolved_once_before_release" in
            stress_model_tests and
        "test_lookup_failure_is_terminal_before_release" in
            stress_model_tests and
        "test_model_uses_exact_21_plus_5_live_handle_shape" in
            stress_model_tests and
        "test_old_22_bit_alias_and_reserved_slot_records_fail_closed" in
            stress_model_tests and
        "test_second_pass_processes_one_record_per_outer_iteration" in
            stress_model_tests,
        "synthetic VerifySecondPass is a distinct bounded exact-object gate "
        "that fails closed before release/reuse and is independently modeled")
    chk("WasFormCachingLifecycleOwnerAuthenticated()" in stress_source and
        "RevalidateFormCachingLifecycleOwner(" in stress_source and
        "EngineFixesFormCaching revalidation PASS" in stress_source and
        "EngineFixesInterop.cpp" in cmake_source and
        "EngineFixesInterop.h" in cmake_source and
        re.search(r"target_link_libraries\([^)]*\bBcrypt\b", cmake_source,
                  re.DOTALL) is not None and
        "RevalidateFormCachingLifecycleOwner" in interop_header,
        "authenticated Engine Fixes chain is linked and revalidated before every prerelease lifecycle checkpoint")
    interop_doc = (ROOT / "docs" /
        "ENGINE-FIXES-FORM-CACHING-INTEROP.md").read_text(encoding="utf-8")
    live_verifier_source = (ROOT / "probes" /
        "verify_live_lifecycle.py").read_text(encoding="utf-8")
    try:
        _validate_live_lifecycle_failure_contract(live_verifier_source)
    except ValueError as exc:
        chk(False, f"live lifecycle generic failure-marker contract: {exc}")
    else:
        chk(True, "live lifecycle verifier generically rejects every CRITICAL line")
    chk(expected_engine_fixes_sha.hex().upper() in interop_doc and
        expected_wrapper_sha.hex().upper() in interop_doc and
        "This is not a generic `E9` allowance" in interop_doc and
        "ENGINE_FIXES_INTEROP_LINE" in live_verifier_source and
        "sum(line == ENGINE_FIXES_INTEROP_LINE for line in lines) != 1" in
            live_verifier_source and
        "ENGINE_FIXES_REVALIDATION_RE" in live_verifier_source and
        "ENGINE_FIXES_REVALIDATION_RE.fullmatch(line)" in live_verifier_source and
        "BEGIN_RE.fullmatch(line)" in live_verifier_source and
        "CHECKPOINT_RE.fullmatch(line)" in live_verifier_source and
        "LOAD_RESULT_RE.fullmatch(line)" in live_verifier_source and
        "duplicate lifecycle BEGIN" in live_verifier_source and
        "len(matching_begins) != 1" in live_verifier_source and
        "matching[0] + 1 == matching_begins[0]" in live_verifier_source and
        "orphan Engine Fixes chain revalidation" in live_verifier_source and
        'REQUIRED_RUNTIME = "Skyrim AE 1.6.1170"' in live_verifier_source and
        "runtime != REQUIRED_RUNTIME" in live_verifier_source,
        "interop contract documents the exact fail-closed boundary and live evidence requires its unique PASS line")
    stock_source = (ROOT / "src" / "StockProbe.cpp").read_text(encoding="utf-8")
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
            {"verboselogging", "lifecycleverification",
             "generationwrapdetection", "samplesize"} and
            config.getint("General", "VerboseLogging") == 0 and
            config.getint("General", "LifecycleVerification") == 0 and
            config.getint("General", "GenerationWrapDetection") == 1 and
            config.getint("General", "SampleSize") == 16,
            "shipping INI exposes exactly VerboseLogging=0, "
            "LifecycleVerification=0, "
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
        try:
            dll_pe = pefile.PE(data=dll_data, fast_load=True)
        except (pefile.PEFormatError, OSError, ValueError) as exc:
            chk(False, f"release DLL is not a parseable PE image: {exc}")
            dll_pe = None
        if dll_pe is not None:
            try:
                skse_contract = validate_compiled_skse_contract(dll_data, dll_pe)
            except (AttributeError, KeyError, TypeError, ValueError, struct.error) as exc:
                chk(False, f"compiled DLL SKSE loader contract is invalid: {exc}")
            else:
                chk(
                    skse_contract["exports"] == tuple(sorted(SKSE_EXPORT_NAMES)) and
                    skse_contract["dataVersion"] == EXPECTED_SKSE_DATA_VERSION and
                    skse_contract["pluginVersion"] == EXPECTED_SKSE_PLUGIN_VERSION and
                    skse_contract["name"] == EXPECTED_SKSE_NAME and
                    skse_contract["author"] == EXPECTED_SKSE_AUTHOR and
                    skse_contract["addressIndependence"] ==
                        EXPECTED_SKSE_ADDRESS_INDEPENDENCE and
                    skse_contract["compatibleVersions"] == EXPECTED_SKSE_RUNTIMES,
                    "compiled DLL exports exactly the three SKSE entry points and "
                    "embeds the exact 2.2.0 loader metadata/runtime list")
        for tag, *_ in EXPECTED:
            if dll_pe is None:
                continue
            try:
                compiled_blobs = compiled_array_blobs_for_pe(
                    profiles[tag], dll_data, dll_pe)
            except (KeyError, TypeError, ValueError, struct.error) as exc:
                chk(False,
                    f"{tag} lifecycle pointer does not target its unique exact "
                    f"teardown-zero-source array: {exc}")
                continue
            chk(True,
                f"{tag} lifecycle pointer targets its unique exact "
                "teardown-zero-source array")
            for label, blob in compiled_blobs.items():
                chk(bool(blob) and dll_data.count(blob) == 1,
                    f"compiled DLL contains the exact {tag} {label} array once")

    print()
    print("ALL CONSISTENT" if ok else "INCONSISTENCIES FOUND")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
