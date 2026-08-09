"""Inventory placed-reference records in a Skyrim Data directory.

This is a read-only, dependency-free probe.  It walks Bethesda record/group
headers without decoding record payloads, validates that every file ends on a
record boundary, and distinguishes new/origin records from override records by
using the TES4 master count and each record's on-disk FormID prefix.

Typical AE invocation::

    python inventory_runtime_refs.py \
      --data "C:\\Games\\Skyrim AE 1.6\\Data" \
      --plugins "$env:LOCALAPPDATA\\Skyrim Special Edition\\plugins.txt" \
      --ccc "C:\\Games\\Skyrim AE 1.6\\Skyrim.ccc"

Pass ``--all-files`` to inventory every plugin in Data instead of the enabled
entries in plugins.txt plus the five base-game masters.
"""

from __future__ import annotations

import argparse
import json
import mmap
import struct
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path


PLUGIN_SUFFIXES = {".esm", ".esp", ".esl"}
BASE_MASTERS = (
    "Skyrim.esm",
    "Update.esm",
    "Dawnguard.esm",
    "HearthFires.esm",
    "Dragonborn.esm",
)
PLACED_SIGNATURES = {
    b"REFR",  # object reference
    b"ACHR",  # actor reference
    b"PMIS",  # missile projectile
    b"PARW",  # arrow projectile
    b"PGRE",  # grenade projectile
    b"PBEA",  # beam projectile
    b"PFLA",  # flame projectile
    b"PCON",  # cone projectile
    b"PBAR",  # barrier projectile
    b"PHZD",  # placed hazard
}

RECORD_HEADER_SIZE = 24
PERSISTENT_FLAG = 0x400
DELETED_FLAG = 0x20
LIGHT_PLUGIN_FLAG = 0x200


@dataclass(frozen=True)
class PluginInventory:
    name: str
    bytes: int
    light_flagged: bool
    master_count: int
    record_count: int
    placed_occurrences: int
    origin_placed: int
    override_occurrences: int
    persistent_placed: int
    deleted_placed: int
    signatures: dict[str, int]


def _enabled_names(path: Path) -> set[str]:
    enabled = {name.casefold() for name in BASE_MASTERS}
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("*") and len(line) > 1:
            enabled.add(line[1:].casefold())
    return enabled


def _listed_names(path: Path) -> set[str]:
    names: set[str] = set()
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    for raw_line in text.splitlines():
        name = raw_line.strip()
        if not name or name.startswith("#"):
            continue
        if Path(name).name != name or Path(name).suffix.casefold() not in PLUGIN_SUFFIXES:
            raise ValueError(f"unsafe or invalid plugin name {name!r} in {path}")
        folded = name.casefold()
        if folded in names:
            raise ValueError(f"duplicate plugin name {name!r} in {path}")
        names.add(folded)
    return names


def _tes4_master_count(data: mmap.mmap, start: int, size: int) -> int:
    pos = start
    end = start + size
    count = 0
    while pos < end:
        if pos + 6 > end:
            raise ValueError(f"truncated TES4 subrecord header at 0x{pos:X}")
        signature = data[pos : pos + 4]
        payload_size = struct.unpack_from("<H", data, pos + 4)[0]
        pos += 6

        if signature == b"XXXX":
            if payload_size != 4 or pos + 4 > end:
                raise ValueError(f"invalid XXXX subrecord at 0x{pos - 6:X}")
            payload_size = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if pos + 6 > end:
                raise ValueError(f"XXXX without following subrecord at 0x{pos:X}")
            signature = data[pos : pos + 4]
            pos += 6  # the following 16-bit size is replaced by XXXX

        if pos + payload_size > end:
            raise ValueError(f"TES4 subrecord overruns header at 0x{pos:X}")
        if signature == b"MAST":
            count += 1
        pos += payload_size

    if pos != end:
        raise ValueError(f"TES4 subrecords end at 0x{pos:X}, expected 0x{end:X}")
    return count


def scan_plugin(path: Path) -> PluginInventory:
    counts: Counter[str] = Counter()
    record_count = 0
    placed = 0
    origin = 0
    overrides = 0
    persistent = 0
    deleted = 0
    master_count: int | None = None
    plugin_flags = 0

    with path.open("rb") as stream:
        file_size = stream.seek(0, 2)
        stream.seek(0)
        if file_size < RECORD_HEADER_SIZE:
            raise ValueError("file is shorter than one record header")

        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            pos = 0
            while pos + RECORD_HEADER_SIZE <= file_size:
                signature = data[pos : pos + 4]
                if signature == b"GRUP":
                    group_size = struct.unpack_from("<I", data, pos + 4)[0]
                    if group_size < RECORD_HEADER_SIZE or pos + group_size > file_size:
                        raise ValueError(
                            f"invalid GRUP at 0x{pos:X}: size 0x{group_size:X}"
                        )
                    # Groups have no footer.  Enter their contents by advancing
                    # over only the group header; record sizes keep the flat walk
                    # synchronized across nested groups.
                    pos += RECORD_HEADER_SIZE
                    continue

                try:
                    decoded_signature = signature.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise ValueError(
                        f"non-ASCII record signature {signature!r} at 0x{pos:X}"
                    ) from exc

                payload_size, flags, raw_form_id = struct.unpack_from(
                    "<III", data, pos + 4
                )
                record_end = pos + RECORD_HEADER_SIZE + payload_size
                if record_end > file_size:
                    raise ValueError(
                        f"{decoded_signature} at 0x{pos:X} overruns the file: "
                        f"payload size 0x{payload_size:X}"
                    )

                record_count += 1
                if signature == b"TES4":
                    if pos != 0:
                        raise ValueError(f"TES4 record is not first (offset 0x{pos:X})")
                    plugin_flags = flags
                    master_count = _tes4_master_count(
                        data, pos + RECORD_HEADER_SIZE, payload_size
                    )
                elif signature in PLACED_SIGNATURES:
                    if master_count is None:
                        raise ValueError("placed record encountered before TES4 header")
                    counts[decoded_signature] += 1
                    placed += 1
                    if (raw_form_id >> 24) == master_count:
                        origin += 1
                    else:
                        overrides += 1
                    if flags & PERSISTENT_FLAG:
                        persistent += 1
                    if flags & DELETED_FLAG:
                        deleted += 1

                pos = record_end

            if pos != file_size:
                raise ValueError(
                    f"trailing {file_size - pos} bytes after offset 0x{pos:X}"
                )

    if master_count is None:
        raise ValueError("missing TES4 header")

    return PluginInventory(
        name=path.name,
        bytes=file_size,
        light_flagged=bool(plugin_flags & LIGHT_PLUGIN_FLAG),
        master_count=master_count,
        record_count=record_count,
        placed_occurrences=placed,
        origin_placed=origin,
        override_occurrences=overrides,
        persistent_placed=persistent,
        deleted_placed=deleted,
        signatures=dict(sorted(counts.items())),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True, help="Skyrim Data folder")
    parser.add_argument(
        "--plugins",
        type=Path,
        help="plugins.txt; required unless --all-files is used",
    )
    parser.add_argument(
        "--all-files",
        action="store_true",
        help="scan every ESM/ESP/ESL in Data",
    )
    parser.add_argument(
        "--ccc",
        type=Path,
        help="optional Skyrim.ccc list whose entries auto-load in addition to plugins.txt",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="include one result object per plugin",
    )
    args = parser.parse_args()

    if not args.data.is_dir():
        parser.error(f"Data directory does not exist: {args.data}")
    if not args.all_files and args.plugins is None:
        parser.error("--plugins is required unless --all-files is used")
    if args.plugins is not None and not args.plugins.is_file():
        parser.error(f"plugins.txt does not exist: {args.plugins}")
    if args.ccc is not None and not args.ccc.is_file():
        parser.error(f"Skyrim.ccc does not exist: {args.ccc}")
    if args.all_files and args.ccc is not None:
        parser.error("--ccc is unnecessary with --all-files")

    enabled = None if args.all_files else _enabled_names(args.plugins)
    if enabled is not None and args.ccc is not None:
        try:
            enabled.update(_listed_names(args.ccc))
        except ValueError as exc:
            parser.error(str(exc))
    candidates = sorted(
        (
            path
            for path in args.data.iterdir()
            if path.is_file()
            and path.suffix.casefold() in PLUGIN_SUFFIXES
            and (enabled is None or path.name.casefold() in enabled)
        ),
        key=lambda path: path.name.casefold(),
    )

    results: list[PluginInventory] = []
    errors: list[dict[str, str]] = []
    for path in candidates:
        try:
            results.append(scan_plugin(path))
        except (OSError, ValueError) as exc:
            errors.append({"plugin": path.name, "error": str(exc)})

    signatures: Counter[str] = Counter()
    for result in results:
        signatures.update(result.signatures)

    missing = []
    if enabled is not None:
        found = {result.name.casefold() for result in results}
        missing = sorted(enabled - found)

    report: dict[str, object] = {
        "data": str(args.data.resolve()),
        "selection": "all files" if args.all_files else {
            "plugins": str(args.plugins.resolve()),
            "ccc": str(args.ccc.resolve()) if args.ccc is not None else None,
        },
        "plugin_files": len(results),
        "full_plugins": sum(not result.light_flagged for result in results),
        "light_flagged_plugins": sum(result.light_flagged for result in results),
        "placed_record_occurrences": sum(
            result.placed_occurrences for result in results
        ),
        "distinct_origin_placed_records": sum(
            result.origin_placed for result in results
        ),
        "override_occurrences": sum(result.override_occurrences for result in results),
        "persistent_placed_occurrences": sum(
            result.persistent_placed for result in results
        ),
        "deleted_placed_occurrences": sum(
            result.deleted_placed for result in results
        ),
        "placed_signatures": dict(sorted(signatures.items())),
        "missing_enabled_files": missing,
        "parse_errors": errors,
        "largest_origin_plugins": [
            {
                "plugin": result.name,
                "origin_placed": result.origin_placed,
                "placed_occurrences": result.placed_occurrences,
            }
            for result in sorted(
                results, key=lambda item: item.origin_placed, reverse=True
            )[:20]
        ],
    }
    if args.details:
        report["plugins"] = [asdict(result) for result in results]

    print(json.dumps(report, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
