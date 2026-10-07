"""Static .pdata / UNWIND_INFO map for the adhesive.dll evidence set (P0/S1).

Reads the x64 exception directory straight from the file on disk, expands every
IMAGE_RUNTIME_FUNCTION into a fully annotated row, and cross-checks the result
against reverse/evidence/baseline.json.

Static file parsing only: nothing in this module loads or executes the specimen.
Outputs are deterministic: fixed row order, fixed column order, no timestamps, so
repeated runs on an unchanged specimen produce byte-identical artifacts.
"""

from __future__ import annotations

import argparse
import bisect
import json
import struct
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Iterator, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import common

SCHEMA_PDATA_STATS: Final[str] = "adhesive-dumper.pdata-stats/1"

UNWIND_FLAG_EHANDLER: Final[int] = 0x01
UNWIND_FLAG_UHANDLER: Final[int] = 0x02
UNWIND_FLAG_CHAININFO: Final[int] = 0x04
UNWIND_HANDLER_MASK: Final[int] = UNWIND_FLAG_EHANDLER | UNWIND_FLAG_UHANDLER
UNWIND_VERSION_MASK: Final[int] = 0x07
UNWIND_INFO_FIXED_SIZE: Final[int] = 4
UNWIND_CODE_SIZE: Final[int] = 2
UNWIND_EXTENSION_ALIGNMENT: Final[int] = 4
CHAINED_ENTRY_SIZE: Final[int] = 12
HANDLER_POINTER_SIZE: Final[int] = 4
MAX_CHAIN_DEPTH: Final[int] = 32
UNWIND_FLAG_MASK: Final[int] = 0xF8
UNWIND_FLAG_SHIFT: Final[int] = 3

UNWIND_FLAG_NAMES: Final[Mapping[int, str]] = {
    UNWIND_FLAG_EHANDLER: "EHANDLER",
    UNWIND_FLAG_UHANDLER: "UHANDLER",
    UNWIND_FLAG_CHAININFO: "CHAININFO",
}

CODE_SECTION: Final[str] = ".text"
EXPECTED_RECORD_COUNT: Final[int] = common.EXPECTED_RUNTIME_FUNCTIONS
EXPECTED_UNIQUE_UNWIND: Final[int] = 15_533
EXPECTED_HANDLER_RECORDS: Final[int] = 2_804
EXPECTED_CHAIN_RECORDS: Final[int] = 2_163
EXPECTED_FLAG_DISTRIBUTION: Final[Mapping[int, int]] = {
    0: 137_037,
    1: 65,
    2: 45,
    3: 2_694,
    4: 2_163,
}
EXPECTED_UNWIND_SECTIONS: Final[Mapping[str, int]] = {".rdata": 15_533}
GAP_BUCKETS: Final[tuple[tuple[str, int, int], ...]] = (
    ("0x1", 1, 1),
    ("0x2..0xF", 2, 15),
    ("0x10..0xFF", 16, 255),
    ("0x100..0xFFF", 256, 4095),
    ("0x1000..0xFFFF", 4096, 65535),
    ("0x10000..0xFFFFF", 65536, 1048575),
    ("0x1000000+", 1048576, 1 << 62),
)
LARGEST_GAPS: Final[int] = 24

CSV_COLUMNS: Final[tuple[str, ...]] = (
    "record_index",
    "begin_address",
    "begin_address_hex",
    "end_address",
    "end_address_hex",
    "code_size",
    "code_section",
    "begin_raw",
    "end_raw",
    "record_raw",
    "record_raw_hex",
    "unwind_info_address",
    "unwind_info_address_hex",
    "unwind_info_raw",
    "unwind_info_raw_hex",
    "unwind_info_section",
    "unwind_info_index",
    "unwind_reference_count",
    "unwind_first_record",
    "unwind_version",
    "unwind_flags",
    "unwind_flag_names",
    "unwind_size_of_prolog",
    "unwind_count_of_codes",
    "unwind_frame_register",
    "unwind_frame_offset",
    "unwind_extension_offset",
    "unwind_info_end",
    "unwind_code_size",
    "has_handler",
    "handler_rva",
    "handler_rva_hex",
    "handler_raw",
    "handler_section",
    "has_chain",
    "chain_begin_address",
    "chain_begin_address_hex",
    "chain_end_address",
    "chain_end_address_hex",
    "chain_unwind_info_address",
    "chain_depth",
    "gap_before",
    "gap_before_hex",
)

COLUMN_NOTES: Final[Mapping[str, str]] = {
    "record_index": "0-based position inside the exception directory",
    "begin_raw": "file offset of BeginAddress",
    "end_raw": "file offset of EndAddress-1, the last covered byte",
    "record_raw": "file offset of this 12-byte IMAGE_RUNTIME_FUNCTION entry",
    "unwind_info_index": "1-based ordinal of the unique UNWIND_INFO, ascending by RVA",
    "unwind_reference_count": "runtime functions pointing at this UNWIND_INFO",
    "unwind_first_record": "lowest record_index pointing at this UNWIND_INFO",
    "unwind_info_end": "RVA just past the decoded UNWIND_INFO, padding included",
    "gap_before": "BeginAddress minus the previous record EndAddress, 0 when adjacent",
}


class RawReader:
    """Bounded RVA reader over an already opened specimen handle."""

    __slots__ = ("_handle", "_pe")

    def __init__(self, handle: Any, pe: Any) -> None:
        self._handle = handle
        self._pe = pe

    def read(self, rva: int, size: int) -> bytes:
        if rva < 0 or size <= 0:
            return b""
        raw = common.rva_to_raw(self._pe, rva)
        if raw is None:
            return b""
        self._handle.seek(raw)
        return self._handle.read(size)


class SectionIndex:
    """rva -> section lookups built once from common.Section records."""

    __slots__ = ("_entries", "_starts")

    def __init__(self, parsed: Sequence[common.Section]) -> None:
        self._entries = tuple(parsed)
        self._starts = tuple(entry.virtual_address for entry in parsed)

    def lookup(self, rva: int) -> common.Section | None:
        position = bisect.bisect_right(self._starts, rva) - 1
        if position < 0:
            return None
        entry = self._entries[position]
        return entry if entry.contains_rva_in_raw(rva) else None

    def name(self, rva: int) -> str:
        entry = self.lookup(rva)
        return entry.name if entry is not None else ""

    def raw(self, rva: int) -> int | None:
        entry = self.lookup(rva)
        if entry is None:
            return None
        return rva - entry.virtual_address + entry.raw_pointer

    def by_name(self, name: str) -> common.Section | None:
        for entry in self._entries:
            if entry.name == name:
                return entry
        return None


@dataclass(frozen=True, slots=True)
class UnwindInfo:
    """One decoded UNWIND_INFO, shared by one or more runtime functions."""

    rva: int
    raw: int | None
    section: str
    version: int
    flags: int
    size_of_prolog: int
    count_of_codes: int
    frame_register: int
    frame_offset: int
    extension_offset: int
    end: int
    handler_rva: int
    handler_raw: int | None
    handler_section: str
    chain_begin: int
    chain_end: int
    chain_unwind: int
    valid: bool

    @property
    def flag_names(self) -> list[str]:
        return [name for mask, name in UNWIND_FLAG_NAMES.items() if self.flags & mask]

    @property
    def has_handler(self) -> bool:
        return bool(self.flags & UNWIND_HANDLER_MASK)

    @property
    def has_chain(self) -> bool:
        return bool(self.flags & UNWIND_FLAG_CHAININFO)

    @property
    def code_size(self) -> int:
        return self.count_of_codes * UNWIND_CODE_SIZE


@dataclass(frozen=True, slots=True)
class Directory:
    """The x64 exception directory as located in the PE optional header."""

    rva: int
    raw: int | None
    size: int
    record_size: int
    count: int
    remainder: int


def parse_unwind_info(reader: RawReader, index: SectionIndex, rva: int) -> UnwindInfo:
    header = reader.read(rva, UNWIND_INFO_FIXED_SIZE)
    if len(header) < UNWIND_INFO_FIXED_SIZE:
        return UnwindInfo(
            rva=rva,
            raw=index.raw(rva),
            section=index.name(rva),
            version=0,
            flags=0,
            size_of_prolog=0,
            count_of_codes=0,
            frame_register=0,
            frame_offset=0,
            extension_offset=0,
            end=rva,
            handler_rva=0,
            handler_raw=None,
            handler_section="",
            chain_begin=0,
            chain_end=0,
            chain_unwind=0,
            valid=False,
        )
    flags = (header[0] & UNWIND_FLAG_MASK) >> UNWIND_FLAG_SHIFT
    extension_offset = common.align_up(
        UNWIND_INFO_FIXED_SIZE + header[2] * UNWIND_CODE_SIZE, UNWIND_EXTENSION_ALIGNMENT
    )
    has_handler = bool(flags & UNWIND_HANDLER_MASK)
    has_chain = bool(flags & UNWIND_FLAG_CHAININFO)
    handler_rva = 0
    chain_begin = 0
    chain_end = 0
    chain_unwind = 0
    if has_chain:
        body = reader.read(rva + extension_offset, CHAINED_ENTRY_SIZE)
        if len(body) == CHAINED_ENTRY_SIZE:
            chain_begin, chain_end, chain_unwind = struct.unpack("<III", body)
        end = rva + extension_offset + CHAINED_ENTRY_SIZE
    else:
        if has_handler:
            body = reader.read(rva + extension_offset, HANDLER_POINTER_SIZE)
            if len(body) == HANDLER_POINTER_SIZE:
                handler_rva = struct.unpack("<I", body)[0]
        end = rva + extension_offset + (HANDLER_POINTER_SIZE if has_handler else 0)
    return UnwindInfo(
        rva=rva,
        raw=index.raw(rva),
        section=index.name(rva),
        version=header[0] & UNWIND_VERSION_MASK,
        flags=flags,
        size_of_prolog=header[1],
        count_of_codes=header[2],
        frame_register=header[3] & 0x0F,
        frame_offset=(header[3] & 0xF0) >> 4,
        extension_offset=extension_offset,
        end=end,
        handler_rva=handler_rva,
        handler_raw=index.raw(handler_rva) if handler_rva else None,
        handler_section=index.name(handler_rva) if handler_rva else "",
        chain_begin=chain_begin,
        chain_end=chain_end,
        chain_unwind=chain_unwind,
        valid=True,
    )


def chain_depths(infos: Mapping[int, UnwindInfo]) -> dict[int, int]:
    """Resolve CHAININFO nesting depth per unique unwind info, cycle safe.

    A non-chained UNWIND_INFO has depth 0; a chained one is 1 + the depth of the
    UNWIND_INFO its chained IMAGE_RUNTIME_FUNCTION points at.
    """
    depths: dict[int, int] = {}
    for start in sorted(infos):
        if start in depths:
            continue
        path: list[int] = []
        seen: set[int] = set()
        current = start
        while True:
            if current in depths:
                depth = depths[current]
                break
            info = infos.get(current)
            if info is None or not info.valid or not info.has_chain:
                depth = 0
                break
            if current in seen or len(path) >= MAX_CHAIN_DEPTH:
                for visited in path:
                    depths[visited] = 0
                path.clear()
                break
            seen.add(current)
            path.append(current)
            current = info.chain_unwind
        for visited in reversed(path):
            depth += 1
            depths[visited] = depth
    return depths


def iterate_rows(
    records: Sequence[tuple[int, int, int]],
    infos: Mapping[int, UnwindInfo],
    depths: Mapping[int, int],
    index: SectionIndex,
    directory: Directory,
    ordinals: Mapping[int, int],
    references: Mapping[int, int],
    first_record: Mapping[int, int],
) -> Iterator[dict[str, Any]]:
    directory_raw = directory.raw
    previous_end: int | None = None
    for position, (begin, end, unwind_rva) in enumerate(records):
        info = infos[unwind_rva]
        section = index.lookup(begin)
        gap = begin - previous_end if previous_end is not None else 0
        previous_end = end
        record_raw = (
            directory_raw + position * directory.record_size if directory_raw is not None else None
        )
        yield {
            "record_index": position,
            "begin_address": begin,
            "begin_address_hex": common.hexs(begin),
            "end_address": end,
            "end_address_hex": common.hexs(end),
            "code_size": end - begin,
            "code_section": section.name if section is not None else "",
            "begin_raw": index.raw(begin) if section is not None else None,
            "end_raw": index.raw(end - 1) if section is not None else None,
            "record_raw": record_raw,
            "record_raw_hex": common.hexs(record_raw) if record_raw is not None else "",
            "unwind_info_address": unwind_rva,
            "unwind_info_address_hex": common.hexs(unwind_rva),
            "unwind_info_raw": info.raw,
            "unwind_info_raw_hex": common.hexs(info.raw) if info.raw is not None else "",
            "unwind_info_section": info.section,
            "unwind_info_index": ordinals[unwind_rva],
            "unwind_reference_count": references[unwind_rva],
            "unwind_first_record": first_record[unwind_rva],
            "unwind_version": info.version,
            "unwind_flags": info.flags,
            "unwind_flag_names": "|".join(info.flag_names),
            "unwind_size_of_prolog": info.size_of_prolog,
            "unwind_count_of_codes": info.count_of_codes,
            "unwind_frame_register": info.frame_register,
            "unwind_frame_offset": info.frame_offset,
            "unwind_extension_offset": info.extension_offset,
            "unwind_info_end": info.end,
            "unwind_code_size": info.code_size,
            "has_handler": info.has_handler,
            "handler_rva": info.handler_rva,
            "handler_rva_hex": common.hexs(info.handler_rva) if info.handler_rva else "",
            "handler_raw": info.handler_raw if info.handler_raw is not None else "",
            "handler_section": info.handler_section,
            "has_chain": info.has_chain,
            "chain_begin_address": info.chain_begin,
            "chain_begin_address_hex": common.hexs(info.chain_begin) if info.chain_begin else "",
            "chain_end_address": info.chain_end,
            "chain_end_address_hex": common.hexs(info.chain_end) if info.chain_end else "",
            "chain_unwind_info_address": info.chain_unwind,
            "chain_depth": depths.get(unwind_rva, 0) if info.has_chain else 0,
            "gap_before": gap,
            "gap_before_hex": common.hexs(gap),
        }


def gap_report(gaps: Sequence[tuple[int, int, int]]) -> dict[str, Any]:
    """Summarize inter-function holes; each entry is (begin, previous_end, size)."""
    histogram: Counter[str] = Counter()
    for _, _, size in gaps:
        for label, low, high in GAP_BUCKETS:
            if low <= size <= high:
                histogram[label] += 1
                break
    sizes = [size for _, _, size in gaps]
    total = sum(sizes)
    largest = sorted(gaps, key=lambda item: (-item[2], item[0]))[:LARGEST_GAPS]
    return {
        "count": len(gaps),
        "total_bytes": total,
        "total_hex": common.hexs(total),
        "min_bytes": min(sizes) if sizes else 0,
        "min_hex": common.hexs(min(sizes)) if sizes else "0x0",
        "max_bytes": max(sizes) if sizes else 0,
        "max_hex": common.hexs(max(sizes)) if sizes else "0x0",
        "histogram": {label: histogram[label] for label, _, _ in GAP_BUCKETS},
        "largest": [
            {
                "offset": begin,
                "offset_hex": common.hexs(begin),
                "previous_end": previous_end,
                "previous_end_hex": common.hexs(previous_end),
                "size": size,
                "size_hex": common.hexs(size),
            }
            for begin, previous_end, size in largest
        ],
    }


def analyze(
    pe: Any,
    reader: RawReader,
    index: SectionIndex,
    baseline: Mapping[str, Any],
) -> tuple[Directory, dict[str, Any], list[common.Check], dict[str, Any]]:
    entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[common.EXCEPTION_DIRECTORY_INDEX]
    record_size = common.RUNTIME_FUNCTION_SIZE
    count, remainder = divmod(int(entry.Size), record_size)
    directory = Directory(
        rva=int(entry.VirtualAddress),
        raw=common.rva_to_raw(pe, int(entry.VirtualAddress)),
        size=int(entry.Size),
        record_size=record_size,
        count=count,
        remainder=remainder,
    )
    blob = reader.read(directory.rva, directory.size)
    records = list(struct.iter_unpack("<III", blob[: count * record_size]))

    unwind_rvas = [record[2] for record in records]
    unique = sorted({rva for rva in unwind_rvas if rva})
    ordinals = {rva: position + 1 for position, rva in enumerate(unique)}
    references = Counter(unwind_rvas)
    first_record: dict[int, int] = {}
    for position, rva in enumerate(unwind_rvas):
        if rva not in first_record:
            first_record[rva] = position
    infos = {rva: parse_unwind_info(reader, index, rva) for rva in unique}
    depths = chain_depths(infos)
    unwind_sections: Counter[str] = Counter(
        info.section or "UNMAPPED" for info in infos.values()
    )

    code_section = index.by_name(CODE_SECTION)
    code_virtual_end = code_section.virtual_end if code_section else 0
    code_raw_end = (
        code_section.virtual_address + code_section.raw_size if code_section else 0
    )
    size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)
    code_sections: Counter[str] = Counter()
    handler_sections: Counter[str] = Counter()
    flags_per_record: Counter[int] = Counter()
    flags_per_unique: Counter[int] = Counter()
    names_per_unique: Counter[str] = Counter()
    names_per_record: Counter[str] = Counter()
    versions: Counter[int] = Counter()
    begin_counter: Counter[int] = Counter()
    handler_rvas: list[int] = []
    gaps: list[tuple[int, int, int]] = []
    code_sizes: list[int] = []
    prologs: list[int] = []
    code_counts: list[int] = []
    chain_records = 0
    chain_invalid = 0
    chain_range_above_record = 0
    unwind_record_sections: Counter[str] = Counter()
    unwind_unmapped = 0
    unwind_end_unmapped = 0
    unwind_invalid_header = 0
    records_outside_text = 0
    records_outside_image = 0
    out_of_order_pairs = 0
    overlap_pairs = 0
    previous_end: int | None = None
    for position, (begin, end, unwind_rva) in enumerate(records):
        begin_counter[begin] += 1
        code_sizes.append(end - begin)
        if position and previous_end is not None:
            if begin < records[position - 1][0]:
                out_of_order_pairs += 1
            if begin < previous_end:
                overlap_pairs += 1
            if begin != previous_end:
                gaps.append((begin, previous_end, begin - previous_end))
        previous_end = end
        owner = index.lookup(begin)
        code_sections[owner.name if owner is not None else "UNMAPPED"] += 1
        if code_section is not None and not (
            code_section.virtual_address <= begin and end <= code_raw_end
        ):
            records_outside_text += 1
        if end > size_of_image:
            records_outside_image += 1
        info = infos[unwind_rva]
        if not info.valid:
            unwind_invalid_header += 1
        if info.section:
            unwind_record_sections[info.section] += 1
        if info.raw is None:
            unwind_unmapped += 1
        elif index.lookup(info.end) is None:
            unwind_end_unmapped += 1
        versions[info.version] += 1
        flags_per_record[info.flags] += 1
        prologs.append(info.size_of_prolog)
        code_counts.append(info.count_of_codes)
        for name in info.flag_names:
            names_per_record[name] += 1
        if info.has_handler:
            handler_rvas.append(info.handler_rva)
            handler_sections[info.handler_section or "UNMAPPED"] += 1
        if info.has_chain:
            chain_records += 1
            if not (info.chain_begin < info.chain_end and info.chain_unwind in ordinals):
                chain_invalid += 1
            elif info.chain_end > begin:
                chain_range_above_record += 1
    for rva in unique:
        flags_per_unique[infos[rva].flags] += 1
        for name in infos[rva].flag_names:
            names_per_unique[name] += 1

    begin_min = min(begin_counter)
    end_max = max(end for _, end, _ in records)
    covered_bytes = sum(code_sizes)
    span = end_max - begin_min
    gap_summary = gap_report(gaps)
    leading_gap = begin_min - code_section.virtual_address if code_section else None
    trailing_gap = code_raw_end - end_max if code_section else None
    beyond_virtual_size = max(0, end_max - code_virtual_end) if code_section else None
    reference_counts = sorted(references.values())

    stats: dict[str, Any] = {
        "exception_directory": {
            "rva": directory.rva,
            "rva_hex": common.hexs(directory.rva),
            "raw": directory.raw,
            "raw_hex": common.hexs(directory.raw) if directory.raw is not None else None,
            "section": index.name(directory.rva),
            "size": directory.size,
            "size_hex": common.hexs(directory.size),
            "record_size": record_size,
            "record_count": count,
            "record_count_hex": common.hexs(count),
            "record_remainder": remainder,
            "parsed_records": len(records),
        },
        "ordering": {
            "sorted_by_begin_address": out_of_order_pairs == 0,
            "out_of_order_pairs": out_of_order_pairs,
            "duplicate_records": len(records) - len(begin_counter),
            "duplicate_begin_addresses": sum(1 for value in begin_counter.values() if value > 1),
            "overlapping_records": overlap_pairs,
            "begin_address_min": begin_min,
            "begin_address_min_hex": common.hexs(begin_min),
            "end_address_max": end_max,
            "end_address_max_hex": common.hexs(end_max),
        },
        "unwind_info": {
            "null_address_records": sum(1 for rva in unwind_rvas if rva == 0),
            "unique_count": len(unique),
            "unmapped_records": unwind_unmapped,
            "invalid_header_records": unwind_invalid_header,
            "end_outside_section_records": unwind_end_unmapped,
            "rva_min": unique[0] if unique else None,
            "rva_min_hex": common.hexs(unique[0]) if unique else None,
            "rva_max": unique[-1] if unique else None,
            "rva_max_hex": common.hexs(unique[-1]) if unique else None,
            "sections": {name: unwind_sections[name] for name in sorted(unwind_sections)},
            "sections_per_record": {
                name: unwind_record_sections[name] for name in sorted(unwind_record_sections)
            },
            "version_distribution": {str(value): versions[value] for value in sorted(versions)},
            "version_invalid_records": sum(
                occurrences for value, occurrences in versions.items() if value != 1
            ),
            "reference_count_max": reference_counts[-1] if reference_counts else 0,
            "reference_count_median": reference_counts[len(reference_counts) // 2]
            if reference_counts
            else 0,
            "size_of_prolog_min": min(prologs) if prologs else 0,
            "size_of_prolog_max": max(prologs) if prologs else 0,
            "count_of_codes_min": min(code_counts) if code_counts else 0,
            "count_of_codes_max": max(code_counts) if code_counts else 0,
        },
        "unwind_flags": {
            "value_distribution_per_record": {
                str(value): flags_per_record[value] for value in sorted(flags_per_record)
            },
            "value_distribution_per_unique_info": {
                str(value): flags_per_unique[value] for value in sorted(flags_per_unique)
            },
            "name_distribution_per_unique_info": {
                name: names_per_unique[name] for name in sorted(names_per_unique)
            },
            "name_distribution_per_record": {
                name: names_per_record[name] for name in sorted(names_per_record)
            },
            "records_with_handler": sum(
                occurrences
                for value, occurrences in flags_per_record.items()
                if value & UNWIND_HANDLER_MASK
            ),
            "records_with_chain": chain_records,
        },
        "handlers": {
            "record_count": len(handler_rvas),
            "unique_handler_rvas": len(set(handler_rvas)),
            "rva_min": min(handler_rvas) if handler_rvas else None,
            "rva_min_hex": common.hexs(min(handler_rvas)) if handler_rvas else None,
            "rva_max": max(handler_rvas) if handler_rvas else None,
            "rva_max_hex": common.hexs(max(handler_rvas)) if handler_rvas else None,
            "sections": {name: handler_sections[name] for name in sorted(handler_sections)},
        },
        "chains": {
            "record_count": chain_records,
            "invalid_chained_entries": chain_invalid,
            "chained_range_above_record_begin": chain_range_above_record,
            "depth_max": max(depths.values()) if depths else 0,
            "unique_infos_by_depth": {
                str(value): sum(1 for depth in depths.values() if depth == value)
                for value in sorted(set(depths.values()))
            },
        },
        "text_coverage": {
            "section": CODE_SECTION,
            "section_present": code_section is not None,
            "section_virtual_address": code_section.virtual_address if code_section else None,
            "section_virtual_address_hex": common.hexs(code_section.virtual_address)
            if code_section
            else None,
            "section_virtual_size": code_section.virtual_size if code_section else None,
            "section_virtual_size_hex": common.hexs(code_section.virtual_size)
            if code_section
            else None,
            "section_raw_size": code_section.raw_size if code_section else None,
            "section_raw_size_hex": common.hexs(code_section.raw_size) if code_section else None,
            "section_virtual_end": code_virtual_end,
            "section_virtual_end_hex": common.hexs(code_virtual_end),
            "section_raw_end_rva": code_raw_end,
            "section_raw_end_rva_hex": common.hexs(code_raw_end),
            "records_by_section": {name: code_sections[name] for name in sorted(code_sections)},
            "records_outside_text": records_outside_text,
            "records_outside_size_of_image": records_outside_image,
            "covered_bytes": covered_bytes,
            "covered_hex": common.hexs(covered_bytes),
            "uncovered_bytes": span - covered_bytes,
            "uncovered_hex": common.hexs(span - covered_bytes),
            "span_bytes": span,
            "span_hex": common.hexs(span),
            "coverage_of_span_percent": round(covered_bytes * 100.0 / span, 6) if span else 0.0,
            "coverage_of_virtual_size_percent": round(
                covered_bytes * 100.0 / code_section.virtual_size, 6
            )
            if code_section and code_section.virtual_size
            else 0.0,
            "leading_gap": leading_gap,
            "leading_gap_hex": common.hexs(leading_gap) if leading_gap is not None else None,
            "trailing_gap": trailing_gap,
            "trailing_gap_hex": common.hexs(trailing_gap) if trailing_gap is not None else None,
            "bytes_beyond_declared_virtual_size": beyond_virtual_size,
            "bytes_beyond_declared_virtual_size_hex": common.hexs(beyond_virtual_size)
            if beyond_virtual_size is not None
            else None,
            "code_size_min": min(code_sizes) if code_sizes else 0,
            "code_size_max": max(code_sizes) if code_sizes else 0,
        },
        "gaps": gap_summary,
    }
    context = {
        "records": records,
        "infos": infos,
        "depths": depths,
        "index": index,
        "directory": directory,
        "ordinals": ordinals,
        "references": references,
        "first_record": first_record,
    }

    baseline_pdata = baseline.get("pdata", {})
    expected_flags = {
        str(value): occurrences for value, occurrences in EXPECTED_FLAG_DISTRIBUTION.items()
    }
    checks: list[common.Check] = []

    def expect(name: str, want: Any, got: Any) -> None:
        checks.append(common.Check(name=name, expected=want, actual=got, ok=want == got))

    expect("record.count", EXPECTED_RECORD_COUNT, count)
    expect("record.remainder", 0, remainder)
    expect("record.parsed", EXPECTED_RECORD_COUNT, len(records))
    expect("record.sorted_by_begin", True, stats["ordering"]["sorted_by_begin_address"])
    expect("record.duplicates", 0, stats["ordering"]["duplicate_records"])
    expect("record.overlaps", 0, overlap_pairs)
    expect("record.nonempty_range", True, all(size > 0 for size in code_sizes))
    expect("record.outside_size_of_image", 0, records_outside_image)
    expect("unwind.null_address", 0, stats["unwind_info"]["null_address_records"])
    expect("unwind.unique", EXPECTED_UNIQUE_UNWIND, len(unique))
    expect("unwind.sections", dict(EXPECTED_UNWIND_SECTIONS), stats["unwind_info"]["sections"])
    expect("unwind.version_invalid", 0, stats["unwind_info"]["version_invalid_records"])
    expect("unwind.unmapped", 0, unwind_unmapped)
    expect("unwind.end_outside_section", 0, unwind_end_unmapped)
    expect("unwind.invalid_header", 0, unwind_invalid_header)
    expect(
        "flags.distribution_per_record",
        expected_flags,
        stats["unwind_flags"]["value_distribution_per_record"],
    )
    expect("handlers.records", EXPECTED_HANDLER_RECORDS, len(handler_rvas))
    expect(
        "handlers.sections",
        {CODE_SECTION: EXPECTED_HANDLER_RECORDS},
        stats["handlers"]["sections"],
    )
    expect("chains.records", EXPECTED_CHAIN_RECORDS, chain_records)
    expect("chains.invalid_entries", 0, chain_invalid)
    expect(
        "text.records",
        {CODE_SECTION: EXPECTED_RECORD_COUNT},
        stats["text_coverage"]["records_by_section"],
    )
    expect("text.records_outside", 0, records_outside_text)
    expect("text.covered_plus_gaps", span, covered_bytes + gap_summary["total_bytes"])
    expect("text.covered_within_span", True, covered_bytes <= span)
    expect("baseline.record_count", baseline_pdata.get("record_count"), count)
    expect(
        "baseline.duplicate_records",
        baseline_pdata.get("duplicate_records"),
        stats["ordering"]["duplicate_records"],
    )
    expect("baseline.overlapping_records", baseline_pdata.get("overlapping_records"), overlap_pairs)
    expect("baseline.begin_address_min", baseline_pdata.get("begin_address_min"), begin_min)
    expect("baseline.end_address_max", baseline_pdata.get("end_address_max"), end_max)
    expect(
        "baseline.unwind_info_address_null",
        baseline_pdata.get("unwind_info_address_null"),
        stats["unwind_info"]["null_address_records"],
    )
    expect("baseline.unique_unwind_infos", baseline_pdata.get("unique_unwind_infos"), len(unique))
    expect(
        "baseline.unwind_info_rva_min",
        baseline_pdata.get("unwind_info_rva_min"),
        unique[0] if unique else None,
    )
    expect(
        "baseline.unwind_info_rva_max",
        baseline_pdata.get("unwind_info_rva_max"),
        unique[-1] if unique else None,
    )
    expect(
        "baseline.unwind_info_sections",
        baseline_pdata.get("unwind_info_sections"),
        stats["unwind_info"]["sections"],
    )
    expect(
        "baseline.unwind_flag_value_distribution",
        baseline_pdata.get("unwind_flag_value_distribution"),
        stats["unwind_flags"]["value_distribution_per_record"],
    )
    expect(
        "baseline.unwind_flag_distribution_per_unique_info",
        baseline_pdata.get("unwind_flag_distribution_per_unique_info"),
        stats["unwind_flags"]["name_distribution_per_unique_info"],
    )
    return directory, stats, checks, context


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description="Static .pdata / UNWIND_INFO map for the adhesive.dll specimen"
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument(
        "--baseline", type=Path, default=root / "reverse" / "evidence" / "baseline.json"
    )
    parser.add_argument(
        "--csv", type=Path, default=root / "reverse" / "evidence" / "pdata_functions.csv"
    )
    parser.add_argument(
        "--stats", type=Path, default=root / "reverse" / "evidence" / "pdata_stats.json"
    )
    parser.add_argument(
        "--no-csv", action="store_true", help="skip the csv, print the summary only"
    )
    parser.add_argument("--max-report", type=int, default=40, help="mismatches to print")
    args = parser.parse_args(argv)

    specimen = args.specimen.resolve()
    baseline_path = args.baseline.resolve()
    csv_path = args.csv.resolve()
    stats_path = args.stats.resolve()

    def relative(path: Path) -> str:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            return path.as_posix()

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    stored_sha256 = baseline.get("specimen", {}).get("sha256")
    specimen_sha256 = common.sha256_file(specimen)

    pe = common.load_pe(specimen)
    try:
        index = SectionIndex(common.sections(pe))
        with specimen.open("rb") as handle:
            directory, stats, checks, context = analyze(
                pe, RawReader(handle, pe), index, baseline
            )
            if not args.no_csv:
                common.write_csv(
                    csv_path,
                    iterate_rows(
                        context["records"],
                        context["infos"],
                        context["depths"],
                        context["index"],
                        context["directory"],
                        context["ordinals"],
                        context["references"],
                        context["first_record"],
                    ),
                    CSV_COLUMNS,
                )
    finally:
        pe.close()

    checks.insert(
        0,
        common.Check(
            name="specimen.sha256_matches_baseline",
            expected=stored_sha256,
            actual=specimen_sha256,
            ok=stored_sha256 == specimen_sha256,
        ),
    )

    coverage = stats["text_coverage"]
    flags = stats["unwind_flags"]
    payload: dict[str, Any] = {
        "schema": SCHEMA_PDATA_STATS,
        "producer": {
            "script": relative(script),
            "script_sha256": common.sha256_file(script),
            "helper": relative(script.parent / "common.py"),
            "helper_sha256": common.sha256_file(script.parent / "common.py"),
            "baseline": relative(baseline_path),
            "baseline_sha256": common.sha256_file(baseline_path),
        },
        "specimen": {
            "path": relative(specimen),
            "name": specimen.name,
            "size": specimen.stat().st_size,
            "sha256": specimen_sha256,
            "sha256_matches_baseline": stored_sha256 == specimen_sha256,
            "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
            "image_base_hex": common.hexs(int(pe.OPTIONAL_HEADER.ImageBase)),
            "size_of_image": int(pe.OPTIONAL_HEADER.SizeOfImage),
            "size_of_image_hex": common.hexs(int(pe.OPTIONAL_HEADER.SizeOfImage)),
        },
        "parsing": {
            "record_layout": "IMAGE_RUNTIME_FUNCTION { BeginAddress, EndAddress, UnwindInfoAddress }",
            "record_size": stats["exception_directory"]["record_size"],
            "unwind_layout": (
                "UNWIND_INFO { Version:3, Flags:5, SizeOfProlog, CountOfCodes, "
                "FrameRegister:4, FrameOffset:4 }"
            ),
            "extension_offset_rule": "align_up(4 + 2 * CountOfCodes, 4)",
            "flag_masks": {name: mask for mask, name in UNWIND_FLAG_NAMES.items()},
            "csv_columns": list(CSV_COLUMNS),
            "csv_column_notes": {name: COLUMN_NOTES[name] for name in sorted(COLUMN_NOTES)},
        },
        "expected": {
            "record_count": EXPECTED_RECORD_COUNT,
            "unique_unwind_info": EXPECTED_UNIQUE_UNWIND,
            "flag_distribution_per_record": {
                str(value): occurrences for value, occurrences in EXPECTED_FLAG_DISTRIBUTION.items()
            },
            "unwind_sections": dict(EXPECTED_UNWIND_SECTIONS),
            "handler_records": EXPECTED_HANDLER_RECORDS,
            "chain_records": EXPECTED_CHAIN_RECORDS,
            "source": common.EXPECTED_RUNTIME_FUNCTION_SOURCE,
        },
        "csv": {
            "path": relative(csv_path),
            "row_count": stats["exception_directory"]["parsed_records"],
            "row_order": "exception directory order, BeginAddress ascending",
            "column_count": len(CSV_COLUMNS),
            "encoding": "utf-8",
            "bom": False,
            "line_terminator": "\\n",
            "sha256": common.sha256_file(csv_path) if not args.no_csv else None,
        },
        "exception_directory": stats["exception_directory"],
        "ordering": stats["ordering"],
        "unwind_info": stats["unwind_info"],
        "unwind_flags": stats["unwind_flags"],
        "handlers": stats["handlers"],
        "chains": stats["chains"],
        "text_coverage": coverage,
        "gaps": stats["gaps"],
        "validation": {
            "check_count": len(checks),
            "failed_count": sum(1 for check in checks if not check.ok),
            "checks": [check.as_row() for check in checks],
        },
    }
    common.write_json(stats_path, payload)

    failed = common.report_checks(checks, args.max_report)
    flag_text = " ".join(
        f"{value}:{occurrences}"
        for value, occurrences in flags["value_distribution_per_record"].items()
    )
    print(
        f"exception rva={stats['exception_directory']['rva_hex']} "
        f"raw={stats['exception_directory']['raw_hex']} "
        f"size={stats['exception_directory']['size_hex']} "
        f"records={stats['exception_directory']['record_count']} "
        f"section={stats['exception_directory']['section']}"
    )
    print(
        f"unwind    unique={stats['unwind_info']['unique_count']} "
        f"null={stats['unwind_info']['null_address_records']} "
        f"version_invalid={stats['unwind_info']['version_invalid_records']} "
        f"sections={','.join(stats['unwind_info']['sections'])}"
    )
    print(
        f"flags     {flag_text} "
        f"chain={flags['records_with_chain']} handler={flags['records_with_handler']} "
        f"chain_depth_max={stats['chains']['depth_max']}"
    )
    print(
        f"text      covered={coverage['covered_hex']}/{coverage['span_hex']} "
        f"coverage={coverage['coverage_of_span_percent']:.4f}% "
        f"gaps={stats['gaps']['count']} total={stats['gaps']['total_hex']} "
        f"max={stats['gaps']['max_hex']}"
    )
    if not args.no_csv:
        print(
            f"csv       {relative(csv_path)} rows={payload['csv']['row_count']} "
            f"columns={len(CSV_COLUMNS)} sha256={payload['csv']['sha256']}"
        )
    print(f"json      {relative(stats_path)}")
    print(f"checks    {len(checks) - failed}/{len(checks)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
