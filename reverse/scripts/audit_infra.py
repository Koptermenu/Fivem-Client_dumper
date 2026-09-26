"""Independent static infrastructure audit of the adhesive.dll evidence set.

The audit is read only. It never loads, maps as an image, or executes the
specimen: every specimen fact is re-derived by parsing the file as data, and
every other fact is re-derived by reading the evidence files as text. The audit
also never imports the producer modules under review; their declared column
orders and expected counts are extracted from their source with ``ast`` so a
behavioural change in a producer cannot silently redefine its own contract.

Scope: ``reverse/scripts/common.py``, ``reverse/evidence/baseline.json``,
``toolchain.json``, ``pdata_functions.csv``, ``pdata_stats.json``,
``cfg_functions.csv``, ``cfg_clusters.csv``, ``xref_edges.csv``,
``indirect_sites.csv``, ``syscall_candidates_raw.csv`` and the specimen digest.
Artifacts outside that list are reported as out of scope, not audited.

Two schemas are read as they stand rather than as they were first written.
``xref_edges.csv`` and ``indirect_sites.csv`` name the pdata function that owns a
decoded instruction ``code_instruction_function_*`` and the pdata function that
hosts an import thunk jmp ``target_thunk_function_*``, so a marker byte that is
not an instruction start carries the latter and leaves the former empty.
``toolchain.json`` carries a ``script_inventory`` block, a ``package_versions``
block that versions every third-party package on independent axes instead of
collapsing them into one number, and a ``digests`` block; the flat
``libraries`` block is therefore cross-checked against the axes rather than
compared for internal equality.

The digest rule accepts a digest recorded by the ``toolchain.json`` digests
block on the same footing as one recorded by a producer, and names the record
that attests each artifact. Presence alone is not enough: every attested digest
has to reproduce from the file bytes, and coverage of the audited artifact list
is asserted by a check rather than inferred from an empty residual. Two cycle
guards keep the block from describing an unsatisfiable fixed point: the payload
may not be an attested target, and no attested artifact may carry the payload
digest in its bytes, so the digests and the files they cover do not attest each
other.

Output is written to ``reverse/evidence/audit_infra.json`` through a local
writer. The payload carries no timestamp, no host path and no environment
value, so a rerun on an unchanged tree produces a byte identical file.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import math
import re
import struct
import sys
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Iterator, Mapping, Sequence

SCHEMA: Final[str] = "adhesive-dumper.audit-infra/1"
SCRIPT_RELATIVE: Final[str] = "reverse/scripts/audit_infra.py"
DEFAULT_OUTPUT: Final[str] = "reverse/evidence/audit_infra.json"
TOOLCHAIN_RELATIVE: Final[str] = "reverse/evidence/toolchain.json"
BOM: Final[bytes] = b"\xef\xbb\xbf"
RUNTIME_FUNCTION_SIZE: Final[int] = 12
UNWIND_FLAG_MASKS: Final[Mapping[int, str]] = {1: "EHANDLER", 2: "UHANDLER", 4: "CHAININFO"}
RATIO_DIGITS: Final[int] = 6
AVERAGE_DIGITS: Final[int] = 3
ENTROPY_DIGITS: Final[int] = 6
DEFAULT_CLUSTER_GAP: Final[int] = 0x1000
IMAGE_BASE_CLAIM: Final[int] = 0x180000000
UNRESOLVED: Final[str] = "<unresolved>"
HOST_PATH_FIELDS: Final[tuple[str, ...]] = (
    "libraries.pefile.module_path",
    "libraries.lief.module_path",
    "libraries.capstone.module_path",
    "binutils.objdump.path",
)
HOST_PATH_PATTERN: Final[Any] = re.compile(r"[A-Za-z]:\\|\\Users\\|/(?:home|usr|opt)/")

CODE_FUNCTION_FIELDS: Final[tuple[str, str, str]] = (
    "code_instruction_function_index",
    "code_instruction_function_begin",
    "code_instruction_function_end",
)
THUNK_FUNCTION_FIELDS: Final[tuple[str, str, str]] = (
    "target_thunk_function_index",
    "target_thunk_function_begin",
    "target_thunk_function_end",
)
THUNK_STUB_OUTSIDE_ANNOTATION: Final[str] = (
    "import_thunk_stub_outside_every_pdata_runtime_function"
)
THUNK_STUB_INTERIOR_ANNOTATION: Final[str] = (
    "import_thunk_stub_interior_byte_of_a_decoded_jmp_inside_a_pdata_function"
)
THUNK_STUB_INTERIOR_ARITHMETIC: Final[Any] = re.compile(
    r"stub_is_byte_(\d+)_of_a_decoded_(\d+)_byte_jmp_at_0x([0-9A-Fa-f]+)"
    r"\+covering_first_byte=0x([0-9A-Fa-f]+)"
)
THUNK_MARKER_BYTES: Final[bytes] = b"\xff\x25"

SCRIPT_INVENTORY_ROOT: Final[str] = "reverse/scripts"
SCRIPT_INVENTORY_GLOB: Final[str] = "*.py"
SCRIPT_INVENTORY_FIELDS: Final[tuple[str, ...]] = (
    "path",
    "name",
    "size",
    "sha256",
    "utf8_bom",
    "crlf_line_count",
    "lf_line_count",
    "third_party_imports",
)
SCRIPT_INVENTORY_OMITTED: Final[tuple[str, ...]] = ("atime", "ctime", "mtime")
PACKAGE_AXES: Final[tuple[str, ...]] = (
    "package_metadata",
    "imported_module",
    "native_engine",
)
PACKAGE_COMPARABLE_AXES: Final[tuple[str, ...]] = ("package_metadata", "imported_module")
LIBRARY_BLOCK_AXIS_FIELD: Final[Mapping[str, str]] = {
    "package_metadata.version": "distribution_version",
    "imported_module.version": "module_version",
    "native_engine.version": "engine_version",
}
DIGEST_ALGORITHM_CLAIM: Final[str] = "sha256 over the file bytes, recomputed on every refresh"
DIGEST_SOURCE_PDATA_STATS: Final[str] = "reverse/evidence/pdata_stats.json"
DIGEST_SOURCE_TOOLCHAIN: Final[str] = "reverse/evidence/toolchain.json#digests.entries"

SCRIPT_COMMON: Final[str] = "reverse/scripts/common.py"
PRODUCERS: Final[Mapping[str, str]] = {
    "common.py": SCRIPT_COMMON,
    "pdata_map.py": "reverse/scripts/pdata_map.py",
    "cfg_build.py": "reverse/scripts/cfg_build.py",
    "xref_build.py": "reverse/scripts/xref_build.py",
    "syscall_scan.py": "reverse/scripts/syscall_scan.py",
}

JSON_EVIDENCE: Final[tuple[str, ...]] = (
    "reverse/evidence/baseline.json",
    "reverse/evidence/toolchain.json",
    "reverse/evidence/pdata_stats.json",
)
CSV_EVIDENCE: Final[tuple[str, ...]] = (
    "reverse/evidence/pdata_functions.csv",
    "reverse/evidence/cfg_functions.csv",
    "reverse/evidence/cfg_clusters.csv",
    "reverse/evidence/xref_edges.csv",
    "reverse/evidence/indirect_sites.csv",
    "reverse/evidence/syscall_candidates_raw.csv",
)
EVIDENCE_DIR: Final[str] = "reverse/evidence"
AUDITED_ARTIFACTS: Final[tuple[str, ...]] = (SCRIPT_COMMON,) + JSON_EVIDENCE + CSV_EVIDENCE

DOC02: Final[str] = "reverse/adhesive-02-pe-layout-security.md"
DOC03: Final[str] = "reverse/adhesive-03-imports-exports.md"
DOC12: Final[str] = "reverse/adhesive-12-risk-methodology-open-questions.md"

DOCUMENTED: Final[Mapping[str, tuple[str, int, str]]] = {
    "runtime_function_records": (DOC02, 142_004, "adhesive-02 section 15 RUNTIME_FUNCTION records"),
    "exception_directory_size_div_12": (
        DOC02,
        142_004,
        "adhesive-02 section 15 Size / 12 with no remainder",
    ),
    "unique_unwind_info": (DOC02, 15_533, "adhesive-02 section 15 unique unwind info"),
    "unwind_flag_zero": (DOC02, 137_037, "adhesive-02 unwind flag distribution, value 0"),
    "unwind_flag_ehandler": (DOC02, 65, "adhesive-02 unwind flag distribution, value 1"),
    "unwind_flag_uhandler": (DOC02, 45, "adhesive-02 unwind flag distribution, value 2"),
    "unwind_flag_ehandler_uhandler": (DOC02, 2_694, "adhesive-02 unwind flag distribution, value 3"),
    "unwind_flag_chaininfo": (DOC02, 2_163, "adhesive-02 unwind flag distribution, value 4"),
    "handler_records": (DOC02, 2_804, "adhesive-02 section 15 records carrying a handler flag"),
    "chain_records": (DOC02, 2_163, "adhesive-02 section 15 CHAININFO records"),
    "direct_iat_call_xrefs": (DOC03, 3_132, "adhesive-03 section 2 accepted direct call [IAT] xrefs"),
    "direct_iat_call_xrefs_regular": (
        DOC03,
        3_131,
        "adhesive-03 section 2 accepted direct call [IAT] xrefs, regular slots",
    ),
    "direct_iat_call_xrefs_delay": (
        DOC03,
        1,
        "adhesive-03 section 2 accepted direct call [IAT] xrefs, delay slot",
    ),
    "thunk_mediated_call_xrefs": (
        DOC03,
        6_304,
        "adhesive-03 section 2 call rel32 xrefs through an import thunk",
    ),
    "import_thunks": (DOC03, 355, "adhesive-03 section 2 import jmp [IAT] thunks"),
    "thunks_reached_by_call": (
        DOC03,
        193,
        "adhesive-03 section 2 import thunks reached by at least one CALL xref",
    ),
    "iat_slots_total": (DOC03, 629, "adhesive-03 section 2 regular plus delay IAT slots"),
    "iat_slots_reached_direct": (DOC03, 364, "adhesive-03 section 2 IAT slots with a direct CALL xref"),
    "iat_slots_touched": (DOC03, 527, "adhesive-03 section 2 IAT slots touched by either xref kind"),
    "total_statistical_call_xrefs": (DOC03, 9_436, "adhesive-03 section 2 all statistical CALL xrefs"),
    "raw_ff15_candidates": (DOC03, 3_148, "adhesive-03 section 9 raw FF 15 candidates onto an IAT slot"),
    "raw_ff15_rejected": (DOC03, 16, "adhesive-03 section 9 raw candidates dropped by the pdata filter"),
    "xref_runtime_functions": (
        DOC03,
        6_039,
        "adhesive-03 section 9 runtime functions carrying an accepted xref",
    ),
    "xref_runtime_function_bytes": (
        DOC03,
        5_353_470,
        "adhesive-03 section 9 bytes of those runtime functions",
    ),
    "syscall_raw_hits": (DOC12, 3_881, "adhesive-12 direct syscall scope raw 0F 05 hits"),
}

FIELD_SOURCES: Final[Mapping[str, tuple[str, str]]] = {
    "reverse/evidence/pdata_functions.csv": ("pdata_map.py", "CSV_COLUMNS"),
    "reverse/evidence/cfg_functions.csv": ("cfg_build.py", "FUNCTION_FIELDS"),
    "reverse/evidence/cfg_clusters.csv": ("cfg_build.py", "CLUSTER_FIELDS"),
    "reverse/evidence/xref_edges.csv": ("xref_build.py", "EDGE_FIELDS"),
    "reverse/evidence/indirect_sites.csv": ("xref_build.py", "SITE_FIELDS"),
    "reverse/evidence/syscall_candidates_raw.csv": ("syscall_scan.py", "CSV_FIELDS"),
}

CLUSTER_COUNTER_HEADER: Final[str] = (
    "cluster_id,first_rva,first_rva_hex,last_end_rva,last_end_rva_hex,rva_span,section,"
    "function_count,size_min,size_max,size_total,size_average,span_bytes,code_bytes,gap_bytes,"
    "entropy_span,entropy_code,basic_blocks,blocks_reached,blocks_linear_only,reached_ratio,"
    "instructions,decoded_bytes,undecoded_bytes,undecoded_regions,edges,back_edges,max_indegree,"
    "cross_calls,cross_jumps,cross_function_edges,direct_calls,direct_jumps,indirect_calls,"
    "indirect_jumps,indirect_jumps_unresolved,iat_call_sites,iat_jump_sites,iat_module_count,"
    "iat_symbol_count,iat_symbols,switch_sites,switch_sites_validated,switch_sites_rejected,"
    "switch_cases,ret_sites,ud2_sites,int3_sites,trap_sites,syscall_sites,"
    "functions_with_linear_blocks,functions_with_undecoded,functions_with_entry_refs,"
    "functions_multi_entry,unwind_ehandler,unwind_uhandler,unwind_chaininfo,overlapping_functions,"
    "entry_point_inside,export_inside,doc_anchors,anchor_tags,anchor_evidence,anchor_count,"
    "anchor_truncated"
)
FUNCTION_SUMMED: Final[tuple[str, ...]] = (
    "basic_blocks",
    "blocks_reached",
    "blocks_linear_only",
    "instructions",
    "decoded_bytes",
    "undecoded_bytes",
    "undecoded_regions",
    "edges",
    "back_edges",
    "cross_calls",
    "cross_jumps",
    "direct_calls",
    "direct_jumps",
    "indirect_calls",
    "indirect_jumps",
    "indirect_jumps_unresolved",
    "iat_call_sites",
    "iat_jump_sites",
    "switch_sites",
    "switch_sites_validated",
    "switch_sites_rejected",
    "switch_cases",
    "ret_sites",
    "ud2_sites",
    "int3_sites",
    "trap_sites",
    "syscall_sites",
) + tuple(
    f"{prefix}_{kind}"
    for prefix in ("term", "exit")
    for kind in (
        "call",
        "jmp_direct",
        "jmp_indirect",
        "jcc",
        "return",
        "trap",
        "invalid",
        "range_end",
    )
)

FUNCTION_BREAKS: Final[tuple[str, ...]] = (
    "func_index_not_contiguous",
    "range_differs_from_pdata",
    "size_column",
    "hex_columns",
    "begin_va",
    "end_va",
    "raw_column",
    "overlapping_functions",
    "blocks_not_split",
    "reached_ratio",
    "decoded_out_of_bounds",
    "instruction_count",
    "undecoded_regions",
    "iat_symbol_count",
    "iat_module_count",
    "unwind_shared_by",
    "unwind_version",
    "cluster_id_not_reproducible_from_gap_rule",
)

CLUSTER_SUM_FIELDS: Final[tuple[str, ...]] = (
    "basic_blocks",
    "blocks_reached",
    "blocks_linear_only",
    "instructions",
    "decoded_bytes",
    "undecoded_bytes",
    "undecoded_regions",
    "edges",
    "back_edges",
    "cross_calls",
    "cross_jumps",
    "direct_calls",
    "direct_jumps",
    "indirect_calls",
    "indirect_jumps",
    "indirect_jumps_unresolved",
    "iat_call_sites",
    "iat_jump_sites",
    "switch_sites",
    "switch_sites_validated",
    "switch_sites_rejected",
    "switch_cases",
    "ret_sites",
    "ud2_sites",
    "int3_sites",
    "trap_sites",
    "syscall_sites",
)

CLUSTER_BOUND_FIELDS: Final[tuple[str, ...]] = (
    "function_count",
    "size_min",
    "size_max",
    "size_total",
    "max_indegree",
    "first_rva",
    "last_end_rva",
    "rva_span",
    "span_bytes",
    "code_bytes",
    "gap_bytes",
    "cross_function_edges",
    "functions_with_linear_blocks",
    "functions_with_undecoded",
    "functions_with_entry_refs",
    "functions_multi_entry",
    "unwind_ehandler",
    "unwind_uhandler",
    "unwind_chaininfo",
    "overlapping_functions",
)

CLUSTER_BREAKS: Final[tuple[str, ...]] = (
    "cluster_id_not_contiguous_1_based",
    "cluster_without_functions",
    "first_rva_hex",
    "last_end_rva_hex",
    "size_average",
    "reached_ratio",
    "anchor_count",
    "iat_symbol_count",
) + tuple(f"sum_{field}" for field in CLUSTER_SUM_FIELDS) + CLUSTER_BOUND_FIELDS

XREF_BREAKS: Final[tuple[str, ...]] = (
    "edge_id_not_contiguous_1_based",
    "src_raw",
    "code_instruction_function_index",
    "code_instruction_function_range",
    "code_edge_without_function",
    "src_bytes",
    "target_thunk_function_index",
    "target_thunk_function_range",
    "iat_edge_without_iat_rva",
)

INDIRECT_BREAKS: Final[tuple[str, ...]] = (
    "site_id_not_contiguous_1_based",
    "insn_raw",
    "code_instruction_function_index",
    "code_instruction_function_range",
    "bytes",
    "empty_annotation",
    "target_section",
    "iat_target",
    "target_thunk_function_index",
    "target_thunk_function_range",
)

SYSCALL_BREAKS: Final[tuple[str, ...]] = (
    "hit_index_not_contiguous_0_based",
    "raw_offset_not_ascending",
    "raw_offset",
    "pattern_bytes",
    "bytes_column",
    "hex_columns",
    "va_column",
    "in_pdata_flag",
    "rva_outside_named_function",
    "pdata_function_start",
    "pdata_function_end",
    "pdata_function_size",
    "pdata_function_offset",
    "pdata_word_boundary",
    "capstone_checked",
    "false_positive_ok",
    "valid_candidate_vs_boundary",
    "false_positive_inverse",
    "disposition_start_without_valid",
    "disposition_nonstart_with_valid",
)


def hex_up(value: int) -> str:
    return f"0x{value:X}"


def ratio_text(numerator: int, denominator: int, digits: int = RATIO_DIGITS) -> str:
    if denominator <= 0:
        return "0.0"
    return str(round(numerator / denominator, digits))


def shannon(counts: Mapping[int, int], total: int) -> float:
    if total <= 0:
        return 0.0
    accumulator = 0.0
    for count in counts.values():
        if count:
            share = count / total
            accumulator -= share * math.log2(share)
    return round(accumulator, ENTROPY_DIGITS)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_digests(path: Path) -> dict[str, str]:
    digests = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def jsonable(value: Any) -> Any:
    if isinstance(value, Counter):
        return {str(key): jsonable(item) for key, item in sorted(value.items(), key=lambda p: str(p[0]))}
    if isinstance(value, (set, frozenset)):
        return sorted(str(item) for item in value)
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    if isinstance(value, float) and value != value:
        return str(value)
    return value


@dataclass(frozen=True, slots=True)
class Check:
    group: str
    name: str
    expected: Any
    actual: Any
    ok: bool


class Ledger:
    def __init__(self) -> None:
        self.checks: list[Check] = []
        self.groups: Counter[str] = Counter()

    def add(self, group: str, name: str, expected: Any, actual: Any, ok: bool) -> None:
        self.checks.append(Check(group, name, jsonable(expected), jsonable(actual), bool(ok)))
        self.groups[group] += 1

    def equal(self, group: str, name: str, expected: Any, actual: Any) -> bool:
        ok = expected == actual
        self.add(group, name, expected, actual, ok)
        return ok

    def at_most(self, group: str, name: str, limit: Any, actual: Any) -> bool:
        ok = actual <= limit
        self.add(group, name, f"<= {limit}", actual, ok)
        return ok

    def expect_documented(self, group: str, key: str, observed: Any) -> None:
        """Compare one independently observed count against the number a document claims."""
        self.equal(group, f"documented[{key}]", DOCUMENTED[key][1], observed)
    def failures(self, group: str | None = None) -> list[Check]:
        return [c for c in self.checks if not c.ok and (group is None or c.group == group)]

    def group_summary(self) -> dict[str, dict[str, int]]:
        summary: dict[str, dict[str, int]] = {}
        for group in sorted(self.groups):
            total = self.groups[group]
            failed = sum(1 for c in self.checks if c.group == group and not c.ok)
            summary[group] = {"checks": total, "failed": failed}
        return summary


def stream_csv(path: Path) -> tuple[list[str], Iterator[list[str]]]:
    handle = path.open("r", encoding="utf-8", newline="")
    reader = csv.reader(handle)

    def rows() -> Iterator[list[str]]:
        try:
            for row in reader:
                yield row
        finally:
            handle.close()

    header = next(reader)
    return header, rows()


def _static_value(node: ast.AST) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Tuple):
        return tuple(_static_value(item) for item in node.elts)
    if isinstance(node, ast.List):
        return [_static_value(item) for item in node.elts]
    if isinstance(node, ast.Set):
        return {_static_value(item) for item in node.elts}
    if isinstance(node, ast.Dict):
        return {_static_value(key): _static_value(value) for key, value in zip(node.keys, node.values)}
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _static_value(node.operand)
        return -inner if isinstance(inner, (int, float)) else UNRESOLVED
    if isinstance(node, ast.Name):
        return f"<name:{node.id}>"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        name = node.func.id
        if name == "bytes" and node.args:
            try:
                return bytes(ast.literal_eval(node.args[0]))
            except (ValueError, TypeError):
                return UNRESOLVED
        if name in ("MappingProxyType", "dict") and node.args:
            return _static_value(node.args[0])
    return UNRESOLVED


def module_constants(path: Path) -> dict[str, Any]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: dict[str, Any] = {}
    for node in tree.body:
        if not isinstance(node, ast.AnnAssign) or not isinstance(node.target, ast.Name):
            continue
        found[node.target.id] = _static_value(node.value)
    return found


def source_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@dataclass(frozen=True, slots=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def mapped_size(self) -> int:
        return max(self.virtual_size, self.raw_size)


class StaticImage:
    """Minimal read only PE reader used to re-derive specimen facts from bytes."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.size = path.stat().st_size
        self.data = path.read_bytes()
        data = self.data
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset:pe_offset + 4] != b"PE\0\0":
            raise ValueError("missing PE signature")
        coff = pe_offset + 4
        (
            self.machine,
            section_count,
            self.timestamp,
            _,
            _,
            optional_size,
            self.characteristics,
        ) = struct.unpack_from("<HHIIIHH", data, coff)
        optional = coff + 20
        self.optional_size = optional_size
        self.magic = struct.unpack_from("<H", data, optional)[0]
        self.pe32plus = self.magic == 0x20B
        self.address_of_entry_point = struct.unpack_from("<I", data, optional + 16)[0]
        if self.pe32plus:
            self.image_base = struct.unpack_from("<Q", data, optional + 24)[0]
        else:
            self.image_base = struct.unpack_from("<I", data, optional + 28)[0]
        self.section_alignment, self.file_alignment = struct.unpack_from("<II", data, optional + 32)
        self.size_of_image, self.size_of_headers = struct.unpack_from("<II", data, optional + 56)
        self.dll_characteristics = struct.unpack_from("<H", data, optional + 70)[0]
        directory_count = struct.unpack_from("<I", data, optional + 108)[0]
        directory_base = optional + 112
        self.data_directories = [
            struct.unpack_from("<II", data, directory_base + index * 8)
            for index in range(directory_count)
        ]
        table = optional + optional_size
        self.sections: list[Section] = []
        for index in range(section_count):
            base = table + index * 40
            name = data[base:base + 8].rstrip(b"\0").decode("ascii", "replace")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, base + 8
            )
            characteristics = struct.unpack_from("<I", data, base + 36)[0]
            self.sections.append(
                Section(
                    name,
                    virtual_address,
                    virtual_size,
                    raw_offset,
                    raw_size,
                    characteristics,
                )
            )

    def directory(self, index: int) -> tuple[int, int]:
        return self.data_directories[index]

    def section_of(self, rva: int) -> Section | None:
        for section in self.sections:
            if section.virtual_address <= rva < section.virtual_address + section.mapped_size:
                return section
        return None

    def raw_of(self, rva: int) -> int | None:
        section = self.section_of(rva)
        if section is None:
            return None
        offset = section.raw_offset + (rva - section.virtual_address)
        return offset if offset < section.raw_offset + section.raw_size else None

    def slice(self, rva: int, length: int) -> bytes:
        raw = self.raw_of(rva)
        return b"" if raw is None else self.data[raw:raw + length]

    def runtime_functions(self) -> list[tuple[int, int, int]]:
        rva, size = self.directory(3)
        blob = self.slice(rva, size)
        count, remainder = divmod(len(blob), RUNTIME_FUNCTION_SIZE)
        if remainder:
            raise ValueError(f"exception directory blob is {len(blob)} bytes")
        return [tuple(record) for record in struct.iter_unpack("<III", blob[: count * RUNTIME_FUNCTION_SIZE])]

    def unwind_header(self, rva: int) -> tuple[int, int] | None:
        raw = self.raw_of(rva)
        if raw is None:
            return None
        header = self.data[raw]
        return header & 0x07, (header & 0xF8) >> 3


def text_profile(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    crlf = data.count(b"\r\n")
    bare_lf = data.count(b"\n") - crlf
    bare_cr = data.count(b"\r") - crlf
    return {
        "size": len(data),
        "sha256": sha256_bytes(data),
        "bom": data.startswith(BOM),
        "crlf": crlf,
        "lf": bare_lf,
        "cr": bare_cr,
        "trailing_newline": data.endswith(b"\n"),
        "nul_bytes": data.count(b"\0"),
        "utf8": _is_utf8(data),
        "line_endings": "lf" if crlf == 0 and bare_cr == 0 else "mixed",
    }


def _is_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def audit_text_artifact(
    ledger: Ledger,
    group: str,
    relative: str,
    path: Path,
    expected_columns: Sequence[str] | None = None,
    record_header: bool = True,
) -> dict[str, Any]:
    profile = text_profile(path)
    ledger.equal(group, f"{relative}.encoding_utf8", True, profile["utf8"])
    ledger.equal(group, f"{relative}.bom_absent", False, profile["bom"])
    ledger.equal(group, f"{relative}.crlf_count", 0, profile["crlf"])
    ledger.equal(group, f"{relative}.bare_cr_count", 0, profile["cr"])
    ledger.equal(group, f"{relative}.trailing_newline", True, profile["trailing_newline"])
    ledger.equal(group, f"{relative}.nul_bytes", 0, profile["nul_bytes"])
    ledger.equal(group, f"{relative}.line_endings", "lf", profile["line_endings"])
    record: dict[str, Any] = dict(profile)
    text = source_text(path)
    record["windows_path_tokens"] = text.count("C:\\")
    record["home_path_tokens"] = text.count("Users\\") + text.count("/home/") + text.count("/tmp/")
    if expected_columns is not None and record_header:
        header = text.split("\n", 1)[0]
        actual = header.split(",")
        record["header_columns"] = len(actual)
        record["header_matches_producer"] = actual == list(expected_columns)
        ledger.equal(
            group,
            f"{relative}.header_matches_producer_declaration",
            ",".join(expected_columns),
            header,
        )
        ledger.equal(group, f"{relative}.column_count", len(expected_columns), len(actual))
    return record


def audit_no_host_dependence(ledger: Ledger, group: str, relative: str, record: Mapping[str, Any]) -> None:
    host_bound = bool(record.get("windows_path_tokens") or record.get("home_path_tokens"))
    ledger.equal(group, f"{relative}.host_independent_payload", False, host_bound)


def doc_anchor(ledger: Ledger, group: str, relative: str, needle: str, root: Path) -> None:
    path = root / relative
    present = path.is_file() and needle in source_text(path)
    ledger.add(
        group,
        f"{relative}.anchor_present[{needle}]",
        True,
        present,
        present,
    )


def audit_specimen(ledger: Ledger, root: Path, image: StaticImage, baseline: Mapping[str, Any],
                   toolchain: Mapping[str, Any], stats: Mapping[str, Any]) -> dict[str, Any]:
    group = "specimen"
    relative = "reverse/adhesive.dll"
    digests = file_digests(image.path)
    record: dict[str, Any] = {
        "path": relative,
        "size": image.size,
        "sha256": digests["sha256"],
        "sha1": digests["sha1"],
        "md5": digests["md5"],
        "executed": False,
    }
    for name, payload in (("baseline", baseline), ("toolchain", toolchain), ("pdata_stats", stats)):
        claimed = _specimen_claim(payload)
        if claimed is None:
            ledger.equal(group, f"{name}.specimen_digest_present", True, False)
            continue
        record[f"{name}_claim"] = claimed
        ledger.equal(group, f"{name}.specimen_size", image.size, claimed.get("size", -1))
        ledger.equal(group, f"{name}.specimen_sha256", digests["sha256"], claimed.get("sha256"))
    record["baseline_sha256_self_claim"] = baseline.get("specimen", {}).get("dll", {}).get("sha256")
    ledger.equal(
        group,
        "baseline.specimen_dll_block_matches_top_level",
        record["baseline_sha256_self_claim"],
        digests["sha256"],
    )
    ledger.equal(group, "pe.magic_is_pe32plus", 0x20B, image.magic)
    ledger.equal(group, "pe.machine_amd64", 0x8664, image.machine)
    ledger.equal(group, "pe.image_base", IMAGE_BASE_CLAIM, image.image_base)
    pe_header = baseline.get("pe", {})
    for key, actual in (
        ("image_base", image.image_base),
        ("size_of_image", image.size_of_image),
        ("size_of_headers", image.size_of_headers),
        ("section_alignment", image.section_alignment),
        ("file_alignment", image.file_alignment),
        ("address_of_entry_point", image.address_of_entry_point),
        ("characteristics", image.characteristics),
        ("dll_characteristics", image.dll_characteristics),
        ("timestamp", image.timestamp),
    ):
        if key in pe_header:
            ledger.equal(group, f"baseline.pe.{key}", pe_header[key], actual)
    observed_sections = [
        {
            "index": position,
            "name": s.name,
            "virtual_address": s.virtual_address,
            "virtual_size": s.virtual_size,
            "raw_pointer": s.raw_offset,
            "raw_size": s.raw_size,
            "characteristics": s.characteristics,
        }
        for position, s in enumerate(image.sections)
    ]
    stored_sections = baseline.get("sections")
    if isinstance(stored_sections, list) and len(stored_sections) == len(observed_sections):
        mismatches = [
            {
                "name": stored.get("name"),
                "field": field,
                "expected": stored.get(field),
                "actual": observed.get(field),
            }
            for stored, observed in zip(stored_sections, observed_sections)
            for field in observed
            if field in stored and stored.get(field) != observed.get(field)
        ]
        ledger.equal(group, "baseline.sections", [], mismatches)
    else:
        ledger.equal(group, "baseline.sections_present_with_matching_length", True, False)
    ledger.equal(group, "section.count", 7, len(image.sections))
    ledger.equal(
        group,
        "section.names",
        [".text", ".rdata", ".data", ".retplne", ".tls", ".rsrc", ".reloc"],
        [s.name for s in image.sections],
    )
    stored_dirs = baseline.get("data_directories")
    if isinstance(stored_dirs, list) and len(stored_dirs) == len(image.data_directories):
        dir_mismatches = [
            {
                "name": stored.get("name"),
                "field": field,
                "expected": stored.get(field),
                "actual": value,
            }
            for stored, (rva, size) in zip(stored_dirs, image.data_directories)
            for field, value in (("address", rva), ("size", size))
            if field in stored and stored.get(field) != value
        ]
        ledger.equal(group, "baseline.data_directories", [], dir_mismatches)
    else:
        ledger.equal(group, "baseline.data_directories_present_with_matching_length", True, False)
    security_rva, security_size = image.directory(4)
    imports = baseline.get("imports", {})
    ledger.equal(group, "imports.descriptor_count", 42, imports.get("descriptor_count"))
    ledger.equal(group, "imports.symbol_count", 628, imports.get("symbol_count"))
    ledger.equal(group, "imports.name_imports", 604, imports.get("name_imports"))
    ledger.equal(group, "imports.ordinal_imports", 24, imports.get("ordinal_imports"))
    ledger.equal(group, "imports.delay_descriptor_count", 1, imports.get("delay_descriptor_count"))
    ledger.equal(group, "imports.delay_symbol_count", 1, imports.get("delay_symbol_count"))
    ledger.equal(group, "imports.total_module_count", 43, imports.get("total_module_count"))
    ledger.equal(group, "imports.total_symbol_count", 629, imports.get("total_symbol_count"))
    ledger.equal(
        group,
        "imports.module_rows",
        imports.get("descriptor_count"),
        len(imports.get("modules", [])),
    )
    ledger.equal(
        group,
        "imports.name_plus_ordinal_equals_symbol_count",
        imports.get("symbol_count"),
        (imports.get("name_imports") or 0) + (imports.get("ordinal_imports") or 0),
    )
    ledger.equal(group, "imports.bound_import_size", 0, imports.get("bound_import_size"))
    iat_rva, iat_size = image.directory(12)
    ledger.equal(group, "imports.iat_rva", imports.get("iat_rva"), iat_rva)
    ledger.equal(group, "imports.iat_size", imports.get("iat_size"), iat_size)
    exports = baseline.get("exports", {})
    ledger.equal(group, "exports.present", True, exports.get("present"))
    ledger.equal(group, "exports.symbol_count", 1, exports.get("symbol_count"))
    ledger.equal(group, "exports.forwarder_count", 0, exports.get("forwarder_count"))
    ledger.equal(group, "exports.symbol_rows", exports.get("symbol_count"), len(exports.get("symbols", [])))
    export_rva, export_size = image.directory(0)
    ledger.equal(group, "exports.rva", exports.get("rva"), export_rva)
    ledger.equal(group, "exports.size", exports.get("size"), export_size)
    overlay = baseline.get("overlay", {})
    certificate = baseline.get("certificate", {})
    security_offset = security_rva
    ledger.equal(
        group,
        "overlay.equals_security_directory",
        True,
        overlay.get("overlay_equals_security_directory"),
    )
    ledger.equal(
        group,
        "overlay.unclaimed_trailing_bytes",
        0,
        overlay.get("unclaimed_trailing_bytes"),
    )
    ledger.equal(
        group,
        "certificate.reaches_file_end",
        True,
        certificate.get("reaches_file_end"),
    )
    ledger.equal(
        group,
        "security_directory.offset_equals_rva",
        security_offset,
        certificate.get("file_offset", certificate.get("offset")),
    )
    ledger.equal(
        group,
        "security_directory.size",
        security_size,
        certificate.get("size", certificate.get("size_bytes")),
    )
    if security_size:
        ledger.equal(
            group,
            "security_directory.end_equals_file_size",
            image.size,
            security_offset + security_size,
        )
    exception_rva, exception_size = image.directory(3)
    pdata = baseline.get("pdata", {})
    ledger.equal(group, "pdata.exception_rva", pdata.get("rva"), exception_rva)
    ledger.equal(group, "pdata.exception_size", pdata.get("size"), exception_size)
    ledger.equal(group, "pdata.record_size", RUNTIME_FUNCTION_SIZE, pdata.get("record_size"))
    count, remainder = divmod(exception_size, RUNTIME_FUNCTION_SIZE)
    ledger.equal(group, "pdata.record_count", pdata.get("record_count"), count)
    ledger.equal(group, "pdata.record_remainder", 0, remainder)
    ledger.expect_documented(group, "runtime_function_records", count)
    ledger.expect_documented(group, "exception_directory_size_div_12", count)
    records = image.runtime_functions()
    begins = [record[0] for record in records]
    ends = [record[1] for record in records]
    unwinds = [record[2] for record in records]
    ledger.equal(group, "pdata.parsed_records", count, len(records))
    ledger.equal(
        group,
        "pdata.sorted_by_begin_address",
        True,
        all(begins[i] <= begins[i + 1] for i in range(len(begins) - 1)),
    )
    ledger.equal(group, "pdata.duplicate_records", 0, len(begins) - len(set(begins)))
    ledger.equal(
        group,
        "pdata.overlapping_records",
        0,
        sum(1 for i in range(len(records) - 1) if ends[i] > begins[i + 1]),
    )
    ledger.equal(group, "pdata.begin_address_min", pdata.get("begin_address_min"), min(begins))
    ledger.equal(group, "pdata.end_address_max", pdata.get("end_address_max"), max(ends))
    ledger.equal(group, "pdata.unwind_info_address_null", 0, sum(1 for u in unwinds if u == 0))
    unique_unwind = sorted({u for u in unwinds if u})
    ledger.equal(group, "pdata.unique_unwind_infos", pdata.get("unique_unwind_infos"), len(unique_unwind))
    ledger.equal(
        group,
        "pdata.unwind_info_rva_min",
        pdata.get("unwind_info_rva_min"),
        unique_unwind[0],
    )
    ledger.equal(
        group,
        "pdata.unwind_info_rva_max",
        pdata.get("unwind_info_rva_max"),
        unique_unwind[-1],
    )
    flag_unique: Counter[int] = Counter()
    version_invalid = 0
    unmapped = 0
    unwind_sections: Counter[str] = Counter()
    for rva in unique_unwind:
        header = image.unwind_header(rva)
        section = image.section_of(rva)
        if header is None or section is None:
            unmapped += 1
            continue
        unwind_sections[section.name] += 1
        version_invalid += int(header[0] != 1)
        flag_unique[header[1]] += 1
    ledger.equal(group, "pdata.unwind_records_out_of_image", 0, unmapped)
    ledger.equal(
        group,
        "pdata.unwind_version_invalid_records",
        0,
        version_invalid,
    )
    ledger.equal(
        group,
        "pdata.unwind_info_sections",
        pdata.get("unwind_info_sections"),
        dict(sorted(unwind_sections.items())),
    )
    flag_by_rva = {
        rva: (image.unwind_header(rva) or (0, 0))[1] for rva in unique_unwind
    }
    flag_record: Counter[int] = Counter()
    for rva in unwinds:
        flag_record[flag_by_rva.get(rva, 0) if rva else 0] += 1
    observed_flags = {str(value): flag_record[value] for value in sorted(flag_record)}
    ledger.equal(
        group,
        "pdata.unwind_flag_value_distribution",
        pdata.get("unwind_flag_value_distribution"),
        observed_flags,
    )
    handler = sum(total for value, total in flag_record.items() if value & 0x03)
    chain = sum(total for value, total in flag_record.items() if value & 0x04)
    name_unique: Counter[str] = Counter()
    for value, total in flag_unique.items():
        for mask, name in UNWIND_FLAG_MASKS.items():
            if value & mask:
                name_unique[name] += total
    ledger.equal(
        group,
        "pdata.unwind_flag_distribution_per_unique_info",
        pdata.get("unwind_flag_distribution_per_unique_info"),
        dict(sorted(name_unique.items())),
    )
    record["rederived"] = {
        "runtime_function_records": count,
        "unique_unwind_info": len(unique_unwind),
        "unwind_flag_value_distribution": observed_flags,
        "handler_records": handler,
        "chain_records": chain,
        "begin_address_min": min(begins),
        "end_address_max": max(ends),
        "covered_bytes": sum(end - begin for begin, end in zip(begins, ends)),
        "exception_directory": {"rva": exception_rva, "size": exception_size},
    }
    return record


def _specimen_claim(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    block = payload.get("specimen")
    if not isinstance(block, Mapping):
        return None
    if "sha256" not in block:
        return None
    return {"size": block.get("size"), "sha256": block.get("sha256")}


def audit_script_contract(
    ledger: Ledger,
    root: Path,
    common_path: Path,
    baseline: Mapping[str, Any],
    toolchain: Mapping[str, Any],
    constants: Mapping[str, Mapping[str, Any]],
    observed_digests: Mapping[str, str],
) -> dict[str, Any]:
    group = "script.common"
    record: dict[str, Any] = {"producers": {}, "forbidden_calls": {}}
    common = constants["common.py"]
    ledger.equal(
        group,
        "common.SCHEMA_BASELINE",
        "adhesive-dumper.baseline/1",
        common.get("SCHEMA_BASELINE"),
    )
    ledger.equal(
        group,
        "common.SCHEMA_TOOLCHAIN",
        "adhesive-dumper.toolchain/1",
        common.get("SCHEMA_TOOLCHAIN"),
    )
    ledger.equal(
        group,
        "common.RUNTIME_FUNCTION_SIZE",
        RUNTIME_FUNCTION_SIZE,
        common.get("RUNTIME_FUNCTION_SIZE"),
    )
    ledger.equal(
        group,
        "common.EXPECTED_RUNTIME_FUNCTIONS",
        DOCUMENTED["runtime_function_records"][1],
        common.get("EXPECTED_RUNTIME_FUNCTIONS"),
    )
    source = common.get("EXPECTED_RUNTIME_FUNCTION_SOURCE")
    ledger.equal(
        group,
        "common.EXPECTED_RUNTIME_FUNCTION_SOURCE",
        f"{DOC02}#15",
        source,
    )
    doc_anchor(ledger, group, DOC02, "## 15. Exception / x64 unwind directory", root)
    doc_anchor(ledger, group, DOC03, "3 132", root)
    doc_anchor(ledger, group, DOC12, "3 881", root)
    text = source_text(common_path)
    forbidden = (
        "ctypes",
        "WinDLL",
        "CDLL",
        "LoadLibrary",
        "importlib.machinery",
        "__import__",
        "exec(",
        "eval(",
    )
    for token in forbidden:
        present = token in text
        record["forbidden_calls"][token] = present
        ledger.equal(group, f"common.absent[{token}]", False, present)
    ledger.equal(group, "common.uses_pefile", True, "import pefile" in text)
    determinism = toolchain.get("determinism", {})
    declared = {
        "json_indent": 2,
        "json_ensure_ascii": False,
        "json_sort_keys": False,
        "text_encoding": "utf-8",
        "bom": False,
        "line_terminator": "\\n",
        "trailing_newline": True,
        "payload_timestamps": False,
    }
    ledger.equal(group, "toolchain.determinism_block", declared, determinism)
    for key, token in (
        ("json_indent", 'indent=2'),
        ("json_ensure_ascii", "ensure_ascii=False"),
        ("json_sort_keys", "sort_keys=False"),
        ("json_allow_nan", "allow_nan=False"),
    ):
        ledger.equal(group, f"common.write_json_declares[{key}]", True, token in text)
    for token in ('newline="\\n"', 'lineterminator="\\n"', 'encoding="utf-8"'):
        ledger.equal(group, f"common.writer_declares[{token}]", True, token in text)
    ledger.equal(group, "common.hexs_uppercase", True, 'f"0x{value:X}"' in text)
    ledger.equal(
        group,
        "common.scalar_text_bool_lowercase",
        True,
        '"true" if value else "false"' in text,
    )
    ledger.equal(
        group,
        "common.write_csv_extrasaction_raise",
        True,
        'extrasaction="raise"' in text,
    )
    ledger.equal(
        group,
        "toolchain.schema",
        "adhesive-dumper.toolchain/1",
        toolchain.get("schema"),
    )
    ledger.equal(
        group,
        "baseline.schema",
        "adhesive-dumper.baseline/1",
        baseline.get("schema"),
    )
    record["toolchain_scripts"] = audit_toolchain_scripts(ledger, root, toolchain)
    record["script_inventory"] = audit_script_inventory_block(
        ledger, toolchain, toolchain.get("scripts", []) if isinstance(toolchain.get("scripts"), list) else []
    )
    record["package_versions"] = audit_package_versions(
        ledger,
        toolchain,
        record["toolchain_scripts"].get("recorded_census", {}),
        record["toolchain_scripts"].get("census", {}),
    )
    record["pdata_map_contract"] = audit_pdata_map_contract(ledger, constants["pdata_map.py"])
    record["xref_build_contract"] = audit_xref_build_contract(ledger, constants["xref_build.py"])
    record["syscall_scan_contract"] = audit_syscall_scan_contract(ledger, constants["syscall_scan.py"])
    record["host_bound_fields"] = audit_toolchain_host_fields(ledger, toolchain)
    record["libraries"] = audit_toolchain_libraries(ledger, toolchain)
    record["toolchain_digests"] = audit_toolchain_digests(
        ledger, root, toolchain, pdata_recorded_digests(root), observed_digests
    )
    return record


def audit_toolchain_libraries(ledger: Ledger, toolchain: Mapping[str, Any]) -> dict[str, Any]:
    group = "toolchain.libraries"
    libraries = toolchain.get("libraries", {})
    ledger.equal(group, "declares_three_libraries", sorted(("pefile", "lief", "capstone")), sorted(libraries))
    return {"declared": sorted(libraries)}


def script_sibling_names(root: Path) -> frozenset[str]:
    return frozenset(
        path.stem for path in (root / SCRIPT_INVENTORY_ROOT).glob(SCRIPT_INVENTORY_GLOB)
    )


def third_party_imports(data: bytes, siblings: frozenset[str]) -> list[str]:
    """Top level module names a script imports that are neither stdlib nor a sibling script."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(data.decode("utf-8-sig"))):
        if isinstance(node, ast.Import):
            names.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.partition(".")[0])
    return sorted(
        name
        for name in names
        if name != "__future__" and name not in siblings and name not in sys.stdlib_module_names
    )


def audit_toolchain_host_fields(ledger: Ledger, toolchain: Mapping[str, Any]) -> dict[str, Any]:
    group = "toolchain.host"
    declared: list[str] = []
    for field in HOST_PATH_FIELDS:
        node: Any = toolchain
        for part in field.split("."):
            node = node.get(part) if isinstance(node, Mapping) else None
        if isinstance(node, str) and HOST_PATH_PATTERN.search(node):
            declared.append(field)
    observed: list[str] = []

    def walk(node: Any, prefix: str) -> None:
        if isinstance(node, Mapping):
            for key, value in node.items():
                walk(value, f"{prefix}.{key}" if prefix else str(key))
        elif isinstance(node, str) and HOST_PATH_PATTERN.search(node):
            observed.append(prefix)

    walk(toolchain, "")
    ledger.equal(group, "host_paths_confined_to_declared_fields", sorted(declared), sorted(observed))
    return {"declared_host_path_fields": sorted(declared), "observed_host_path_fields": sorted(observed)}


def audit_script_inventory_block(
    ledger: Ledger, toolchain: Mapping[str, Any], stored: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    group = "toolchain.inventory"
    block = toolchain.get("script_inventory")
    if not isinstance(block, Mapping):
        ledger.equal(group, "script_inventory_block_present", True, False)
        return {}
    ledger.equal(group, "root", SCRIPT_INVENTORY_ROOT, block.get("root"))
    ledger.equal(group, "glob", SCRIPT_INVENTORY_GLOB, block.get("glob"))
    ledger.equal(group, "entry_count", len(stored), block.get("entry_count"))
    ledger.equal(group, "fields", list(SCRIPT_INVENTORY_FIELDS), block.get("fields"))
    ledger.equal(group, "omitted", list(SCRIPT_INVENTORY_OMITTED), block.get("omitted"))
    ledger.equal(group, "omitted_reason_present", True, bool(str(block.get("omitted_reason", "")).strip()))
    producer = str(block.get("producer", ""))
    ledger.equal(
        group,
        "producer_names_both_stages",
        True,
        "common.py" in producer and "refresh_toolchain.py" in producer,
    )
    ledger.equal(
        group,
        "order_declares_file_name_ascending",
        True,
        "file name ascending" in str(block.get("order", "")),
    )
    declared_fields = sorted(SCRIPT_INVENTORY_FIELDS)
    field_drift = sorted(
        str(entry.get("name"))
        for entry in stored
        if isinstance(entry, Mapping) and sorted(entry) != declared_fields
    )
    ledger.equal(group, "every_entry_carries_exactly_the_declared_fields", [], field_drift)
    return {
        "declared_fields": list(SCRIPT_INVENTORY_FIELDS),
        "omitted": list(SCRIPT_INVENTORY_OMITTED),
        "entry_count": block.get("entry_count"),
    }


def audit_toolchain_scripts(ledger: Ledger, root: Path, toolchain: Mapping[str, Any]) -> dict[str, Any]:
    group = "toolchain.scripts"
    stored = toolchain.get("scripts", [])
    if not isinstance(stored, list):
        ledger.equal(group, "inventory_is_list", True, False)
        return {"stored": 0, "on_disk": 0, "census": {}, "recorded_census": {}}
    siblings = script_sibling_names(root)
    on_disk: dict[str, dict[str, Any]] = {}
    for path in sorted(
        (root / SCRIPT_INVENTORY_ROOT).glob(SCRIPT_INVENTORY_GLOB), key=lambda item: item.name
    ):
        data = path.read_bytes()
        on_disk[path.name] = {
            "path": path.relative_to(root).as_posix(),
            "size": len(data),
            "sha256": sha256_bytes(data),
            "utf8_bom": data.startswith(BOM),
            "crlf_line_count": data.count(b"\r\n"),
            "lf_line_count": data.count(b"\n"),
            "third_party_imports": third_party_imports(data, siblings),
        }
    stored_by_name = {entry.get("name"): entry for entry in stored if isinstance(entry, Mapping)}
    ledger.equal(group, "inventory_names", sorted(on_disk), sorted(stored_by_name))
    ledger.equal(group, "inventory_count", len(on_disk), len(stored))
    for name, expected in sorted(on_disk.items()):
        entry = stored_by_name.get(name)
        if entry is None:
            ledger.equal(group, f"entry_present[{name}]", True, False)
            continue
        for key, value in expected.items():
            ledger.equal(group, f"{name}.{key}", value, entry.get(key))
    census = {name: record["third_party_imports"] for name, record in on_disk.items()}
    recorded_census = {
        name: list(entry["third_party_imports"])
        for name, entry in stored_by_name.items()
        if isinstance(entry.get("third_party_imports"), list)
    }
    ledger.equal(
        group,
        "recorded_census_is_internally_consistent",
        {},
        {
            name: {"recorded": values, "recomputed": census.get(name)}
            for name, values in sorted(recorded_census.items())
            if values != census.get(name)
        },
    )
    return {
        "stored": len(stored),
        "on_disk": len(on_disk),
        "missing_from_toolchain": sorted(set(on_disk) - set(stored_by_name)),
        "unknown_in_toolchain": sorted(set(stored_by_name) - set(on_disk)),
        "drift": {
            name: sorted(key for key in on_disk[name] if entry.get(key) != on_disk[name][key])
            for name, entry in sorted(stored_by_name.items())
            if name in on_disk
            and any(entry.get(key) != on_disk[name][key] for key in on_disk[name])
        },
        "census": census,
        "recorded_census": recorded_census,
    }


def function_columns_are_atomic(
    row: Sequence[str], index: Mapping[str, int], fields: Sequence[str]
) -> bool:
    """The three columns naming one pdata function are empty together or populated together."""
    populated = [bool(row[index[field]]) for field in fields]
    return not any(populated) or all(populated)


def _axis_proof(axis: Mapping[str, Any], name: str) -> str | None:
    """The machine checkable reason an axis may differ from the distribution version."""
    if name != "imported_module":
        return None
    if axis.get("version_equals_composition") is True and axis.get(
        "version_composed_from_binding_constants"
    ):
        return "imported_version_is_composed_from_binding_constants"
    if axis.get("version_re_exported_from_kind") == "compiled extension":
        return "imported_version_re_exported_from_a_compiled_extension"
    return None


def _importer_map(census: Mapping[str, Sequence[str]]) -> dict[str, list[str]]:
    """Invert a per script import census into the per package importer list."""
    reverse: dict[str, set[str]] = {}
    for script, names in census.items():
        for name in names:
            reverse.setdefault(name, set()).add(script)
    return {name: sorted(scripts) for name, scripts in sorted(reverse.items())}


def audit_package_versions(
    ledger: Ledger,
    toolchain: Mapping[str, Any],
    recorded_census: Mapping[str, Sequence[str]],
    census: Mapping[str, Sequence[str]],
) -> dict[str, Any]:
    group = "toolchain.package_versions"
    block = toolchain.get("package_versions")
    if not isinstance(block, Mapping):
        ledger.equal(group, "package_versions_block_present", True, False)
        return {}
    importers = _importer_map(recorded_census)
    audit_importers = _importer_map(census)
    libraries = toolchain.get("libraries", {})
    ledger.equal(group, "axes", list(PACKAGE_AXES), block.get("axes"))
    ledger.equal(
        group,
        "library_block_field_map",
        dict(LIBRARY_BLOCK_AXIS_FIELD),
        block.get("library_block_fields"),
    )
    packages = block.get("packages", {})
    ledger.equal(group, "declared", sorted(libraries), block.get("declared"))
    missing_axes: list[str] = []
    reconciled: list[str] = []
    wrong_comparable: list[str] = []
    engine_compared: list[str] = []
    unassessed: list[dict[str, Any]] = []
    undecidable: list[dict[str, Any]] = []
    undocumented: list[dict[str, Any]] = []
    inconsistent_claims: list[dict[str, Any]] = []
    library_drift: list[dict[str, Any]] = []
    unbounded_effect: list[str] = []
    importer_drift: list[dict[str, Any]] = []
    disagreements: dict[str, list[str]] = {}
    proofs: dict[str, dict[str, str]] = {}
    for name in sorted(packages):
        record = packages[name]
        axes = record.get("axes", {})
        missing_axes.extend(
            f"{name}.{axis}" for axis in PACKAGE_AXES if not isinstance(axes.get(axis), Mapping)
        )
        divergence = record.get("divergence", {})
        values = divergence.get("axes", {})
        disagreeing = [str(axis) for axis in divergence.get("axes_disagreeing_with_package_metadata") or ()]
        disagreements[name] = sorted(disagreeing)
        if divergence.get("axes_reconciled") is not False:
            reconciled.append(name)
        if sorted(str(axis) for axis in divergence.get("compared_axes") or ()) != sorted(
            PACKAGE_COMPARABLE_AXES
        ):
            wrong_comparable.append(name)
        if "native_engine" in disagreeing:
            engine_compared.append(name)
        assessments = divergence.get("assessments", {})
        proofs[name] = {}
        for axis in sorted(disagreeing):
            if not str(assessments.get(axis, "")).strip():
                unassessed.append({"package": name, "axis": axis})
                continue
            proof = _axis_proof(axes.get(axis, {}), axis)
            if proof is None:
                undecidable.append({"package": name, "axis": axis})
            else:
                proofs[name][axis] = proof
        claims = divergence.get("documented_claims") or ()
        if disagreeing and not claims:
            undocumented.append({"package": name})
        for claim in claims:
            if claim.get("agrees_with_package_metadata") != (
                claim.get("version") == values.get("package_metadata")
            ):
                inconsistent_claims.append({"package": name, "file": claim.get("file")})
        if not str(divergence.get("effect_on_evidence", "")).strip():
            unbounded_effect.append(name)
        for axis_field, library_field in LIBRARY_BLOCK_AXIS_FIELD.items():
            axis, _, key = axis_field.partition(".")
            if libraries.get(name, {}).get(library_field) != axes.get(axis, {}).get(key):
                library_drift.append({"package": name, "field": library_field})
        if list(record.get("imported_by") or ()) != importers.get(name, []):
            importer_drift.append(
                {
                    "package": name,
                    "recorded": list(record.get("imported_by") or ()),
                    "census": importers.get(name, []),
                }
            )
    undeclared = block.get("undeclared_imports", {})
    ledger.equal(group, "every_package_is_versioned_on_all_axes", [], sorted(missing_axes))
    ledger.equal(group, "axes_are_never_reconciled", [], sorted(reconciled))
    ledger.equal(
        group,
        "only_the_two_release_axes_are_compared",
        [],
        sorted(set(wrong_comparable) | set(engine_compared)),
    )
    ledger.equal(group, "library_block_consistent_with_the_axes", [], library_drift)
    ledger.equal(
        group,
        "every_disagreement_carries_an_assessment",
        [],
        unassessed,
    )
    ledger.equal(
        group,
        "every_disagreement_is_decidable_from_the_record",
        [],
        sorted(undecidable, key=lambda item: (item["package"], item["axis"])),
    )
    ledger.equal(
        group,
        "every_disagreement_names_the_documented_axis",
        [],
        undocumented,
    )
    ledger.equal(
        group,
        "documented_claim_flags_match_the_axis_values",
        [],
        sorted(inconsistent_claims, key=lambda item: (item["package"], str(item["file"]))),
    )
    ledger.equal(group, "effect_on_evidence_stated_for_every_package", [], sorted(unbounded_effect))
    ledger.equal(
        group,
        "imported_by_matches_the_inventory_census",
        [],
        sorted(importer_drift, key=lambda item: item["package"]),
    )
    ledger.equal(
        group,
        "imported_by_matches_the_audit_census",
        [],
        sorted(
            (
                {
                    "package": name,
                    "recorded": list(packages[name].get("imported_by") or ()),
                    "census": audit_importers.get(name, []),
                }
                for name in sorted(packages)
                if list(packages[name].get("imported_by") or ()) != audit_importers.get(name, [])
            ),
            key=lambda item: item["package"],
        ),
    )
    ledger.equal(
        group,
        "undeclared_imports_are_disclosed",
        [],
        sorted(set(audit_importers) - set(libraries) - set(undeclared)),
    )
    ledger.equal(
        group,
        "import_census_matches_the_inventory_census",
        {},
        {
            name: {"recorded": list(values), "recomputed": list(recorded_census.get(name, ()))}
            for name, values in sorted((block.get("import_census") or {}).items())
            if list(values) != list(recorded_census.get(name, ()))
        },
    )
    return {
        "axes": list(PACKAGE_AXES),
        "declared": sorted(packages),
        "disagreements": {name: sorted(value) for name, value in sorted(disagreements.items()) if value},
        "disagreement_proofs": {
            name: proofs[name] for name in sorted(proofs) if proofs[name]
        },
        "decidable": not undecidable,
        "undeclared_imports": sorted(undeclared),
        "declared_without_producer_importer": sorted(
            name for name in packages if not packages[name].get("imported_by")
        ),
        "axis_values": {
            name: (packages[name].get("divergence", {}) or {}).get("axes")
            for name in sorted(packages)
        },
    }


def contains_digest(path: Path, needle: str) -> bool:
    """Whether the hex string occurs anywhere in the file, over a sliding window."""
    overlap = len(needle) - 1
    tail = ""
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                return False
            window = tail + chunk.decode("latin-1")
            if needle in window:
                return True
            tail = window[-overlap:] if overlap else ""


def audit_toolchain_digests(
    ledger: Ledger,
    root: Path,
    toolchain: Mapping[str, Any],
    attested_elsewhere: Mapping[str, str],
    observed: Mapping[str, str],
) -> dict[str, Any]:
    group = "toolchain.digests"
    block = toolchain.get("digests")
    if not isinstance(block, Mapping):
        ledger.equal(group, "digests_block_present", True, False)
        return {}
    ledger.equal(group, "algorithm", DIGEST_ALGORITHM_CLAIM, block.get("algorithm"))
    entries = block.get("entries", {})
    recomputed: dict[str, dict[str, Any]] = {}
    for target in sorted(entries):
        path = root / target
        if path.is_file():
            recomputed[target] = {"size": path.stat().st_size, "sha256": sha256_file(path)}
    ledger.equal(
        group,
        "entry_digests_recomputed",
        [],
        [target for target, value in sorted(recomputed.items()) if entries.get(target) != value],
    )
    ledger.equal(
        group,
        "entries_exist_on_disk",
        [],
        sorted(set(entries) - set(recomputed)),
    )
    ledger.equal(
        group,
        "no_entry_attests_the_payload",
        [],
        sorted(set(str(target) for target in entries) & {TOOLCHAIN_RELATIVE}),
    )
    payload_digest = observed.get(TOOLCHAIN_RELATIVE)
    ledger.equal(
        group,
        "no_attested_artifact_records_the_payload_digest",
        [],
        sorted(
            target
            for target in entries
            if payload_digest is not None
            and (root / str(target)).is_file()
            and contains_digest(root / str(target), payload_digest)
        ),
    )
    broken: list[dict[str, Any]] = []
    for reference in block.get("cross_references") or ():
        target = reference.get("target")
        source = reference.get("field")
        actual = recomputed.get(target, {}).get("sha256")
        payload: Any = (
            json.loads((root / str(reference.get("file"))).read_text(encoding="utf-8"))
            if (root / str(reference.get("file"))).is_file()
            else None
        )
        recorded: Any = payload
        for part in str(source).split("."):
            recorded = recorded.get(part) if isinstance(recorded, Mapping) else None
        if not (actual is not None and recorded == actual and reference.get("matches_recomputed") is True):
            broken.append({"file": reference.get("file"), "field": source, "target": target})
    ledger.equal(group, "cross_references_verified_independently", [], broken)
    own = block.get("self") if isinstance(block.get("self"), Mapping) else {}
    reason = str(own.get("reason", ""))
    ledger.equal(group, "self_digest_is_null", None, own.get("sha256"))
    ledger.equal(group, "self_path_is_the_payload", TOOLCHAIN_RELATIVE, own.get("path"))
    ledger.equal(
        group,
        "self_exclusion_names_the_producer_that_prints_it",
        True,
        bool(reason.strip()) and "refresh_toolchain.py" in reason,
    )
    attested: dict[str, dict[str, str]] = {}
    for target, value in sorted(attested_elsewhere.items()):
        attested.setdefault(str(target), {})[DIGEST_SOURCE_PDATA_STATS] = value
    for target, entry in entries.items():
        if isinstance(entry, Mapping):
            attested.setdefault(str(target), {})[DIGEST_SOURCE_TOOLCHAIN] = str(entry.get("sha256"))
    ledger.equal(
        group,
        "every_attested_digest_recomputes_from_the_bytes",
        [],
        sorted(
            f"{target}#{source}"
            for target, sources in sorted(attested.items())
            for source, value in sorted(sources.items())
            if observed.get(target) not in (None, value)
        ),
    )
    unattested: list[str] = []
    for relative in AUDITED_ARTIFACTS:
        if relative == TOOLCHAIN_RELATIVE:
            ledger.equal(
                group,
                "self_exclusion_covers_the_payload",
                True,
                own.get("path") == TOOLCHAIN_RELATIVE and bool(reason.strip()),
            )
            continue
        if relative not in attested:
            unattested.append(relative)
        ledger.equal(group, f"digest_attested[{relative}]", True, relative in attested)
    ledger.equal(group, "every_audited_artifact_is_attested", [], sorted(unattested))
    return {
        "entries": sorted(entries),
        "cross_references": len(block.get("cross_references") or ()),
        "attested_by_any_record": sorted(attested),
        "attested_by": {
            target: {source: value for source, value in sorted(sources.items())}
            for target, sources in sorted(attested.items())
        },
        "attested_only_by_the_toolchain_block": sorted(
            target for target, sources in attested.items() if list(sources) == [DIGEST_SOURCE_TOOLCHAIN]
        ),
        "unattested": sorted(unattested),
        "self_excluded": TOOLCHAIN_RELATIVE,
    }


def audit_pdata_map_contract(ledger: Ledger, constants: Mapping[str, Any]) -> dict[str, Any]:
    group = "script.pdata_map"
    expected_unique = DOCUMENTED["unique_unwind_info"][1]
    expected_flags = {
        0: DOCUMENTED["unwind_flag_zero"][1],
        1: DOCUMENTED["unwind_flag_ehandler"][1],
        2: DOCUMENTED["unwind_flag_uhandler"][1],
        3: DOCUMENTED["unwind_flag_ehandler_uhandler"][1],
        4: DOCUMENTED["unwind_flag_chaininfo"][1],
    }
    ledger.equal(group, "EXPECTED_UNIQUE_UNWIND", expected_unique, constants.get("EXPECTED_UNIQUE_UNWIND"))
    ledger.equal(
        group,
        "EXPECTED_HANDLER_RECORDS",
        DOCUMENTED["handler_records"][1],
        constants.get("EXPECTED_HANDLER_RECORDS"),
    )
    ledger.equal(
        group,
        "EXPECTED_CHAIN_RECORDS",
        DOCUMENTED["chain_records"][1],
        constants.get("EXPECTED_CHAIN_RECORDS"),
    )
    ledger.equal(
        group,
        "EXPECTED_FLAG_DISTRIBUTION",
        expected_flags,
        constants.get("EXPECTED_FLAG_DISTRIBUTION"),
    )
    ledger.equal(
        group,
        "EXPECTED_UNWIND_SECTIONS",
        {".rdata": expected_unique},
        constants.get("EXPECTED_UNWIND_SECTIONS"),
    )
    ledger.equal(group, "CSV_COLUMNS_present", True, isinstance(constants.get("CSV_COLUMNS"), (list, tuple)))
    return {
        "expected_unique_unwind": constants.get("EXPECTED_UNIQUE_UNWIND"),
        "expected_handler_records": constants.get("EXPECTED_HANDLER_RECORDS"),
        "expected_chain_records": constants.get("EXPECTED_CHAIN_RECORDS"),
    }


def audit_xref_build_contract(ledger: Ledger, constants: Mapping[str, Any]) -> dict[str, Any]:
    group = "script.xref_build"
    expectations = constants.get("DOC03_EXPECTATIONS")
    if not isinstance(expectations, dict):
        ledger.equal(group, "DOC03_EXPECTATIONS_extracted", True, False)
        return {}
    for key in (
        "runtime_function_count",
        "direct_call_iat_xrefs",
        "direct_call_iat_xrefs_regular",
        "direct_call_iat_xrefs_delay",
        "thunk_mediated_call_xrefs",
        "import_thunk_count",
        "thunks_reached_by_call",
        "iat_slot_count_total",
        "raw_direct_call_iat_candidates",
        "raw_direct_call_iat_rejected",
        "total_statistical_call_xrefs",
        "xref_runtime_functions",
        "xref_runtime_function_bytes",
    ):
        claim = DOCUMENTED.get(key)
        if claim is None:
            continue
        ledger.equal(group, f"doc03_claim[{key}]", claim[1], expectations.get(key))
    ledger.equal(group, "DOC03_TABLES_anchor", f"{DOC03}#10", constants.get("DOC03_TABLES"))
    return {"expectations": expectations}


def audit_syscall_scan_contract(ledger: Ledger, constants: Mapping[str, Any]) -> dict[str, Any]:
    group = "script.syscall_scan"
    ledger.equal(
        group,
        "EXPECTED_RAW_HITS",
        DOCUMENTED["syscall_raw_hits"][1],
        constants.get("EXPECTED_RAW_HITS"),
    )
    pattern = constants.get("PATTERN")
    ledger.equal(
        group,
        "PATTERN",
        "0f05",
        bytes(pattern).hex() if isinstance(pattern, (bytes, bytearray)) else None,
    )
    ledger.equal(group, "CSV_FIELDS_present", True, isinstance(constants.get("CSV_FIELDS"), (list, tuple)))
    return {"expected_raw_hits": constants.get("EXPECTED_RAW_HITS")}


class PdataFacts:
    """Aggregates of pdata_functions.csv plus the specimen records it must mirror."""

    def __init__(self) -> None:
        self.rows = 0
        self.index_breaks = 0
        self.hex_breaks = 0
        self.range_breaks = 0
        self.raw_breaks = 0
        self.order_breaks = 0
        self.overflow_breaks = 0
        self.spec_breaks = 0
        self.unwind_index_breaks = 0
        self.unwind_ref_breaks = 0
        self.unwind_first_breaks = 0
        self.flag_breaks = 0
        self.handler_breaks = 0
        self.chain_breaks = 0
        self.empty_breaks = 0
        self.flags: Counter[int] = Counter()
        self.unwind_addresses: Counter[int] = Counter()
        self.first_record: dict[int, int] = {}
        self.reference_count: dict[int, int] = {}
        self.begins: list[int] = []
        self.ends: list[int] = []
        self.gaps: list[tuple[int, int, int]] = []
        self.covered_bytes = 0

    def owner_of(self, rva: int) -> int | None:
        index = bisect_right(self.begins, rva) - 1
        if index >= 0 and self.begins[index] <= rva < self.ends[index]:
            return index
        return None

    def owner_range(self, rva: int) -> tuple[int, int] | None:
        index = self.owner_of(rva)
        return None if index is None else (self.begins[index], self.ends[index])


def audit_pdata_csv(
    ledger: Ledger,
    image: StaticImage,
    records: Sequence[tuple[int, int, int]],
    path: Path,
) -> PdataFacts:
    group = "pdata.csv"
    facts = PdataFacts()
    exception_rva, _ = image.directory(3)
    exception_raw = image.raw_of(exception_rva) or 0
    header, rows = stream_csv(path)
    index = {name: position for position, name in enumerate(header)}
    previous_end: int | None = None
    for row in rows:
        facts.rows += 1
        record_index = int(row[index["record_index"]])
        if record_index != facts.rows - 1:
            facts.index_breaks += 1
        begin = int(row[index["begin_address"]])
        end = int(row[index["end_address"]])
        facts.begins.append(begin)
        facts.ends.append(end)
        facts.covered_bytes += end - begin
        if row[index["begin_address_hex"]] != hex_up(begin):
            facts.hex_breaks += 1
        if row[index["end_address_hex"]] != hex_up(end):
            facts.hex_breaks += 1
        if int(row[index["code_size"]]) != end - begin:
            facts.range_breaks += 1
        if int(row[index["begin_raw"]]) != (image.raw_of(begin) or -1):
            facts.raw_breaks += 1
        if int(row[index["end_raw"]]) != (image.raw_of(end - 1) or -1):
            facts.raw_breaks += 1
        if int(row[index["record_raw"]]) != exception_raw + RUNTIME_FUNCTION_SIZE * record_index:
            facts.raw_breaks += 1
        if previous_end is not None:
            if begin < previous_end:
                facts.order_breaks += 1
            if int(row[index["gap_before"]]) != begin - previous_end:
                facts.range_breaks += 1
            if begin > previous_end:
                facts.gaps.append((begin, previous_end, begin - previous_end))
        previous_end = end
        if record_index < len(records):
            begin_claim, end_claim, unwind_claim = records[record_index]
            if (begin_claim, end_claim, unwind_claim) != (begin, end, int(row[index["unwind_info_address"]])):
                facts.spec_breaks += 1
        unwind = int(row[index["unwind_info_address"]])
        facts.unwind_addresses[unwind] += 1
        if unwind not in facts.first_record:
            facts.first_record[unwind] = record_index
        flag = int(row[index["unwind_flags"]])
        facts.flags[flag] += 1
        version = int(row[index["unwind_version"]])
        if version != 1:
            facts.flag_breaks += 1
        has_handler = row[index["has_handler"]] == "true"
        names = set(filter(None, row[index["unwind_flag_names"]].split("|")))
        handler_rva = int(row[index["handler_rva"]])
        if has_handler != bool(names & {"EHANDLER", "UHANDLER"}):
            facts.handler_breaks += 1
        if has_handler != (handler_rva != 0):
            facts.handler_breaks += 1
        if has_handler and (image.raw_of(handler_rva) is None or not image.section_of(handler_rva)):
            facts.handler_breaks += 1
        has_chain = row[index["has_chain"]] == "true"
        chain_begin = int(row[index["chain_begin_address"]])
        chain_end = int(row[index["chain_end_address"]])
        chain_unwind = int(row[index["chain_unwind_info_address"]])
        if has_chain != ("CHAININFO" in names):
            facts.chain_breaks += 1
        if has_chain != (chain_begin != 0 and chain_end != 0 and chain_unwind != 0):
            facts.chain_breaks += 1
        if has_chain and not (chain_begin < chain_end):
            facts.chain_breaks += 1
        section = image.section_of(begin)
        if section is None or section.name != row[index["code_section"]]:
            facts.empty_breaks += 1
        unwind_section = image.section_of(unwind) if unwind else None
        if unwind and (unwind_section is None or unwind_section.name != row[index["unwind_info_section"]]):
            facts.empty_breaks += 1
    ordered = sorted(facts.unwind_addresses)
    expected_ordinal = {unwind: position + 1 for position, unwind in enumerate(ordered)}
    second_header, second_rows = stream_csv(path)
    second_index = {name: position for position, name in enumerate(second_header)}
    for row in second_rows:
        unwind = int(row[second_index["unwind_info_address"]])
        if int(row[second_index["unwind_info_index"]]) != expected_ordinal[unwind]:
            facts.unwind_index_breaks += 1
        if int(row[second_index["unwind_reference_count"]]) != facts.unwind_addresses[unwind]:
            facts.unwind_ref_breaks += 1
        if int(row[second_index["unwind_first_record"]]) != facts.first_record[unwind]:
            facts.unwind_first_breaks += 1
    ledger.equal(group, "row_count_matches_specimen_records", len(records), facts.rows)
    ledger.equal(group, "record_index_contiguous_0_based", 0, facts.index_breaks)
    ledger.equal(group, "hex_columns_match_decimal_columns", 0, facts.hex_breaks)
    ledger.equal(group, "code_size_and_gap_before_consistent", 0, facts.range_breaks)
    ledger.equal(group, "raw_offsets_match_section_map", 0, facts.raw_breaks)
    ledger.equal(group, "record_order_strictly_ascending", 0, facts.order_breaks)
    ledger.equal(group, "csv_matches_exception_directory_bytes", 0, facts.spec_breaks)
    ledger.equal(group, "unwind_info_index_is_ascending_rva_ordinal", 0, facts.unwind_index_breaks)
    ledger.equal(group, "unwind_reference_count_matches_group_size", 0, facts.unwind_ref_breaks)
    ledger.equal(group, "unwind_first_record_is_group_minimum", 0, facts.unwind_first_breaks)
    ledger.equal(group, "unwind_version_all_one", 0, facts.flag_breaks)
    ledger.equal(group, "handler_flag_consistency", 0, facts.handler_breaks)
    ledger.equal(group, "chain_flag_consistency", 0, facts.chain_breaks)
    ledger.equal(group, "section_labels_match_image", 0, facts.empty_breaks)
    observed_flags = {str(value): facts.flags[value] for value in sorted(facts.flags)}
    for key, flag in (
        ("unwind_flag_zero", 0),
        ("unwind_flag_ehandler", 1),
        ("unwind_flag_uhandler", 2),
        ("unwind_flag_ehandler_uhandler", 3),
        ("unwind_flag_chaininfo", 4),
    ):
        ledger.expect_documented(group, key, observed_flags.get(str(flag)))
    ledger.expect_documented(group, "runtime_function_records", facts.rows)
    ledger.expect_documented(group, "unique_unwind_info", len(facts.unwind_addresses))
    handler_records = sum(count for value, count in facts.flags.items() if value & 0x03)
    chain_records = sum(count for value, count in facts.flags.items() if value & 0x04)
    ledger.expect_documented(group, "handler_records", handler_records)
    ledger.expect_documented(group, "chain_records", chain_records)
    ledger.equal(
        group,
        "flag_distribution_sums_to_row_count",
        facts.rows,
        sum(observed_flags.values()),
    )
    return facts


def audit_pdata_stats(
    ledger: Ledger,
    root: Path,
    stats: Mapping[str, Any],
    facts: PdataFacts,
    pdata_csv_sha: str,
    header_columns: int,
    baseline: Mapping[str, Any],
) -> dict[str, Any]:
    group = "pdata.stats"
    ledger.equal(group, "schema", "adhesive-dumper.pdata-stats/1", stats.get("schema"))
    expected = stats.get("expected", {})
    ledger.equal(group, "expected.record_count", facts.rows, expected.get("record_count"))
    ledger.equal(
        group,
        "expected.unique_unwind_info",
        len(facts.unwind_addresses),
        expected.get("unique_unwind_info"),
    )
    ledger.equal(
        group,
        "expected.flag_distribution_per_record",
        {str(value): facts.flags[value] for value in sorted(facts.flags)},
        expected.get("flag_distribution_per_record"),
    )
    ledger.equal(group, "expected.source", f"{DOC02}#15", expected.get("source"))
    csv_block = stats.get("csv", {})
    ledger.equal(group, "csv.path", "reverse/evidence/pdata_functions.csv", csv_block.get("path"))
    ledger.equal(group, "csv.row_count", facts.rows, csv_block.get("row_count"))
    ledger.equal(group, "csv.sha256", pdata_csv_sha, csv_block.get("sha256"))
    ledger.equal(group, "csv.encoding", "utf-8", csv_block.get("encoding"))
    ledger.equal(group, "csv.bom", False, csv_block.get("bom"))
    ledger.equal(group, "csv.line_terminator", "\\n", csv_block.get("line_terminator"))
    ledger.equal(group, "csv.column_count", header_columns, csv_block.get("column_count"))
    parsing = stats.get("parsing", {})
    ledger.equal(group, "parsing.csv_columns_is_list", True, isinstance(parsing.get("csv_columns"), list))
    ordering = stats.get("ordering", {})
    ledger.equal(group, "ordering.sorted_by_begin_address", True, ordering.get("sorted_by_begin_address"))
    ledger.equal(group, "ordering.duplicate_records", 0, ordering.get("duplicate_records"))
    ledger.equal(group, "ordering.duplicate_begin_addresses", 0, ordering.get("duplicate_begin_addresses"))
    ledger.equal(group, "ordering.overlapping_records", 0, ordering.get("overlapping_records"))
    ledger.equal(group, "ordering.out_of_order_pairs", 0, ordering.get("out_of_order_pairs"))
    ledger.equal(group, "ordering.begin_address_min", facts.begins[0], ordering.get("begin_address_min"))
    ledger.equal(group, "ordering.end_address_max", max(facts.ends), ordering.get("end_address_max"))
    unwind = stats.get("unwind_info", {})
    ledger.equal(group, "unwind_info.unique_count", len(facts.unwind_addresses), unwind.get("unique_count"))
    ledger.equal(group, "unwind_info.null_address_records", 0, unwind.get("null_address_records"))
    ledger.equal(group, "unwind_info.unmapped_records", 0, unwind.get("unmapped_records"))
    ledger.equal(group, "unwind_info.invalid_header_records", 0, unwind.get("invalid_header_records"))
    ledger.equal(group, "unwind_info.version_invalid_records", 0, unwind.get("version_invalid_records"))
    ledger.equal(
        group,
        "unwind_info.end_outside_section_records",
        0,
        unwind.get("end_outside_section_records"),
    )
    observed_reference = sorted(facts.unwind_addresses.values())
    if observed_reference:
        median = (
            observed_reference[len(observed_reference) // 2]
            if len(observed_reference) % 2
            else (
                observed_reference[len(observed_reference) // 2 - 1]
                + observed_reference[len(observed_reference) // 2]
            )
            / 2
        )
        ledger.equal(
            group,
            "unwind_info.reference_count_max",
            max(observed_reference),
            unwind.get("reference_count_max"),
        )
        ledger.equal(
            group,
            "unwind_info.reference_count_median",
            median,
            unwind.get("reference_count_median"),
        )
    flags = stats.get("unwind_flags", {})
    observed_flags = {str(value): facts.flags[value] for value in sorted(facts.flags)}
    ledger.equal(
        group,
        "unwind_flags.value_distribution_per_record",
        observed_flags,
        flags.get("value_distribution_per_record"),
    )
    handler_records = sum(count for value, count in facts.flags.items() if value & 0x03)
    chain_records = sum(count for value, count in facts.flags.items() if value & 0x04)
    ledger.equal(
        group,
        "unwind_flags.records_with_handler",
        handler_records,
        flags.get("records_with_handler"),
    )
    ledger.equal(group, "unwind_flags.records_with_chain", chain_records, flags.get("records_with_chain"))
    handlers = stats.get("handlers", {})
    ledger.equal(group, "handlers.record_count", handler_records, handlers.get("record_count"))
    chains = stats.get("chains", {})
    ledger.equal(group, "chains.record_count", chain_records, chains.get("record_count"))
    ledger.equal(group, "chains.invalid_chained_entries", 0, chains.get("invalid_chained_entries"))
    coverage = stats.get("text_coverage", {})
    ledger.equal(group, "text_coverage.covered_bytes", facts.covered_bytes, coverage.get("covered_bytes"))
    ledger.equal(
        group,
        "text_coverage.records_outside_text",
        0,
        coverage.get("records_outside_text"),
    )
    span = facts.ends[-1] - facts.begins[0]
    ledger.equal(
        group,
        "text_coverage.uncovered_bytes",
        span - facts.covered_bytes,
        coverage.get("uncovered_bytes"),
    )
    ledger.equal(group, "text_coverage.span_bytes", span, coverage.get("span_bytes"))
    gaps = stats.get("gaps", {})
    sizes = sorted(size for _, _, size in facts.gaps)
    ledger.equal(group, "gaps.count", len(facts.gaps), gaps.get("count"))
    ledger.equal(group, "gaps.total_bytes", sum(sizes), gaps.get("total_bytes"))
    if sizes:
        ledger.equal(group, "gaps.min_bytes", sizes[0], gaps.get("min_bytes"))
        ledger.equal(group, "gaps.max_bytes", sizes[-1], gaps.get("max_bytes"))
    largest = sorted(facts.gaps, key=lambda item: item[2], reverse=True)[:24]
    observed_largest = [
        {"offset": offset, "previous_end": previous, "size": size} for offset, previous, size in largest
    ]
    stored_largest = [
        {"offset": entry.get("offset"), "previous_end": entry.get("previous_end"), "size": entry.get("size")}
        for entry in gaps.get("largest", [])
    ]
    ledger.equal(group, "gaps.largest", stored_largest, observed_largest)
    validation = stats.get("validation", {})
    stored_checks = validation.get("checks", [])
    ledger.equal(group, "validation.check_count", len(stored_checks), validation.get("check_count"))
    ledger.equal(
        group,
        "validation.failed_count",
        0,
        validation.get("failed_count"),
    )
    not_ok = [
        entry.get("check")
        for entry in stored_checks
        if str(entry.get("ok")).lower() not in ("true", "1")
    ]
    ledger.equal(group, "validation.stored_checks_all_ok", [], not_ok)
    producer = stats.get("producer", {})
    ledger.equal(group, "producer.script", "reverse/scripts/pdata_map.py", producer.get("script"))
    ledger.equal(group, "producer.helper", SCRIPT_COMMON, producer.get("helper"))
    for key, relative in (
        ("script_sha256", PRODUCERS["pdata_map.py"]),
        ("helper_sha256", SCRIPT_COMMON),
        ("baseline_sha256", "reverse/evidence/baseline.json"),
    ):
        path = root / relative
        observed = sha256_file(path) if path.is_file() else None
        ledger.equal(group, f"producer.{key}", producer.get(key), observed)
    ledger.equal(
        group,
        "producer.baseline_record_count",
        facts.rows,
        baseline.get("pdata", {}).get("record_count"),
    )
    return {
        "csv_row_count": csv_block.get("row_count"),
        "csv_sha256": csv_block.get("sha256"),
        "gaps_count": gaps.get("count"),
        "validation_failed_count": validation.get("failed_count"),
    }


def unwind_flag_value(names: str) -> int:
    value = 0
    present = set(filter(None, names.split("|")))
    for mask, name in UNWIND_FLAG_MASKS.items():
        if name in present:
            value |= mask
    return value


def audit_cfg(
    ledger: Ledger,
    image: StaticImage,
    facts: PdataFacts,
    functions_path: Path,
    clusters_path: Path,
) -> dict[str, Any]:
    group = "cfg.functions"
    clusters_group = "cfg.clusters"
    header, rows = stream_csv(functions_path)
    index = {name: position for position, name in enumerate(header)}
    clusters_header, cluster_rows = stream_csv(clusters_path)
    cluster_index = {name: position for position, name in enumerate(clusters_header)}
    ledger.equal(
        clusters_group,
        "header_matches_producer_declaration",
        CLUSTER_COUNTER_HEADER,
        ",".join(clusters_header),
    )
    summed = tuple(field for field in FUNCTION_SUMMED if field in index)
    clusters: dict[int, dict[str, Any]] = {}
    rows_seen = 0
    breaks: Counter[str] = Counter()
    previous_end: int | None = None
    expected_cluster = 0
    cluster_last_end = 0
    for row in rows:
        rows_seen += 1
        func_index = int(row[index["func_index"]])
        if func_index != rows_seen - 1:
            breaks["func_index_not_contiguous"] += 1
        begin = int(row[index["begin_rva"]])
        end = int(row[index["end_rva"]])
        size = end - begin
        if func_index >= len(facts.begins):
            breaks["range_differs_from_pdata"] += 1
        elif (facts.begins[func_index], facts.ends[func_index]) != (begin, end):
            breaks["range_differs_from_pdata"] += 1
        if int(row[index["size"]]) != size:
            breaks["size_column"] += 1
        if row[index["begin_rva_hex"]] != hex_up(begin) or row[index["end_rva_hex"]] != hex_up(end):
            breaks["hex_columns"] += 1
        if int(row[index["begin_va"]]) != begin + image.image_base:
            breaks["begin_va"] += 1
        if int(row[index["end_va"]]) != end + image.image_base:
            breaks["end_va"] += 1
        if (image.raw_of(begin) or -1) != int(row[index["raw"]]):
            breaks["raw_column"] += 1
        if previous_end is not None and begin < previous_end:
            breaks["overlapping_functions"] += 1
        previous_end = end
        basic_blocks = int(row[index["basic_blocks"]])
        reached = int(row[index["blocks_reached"]])
        linear = int(row[index["blocks_linear_only"]])
        if basic_blocks != reached + linear:
            breaks["blocks_not_split"] += 1
        if row[index["reached_ratio"]] != ratio_text(reached, basic_blocks):
            breaks["reached_ratio"] += 1
        decoded = int(row[index["decoded_bytes"]])
        undecoded = int(row[index["undecoded_bytes"]])
        instructions = int(row[index["instructions"]])
        if decoded > size or decoded + undecoded > size:
            breaks["decoded_out_of_bounds"] += 1
        if instructions > decoded:
            breaks["instruction_count"] += 1
        if undecoded > 0 and int(row[index["undecoded_regions"]]) == 0:
            breaks["undecoded_regions"] += 1
        if undecoded == 0 and int(row[index["undecoded_regions"]]) != 0:
            breaks["undecoded_regions"] += 1
        symbols = set(filter(None, row[index["iat_symbols"]].split(";")))
        if int(row[index["iat_symbol_count"]]) < len(symbols):
            breaks["iat_symbol_count"] += 1
        if symbols and int(row[index["iat_module_count"]]) < 1:
            breaks["iat_module_count"] += 1
        if int(row[index["unwind_shared_by"]]) != facts.unwind_addresses.get(
            int(row[index["unwind_rva"]]), -1
        ):
            breaks["unwind_shared_by"] += 1
        if int(row[index["unwind_version"]]) != 1:
            breaks["unwind_version"] += 1
        cluster_id = int(row[index["cluster_id"]])
        if expected_cluster == 0 or begin - cluster_last_end > DEFAULT_CLUSTER_GAP:
            expected_cluster += 1
            cluster_last_end = end
        else:
            cluster_last_end = max(cluster_last_end, end)
        if cluster_id != expected_cluster:
            breaks["cluster_id_not_reproducible_from_gap_rule"] += 1
        entry = clusters.get(cluster_id)
        if entry is None:
            entry = clusters[cluster_id] = {
                "count": 0,
                "size_min": None,
                "size_max": None,
                "size_total": 0,
                "first": None,
                "last": None,
                "max_indegree": 0,
                "codes": Counter(),
                "sum": Counter(),
                "flags": Counter(),
                "linear": 0,
                "undecoded": 0,
                "entry_refs": 0,
                "multi_entry": 0,
                "overlapping": 0,
            }
        entry["count"] += 1
        entry["size_total"] += size
        entry["size_min"] = size if entry["size_min"] is None else min(entry["size_min"], size)
        entry["size_max"] = size if entry["size_max"] is None else max(entry["size_max"], size)
        entry["first"] = begin if entry["first"] is None else min(entry["first"], begin)
        entry["last"] = end if entry["last"] is None else max(entry["last"], end)
        entry["max_indegree"] = max(entry["max_indegree"], int(row[index["max_indegree"]]))
        for field in summed:
            entry["sum"][field] += int(row[index[field]])
        entry["linear"] += int(linear > 0)
        entry["undecoded"] += int(undecoded > 0)
        entry["entry_refs"] += int(int(row[index["entry_refs"]]) > 0)
        entry["multi_entry"] += int(
            int(row[index["entry_external_calls"]])
            + int(row[index["entry_external_jumps"]])
            + (1 if int(row[index["entry_internal"]]) > 0 else 0)
            > 1
        )
        entry["overlapping"] += int(row[index["overlap_role"]] != "sole")
        flags = unwind_flag_value(row[index["unwind_flags"]])
        for mask, name in UNWIND_FLAG_MASKS.items():
            entry["flags"][name] += int(bool(flags & mask))
        chunk = image.slice(begin, size)
        if len(chunk) == size:
            entry["codes"].update(chunk)
    ledger.equal(group, "row_count_equals_pdata_records", len(facts.begins), rows_seen)
    for name in FUNCTION_BREAKS:
        ledger.equal(group, name, 0, breaks[name])
    cluster_rows_seen = 0
    cluster_breaks: Counter[str] = Counter()
    entropy_breaks = 0
    for row in cluster_rows:
        cluster_rows_seen += 1
        cluster_id = int(row[cluster_index["cluster_id"]])
        if cluster_id != cluster_rows_seen:
            cluster_breaks["cluster_id_not_contiguous_1_based"] += 1
        entry = clusters.get(cluster_id)
        if entry is None:
            cluster_breaks["cluster_without_functions"] += 1
            continue
        for field in CLUSTER_SUM_FIELDS:
            if int(row[cluster_index[field]]) != entry["sum"][field]:
                cluster_breaks[f"sum_{field}"] += 1
        expectations = {
            "function_count": entry["count"],
            "size_min": entry["size_min"],
            "size_max": entry["size_max"],
            "size_total": entry["size_total"],
            "max_indegree": entry["max_indegree"],
            "first_rva": entry["first"],
            "last_end_rva": entry["last"],
            "rva_span": entry["last"] - entry["first"],
            "span_bytes": entry["last"] - entry["first"],
            "code_bytes": entry["size_total"],
            "gap_bytes": entry["last"] - entry["first"] - entry["size_total"],
            "cross_function_edges": entry["sum"]["cross_calls"] + entry["sum"]["cross_jumps"],
            "functions_with_linear_blocks": entry["linear"],
            "functions_with_undecoded": entry["undecoded"],
            "functions_with_entry_refs": entry["entry_refs"],
            "functions_multi_entry": entry["multi_entry"],
            "unwind_ehandler": entry["flags"]["EHANDLER"],
            "unwind_uhandler": entry["flags"]["UHANDLER"],
            "unwind_chaininfo": entry["flags"]["CHAININFO"],
            "overlapping_functions": entry["overlapping"],
        }
        for field, observed in expectations.items():
            if int(row[cluster_index[field]]) != observed:
                cluster_breaks[field] += 1
        if row[cluster_index["first_rva_hex"]] != hex_up(entry["first"]):
            cluster_breaks["first_rva_hex"] += 1
        if row[cluster_index["last_end_rva_hex"]] != hex_up(entry["last"]):
            cluster_breaks["last_end_rva_hex"] += 1
        if row[cluster_index["size_average"]] != str(
            round(entry["size_total"] / entry["count"], AVERAGE_DIGITS)
        ):
            cluster_breaks["size_average"] += 1
        if row[cluster_index["reached_ratio"]] != ratio_text(
            entry["sum"]["blocks_reached"], entry["sum"]["basic_blocks"]
        ):
            cluster_breaks["reached_ratio"] += 1
        if int(row[cluster_index["anchor_count"]]) != len(
            [item for item in row[cluster_index["anchor_evidence"]].split(";") if item]
        ):
            cluster_breaks["anchor_count"] += 1
        listed = set(filter(None, row[cluster_index["iat_symbols"]].split(";")))
        if int(row[cluster_index["iat_symbol_count"]]) < len(listed):
            cluster_breaks["iat_symbol_count"] += 1
        span = entry["last"] - entry["first"]
        span_chunk = image.slice(entry["first"], span)
        if len(span_chunk) == span:
            if float(row[cluster_index["entropy_span"]]) != shannon(Counter(span_chunk), span):
                entropy_breaks += 1
        code_chunk_total = sum(entry["codes"].values())
        if code_chunk_total and float(row[cluster_index["entropy_code"]]) != shannon(
            entry["codes"], code_chunk_total
        ):
            entropy_breaks += 1
    for name in CLUSTER_BREAKS:
        ledger.equal(clusters_group, name, 0, cluster_breaks[name])
    ledger.equal(clusters_group, "entropy_recomputed_from_specimen", 0, entropy_breaks)
    ledger.equal(
        clusters_group,
        "cluster_rows_cover_all_function_references",
        len(clusters),
        cluster_rows_seen,
    )
    return {
        "function_rows": rows_seen,
        "cluster_rows": cluster_rows_seen,
        "clusters_referenced": len(clusters),
    }


def audit_xref(
    ledger: Ledger,
    image: StaticImage,
    facts: PdataFacts,
    path: Path,
) -> dict[str, Any]:
    group = "xref.edges"
    header, rows = stream_csv(path)
    index = {name: position for position, name in enumerate(header)}
    breaks: Counter[str] = Counter()
    relations: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    call_functions: dict[int, tuple[int, int]] = {}
    call_rows = 0
    edge_id_first = 0
    edge_id_last = 0
    direct_iat_slots: set[str] = set()
    thunk_iat_slots: set[str] = set()
    binding_slots: set[str] = set()
    thunk_stub_rvas: set[int] = set()
    reached_thunk_stubs: set[int] = set()
    thunk_targets: set[int] = set()
    hosting_thunks: dict[int, int] = {}
    jmp_thunk_rows = 0
    stub_inside_pdata = 0
    stub_with_code_function = 0
    code_function_partial = 0
    thunk_function_partial = 0
    direct_iat_regular = 0
    direct_iat_delay = 0
    thunk_call_regular = 0
    thunk_call_delay = 0
    row_count = 0
    for row in rows:
        row_count += 1
        edge_id = int(row[index["edge_id"]])
        if row_count == 1:
            edge_id_first = edge_id
        edge_id_last = edge_id
        if edge_id != row_count:
            breaks["edge_id_not_contiguous_1_based"] += 1
        relation = row[index["relation"]]
        category = row[index["category"]]
        relations[relation] += 1
        categories[category] += 1
        src_rva = int(row[index["src_rva"]])
        via_rva = row[index["via_rva"]]
        if (image.raw_of(src_rva) or -1) != int(row[index["src_raw"]]):
            breaks["src_raw"] += 1
        function_index = row[index["code_instruction_function_index"]]
        if not function_columns_are_atomic(row, index, CODE_FUNCTION_FIELDS):
            code_function_partial += 1
        if not function_columns_are_atomic(row, index, THUNK_FUNCTION_FIELDS):
            thunk_function_partial += 1
        if function_index:
            owner = facts.owner_of(src_rva)
            if owner is None or str(owner) != function_index:
                breaks["code_instruction_function_index"] += 1
            begin = int(row[index["code_instruction_function_begin"]])
            end = int(row[index["code_instruction_function_end"]])
            if (begin, end) != (facts.begins[int(function_index)], facts.ends[int(function_index)]):
                breaks["code_instruction_function_range"] += 1
        elif category in ("direct_call", "direct_jmp"):
            breaks["code_edge_without_function"] += 1
        thunk_function = row[index["target_thunk_function_index"]]
        if thunk_function:
            begin = int(row[index["target_thunk_function_begin"]])
            end = int(row[index["target_thunk_function_end"]])
            if (begin, end) != (facts.begins[int(thunk_function)], facts.ends[int(thunk_function)]):
                breaks["target_thunk_function_index"] += 1
            if not begin <= int(via_rva or src_rva) < end:
                breaks["target_thunk_function_range"] += 1
        payload = row[index["src_bytes"]]
        if payload:
            expected = bytes.fromhex(payload.replace(" ", ""))
            raw = image.raw_of(src_rva)
            if raw is None or image.data[raw:raw + len(expected)] != expected:
                breaks["src_bytes"] += 1
        iat_rva = row[index["iat_rva"]]
        if category in ("iat", "thunk") and relation != "call_rel32_to_thunk" and not iat_rva:
            if relation not in ("jmp_rel32_to_thunk",):
                breaks["iat_edge_without_iat_rva"] += 1
        if relation == "iat_slot_symbol_binding":
            binding_slots.add(iat_rva)
        if relation == "iat_jmp_thunk_stub":
            thunk_stub_rvas.add(src_rva)
            if function_index:
                stub_with_code_function += 1
            if thunk_function:
                hosting_thunks[int(src_rva)] = int(thunk_function)
            elif facts.owner_of(src_rva) is not None:
                stub_inside_pdata += 1
        if relation in ("call_indirect_iat", "call_rel32_to_thunk"):
            call_rows += 1
            owner = int(function_index)
            call_functions[owner] = (
                facts.begins[owner],
                facts.ends[owner],
            )
        if relation in ("call_rel32_to_thunk", "jmp_rel32_to_thunk") and via_rva:
            thunk_targets.add(int(via_rva))
        if relation == "call_indirect_iat":
            direct_iat_slots.add(iat_rva)
            if "import_kind_delay" in row[index["evidence"]]:
                direct_iat_delay += 1
            else:
                direct_iat_regular += 1
        if relation == "call_rel32_to_thunk":
            thunk_iat_slots.add(iat_rva)
            reached_thunk_stubs.add(int(via_rva))
            if "import_kind_delay" in row[index["evidence"]]:
                thunk_call_delay += 1
            else:
                thunk_call_regular += 1
        if relation == "jmp_rel32_to_thunk":
            jmp_thunk_rows += 1
    ledger.equal(group, "edge_id_range", [1, row_count], [edge_id_first, edge_id_last])
    ledger.equal(
        group,
        "thunk_edge_targets_are_declared_stubs",
        [],
        sorted(thunk_targets - thunk_stub_rvas),
    )
    ledger.at_most(
        group,
        "thunk_stub_count_matches_documented_import_thunks",
        DOCUMENTED["import_thunks"][1],
        len(thunk_stub_rvas),
    )
    ledger.equal(
        group,
        "thunk_stub_rows_declare_no_code_instruction_function",
        0,
        stub_with_code_function,
    )
    ledger.equal(
        group,
        "code_instruction_function_columns_are_atomic",
        0,
        code_function_partial,
    )
    ledger.equal(
        group,
        "target_thunk_function_columns_are_atomic",
        0,
        thunk_function_partial,
    )
    ledger.equal(
        group,
        "thunk_stub_rows_covered_by_a_pdata_function",
        0,
        stub_inside_pdata,
    )
    ledger.equal(
        group,
        "thunk_stub_hosting_thunk_function_covers_the_stub_byte",
        [],
        sorted(rva for rva, owner in hosting_thunks.items() if not facts.begins[owner] <= rva < facts.ends[owner]),
    )
    for name in XREF_BREAKS:
        ledger.equal(group, name, 0, breaks[name])
    ledger.expect_documented(group, "direct_iat_call_xrefs", relations["call_indirect_iat"])
    ledger.expect_documented(group, "direct_iat_call_xrefs_regular", direct_iat_regular)
    ledger.expect_documented(group, "direct_iat_call_xrefs_delay", direct_iat_delay)
    ledger.expect_documented(group, "thunk_mediated_call_xrefs", relations["call_rel32_to_thunk"])
    ledger.expect_documented(group, "import_thunks", relations["iat_jmp_thunk_stub"])
    ledger.expect_documented(group, "thunks_reached_by_call", len(reached_thunk_stubs))
    ledger.expect_documented(group, "iat_slots_total", len(binding_slots))
    ledger.expect_documented(group, "iat_slots_reached_direct", len(direct_iat_slots))
    ledger.expect_documented(group, "iat_slots_touched", len(direct_iat_slots | thunk_iat_slots))
    ledger.expect_documented(group, "total_statistical_call_xrefs", call_rows)
    ledger.expect_documented(group, "xref_runtime_functions", len(call_functions))
    ledger.expect_documented(
        group,
        "xref_runtime_function_bytes",
        sum(end - begin for begin, end in call_functions.values()),
    )
    ledger.equal(
        group,
        "call_xrefs_equal_direct_plus_thunk",
        relations["call_indirect_iat"] + relations["call_rel32_to_thunk"],
        call_rows,
    )
    ledger.at_most(
        group,
        "thunk_call_targets_are_declared_stubs",
        len(thunk_stub_rvas),
        len(reached_thunk_stubs),
    )
    return {
        "rows": row_count,
        "relations": dict(sorted(relations.items())),
        "categories": dict(sorted(categories.items())),
        "direct_iat_call_xrefs": relations["call_indirect_iat"],
        "thunk_mediated_call_xrefs": relations["call_rel32_to_thunk"],
        "import_thunk_stubs": relations["iat_jmp_thunk_stub"],
        "thunk_mediated_jmp_edges": jmp_thunk_rows,
        "thunk_stubs_reached_by_call": len(reached_thunk_stubs),
        "iat_slots_bound": len(binding_slots),
        "iat_slots_reached_direct": len(direct_iat_slots),
        "iat_slots_reached_via_thunk": len(thunk_iat_slots),
        "iat_slots_touched": len(direct_iat_slots | thunk_iat_slots),
        "iat_slots_untouched": len(binding_slots) - len(direct_iat_slots | thunk_iat_slots),
        "call_xref_runtime_functions": len(call_functions),
        "call_xref_runtime_function_bytes": sum(end - begin for begin, end in call_functions.values()),
        "thunk_stub_rows_covered_by_a_pdata_function": stub_inside_pdata,
        "thunk_stubs_hosted_inside_a_pdata_function": len(hosting_thunks),
        "thunk_stub_hosting_functions": {str(rva): owner for rva, owner in sorted(hosting_thunks.items())},
    }


def audit_indirect_sites(
    ledger: Ledger,
    image: StaticImage,
    facts: PdataFacts,
    path: Path,
) -> dict[str, Any]:
    group = "indirect.sites"
    header, rows = stream_csv(path)
    index = {name: position for position, name in enumerate(header)}
    breaks: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    target_kinds: Counter[str] = Counter()
    row_count = 0
    ids_first = 0
    ids_last = 0
    stub_rows = 0
    stub_annotated_outside = 0
    stub_annotated_outside_but_inside = 0
    stub_annotated_interior = 0
    stub_with_function_index = 0
    stub_interior_arithmetic_breaks = 0
    stub_interior_host_breaks = 0
    code_function_partial = 0
    thunk_function_partial = 0
    stub_hosting_functions: dict[int, int] = {}
    rejected_rows = 0
    rejected_inside_pdata = 0
    rejected_symbols: Counter[str] = Counter()
    for row in rows:
        row_count += 1
        site_id = int(row[index["site_id"]])
        if row_count == 1:
            ids_first = site_id
        ids_last = site_id
        if site_id != row_count:
            breaks["site_id_not_contiguous_1_based"] += 1
        insn_rva = int(row[index["insn_rva"]])
        kinds[row[index["kind"]]] += 1
        sources[row[index["source"]]] += 1
        target_kinds[row[index["target_kind"]]] += 1
        if (image.raw_of(insn_rva) or -1) != int(row[index["insn_raw"]]):
            breaks["insn_raw"] += 1
        function_index = row[index["code_instruction_function_index"]]
        if not function_columns_are_atomic(row, index, CODE_FUNCTION_FIELDS):
            code_function_partial += 1
        if not function_columns_are_atomic(row, index, THUNK_FUNCTION_FIELDS):
            thunk_function_partial += 1
        if function_index:
            owner = facts.owner_of(insn_rva)
            if owner is None or str(owner) != function_index:
                breaks["code_instruction_function_index"] += 1
            if (int(row[index["code_instruction_function_begin"]]), int(row[index["code_instruction_function_end"]])) != (
                facts.begins[int(function_index)],
                facts.ends[int(function_index)],
            ):
                breaks["code_instruction_function_range"] += 1
        thunk_function = row[index["target_thunk_function_index"]]
        if thunk_function:
            begin = int(row[index["target_thunk_function_begin"]])
            end = int(row[index["target_thunk_function_end"]])
            if (begin, end) != (facts.begins[int(thunk_function)], facts.ends[int(thunk_function)]):
                breaks["target_thunk_function_index"] += 1
            if facts.owner_of(insn_rva) != int(thunk_function):
                breaks["target_thunk_function_range"] += 1
        payload = row[index["bytes"]]
        expected = bytes.fromhex(payload.replace(" ", ""))
        raw = image.raw_of(insn_rva)
        if raw is None or image.data[raw:raw + len(expected)] != expected:
            breaks["bytes"] += 1
        annotation = row[index["annotation"]]
        if not annotation:
            breaks["empty_annotation"] += 1
        target_rva = row[index["target_rva"]]
        if target_rva:
            section = image.section_of(int(target_rva))
            if section is None:
                if row[index["target_section"]] not in ("UNMAPPED", ""):
                    breaks["target_section"] += 1
            elif section.name != row[index["target_section"]]:
                breaks["target_section"] += 1
        if row[index["target_kind"]] == "iat_slot" and row[index["iat_rva"]] != target_rva:
            breaks["iat_target"] += 1
        if annotation.startswith(THUNK_STUB_OUTSIDE_ANNOTATION) or annotation.startswith(
            THUNK_STUB_INTERIOR_ANNOTATION
        ):
            stub_rows += 1
            if function_index:
                stub_with_function_index += 1
            if annotation.startswith(THUNK_STUB_OUTSIDE_ANNOTATION):
                stub_annotated_outside += 1
                if facts.owner_of(insn_rva) is not None:
                    stub_annotated_outside_but_inside += 1
            else:
                stub_annotated_interior += 1
                arithmetic = THUNK_STUB_INTERIOR_ARITHMETIC.search(annotation)
                start = int(arithmetic.group(3), 16) if arithmetic is not None else -1
                first = image.data[image.raw_of(start)] if image.raw_of(start) is not None else -1
                if (
                    arithmetic is None
                    or insn_rva != start + int(arithmetic.group(1))
                    or first != int(arithmetic.group(4), 16)
                    or facts.owner_of(start) is None
                    or image.data[raw : raw + len(THUNK_MARKER_BYTES)] != THUNK_MARKER_BYTES
                ):
                    stub_interior_arithmetic_breaks += 1
                if thunk_function:
                    stub_hosting_functions[insn_rva] = int(thunk_function)
                    if facts.owner_of(start) != int(thunk_function):
                        stub_interior_host_breaks += 1
                else:
                    stub_interior_host_breaks += 1
        if row[index["kind"]] == "raw_ff15_rejected":
            rejected_rows += 1
            rejected_symbols[row[index["symbol"]]] += 1
            if facts.owner_of(insn_rva) is not None:
                rejected_inside_pdata += 1
    for name in INDIRECT_BREAKS:
        ledger.equal(group, name, 0, breaks[name])
    ledger.expect_documented(group, "raw_ff15_rejected", rejected_rows)
    ledger.equal(group, "rejected_candidates_outside_every_pdata_function", 0, rejected_inside_pdata)
    ledger.equal(
        group,
        "rejected_candidate_symbols",
        {"RtlVirtualUnwind": DOCUMENTED["raw_ff15_rejected"][1]},
        dict(rejected_symbols),
    )
    ledger.equal(
        group,
        "thunk_stub_annotation_contradicted_by_own_function_columns",
        0,
        stub_annotated_outside_but_inside,
    )
    ledger.equal(
        group,
        "thunk_stub_rows_never_claim_a_code_instruction_function",
        0,
        stub_with_function_index,
    )
    ledger.equal(
        group,
        "thunk_stub_interior_rows_recompute_from_their_own_annotation",
        0,
        stub_interior_arithmetic_breaks,
    )
    ledger.equal(
        group,
        "thunk_stub_interior_rows_name_their_hosting_thunk_function",
        0,
        stub_interior_host_breaks,
    )
    ledger.equal(
        group,
        "code_instruction_function_columns_are_atomic",
        0,
        code_function_partial,
    )
    ledger.equal(
        group,
        "target_thunk_function_columns_are_atomic",
        0,
        thunk_function_partial,
    )
    return {
        "rows": row_count,
        "site_id_range": [ids_first, ids_last],
        "kinds": dict(sorted(kinds.items())),
        "sources": dict(sorted(sources.items())),
        "target_kinds": dict(sorted(target_kinds.items())),
        "thunk_stub_sites": stub_rows,
        "thunk_stub_sites_with_function_index": stub_with_function_index,
        "thunk_stub_hosting_functions": {str(rva): owner for rva, owner in sorted(stub_hosting_functions.items())},
        "thunk_stub_sites_annotated_outside_pdata": stub_annotated_outside,
        "thunk_stub_sites_annotated_outside_but_inside_pdata": stub_annotated_outside_but_inside,
        "thunk_stub_sites_annotated_interior": stub_annotated_interior,
        "thunk_stub_sites_annotated_interior_hosted_in_pdata": len(stub_hosting_functions),
        "thunk_stub_interior_arithmetic_breaks": stub_interior_arithmetic_breaks,
        "rejected_raw_sites": rejected_rows,
    }


def audit_thunk_stub_cross_file(
    ledger: Ledger, xref: Mapping[str, Any], indirect: Mapping[str, Any]
) -> None:
    """The two evidence files must name the same hosting runtime function for the same stub RVA."""
    sites = indirect.get("thunk_stub_hosting_functions", {})
    ledger.equal(
        "xref.edges",
        "thunk_stub_hosting_thunk_function_agrees_with_indirect_sites",
        {},
        {
            rva: {"xref_edges": owner, "indirect_sites": sites.get(rva)}
            for rva, owner in sorted(xref.get("thunk_stub_hosting_functions", {}).items())
            if sites.get(rva) != owner
        },
    )


def audit_syscall_candidates(
    ledger: Ledger,
    image: StaticImage,
    facts: PdataFacts,
    path: Path,
) -> dict[str, Any]:
    group = "syscall.candidates"
    header, rows = stream_csv(path)
    index = {name: position for position, name in enumerate(header)}
    breaks: Counter[str] = Counter()
    tally: Counter[str] = Counter()
    row_count = 0
    previous_raw = -1
    rows_without_function_index = 0
    for row in rows:
        row_count += 1
        hit_index = int(row[index["hit_index"]])
        if hit_index != row_count - 1:
            breaks["hit_index_not_contiguous_0_based"] += 1
        raw_offset = int(row[index["raw_offset"]])
        rva = int(row[index["rva"]])
        if raw_offset <= previous_raw:
            breaks["raw_offset_not_ascending"] += 1
        previous_raw = raw_offset
        if (image.raw_of(rva) or -1) != raw_offset:
            breaks["raw_offset"] += 1
        if image.data[raw_offset:raw_offset + 2] != b"\x0f\x05":
            breaks["pattern_bytes"] += 1
        if row[index["bytes_hex"]] != "0F05" or row[index["bytes_ok"]] != "true":
            breaks["bytes_column"] += 1
        if row[index["raw_offset_hex"]] != hex_up(raw_offset) or row[index["rva_hex"]] != hex_up(rva):
            breaks["hex_columns"] += 1
        if row[index["va"]] != "" and int(row[index["va"]]) != rva + image.image_base:
            breaks["va_column"] += 1
        in_pdata = row[index["in_pdata"]] == "true"
        function_index = row[index["pdata_function_index"]]
        if not function_index:
            rows_without_function_index += 1
        if in_pdata != bool(function_index):
            breaks["in_pdata_flag"] += 1
        if function_index:
            owner = int(function_index)
            begin = facts.begins[owner]
            end = facts.ends[owner]
            if not begin <= rva < end:
                breaks["rva_outside_named_function"] += 1
            if row[index["pdata_function_start_rva_hex"]] != hex_up(begin):
                breaks["pdata_function_start"] += 1
            if row[index["pdata_function_end_rva_hex"]] != hex_up(end):
                breaks["pdata_function_end"] += 1
            if int(row[index["pdata_function_size"]]) != end - begin:
                breaks["pdata_function_size"] += 1
            if int(row[index["pdata_function_offset"]]) != rva - begin:
                breaks["pdata_function_offset"] += 1
            expected_boundary = (rva - begin) % 4 == 0
            if (row[index["pdata_word_boundary_ok"]] == "true") != expected_boundary:
                breaks["pdata_word_boundary"] += 1
        if (row[index["capstone_checked"]] == "true") != in_pdata:
            breaks["capstone_checked"] += 1
        disposition = row[index["capstone_candidate_disposition"]]
        valid = row[index["valid_candidate"]] == "true"
        false_positive = row[index["false_positive"]] == "true"
        boundary_ok = row[index["capstone_boundary_ok"]] == "true"
        if (row[index["false_positive_ok"]] == "true") != valid:
            breaks["false_positive_ok"] += 1
        if valid != boundary_ok:
            breaks["valid_candidate_vs_boundary"] += 1
        if false_positive == valid:
            breaks["false_positive_inverse"] += 1
        if disposition == "instruction_start" and not valid:
            breaks["disposition_start_without_valid"] += 1
        if disposition in ("covered_by_instruction", "no_pdata_function") and valid:
            breaks["disposition_nonstart_with_valid"] += 1
        tally["valid_candidate"] += int(valid)
        tally["false_positive"] += int(false_positive)
        tally["in_pdata"] += int(in_pdata)
        tally["capstone_boundary_ok"] += int(boundary_ok)
        tally["pdata_word_boundary_ok"] += int(row[index["pdata_word_boundary_ok"]] == "true")
        tally["disposition_" + disposition] += 1
    for name in SYSCALL_BREAKS:
        ledger.equal(group, name, 0, breaks[name])
    ledger.expect_documented(group, "syscall_raw_hits", row_count)
    ledger.equal(
        group,
        "valid_candidate_count",
        tally["valid_candidate"],
        tally["capstone_boundary_ok"],
    )
    ledger.equal(
        group,
        "valid_plus_false_positive_equals_rows",
        row_count,
        tally["valid_candidate"] + tally["false_positive"],
    )
    ledger.equal(
        group,
        "disposition_totals_equal_rows",
        row_count,
        tally["disposition_instruction_start"]
        + tally["disposition_covered_by_instruction"]
        + tally["disposition_no_pdata_function"],
    )
    ledger.equal(
        group,
        "valid_candidates_equal_instruction_start_dispositions",
        tally["disposition_instruction_start"],
        tally["valid_candidate"],
    )
    ledger.equal(
        group,
        "in_pdata_equals_disposition_not_no_pdata",
        tally["in_pdata"],
        row_count - tally["disposition_no_pdata_function"],
    )
    ledger.equal(
        group,
        "rows_without_pdata_function_have_empty_index",
        tally["disposition_no_pdata_function"],
        rows_without_function_index,
    )
    return {
        "rows": row_count,
        "valid_candidates": tally["valid_candidate"],
        "false_positives": tally["false_positive"],
        "inside_pdata_functions": tally["in_pdata"],
        "rows_without_pdata_function": rows_without_function_index,
        "pdata_word_boundary_ok": tally["pdata_word_boundary_ok"],
        "dispositions": {
            key[len("disposition_") :]: value
            for key, value in sorted(tally.items())
            if key.startswith("disposition_")
        },
    }


def pdata_recorded_digests(root: Path) -> dict[str, str]:
    """Digests pdata_stats.json records for the artifacts it and its producer produced."""
    stats = json.loads((root / "reverse/evidence/pdata_stats.json").read_text(encoding="utf-8"))
    return {
        "reverse/evidence/baseline.json": stats.get("producer", {}).get("baseline_sha256"),
        "reverse/evidence/pdata_functions.csv": stats.get("csv", {}).get("sha256"),
        PRODUCERS["pdata_map.py"]: stats.get("producer", {}).get("script_sha256"),
        SCRIPT_COMMON: stats.get("producer", {}).get("helper_sha256"),
    }


def audit_provenance(ledger: Ledger, root: Path, digests: Mapping[str, str]) -> dict[str, Any]:
    group = "provenance"
    recorded = pdata_recorded_digests(root)
    for relative, value in sorted(recorded.items()):
        present = isinstance(value, str) and len(value) == 64
        ledger.equal(group, f"digest_recorded_for[{relative}]", True, present)
        if present:
            ledger.equal(group, f"digest_matches_recorded[{relative}]", value, digests.get(relative))
    digests_not_recorded = [
        relative for relative in AUDITED_ARTIFACTS if relative not in recorded
    ]
    return {
        "digests": dict(sorted(digests.items())),
        "digests_recorded": dict(sorted(recorded.items())),
        "digests_not_recorded": digests_not_recorded,
        "digests_not_recorded_in": DIGEST_SOURCE_PDATA_STATS,
        "digests_not_recorded_note": (
            "this list is measured against pdata_stats.json alone, because that is the only producer "
            "that records an output digest. Whether an artifact is attested anywhere in the set, the "
            "toolchain digests block included, is decided by the toolchain.digests.digest_attested "
            "checks and the D-004 residual"
        ),
    }


def build_discrepancies(
    ledger: Ledger,
    contract: Mapping[str, Any],
    indirect: Mapping[str, Any],
    xref: Mapping[str, Any],
    provenance: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Re-derive the four standing findings against the schema the evidence set now carries.

    Every entry is emitted whether or not it still fails, and each carries the scope the
    finding is bounded to, so the register reads as four claims with a verdict rather than
    as a list that silently shrinks. A closed entry is one whose evidence checks all pass
    now and are re-checked on every run; a bounded_open entry is one whose evidence still
    fails and whose residual is quantified here.
    """
    entries: list[dict[str, Any]] = []
    scripts = contract["toolchain_scripts"]
    packages = contract["package_versions"]
    digests = contract["toolchain_digests"]
    known = {f"{check.group}.{check.name}": check.ok for check in ledger.checks}

    def add(
        identifier: str,
        status: str,
        severity: str,
        area: str,
        title: str,
        detail: str,
        evidence: Sequence[str],
        files: Sequence[str],
        bounded: Mapping[str, Any],
        root_cause_closed: bool,
    ) -> None:
        entries.append(
            {
                "id": identifier,
                "status": status,
                "root_cause_closed": root_cause_closed,
                "severity": severity,
                "area": area,
                "title": title,
                "detail": detail,
                "bounded": dict(bounded),
                "evidence_checks": list(evidence),
                "files": list(files),
            }
        )

    axis_values = packages.get("axis_values", {})
    disagreements = packages.get("disagreements", {})
    proofs = packages.get("disagreement_proofs", {})
    rendered = "; ".join(
        f"{name} " + " vs ".join(
            f"{axis}={axis_values.get(name, {}).get(axis)!r}" for axis in axes
        )
        + (f" decided by {proofs.get(name, {}).get(axes[0])}" if proofs.get(name) else "")
        for name, axes in sorted(disagreements.items())
    )
    add(
        "D-001",
        "closed" if packages.get("decidable") else "bounded_open",
        "medium",
        "toolchain",
        "library versions are recorded on independent axes and each disagreement is decidable",
        "toolchain.json no longer offers one collapsed version per library. The package_versions "
        "block versions every third-party package on the installed distribution metadata, the "
        "attribute the imported module exposes and the number the native engine reports, keeps the "
        "three side by side and never reconciles them, and the flat libraries block is checked "
        "against those axes instead of against itself. The earlier finding was that a reader could "
        "not tell which build produced the decoded evidence; that is now decidable per package. "
        f"Observed disagreements: {rendered or 'none'}. Each carries an assessment naming the "
        "mechanism and a machine checkable proof of it: a version composed from the binding "
        "constants is a literal in the package source, a version re exported from a compiled "
        "extension is a build stamp baked in at build time. The two axes resolve in opposite "
        "directions, which is why no single axis is declared authoritative. documented_claims "
        "attributes the version named in adhesive-03 and adhesive-12 to the imported_module axis "
        "and flags that it does not match the distribution version, and effect_on_evidence names "
        "either the importing producers or states that the divergence cannot have changed any "
        "decoded artifact. native_engine is never compared against a release string.",
        [
            "toolchain.package_versions.axes_are_never_reconciled",
            "toolchain.package_versions.every_package_is_versioned_on_all_axes",
            "toolchain.package_versions.only_the_two_release_axes_are_compared",
            "toolchain.package_versions.library_block_consistent_with_the_axes",
            "toolchain.package_versions.every_disagreement_carries_an_assessment",
            "toolchain.package_versions.every_disagreement_is_decidable_from_the_record",
            "toolchain.package_versions.every_disagreement_names_the_documented_axis",
            "toolchain.package_versions.documented_claim_flags_match_the_axis_values",
            "toolchain.package_versions.effect_on_evidence_stated_for_every_package",
            "toolchain.package_versions.undeclared_imports_are_disclosed",
        ],
        [
            "reverse/evidence/toolchain.json",
            "reverse/scripts/refresh_toolchain.py",
            "reverse/scripts/common.py",
            DOC03,
            DOC12,
        ],
        {
            "axis_values": axis_values,
            "disagreements": disagreements,
            "disagreement_proofs": proofs,
            "declared_without_producer_importer": packages.get(
                "declared_without_producer_importer", []
            ),
            "undeclared_imports": packages.get("undeclared_imports", []),
            "affects_decoded_counts": False,
        },
        True,
    )

    missing = list(scripts.get("missing_from_toolchain", ()))
    drift = dict(scripts.get("drift", {}))
    inventory_checks = [
        "toolchain.scripts.inventory_names",
        "toolchain.scripts.inventory_count",
        "toolchain.scripts.recorded_census_is_internally_consistent",
        *[f"toolchain.scripts.entry_present[{name}]" for name in missing],
        *[
            f"toolchain.scripts.{name}.{field}"
            for name, fields in sorted(drift.items())
            for field in fields
        ],
    ]
    attestation_checks = sorted(
        {
            "pdata.stats.producer.script_sha256",
            "pdata.stats.producer.helper_sha256",
            "pdata.stats.producer.baseline_sha256",
            *[
                f"provenance.digest_matches_recorded[{relative}]"
                for relative in provenance.get("digests_recorded", {})
            ],
            "toolchain.digests.entry_digests_recomputed",
            "toolchain.digests.cross_references_verified_independently",
            "toolchain.package_versions.imported_by_matches_the_inventory_census",
            "toolchain.package_versions.imported_by_matches_the_audit_census",
        }
    )
    stale_recorded = [
        name for name in attestation_checks if not known.get(name, False)
    ]
    d002_open = bool(missing or drift or stale_recorded)
    d002_intro = (
        "The root cause the earlier finding named is closed. toolchain.json now carries a "
        "script_inventory block that declares its root, glob, field set and the timestamps it "
        "deliberately omits, a sha256 for every producer under reverse/scripts including the ones that "
        "emitted the cfg, xref, indirect and syscall evidence, and a third_party_imports census per "
        "script that this audit re-derives from the script bytes with ast."
    )
    d002_detail = (
        d002_intro
        + (
            " What remains is that the stored payloads were not refreshed after the last producer "
            "edits, so every recorded digest in the set is pinned to an older revision than the file "
            f"on disk: {len(missing)} script is absent from the inventory, {len(drift)} recorded "
            "script entries have drifted, and the digests cross referenced out of pdata_stats.json and "
            "out of the toolchain digests block no longer reproduce. The package_versions importer "
            "lists inherit the same staleness for the packages the missing script imports. No decoded "
            "count depends on a script digest, so the residual is bounded to the attestation of the "
            "producer tree. Remediation is a single reverse/scripts/refresh_toolchain.py run followed "
            "by a pdata_map.py run, which is outside the read only scope of this audit."
            if d002_open
            else " The stored payloads have since been refreshed, so the inventory names all "
            f"{scripts.get('on_disk')} producers under reverse/scripts and every recorded size, line "
            "count, encoding flag and sha256 reproduces from the script bytes, the package_versions "
            "importer lists agree with the census this audit derives with ast, and the digests cross "
            "referenced out of pdata_stats.json and out of the toolchain digests block reproduce as "
            "well. The ordering constraint the digests block introduces is that it now hashes "
            "pdata_stats.json, so reverse/scripts/refresh_toolchain.py has to run after pdata_map.py; "
            "over an unchanged tree it rewrites nothing. No decoded count depends on a script digest, "
            "so the finding stays bounded to the attestation of the producer tree and every check "
            "behind it is re-run on each audit."
        )
    )
    add(
        "D-002",
        "bounded_open" if d002_open else "closed",
        "low",
        "toolchain",
        "producer digests are attested but the stored payloads are pinned to older revisions",
        d002_detail,
        [*inventory_checks, *attestation_checks],
        [
            "reverse/evidence/toolchain.json",
            "reverse/evidence/pdata_stats.json",
            "reverse/scripts/refresh_toolchain.py",
            *sorted({*missing, *drift}),
        ],
        {
            "missing_from_inventory": missing,
            "drifted_entries": drift,
            "stored_entries": scripts.get("stored"),
            "on_disk_entries": scripts.get("on_disk"),
            "attestation_checks": attestation_checks,
            "failing_attestation_checks": stale_recorded,
            "affects_decoded_counts": False,
        },
        True,
    )


    add(
        "D-003",
        "closed"
        if not (
            indirect.get("thunk_stub_sites_annotated_outside_but_inside_pdata")
            or indirect.get("thunk_stub_interior_arithmetic_breaks")
            or xref.get("thunk_stub_rows_covered_by_a_pdata_function")
        )
        else "bounded_open",
        "high",
        "xref",
        "import thunk stub rows no longer claim an owner their annotation denies",
        "The earlier finding was that all 355 raw scan stub rows carried "
        "import_thunk_stub_outside_every_pdata_runtime_function while sitting at RVAs a .pdata "
        "runtime function covers, so the annotation and the function columns of the same row "
        "contradicted each other. The producer now separates the two cases in the annotation and "
        "in the column names. The "
        f"{indirect.get('thunk_stub_sites_annotated_outside_pdata')} rows that really are outside "
        "every runtime function keep that claim and leave both function column groups empty, and "
        "the audit re-derives from .pdata that they are outside. The remaining "
        f"{indirect.get('thunk_stub_sites_annotated_interior')} rows are marker bytes in the "
        "interior of an already decoded seven byte jmp, so they carry "
        "import_thunk_stub_interior_byte_of_a_decoded_jmp_inside_a_pdata_function plus the byte "
        "offset, the instruction start and the covering first byte; the audit recomputes all "
        "three from the specimen bytes and recomputes the owning runtime function from .pdata. "
        "Those rows correctly leave code_instruction_function empty, because the marker byte is "
        "not an instruction start, and populate target_thunk_function with the runtime function "
        f"that hosts the jmp; {xref.get('thunk_stubs_hosted_inside_a_pdata_function')} xref_edges "
        "iat_jmp_thunk_stub rows name the same function for the same RVA, so the two evidence "
        "files now agree instead of contradicting each other. The 6 304 thunk mediated CALL xrefs "
        "and the 355 stub count are unchanged and remain equal to the doc 03 claims.",
        [
            "indirect.sites.thunk_stub_annotation_contradicted_by_own_function_columns",
            "indirect.sites.thunk_stub_rows_never_claim_a_code_instruction_function",
            "indirect.sites.thunk_stub_interior_rows_recompute_from_their_own_annotation",
            "indirect.sites.thunk_stub_interior_rows_name_their_hosting_thunk_function",
            "indirect.sites.code_instruction_function_columns_are_atomic",
            "indirect.sites.target_thunk_function_columns_are_atomic",
            "indirect.sites.target_thunk_function_index",
            "indirect.sites.target_thunk_function_range",
            "xref.edges.thunk_stub_rows_declare_no_code_instruction_function",
            "xref.edges.code_instruction_function_columns_are_atomic",
            "xref.edges.target_thunk_function_columns_are_atomic",
            "xref.edges.thunk_stub_rows_covered_by_a_pdata_function",
            "xref.edges.thunk_stub_hosting_thunk_function_covers_the_stub_byte",
            "xref.edges.target_thunk_function_index",
            "xref.edges.target_thunk_function_range",
            "xref.edges.thunk_stub_hosting_thunk_function_agrees_with_indirect_sites",
        ],
        [
            "reverse/evidence/indirect_sites.csv",
            "reverse/evidence/xref_edges.csv",
            "reverse/scripts/xref_build.py",
        ],
        {
            "stub_rows": indirect.get("thunk_stub_sites"),
            "annotated_outside_every_pdata_function": indirect.get(
                "thunk_stub_sites_annotated_outside_pdata"
            ),
            "annotated_interior_of_a_decoded_jmp": indirect.get("thunk_stub_sites_annotated_interior"),
            "interior_rows_hosted_in_a_pdata_function": indirect.get(
                "thunk_stub_sites_annotated_interior_hosted_in_pdata"
            ),
            "contradicted_rows": indirect.get("thunk_stub_sites_annotated_outside_but_inside_pdata"),
            "affects_decoded_counts": False,
        },
        True,
    )

    unattested = list(digests.get("unattested", ()))
    digest_entries = list(digests.get("entries", ()))
    toolchain_only = list(digests.get("attested_only_by_the_toolchain_block", ()))
    d004_detail = (
        "The rule the earlier finding lacked is now stated in the payload and independently verified "
        "here. toolchain.json carries a digests block that names the algorithm, records size and "
        f"sha256 for the {len(digest_entries)} files the rest of the set is built on and decoded from "
        f"({', '.join(digest_entries)}), lists each cross reference to the field that records the "
        "same digest elsewhere and marks whether it matches, and explains why the payload cannot "
        "contain its own digest and which script prints it. This audit recomputes every one of those "
        "digests from the file bytes and re-derives the cross referenced values out of "
        "pdata_stats.json rather than trusting the matches_recomputed flag, and it records which "
        f"record attests each artifact: {len(toolchain_only)} of them ({', '.join(toolchain_only)}) are "
        "attested by the toolchain block alone, because no producer of theirs records an output "
        "digest the way pdata_map.py does. The rule counts a digest recorded by the toolchain block as "
        "attestation on the same footing as one recorded by a producer. The earlier wording of the "
        "rule credited a producer recorded digest only, which is why these artifacts were reported as "
        "unattested even though the block the evidence set is read against already covered them. That "
        "is the refinement, and it is enforced rather than asserted in prose: every attested digest has "
        "to reproduce from the bytes, coverage of the audited artifact list is a check in its own right "
        "rather than an inference from an empty residual, and two cycle guards keep the block out of a "
        "fixed point it could never reach, one rejecting the payload as an attested target and one "
        "rejecting an attested artifact whose bytes carry the payload digest."
        + (
            f" What the rule still does not cover is the {len(unattested)} remaining artifacts "
            f"({', '.join(unattested)}): {len(unattested)} of the {len(AUDITED_ARTIFACTS)} audited "
            "artifacts have no recorded digest anywhere in the set, so drift in them cannot be detected "
            "against a stored value. The gap is bounded to attestation and changes no decoded count, "
            "and it stays open until the digests block covers the remaining artifacts or their "
            "producers record their own output digest the way pdata_map.py does."
            if unattested
            else f" {len(AUDITED_ARTIFACTS) - 1} of the {len(AUDITED_ARTIFACTS)} audited artifacts "
            "carry a recorded digest and the payload is the single exclusion, so nothing in the "
            "audited set is left without a stored value to detect drift against."
        )
    )
    add(
        "D-004",
        "bounded_open" if unattested else "closed",
        "low",
        "provenance",
        (
            "digest entry rule is enforced and covers every audited artifact"
            if not unattested
            else "digest entry rule is real and enforced, but its scope stops short of the csv producers"
        ),
        d004_detail,
        [
            "toolchain.digests.algorithm",
            "toolchain.digests.entry_digests_recomputed",
            "toolchain.digests.entries_exist_on_disk",
            "toolchain.digests.no_entry_attests_the_payload",
            "toolchain.digests.no_attested_artifact_records_the_payload_digest",
            "toolchain.digests.every_attested_digest_recomputes_from_the_bytes",
            "toolchain.digests.every_audited_artifact_is_attested",
            "toolchain.digests.cross_references_verified_independently",
            "toolchain.digests.self_digest_is_null",
            "toolchain.digests.self_path_is_the_payload",
            "toolchain.digests.self_exclusion_names_the_producer_that_prints_it",
            "toolchain.digests.self_exclusion_covers_the_payload",
            *[f"toolchain.digests.digest_attested[{relative}]" for relative in unattested],
        ],
        [
            "reverse/evidence/toolchain.json",
            "reverse/evidence/pdata_stats.json",
            *digest_entries,
            *unattested,
        ],
        {
            "attested_by_any_record": digests.get("attested_by_any_record", []),
            "attested_by": digests.get("attested_by", {}),
            "attested_only_by_the_toolchain_block": toolchain_only,
            "unattested": unattested,
            "self_excluded": digests.get("self_excluded"),
            "cross_references": digests.get("cross_references"),
            "rule": {
                "accepted_records": [DIGEST_SOURCE_PDATA_STATS, DIGEST_SOURCE_TOOLCHAIN],
                "cycle_guards": [
                    "toolchain.digests.no_entry_attests_the_payload",
                    "toolchain.digests.no_attested_artifact_records_the_payload_digest",
                ],
                "refined": (
                    "the residual used to be measured against producer recorded digests only, so a "
                    "toolchain level attestation did not close the finding and a digest only had to be "
                    "present to count. The source is now named per artifact, every recorded digest has "
                    "to reproduce from the bytes, and coverage of the audited artifact list is asserted "
                    "by a check rather than implied by an empty residual."
                ),
            },
            "affects_decoded_counts": False,
        },
        True,
    )

    failed = {name for name, ok in known.items() if not ok}
    open_entries = [entry for entry in entries if entry["status"] == "bounded_open"]
    closed_entries = [entry for entry in entries if entry["status"] == "closed"]
    attributed = {name for entry in open_entries for name in entry["evidence_checks"]}
    group = "discrepancy.integrity"
    ledger.equal(
        group,
        "every_evidence_check_resolves",
        [],
        sorted(
            {
                name
                for entry in entries
                for name in entry["evidence_checks"]
                if name not in known
            }
        ),
    )
    ledger.equal(
        group,
        "every_failing_check_is_attributed_to_an_open_discrepancy",
        [],
        sorted(failed - attributed),
    )
    ledger.equal(
        group,
        "open_discrepancies_have_at_least_one_failing_check",
        [],
        sorted(
            entry["id"]
            for entry in open_entries
            if not any(not known.get(name, False) for name in entry["evidence_checks"])
        ),
    )
    ledger.equal(
        group,
        "closed_discrepancies_have_no_failing_evidence_check",
        [],
        sorted(
            f"{entry['id']}.{name}"
            for entry in closed_entries
            for name in entry["evidence_checks"]
            if known.get(name, False) is False
        ),
    )
    ledger.equal(
        group,
        "register_holds_exactly_four_findings",
        4,
        len(entries),
    )
    return entries


def write_payload(path: Path, payload: Mapping[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False, allow_nan=False) + "\n"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def out_of_scope(root: Path, audited: Sequence[str]) -> list[str]:
    directory = root / EVIDENCE_DIR
    if not directory.is_dir():
        return []
    covered = set(audited) | {DEFAULT_OUTPUT}
    return sorted(
        path.relative_to(root).as_posix()
        for path in directory.iterdir()
        if path.is_file() and path.relative_to(root).as_posix() not in covered
    )


def build_payload(
    ledger: Ledger,
    files: Mapping[str, Any],
    specimen: Mapping[str, Any],
    documented: Mapping[str, Any],
    scope: Mapping[str, Any],
    provenance: Mapping[str, Any],
    discrepancies: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    failed = ledger.failures()
    return {
        "schema": SCHEMA,
        "audit": {
            "script": SCRIPT_RELATIVE,
            "script_sha256": sha256_file(Path(__file__).resolve()),
            "method": (
                "static file parsing only: the specimen is read as bytes and is never loaded, "
                "mapped as an image or executed, and the producer modules are never imported; "
                "their declared column orders and expected counts are read from source with ast"
            ),
            "read_only_targets": True,
            "determinism": {
                "json_indent": 2,
                "json_ensure_ascii": False,
                "json_sort_keys": False,
                "json_allow_nan": False,
                "text_encoding": "utf-8",
                "bom": False,
                "line_terminator": "\\n",
                "trailing_newline": True,
                "payload_timestamps": False,
                "payload_host_paths": False,
            },
        },
        "scope": dict(scope),
        "specimen": dict(specimen),
        "files": dict(files),
        "provenance": dict(provenance),
        "documented_claims": dict(documented),
        "summary": {
            "check_count": len(ledger.checks),
            "failed_count": len(failed),
            "verdict": "pass" if not failed else "fail",
            "by_group": ledger.group_summary(),
            "discrepancy_count": len(discrepancies),
            "discrepancy_open_count": sum(
                1 for entry in discrepancies if entry["status"] == "bounded_open"
            ),
            "discrepancy_status": {entry["id"]: entry["status"] for entry in discrepancies},
        },
        "failed_checks": [
            {"group": c.group, "check": c.name, "expected": c.expected, "actual": c.actual}
            for c in failed
        ],
        "checks": [
            {"group": c.group, "check": c.name, "expected": c.expected, "actual": c.actual, "ok": c.ok}
            for c in ledger.checks
        ],
        "discrepancies": list(discrepancies),
    }


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    default_root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description=(
            "Independent static audit of the adhesive.dll evidence set. The specimen is read as "
            "data and never executed, and no artifact other than the audit report is written."
        )
    )
    parser.add_argument("--root", type=Path, default=default_root)
    parser.add_argument("--specimen", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--max-report", type=int, default=40)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    specimen_path = (args.specimen or (root / "reverse" / "adhesive.dll")).resolve()
    output_path = (args.out or (root / DEFAULT_OUTPUT)).resolve()
    ledger = Ledger()
    constants = {
        name: module_constants(root / relative) for name, relative in sorted(PRODUCERS.items())
    }
    audited = AUDITED_ARTIFACTS
    digests = {
        relative: sha256_file(root / relative)
        for relative in sorted(set(audited) | set(PRODUCERS.values()))
        if (root / relative).is_file()
    }
    files: dict[str, Any] = {}
    files[SCRIPT_COMMON] = audit_text_artifact(ledger, "script.common", SCRIPT_COMMON, root / SCRIPT_COMMON)
    for relative in JSON_EVIDENCE:
        record = audit_text_artifact(ledger, "json.format", relative, root / relative)
        if relative != "reverse/evidence/toolchain.json":
            audit_no_host_dependence(ledger, "json.format", relative, record)
        files[relative] = record
    for relative in CSV_EVIDENCE:
        producer, constant = FIELD_SOURCES[relative]
        expected = constants[producer].get(constant)
        record = audit_text_artifact(
            ledger,
            "csv.format",
            relative,
            root / relative,
            expected if isinstance(expected, (list, tuple)) else None,
        )
        audit_no_host_dependence(ledger, "csv.format", relative, record)
        files[relative] = record
    baseline = json.loads((root / "reverse/evidence/baseline.json").read_text(encoding="utf-8"))
    toolchain = json.loads((root / "reverse/evidence/toolchain.json").read_text(encoding="utf-8"))
    pdata_stats = json.loads((root / "reverse/evidence/pdata_stats.json").read_text(encoding="utf-8"))
    image = StaticImage(specimen_path)
    records = image.runtime_functions()
    specimen = audit_specimen(ledger, root, image, baseline, toolchain, pdata_stats)
    contract = audit_script_contract(
        ledger, root, root / SCRIPT_COMMON, baseline, toolchain, constants, digests
    )
    facts = audit_pdata_csv(ledger, image, records, root / "reverse/evidence/pdata_functions.csv")
    pdata_summary = audit_pdata_stats(
        ledger,
        root,
        pdata_stats,
        facts,
        files["reverse/evidence/pdata_functions.csv"]["sha256"],
        files["reverse/evidence/pdata_functions.csv"]["header_columns"],
        baseline,
    )
    cfg_summary = audit_cfg(
        ledger,
        image,
        facts,
        root / "reverse/evidence/cfg_functions.csv",
        root / "reverse/evidence/cfg_clusters.csv",
    )
    xref_summary = audit_xref(ledger, image, facts, root / "reverse/evidence/xref_edges.csv")
    indirect_summary = audit_indirect_sites(
        ledger, image, facts, root / "reverse/evidence/indirect_sites.csv"
    )
    audit_thunk_stub_cross_file(ledger, xref_summary, indirect_summary)
    ledger.expect_documented(
        "xref.edges",
        "raw_ff15_candidates",
        xref_summary["direct_iat_call_xrefs"] + indirect_summary["rejected_raw_sites"],
    )
    syscall_summary = audit_syscall_candidates(
        ledger, image, facts, root / "reverse/evidence/syscall_candidates_raw.csv"
    )
    files["reverse/evidence/pdata_stats.json"]["observed"] = pdata_summary
    files["reverse/evidence/pdata_functions.csv"]["observed"] = {
        "row_count": facts.rows,
        "unique_unwind_info": len(facts.unwind_addresses),
        "unwind_flag_value_distribution": {str(v): facts.flags[v] for v in sorted(facts.flags)},
        "covered_bytes": facts.covered_bytes,
    }
    files["reverse/evidence/cfg_functions.csv"]["observed"] = cfg_summary
    files["reverse/evidence/cfg_clusters.csv"]["observed"] = cfg_summary
    files["reverse/evidence/xref_edges.csv"]["observed"] = xref_summary
    files["reverse/evidence/indirect_sites.csv"]["observed"] = indirect_summary
    files["reverse/evidence/syscall_candidates_raw.csv"]["observed"] = syscall_summary
    provenance = audit_provenance(ledger, root, digests)
    documented: dict[str, Any] = {}
    for key, (source, claim, origin) in DOCUMENTED.items():
        check = next((c for c in ledger.checks if c.name.endswith(f"[{key}]")), None)
        documented[key] = {
            "source": f"{source} ({origin})",
            "claimed": claim,
            "observed": None if check is None else check.actual,
            "check": None if check is None else f"{check.group}.{check.name}",
            "ok": None if check is None else check.ok,
        }
    scope = {
        "audited": [*audited, "reverse/adhesive.dll"],
        "out_of_scope": out_of_scope(root, audited),
        "method": "read only, static, specimen never executed",
    }
    discrepancies = build_discrepancies(
        ledger,
        contract,
        indirect_summary,
        xref_summary,
        provenance,
    )
    payload = build_payload(
        ledger, files, specimen, documented, scope, provenance, discrepancies
    )
    write_payload(output_path, payload)
    summary = payload["summary"]
    print(f"root      {root}")
    print(f"specimen  {specimen['path']} size={specimen['size']} sha256={specimen['sha256']}")
    print(f"checks    {summary['check_count'] - summary['failed_count']}/{summary['check_count']} passed")
    for group, stats in summary["by_group"].items():
        print(f"  {group:22s} {stats['checks'] - stats['failed']:5d}/{stats['checks']:<5d}")
    for entry in discrepancies:
        print(
            f"DISCREPANCY {entry['id']} [{entry['status']}/{entry['severity']}] {entry['title']}"
        )
    for check in ledger.failures()[: args.max_report]:
        print(f"FAIL {check.group}.{check.name}: expected={check.expected!r} actual={check.actual!r}")
    remaining = len(ledger.failures()) - args.max_report
    if remaining > 0:
        print(f"FAIL ... {remaining} further mismatches")
    print(f"report    {_display(root, output_path)}")
    return 1 if summary["failed_count"] else 0


def _display(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


if __name__ == "__main__":
    raise SystemExit(main())


