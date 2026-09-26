"""Unresolved-region audit over the cfg/pdata evidence set (P0/S1).

Joins reverse/evidence/cfg_functions.csv with reverse/evidence/pdata_functions.csv,
re-derives the exact byte ranges the CFG pass could not resolve, classifies every
residue as code, data or unknown, and emits a triage-ordered region table.

Static file parsing only: the specimen is read as bytes and never loaded, mapped or
executed. Outputs are deterministic - fixed family order, fixed column order, sorted
region order, rounded floats, no timestamps - so repeated runs on unchanged inputs
produce byte-identical artifacts.

Detection families, in audit severity order:

  data_record        a pdata range whose bytes are a table, not a code body
  undecoded_range    an exact byte run no pass of the CFG builder could decode
  switch_unvalidated a jump-table candidate the builder refused to trust
  boundary_cross     a basic block that ran into EndAddress with no terminator
  linear_only_blocks blocks that only the linear sweep found, never an edge
  multi_entry        a range reachable from more than one entry point
  pdata_gap          bytes inside .text that no IMAGE_RUNTIME_FUNCTION covers
"""

from __future__ import annotations

import argparse
import bisect
import csv
import struct
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Iterator, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cfg_build  # noqa: E402  (the path shim above is load-bearing)
import common  # noqa: E402

from capstone import CS_ARCH_X86, CS_MODE_64, Cs  # noqa: E402

SCHEMA: Final[str] = "adhesive-dumper.unresolved-regions/1"

FAMILY_DATA_RECORD: Final[str] = "data_record"
FAMILY_UNDECODED: Final[str] = "undecoded_range"
FAMILY_SWITCH: Final[str] = "switch_unvalidated"
FAMILY_BOUNDARY: Final[str] = "boundary_cross"
FAMILY_LINEAR_ONLY: Final[str] = "linear_only_blocks"
FAMILY_MULTI_ENTRY: Final[str] = "multi_entry"
FAMILY_PDATA_GAP: Final[str] = "pdata_gap"

FAMILY_ORDER: Final[tuple[str, ...]] = (
    FAMILY_DATA_RECORD,
    FAMILY_UNDECODED,
    FAMILY_SWITCH,
    FAMILY_BOUNDARY,
    FAMILY_LINEAR_ONLY,
    FAMILY_MULTI_ENTRY,
    FAMILY_PDATA_GAP,
)
FAMILY_RANK: Final[Mapping[str, int]] = {name: index for index, name in enumerate(FAMILY_ORDER)}

FUNCTION_FAMILIES: Final[tuple[str, ...]] = tuple(
    name for name in FAMILY_ORDER if name != FAMILY_PDATA_GAP
)

KIND_CODE: Final[str] = "code"
KIND_DATA: Final[str] = "data"
KIND_UNKNOWN: Final[str] = "unknown"
KINDS: Final[tuple[str, ...]] = (KIND_CODE, KIND_DATA, KIND_UNKNOWN)

TRIAGE_UNRESOLVED: Final[str] = "unresolved"
TRIAGE_CLASSIFIED: Final[str] = "classified"
TRIAGE_BENIGN: Final[str] = "benign_padding"
TRIAGES: Final[tuple[str, ...]] = (TRIAGE_UNRESOLVED, TRIAGE_CLASSIFIED, TRIAGE_BENIGN)

PRIORITY_TAGS: Final[tuple[str, ...]] = ("security", "syscall", "patch", "lifecycle", "coverage")
PRIORITY_RANK: Final[Mapping[str, int]] = {tag: index for index, tag in enumerate(PRIORITY_TAGS)}
PRIORITY_LEVELS: Final[Mapping[str, str]] = {
    "security": "P0",
    "syscall": "P1",
    "patch": "P2",
    "lifecycle": "P3",
    "coverage": "P4",
}
PRIORITY_VALUES: Final[tuple[str, ...]] = ("P0", "P1", "P2", "P3", "P4")

CONFIDENCE_HIGH: Final[str] = "HIGH"
CONFIDENCE_MEDIUM: Final[str] = "MEDIUM"
CONFIDENCE_LOW: Final[str] = "LOW"
CONFIDENCES: Final[tuple[str, ...]] = (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW)

# Byte level classification thresholds. A range is data only when it carries no
# control-flow terminator at all, most of its words are in-image RVAs or small
# table bytes, and a straight linear sweep cannot follow it.
TABLE_DWORD_RATIO: Final[float] = 0.45
TABLE_DWORD_STRONG: Final[float] = 0.90
SMALL_BYTE_RATIO: Final[float] = 0.60
DATA_LINEAR_MAX: Final[float] = 0.85
CODE_LINEAR_MIN: Final[float] = 0.80
CODE_LINEAR_STRONG: Final[float] = 0.95
RATIO_DIGITS: Final[int] = 6
PAD_BYTES: Final[frozenset[int]] = frozenset({0x00, 0x90, 0xCC})
REDECODE_MAX_SIZE: Final[int] = 0x10000
HEX_SAMPLE_BYTES: Final[int] = 8
DETAIL_GAP_LIMIT: Final[int] = 1000
EVIDENCE_SYMBOL_CAP: Final[int] = 4
CODE_SECTION: Final[str] = ".text"
IAT_SYMBOL_CSV_CAP: Final[int] = 8

CONTENT_INT3_PAD: Final[str] = "int3_pad"
CONTENT_ZERO_PAD: Final[str] = "zero_pad"
CONTENT_NOP_PAD: Final[str] = "nop_pad"
CONTENT_MIXED_PAD: Final[str] = "mixed_pad"
CONTENT_BODY: Final[str] = "body"
CONTENT_KINDS: Final[tuple[str, ...]] = (
    CONTENT_INT3_PAD,
    CONTENT_ZERO_PAD,
    CONTENT_NOP_PAD,
    CONTENT_MIXED_PAD,
    CONTENT_BODY,
)

GAP_LEADING: Final[str] = "gap_leading"
GAP_INTERIOR: Final[str] = "gap_interior"
GAP_TRAILING: Final[str] = "gap_trailing"

SECURITY_CORE_IAT: Final[frozenset[str]] = frozenset(
    {
        "ADVAPI32.dll!RegGetValueW",
        "CFGMGR32.dll!CM_Get_Device_Interface_ListW",
        "CFGMGR32.dll!CM_Get_Device_Interface_List_SizeW",
        "IPHLPAPI.DLL!GetAdaptersInfo",
        "KERNEL32.dll!CloseHandle",
        "KERNEL32.dll!ConvertFiberToThread",
        "KERNEL32.dll!ConvertThreadToFiber",
        "KERNEL32.dll!CopyFileW",
        "KERNEL32.dll!CreateFileMappingW",
        "KERNEL32.dll!CreateFileW",
        "KERNEL32.dll!CreateFiber",
        "KERNEL32.dll!CreateWaitableTimerW",
        "KERNEL32.dll!DeleteFileW",
        "KERNEL32.dll!DeleteFiber",
        "KERNEL32.dll!ExitProcess",
        "KERNEL32.dll!FindFirstFileW",
        "KERNEL32.dll!FindNextFileW",
        "KERNEL32.dll!FlushInstructionCache",
        "KERNEL32.dll!FreeLibrary",
        "KERNEL32.dll!GetCommandLineW",
        "KERNEL32.dll!GetCurrentProcess",
        "KERNEL32.dll!GetCurrentProcessId",
        "KERNEL32.dll!GetCurrentThread",
        "KERNEL32.dll!GetCurrentThreadId",
        "KERNEL32.dll!GetEnvironmentVariableA",
        "KERNEL32.dll!GetEnvironmentVariableW",
        "KERNEL32.dll!GetFileAttributesExW",
        "KERNEL32.dll!GetFileAttributesW",
        "KERNEL32.dll!GetModuleFileNameW",
        "KERNEL32.dll!GetModuleHandleA",
        "KERNEL32.dll!GetModuleHandleExW",
        "KERNEL32.dll!GetModuleHandleW",
        "KERNEL32.dll!GetNativeSystemInfo",
        "KERNEL32.dll!GetPrivateProfileIntW",
        "KERNEL32.dll!GetPrivateProfileStringW",
        "KERNEL32.dll!GetProcAddress",
        "KERNEL32.dll!GetProcessAffinityMask",
        "KERNEL32.dll!GetProcessHeap",
        "KERNEL32.dll!GetProcessWorkingSetSize",
        "KERNEL32.dll!GetSystemDirectoryW",
        "KERNEL32.dll!GetSystemInfo",
        "KERNEL32.dll!GetThreadContext",
        "KERNEL32.dll!HeapCreate",
        "KERNEL32.dll!IsDebuggerPresent",
        "KERNEL32.dll!LoadLibraryA",
        "KERNEL32.dll!LoadLibraryExA",
        "KERNEL32.dll!LoadLibraryW",
        "KERNEL32.dll!MapViewOfFile",
        "KERNEL32.dll!MoveFileExW",
        "KERNEL32.dll!OpenProcess",
        "KERNEL32.dll!OpenThread",
        "KERNEL32.dll!OutputDebugStringA",
        "KERNEL32.dll!QueueUserAPC",
        "KERNEL32.dll!RaiseException",
        "KERNEL32.dll!ResumeThread",
        "KERNEL32.dll!RtlCaptureContext",
        "KERNEL32.dll!RtlLookupFunctionEntry",
        "KERNEL32.dll!RtlVirtualUnwind",
        "KERNEL32.dll!SetThreadContext",
        "KERNEL32.dll!SetUnhandledExceptionFilter",
        "KERNEL32.dll!SetWaitableTimer",
        "KERNEL32.dll!Sleep",
        "KERNEL32.dll!SleepEx",
        "KERNEL32.dll!SwitchToFiber",
        "KERNEL32.dll!TerminateProcess",
        "KERNEL32.dll!TerminateThread",
        "KERNEL32.dll!UnhandledExceptionFilter",
        "KERNEL32.dll!UnmapViewOfFile",
        "KERNEL32.dll!VerifyVersionInfoW",
        "KERNEL32.dll!VirtualAlloc",
        "KERNEL32.dll!VirtualFree",
        "KERNEL32.dll!VirtualLock",
        "KERNEL32.dll!VirtualProtect",
        "KERNEL32.dll!VirtualQuery",
        "KERNEL32.dll!VirtualUnlock",
        "KERNEL32.dll!WriteFile",
        "ole32.dll!CoTaskMemFree",
    }
)

SECURITY_TRUST_IAT: Final[frozenset[str]] = frozenset(
    {
        "CRYPT32.dll!CertCloseStore",
        "CRYPT32.dll!CertEnumCertificatesInStore",
        "CRYPT32.dll!CertFindCertificateInStore",
        "CRYPT32.dll!CertFreeCertificateContext",
        "CRYPT32.dll!CertGetEnhancedKeyUsage",
        "CRYPT32.dll!CertGetIntendedKeyUsage",
        "CRYPT32.dll!CertGetNameStringW",
        "CRYPT32.dll!CertOpenSystemStoreA",
        "CRYPT32.dll!CertOpenSystemStoreW",
        "CRYPT32.dll!CryptMsgGetParam",
        "CRYPT32.dll!CryptQueryObject",
    }
)

SECURITY_NET_IAT: Final[frozenset[str]] = frozenset(
    {
        "WS2_32.dll!WSAEventSelect",
        "WS2_32.dll!WSAIoctl",
        "WS2_32.dll!WSARecv",
        "WS2_32.dll!WSARecvFrom",
        "WS2_32.dll!WSASend",
        "WS2_32.dll!WSASendTo",
        "WS2_32.dll!WSASocketW",
        "WS2_32.dll!WSAStartup",
        "WS2_32.dll!accept",
        "WS2_32.dll!bind",
        "WS2_32.dll!closesocket",
        "WS2_32.dll!connect",
        "WS2_32.dll!getaddrinfo",
        "WS2_32.dll!getnameinfo",
        "WS2_32.dll!ioctlsocket",
        "WS2_32.dll!recv",
        "WS2_32.dll!select",
        "WS2_32.dll!send",
        "WS2_32.dll!shutdown",
        "WS2_32.dll!socket",
    }
)

SECURITY_IAT: Final[frozenset[str]] = (
    SECURITY_CORE_IAT | SECURITY_TRUST_IAT | SECURITY_NET_IAT
)

LIFECYCLE_IAT: Final[frozenset[str]] = frozenset(
    {
        "ADVAPI32.dll!DeregisterEventSource",
        "ADVAPI32.dll!RegisterEventSourceW",
        "KERNEL32.dll!CreateFiber",
        "KERNEL32.dll!ConvertFiberToThread",
        "KERNEL32.dll!ConvertThreadToFiber",
        "KERNEL32.dll!DeleteFiber",
        "KERNEL32.dll!DisableThreadLibraryCalls",
        "KERNEL32.dll!ExitProcess",
        "KERNEL32.dll!FreeLibrary",
        "KERNEL32.dll!GetModuleFileNameW",
        "KERNEL32.dll!GetModuleHandleA",
        "KERNEL32.dll!GetModuleHandleExW",
        "KERNEL32.dll!GetModuleHandleW",
        "KERNEL32.dll!InitOnceBeginInitialize",
        "KERNEL32.dll!InitOnceComplete",
        "KERNEL32.dll!SetUnhandledExceptionFilter",
        "KERNEL32.dll!SwitchToFiber",
        "KERNEL32.dll!TerminateProcess",
        "KERNEL32.dll!TlsAlloc",
        "KERNEL32.dll!TlsFree",
        "KERNEL32.dll!TlsGetValue",
        "KERNEL32.dll!TlsSetValue",
        "KERNEL32.dll!UnhandledExceptionFilter",
        "USER32.dll!RegisterSuspendResumeNotification",
    }
)

SECURITY_ANCHORS: Final[frozenset[str]] = frozenset(
    {
        "allocation_call_site",
        "handle_dispatch_site",
        "handle_forward_wrapper",
        "nop_write_helper",
        "open_process_argument_site",
        "protection_constant_setup",
        "read_wrapper",
        "registry_root_constant",
        "toolhelp_stub",
        "write_wrapper",
    }
)
SYSCALL_ANCHORS: Final[frozenset[str]] = frozenset({"direct_syscall_site"})
PATCH_ANCHORS: Final[frozenset[str]] = frozenset({"patcher_entry"})

# Most alarming first. A candidate whose table exists but whose targets are broken is
# far more interesting than one the builder simply could not bound.
SWITCH_REJECT_SEVERITY: Final[tuple[str, ...]] = (
    "TARGET_NOT_INSTRUCTION_START",
    "TARGET_OUT_OF_FUNCTION",
    "TABLE_UNMAPPED",
    "UNSUPPORTED_ENTRY_SIZE",
    "NO_BOUND",
    "NO_TABLE_BASE",
    "NO_INDEX_REGISTER",
    "TOO_FEW_DISTINCT_TARGETS",
)

PATCH_CROSS_REFERENCES: Final[tuple[str, ...]] = (
    "patch_mechanisms_1e270.csv",
    "patch_mechanisms_helpers.csv",
)
PATCH_RVA_COLUMNS: Final[frozenset[str]] = frozenset(
    {"rva", "site_rva", "caller_rvas", "readers", "writers"}
)

# The range named in the audit brief. Pinned so its presence and verdict are asserted.
PINNED_BEGINS: Final[tuple[int, ...]] = (0x2B4D640,)

CSV_COLUMNS: Final[tuple[str, ...]] = (
    "region_id",
    "family",
    "reason",
    "triage",
    "kind",
    "begin_rva",
    "begin_rva_hex",
    "end_rva",
    "end_rva_hex",
    "size",
    "raw",
    "raw_hex",
    "section",
    "fn_index",
    "fn",
    "fn_next_index",
    "fn_next",
    "priority",
    "priority_tags",
    "ok",
    "confidence",
    "content",
    "dword_rva_ratio",
    "small_byte_ratio",
    "linear_ratio",
    "linear_decoded_bytes",
    "first_fail_rva_hex",
    "prefix_pad_bytes",
    "suffix_pad_bytes",
    "code_terminators",
    "decoded_bytes",
    "undecoded_bytes",
    "reached_ratio",
    "unwind_flags",
    "doc_anchor",
    "cluster_id",
    "evidence",
)

COLUMN_NOTES: Final[Mapping[str, str]] = {
    "region_id": "UR-000001 style ordinal, assigned after the fixed sort, 1-based",
    "fn": "bordering pdata record as <record_index>:<begin_hex>-<end_hex>, the owner",
    "fn_next": "for a pdata_gap the record that follows the gap, same encoding as fn",
    "triage": "unresolved | classified | benign_padding",
    "ok": "true when the audit fully accounted for the region, false when a residual is left",
    "confidence": "HIGH / MEDIUM / LOW, first match of method.confidence_rules",
    "kind": "code | data | unknown, first match of method.kind_rules",
    "content": f"body shape: {', '.join(CONTENT_KINDS)}",
    "dword_rva_ratio": (
        "share of 4-byte words of the non-pad core that point inside the image, "
        "either as a pre-relocation RVA or as a VA"
    ),
    "small_byte_ratio": "share of non-pad core bytes below 0x10",
    "linear_ratio": "share of the non-pad core a straight linear sweep decoded contiguously",
    "linear_decoded_bytes": "bytes the linear sweep consumed before it stopped",
    "first_fail_rva_hex": "where the linear sweep stopped inside the core, empty if it did not",
    "prefix_pad_bytes": "leading core bytes that are alignment padding only",
    "suffix_pad_bytes": "trailing core bytes that are alignment padding only",
    "doc_anchor": "documented anchors of the owner, as recorded by cfg_build",
    "evidence": (
        "semicolon separated key=value facts that have no dedicated column: the block "
        "terminator and instruction site histograms, the entry-point and overlap inputs, "
        "the full switch reject reason set, and the owner attribution used for priority"
    ),
}

KIND_RULES: Final[tuple[str, ...]] = (
    "1. data    terminators == 0 and dword_rva_ratio >= "
    f"{TABLE_DWORD_RATIO} and linear_ratio < {DATA_LINEAR_MAX}",
    "2. data    terminators == 0 and small_byte_ratio >= "
    f"{SMALL_BYTE_RATIO} and linear_ratio < {DATA_LINEAR_MAX}",
    "3. code    terminators >= 1 and linear_ratio >= " f"{CODE_LINEAR_MIN}",
    f"4. code    linear_ratio >= {CODE_LINEAR_STRONG}, terminator or not",
    "5. unknown everything else, including pure inter-function alignment padding",
)

OK_RULES: Final[tuple[str, ...]] = (
    "true  benign_padding: the bytes are inter-function alignment padding and nothing else",
    "true  data_record: the pdata range is proven to be a table, so its code coverage "
    "question is answered even though the metadata is wrong",
    "true  multi_entry with kind code or data: a pure entry-point count, nothing left to decode",
    "false every other family, and every region whose kind stayed unknown",
)

CONFIDENCE_RULES: Final[tuple[str, ...]] = (
    "1. HIGH   data_record, undecoded_range, switch_unvalidated, boundary_cross and "
    "multi_entry: the verdict is a counted field of the cfg builder, an exact re-decode, "
    "or a byte rule confirmed by independent signals",
    "2. HIGH   pdata_gap whose core is empty, or whose dword_rva_ratio >= "
    f"{TABLE_DWORD_STRONG} with linear_ratio < {DATA_LINEAR_MAX}",
    "3. MEDIUM pdata_gap whose core is attributed to code, or that stays unknown after a "
    "partial linear sweep",
    "4. MEDIUM linear_only_blocks: aggregate counters only, sub ranges not re-decoded",
    "5. LOW    owner larger than the re-decode cap, owner bytes not fully file backed, "
    "or a non-gap region whose kind stayed unknown",
)


@dataclass(frozen=True, slots=True)
class Function:
    """The subset of one cfg_functions.csv row the audit needs."""

    index: int
    begin: int
    end: int
    size: int
    raw: int
    section: str
    unwind_flags: str
    overlap_role: str
    overlap_partners: int
    entry_internal: int
    entry_external_calls: int
    entry_external_jumps: int
    basic_blocks: int
    blocks_reached: int
    blocks_linear_only: int
    instructions: int
    reached_ratio: float
    decoded_bytes: int
    undecoded_bytes: int
    undecoded_regions: int
    term_call: int
    term_jmp_direct: int
    term_jmp_indirect: int
    term_jcc: int
    term_return: int
    term_trap: int
    term_invalid: int
    term_range_end: int
    exit_range_end: int
    switch_sites: int
    switch_validated: int
    switch_rejected: int
    switch_reject_reasons: str
    indirect_jumps: int
    indirect_unresolved: int
    ret_sites: int
    ud2_sites: int
    int3_sites: int
    trap_sites: int
    syscall_sites: int
    iat_symbols: str
    iat_symbol_count: int
    doc_anchors: str
    cluster_id: int
    decode_status: str

    @property
    def terminators(self) -> int:
        return self.ret_sites + self.term_call + self.term_jmp_direct + self.term_jmp_indirect

    @property
    def symbols(self) -> frozenset[str]:
        return frozenset(item for item in self.iat_symbols.split(";") if item)

    @property
    def anchors(self) -> frozenset[str]:
        return frozenset(
            item.partition(":")[2] for item in self.doc_anchors.split(";") if item
        )

    @property
    def entry_points(self) -> int:
        return self.entry_external_calls + self.entry_external_jumps + (
            1 if self.entry_internal else 0
        )

    @property
    def label(self) -> str:
        return f"{self.index}:{common.hexs(self.begin)}-{common.hexs(self.end)}"

    def is_undecoded(self) -> bool:
        return self.undecoded_bytes > 0

    def is_switch_unvalidated(self) -> bool:
        return self.switch_rejected > 0

    def is_boundary_cross(self) -> bool:
        return self.term_range_end > 0 or self.exit_range_end > 0

    def is_linear_only(self) -> bool:
        return self.blocks_linear_only > 0

    def is_multi_entry(self) -> bool:
        return (
            self.entry_points > 1
            or self.overlap_role != "sole"
            or self.overlap_partners > 0
        )

    def is_unreachable(self) -> bool:
        return self.reached_ratio == 0.0

    def is_overlapped(self) -> bool:
        return self.overlap_role != "sole" or self.overlap_partners > 0

    def families(self) -> tuple[str, ...]:
        """Structure families; undecoded_range is decided in function_families."""
        marks = []
        if self.is_switch_unvalidated():
            marks.append(FAMILY_SWITCH)
        if self.is_boundary_cross():
            marks.append(FAMILY_BOUNDARY)
        if self.is_linear_only():
            marks.append(FAMILY_LINEAR_ONLY)
        if self.is_multi_entry():
            marks.append(FAMILY_MULTI_ENTRY)
        return tuple(marks)


@dataclass(frozen=True, slots=True)
class Pdata:
    """One IMAGE_RUNTIME_FUNCTION as stored in pdata_functions.csv."""

    record_index: int
    begin: int
    end: int
    code_size: int
    gap_before: int


@dataclass(frozen=True, slots=True)
class Measurements:
    """Byte level verdict for one range, computed once and reused by the families."""

    kind: str
    content: str
    dword_rva_ratio: float
    small_byte_ratio: float
    linear_ratio: float
    linear_decoded_bytes: int
    first_fail_rva: int
    prefix_pad: int
    suffix_pad: int
    core_size: int
    mapped: bool


@dataclass(frozen=True, slots=True)
class Region:
    """One unresolved or explained byte range, ready to be emitted."""

    family: str
    reason: str
    triage: str
    kind: str
    begin: int
    end: int
    raw: int | None
    section: str
    fn_index: int
    fn_label: str
    fn_next_index: int
    fn_next_label: str
    tags: tuple[str, ...]
    priority: str
    ok: bool
    confidence: str
    content: str
    dword_rva_ratio: float
    small_byte_ratio: float
    linear_ratio: float
    linear_decoded_bytes: int
    first_fail_rva: int
    prefix_pad: int
    suffix_pad: int
    terminators: int
    decoded_bytes: int
    undecoded_bytes: int
    reached_ratio: float
    unwind_flags: str
    doc_anchor: str
    cluster_id: int
    evidence: str

    @property
    def size(self) -> int:
        return self.end - self.begin

    def sort_key(self) -> tuple[int, int, int, int, str]:
        return (
            PRIORITY_RANK[self.tags[0]],
            FAMILY_RANK[self.family],
            self.begin,
            self.end,
            self.reason,
        )


def _as_int(row: Mapping[str, str], name: str) -> int:
    value = row.get(name) or ""
    return int(value) if value else 0


def _as_float(row: Mapping[str, str], name: str) -> float:
    value = row.get(name) or ""
    return float(value) if value else 0.0


def _round(value: float) -> float:
    return round(value, RATIO_DIGITS)


def load_functions(path: Path) -> list[Function]:
    """Parse cfg_functions.csv into the compact per-record shape the audit needs."""
    functions: list[Function] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            functions.append(
                Function(
                    index=_as_int(row, "func_index"),
                    begin=_as_int(row, "begin_rva"),
                    end=_as_int(row, "end_rva"),
                    size=_as_int(row, "size"),
                    raw=_as_int(row, "raw"),
                    section=row["section"],
                    unwind_flags=row["unwind_flags"],
                    overlap_role=row["overlap_role"],
                    overlap_partners=_as_int(row, "overlap_partners"),
                    entry_internal=_as_int(row, "entry_internal"),
                    entry_external_calls=_as_int(row, "entry_external_calls"),
                    entry_external_jumps=_as_int(row, "entry_external_jumps"),
                    basic_blocks=_as_int(row, "basic_blocks"),
                    blocks_reached=_as_int(row, "blocks_reached"),
                    blocks_linear_only=_as_int(row, "blocks_linear_only"),
                    instructions=_as_int(row, "instructions"),
                    reached_ratio=_as_float(row, "reached_ratio"),
                    decoded_bytes=_as_int(row, "decoded_bytes"),
                    undecoded_bytes=_as_int(row, "undecoded_bytes"),
                    undecoded_regions=_as_int(row, "undecoded_regions"),
                    term_call=_as_int(row, "term_call"),
                    term_jmp_direct=_as_int(row, "term_jmp_direct"),
                    term_jmp_indirect=_as_int(row, "term_jmp_indirect"),
                    term_jcc=_as_int(row, "term_jcc"),
                    term_return=_as_int(row, "term_return"),
                    term_trap=_as_int(row, "term_trap"),
                    term_invalid=_as_int(row, "term_invalid"),
                    term_range_end=_as_int(row, "term_range_end"),
                    exit_range_end=_as_int(row, "exit_range_end"),
                    switch_sites=_as_int(row, "switch_sites"),
                    switch_validated=_as_int(row, "switch_sites_validated"),
                    switch_rejected=_as_int(row, "switch_sites_rejected"),
                    switch_reject_reasons=row["switch_reject_reasons"],
                    indirect_jumps=_as_int(row, "indirect_jumps"),
                    indirect_unresolved=_as_int(row, "indirect_jumps_unresolved"),
                    ret_sites=_as_int(row, "ret_sites"),
                    ud2_sites=_as_int(row, "ud2_sites"),
                    int3_sites=_as_int(row, "int3_sites"),
                    trap_sites=_as_int(row, "trap_sites"),
                    syscall_sites=_as_int(row, "syscall_sites"),
                    iat_symbols=row["iat_symbols"],
                    iat_symbol_count=_as_int(row, "iat_symbol_count"),
                    doc_anchors=row["doc_anchors"],
                    cluster_id=_as_int(row, "cluster_id"),
                    decode_status=row["decode_status"],
                )
            )
    return functions


def load_pdata(path: Path) -> list[Pdata]:
    """Parse pdata_functions.csv into the exception-directory record shape."""
    records: list[Pdata] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            records.append(
                Pdata(
                    record_index=_as_int(row, "record_index"),
                    begin=_as_int(row, "begin_address"),
                    end=_as_int(row, "end_address"),
                    code_size=_as_int(row, "code_size"),
                    gap_before=_as_int(row, "gap_before"),
                )
            )
    return records


def _parse_rva_field(value: str) -> tuple[int, ...]:
    values: list[int] = []
    for part in value.split("|"):
        token = part.strip()
        if not token:
            continue
        try:
            values.append(int(token, 16) if token.lower().startswith("0x") else int(token))
        except ValueError:
            continue
    return tuple(values)


def load_patch_rvas(evidence_dir: Path) -> dict[str, tuple[int, ...]]:
    """Optional cross reference: every RVA the patch audit already attributes."""
    found: dict[str, tuple[int, ...]] = {}
    for name in PATCH_CROSS_REFERENCES:
        path = evidence_dir / name
        if not path.is_file():
            continue
        rvas: set[int] = set()
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            columns = {name.lower() for name in (reader.fieldnames or ())}
            usable = sorted(PATCH_RVA_COLUMNS & columns)
            for row in reader:
                for column in usable:
                    rvas.update(_parse_rva_field(row.get(column) or ""))
        found[name] = tuple(sorted(rvas))
    return found


def _pad_run(data: bytes, start: int, step: int) -> int:
    count = 0
    index = start
    while 0 <= index < len(data) and data[index] in PAD_BYTES:
        count += 1
        index += step
    return count


def _pad_kind(data: bytes) -> str:
    distinct = set(data)
    if distinct <= {0xCC}:
        return CONTENT_INT3_PAD
    if distinct <= {0x00}:
        return CONTENT_ZERO_PAD
    if distinct <= {0x90}:
        return CONTENT_NOP_PAD
    return CONTENT_MIXED_PAD


def _in_image(value: int, image_base: int, size_of_image: int) -> bool:
    """True for a word that points inside the image, as a pre-relocation RVA or a VA."""
    if value <= 0:
        return False
    return value < size_of_image or image_base <= value < image_base + size_of_image


def _dword_rva_ratio(data: bytes, image_base: int, size_of_image: int) -> float:
    total = len(data) // 4
    if total == 0:
        return 0.0
    hits = 0
    for offset in range(0, total * 4, 4):
        if _in_image(struct.unpack_from("<I", data, offset)[0], image_base, size_of_image):
            hits += 1
    return _round(hits / total)


def _small_byte_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return _round(sum(1 for value in data if value < 0x10) / len(data))


def classify(terminators: int, dword: float, small: float, linear: float) -> str:
    """Ordered code / data / unknown verdict, mirrored in KIND_RULES."""
    if terminators == 0 and linear < DATA_LINEAR_MAX:
        if dword >= TABLE_DWORD_RATIO or small >= SMALL_BYTE_RATIO:
            return KIND_DATA
    if terminators >= 1 and linear >= CODE_LINEAR_MIN:
        return KIND_CODE
    if linear >= CODE_LINEAR_STRONG:
        return KIND_CODE
    return KIND_UNKNOWN


class Prober:
    """Byte level classifier over the file-backed part of the executable section."""

    def __init__(self, pe: Any, blob: bytes, section_name: str) -> None:
        self.pe = pe
        self._md = Cs(CS_ARCH_X86, CS_MODE_64)
        self._md.detail = False
        self._md.skipdata = False
        base = int(pe.OPTIONAL_HEADER.ImageBase)
        self._image_base = base
        self._size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)
        matches = [
            item
            for item in common.sections(pe)
            if item.name == section_name and item.raw_size
        ]
        if not matches:
            raise SystemExit(f"section {section_name} is absent from the specimen")
        section = matches[0]
        self.start = section.virtual_address
        self.end = section.virtual_address + section.raw_size
        self._data = blob[section.raw_pointer : section.raw_pointer + section.raw_size]
        self._cache: dict[tuple[int, int, int], Measurements] = {}

    def span(self, begin: int, end: int) -> tuple[bytes, bool]:
        """Return the file backed bytes of [begin, end) and whether all are present."""
        size = end - begin
        if size <= 0:
            return b"", False
        offset = begin - self.start
        if offset < 0 or offset >= len(self._data):
            return b"", False
        data = self._data[offset : offset + size]
        return data, len(data) == size

    def core_ratios(self, begin: int, end: int) -> tuple[float, float]:
        """Dword and small-byte ratios of a range's non-pad core, no classification."""
        data, _ = self.span(begin, end)
        if not data:
            return 0.0, 0.0
        core = data[_pad_run(data, 0, 1) : len(data) - _pad_run(data, len(data), -1)]
        return (
            _dword_rva_ratio(core, self._image_base, self._size_of_image),
            _small_byte_ratio(core),
        )

    def measure(self, begin: int, end: int, terminators: int) -> Measurements:
        """Classify one range as code, data or unknown from its own bytes."""
        key = (begin, end, terminators)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        data, mapped = self.span(begin, end)
        if not data:
            empty = Measurements(
                kind=KIND_UNKNOWN,
                content=CONTENT_BODY,
                dword_rva_ratio=0.0,
                small_byte_ratio=0.0,
                linear_ratio=0.0,
                linear_decoded_bytes=0,
                first_fail_rva=0,
                prefix_pad=0,
                suffix_pad=0,
                core_size=0,
                mapped=mapped,
            )
            self._cache[key] = empty
            return empty
        prefix = _pad_run(data, 0, 1)
        suffix = _pad_run(data, len(data), -1)
        core = data[prefix : len(data) - suffix]
        if not core:
            result = Measurements(
                kind=KIND_UNKNOWN,
                content=_pad_kind(data),
                dword_rva_ratio=0.0,
                small_byte_ratio=0.0,
                linear_ratio=0.0,
                linear_decoded_bytes=0,
                first_fail_rva=0,
                prefix_pad=prefix,
                suffix_pad=suffix,
                core_size=0,
                mapped=mapped,
            )
            self._cache[key] = result
            return result
        decoded = 0
        for insn in self._md.disasm(core, begin + prefix):
            decoded += insn.size
        dword = _dword_rva_ratio(core, self._image_base, self._size_of_image)
        small = _small_byte_ratio(core)
        linear = _round(decoded / len(core))
        result = Measurements(
            kind=classify(terminators, dword, small, linear),
            content=CONTENT_BODY,
            dword_rva_ratio=dword,
            small_byte_ratio=small,
            linear_ratio=linear,
            linear_decoded_bytes=decoded,
            first_fail_rva=begin + prefix + decoded if decoded < len(core) else 0,
            prefix_pad=prefix,
            suffix_pad=suffix,
            core_size=len(core),
            mapped=mapped,
        )
        self._cache[key] = result
        return result


class ReDecoder:
    """Re-runs the cfg builder on flagged functions to recover exact sub-ranges."""

    def __init__(self, pe: Any, blob: bytes) -> None:
        self._image = cfg_build.build_raw_image(pe, blob)
        self._iat = cfg_build.build_iat_slots(pe)
        base = int(pe.OPTIONAL_HEADER.ImageBase)
        self._base = base
        self._end = base + int(pe.OPTIONAL_HEADER.SizeOfImage)
        self._md = Cs(CS_ARCH_X86, CS_MODE_64)
        self._md.detail = True
        self._index = {
            record[0]: (position, record)
            for position, record in enumerate(cfg_build.parse_runtime_functions(pe))
        }

    def analyse(self, begin: int, end: int) -> tuple[Any, bytes]:
        """Return the rebuilt stats and the raw per-byte decode coverage map."""
        position, record = self._index[begin]
        builder = cfg_build.FunctionBuilder(
            self._image, self._md, self._iat, {}, self._base, self._end
        )
        stats = builder.analyse(
            position,
            begin,
            end,
            record[2],
            self._image.section_at(begin),
            self._image.raw_offset(begin),
        )
        return stats, bytes(builder._covered)


def undecoded_runs(covered: bytes, begin: int) -> list[tuple[int, int]]:
    """Maximal byte runs inside a function that no pass of the builder decoded."""
    runs: list[tuple[int, int]] = []
    offset = 0
    total = len(covered)
    while offset < total:
        if covered[offset]:
            offset += 1
            continue
        limit = offset
        while limit < total and not covered[limit]:
            limit += 1
        runs.append((begin + offset, begin + limit))
        offset = limit
    return runs


def _contains_any(begin: int, end: int, needles: Sequence[int]) -> bool:
    if not needles:
        return False
    position = bisect.bisect_right(needles, begin - 1)
    return position < len(needles) and needles[position] < end


def priority_for(
    owners: Sequence[Function],
    patch_rvas: Sequence[int],
    lifecycle_rvas: Sequence[int],
) -> tuple[str, ...]:
    """Tags a region, in priority order, with what it is attached to."""
    tags: set[str] = set()
    for owner in owners:
        if owner.symbols & SECURITY_IAT or owner.anchors & SECURITY_ANCHORS:
            tags.add("security")
        if owner.syscall_sites > 0 or owner.anchors & SYSCALL_ANCHORS:
            tags.add("syscall")
        if owner.anchors & PATCH_ANCHORS or _contains_any(
            owner.begin, owner.end, patch_rvas
        ):
            tags.add("patch")
        if owner.symbols & LIFECYCLE_IAT or _contains_any(
            owner.begin, owner.end, lifecycle_rvas
        ):
            tags.add("lifecycle")
    tags.add("coverage")
    return tuple(tag for tag in PRIORITY_TAGS if tag in tags)


def confidence_for(
    family: str,
    kind: str,
    measurements: Measurements,
    degraded: bool,
) -> str:
    """First matching entry of CONFIDENCE_RULES, evaluated in order."""
    if family in {
        FAMILY_DATA_RECORD,
        FAMILY_UNDECODED,
        FAMILY_SWITCH,
        FAMILY_BOUNDARY,
        FAMILY_MULTI_ENTRY,
    }:
        level = CONFIDENCE_HIGH
    elif family == FAMILY_PDATA_GAP and (
        measurements.content != CONTENT_BODY
        or (
            measurements.dword_rva_ratio >= TABLE_DWORD_STRONG
            and measurements.linear_ratio < DATA_LINEAR_MAX
        )
    ):
        level = CONFIDENCE_HIGH
    else:
        level = CONFIDENCE_MEDIUM
    if degraded or not measurements.mapped:
        level = CONFIDENCE_LOW
    elif kind == KIND_UNKNOWN and family != FAMILY_PDATA_GAP:
        level = CONFIDENCE_LOW
    return level


def triage_for(family: str, kind: str, measurements: Measurements) -> str:
    if family == FAMILY_PDATA_GAP and measurements.content != CONTENT_BODY:
        return TRIAGE_BENIGN
    if family in {FAMILY_DATA_RECORD, FAMILY_MULTI_ENTRY} and kind in {
        KIND_CODE,
        KIND_DATA,
    }:
        return TRIAGE_CLASSIFIED
    return TRIAGE_UNRESOLVED


def ok_for(family: str, kind: str, measurements: Measurements) -> bool:
    if family == FAMILY_PDATA_GAP and measurements.content != CONTENT_BODY:
        return True
    if family == FAMILY_DATA_RECORD and kind == KIND_DATA:
        return True
    if family == FAMILY_MULTI_ENTRY and kind in {KIND_CODE, KIND_DATA}:
        return True
    return False


def _reason_for(function: Function, family: str) -> str:
    if family == FAMILY_DATA_RECORD:
        return "pdata_range_is_data"
    if family == FAMILY_SWITCH:
        return f"switch_rejected:{primary_reject_reason(function.switch_reject_reasons)}"
    if family == FAMILY_BOUNDARY:
        return "range_end_terminator"
    if family == FAMILY_LINEAR_ONLY:
        return (
            "unreachable_block_set" if function.is_unreachable() else "linear_sweep_only_blocks"
        )
    return "pdata_overlap" if function.is_overlapped() else "multi_entry_point"


def primary_reject_reason(reasons: str) -> str:
    """Highest ranked reject reason present, ranked by SWITCH_REJECT_SEVERITY."""
    names = {item.partition("=")[0] for item in reasons.split(";") if item}
    if not names:
        return "UNSPECIFIED"
    for candidate in SWITCH_REJECT_SEVERITY:
        if candidate in names:
            return candidate
    return sorted(names)[0]


def function_evidence(function: Function, measurements: Measurements) -> str:
    symbols = sorted(function.symbols & (SECURITY_IAT | LIFECYCLE_IAT))
    terms = ",".join(
        (
            f"call:{function.term_call}",
            f"jmp_direct:{function.term_jmp_direct}",
            f"jmp_indirect:{function.term_jmp_indirect}",
            f"jcc:{function.term_jcc}",
            f"return:{function.term_return}",
            f"trap:{function.term_trap}",
            f"invalid:{function.term_invalid}",
            f"range_end:{function.term_range_end}",
        )
    )
    sites = ",".join(
        (
            f"ret:{function.ret_sites}",
            f"ud2:{function.ud2_sites}",
            f"int3:{function.int3_sites}",
            f"trap:{function.trap_sites}",
            f"syscall:{function.syscall_sites}",
            f"ijmp:{function.indirect_jumps}",
            f"ijmp_unresolved:{function.indirect_unresolved}",
        )
    )
    return ";".join(
        (
            f"term={terms}",
            f"sites={sites}",
            f"exit_range_end={function.exit_range_end}",
            f"switch_reject_reasons={function.switch_reject_reasons or 'none'}",
            f"entry_points={function.entry_points}",
            f"ext_calls={function.entry_external_calls}",
            f"ext_jumps={function.entry_external_jumps}",
            f"int_entries={function.entry_internal}",
            f"overlap_role={function.overlap_role}",
            f"overlap_partners={function.overlap_partners}",
            f"core={measurements.core_size}",
            f"decode_status={function.decode_status}",
            f"iat={';'.join(symbols[:EVIDENCE_SYMBOL_CAP]) or 'none'}",
            f"iat_symbol_count={function.iat_symbol_count}",
        )
    )


def function_region(
    function: Function,
    family: str,
    prober: Prober,
    measurements: Measurements,
    tags: tuple[str, ...],
) -> Region:
    kind = measurements.kind
    return Region(
        family=family,
        reason=_reason_for(function, family),
        triage=triage_for(family, kind, measurements),
        kind=kind,
        begin=function.begin,
        end=function.end,
        raw=function.raw if function.raw >= 0 else None,
        section=function.section,
        fn_index=function.index,
        fn_label=function.label,
        fn_next_index=function.index,
        fn_next_label=function.label,
        tags=tags,
        priority=PRIORITY_LEVELS[tags[0]],
        ok=ok_for(family, kind, measurements),
        confidence=confidence_for(family, kind, measurements, function.size > REDECODE_MAX_SIZE),
        content=measurements.content,
        dword_rva_ratio=measurements.dword_rva_ratio,
        small_byte_ratio=measurements.small_byte_ratio,
        linear_ratio=measurements.linear_ratio,
        linear_decoded_bytes=measurements.linear_decoded_bytes,
        first_fail_rva=measurements.first_fail_rva,
        prefix_pad=measurements.prefix_pad,
        suffix_pad=measurements.suffix_pad,
        terminators=function.terminators,
        decoded_bytes=function.decoded_bytes,
        undecoded_bytes=function.undecoded_bytes,
        reached_ratio=_round(function.reached_ratio),
        unwind_flags=function.unwind_flags,
        doc_anchor=function.doc_anchors,
        cluster_id=function.cluster_id,
        evidence=function_evidence(function, measurements),
    )


def undecoded_region(
    function: Function,
    run_begin: int,
    run_end: int,
    prober: Prober,
    measurements: tuple[float, float],
    tags: tuple[str, ...],
) -> Region:
    data, _ = prober.span(run_begin, run_end)
    return Region(
        family=FAMILY_UNDECODED,
        reason="undecoded_run",
        triage=TRIAGE_UNRESOLVED,
        kind=KIND_UNKNOWN,
        begin=run_begin,
        end=run_end,
        raw=common.rva_to_raw(prober.pe, run_begin),
        section=function.section,
        fn_index=function.index,
        fn_label=function.label,
        fn_next_index=function.index,
        fn_next_label=function.label,
        tags=tags,
        priority=PRIORITY_LEVELS[tags[0]],
        ok=False,
        confidence=CONFIDENCE_HIGH,
        content=CONTENT_BODY,
        dword_rva_ratio=measurements[0],
        small_byte_ratio=measurements[1],
        linear_ratio=0.0,
        linear_decoded_bytes=0,
        first_fail_rva=run_begin,
        prefix_pad=0,
        suffix_pad=0,
        terminators=function.terminators,
        decoded_bytes=function.decoded_bytes,
        undecoded_bytes=function.undecoded_bytes,
        reached_ratio=_round(function.reached_ratio),
        unwind_flags=function.unwind_flags,
        doc_anchor=function.doc_anchors,
        cluster_id=function.cluster_id,
        evidence=";".join(
            (
                f"bytes={data[:HEX_SAMPLE_BYTES].hex(' ')}",
                "source=cfg_build.FunctionBuilder coverage map",
                f"owner_undecoded_runs={function.undecoded_regions}",
                f"owner_invalid_term={function.term_invalid}",
                f"owner_range_end_term={function.term_range_end}",
                f"owner_unwind={function.unwind_flags or 'none'}",
            )
        ),
    )


def redecode_check(function: Function, stats: Any) -> common.Check:
    pairs = (
        ("decoded_bytes", stats.decoded_bytes),
        ("undecoded_bytes", stats.undecoded_bytes),
        ("undecoded_regions", stats.undecoded_regions),
        ("basic_blocks", stats.basic_blocks),
        ("blocks_reached", stats.blocks_reached),
        ("blocks_linear_only", stats.blocks_linear_only),
        ("instructions", stats.instructions),
    )
    mismatches = [
        f"{name}={getattr(function, name)}!={value}"
        for name, value in pairs
        if getattr(function, name) != value
    ]
    return common.Check(
        name=f"redecode.func_{function.index}_{common.hexs(function.begin)}",
        expected="cfg_functions.csv counters reproduced",
        actual=";".join(mismatches) if mismatches else "match",
        ok=not mismatches,
    )


def function_families(
    functions: Sequence[Function],
    prober: Prober,
    redecoder: ReDecoder,
    patch_rvas: Sequence[int],
    lifecycle_rvas: Sequence[int],
) -> tuple[list[Region], list[common.Check], dict[str, int]]:
    """One region per function level family, plus exact undecoded sub-ranges."""
    regions: list[Region] = []
    checks: list[common.Check] = []
    counters: Counter[str] = Counter()

    for function in functions:
        marks = function.families()
        if not marks and not function.is_undecoded():
            continue
        measurements = prober.measure(function.begin, function.end, function.terminators)
        tags = priority_for((function,), patch_rvas, lifecycle_rvas)
        if function.is_undecoded() and function.size <= REDECODE_MAX_SIZE:
            stats, covered = redecoder.analyse(function.begin, function.end)
            checks.append(redecode_check(function, stats))
            counters["redecoded_functions"] += 1
            for run_begin, run_end in undecoded_runs(covered, function.begin):
                regions.append(
                    undecoded_region(
                        function,
                        run_begin,
                        run_end,
                        prober,
                        prober.core_ratios(run_begin, run_end),
                        tags,
                    )
                )
                counters["undecoded_runs"] += 1
        elif function.is_undecoded():
            counters["oversize_undecoded_functions"] += 1
            regions.append(function_region(function, FAMILY_UNDECODED, prober, measurements, tags))
        for mark in marks:
            regions.append(function_region(function, mark, prober, measurements, tags))
            counters[mark] += 1
    return regions, checks, dict(counters)


def data_record_families(
    functions: Sequence[Function],
    prober: Prober,
    patch_rvas: Sequence[int],
    lifecycle_rvas: Sequence[int],
) -> list[Region]:
    """Every pdata range whose own bytes are a table rather than a code body."""
    regions: list[Region] = []
    for function in functions:
        if function.terminators:
            continue
        measurements = prober.measure(function.begin, function.end, 0)
        if measurements.kind != KIND_DATA:
            continue
        tags = priority_for((function,), patch_rvas, lifecycle_rvas)
        regions.append(
            function_region(function, FAMILY_DATA_RECORD, prober, measurements, tags)
        )
    return regions


def gap_families(
    records: Sequence[Pdata],
    functions: Sequence[Function],
    code_begin: int,
    code_end: int,
    prober: Prober,
    patch_rvas: Sequence[int],
    lifecycle_rvas: Sequence[int],
) -> tuple[list[Region], dict[str, int]]:
    """Every run of section bytes no IMAGE_RUNTIME_FUNCTION covers, plus both edges."""
    by_begin = {item.begin: item for item in functions}
    holes: list[tuple[int, int, Function | None, Function | None, str]] = []
    cursor = code_begin
    previous: Function | None = None
    for record in records:
        if record.begin > cursor:
            reason = GAP_LEADING if previous is None else GAP_INTERIOR
            holes.append((cursor, record.begin, previous, by_begin.get(record.begin), reason))
        previous = by_begin.get(record.begin)
        cursor = record.end
    if previous is not None and cursor < code_end:
        holes.append((cursor, code_end, previous, None, GAP_TRAILING))

    regions: list[Region] = []
    stats: Counter[str] = Counter()
    for begin, end, before, after, reason in holes:
        owner = before or after
        if owner is None:
            continue
        extra = after if before is not None else None
        owners = [item for item in (owner, extra) if item is not None]
        measurements = prober.measure(begin, end, 0)
        tags = priority_for(owners, patch_rvas, lifecycle_rvas)
        symbols = sorted(owner.symbols & (SECURITY_IAT | LIFECYCLE_IAT))
        regions.append(
            Region(
                family=FAMILY_PDATA_GAP,
                reason=reason,
                triage=triage_for(FAMILY_PDATA_GAP, measurements.kind, measurements),
                kind=measurements.kind,
                begin=begin,
                end=end,
                raw=common.rva_to_raw(prober.pe, begin),
                section=owner.section,
                fn_index=owner.index,
                fn_label=owner.label,
                fn_next_index=extra.index if extra is not None else owner.index,
                fn_next_label=extra.label if extra is not None else owner.label,
                tags=tags,
                priority=PRIORITY_LEVELS[tags[0]],
                ok=ok_for(FAMILY_PDATA_GAP, measurements.kind, measurements),
                confidence=confidence_for(
                    FAMILY_PDATA_GAP, measurements.kind, measurements, owner.size > REDECODE_MAX_SIZE
                ),
                content=measurements.content,
                dword_rva_ratio=measurements.dword_rva_ratio,
                small_byte_ratio=measurements.small_byte_ratio,
                linear_ratio=measurements.linear_ratio,
                linear_decoded_bytes=measurements.linear_decoded_bytes,
                first_fail_rva=measurements.first_fail_rva,
                prefix_pad=measurements.prefix_pad,
                suffix_pad=measurements.suffix_pad,
                terminators=0,
                decoded_bytes=0,
                undecoded_bytes=0,
                reached_ratio=0.0,
                unwind_flags=owner.unwind_flags,
                doc_anchor=owner.doc_anchors,
                cluster_id=owner.cluster_id,
                evidence=";".join(
                    (
                        "covered_by_pdata=false",
                        f"core={measurements.core_size}",
                        f"owner_syscall_sites={owner.syscall_sites}",
                        f"owner_iat={';'.join(symbols[:EVIDENCE_SYMBOL_CAP]) or 'none'}",
                        f"owner_iat_truncated={owner.iat_symbol_count >= IAT_SYMBOL_CSV_CAP}",
                        f"owner_anchors={owner.doc_anchors or 'none'}",
                        f"owner_unwind={owner.unwind_flags or 'none'}",
                    )
                ),
            )
        )
        stats[measurements.content] += 1
        stats["bytes"] += end - begin
        if reason != GAP_INTERIOR:
            stats[reason] += 1
    return regions, dict(stats)


def region_row(region_id: str, region: Region) -> dict[str, Any]:
    return {
        "region_id": region_id,
        "family": region.family,
        "reason": region.reason,
        "triage": region.triage,
        "kind": region.kind,
        "begin_rva": region.begin,
        "begin_rva_hex": common.hexs(region.begin),
        "end_rva": region.end,
        "end_rva_hex": common.hexs(region.end),
        "size": region.size,
        "raw": region.raw if region.raw is not None else "",
        "raw_hex": common.hexs(region.raw) if region.raw is not None else "",
        "section": region.section,
        "fn_index": region.fn_index,
        "fn": region.fn_label,
        "fn_next_index": region.fn_next_index,
        "fn_next": region.fn_next_label,
        "priority": region.priority,
        "priority_tags": ";".join(region.tags),
        "ok": region.ok,
        "confidence": region.confidence,
        "content": region.content,
        "dword_rva_ratio": region.dword_rva_ratio,
        "small_byte_ratio": region.small_byte_ratio,
        "linear_ratio": region.linear_ratio,
        "linear_decoded_bytes": region.linear_decoded_bytes,
        "first_fail_rva_hex": common.hexs(region.first_fail_rva) if region.first_fail_rva else "",
        "prefix_pad_bytes": region.prefix_pad,
        "suffix_pad_bytes": region.suffix_pad,
        "code_terminators": region.terminators,
        "decoded_bytes": region.decoded_bytes,
        "undecoded_bytes": region.undecoded_bytes,
        "reached_ratio": region.reached_ratio,
        "unwind_flags": region.unwind_flags,
        "doc_anchor": region.doc_anchor,
        "cluster_id": region.cluster_id,
        "evidence": region.evidence,
    }


def iter_region_rows(regions: Sequence[Region]) -> Iterator[dict[str, Any]]:
    for position, region in enumerate(regions, start=1):
        yield region_row(f"UR-{position:06d}", region)


def region_detail(region_id: str, region: Region) -> dict[str, Any]:
    return {
        "region_id": region_id,
        "family": region.family,
        "reason": region.reason,
        "triage": region.triage,
        "kind": region.kind,
        "begin_rva": region.begin,
        "begin_rva_hex": common.hexs(region.begin),
        "end_rva": region.end,
        "end_rva_hex": common.hexs(region.end),
        "size": region.size,
        "raw": region.raw,
        "raw_hex": common.hexs(region.raw) if region.raw is not None else None,
        "section": region.section,
        "fn": region.fn_label,
        "fn_next": region.fn_next_label,
        "priority": region.priority,
        "priority_tags": list(region.tags),
        "ok": region.ok,
        "confidence": region.confidence,
        "content": region.content,
        "dword_rva_ratio": region.dword_rva_ratio,
        "small_byte_ratio": region.small_byte_ratio,
        "linear_ratio": region.linear_ratio,
        "code_terminators": region.terminators,
        "decoded_bytes": region.decoded_bytes,
        "undecoded_bytes": region.undecoded_bytes,
        "reached_ratio": region.reached_ratio,
        "unwind_flags": region.unwind_flags,
        "cluster_id": region.cluster_id,
        "evidence": region.evidence,
    }


def summarise_families(regions: Sequence[Region]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for family in FAMILY_ORDER:
        members = [item for item in regions if item.family == family]
        if not members:
            continue
        total = sum(item.size for item in members)
        summary[family] = {
            "regions": len(members),
            "bytes": total,
            "bytes_hex": common.hexs(total),
            "resolved": sum(1 for item in members if item.ok),
            "unresolved": sum(1 for item in members if not item.ok),
            "unique_ranges": len({(item.begin, item.end) for item in members}),
            "by_kind": {kind: sum(1 for item in members if item.kind == kind) for kind in KINDS},
            "by_triage": {
                triage: sum(1 for item in members if item.triage == triage) for triage in TRIAGES
            },
            "by_priority": {
                level: sum(1 for item in members if item.priority == level)
                for level in PRIORITY_VALUES
            },
            "by_confidence": {
                level: sum(1 for item in members if item.confidence == level)
                for level in CONFIDENCES
            },
        }
    return summary


def tls_callback_rvas(pe: Any, image_base: int) -> list[int]:
    directory = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if directory is None:
        return []
    callback_rva = int(directory.struct.AddressOfCallBacks) - image_base
    found: list[int] = []
    for slot in range(256):
        raw = common.read_rva(pe, callback_rva + slot * 8, 8)
        if len(raw) < 8:
            break
        value = struct.unpack("<Q", raw)[0]
        if value == 0:
            break
        found.append(value - image_base)
    return found


def build_report(
    root: Path,
    script: Path,
    specimen: Path,
    cfg_path: Path,
    pdata_path: Path,
    csv_path: Path,
    json_path: Path,
    detail_gap_limit: int,
) -> tuple[dict[str, Any], list[common.Check]]:
    def relative(path: Path) -> str:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            return path.as_posix()

    blob = specimen.read_bytes()
    pe = common.load_pe(specimen)
    try:
        code_section = next(
            (item for item in common.sections(pe) if item.name == CODE_SECTION), None
        )
        if code_section is None or not code_section.raw_size:
            raise SystemExit(f"{CODE_SECTION} is absent from {specimen}")
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)
        entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        export_rvas = sorted(
            int(symbol["rva"]) for symbol in common.export_summary(pe)["symbols"]
        )
        tls_rvas = sorted(tls_callback_rvas(pe, image_base))
        prober = Prober(pe, blob, CODE_SECTION)
        redecoder = ReDecoder(pe, blob)
    finally:
        pe.close()

    functions = load_functions(cfg_path)
    records = load_pdata(pdata_path)
    patch_by_file = load_patch_rvas(cfg_path.parent)
    patch_rvas = tuple(sorted({value for values in patch_by_file.values() for value in values}))
    lifecycle_rvas = tuple(sorted({entry_rva, *export_rvas, *tls_rvas}))

    data_regions = data_record_families(functions, prober, patch_rvas, lifecycle_rvas)
    function_regions, redecode_checks, counters = function_families(
        functions, prober, redecoder, patch_rvas, lifecycle_rvas
    )
    gap_regions, gap_stats = gap_families(
        records,
        functions,
        code_section.virtual_address,
        code_section.virtual_address + code_section.raw_size,
        prober,
        patch_rvas,
        lifecycle_rvas,
    )
    code_begin = code_section.virtual_address
    code_end = code_begin + code_section.raw_size

    regions = sorted(
        data_regions + function_regions + gap_regions, key=lambda item: item.sort_key()
    )
    ids = [f"UR-{position:06d}" for position in range(1, len(regions) + 1)]
    pinned: list[dict[str, Any]] = []
    for region_id, region in zip(ids, regions):
        if region.family != FAMILY_DATA_RECORD:
            continue
        if any(region.begin <= value < region.end for value in PINNED_BEGINS):
            pinned.append(region_detail(region_id, region))

    common.write_csv(csv_path, iter_region_rows(regions), CSV_COLUMNS)

    checks: list[common.Check] = list(redecode_checks)
    checks.extend(
        _structural_checks(
            functions, records, regions, gap_stats, pinned, code_begin, code_end
        )
    )

    priority_regions: Counter[str] = Counter()
    priority_bytes: Counter[str] = Counter()
    for region in regions:
        for tag in region.tags:
            priority_regions[tag] += 1
            priority_bytes[tag] += region.size
    capped_iat = sum(1 for item in functions if item.iat_symbol_count >= IAT_SYMBOL_CSV_CAP)
    capped_flagged = sum(
        1
        for item in functions
        if item.iat_symbol_count >= IAT_SYMBOL_CSV_CAP
        and (item.families() or item.is_unreachable())
    )
    gap_only = [item for item in regions if item.family == FAMILY_PDATA_GAP]
    embedded: list[dict[str, Any]] = []
    gap_embedded = 0
    for region_id, region in zip(ids, regions):
        if region.family == FAMILY_PDATA_GAP:
            if gap_embedded < detail_gap_limit:
                embedded.append(region_detail(region_id, region))
                gap_embedded += 1
            continue
        embedded.append(region_detail(region_id, region))

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "producer": {
            "script": relative(script),
            "script_sha256": common.sha256_file(script),
            "helpers": {
                relative(script.parent / "common.py"): common.sha256_file(
                    script.parent / "common.py"
                ),
                relative(script.parent / "cfg_build.py"): common.sha256_file(
                    script.parent / "cfg_build.py"
                ),
            },
        },
        "specimen": {
            "path": relative(specimen),
            "name": specimen.name,
            "size": specimen.stat().st_size,
            "sha256": common.sha256_file(specimen),
            "image_base": image_base,
            "image_base_hex": common.hexs(image_base),
            "size_of_image": size_of_image,
            "size_of_image_hex": common.hexs(size_of_image),
            "code_section": CODE_SECTION,
            "code_section_virtual_address": code_section.virtual_address,
            "code_section_virtual_address_hex": common.hexs(code_section.virtual_address),
            "code_section_raw_size": code_section.raw_size,
            "code_section_raw_size_hex": common.hexs(code_section.raw_size),
            "loaded": False,
            "executed": False,
            "note": "read as a byte slice through the section table; never mapped or run",
        },
        "inputs": {
            "cfg_functions.csv": {
                "path": relative(cfg_path),
                "size": cfg_path.stat().st_size,
                "sha256": common.sha256_file(cfg_path),
                "row_count": len(functions),
            },
            "pdata_functions.csv": {
                "path": relative(pdata_path),
                "size": pdata_path.stat().st_size,
                "sha256": common.sha256_file(pdata_path),
                "row_count": len(records),
            },
            "patch_cross_references": {
                name: {
                    "path": relative(cfg_path.parent / name),
                    "sha256": common.sha256_file(cfg_path.parent / name),
                    "rva_count": len(values),
                }
                for name, values in patch_by_file.items()
            },
        },
        "method": {
            "join_key": "cfg_functions.csv.func_index == pdata_functions.csv.record_index",
            "family_order": list(FAMILY_ORDER),
            "families": {
                FAMILY_DATA_RECORD: (
                    "a pdata range with zero control-flow terminators whose own bytes classify "
                    "as data; the record is a table registered as a code range"
                ),
                FAMILY_UNDECODED: (
                    "undecoded_bytes > 0; the function is re-decoded with "
                    "cfg_build.FunctionBuilder and one region is emitted per maximal byte run "
                    "its coverage map leaves uncovered. A function above the re-decode cap "
                    "contributes one whole-range region instead, and is counted in "
                    "counters.oversize_undecoded_functions"
                ),
                FAMILY_SWITCH: (
                    "switch_sites_rejected > 0; reason carries the highest ranked entry of "
                    "method.switch_reject_severity present in switch_reject_reasons, so a "
                    "plausible table with broken targets outranks a table the builder could "
                    "not bound"
                ),
                FAMILY_BOUNDARY: "term_range_end > 0 or exit_range_end > 0",
                FAMILY_LINEAR_ONLY: "blocks_linear_only > 0",
                FAMILY_MULTI_ENTRY: (
                    "entry_external_calls + entry_external_jumps + (entry_internal > 0) > 1, "
                    "or overlap_role != sole, or overlap_partners > 0"
                ),
                FAMILY_PDATA_GAP: (
                    "every run of section bytes between consecutive IMAGE_RUNTIME_FUNCTION "
                    "ranges plus the region before the first and after the last record"
                ),
            },
            "kind_rules": list(KIND_RULES),
            "ok_rules": list(OK_RULES),
            "confidence_rules": list(CONFIDENCE_RULES),
            "switch_reject_severity": list(SWITCH_REJECT_SEVERITY),
            "priority_order": list(PRIORITY_TAGS),
            "priority_levels": dict(PRIORITY_LEVELS),
            "priority_sources": {
                "security": (
                    "the owner imports one of the curated KERNEL32, CRYPT32, WS2_32, "
                    "ADVAPI32, CFGMGR32, IPHLPAPI or ole32 symbols, or carries a security "
                    "doc_anchor"
                ),
                "syscall": "the owner has syscall_sites > 0 or a direct_syscall_site anchor",
                "patch": (
                    "the owner carries a patcher_entry anchor, or its pdata range contains an "
                    "RVA the patch audit already attributes"
                ),
                "lifecycle": (
                    "the owner imports a module load, TLS, init-once, exception-filter, fiber "
                    "or event-source symbol, or its pdata range contains the PE entry point, "
                    "an export or a TLS callback"
                ),
                "coverage": "always present, the lowest level",
            },
            "thresholds": {
                "table_dword_ratio": TABLE_DWORD_RATIO,
                "table_dword_ratio_strong": TABLE_DWORD_STRONG,
                "small_byte_ratio": SMALL_BYTE_RATIO,
                "data_linear_max": DATA_LINEAR_MAX,
                "code_linear_min": CODE_LINEAR_MIN,
                "code_linear_strong": CODE_LINEAR_STRONG,
                "redecode_max_size": REDECODE_MAX_SIZE,
                "redecode_max_size_hex": common.hexs(REDECODE_MAX_SIZE),
                "pad_bytes": sorted(PAD_BYTES),
                "ratio_digits": RATIO_DIGITS,
            },
            "row_order": (
                "priority tag rank, then family rank, then begin_rva, then end_rva, then "
                "reason; region_id is the 1-based ordinal of that order"
            ),
            "determinism": {
                "payload_timestamps": False,
                "unordered_iteration": "every set is sorted before it reaches the payload",
                "float_rounding_digits": RATIO_DIGITS,
                "encoding": "utf-8",
                "bom": False,
                "line_terminator": "\\n",
                "trailing_newline": True,
            },
            "limitations": [
                "cfg_functions.csv caps iat_symbols at "
                f"{IAT_SYMBOL_CSV_CAP} entries per function, so priority attribution can "
                f"miss a security import on the {capped_iat} capped rows, "
                f"{capped_flagged} of which are flagged here",
                "linear_ratio covers the contiguous prefix a straight sweep decodes; a region "
                "stops the sweep at its first undecodable byte and the remainder is reported "
                "through first_fail_rva_hex rather than per instruction",
                "kind is a byte level heuristic, not a semantic proof; a range that fits "
                "neither rule is reported as unknown rather than guessed",
                "priority tags for a pdata_gap come from both bordering records, because a "
                "hole belongs to neither",
            ],
        },
        "baseline": {
            "pdata_records": len(records),
            "pdata_covered_bytes": sum(record.code_size for record in records),
            "pdata_covered_bytes_hex": common.hexs(sum(record.code_size for record in records)),
            "pdata_span_bytes": (records[-1].end - records[0].begin) if records else 0,
            "code_section_bytes": code_section.raw_size,
            "overlapping_records": sum(1 for item in functions if item.is_overlapped()),
            "lifecycle_entry_points": {
                "address_of_entry_point": entry_rva,
                "address_of_entry_point_hex": common.hexs(entry_rva),
                "exports": [common.hexs(value) for value in export_rvas],
                "tls_callbacks": [common.hexs(value) for value in tls_rvas],
            },
        },
        "totals": {
            "regions": len(regions),
            "bytes": sum(item.size for item in regions),
            "bytes_hex": common.hexs(sum(item.size for item in regions)),
            "resolved": sum(1 for item in regions if item.ok),
            "unresolved": sum(1 for item in regions if not item.ok),
            "by_family": {
                name: sum(1 for item in regions if item.family == name)
                for name in FAMILY_ORDER
            },
            "by_kind": {kind: sum(1 for item in regions if item.kind == kind) for kind in KINDS},
            "by_triage": {
                triage: sum(1 for item in regions if item.triage == triage) for triage in TRIAGES
            },
            "by_priority": {
                level: sum(1 for item in regions if item.priority == level)
                for level in PRIORITY_VALUES
            },
            "by_confidence": {
                level: sum(1 for item in regions if item.confidence == level)
                for level in CONFIDENCES
            },
        },
        "families": summarise_families(regions),
        "priority": {
            tag: {
                "level": PRIORITY_LEVELS[tag],
                "regions": priority_regions[tag],
                "bytes": priority_bytes[tag],
                "bytes_hex": common.hexs(priority_bytes[tag]),
            }
            for tag in PRIORITY_TAGS
        },
        "pdata_gap_content": {
            **{content: gap_stats.get(content, 0) for content in CONTENT_KINDS},
            GAP_LEADING: gap_stats.get(GAP_LEADING, 0),
            GAP_TRAILING: gap_stats.get(GAP_TRAILING, 0),
            "bytes": gap_stats.get("bytes", 0),
        },
        "counters": counters,
        "pinned_ranges": [common.hexs(value) for value in PINNED_BEGINS],
        "pinned": pinned,
        "regions": embedded,
        "regions_scope": {
            "complete_families": list(FUNCTION_FAMILIES),
            "truncated_families": [FAMILY_PDATA_GAP],
            "pdata_gap_regions_total": len(gap_only),
            "pdata_gap_regions_in_json": gap_embedded,
            "note": (
                "the csv is the complete region table; the json embeds every non-gap family "
                "and the first pdata_gap_regions_in_json gaps in row order"
            ),
        },
        "csv": {
            "path": relative(csv_path),
            "row_count": len(regions),
            "column_count": len(CSV_COLUMNS),
            "columns": list(CSV_COLUMNS),
            "column_notes": {name: COLUMN_NOTES[name] for name in sorted(COLUMN_NOTES)},
            "row_order": "identical to method.row_order",
            "encoding": "utf-8",
            "bom": False,
            "line_terminator": "\\n",
            "sha256": common.sha256_file(csv_path),
        },
        "json": {
            "path": relative(json_path),
            "schema": SCHEMA,
            "indent": 2,
            "ensure_ascii": False,
        },
        "validation": {
            "check_count": len(checks),
            "failed_count": sum(1 for check in checks if not check.ok),
            "checks": [check.as_row() for check in checks],
        },
    }
    return payload, checks


def _structural_checks(
    functions: Sequence[Function],
    records: Sequence[Pdata],
    regions: Sequence[Region],
    gap_stats: Mapping[str, int],
    pinned: Sequence[Mapping[str, Any]],
    code_begin: int,
    code_end: int,
) -> list[common.Check]:
    checks: list[common.Check] = []
    joined = sum(
        1
        for function, record in zip(functions, records)
        if function.begin != record.begin
        or function.end != record.end
        or function.size != record.code_size
    )
    checks.append(
        common.Check(
            name="join.cfg_pdata_ranges_agree", expected=0, actual=joined, ok=joined == 0
        )
    )
    checks.append(
        common.Check(
            name="join.row_counts_agree",
            expected=len(functions),
            actual=len(records),
            ok=len(functions) == len(records),
        )
    )
    overlapped = sum(1 for item in functions if item.is_overlapped())
    checks.append(
        common.Check(
            name="pdata.overlapping_records", expected=0, actual=overlapped, ok=overlapped == 0
        )
    )
    covered = sum(record.code_size for record in records)
    span = (records[-1].end - records[0].begin) if records else 0
    interior_expected = sum(1 for record in records if record.gap_before > 0)
    interior_regions = [
        region
        for region in regions
        if region.family == FAMILY_PDATA_GAP and region.reason == GAP_INTERIOR
    ]
    checks.append(
        common.Check(
            name="gaps.covered_plus_interior_holes_equal_span",
            expected=span,
            actual=covered + sum(region.size for region in interior_regions),
            ok=covered + sum(region.size for region in interior_regions) == span,
        )
    )
    checks.append(
        common.Check(
            name="gaps.interior_count_matches_pdata",
            expected=interior_expected,
            actual=len(interior_regions),
            ok=interior_expected == len(interior_regions),
        )
    )
    leading_expected = int(bool(records) and records[0].begin > code_begin)
    checks.append(
        common.Check(
            name="gaps.leading_region",
            expected=leading_expected,
            actual=gap_stats.get(GAP_LEADING, 0),
            ok=gap_stats.get(GAP_LEADING, 0) == leading_expected,
        )
    )
    trailing_expected = int(bool(records) and records[-1].end < code_end)
    checks.append(
        common.Check(
            name="gaps.trailing_region",
            expected=trailing_expected,
            actual=gap_stats.get(GAP_TRAILING, 0),
            ok=gap_stats.get(GAP_TRAILING, 0) == trailing_expected,
        )
    )
    checks.append(
        common.Check(
            name="pinned.data_record_verdict",
            expected="one data_record region per pinned begin",
            actual=f"{len(pinned)} pinned region(s)",
            ok=len(pinned) == len(PINNED_BEGINS),
        )
    )
    incomplete = [
        region
        for region in regions
        if not region.family
        or not region.reason
        or region.kind not in KINDS
        or region.priority not in PRIORITY_VALUES
        or region.confidence not in CONFIDENCES
        or not region.evidence
    ]
    checks.append(
        common.Check(
            name="schema.every_region_fully_populated",
            expected=0,
            actual=len(incomplete),
            ok=not incomplete,
        )
    )
    keys = {(region.family, region.begin, region.end, region.reason) for region in regions}
    checks.append(
        common.Check(
            name="schema.no_duplicate_region_keys",
            expected=0,
            actual=len(regions) - len(keys),
            ok=len(regions) == len(keys),
        )
    )
    unsorted = sum(
        1
        for position in range(1, len(regions))
        if regions[position - 1].sort_key() > regions[position].sort_key()
    )
    checks.append(
        common.Check(
            name="order.rows_are_sorted", expected=0, actual=unsorted, ok=unsorted == 0
        )
    )
    return checks


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description="Static unresolved-region audit over the cfg/pdata evidence set"
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument(
        "--cfg", type=Path, default=root / "reverse" / "evidence" / "cfg_functions.csv"
    )
    parser.add_argument(
        "--pdata", type=Path, default=root / "reverse" / "evidence" / "pdata_functions.csv"
    )
    parser.add_argument(
        "--csv", type=Path, default=root / "reverse" / "evidence" / "unresolved_regions.csv"
    )
    parser.add_argument(
        "--json", type=Path, default=root / "reverse" / "evidence" / "unresolved_regions.json"
    )
    parser.add_argument(
        "--detail-gap-limit",
        type=int,
        default=DETAIL_GAP_LIMIT,
        help="pdata_gap regions embedded in the json; the csv always stays complete",
    )
    parser.add_argument("--max-report", type=int, default=40, help="failed checks to print")
    args = parser.parse_args(argv)

    payload, checks = build_report(
        root,
        script,
        args.specimen.resolve(),
        args.cfg.resolve(),
        args.pdata.resolve(),
        args.csv.resolve(),
        args.json.resolve(),
        args.detail_gap_limit,
    )
    common.write_json(args.json, payload)

    failed = common.report_checks(checks, args.max_report)
    totals = payload["totals"]
    print(
        f"script    {payload['producer']['script']} "
        f"sha256={payload['producer']['script_sha256']}"
    )
    print(
        f"inputs    cfg={payload['inputs']['cfg_functions.csv']['row_count']} "
        f"pdata={payload['inputs']['pdata_functions.csv']['row_count']} "
        f"specimen={payload['specimen']['name']} sha256={payload['specimen']['sha256']}"
    )
    print(
        f"regions   {totals['regions']} bytes={totals['bytes_hex']} "
        f"resolved={totals['resolved']} unresolved={totals['unresolved']}"
    )
    for family in FAMILY_ORDER:
        stats = payload["families"].get(family)
        if stats is None:
            continue
        print(
            f"family    {family:20s} regions={stats['regions']:<7d} "
            f"bytes={stats['bytes_hex']:>12s} unresolved={stats['unresolved']:<7d} "
            f"code={stats['by_kind'][KIND_CODE]} "
            f"data={stats['by_kind'][KIND_DATA]} "
            f"unknown={stats['by_kind'][KIND_UNKNOWN]}"
        )
    print(
        "priority  "
        + " ".join(
            f"{PRIORITY_LEVELS[tag]}:{payload['priority'][tag]['regions']}"
            for tag in PRIORITY_TAGS
        )
    )
    for record in payload["pinned"]:
        print(
            f"pinned    {record['begin_rva_hex']} kind={record['kind']} "
            f"family={record['family']} priority={record['priority']} "
            f"confidence={record['confidence']} bytes={record['size']}"
        )
    print(
        f"csv       {payload['csv']['path']} rows={payload['csv']['row_count']} "
        f"columns={payload['csv']['column_count']} sha256={payload['csv']['sha256']}"
    )
    print(f"json      {payload['json']['path']}")
    print(f"checks    {len(checks) - failed}/{len(checks)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
