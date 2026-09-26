"""Recursive-descent control-flow reconstruction over the x64 exception directory.

Static file parsing only. The specimen is opened read-only, is never mapped as
an image and is never executed. Every edge of the emitted graph is derived from
bytes decoded inside the bounds of exactly one IMAGE_RUNTIME_FUNCTION record.

Method
------
* Function bounds come from the IMAGE_RUNTIME_FUNCTION records of the exception
  data directory, parsed here directly with ``struct`` (12 byte BeginAddress /
  EndAddress / UnwindInfo). A function is never grown past its EndAddress.
* Capstone disassembles each function in x86-64 mode and is fed RVA based
  addresses, so every decoded branch target is already an RVA.
* Basic blocks start at the function entry, at a decoded direct branch target,
  at a validated jump-table target and at the fallthrough of a conditional
  branch. A direct call ends a block and continues at the next instruction; the
  call target is recorded as an out-of-function reference, never as a CFG edge.
* Bytes that no edge reaches are swept linearly. Those blocks are reported in
  ``blocks_linear_only`` and excluded from ``blocks_reached``, which is why
  ``reached_ratio`` is measured and never assumed to be 1.0.
* A jump-table site becomes a validated node only when every table entry
  resolves to a decoded instruction start inside the same function. A site that
  fails any check is counted as rejected with an explicit reason and
  contributes no edges, so the graph is never grown on an unvalidated table.
* Overlapping runtime functions, runtime functions reachable through more than
  one entry point and cross-function references are reported, never merged.

Limits
------
These bounds are what the two CSV files are allowed to claim, and they are the
reason several columns exist:

* A jump-table case count comes from a ``cmp register, immediate`` bound that the
  builder still tracks on the same linear path. A bound established on another
  path is not propagated, so such a site is reported as rejected with
  ``NO_BOUND`` instead of being guessed.
* An instruction that straddles the boundary between a reached region and a
  linearly swept region is not decoded, so a jump-table target on such a byte
  fails validation and the site is reported as rejected.
* Registers are tracked per basic block and across layout contiguous
  fallthroughs only; any instruction with an unknown register effect clears the
  tracked state.
* Unreached code is reported, never merged into the graph: it stays in
  ``blocks_linear_only``, it adds no out-of-function reference and it never
  turns another block into a reached one, even when a jump table inside it
  validates.

Determinism
-----------
No timestamps, no dictionary-order dependence, no randomness: rerunning on the
same specimen reproduces both CSV files byte for byte. Output is UTF-8 without
BOM, LF terminated, with a fixed column order.
"""

from __future__ import annotations

import argparse
import bisect
import math
import struct
import sys
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Iterable, Iterator, Mapping, Sequence

_SCRIPT_DIR: Final[Path] = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import common
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_INS_NOP, X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

DEFAULT_CLUSTER_GAP: Final[int] = 0x1000
BLOCK_WINDOW: Final[int] = 256
MAX_SWITCH_CASES: Final[int] = 1024
SWITCH_FIXPOINT_ROUNDS: Final[int] = 4
RATIO_DIGITS: Final[int] = 6
ENTROPY_DIGITS: Final[int] = 6
SYMBOL_CAP_FUNCTION: Final[int] = 8
SYMBOL_CAP_CLUSTER: Final[int] = 32
SYMBOL_SET_CAP_FUNCTION: Final[int] = 64
SYMBOL_SET_CAP_CLUSTER: Final[int] = 256
MODULE_SET_CAP: Final[int] = 32
TARGET_SAMPLE_CAP: Final[int] = 8
ANCHOR_EVIDENCE_CAP: Final[int] = 12
DEFAULT_PROGRESS: Final[int] = 20000

EDGE_CALL: Final[int] = 1
EDGE_JUMP: Final[int] = 2

TERM_CALL: Final[str] = "call"
TERM_JMP_DIRECT: Final[str] = "jmp_direct"
TERM_JMP_INDIRECT: Final[str] = "jmp_indirect"
TERM_JCC: Final[str] = "jcc"
TERM_RETURN: Final[str] = "return"
TERM_TRAP: Final[str] = "trap"
TERM_INVALID: Final[str] = "invalid"
TERM_RANGE_END: Final[str] = "range_end"

EXIT_CALL: Final[str] = "call"
EXIT_BRANCH: Final[str] = "branch"
EXIT_COND: Final[str] = "cond"
EXIT_SWITCH: Final[str] = "switch"
EXIT_INDIRECT: Final[str] = "indirect"
EXIT_RETURN: Final[str] = "return"
EXIT_TRAP: Final[str] = "trap"
EXIT_INVALID: Final[str] = "invalid"
EXIT_RANGE_END: Final[str] = "range_end"

ORIGIN_ENTRY: Final[str] = "entry"
ORIGIN_FALLTHROUGH: Final[str] = "fallthrough"
ORIGIN_BRANCH: Final[str] = "branch"
ORIGIN_COND: Final[str] = "cond"
ORIGIN_SWITCH: Final[str] = "switch"
ORIGIN_LINEAR: Final[str] = "linear"

TERMINATOR_KINDS: Final[tuple[str, ...]] = (
    TERM_CALL,
    TERM_JMP_DIRECT,
    TERM_JMP_INDIRECT,
    TERM_JCC,
    TERM_RETURN,
    TERM_TRAP,
    TERM_INVALID,
    TERM_RANGE_END,
)

EXIT_KINDS: Final[tuple[str, ...]] = (
    EXIT_CALL,
    EXIT_BRANCH,
    EXIT_COND,
    EXIT_SWITCH,
    EXIT_INDIRECT,
    EXIT_RETURN,
    EXIT_TRAP,
    EXIT_INVALID,
    EXIT_RANGE_END,
)

JCC_MNEMONICS: Final[frozenset[str]] = frozenset(
    {
        "ja", "jae", "jb", "jbe", "jc", "jcxz", "je", "jecxz", "jg", "jge", "jl", "jle",
        "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl", "jnle", "jno",
        "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "jrcxz", "js", "jz",
    }
)

RETURN_MNEMONICS: Final[frozenset[str]] = frozenset(
    {"ret", "retf", "retfq", "iret", "iretd", "iretq"}
)

TRAP_MNEMONICS: Final[frozenset[str]] = frozenset(
    {"hlt", "int", "int1", "int3", "into", "ud2"}
)

SYSTEM_MNEMONICS: Final[frozenset[str]] = frozenset(
    {"syscall", "sysenter", "sysexit", "sysexitq"}
)

TRACKING_READ_MNEMONICS: Final[frozenset[str]] = frozenset(
    {
        "bt", "btc", "btr", "bts", "call", "clc", "cmc", "comisd", "comiss", "endbr64",
        "jmp", "nop", "pause", "prefetchw", "push", "pushfq", "stc", "test", "ucomisd",
        "ucomiss",
    }
)

COPY_MNEMONICS: Final[frozenset[str]] = frozenset({"mov", "movsx", "movzx"})

WIDE_REGISTERS: Final[tuple[str, ...]] = (
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)

REGISTER_ALIASES: Final[Mapping[str, str]] = {
    **{f"{name}{suffix}": name for name in WIDE_REGISTERS for suffix in ("b", "d", "w")},
    "ah": "rax", "al": "rax", "ax": "rax", "eax": "rax",
    "bh": "rbx", "bl": "rbx", "bx": "rbx", "ebx": "rbx",
    "ch": "rcx", "cl": "rcx", "cx": "rcx", "ecx": "rcx",
    "dh": "rdx", "dl": "rdx", "dx": "rdx", "edx": "rdx",
    "sil": "rsi", "si": "rsi", "esi": "rsi",
    "dil": "rdi", "di": "rdi", "edi": "rdi",
    "bpl": "rbp", "bp": "rbp", "ebp": "rbp",
    "spl": "rsp", "sp": "rsp", "esp": "rsp",
    "ip": "rip", "eip": "rip",
}

DOCUMENTED_ANCHORS: Final[Mapping[int, str]] = {
    0x0001E270: "patcher_entry",
    0x00325969: "time_url_xref",
    0x011660B: "registry_root_constant",
    0x0C85650: "handle_forward_wrapper",
    0x0C856C0: "handle_dispatch_site",
    0x0C874E3: "protection_constant_setup",
    0x0C874E9: "allocation_call_site",
    0x0C8CE70: "toolhelp_stub",
    0x0C8F650: "write_wrapper",
    0x0C8F880: "read_wrapper",
    0x0D7B0AE: "direct_syscall_site",
    0x0D7B4B9: "direct_syscall_site",
    0x0D7B863: "open_process_argument_site",
    0x0D7C0AC: "direct_syscall_site",
    0x1754520: "nop_write_helper",
    0x2BED750: "import_thunk",
    0x2E4D390: "import_iat_slot",
    0x2E4D920: "import_iat_slot",
}

ANCHOR_TAGS: Final[tuple[str, ...]] = (
    "DOC_ANCHOR",
    "ENTRY_POINT",
    "EXPORT",
    "SYSCALL",
    "IAT_CALL",
    "IAT_JUMP",
    "JUMP_TABLE",
    "SWITCH_REJECTED",
    "INDIRECT_CALL",
    "INDIRECT_JUMP",
    "UD2",
    "INT3",
    "TRAP",
    "UNDECODED",
    "LINEAR_BLOCKS",
    "INCOMING_REFERENCE",
    "UNWIND_EHANDLER",
    "UNWIND_UHANDLER",
    "UNWIND_CHAININFO",
    "OVERLAP",
)

SWITCH_REJECT_REASONS: Final[tuple[str, ...]] = (
    "NO_BOUND",
    "NO_TABLE_BASE",
    "NO_INDEX_REGISTER",
    "UNSUPPORTED_ENTRY_SIZE",
    "TABLE_UNMAPPED",
    "TARGET_OUT_OF_IMAGE",
    "TARGET_OUT_OF_FUNCTION",
    "TARGET_NOT_INSTRUCTION_START",
    "TOO_FEW_DISTINCT_TARGETS",
)

UNWIND_FLAGS: Final[tuple[tuple[int, str], ...]] = (
    (0x01, "EHANDLER"),
    (0x02, "UHANDLER"),
    (0x04, "CHAININFO"),
)

UNWIND_TAGS: Final[tuple[tuple[str, str], ...]] = (
    ("EHANDLER", "UNWIND_EHANDLER"),
    ("UHANDLER", "UNWIND_UHANDLER"),
    ("CHAININFO", "UNWIND_CHAININFO"),
)

SUMMED_FIELDS: Final[tuple[str, ...]] = (
    "size",
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
    "iat_calls",
    "iat_jumps",
    "switch_sites",
    "switch_validated",
    "switch_rejected",
    "switch_cases",
    "rets",
    "ud2",
    "int3",
    "traps",
    "syscalls",
    "functions_with_linear_blocks",
    "functions_with_undecoded",
    "functions_with_entry_refs",
    "functions_multi_entry",
    "unwind_ehandler",
    "unwind_uhandler",
    "unwind_chain",
    "overlapping_functions",
    *(f"term_{kind}" for kind in TERMINATOR_KINDS),
    *(f"exit_{kind}" for kind in EXIT_KINDS),
)

FUNCTION_FIELDS: Final[tuple[str, ...]] = (
    "func_index",
    "begin_rva",
    "begin_rva_hex",
    "begin_va",
    "begin_va_hex",
    "end_rva",
    "end_rva_hex",
    "end_va",
    "end_va_hex",
    "size",
    "section",
    "raw",
    "raw_hex",
    "unwind_rva",
    "unwind_rva_hex",
    "unwind_version",
    "unwind_flags",
    "unwind_shared_by",
    "overlap_role",
    "overlap_partners",
    "entry_internal",
    "entry_external_calls",
    "entry_external_jumps",
    "entry_refs",
    "basic_blocks",
    "blocks_reached",
    "blocks_linear_only",
    "reached_ratio",
    "instructions",
    "decoded_bytes",
    "undecoded_bytes",
    "undecoded_regions",
    "edges",
    "max_indegree",
    "blocks_indegree_gt1",
    "back_edges",
    "cross_calls",
    "cross_jumps",
    "cross_function_edges",
    "cross_function_targets",
    "term_call",
    "term_jmp_direct",
    "term_jmp_indirect",
    "term_jcc",
    "term_return",
    "term_trap",
    "term_invalid",
    "term_range_end",
    "exit_call",
    "exit_branch",
    "exit_cond",
    "exit_switch",
    "exit_indirect",
    "exit_return",
    "exit_trap",
    "exit_invalid",
    "exit_range_end",
    "direct_calls",
    "direct_jumps",
    "indirect_calls",
    "indirect_jumps",
    "indirect_jumps_unresolved",
    "iat_call_sites",
    "iat_jump_sites",
    "iat_module_count",
    "iat_symbol_count",
    "iat_symbols",
    "switch_sites",
    "switch_sites_validated",
    "switch_sites_rejected",
    "switch_cases",
    "switch_reject_reasons",
    "ret_sites",
    "ud2_sites",
    "int3_sites",
    "trap_sites",
    "syscall_sites",
    "decode_status",
    "doc_anchors",
    "cluster_id",
)

CLUSTER_FIELDS: Final[tuple[str, ...]] = (
    "cluster_id",
    "first_rva",
    "first_rva_hex",
    "last_end_rva",
    "last_end_rva_hex",
    "rva_span",
    "section",
    "function_count",
    "size_min",
    "size_max",
    "size_total",
    "size_average",
    "span_bytes",
    "code_bytes",
    "gap_bytes",
    "entropy_span",
    "entropy_code",
    "basic_blocks",
    "blocks_reached",
    "blocks_linear_only",
    "reached_ratio",
    "instructions",
    "decoded_bytes",
    "undecoded_bytes",
    "undecoded_regions",
    "edges",
    "back_edges",
    "max_indegree",
    "cross_calls",
    "cross_jumps",
    "cross_function_edges",
    "direct_calls",
    "direct_jumps",
    "indirect_calls",
    "indirect_jumps",
    "indirect_jumps_unresolved",
    "iat_call_sites",
    "iat_jump_sites",
    "iat_module_count",
    "iat_symbol_count",
    "iat_symbols",
    "switch_sites",
    "switch_sites_validated",
    "switch_sites_rejected",
    "switch_cases",
    "ret_sites",
    "ud2_sites",
    "int3_sites",
    "trap_sites",
    "syscall_sites",
    "functions_with_linear_blocks",
    "functions_with_undecoded",
    "functions_with_entry_refs",
    "functions_multi_entry",
    "unwind_ehandler",
    "unwind_uhandler",
    "unwind_chaininfo",
    "overlapping_functions",
    "entry_point_inside",
    "export_inside",
    "doc_anchors",
    "anchor_tags",
    "anchor_evidence",
    "anchor_count",
    "anchor_truncated",
)


@dataclass(frozen=True, slots=True)
class RawImage:
    """Byte access for the file-backed part of the image, keyed by RVA."""

    blob: bytes
    headers: int
    spans: tuple[tuple[int, int, int, str], ...]
    start_keys: tuple[int, ...]

    def span_index(self, rva: int) -> int:
        return bisect.bisect_right(self.start_keys, rva) - 1

    def mapped_length(self, rva: int, length: int) -> int:
        if length <= 0 or rva < 0:
            return 0
        if rva < self.headers:
            return min(length, self.headers - rva)
        index = self.span_index(rva)
        if index < 0:
            return 0
        start, end, _, _ = self.spans[index]
        return min(length, end - rva) if start <= rva < end else 0

    def slice(self, rva: int, length: int) -> bytes:
        available = self.mapped_length(rva, length)
        if available <= 0:
            return b""
        if rva < self.headers:
            return self.blob[rva : rva + available]
        _, _, delta, _ = self.spans[self.span_index(rva)]
        offset = rva + delta
        return self.blob[offset : offset + available]

    def at(self, rva: int, length: int) -> bytes | None:
        if self.mapped_length(rva, length) < length:
            return None
        return self.slice(rva, length)

    def section_at(self, rva: int) -> str:
        index = self.span_index(rva)
        if 0 <= index < len(self.spans) and self.spans[index][0] <= rva < self.spans[index][1]:
            return self.spans[index][3]
        return "NONE"

    def raw_offset(self, rva: int) -> int | None:
        if rva < self.headers:
            return rva
        index = self.span_index(rva)
        if 0 <= index < len(self.spans) and self.spans[index][0] <= rva < self.spans[index][1]:
            return rva + self.spans[index][2]
        return None


def build_raw_image(pe: Any, blob: bytes) -> RawImage:
    spans = tuple(
        sorted(
            (
                section.virtual_address,
                section.virtual_address + section.raw_size,
                section.raw_pointer - section.virtual_address,
                section.name,
            )
            for section in common.sections(pe)
            if section.raw_size
        )
    )
    return RawImage(
        blob=blob,
        headers=int(pe.OPTIONAL_HEADER.SizeOfHeaders),
        spans=spans,
        start_keys=tuple(span[0] for span in spans),
    )


def build_iat_slots(pe: Any) -> dict[int, str]:
    """Map every import address table slot RVA to a ``dll!symbol`` label."""

    thunk_size = 8 if int(pe.OPTIONAL_HEADER.Magic) == 0x020B else 4
    slots: dict[int, str] = {}
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = descriptor.dll.decode("ascii", errors="replace")
        first_thunk = int(descriptor.struct.FirstThunk)
        for position, entry in enumerate(descriptor.imports):
            label = (
                entry.name.decode("ascii", errors="replace")
                if entry.name
                else f"ordinal_{entry.ordinal}"
            )
            slots[first_thunk + position * thunk_size] = f"{dll}!{label}"
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
        dll = descriptor.dll.decode("ascii", errors="replace")
        table = int(descriptor.struct.pIAT)
        for position, entry in enumerate(descriptor.imports):
            label = (
                entry.name.decode("ascii", errors="replace")
                if entry.name
                else f"ordinal_{entry.ordinal}"
            )
            slots[table + position * thunk_size] = f"{dll}!{label}"
    return slots


def parse_runtime_functions(pe: Any) -> list[tuple[int, int, int]]:
    """Decode IMAGE_RUNTIME_FUNCTION triples from the exception directory."""

    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[common.EXCEPTION_DIRECTORY_INDEX]
    rva = int(directory.VirtualAddress)
    size = int(directory.Size)
    if rva == 0 or size == 0:
        return []
    record_size = common.RUNTIME_FUNCTION_SIZE
    count = size // record_size
    if count == 0:
        return []
    records = list(struct.iter_unpack("<III", common.read_rva(pe, rva, count * record_size)))
    return [(begin, end, unwind) for begin, end, unwind in records[:count]]


def overlap_roles(records: Sequence[tuple[int, int, int]]) -> list[tuple[str, int]]:
    """Classify every record as sole, primary or secondary owner of its range."""

    roles: list[tuple[str, int]] = []
    active: list[int] = []
    for index, (begin, _, _) in enumerate(records):
        active = [other for other in active if records[other][1] > begin]
        if not active:
            active.append(index)
            roles.append(("sole", 0))
            continue
        first = active[0]
        active.append(index)
        roles.append(("secondary" if begin != records[first][0] else "primary", len(active) - 1))
    return roles


def unwind_headers(image: RawImage, unwind_rvas: Sequence[int]) -> dict[int, tuple[int, str]]:
    """Read version and flag names of every distinct unwind record once."""

    headers: dict[int, tuple[int, str]] = {}
    for rva in sorted({value for value in unwind_rvas if value}):
        raw = image.at(rva, 4)
        if raw is None:
            headers[rva] = (0, "UNREADABLE")
            continue
        version = raw[0] & 0x07
        flags = (raw[0] & 0xF8) >> 3
        headers[rva] = (version, "|".join(common.decode_flags(flags, UNWIND_FLAGS)))
    return headers


def shannon_entropy(counts: Mapping[int, int], total: int) -> float:
    if total <= 0:
        return 0.0
    accumulator = 0.0
    for count in counts.values():
        if count:
            share = count / total
            accumulator -= share * math.log2(share)
    return round(accumulator, ENTROPY_DIGITS)


def canonical_register(md: Cs, register: int) -> str:
    name = md.reg_name(register)
    return REGISTER_ALIASES.get(name, name)


def is_hidden_indirect_jump(insn: Any) -> bool:
    """Detect the ``0F 1F /4`` unconditional jump that Capstone reports as a nop."""

    if insn.id != X86_INS_NOP or len(insn.bytes) < 3:
        return False
    return insn.bytes[0] == 0x0F and insn.bytes[1] == 0x1F and (insn.bytes[2] >> 3) & 0x07 == 4


@dataclass(slots=True)
class RegisterState:
    """Bounded, path-insensitive tracking of switch-table base registers."""

    tables: dict[str, int] = field(default_factory=dict)
    indexed: dict[str, tuple[int, str, int]] = field(default_factory=dict)
    bounds: dict[str, int] = field(default_factory=dict)
    copied_from: dict[str, str] = field(default_factory=dict)

    def clear(self) -> None:
        self.tables.clear()
        self.indexed.clear()
        self.bounds.clear()
        self.copied_from.clear()

    def copy(self) -> "RegisterState":
        return RegisterState(
            dict(self.tables), dict(self.indexed), dict(self.bounds), dict(self.copied_from)
        )

    def drop(self, register: str) -> None:
        self.tables.pop(register, None)
        self.indexed.pop(register, None)
        self.copied_from.pop(register, None)

    def bound_of(self, register: str) -> int | None:
        """Follow zero extending copies so a bound on the source register applies."""

        current: str | None = register
        for _ in range(4):
            if current is None:
                return None
            bound = self.bounds.get(current)
            if bound is not None:
                return bound
            current = self.copied_from.get(current)
        return None


@dataclass(slots=True)
class SwitchSite:
    """A jump-table candidate that must validate before it becomes a node."""

    site_rva: int
    kind: str
    table_rva: int
    scale: int
    count: int
    signed_entries: bool
    reason: str = ""
    resolved: bool = False


@dataclass(slots=True)
class Block:
    """One basic block of a single runtime function.

    Only the graph shape lives here; every counter is kept per function so a
    block record stays cheap for the millions of blocks of a full build.
    """

    start: int
    origin: str = ORIGIN_ENTRY
    reached: bool = True
    instructions: int = 0
    terminator: str = ""
    exit_kind: str = ""
    successors: list[int] = field(default_factory=list)
    cross_targets: list[tuple[int, int]] = field(default_factory=list)
    pending: list[SwitchSite] = field(default_factory=list)


@dataclass(slots=True)
class FunctionStats:
    """Per-function result, emitted as a row and aggregated into clusters."""

    func_index: int
    begin: int
    end: int
    unwind: int
    section: str
    raw: int
    unwind_version: int
    unwind_flags: str
    unwind_shared_by: int
    overlap_role: str
    overlap_partners: int
    decode_status: str = "ok"
    size: int = 0
    basic_blocks: int = 0
    blocks_reached: int = 0
    blocks_linear_only: int = 0
    instructions: int = 0
    decoded_bytes: int = 0
    undecoded_bytes: int = 0
    undecoded_regions: int = 0
    edges: int = 0
    max_indegree: int = 0
    blocks_indegree_gt1: int = 0
    back_edges: int = 0
    entry_internal: int = 0
    cross_calls: int = 0
    cross_jumps: int = 0
    cross_targets: list[int] = field(default_factory=list)
    direct_calls: int = 0
    direct_jumps: int = 0
    indirect_calls: int = 0
    indirect_jumps: int = 0
    indirect_jumps_unresolved: int = 0
    iat_calls: int = 0
    iat_jumps: int = 0
    iat_symbol_count: int = 0
    iat_symbols: set[str] = field(default_factory=set)
    iat_modules: set[str] = field(default_factory=set)
    switch_sites: int = 0
    switch_validated: int = 0
    switch_rejected: int = 0
    switch_cases: int = 0
    switch_reasons: dict[str, int] = field(default_factory=dict)
    rets: int = 0
    ud2: int = 0
    int3: int = 0
    traps: int = 0
    syscalls: int = 0
    functions_with_linear_blocks: int = 0
    functions_with_undecoded: int = 0
    functions_with_entry_refs: int = 0
    functions_multi_entry: int = 0
    unwind_ehandler: int = 0
    unwind_uhandler: int = 0
    unwind_chain: int = 0
    overlapping_functions: int = 0
    doc_anchors: tuple[str, ...] = ()
    tags: dict[str, int] = field(default_factory=dict)
    cluster_id: int = 0
    terms: dict[str, int] = field(default_factory=dict)
    exits: dict[str, int] = field(default_factory=dict)


class FunctionBuilder:
    """Recursive-descent CFG builder for one IMAGE_RUNTIME_FUNCTION record.

    The explicit work list is the non-recursive formulation of recursive descent:
    it keeps very large runtime functions inside the interpreter stack limits.
    """

    def __init__(
        self,
        image: RawImage,
        decoder: Cs,
        iat_slots: Mapping[int, str],
        incoming: dict[int, int],
        image_base: int,
        image_end: int,
    ) -> None:
        self._image = image
        self._md = decoder
        self._iat = iat_slots
        self._incoming = incoming
        self._image_base = image_base
        self._image_end = image_end
        self._begin = 0
        self._end = 0
        self._code = b""
        self._covered = b""
        self._blocks: dict[int, Block] = {}
        self._insn_starts: set[int] = set()
        self._worklist: deque[int] = deque()
        self._sealed: dict[int, RegisterState] = {}
        self._instructions = 0
        self._back_edges = 0
        self._cross_calls = 0
        self._cross_jumps = 0
        self._direct_calls = 0
        self._direct_jumps = 0
        self._indirect_calls = 0
        self._indirect_jumps = 0
        self._indirect_unresolved = 0
        self._iat_calls = 0
        self._iat_jumps = 0
        self._switch_sites = 0
        self._switch_validated = 0
        self._switch_rejected = 0
        self._switch_cases = 0
        self._switch_reasons: Counter[str] = Counter()
        self._queue_edges = True
        self._rets = 0
        self._ud2 = 0
        self._int3 = 0
        self._traps = 0
        self._syscalls = 0
        self._symbols: set[str] = set()
        self._modules: set[str] = set()
        self._tags: dict[str, int] = {}

    def analyse(
        self,
        index: int,
        begin: int,
        end: int,
        unwind: int,
        section: str,
        raw: int,
    ) -> FunctionStats:
        self._begin = begin
        self._end = end
        size = max(0, end - begin)
        mapped = self._image.mapped_length(begin, size)
        self._code = self._image.slice(begin, mapped)
        self._covered = bytearray(len(self._code))
        stats = FunctionStats(
            func_index=index,
            begin=begin,
            end=end,
            unwind=unwind,
            section=section,
            raw=raw,
            unwind_version=0,
            unwind_flags="",
            unwind_shared_by=0,
            overlap_role="sole",
            overlap_partners=0,
            size=size,
        )
        if size <= 0:
            stats.decode_status = "empty"
            return stats
        if not self._code:
            stats.decode_status = "unmapped"
            return stats
        if mapped < size:
            stats.decode_status = "partial_mapping"
        self._ensure_block(0, ORIGIN_ENTRY)
        self._drain()
        self._sweep()
        for _ in range(SWITCH_FIXPOINT_ROUNDS):
            if not self._retry_pending():
                break
            self._drain()
        self._collect(stats)
        return stats

    def _collect(self, stats: FunctionStats) -> None:
        indegree: Counter[int] = Counter()
        terms = {f"term_{kind}": 0 for kind in TERMINATOR_KINDS}
        exits = {f"exit_{kind}": 0 for kind in EXIT_KINDS}
        internal_entries: set[int] = set()
        reached = 0
        for block in self._blocks.values():
            terms[f"term_{block.terminator}"] = terms.get(f"term_{block.terminator}", 0) + 1
            exits[f"exit_{block.exit_kind}"] = exits.get(f"exit_{block.exit_kind}", 0) + 1
            if block.reached:
                reached += 1
            for target in block.successors:
                indegree[target] += 1
                if block.reached and target != self._begin:
                    internal_entries.add(target)
        rejected = self._switch_rejected
        for block in self._blocks.values():
            for site in block.pending:
                if site.resolved:
                    continue
                rejected += 1
                self._switch_reasons[site.reason] += 1
        stats.basic_blocks = len(self._blocks)
        stats.blocks_reached = reached
        stats.blocks_linear_only = len(self._blocks) - reached
        stats.instructions = self._instructions
        stats.decoded_bytes, stats.undecoded_regions = self._coverage()
        stats.undecoded_bytes = len(self._code) - stats.decoded_bytes
        stats.edges = sum(len(block.successors) for block in self._blocks.values())
        stats.max_indegree = max(indegree.values(), default=0)
        stats.blocks_indegree_gt1 = sum(1 for value in indegree.values() if value > 1)
        stats.back_edges = self._back_edges
        stats.entry_internal = len(internal_entries)
        stats.cross_calls = self._cross_calls
        stats.cross_jumps = self._cross_jumps
        stats.cross_targets = sorted(
            {target for block in self._blocks.values() for target, _ in block.cross_targets}
        )
        stats.direct_calls = self._direct_calls
        stats.direct_jumps = self._direct_jumps
        stats.indirect_calls = self._indirect_calls
        stats.indirect_jumps = self._indirect_jumps
        stats.indirect_jumps_unresolved = self._indirect_unresolved
        stats.iat_calls = self._iat_calls
        stats.iat_jumps = self._iat_jumps
        stats.iat_symbols = set(self._symbols)
        stats.iat_modules = set(self._modules)
        stats.iat_symbol_count = len(self._symbols)
        stats.switch_sites = self._switch_sites
        stats.switch_validated = self._switch_validated
        stats.switch_rejected = rejected
        stats.switch_cases = self._switch_cases
        stats.switch_reasons = order_reasons(self._switch_reasons)
        stats.rets = self._rets
        stats.ud2 = self._ud2
        stats.int3 = self._int3
        stats.traps = self._traps
        stats.syscalls = self._syscalls
        stats.tags = dict(self._tags)
        stats.terms = terms
        stats.exits = exits
        if stats.blocks_linear_only:
            stats.functions_with_linear_blocks = 1
            self._note(stats.tags, "LINEAR_BLOCKS", self._begin)
        if stats.undecoded_bytes:
            stats.functions_with_undecoded = 1
            self._note(stats.tags, "UNDECODED", self._begin)

    def _coverage(self) -> tuple[int, int]:
        """Count decoded bytes and the maximal runs of bytes no pass could decode."""

        decoded = 0
        regions = 0
        open_region = False
        for flag in self._covered:
            if flag:
                decoded += 1
                open_region = False
            elif not open_region:
                regions += 1
                open_region = True
        return decoded, regions

    def _note(self, tags: dict[str, int], name: str, rva: int) -> None:
        current = tags.get(name)
        if current is None or rva < current:
            tags[name] = rva

    def _ensure_block(self, offset: int, origin: str) -> Block:
        block = self._blocks.get(offset)
        if block is not None and block.reached:
            return block
        block = Block(start=self._begin + offset, origin=origin)
        self._blocks[offset] = block
        self._worklist.append(offset)
        return block

    def _drain(self) -> None:
        while self._worklist:
            self._process(self._worklist.popleft())

    def _process(self, offset: int) -> None:
        block = self._blocks[offset]
        state = self._sealed.pop(offset, None) or RegisterState()
        while offset < len(self._code):
            window = self._code[offset : offset + BLOCK_WINDOW]
            if not window:
                self._close(block, TERM_RANGE_END, EXIT_RANGE_END)
                return
            terminated = False
            decoded = False
            for insn in self._md.disasm(window, self._begin + offset):
                decoded = True
                offset = insn.address + insn.size - self._begin
                terminated = self._handle(insn, block, state)
                if terminated:
                    break
            if not decoded:
                block.terminator = TERM_INVALID
                block.exit_kind = EXIT_INVALID
                return
            if terminated:
                return
            if offset >= len(self._code):
                self._close(block, TERM_RANGE_END, EXIT_RANGE_END)
                return

    def _close(self, block: Block, terminator: str, exit_kind: str) -> None:
        block.terminator = terminator
        block.exit_kind = exit_kind

    def _handle(self, insn: Any, block: Block, state: RegisterState) -> bool:
        mnemonic = insn.mnemonic
        offset = insn.address - self._begin
        if offset not in self._insn_starts:
            self._instructions += 1
        self._covered[offset : offset + insn.size] = b"\x01" * insn.size
        self._insn_starts.add(offset)
        block.instructions += 1
        if mnemonic == "call":
            return self._handle_call(insn, block, state)
        if mnemonic == "jmp" or is_hidden_indirect_jump(insn):
            return self._handle_jump(insn, block, state)
        if mnemonic == "ljmp":
            self._close(block, TERM_JMP_INDIRECT, EXIT_INDIRECT)
            self._indirect_jumps += 1
            self._indirect_unresolved += 1
            self._note(self._tags, "INDIRECT_JUMP", insn.address)
            return True
        if mnemonic in JCC_MNEMONICS:
            return self._handle_conditional(insn, block, state)
        if mnemonic in RETURN_MNEMONICS:
            self._close(block, TERM_RETURN, EXIT_RETURN)
            self._rets += 1
            return True
        if mnemonic in TRAP_MNEMONICS:
            self._close(block, TERM_TRAP, EXIT_TRAP)
            self._count_trap(mnemonic, insn.address)
            return True
        self._track_state(mnemonic, insn, state)
        return False

    def _count_trap(self, mnemonic: str, rva: int) -> None:
        if mnemonic == "ud2":
            self._ud2 += 1
            self._note(self._tags, "UD2", rva)
        elif mnemonic == "int3":
            self._int3 += 1
            self._note(self._tags, "INT3", rva)
        else:
            self._traps += 1
            self._note(self._tags, "TRAP", rva)

    def _track_state(self, mnemonic: str, insn: Any, state: RegisterState) -> None:
        if mnemonic in SYSTEM_MNEMONICS:
            self._syscalls += 1
            self._note(self._tags, "SYSCALL", insn.address)
        if mnemonic == "lea":
            if not self._read_lea(insn, state):
                state.clear()
        elif mnemonic in COPY_MNEMONICS:
            if not self._read_mov(insn, state):
                state.clear()
        elif mnemonic == "movsxd":
            if not self._read_movsxd(insn, state):
                state.clear()
        elif mnemonic == "add":
            if not self._read_add(insn, state):
                state.clear()
        elif mnemonic == "cmp":
            if not self._read_cmp(insn, state):
                state.clear()
        elif mnemonic not in TRACKING_READ_MNEMONICS:
            state.clear()

    def _read_lea(self, insn: Any, state: RegisterState) -> bool:
        operands = insn.operands
        if len(operands) != 2 or operands[0].type != X86_OP_REG or operands[1].type != X86_OP_MEM:
            return False
        if operands[1].mem.base != X86_REG_RIP:
            return True
        register = canonical_register(self._md, operands[0].reg)
        state.drop(register)
        state.tables[register] = insn.address + insn.size + operands[1].mem.disp
        return True

    def _read_mov(self, insn: Any, state: RegisterState) -> bool:
        operands = insn.operands
        if len(operands) != 2 or operands[0].type != X86_OP_REG:
            return False
        register = canonical_register(self._md, operands[0].reg)
        state.drop(register)
        if operands[1].type == X86_OP_IMM:
            value = operands[1].imm
            if self._image_base <= value < self._image_end:
                state.tables[register] = value - self._image_base
        elif operands[1].type == X86_OP_REG and insn.mnemonic in COPY_MNEMONICS:
            state.copied_from[register] = canonical_register(self._md, operands[1].reg)
        return True

    def _read_movsxd(self, insn: Any, state: RegisterState) -> bool:
        operands = insn.operands
        if len(operands) != 2 or operands[0].type != X86_OP_REG or operands[1].type != X86_OP_MEM:
            return False
        register = canonical_register(self._md, operands[0].reg)
        state.drop(register)
        table = self._table_of(operands[1].mem, state)
        if table is None:
            return True
        memory = operands[1].mem
        state.indexed[register] = (table, canonical_register(self._md, memory.index), memory.scale)
        return True

    def _read_add(self, insn: Any, state: RegisterState) -> bool:
        operands = insn.operands
        if len(operands) != 2 or operands[0].type != X86_OP_REG or operands[1].type != X86_OP_REG:
            return False
        destination = canonical_register(self._md, operands[0].reg)
        source = canonical_register(self._md, operands[1].reg)
        destination_table = state.tables.get(destination)
        destination_expression = state.indexed.get(destination)
        source_table = state.tables.get(source)
        source_expression = state.indexed.get(source)
        state.drop(destination)
        if destination_table is not None and source_expression is not None:
            state.indexed[destination] = (
                destination_table,
                source_expression[1],
                source_expression[2],
            )
        elif source_table is not None and destination_expression is not None:
            state.indexed[destination] = (
                source_table,
                destination_expression[1],
                destination_expression[2],
            )
        return True

    def _read_cmp(self, insn: Any, state: RegisterState) -> bool:
        operands = insn.operands
        if len(operands) != 2 or operands[0].type != X86_OP_REG or operands[1].type != X86_OP_IMM:
            return False
        value = operands[1].imm
        if 0 <= value < MAX_SWITCH_CASES:
            register = canonical_register(self._md, operands[0].reg)
            if value > state.bounds.get(register, -1):
                state.bounds[register] = value
        return True

    def _table_of(self, memory: Any, state: RegisterState) -> int | None:
        if memory.index == 0 or memory.base == X86_REG_RIP:
            return None
        base = state.tables.get(canonical_register(self._md, memory.base))
        return None if base is None else base + memory.disp

    def _bound_count(self, state: RegisterState, register: str) -> int:
        bound = state.bound_of(register)
        if bound is None:
            return 0
        return min(bound + 1, MAX_SWITCH_CASES)

    def _register_switch_site(self, insn: Any, operand: Any, state: RegisterState) -> SwitchSite | None:
        expression = state.indexed.get(canonical_register(self._md, operand.reg))
        if expression is None:
            return None
        table, index_register, scale = expression
        return SwitchSite(
            site_rva=insn.address,
            kind="register",
            table_rva=table,
            scale=scale,
            count=self._bound_count(state, index_register),
            signed_entries=scale == 4,
        )

    def _memory_switch_site(self, insn: Any, operand: Any, state: RegisterState) -> SwitchSite | None:
        memory = operand.mem
        if memory.index == 0:
            return None
        base = state.tables.get(canonical_register(self._md, memory.base))
        if base is None:
            return None
        index_register = canonical_register(self._md, memory.index)
        return SwitchSite(
            site_rva=insn.address,
            kind="memory",
            table_rva=base + memory.disp,
            scale=memory.scale,
            count=self._bound_count(state, index_register),
            signed_entries=False,
        )

    def _resolve(self, site: SwitchSite) -> tuple[list[int], str]:
        """Validate a jump-table candidate against decoded instruction starts."""

        if site.scale == 4:
            signed = True
        elif site.scale == 8:
            signed = False
        else:
            return [], "UNSUPPORTED_ENTRY_SIZE"
        if site.count <= 0:
            return [], "NO_BOUND"
        targets: list[int] = []
        for index in range(site.count):
            raw = self._image.at(site.table_rva + index * site.scale, site.scale)
            if raw is None:
                return [], "TABLE_UNMAPPED"
            value = int.from_bytes(raw, "little", signed=signed)
            if signed:
                target = site.table_rva + value
            else:
                if not self._image_base <= value < self._image_end:
                    return [], "TARGET_OUT_OF_IMAGE"
                target = value - self._image_base
            if not self._begin <= target < self._end:
                return [], "TARGET_OUT_OF_FUNCTION"
            if target - self._begin not in self._insn_starts:
                return [], "TARGET_NOT_INSTRUCTION_START"
            targets.append(target)
        if len(set(targets)) < 2:
            return [], "TOO_FEW_DISTINCT_TARGETS"
        return targets, ""

    def _handle_call(self, insn: Any, block: Block, state: RegisterState) -> bool:
        self._close(block, TERM_CALL, EXIT_CALL)
        operands = insn.operands
        operand = operands[0] if operands else None
        if operand is not None and operand.type == X86_OP_IMM:
            self._direct_calls += 1
            self._record_out_of_function(operand.imm, EDGE_CALL, block)
        else:
            self._indirect_calls += 1
            self._note(self._tags, "INDIRECT_CALL", insn.address)
            if operand is not None and operand.type == X86_OP_MEM:
                self._note_iat(insn, operand, is_call=True)
        self._fallthrough(block, insn, state)
        return True

    def _handle_conditional(self, insn: Any, block: Block, state: RegisterState) -> bool:
        self._close(block, TERM_JCC, EXIT_COND)
        if insn.operands and insn.operands[0].type == X86_OP_IMM:
            self._direct_jumps += 1
            self._link(block, insn.operands[0].imm, ORIGIN_COND)
        self._fallthrough(block, insn, state)
        return True

    def _handle_jump(self, insn: Any, block: Block, state: RegisterState) -> bool:
        block.terminator = TERM_JMP_INDIRECT
        block.exit_kind = EXIT_INDIRECT
        operands = insn.operands
        operand = operands[0] if operands else None
        if operand is not None and operand.type == X86_OP_IMM:
            self._close(block, TERM_JMP_DIRECT, EXIT_BRANCH)
            self._direct_jumps += 1
            self._link(block, operand.imm, ORIGIN_BRANCH)
            return True
        self._indirect_jumps += 1
        self._note(self._tags, "INDIRECT_JUMP", insn.address)
        if operand is None:
            return True
        if operand.type == X86_OP_REG:
            site = self._register_switch_site(insn, operand, state)
        else:
            self._note_iat(insn, operand, is_call=False)
            site = self._memory_switch_site(insn, operand, state)
        if site is None:
            self._indirect_unresolved += 1
            return True
        self._switch_sites += 1
        targets, reason = self._resolve(site)
        if targets:
            block.exit_kind = EXIT_SWITCH
            self._switch_validated += 1
            self._switch_cases += len(targets)
            self._note(self._tags, "JUMP_TABLE", site.site_rva)
            for target in targets:
                self._link(block, target, ORIGIN_SWITCH)
        else:
            site.reason = reason
            self._note(self._tags, "SWITCH_REJECTED", site.site_rva)
            if block.reached:
                block.pending.append(site)
            else:
                self._switch_rejected += 1
                self._switch_reasons[reason] += 1
        return True

    def _note_iat(self, insn: Any, operand: Any, is_call: bool) -> None:
        memory = operand.mem
        if memory.base != X86_REG_RIP:
            return
        label = self._iat.get(insn.address + insn.size + memory.disp)
        if label is None:
            return
        if is_call:
            self._iat_calls += 1
            self._note(self._tags, "IAT_CALL", insn.address)
        else:
            self._iat_jumps += 1
            self._note(self._tags, "IAT_JUMP", insn.address)
        if len(self._symbols) < SYMBOL_SET_CAP_FUNCTION:
            self._symbols.add(label)
        if len(self._modules) < MODULE_SET_CAP:
            self._modules.add(label.partition("!")[0])

    def _fallthrough(self, block: Block, insn: Any, state: RegisterState) -> None:
        target = insn.address + insn.size
        if target >= self._end:
            return
        if self._link(block, target, ORIGIN_FALLTHROUGH) and self._queue_edges:
            self._sealed[target - self._begin] = state.copy()

    def _link(self, block: Block, target: int, origin: str) -> bool:
        """Add an intra-function edge and report whether it stays in bounds."""

        if not self._begin <= target < self._end:
            self._record_out_of_function(target, EDGE_JUMP, block)
            return False
        block.successors.append(target)
        if block.reached and target <= block.start:
            self._back_edges += 1
        if self._queue_edges:
            self._ensure_block(target - self._begin, origin)
        return True

    def _record_out_of_function(self, target: int, kind: int, block: Block) -> None:
        if not block.reached:
            return
        block.cross_targets.append((target, kind))
        if kind == EDGE_CALL:
            self._cross_calls += 1
        else:
            self._cross_jumps += 1
        self._incoming[target] = self._incoming.get(target, 0) | kind

    def _retry_pending(self) -> int:
        """Re-resolve deferred jump tables after more instruction starts are known."""

        progressed = 0
        for block in list(self._blocks.values()):
            for site in block.pending:
                if site.resolved:
                    continue
                targets, reason = self._resolve(site)
                if not targets:
                    site.reason = reason
                    continue
                site.resolved = True
                block.exit_kind = EXIT_SWITCH
                self._switch_validated += 1
                self._switch_cases += len(targets)
                self._note(self._tags, "JUMP_TABLE", site.site_rva)
                for target in targets:
                    self._link(block, target, ORIGIN_SWITCH)
                progressed += 1
        return progressed

    def _sweep(self) -> None:
        """Decode every byte no edge reached, without extending the graph."""

        self._queue_edges = False
        try:
            offset = 0
            size = len(self._code)
            while offset < size:
                if self._covered[offset]:
                    offset += 1
                    continue
                limit = offset
                while limit < size and not self._covered[limit]:
                    limit += 1
                self._sweep_region(offset, limit)
                offset = limit
        finally:
            self._queue_edges = True

    def _sweep_region(self, start: int, limit: int) -> None:
        offset = start
        while offset < limit:
            block = Block(start=self._begin + offset, origin=ORIGIN_LINEAR, reached=False)
            self._blocks[offset] = block
            state = RegisterState()
            terminated = False
            decoded = False
            for insn in self._md.disasm(
                self._code[offset : min(limit, offset + BLOCK_WINDOW)],
                self._begin + offset,
            ):
                decoded = True
                offset = insn.address + insn.size - self._begin
                terminated = self._handle(insn, block, state)
                if terminated:
                    break
            if not decoded:
                self._close(block, TERM_INVALID, EXIT_INVALID)
                offset += 1
            elif not terminated and not block.terminator:
                self._close(block, TERM_RANGE_END, EXIT_RANGE_END)

@dataclass(slots=True)
class Cluster:
    """A maximal run of address adjacent runtime functions with its evidence."""

    cluster_id: int
    first_rva: int
    last_end_rva: int
    section: str
    totals: dict[str, int] = field(default_factory=dict)
    function_count: int = 0
    size_min: int = 0
    size_max: int = 0
    size_average: float = 0.0
    code_bytes: int = 0
    gap_bytes: int = 0
    entropy_span: float = 0.0
    entropy_code: float = 0.0
    max_indegree: int = 0
    cross_function_edges: int = 0
    iat_module_count: int = 0
    iat_symbol_count: int = 0
    iat_symbols: tuple[str, ...] = ()
    doc_anchors: tuple[str, ...] = ()
    anchor_tags: tuple[str, ...] = ()
    anchor_evidence: tuple[str, ...] = ()
    anchor_truncated: bool = False
    entry_point_inside: bool = False
    export_inside: bool = False

    def __post_init__(self) -> None:
        if not self.totals:
            self.totals = {name: 0 for name in SUMMED_FIELDS}

    def add(self, stats: FunctionStats) -> None:
        totals = self.totals
        for name in SUMMED_FIELDS:
            totals[name] += summed_value(stats, name)
        self.function_count += 1
        self.size_min = stats.size if self.function_count == 1 else min(self.size_min, stats.size)
        self.size_max = max(self.size_max, stats.size)
        self.max_indegree = max(self.max_indegree, stats.max_indegree)


def summed_value(stats: FunctionStats, name: str) -> int:
    """Read one aggregate field of a function regardless of where it is stored."""

    if name.startswith("term_"):
        return stats.terms.get(name, 0)
    if name.startswith("exit_"):
        return stats.exits.get(name, 0)
    return getattr(stats, name)


def order_reasons(counts: Mapping[str, int]) -> dict[str, int]:
    """Order reject reasons by the declared vocabulary, then alphabetically."""

    ordered = {name: counts[name] for name in SWITCH_REJECT_REASONS if name in counts}
    ordered.update(
        {name: count for name, count in sorted(counts.items()) if name not in ordered}
    )
    return ordered


def note_min(tags: dict[str, int], name: str, rva: int) -> None:
    current = tags.get(name)
    if current is None or rva < current:
        tags[name] = rva


class ClusterBuilder:
    """Groups analysed functions into clusters and aggregates their evidence."""

    def __init__(
        self,
        image: RawImage,
        gap: int,
        entry_point_rva: int,
        export_rvas: Sequence[int],
    ) -> None:
        self._image = image
        self._gap = gap
        self._entry_point = entry_point_rva
        self._exports = frozenset(export_rvas)
        self._clusters: list[Cluster] = []
        self._current: Cluster | None = None
        self._members: list[FunctionStats] = []

    def add(self, stats: FunctionStats) -> None:
        if self._current is not None and stats.begin - self._current.last_end_rva <= self._gap:
            self._current.last_end_rva = max(self._current.last_end_rva, stats.end)
        else:
            self._finish()
            self._current = Cluster(
                cluster_id=len(self._clusters) + 1,
                first_rva=stats.begin,
                last_end_rva=stats.end,
                section=stats.section,
            )
        self._members.append(stats)
        stats.cluster_id = self._current.cluster_id

    def _finish(self) -> None:
        if self._current is None or not self._members:
            return
        self._aggregate(self._current, self._members)
        self._clusters.append(self._current)
        self._current = None
        self._members = []

    def _aggregate(self, cluster: Cluster, members: Sequence[FunctionStats]) -> None:
        symbols: set[str] = set()
        modules: set[str] = set()
        tags: dict[str, int] = {}
        span_counts: Counter[int] = Counter()
        code_counts: Counter[int] = Counter()
        anchors: set[str] = set()
        for stats in members:
            cluster.add(stats)
            if len(symbols) < SYMBOL_SET_CAP_CLUSTER:
                symbols.update(stats.iat_symbols)
            modules.update(stats.iat_modules)
            anchors.update(stats.doc_anchors)
            for name, rva in stats.tags.items():
                note_min(tags, name, rva)
            code_counts.update(self._image.slice(stats.begin, stats.size))
            cluster.code_bytes += len(self._image.slice(stats.begin, stats.size))
            if stats.begin in self._exports:
                cluster.export_inside = True
                note_min(tags, "EXPORT", stats.begin)
        span_counts.update(self._image.slice(cluster.first_rva, cluster.last_end_rva - cluster.first_rva))
        cluster.size_average = round(cluster.totals["size"] / cluster.function_count, 3)
        cluster.gap_bytes = cluster.last_end_rva - cluster.first_rva - cluster.code_bytes
        cluster.entropy_span = shannon_entropy(span_counts, sum(span_counts.values()))
        cluster.entropy_code = shannon_entropy(code_counts, sum(code_counts.values()))
        cluster.cross_function_edges = cluster.totals["cross_calls"] + cluster.totals["cross_jumps"]
        cluster.iat_symbol_count = len(symbols)
        cluster.iat_symbols = tuple(sorted(symbols)[:SYMBOL_CAP_CLUSTER])
        cluster.iat_module_count = len(modules)
        cluster.doc_anchors = tuple(sorted(anchors))
        cluster.entry_point_inside = cluster.first_rva <= self._entry_point < cluster.last_end_rva
        if cluster.entry_point_inside:
            note_min(tags, "ENTRY_POINT", self._entry_point)
        cluster.anchor_tags = tuple(name for name in ANCHOR_TAGS if name in tags)
        evidence = [f"{name}@{common.hexs(tags[name])}" for name in cluster.anchor_tags]
        cluster.anchor_truncated = len(evidence) > ANCHOR_EVIDENCE_CAP
        cluster.anchor_evidence = tuple(evidence[:ANCHOR_EVIDENCE_CAP])

    def rows(self) -> Iterator[Mapping[str, Any]]:
        self._finish()
        for cluster in self._clusters:
            yield cluster_row(cluster)


def cluster_row(cluster: Cluster) -> dict[str, Any]:
    totals = cluster.totals
    row: dict[str, Any] = dict(totals)
    row.update(
        {
            "cluster_id": cluster.cluster_id,
            "first_rva": cluster.first_rva,
            "first_rva_hex": common.hexs(cluster.first_rva),
            "last_end_rva": cluster.last_end_rva,
            "last_end_rva_hex": common.hexs(cluster.last_end_rva),
            "rva_span": cluster.last_end_rva - cluster.first_rva,
            "section": cluster.section,
            "function_count": cluster.function_count,
            "size_min": cluster.size_min,
            "size_max": cluster.size_max,
            "size_total": totals["size"],
            "size_average": cluster.size_average,
            "span_bytes": cluster.last_end_rva - cluster.first_rva,
            "code_bytes": cluster.code_bytes,
            "gap_bytes": cluster.gap_bytes,
            "entropy_span": cluster.entropy_span,
            "entropy_code": cluster.entropy_code,
            "max_indegree": cluster.max_indegree,
            "cross_function_edges": cluster.cross_function_edges,
            "iat_call_sites": totals["iat_calls"],
            "iat_jump_sites": totals["iat_jumps"],
            "iat_module_count": cluster.iat_module_count,
            "iat_symbol_count": cluster.iat_symbol_count,
            "iat_symbols": ";".join(cluster.iat_symbols),
            "switch_sites_validated": totals["switch_validated"],
            "switch_sites_rejected": totals["switch_rejected"],
            "switch_cases": totals["switch_cases"],
            "ret_sites": totals["rets"],
            "ud2_sites": totals["ud2"],
            "int3_sites": totals["int3"],
            "trap_sites": totals["traps"],
            "syscall_sites": totals["syscalls"],
            "unwind_chaininfo": totals["unwind_chain"],
            "entry_point_inside": cluster.entry_point_inside,
            "export_inside": cluster.export_inside,
            "doc_anchors": ";".join(cluster.doc_anchors),
            "anchor_tags": ";".join(cluster.anchor_tags),
            "anchor_evidence": ";".join(cluster.anchor_evidence),
            "anchor_count": len(cluster.anchor_evidence),
            "anchor_truncated": cluster.anchor_truncated,
        }
    )
    row["reached_ratio"] = _ratio(row["blocks_reached"], row["basic_blocks"])
    return {name: row.get(name) for name in CLUSTER_FIELDS}


@dataclass(frozen=True, slots=True)
class Annotations:
    """Run level context used to label one analysed function."""

    unwind: Mapping[int, tuple[int, str]]
    unwind_shared: Mapping[int, int]
    entry_point_rva: int
    anchor_rvas: tuple[int, ...]
    anchors: Mapping[int, str]

    def apply(self, stats: FunctionStats, role: str, partners: int) -> None:
        version, flags = self.unwind.get(stats.unwind, (0, "UNREADABLE"))
        names = set(flags.split("|")) - {""}
        stats.unwind_version = version
        stats.unwind_flags = flags
        stats.unwind_shared_by = self.unwind_shared[stats.unwind]
        stats.overlap_role = role
        stats.overlap_partners = partners
        stats.unwind_ehandler = 1 if "EHANDLER" in names else 0
        stats.unwind_uhandler = 1 if "UHANDLER" in names else 0
        stats.unwind_chain = 1 if "CHAININFO" in names else 0
        for flag, tag in UNWIND_TAGS:
            if flag in names:
                note_min(stats.tags, tag, stats.begin)
        if role != "sole":
            stats.overlapping_functions = 1
            note_min(stats.tags, "OVERLAP", stats.begin)
        if stats.begin <= self.entry_point_rva < stats.end:
            note_min(stats.tags, "ENTRY_POINT", self.entry_point_rva)
        for rva in self.anchor_rvas:
            if stats.begin <= rva < stats.end:
                note_min(stats.tags, "DOC_ANCHOR", rva)
                stats.doc_anchors += (f"{common.hexs(rva)}:{self.anchors[rva]}",)


def display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, RATIO_DIGITS)


def function_row(stats: FunctionStats, entry_flags: int, image_base: int) -> dict[str, Any]:
    calls = 1 if entry_flags & EDGE_CALL else 0
    jumps = 1 if entry_flags & EDGE_JUMP else 0
    entry_points = calls + jumps + (1 if stats.entry_internal else 0)
    row: dict[str, Any] = {
        "func_index": stats.func_index,
        "begin_rva": stats.begin,
        "begin_rva_hex": common.hexs(stats.begin),
        "begin_va": image_base + stats.begin,
        "begin_va_hex": common.hexs(image_base + stats.begin),
        "end_rva": stats.end,
        "end_rva_hex": common.hexs(stats.end),
        "end_va": image_base + stats.end,
        "end_va_hex": common.hexs(image_base + stats.end),
        "size": stats.size,
        "section": stats.section,
        "raw": stats.raw,
        "raw_hex": common.hexs(stats.raw) if stats.raw is not None else None,
        "unwind_rva": stats.unwind,
        "unwind_rva_hex": common.hexs(stats.unwind),
        "unwind_version": stats.unwind_version,
        "unwind_flags": stats.unwind_flags,
        "unwind_shared_by": stats.unwind_shared_by,
        "overlap_role": stats.overlap_role,
        "overlap_partners": stats.overlap_partners,
        "entry_internal": stats.entry_internal,
        "entry_external_calls": calls,
        "entry_external_jumps": jumps,
        "entry_refs": calls + jumps,
        "basic_blocks": stats.basic_blocks,
        "blocks_reached": stats.blocks_reached,
        "blocks_linear_only": stats.blocks_linear_only,
        "reached_ratio": _ratio(stats.blocks_reached, stats.basic_blocks),
        "instructions": stats.instructions,
        "decoded_bytes": stats.decoded_bytes,
        "undecoded_bytes": stats.undecoded_bytes,
        "undecoded_regions": stats.undecoded_regions,
        "edges": stats.edges,
        "max_indegree": stats.max_indegree,
        "blocks_indegree_gt1": stats.blocks_indegree_gt1,
        "back_edges": stats.back_edges,
        "cross_calls": stats.cross_calls,
        "cross_jumps": stats.cross_jumps,
        "cross_function_edges": stats.cross_calls + stats.cross_jumps,
        "cross_function_targets": ";".join(
            common.hexs(target) for target in stats.cross_targets[:TARGET_SAMPLE_CAP]
        ),
        "direct_calls": stats.direct_calls,
        "direct_jumps": stats.direct_jumps,
        "indirect_calls": stats.indirect_calls,
        "indirect_jumps": stats.indirect_jumps,
        "indirect_jumps_unresolved": stats.indirect_jumps_unresolved,
        "iat_call_sites": stats.iat_calls,
        "iat_jump_sites": stats.iat_jumps,
        "iat_module_count": len(stats.iat_modules),
        "iat_symbol_count": stats.iat_symbol_count,
        "iat_symbols": ";".join(sorted(stats.iat_symbols)[:SYMBOL_CAP_FUNCTION]),
        "switch_sites": stats.switch_sites,
        "switch_sites_validated": stats.switch_validated,
        "switch_sites_rejected": stats.switch_rejected,
        "switch_cases": stats.switch_cases,
        "switch_reject_reasons": ";".join(
            f"{name}={stats.switch_reasons[name]}" for name in sorted(stats.switch_reasons)
        ),
        "ret_sites": stats.rets,
        "ud2_sites": stats.ud2,
        "int3_sites": stats.int3,
        "trap_sites": stats.traps,
        "syscall_sites": stats.syscalls,
        "decode_status": stats.decode_status,
        "doc_anchors": ";".join(stats.doc_anchors),
        "cluster_id": stats.cluster_id,
    }
    row.update(stats.terms)
    row.update(stats.exits)
    return {name: row.get(name) for name in FUNCTION_FIELDS}


def parse_anchors(values: Iterable[str]) -> dict[int, str]:
    anchors: dict[int, str] = dict(DOCUMENTED_ANCHORS)
    for value in values:
        rva_text, _, label = value.partition(":")
        anchors[int(rva_text, 0)] = label or "custom_anchor"
    return anchors


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    root = Path(__file__).resolve().parent.parent.parent
    parser = argparse.ArgumentParser(
        description="Recursive-descent CFG reconstruction over the x64 exception directory"
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument(
        "--functions-csv",
        type=Path,
        default=root / "reverse" / "evidence" / "cfg_functions.csv",
    )
    parser.add_argument(
        "--clusters-csv",
        type=Path,
        default=root / "reverse" / "evidence" / "cfg_clusters.csv",
    )
    parser.add_argument(
        "--cluster-gap",
        type=lambda value: int(value, 0),
        default=DEFAULT_CLUSTER_GAP,
        help="maximum byte gap that keeps two functions in the same cluster",
    )
    parser.add_argument(
        "--max-functions",
        type=int,
        default=0,
        help="analyse only the first N runtime functions (0 = all)",
    )
    parser.add_argument(
        "--progress",
        type=int,
        default=DEFAULT_PROGRESS,
        help="print progress every N functions (0 = silent)",
    )
    parser.add_argument(
        "--anchor",
        action="append",
        default=[],
        metavar="RVA[:LABEL]",
        help="add a documented anchor RVA on top of the built-in list",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    specimen = args.specimen.resolve()
    functions_csv = args.functions_csv.resolve()
    clusters_csv = args.clusters_csv.resolve()
    anchors = parse_anchors(args.anchor)
    anchor_rvas = tuple(sorted(anchors))
    print(f"script    {display_path(script, root)}")
    print(f"sha256    {common.sha256_file(script)}")
    print(f"specimen  {display_path(specimen, root)} size={specimen.stat().st_size}")

    blob = specimen.read_bytes()
    pe = common.load_pe(specimen)
    try:
        image = build_raw_image(pe, blob)
        iat_slots = build_iat_slots(pe)
        exports = common.export_summary(pe)
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        image_end = image_base + int(pe.OPTIONAL_HEADER.SizeOfImage)
        entry_point_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        records = parse_runtime_functions(pe)
    finally:
        pe.close()
    export_rvas = tuple(int(symbol["rva"]) for symbol in exports["symbols"])
    roles = overlap_roles(records)
    unwind_cache = unwind_headers(image, [record[2] for record in records])
    annotations = Annotations(
        unwind=unwind_cache,
        unwind_shared=Counter(record[2] for record in records),
        entry_point_rva=entry_point_rva,
        anchor_rvas=anchor_rvas,
        anchors=anchors,
    )
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    incoming: dict[int, int] = {}
    limit = args.max_functions or len(records)
    print(
        f"pdata     records={len(records)} analysed={limit} "
        f"cluster_gap={common.hexs(args.cluster_gap)} anchors={len(anchors)}"
    )

    results: list[FunctionStats] = []
    for index, (begin, end, unwind) in enumerate(records):
        if index >= limit:
            break
        builder = FunctionBuilder(image, decoder, iat_slots, incoming, image_base, image_end)
        stats = builder.analyse(
            index,
            begin,
            end,
            unwind,
            image.section_at(begin),
            image.raw_offset(begin),
        )
        annotations.apply(stats, *roles[index])
        results.append(stats)
        if args.progress and (index + 1) % args.progress == 0:
            print(f"progress  {index + 1}/{limit}")

    for stats in results:
        flags = incoming.get(stats.begin, 0)
        if not flags:
            continue
        stats.functions_with_entry_refs = 1
        entries = (1 if flags & EDGE_CALL else 0) + (1 if flags & EDGE_JUMP else 0)
        if entries + (1 if stats.entry_internal else 0) > 1:
            stats.functions_multi_entry = 1
        note_min(stats.tags, "INCOMING_REFERENCE", stats.begin)

    clusters = ClusterBuilder(image, args.cluster_gap, entry_point_rva, export_rvas)
    for stats in results:
        clusters.add(stats)
    cluster_rows = list(clusters.rows())

    common.write_csv(functions_csv, function_rows(results, incoming, image_base), FUNCTION_FIELDS)
    common.write_csv(clusters_csv, cluster_rows, CLUSTER_FIELDS)

    checks = build_checks(records, results, cluster_rows, limit)
    for name, ok, detail in checks:
        print(f"check     {name} {'ok' if ok else 'FAIL'} {detail}")
    failed = [name for name, ok, _ in checks if not ok]
    totals = cluster_totals(results)
    print(
        f"functions {len(results)} blocks={totals['basic_blocks']} "
        f"reached_ratio={_ratio(totals['blocks_reached'], totals['basic_blocks'])} "
        f"switches={totals['switch_sites']} validated={totals['switch_validated']}"
    )
    print(f"clusters  {len(cluster_rows)} gap={common.hexs(args.cluster_gap)}")
    print(f"csv       {display_path(functions_csv, root)} rows={len(results)}")
    print(f"csv       {display_path(clusters_csv, root)} rows={len(cluster_rows)}")
    print(f"sha256    {common.sha256_file(functions_csv)}")
    print(f"sha256    {common.sha256_file(clusters_csv)}")
    return 1 if failed else 0


def function_rows(
    results: Sequence[FunctionStats],
    incoming: Mapping[int, int],
    image_base: int,
) -> Iterator[Mapping[str, Any]]:
    for stats in results:
        yield function_row(stats, incoming.get(stats.begin, 0), image_base)


def cluster_totals(results: Sequence[FunctionStats]) -> dict[str, int]:
    totals = {name: 0 for name in SUMMED_FIELDS}
    for stats in results:
        for name in SUMMED_FIELDS:
            totals[name] += summed_value(stats, name)
    return totals


def build_checks(
    records: Sequence[tuple[int, int, int]],
    results: Sequence[FunctionStats],
    cluster_rows: Sequence[Mapping[str, Any]],
    limit: int,
) -> list[tuple[str, bool, str]]:
    totals = cluster_totals(results)
    expected = records[:limit]
    checks: list[tuple[str, bool, str]] = [
        (
            "functions_analysed",
            len(results) == limit,
            f"{len(results)}/{limit}",
        ),
        (
            "pdata_bytes_preserved",
            totals["size"] == sum(end - begin for begin, end, _ in expected),
            f"{totals['size']} bytes",
        ),
        (
            "blocks_split_into_reached_and_linear",
            all(
                stats.basic_blocks == stats.blocks_reached + stats.blocks_linear_only
                for stats in results
            ),
            f"{totals['basic_blocks']} blocks",
        ),
        (
            "decoded_within_function_bounds",
            all(
                stats.decoded_bytes <= stats.size
                and stats.decoded_bytes + stats.undecoded_bytes <= stats.size
                for stats in results
            ),
            f"{totals['decoded_bytes']} decoded bytes",
        ),
        (
            "switch_sites_accounted",
            all(
                stats.switch_validated + stats.switch_rejected == stats.switch_sites
                for stats in results
            ),
            f"{totals['switch_sites']} sites, {totals['switch_rejected']} rejected",
        ),
        (
            "cluster_functions_cover_pdata",
            sum(int(row["function_count"]) for row in cluster_rows) == len(results),
            f"{len(cluster_rows)} clusters",
        ),
        (
            "cluster_spans_disjoint",
            all(
                int(cluster_rows[index]["last_end_rva"]) <= int(cluster_rows[index + 1]["first_rva"])
                for index in range(len(cluster_rows) - 1)
            ),
            "ordered by rva",
        ),
    ]
    return checks


if __name__ == "__main__":
    raise SystemExit(main())
