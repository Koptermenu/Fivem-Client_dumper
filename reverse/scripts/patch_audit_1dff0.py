"""Static P0/S10 thread-snapshot audit of the RVA 0x1DFF0 RIP-redirect walker.

Scope
-----
Audits the live thread-snapshot mechanism of the specimen.  The subject is the
0x1DFF0 function, the two call sites of the 0x1E360 orchestrator that drive it,
the 0x1E270 inline patcher whose flag write orders the two mechanisms, and the
0x1E590 list builder whose 0x28 / 0x30 byte lists the 0x1DFF0 loop consumes.  The
emitted table maps the thread handles, the CONTEXT buffer, the record fields and
the RIP reconstruction, and it enumerates every branch that can abandon the
mechanism.

Method
------
Static file parsing only.  pefile resolves the PE layout, the exception
directory supplies the exact function extents, and capstone decodes only the
seven functions named below.  The specimen is never loaded as an image, never
mapped and never executed.

Every claim is tied to a numbered anchor, and every anchor is re-verified against
the file on each run by matching the decoded mnemonic, the operand width, the
operand displacement, the immediate and the branch or call destination.  A
changed specimen therefore fails the anchor table instead of silently reusing
stale text.

The output describes mechanism structure only: symbolic address expressions,
the control-flow predicates that gate each step, the cross-function ordering,
and the error branches.  No relative displacement value, no patched byte
sequence, no ready to use patch step and no bypass procedure is produced or
recorded.  The subject rewrites a saved instruction pointer rather than code
bytes, and the emitted expressions are kept in the symbolic form the code
computes.

Determinism
-----------
The specimen digest is pinned, every collection is sorted before it is rendered,
and both outputs are written through the common writers (UTF-8, no BOM, LF,
fixed column order, no timestamps).  --verify recomputes both artefacts and
diffs them against the stored files, so a rerun on an unchanged specimen is a
byte-for-byte no-op.

Emits:
  reverse/evidence/patch_mechanisms_1dff0.csv
  reverse/evidence/thread_context_map.json
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Mapping, Sequence

import capstone
import pefile
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

sys.path.insert(0, str(Path(__file__).resolve().parent))

import common  # noqa: E402  (the path bootstrap has to run before the import)

SCHEMA_CSV: Final[str] = "adhesive-dumper.patch-mechanisms-1dff0/1"
SCHEMA_JSON: Final[str] = "adhesive-dumper.thread-context-map/1"
MODE: Final[str] = "static file parsing only, the specimen is never loaded or executed"

SPECIMEN_RELATIVE: Final[str] = "reverse/adhesive.dll"
SPECIMEN_SHA256: Final[str] = "91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e"

CSV_FIELDS: Final[tuple[str, ...]] = (
    "mechanism",
    "RVA",
    "fn",
    "target_expr",
    "caller_rvas",
    "activation_cond",
    "status",
    "confidence",
)

# --------------------------------------------------------------------------- #
# Subjects and constants
# --------------------------------------------------------------------------- #

REDIRECT_RVA: Final[int] = 0x1DFF0
ORCHESTRATOR_RVA: Final[int] = 0x1E360
PATCHER_RVA: Final[int] = 0x1E270
BUILDER_RVA: Final[int] = 0x1E590
REGISTRAR_RVA: Final[int] = 0x1DCF0
ARENA_RVA: Final[int] = 0x1D280

SUBJECT_RVAS: Final[tuple[int, ...]] = (
    REDIRECT_RVA,
    ORCHESTRATOR_RVA,
    PATCHER_RVA,
    BUILDER_RVA,
)

CALLER_ALL_RVA: Final[int] = 0x1E400
CALLER_ONE_RVA: Final[int] = 0x1E4F6
CALLER_ALL_PATCH_RVA: Final[int] = 0x1E425
CALLER_ONE_PATCH_RVA: Final[int] = 0x1E4FD

THUNK_SNAPSHOT_RVA: Final[int] = 0x2BED400
THUNK_FIRST_RVA: Final[int] = 0x2BED410
THUNK_NEXT_RVA: Final[int] = 0x2BED420
COOKIE_CHECK_RVA: Final[int] = 0x2AB3500

RECORD_TABLE_VA: Final[int] = 0x1830D44F8
RECORD_COUNT_VA: Final[int] = 0x1830D4508
HEAP_HANDLE_VA: Final[int] = 0x1830D44F0
SPIN_LOCK_VA: Final[int] = 0x1830D44E8
COOKIE_VA: Final[int] = 0x1830B9140

IAT_SNAPSHOT: Final[int] = 0x2E4D290
IAT_FIRST: Final[int] = 0x2E4D5C8
IAT_NEXT: Final[int] = 0x2E4D5D0
IAT_OPEN_THREAD: Final[int] = 0x2E4D4C8
IAT_SUSPEND_THREAD: Final[int] = 0x2E4D5A0
IAT_RESUME_THREAD: Final[int] = 0x2E4D538
IAT_GET_CONTEXT: Final[int] = 0x2E4D400
IAT_SET_CONTEXT: Final[int] = 0x2E4D570
IAT_CLOSE_HANDLE: Final[int] = 0x2E4D228
IAT_HEAP_ALLOC: Final[int] = 0x2E4D410
IAT_HEAP_REALLOC: Final[int] = 0x2E4D428
IAT_HEAP_FREE: Final[int] = 0x2E4D420
IAT_GET_PID: Final[int] = 0x2E4D320
IAT_GET_TID: Final[int] = 0x2E4D330

RECORD_STRIDE: Final[int] = 0x38
RECORD_FLAG_OFFSET: Final[int] = 0x20
RECORD_COUNT_OFFSET: Final[int] = 0x24
RECORD_MATCH_LIST_OFFSET: Final[int] = 0x28
RECORD_TARGET_LIST_OFFSET: Final[int] = 0x30
RECORD_ANCHOR_OFFSET: Final[int] = 0x00
RECORD_IMAGE_BASE_OFFSET: Final[int] = 0x10

FLAG_SKIP: Final[int] = 0x02
FLAG_PATCHED: Final[int] = 0x04
FLAG_TWO_SLOT: Final[int] = 0x01
PATCH_FLAG_MASK: Final[int] = 0x06

LIST_COUNT_MASK: Final[int] = 0x0F
LIST_ENTRY_CAP: Final[int] = 8
LIST_CAPACITY_BYTES: Final[int] = 8
WINDOW_CAP: Final[int] = 0x32

CONTEXT_FLAGS_VALUE: Final[int] = 0x00100001
CONTEXT_CONTROL_FLAG: Final[int] = 0x00100000
CONTEXT_CONTEXTFLAGS_OFFSET: Final[int] = 0x30
CONTEXT_RIP_OFFSET: Final[int] = 0xF8
CONTEXT_SIZE: Final[int] = 0x4D0
FRAME_SIZE: Final[int] = 0x508
CONTEXT_STACK_OFFSET: Final[int] = 0x30
COOKIE_STACK_OFFSET: Final[int] = 0x500
THREADENTRY32_SIZE: Final[int] = 0x1C
THREADENTRY32_MIN_SIZE: Final[int] = 0x10
THREADENTRY32_TID_OFFSET: Final[int] = 0x08
THREADENTRY32_PID_OFFSET: Final[int] = 0x0C

OPEN_THREAD_ACCESS: Final[int] = 0x5A
OPEN_THREAD_ACCESS_PARTS: Final[tuple[tuple[int, str], ...]] = (
    (0x0002, "THREAD_SUSPEND_RESUME"),
    (0x0008, "THREAD_GET_CONTEXT"),
    (0x0010, "THREAD_SET_CONTEXT"),
    (0x0040, "THREAD_QUERY_INFORMATION"),
)
SNAPSHOT_FLAG: Final[int] = 0x00000004
INITIAL_CAPACITY_ENTRIES: Final[int] = 0x80
INITIAL_CAPACITY_BYTES: Final[int] = 0x200
ENTRY_SIZE_BYTES: Final[int] = 4

ALL_RECORDS_SENTINEL: Final[int] = -1

# Symbolic expressions, shared verbatim by the csv and the json output.
EXPR_RECORD: Final[str] = "rec = *(qword *)(0x1830D44F8) + index * 0x38"
EXPR_CONTEXT_BASE: Final[str] = "ctx = rsp + 0x30"
EXPR_CONTEXT_RIP: Final[str] = "ctx + 0xF8, reached as [rsp + 0x128]"
EXPR_MATCH: Final[str] = "rec + 0x00 + rec[0x28][i] == ctx + 0xF8"
EXPR_TARGET: Final[str] = "rec + 0x10 + rec[0x30][i]"
EXPR_ENTRY_OFFSET: Final[str] = "rec[0x28][i], byte built as the instruction start offset from rec + 0x00"
EXPR_ENTRY_TARGET: Final[str] = "rec[0x30][i], byte built as the window cursor past that instruction"
EXPR_THREAD_ID: Final[str] = "out.array[out.index], a dword thread identifier"
EXPR_RECORD_INDEX: Final[str] = "edx, the record index, or -1 for every record"

CONFIDENCE_SCALE: Final[Mapping[str, str]] = {
    "HIGH": "an instruction, an immediate or a directory entry settles it",
    "MEDIUM": "derived from the file but conditional on one run time property",
    "LOW": "the mechanism is known, the deciding instance data is absent from the file",
    "OPEN": "not decidable from the file alone, carried as an open question",
}

# The only three status values the table uses, matching the sibling mechanism
# tables: an observed structure, a proven absence, and an unresolved reference.
OBSERVED: Final[str] = "OBSERVED"
ABSENT: Final[str] = "ABSENT"
ASYMMETRIC: Final[str] = "ASYMMETRIC"
UNRESOLVED: Final[str] = "UNRESOLVED"

NOT_STATIC: Final[str] = "none_static"
CALLERS: Final[str] = f"{common.hexs(CALLER_ALL_RVA)};{common.hexs(CALLER_ONE_RVA)}"
SUBJECT_FN: Final[str] = "0x1DFF0-0x1E26A"
ORCHESTRATOR_FN: Final[str] = "0x1E360-0x1E583"
PATCHER_FN: Final[str] = "0x1E270-0x1E357"
BUILDER_FN: Final[str] = "0x1E590-0x1E9D0"
REGISTRAR_FN: Final[str] = "0x1DCF0-0x1DFE1"

_MASK64: Final[int] = (1 << 64) - 1
_MASK32: Final[int] = (1 << 32) - 1


def _immediate_matches(observed: int, expected: int) -> bool:
    """Compare immediates across the zero extension a 32 bit form performs."""
    if (observed & _MASK64) == (expected & _MASK64):
        return True
    return (observed & _MASK32) == (expected & _MASK32)


# --------------------------------------------------------------------------- #
# Disassembly helpers
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Insn:
    """One decoded instruction, reduced to the facts the evidence set needs."""

    rva: int
    size: int
    mnemonic: str
    rip_targets: tuple[int, ...]
    mem_disps: tuple[int, ...]
    mem_sizes: tuple[int, ...]
    immediates: tuple[int, ...]
    operand_registers: tuple[str, ...]
    call_target: int | None
    branch_target: int | None

    @property
    def end(self) -> int:
        return self.rva + self.size


def _decode(pe: pefile.PE, md: capstone.Cs, start_rva: int, size: int) -> tuple[Insn, ...]:
    data = common.read_rva(pe, start_rva, size)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    decoded: list[Insn] = []
    for ins in md.disasm(data, image_base + start_rva):
        rip_targets: list[int] = []
        mem_disps: list[int] = []
        mem_sizes: list[int] = []
        immediates: list[int] = []
        operand_registers: list[str] = []
        call_target: int | None = None
        branch_target: int | None = None
        for operand in ins.operands:
            if operand.type == X86_OP_IMM:
                immediates.append(operand.imm)
                if ins.mnemonic in ("call", "jmp") or ins.mnemonic.startswith("j"):
                    target = operand.imm - image_base
                    if ins.mnemonic == "call":
                        call_target = target
                    else:
                        branch_target = target
            elif operand.type == X86_OP_REG:
                operand_registers.append(ins.reg_name(operand.reg))
            if operand.type == X86_OP_MEM:
                mem_disps.append(operand.mem.disp)
                mem_sizes.append(operand.size)
                if operand.mem.base == X86_REG_RIP:
                    rip_targets.append(ins.address + ins.size + operand.mem.disp - image_base)
        decoded.append(
            Insn(
                rva=ins.address - image_base,
                size=ins.size,
                mnemonic=ins.mnemonic.split()[-1],
                rip_targets=tuple(rip_targets),
                mem_disps=tuple(mem_disps),
                mem_sizes=tuple(mem_sizes),
                immediates=tuple(immediates),
                operand_registers=tuple(operand_registers),
                call_target=call_target,
                branch_target=branch_target,
            )
        )
    return tuple(decoded)


def _make_md() -> capstone.Cs:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    return md


_PDATA: list[tuple[tuple[int, int, int], ...]] = []


def _pdata(pe: pefile.PE) -> tuple[tuple[int, int, int], ...]:
    """The exception directory, parsed once per run."""
    if not _PDATA:
        _PDATA.append(runtime_functions(pe))
    return _PDATA[0]


def runtime_functions(pe: pefile.PE) -> tuple[tuple[int, int, int], ...]:
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[common.EXCEPTION_DIRECTORY_INDEX]
    blob = common.read_rva(pe, int(directory.VirtualAddress), int(directory.Size))
    return tuple(sorted(struct.iter_unpack("<III", blob)))


def function_bounds(pe: pefile.PE, rva: int) -> tuple[int, int, int]:
    """Resolve the exception directory record that covers rva."""
    for begin, end, unwind in _pdata(pe):
        if begin <= rva < end:
            return begin, end, unwind
    raise KeyError(common.hexs(rva))


def instruction_at(insns: Sequence[Insn], rva: int) -> Insn | None:
    for insn in insns:
        if insn.rva == rva:
            return insn
    return None


def resolve_iat(pe: pefile.PE) -> dict[int, str]:
    """Import address table slots, keyed by rva, as dll!symbol."""
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    table: dict[int, str] = {}
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = descriptor.dll.decode("ascii", errors="replace")
        for entry in descriptor.imports:
            name = entry.name.decode("ascii", errors="replace") if entry.name else f"ordinal_{entry.ordinal}"
            table[int(entry.address) - image_base] = f"{dll}!{name}"
    return table


def access_decomposition(value: int, table: Sequence[tuple[int, str]]) -> list[str]:
    return [name for mask, name in table if value & mask]


# --------------------------------------------------------------------------- #
# Anchor table
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Anchor:
    """One claim about one instruction, re-verified against the file every run."""

    name: str
    rva: int
    mnemonic: str
    description: str
    rip_target: int | None = None
    mem_disp: int | None = None
    mem_size: int | None = None
    imm: int | None = None
    call_target: int | None = None
    branch_target: int | None = None
    operand_registers: tuple[str, ...] | None = None


def _snapshot(name: str, rva: int, mnemonic: str, description: str, **kw: Any) -> Anchor:
    return Anchor(name=name, rva=rva, mnemonic=mnemonic, description=description, **kw)


ANCHORS: Final[tuple[Anchor, ...]] = (
    # ---- frame and out-parameter zeroing --------------------------------- #
    _snapshot("frame_reserve", 0x1DFFC, "sub", "the frame is sized for one CONTEXT plus the cookie"),
    _snapshot("out_zero_store", 0x1E01F, "movups", "the sixteen byte out block is zeroed on entry", mem_disp=0, mem_size=16),
    _snapshot("out_zero_source", 0x1E01C, "xorps", "the zeroing source is a cleared vector register"),
    _snapshot("cookie_load", 0x1E00A, "mov", "the stack cookie is read from the guard global", rip_target=COOKIE_VA - 0x180000000, mem_size=8),
    _snapshot("cookie_check", 0x1E250, "call", "the cookie is verified before the epilogue", call_target=COOKIE_CHECK_RVA),
    # ---- thread enumeration ---------------------------------------------- #
    _snapshot("snapshot_flag", 0x1E022, "mov", "the snapshot is requested for threads only", imm=SNAPSHOT_FLAG),
    _snapshot("snapshot_pid", 0x1E027, "xor", "the snapshot process identifier is zero, meaning every process"),
    _snapshot("snapshot_call", 0x1E029, "call", "the snapshot is taken", call_target=THUNK_SNAPSHOT_RVA),
    _snapshot("snapshot_invalid", 0x1E02E, "cmp", "the invalid handle value is rejected", imm=-1),
    _snapshot("snapshot_invalid_branch", 0x1E032, "je", "an invalid snapshot skips the whole mechanism", branch_target=0x1E0C0),
    _snapshot("entry_size_init", 0x1E03B, "mov", "the thread entry structure size is armed before the first read", imm=THREADENTRY32_SIZE),
    _snapshot("first_call", 0x1E04B, "call", "the first thread entry is read", call_target=THUNK_FIRST_RVA),
    _snapshot("first_failed", 0x1E050, "test", "the first read result decides whether enumeration starts"),
    _snapshot("entry_size_gate", 0x1E054, "cmp", "a returned structure smaller than the offset window is rejected", mem_disp=CONTEXT_STACK_OFFSET, mem_size=4, imm=THREADENTRY32_MIN_SIZE),
    _snapshot("entry_size_branch", 0x1E059, "jb", "a rejected structure skips the thread", branch_target=0x1E1C7),
    _snapshot("owner_pid_read", 0x1E05F, "mov", "the owner process identifier is read at structure offset 0x0C", mem_disp=0x3C, mem_size=4),
    _snapshot("owner_pid_call", 0x1E063, "call", "the current process identifier is read"),
    _snapshot("owner_pid_filter", 0x1E069, "cmp", "a foreign process is dropped from the list"),
    _snapshot("owner_pid_branch", 0x1E06B, "jne", "a foreign process skips the thread", branch_target=0x1E1C7),
    _snapshot("thread_id_read", 0x1E071, "mov", "the thread identifier is read at structure offset 0x08", mem_disp=0x38, mem_size=4),
    _snapshot("thread_id_call", 0x1E075, "call", "the current thread identifier is read"),
    _snapshot("self_exclusion", 0x1E07B, "cmp", "the calling thread itself is dropped from the list"),
    _snapshot("self_exclusion_branch", 0x1E07D, "je", "the calling thread skips itself", branch_target=0x1E1C7),
    # ---- out block population -------------------------------------------- #
    _snapshot("array_load", 0x1E083, "mov", "the identifier array pointer is loaded", mem_disp=0, mem_size=8),
    _snapshot("array_capacity_init", 0x1E08F, "mov", "the initial capacity is one hundred and twenty eight entries", mem_disp=8, mem_size=4, imm=INITIAL_CAPACITY_ENTRIES),
    _snapshot("array_heap", 0x1E096, "mov", "the identifier array is taken from the shared process heap", rip_target=HEAP_HANDLE_VA - 0x180000000, mem_size=8),
    _snapshot("array_alloc_bytes", 0x1E09D, "mov", "the first allocation is capacity times four bytes", imm=INITIAL_CAPACITY_BYTES),
    _snapshot("array_alloc_call", 0x1E0A5, "call", "the identifier array is allocated"),
    _snapshot("array_store", 0x1E0AB, "mov", "the allocation result is published into the out block", mem_disp=0, mem_size=8),
    _snapshot("array_capacity_check", 0x1E187, "cmp", "the append is refused once the count reaches the capacity", mem_disp=0x0C, mem_size=4),
    _snapshot("array_capacity_branch", 0x1E18B, "jb", "the append proceeds while the count is below the capacity", branch_target=0x1E1B5),
    _snapshot("array_grow_bytes", 0x1E18D, "add", "the growth byte count is the capacity doubled"),
    _snapshot("array_grow_scale", 0x1E190, "shl", "the growth byte count is scaled by the four byte entry size"),
    _snapshot("array_grow_call", 0x1E1A0, "call", "the identifier array is grown"),
    _snapshot("array_capacity_double", 0x1E1AF, "shl", "the stored capacity is doubled after a growth", mem_disp=8, mem_size=4),
    _snapshot("array_count_read", 0x1E1B9, "mov", "the live entry count is read for the append", mem_disp=0x0C, mem_size=4),
    _snapshot("array_count_write", 0x1E1C0, "mov", "the entry count is incremented", mem_disp=0x0C, mem_size=4),
    _snapshot("array_append", 0x1E1C4, "mov", "the thread identifier is appended", mem_disp=0, mem_size=4),
    _snapshot("entry_size_rearm", 0x1E1C7, "mov", "the structure size is re-armed before every next call", imm=THREADENTRY32_SIZE),
    _snapshot("next_call", 0x1E1D7, "call", "the next thread entry is read", call_target=THUNK_NEXT_RVA),
    _snapshot("next_loop", 0x1E1DC, "jmp", "enumeration re-tests the iteration result"),
    _snapshot("snapshot_close", 0x1E0BA, "call", "the snapshot handle is closed"),
    # ---- empty list guards ----------------------------------------------- #
    _snapshot("list_null_guard", 0x1E0C0, "cmp", "an unpublished array ends the mechanism", mem_disp=0, mem_size=8),
    _snapshot("list_null_branch", 0x1E0C4, "je", "a null array returns immediately", branch_target=0x1E245),
    _snapshot("list_count_guard", 0x1E0CA, "cmp", "an empty array ends the mechanism", mem_disp=0x0C, mem_size=4),
    _snapshot("list_count_branch", 0x1E0CE, "je", "an empty list returns immediately", branch_target=0x1E245),
    # ---- index and limit derivation -------------------------------------- #
    _snapshot("index_argument", 0x1E0D7, "mov", "the record index argument is loaded from the frame", mem_disp=0x2C, mem_size=4),
    _snapshot("limit_base", 0x1E0DB, "mov", "the exclusive limit starts from the index argument"),
    _snapshot("limit_increment", 0x1E0DD, "inc", "the exclusive limit is the index argument plus one"),
    _snapshot("start_index", 0x1E0DF, "mov", "the first scanned record is the index argument"),
    _snapshot("start_index_sentinel", 0x1E0E2, "cmove", "the sentinel argument folds the first scanned record to zero"),
    # ---- per thread suspend and context read ------------------------------ #
    _snapshot("thread_id_load", 0x1E0E9, "mov", "the thread identifier is loaded into the third argument register", operand_registers=("r8d",)),
    _snapshot("open_access", 0x1E0ED, "mov", "the requested access is the four rights the sequence needs", imm=OPEN_THREAD_ACCESS, operand_registers=("ecx",)),
    _snapshot("open_inherit", 0x1E0F2, "xor", "the handle is requested non inheritable", operand_registers=("edx", "edx")),
    _snapshot("open_call", 0x1E0F4, "call", "the thread is opened"),
    _snapshot("open_failed", 0x1E0FD, "je", "an unopenable thread is skipped without any other effect", branch_target=0x1E236),
    _snapshot("suspend_call", 0x1E109, "call", "the thread is suspended"),
    _snapshot("context_flags_store", 0x1E10F, "mov", "the context request mask is written into the structure", mem_disp=0x60, mem_size=4, imm=CONTEXT_FLAGS_VALUE),
    _snapshot("context_buffer", 0x1E117, "lea", "the context structure is the frame buffer"),
    _snapshot("context_get", 0x1E11F, "call", "the thread context is read"),
    _snapshot("context_get_failed", 0x1E127, "je", "an unreadable context skips the record scan for that thread", branch_target=0x1E22D),
    # ---- limit resolution -------------------------------------------------- #
    _snapshot("limit_from_argument", 0x1E12D, "mov", "the exclusive limit falls back to the index argument plus one"),
    _snapshot("limit_sentinel_test", 0x1E12F, "cmp", "the sentinel argument is recognised", mem_disp=0x2C, mem_size=4, imm=-1),
    _snapshot("limit_sentinel_load", 0x1E136, "mov", "the sentinel resolves the limit to the live record count", rip_target=RECORD_COUNT_VA - 0x180000000, mem_size=4),
    _snapshot("limit_range_check", 0x1E13C, "cmp", "a start index at or above the limit skips the record scan"),
    _snapshot("limit_range_branch", 0x1E13F, "jae", "an out of range start index closes the handle", branch_target=0x1E22D),
    _snapshot("limit_hold", 0x1E145, "mov", "the exclusive limit is kept in a register for the loop"),
    # ---- record scan ------------------------------------------------------- #
    _snapshot("record_table_load", 0x1E148, "mov", "the record array is loaded once per thread", rip_target=RECORD_TABLE_VA - 0x180000000, mem_size=8),
    _snapshot("record_index_init", 0x1E14F, "mov", "the record cursor starts at the first scanned record"),
    _snapshot("record_stride", 0x1E152, "imul", "the record offset is the cursor times the record stride", imm=RECORD_STRIDE),
    _snapshot("record_skip_test", 0x1E156, "test", "the skip flag bit hides the record from the rewrite", mem_disp=RECORD_FLAG_OFFSET, mem_size=1, imm=FLAG_SKIP),
    _snapshot("record_skip_branch", 0x1E15B, "jne", "a skipped record advances the cursor", branch_target=0x1E221),
    _snapshot("record_count_load", 0x1E161, "mov", "the entry count dword is read", mem_disp=RECORD_COUNT_OFFSET, mem_size=4),
    _snapshot("record_count_mask", 0x1E165, "and", "only the low nibble of the count is used", imm=LIST_COUNT_MASK),
    _snapshot("record_count_zero", 0x1E169, "je", "a zero nibble makes the record inert", branch_target=0x1E221),
    _snapshot("record_base", 0x1E16F, "lea", "the record base is kept for the two list loads"),
    _snapshot("context_rip_read", 0x1E173, "mov", "the saved instruction pointer is loaded per record", mem_disp=0x128, mem_size=8),
    _snapshot("record_anchor", 0x1E17B, "mov", "the record anchor is loaded", mem_disp=RECORD_ANCHOR_OFFSET, mem_size=8),
    _snapshot("entry_index_init", 0x1E17E, "xor", "the entry cursor starts at zero"),
    # ---- entry loop -------------------------------------------------------- #
    _snapshot("entry_advance", 0x1E1E1, "inc", "the entry cursor advances"),
    _snapshot("entry_end", 0x1E1E4, "cmp", "the entry cursor is compared with the masked count"),
    _snapshot("entry_end_branch", 0x1E1E7, "je", "the record is abandoned when the cursor reaches the count", branch_target=0x1E221),
    _snapshot("match_byte_load", 0x1E1E9, "movzx", "the match byte is read from the 0x28 list", mem_disp=RECORD_MATCH_LIST_OFFSET, mem_size=1),
    _snapshot("match_byte_add", 0x1E1EF, "add", "the match byte is added to the record anchor"),
    _snapshot("match_compare", 0x1E1F2, "cmp", "the reconstructed address is compared with the saved instruction pointer"),
    _snapshot("match_miss", 0x1E1F5, "jne", "a miss advances the entry cursor", branch_target=0x1E1E1),
    _snapshot("target_byte_load", 0x1E1F7, "movzx", "the target byte is read from the 0x30 list", mem_disp=RECORD_TARGET_LIST_OFFSET, mem_size=1),
    _snapshot("target_byte_add", 0x1E1FD, "add", "the target byte is added to the rebuilt image base", mem_disp=RECORD_IMAGE_BASE_OFFSET, mem_size=8),
    _snapshot("target_zero", 0x1E202, "je", "a zero result abandons the record", branch_target=0x1E221),
    _snapshot("context_rip_write", 0x1E204, "mov", "the replacement instruction pointer is written into the frame copy", mem_disp=0x128, mem_size=8),
    _snapshot("context_set", 0x1E214, "call", "the rewritten context is applied to the thread"),
    _snapshot("record_table_reload", 0x1E21A, "mov", "the record array pointer is refreshed after every apply", rip_target=RECORD_TABLE_VA - 0x180000000, mem_size=8),
    _snapshot("record_advance", 0x1E221, "inc", "the record cursor advances"),
    _snapshot("record_end", 0x1E224, "cmp", "the record cursor is compared with the exclusive limit"),
    _snapshot("record_end_branch", 0x1E227, "jne", "the scan repeats until the limit is reached", branch_target=0x1E152),
    # ---- per thread teardown ------------------------------------------------ #
    _snapshot("thread_close", 0x1E230, "call", "the thread handle is closed"),
    _snapshot("thread_advance", 0x1E236, "inc", "the thread cursor advances"),
    _snapshot("thread_count", 0x1E239, "mov", "the identifier count drives the thread loop"),
    _snapshot("thread_end", 0x1E23C, "cmp", "the thread cursor is compared with the identifier count"),
    _snapshot("thread_end_branch", 0x1E23F, "jb", "the next thread is opened until the count is reached", branch_target=0x1E0E6),
    # ---- orchestrator lock and the two call sites -------------------------- #
    _snapshot("lock_take", 0x1E39A, "cmpxchg", "the orchestrator takes the shared once flag", rip_target=SPIN_LOCK_VA - 0x180000000, mem_size=4),
    _snapshot("lock_drop", 0x1E562, "xchg", "the orchestrator releases the shared once flag", rip_target=SPIN_LOCK_VA - 0x180000000, mem_size=4),
    _snapshot("lock_spin", 0x1E38F, "call", "a losing lock contender sleeps and retries"),
    _snapshot("branch_select", 0x1E3B8, "test", "a null argument selects the every record path"),
    _snapshot("single_path", 0x1E3BB, "jne", "a non null argument selects the single record path"),
    _snapshot("count_guard_bulk", 0x1E3C1, "mov", "the live record count is read on the bulk path", rip_target=RECORD_COUNT_VA - 0x180000000, mem_size=4),
    _snapshot("first_usable_scan", 0x1E3E0, "test", "the bulk path looks for the first record without the skip bit", mem_disp=RECORD_FLAG_OFFSET, mem_size=1, imm=FLAG_SKIP),
    _snapshot("call_all_buffer", 0x1E3F6, "lea", "the out block of the bulk path is the orchestrator frame"),
    _snapshot("call_all_sentinel", 0x1E3FB, "mov", "the bulk path passes the every record sentinel", imm=ALL_RECORDS_SENTINEL),
    _snapshot("call_all", CALLER_ALL_RVA, "call", "first direct call site of the redirect walker", call_target=REDIRECT_RVA),
    _snapshot("call_all_result_dropped", 0x1E405, "mov", "the bulk path discards any return value"),
    _snapshot("call_all_before_patch", CALLER_ALL_PATCH_RVA, "call", "the inline patcher runs after the redirect on the bulk path", call_target=PATCHER_RVA),
    _snapshot("out_block_read", 0x1E449, "mov", "the out block is read back by the caller", mem_disp=0x28, mem_size=8),
    _snapshot("resume_loop_count", 0x1E45C, "test", "an empty identifier list skips the resume pass"),
    _snapshot("resume_open", 0x1E473, "call", "the resume pass opens each collected thread again", rip_target=IAT_OPEN_THREAD),
    _snapshot("resume_call", 0x1E484, "call", "the resume pass is the only place a suspend is undone", rip_target=IAT_RESUME_THREAD),
    _snapshot("resume_close", 0x1E48D, "call", "the resume handle is closed immediately"),
    _snapshot("lookup_count", 0x1E4A0, "mov", "the single path reads the live record count", rip_target=RECORD_COUNT_VA - 0x180000000, mem_size=4),
    _snapshot("lookup_compare", 0x1E4C1, "cmp", "the single path matches the argument against the record anchor", mem_disp=RECORD_ANCHOR_OFFSET, mem_size=8),
    _snapshot("lookup_dead_guard", 0x1E4D4, "cmp", "the single path tests the found index against the sentinel", imm=-1),
    _snapshot("lookup_dead_branch", 0x1E4D7, "je", "the single path sentinel branch is unreachable after a found index", branch_target=0x1E560),
    _snapshot("lookup_stride", 0x1E4DF, "imul", "the single path address probe uses the record stride", imm=RECORD_STRIDE),
    _snapshot("lookup_skip_test", 0x1E4E8, "test", "the single path refuses a record with the skip bit set", mem_disp=RECORD_FLAG_OFFSET, mem_size=1, imm=FLAG_SKIP),
    _snapshot("call_one_buffer", 0x1E4EF, "lea", "the out block of the single path is the orchestrator frame"),
    _snapshot("call_one_index", 0x1E4F4, "mov", "the single path passes the found record index"),
    _snapshot("call_one", CALLER_ONE_RVA, "call", "second direct call site of the redirect walker", call_target=REDIRECT_RVA),
    _snapshot("call_one_result_dropped", 0x1E4FB, "mov", "the single path discards any return value"),
    _snapshot("call_one_before_patch", CALLER_ONE_PATCH_RVA, "call", "the inline patcher runs after the redirect on the single path", call_target=PATCHER_RVA),
    _snapshot("resume_open_second", 0x1E526, "call", "the second resume pass opens each collected thread again", rip_target=IAT_OPEN_THREAD),
    _snapshot("resume_call_second", 0x1E537, "call", "the second resume pass is the only place a suspend is undone", rip_target=IAT_RESUME_THREAD),
    _snapshot("out_block_free", 0x1E55A, "call", "the caller frees the identifier array from the shared heap", rip_target=IAT_HEAP_FREE),
    _snapshot("out_block_free_heap", 0x1E54E, "mov", "the free uses the same shared process heap", rip_target=HEAP_HANDLE_VA - 0x180000000, mem_size=8),
    # ---- inline patcher flag write ----------------------------------------- #
    _snapshot("patch_flag_write", 0x1E336, "or", "the patcher raises the skip and patched bits together through a pointer to the flag byte", mem_disp=0, mem_size=1, imm=PATCH_FLAG_MASK),
    # ---- list builder provenance ------------------------------------------- #
    _snapshot("window_anchor", 0x1E61A, "add", "the window cursor is biased by the anchor", mem_disp=0, mem_size=8),
    _snapshot("window_length_agree", 0x1E829, "cmp", "the decoded length must match the opcode derived length"),
    _snapshot("window_advance", 0x1E82D, "add", "the window cursor advances by the instruction length"),
    _snapshot("window_cap", 0x1E82F, "cmp", "the scanned window is capped", imm=WINDOW_CAP),
    _snapshot("entry_count_load", 0x1E834, "mov", "the builder keeps its entry counter in the descriptor", mem_disp=RECORD_COUNT_OFFSET, mem_size=4),
    _snapshot("entry_cap", 0x1E837, "cmp", "the builder refuses a ninth entry", imm=LIST_ENTRY_CAP),
    _snapshot("entry_abandon", 0x1E83B, "jb", "storing continues while the counter is below the cap"),
    _snapshot("match_list_store", 0x1E844, "mov", "the instruction start offset is appended to the 0x28 list", mem_disp=RECORD_MATCH_LIST_OFFSET, mem_size=1),
    _snapshot("target_list_store", 0x1E849, "mov", "the window cursor past the instruction is appended to the 0x30 list", mem_disp=RECORD_TARGET_LIST_OFFSET, mem_size=1),
    _snapshot("entry_count_store", 0x1E850, "mov", "the entry counter is incremented", mem_disp=RECORD_COUNT_OFFSET, mem_size=4),
    _snapshot("match_cursor_advance", 0x1E85E, "add", "the match cursor advances by the instruction length", mem_disp=0x60, mem_size=1),
    _snapshot("target_cursor_capture", 0x1E863, "mov", "the target cursor is captured after the advance"),
)


def verify_anchors(pe: pefile.PE, md: capstone.Cs) -> list[dict[str, Any]]:
    """Re-verify every anchor against the file; the outcome becomes the invariants."""
    cache: dict[tuple[int, int], tuple[Insn, ...]] = {}
    results: list[dict[str, Any]] = []
    for anchor in ANCHORS:
        begin, end, unwind = function_bounds(pe, anchor.rva)
        key = (begin, end)
        if key not in cache:
            cache[key] = _decode(pe, md, begin, end - begin)
        insn = instruction_at(cache[key], anchor.rva)
        problems: list[str] = []
        if insn is None:
            problems.append("no instruction decodes at this rva")
        else:
            if insn.mnemonic != anchor.mnemonic:
                problems.append(f"mnemonic {insn.mnemonic} != {anchor.mnemonic}")
            if anchor.rip_target is not None and anchor.rip_target not in insn.rip_targets:
                problems.append(f"rip target {common.hexs(anchor.rip_target)} not reached")
            if anchor.mem_disp is not None and insn.mem_disps[:1] != (anchor.mem_disp,):
                problems.append(f"memory displacement {anchor.mem_disp} not the first operand")
            if anchor.mem_size is not None and insn.mem_sizes[:1] != (anchor.mem_size,):
                problems.append(f"operand width {anchor.mem_size} not the first operand")
            if anchor.imm is not None:
                if not insn.immediates or not _immediate_matches(insn.immediates[0], anchor.imm):
                    shown = insn.immediates[0] if insn.immediates else None
                    problems.append(f"immediate {shown} != {anchor.imm}")
            if anchor.call_target is not None and insn.call_target != anchor.call_target:
                problems.append(f"call target {insn.call_target} != {anchor.call_target}")
            if anchor.branch_target is not None and insn.branch_target != anchor.branch_target:
                problems.append(f"branch target {insn.branch_target} != {anchor.branch_target}")
            if anchor.operand_registers is not None and insn.operand_registers != anchor.operand_registers:
                problems.append(
                    f"operands {insn.operand_registers} != {anchor.operand_registers}"
                )
        results.append(
            {
                "anchor": anchor.name,
                "site_rva": common.hexs(anchor.rva),
                "site_va": common.hexs(anchor.rva + int(pe.OPTIONAL_HEADER.ImageBase)),
                "function_rva": common.hexs(begin),
                "unwind_info_rva": common.hexs(unwind),
                "mnemonic": anchor.mnemonic,
                "description": anchor.description,
                "ok": not problems,
                "problem": None if not problems else "; ".join(problems),
            }
        )
    results.sort(key=lambda row: (int(row["site_rva"], 16), row["anchor"]))
    return results


# --------------------------------------------------------------------------- #
# Whole image reachability
# --------------------------------------------------------------------------- #


def direct_call_sites(pe: pefile.PE, section: common.Section, targets: frozenset[int]) -> list[int]:
    """Every relative call site in the section whose destination is in targets."""
    blob = common.read_rva(pe, section.virtual_address, section.raw_size)
    base = section.virtual_address
    sites: list[int] = []
    cursor = 0
    while True:
        index = blob.find(b"\xe8", cursor)
        if index < 0 or index + 5 > len(blob):
            break
        cursor = index + 1
        if base + index + 5 + struct.unpack_from("<i", blob, index + 1)[0] in targets:
            sites.append(base + index)
    sites.sort()
    return sites


def literal_occurrences(pe: pefile.PE, needle: bytes) -> list[int]:
    """Every offset of a byte pattern inside the raw code section."""
    section = _code_section(pe)
    blob = common.read_rva(pe, section.virtual_address, section.raw_size)
    base = section.virtual_address
    found: list[int] = []
    cursor = 0
    while True:
        index = blob.find(needle, cursor)
        if index < 0:
            break
        cursor = index + 1
        found.append(base + index)
    return found


def _code_section(pe: pefile.PE) -> common.Section:
    for section in common.sections(pe):
        if section.name == ".text":
            return section
    raise KeyError(".text")


def _is_rip_relative_modrm(byte: int) -> bool:
    """True for the eight ModRM bytes that encode a rip relative operand."""
    return (byte & 0xC7) == 0x05


def rip_relative_sites(pe: pefile.PE, section: common.Section, target: int) -> list[dict[str, Any]]:
    """Every rip relative displacement in the section that resolves to target.

    The filter reads the ModRM byte that precedes the four displacement bytes,
    which is the only encoding of a rip relative memory operand in 64 bit mode,
    and it reads the displacement directly, so a leaf function without an
    exception directory entry is covered as well.
    """
    blob = common.read_rva(pe, section.virtual_address, section.raw_size)
    base = section.virtual_address
    found: list[dict[str, Any]] = []
    for modrm in range(0x100):
        if not _is_rip_relative_modrm(modrm):
            continue
        needle = bytes((modrm,))
        cursor = 0
        while True:
            index = blob.find(needle, cursor)
            if index < 0 or index + 5 > len(blob):
                break
            cursor = index + 1
            disp = struct.unpack_from("<i", blob, index + 1)[0]
            field_end = base + index + 5
            if field_end + disp != target:
                continue
            found.append(
                {
                    "modrm_rva": common.hexs(base + index),
                    "resolved_rva": common.hexs(target),
                    "modrm": common.hexs(modrm),
                }
            )
    found.sort(key=lambda row: row["modrm_rva"])
    return found


def reachable_functions(pe: pefile.PE) -> dict[str, Any]:
    """Provenance of every reference to the subject function across the file."""
    section = _code_section(pe)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    calls = direct_call_sites(pe, section, frozenset({REDIRECT_RVA}))
    rip_refs = rip_relative_sites(pe, section, REDIRECT_RVA)
    rva32 = literal_occurrences(pe, struct.pack("<I", REDIRECT_RVA))
    va64 = literal_occurrences(pe, struct.pack("<Q", REDIRECT_RVA + image_base))

    # A four byte rva literal in the code section is a real pointer only when it
    # is not part of a longer operand.  The single hit here is the displacement
    # of a rip relative lea, recognised by the ModRM byte that precedes it, and
    # the displacement resolves to a different address, so the hit is a byte
    # coincidence rather than a reference.
    blob = common.read_rva(pe, section.virtual_address, section.raw_size)
    base = section.virtual_address
    classified: list[dict[str, Any]] = []
    for hit in rva32:
        offset = hit - base
        if offset >= 1 and _is_rip_relative_modrm(blob[offset - 1]):
            disp = struct.unpack_from("<i", blob, offset)[0]
            resolved = hit + 4 + disp
            classified.append(
                {
                    "site_rva": common.hexs(hit),
                    "is_pointer": False,
                    "is_rip_displacement": True,
                    "resolved_rva": common.hexs(resolved),
                    "note": "the literal is the rip relative displacement of the instruction that precedes it, and it resolves to a different address",
                }
            )
            continue
        classified.append(
            {
                "site_rva": common.hexs(hit),
                "is_pointer": True,
                "is_rip_displacement": False,
                "resolved_rva": None,
                "note": "the literal is not part of a rip relative displacement, so it is a bare pointer",
            }
        )

    pointer_sites = [row["site_rva"] for row in classified if row["is_pointer"]]
    return {
        "direct_call_sites": [common.hexs(site) for site in calls],
        "direct_call_site_count": len(calls),
        "rip_relative_reference_sites": rip_refs,
        "rip_relative_reference_count": len(rip_refs),
        "rva32_literal_sites": [common.hexs(hit) for hit in rva32],
        "rva32_literal_count": len(rva32),
        "rva32_literal_classification": classified,
        "va64_literal_sites": [common.hexs(hit) for hit in va64],
        "va64_literal_count": len(va64),
        "pointer_literal_sites": pointer_sites,
        "exception_directory_entries": sum(
            1 for begin, _, _ in runtime_functions(pe) if begin == REDIRECT_RVA
        ),
        "address_taken": bool(pointer_sites) or bool(va64) or bool(rip_refs),
    }


# --------------------------------------------------------------------------- #
# Mechanism table
# --------------------------------------------------------------------------- #


def _gate(*parts: str) -> str:
    return " AND ".join(part for part in parts if part) if parts else "unconditional"


def _predicate(rva: int, text: str) -> str:
    return f"{common.hexs(rva)}: {text}"


def build_mechanisms() -> list[dict[str, str]]:
    """The mechanism table, one row per audited step, in a fixed order."""
    rows: list[dict[str, str]] = [
        {
            "mechanism": "thread_snapshot_enumeration",
            "RVA": f"{common.hexs(0x1E022)};{common.hexs(0x1E027)};{common.hexs(0x1E029)}",
            "fn": SUBJECT_FN,
            "target_expr": "KERNEL32.dll!CreateToolhelp32Snapshot(dwFlags=TH32CS_SNAPTHREAD 0x4, dwProcessId=0) via the thunk at 0x2BED400",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E0D4, "enters the function, the out block is always zeroed first"),
                _predicate(0x1E0BA, "the snapshot handle is closed on every enumeration exit"),
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_snapshot_invalid_handle",
            "RVA": common.hexs(0x1E02E),
            "fn": SUBJECT_FN,
            "target_expr": "rax == 0xFFFFFFFFFFFFFFFF",
            "caller_rvas": CALLERS,
            "activation_cond": _predicate(0x1E032, "an invalid snapshot jumps past the enumeration and the thread pass"),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_snapshot_iteration",
            "RVA": f"{common.hexs(0x1E04B)};{common.hexs(0x1E1D7)}",
            "fn": SUBJECT_FN,
            "target_expr": "KERNEL32.dll!Thread32First and KERNEL32.dll!Thread32Next on a THREADENTRY32 at rsp+0x30, dwSize re-armed to 0x1C before every call",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E03B, "the structure size is armed before the first read"),
                _predicate(0x1E1C7, "the structure size is re-armed before every next call"),
                _predicate(0x1E050, "the loop condition is the return value of the previous read"),
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_entry_size_gate",
            "RVA": common.hexs(0x1E054),
            "fn": SUBJECT_FN,
            "target_expr": f"dword [rsp+0x30] >= {common.hexs(THREADENTRY32_MIN_SIZE)}",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E059, "a smaller reported structure drops the thread from the list entirely"),
                "the two identifiers the code reads live at structure offsets 0x08 and 0x0C",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_owner_process_filter",
            "RVA": f"{common.hexs(0x1E05F)};{common.hexs(0x1E063)};{common.hexs(0x1E069)}",
            "fn": SUBJECT_FN,
            "target_expr": "th32OwnerProcessID at structure offset 0x0C == KERNEL32.dll!GetCurrentProcessId()",
            "caller_rvas": CALLERS,
            "activation_cond": _predicate(0x1E06B, "a thread owned by another process is not appended"),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_self_exclusion",
            "RVA": f"{common.hexs(0x1E071)};{common.hexs(0x1E075)};{common.hexs(0x1E07B)}",
            "fn": SUBJECT_FN,
            "target_expr": "th32ThreadID at structure offset 0x08 != KERNEL32.dll!GetCurrentThreadId()",
            "caller_rvas": CALLERS,
            "activation_cond": _predicate(0x1E07D, "the calling thread is never suspended by its own walker"),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_id_array_alloc",
            "RVA": f"{common.hexs(0x1E08F)};{common.hexs(0x1E096)};{common.hexs(0x1E09D)};{common.hexs(0x1E0A5)};{common.hexs(0x1E0AB)}",
            "fn": SUBJECT_FN,
            "target_expr": f"KERNEL32.dll!HeapAlloc(heap=*(0x{HEAP_HANDLE_VA:X}), flags=0, bytes={common.hexs(INITIAL_CAPACITY_BYTES)}), published into rcx+0x00",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E089, "only the first accepted thread triggers the allocation"),
                _predicate(0x1E0AE, "a null allocation leaves the out block unpublished and the mechanism returns"),
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_id_array_grow",
            "RVA": f"{common.hexs(0x1E187)};{common.hexs(0x1E18D)};{common.hexs(0x1E190)};{common.hexs(0x1E1A0)};{common.hexs(0x1E1AF)}",
            "fn": SUBJECT_FN,
            "target_expr": f"KERNEL32.dll!HeapReAlloc(heap=*(0x{HEAP_HANDLE_VA:X}), flags=0, bytes=capacity*2*{common.hexs(ENTRY_SIZE_BYTES)})",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E18B, "the append is refused while count is below capacity"),
                _predicate(0x1E1A6, "a failed growth closes the snapshot and ends the mechanism"),
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_id_array_append",
            "RVA": f"{common.hexs(0x1E1B9)};{common.hexs(0x1E1BC)};{common.hexs(0x1E1C0)};{common.hexs(0x1E1C4)}",
            "fn": SUBJECT_FN,
            "target_expr": f"out.array[count++] = th32ThreadID, an element of {common.hexs(ENTRY_SIZE_BYTES)} bytes at rcx+0x00, rcx+0x08 capacity, rcx+0x0C count",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E0C0, "an unpublished array and an empty list both end the mechanism"),
                "the capacity comparison precedes every append, so the array never overruns",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "empty_list_guard",
            "RVA": f"{common.hexs(0x1E0C0)};{common.hexs(0x1E0CA)}",
            "fn": SUBJECT_FN,
            "target_expr": "rcx+0x00 != 0 AND rcx+0x0C != 0",
            "caller_rvas": CALLERS,
            "activation_cond": _predicate(0x1E0C4, "a null array or a zero count returns without opening a single thread"),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "record_index_sentinel",
            "RVA": f"{common.hexs(0x1E0D7)};{common.hexs(0x1E0DD)};{common.hexs(0x1E0E2)};{common.hexs(0x1E12F)};{common.hexs(0x1E136)}",
            "fn": SUBJECT_FN,
            "target_expr": f"{EXPR_RECORD_INDEX}; -1 folds the start index to 0 and the limit to *(dword *)(0x{RECORD_COUNT_VA:X})",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E0E2, "the conditional move fires only when index+1 wrapped to zero"),
                _predicate(0x1E134, "the count load is skipped unless the argument is the sentinel"),
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "record_index_range_check",
            "RVA": f"{common.hexs(0x1E13C)};{common.hexs(0x1E145)}",
            "fn": SUBJECT_FN,
            "target_expr": f"start_index < limit, where limit is index+1 or *(dword *)(0x{RECORD_COUNT_VA:X})",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E13F, "a start index at or above the limit closes the handle and skips the record scan"),
                "no other bound on the exclusive limit exists in the function",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_handle_open",
            "RVA": f"{common.hexs(0x1E0ED)};{common.hexs(0x1E0F2)};{common.hexs(0x1E0F4)}",
            "fn": SUBJECT_FN,
            "target_expr": "KERNEL32.dll!OpenThread(dwDesiredAccess=0x5A, bInheritHandle=FALSE, dwThreadId=out.array[i])",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E0FD, "a failed open advances the thread cursor with no other effect"),
                "0x5A decomposes into " + " + ".join(access_decomposition(OPEN_THREAD_ACCESS, OPEN_THREAD_ACCESS_PARTS)),
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_suspend",
            "RVA": common.hexs(0x1E109),
            "fn": SUBJECT_FN,
            "target_expr": "KERNEL32.dll!SuspendThread(handle), result not examined",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "reached for every successfully opened thread, unconditionally after the open test",
                "the suspend count is not read back or compared anywhere in the function",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "context_request_mask",
            "RVA": common.hexs(0x1E10F),
            "fn": SUBJECT_FN,
            "target_expr": f"[rsp + 0x60] = {common.hexs(CONTEXT_FLAGS_VALUE)}, the ContextFlags field at {EXPR_CONTEXT_BASE} plus {common.hexs(CONTEXT_CONTEXTFLAGS_OFFSET)}",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "written once per thread immediately before the context read",
                f"the value equals CONTEXT_CONTROL {common.hexs(CONTEXT_CONTROL_FLAG)} with the low bit set, so only the control fields are requested",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "context_buffer_layout",
            "RVA": f"{common.hexs(0x1E117)};{common.hexs(0x1E1FC)}",
            "fn": SUBJECT_FN,
            "target_expr": f"{EXPR_CONTEXT_BASE}, a {common.hexs(CONTEXT_SIZE)} byte structure, and the frame is {common.hexs(FRAME_SIZE)} bytes so structure plus cookie ends exactly at the cookie slot",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "the same frame slot holds the thread entry structure first and the context afterwards, never at the same time",
                _predicate(0x1E0DC, "enumeration completes before any context field is touched"),
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "context_get",
            "RVA": f"{common.hexs(0x1E11F)};{common.hexs(0x1E125)}",
            "fn": SUBJECT_FN,
            "target_expr": "KERNEL32.dll!GetThreadContext(handle, ctx)",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E127, "a failed read closes the handle and skips the record scan for that thread"),
                "the thread stays suspended on this branch, the resume belongs to the caller",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "context_rip_read",
            "RVA": common.hexs(0x1E173),
            "fn": SUBJECT_FN,
            "target_expr": EXPR_CONTEXT_RIP,
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "read once per record, after the skip and count gates have passed",
                "this is the only context field the function reads",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "record_table_scan",
            "RVA": f"{common.hexs(0x1E148)};{common.hexs(0x1E14F)};{common.hexs(0x1E152)}",
            "fn": SUBJECT_FN,
            "target_expr": f"{EXPR_RECORD}; the same global the inline patcher and the orchestrator walk",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E148, "loaded once per thread, before the record loop"),
                _predicate(0x1E21A, "reloaded after every applied context, so a growth during the walk cannot leave a stale pointer"),
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "record_skip_gate",
            "RVA": common.hexs(0x1E156),
            "fn": SUBJECT_FN,
            "target_expr": f"(rec + {common.hexs(RECORD_FLAG_OFFSET)}) & {common.hexs(FLAG_SKIP)}",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E15B, "a set skip bit advances the record cursor without touching the context"),
                "the same bit is what the inline patcher raises, so a patched record disappears from both mechanisms",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "record_entry_count_gate",
            "RVA": f"{common.hexs(0x1E161)};{common.hexs(0x1E165)};{common.hexs(0x1E169)}",
            "fn": SUBJECT_FN,
            "target_expr": f"(rec + {common.hexs(RECORD_COUNT_OFFSET)}) & {common.hexs(LIST_COUNT_MASK)}",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E169, "a zero nibble abandons the record before the first list load"),
                "the count is reduced to four bits, so a stored count above fifteen is indistinguishable from its low nibble",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "rip_match_reconstruction",
            "RVA": f"{common.hexs(0x1E1E9)};{common.hexs(0x1E1EF)};{common.hexs(0x1E1F2)}",
            "fn": SUBJECT_FN,
            "target_expr": f"{EXPR_MATCH}; {EXPR_ENTRY_OFFSET}",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E1F5, "equality against the saved instruction pointer must hold exactly"),
                "the byte is zero extended, so a match offset is an unsigned value in 0 to 255",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "rip_target_reconstruction",
            "RVA": f"{common.hexs(0x1E1F7)};{common.hexs(0x1E1FD)}",
            "fn": SUBJECT_FN,
            "target_expr": f"{EXPR_TARGET}; {EXPR_ENTRY_TARGET}",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "the two lists are indexed by the same cursor, so entry i of 0x28 always pairs with entry i of 0x30",
                "the target is the rebuilt image base plus the window cursor past the matched instruction, that is the continuation of the same relative position",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "rip_zero_target_gate",
            "RVA": common.hexs(0x1E202),
            "fn": SUBJECT_FN,
            "target_expr": f"({EXPR_TARGET}) != 0",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E202, "a zero sum abandons the whole record, not only the current entry"),
                "no separate test of the image base field exists, only the test of the sum",
            ),
            "status": OBSERVED,
            "confidence": "MEDIUM",
        },
        {
            "mechanism": "context_rip_write",
            "RVA": common.hexs(0x1E204),
            "fn": SUBJECT_FN,
            "target_expr": f"[rsp + 0x128] = {EXPR_TARGET}, the frame copy of CONTEXT.Rip",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "written before the apply, so the frame copy is updated whether or not the apply succeeds",
                "the next record reads this same slot, which chains a further redirect onto the new value",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "context_set",
            "RVA": common.hexs(0x1E214),
            "fn": SUBJECT_FN,
            "target_expr": "KERNEL32.dll!SetThreadContext(handle, ctx), result not examined",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "reached only after an exact instruction pointer match and a non zero target",
                "at most one apply per record, because the entry loop is abandoned on the way out of the match",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "context_entry_loop_single_shot",
            "RVA": f"{common.hexs(0x1E21A)};{common.hexs(0x1E221)}",
            "fn": SUBJECT_FN,
            "target_expr": "the match branch leaves through the record advance, not back into the entry cursor",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                _predicate(0x1E1E7, "a miss re-enters the entry loop"),
                "a hit falls through to the record advance, so a record contributes at most one apply per thread",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "record_chain_continuation",
            "RVA": f"{common.hexs(0x1E173)};{common.hexs(0x1E221)};{common.hexs(0x1E227)}",
            "fn": SUBJECT_FN,
            "target_expr": "the next record compares against the value the previous record wrote into the frame copy",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "the record loop keeps running after an apply, up to the exclusive limit",
                "the number of applies per thread is therefore bounded by the number of scanned records",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_handle_close",
            "RVA": f"{common.hexs(0x1E22D)};{common.hexs(0x1E230)};{common.hexs(0x1E236)};{common.hexs(0x1E23C)}",
            "fn": SUBJECT_FN,
            "target_expr": "KERNEL32.dll!CloseHandle(handle) on every path that opened a thread handle",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "the same register carries the snapshot handle first and the thread handles afterwards, and the snapshot is closed before any thread is opened",
                _predicate(0x1E23F, "the thread loop runs until the identifier count is reached"),
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_resume_inside_subject",
            "RVA": "none",
            "fn": SUBJECT_FN,
            "target_expr": "KERNEL32.dll!ResumeThread is not called anywhere between 0x1DFF0 and 0x1E26A",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "every thread this function suspends stays suspended when the function returns",
                "the resume is performed by the caller, see thread_resume_in_caller",
            ),
            "status": ABSENT,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_resume_in_caller",
            "RVA": f"{common.hexs(0x1E484)};{common.hexs(0x1E537)}",
            "fn": ORCHESTRATOR_FN,
            "target_expr": "KERNEL32.dll!ResumeThread on a freshly opened handle per collected thread identifier, two duplicated blocks",
            "caller_rvas": f"{common.hexs(0x1E400)};{common.hexs(0x1E4F6)}",
            "activation_cond": _gate(
                _predicate(0x1E45C, "an empty identifier list skips the resume pass"),
                _predicate(0x1E479, "a failed re-open skips the resume for that identifier"),
                "exactly one suspend and one resume per identifier, so a pre-existing suspend count is preserved",
            ),
            "status": ASYMMETRIC,
            "confidence": "HIGH",
        },
        {
            "mechanism": "caller_lock_discipline",
            "RVA": f"{common.hexs(0x1E39A)};{common.hexs(0x1E38F)};{common.hexs(0x1E562)}",
            "fn": ORCHESTRATOR_FN,
            "target_expr": f"lock cmpxchg and xchg on *(dword *)(0x{SPIN_LOCK_VA:X}), a hand rolled once flag",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "both call sites sit between the take and the drop, so the subject runs with the flag held",
                _predicate(0x1E3A2, "a losing contender sleeps and retries instead of proceeding"),
                "the subject itself neither takes nor releases the flag",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "caller_heap_ownership",
            "RVA": f"{common.hexs(0x1E096)};{common.hexs(0x1E54E)};{common.hexs(0x1E55A)}",
            "fn": f"{SUBJECT_FN};{ORCHESTRATOR_FN}",
            "target_expr": f"KERNEL32.dll!HeapAlloc and KERNEL32.dll!HeapFree both use *(qword *)(0x{HEAP_HANDLE_VA:X})",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "the subject allocates the identifier array, the caller frees it",
                _predicate(0x1E451, "a null array skips the free, and a null array is the only case where the free is skipped"),
                "the same heap global also backs the record array, so both structures share one allocator",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "caller_ordering_redirect_before_patch",
            "RVA": f"{common.hexs(CALLER_ALL_RVA)};{common.hexs(CALLER_ALL_PATCH_RVA)};{common.hexs(CALLER_ONE_RVA)};{common.hexs(CALLER_ONE_PATCH_RVA)}",
            "fn": ORCHESTRATOR_FN,
            "target_expr": "the redirect call precedes the inline patcher call on both paths",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                f"bulk path {common.hexs(CALLER_ALL_RVA)} then {common.hexs(CALLER_ALL_PATCH_RVA)}",
                f"single path {common.hexs(CALLER_ONE_RVA)} then {common.hexs(CALLER_ONE_PATCH_RVA)}",
                "the thread is therefore suspended and moved before the bytes it is about to run are replaced",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "patch_flag_0x06",
            "RVA": common.hexs(0x1E336),
            "fn": PATCHER_FN,
            "target_expr": f"(rec + {common.hexs(RECORD_FLAG_OFFSET)}) |= {common.hexs(PATCH_FLAG_MASK)}",
            "caller_rvas": f"{common.hexs(CALLER_ALL_PATCH_RVA)};{common.hexs(CALLER_ONE_PATCH_RVA)}",
            "activation_cond": _gate(
                f"the mask raises {common.hexs(FLAG_SKIP)} and {common.hexs(FLAG_PATCHED)} in one store",
                "the skip bit is read by both mechanisms, the patched bit is read by neither",
                "because the flag is written after the redirect, the redirect always sees the bit clear on the first pass",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "list_provenance_0x28",
            "RVA": f"{common.hexs(0x1E844)};{common.hexs(0x1E85E)}",
            "fn": BUILDER_FN,
            "target_expr": EXPR_ENTRY_OFFSET,
            "caller_rvas": NOT_STATIC,
            "activation_cond": _gate(
                _predicate(0x1E837, "a ninth entry abandons the whole descriptor"),
                _predicate(0x1E829, "the decoded length and the opcode derived length must agree before an entry is stored"),
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "list_provenance_0x30",
            "RVA": f"{common.hexs(0x1E82D)};{common.hexs(0x1E849)};{common.hexs(0x1E863)}",
            "fn": BUILDER_FN,
            "target_expr": EXPR_ENTRY_TARGET,
            "caller_rvas": NOT_STATIC,
            "activation_cond": _gate(
                _predicate(0x1E82F, f"the window is capped at {common.hexs(WINDOW_CAP)} bytes"),
                "the captured cursor is the offset just past the instruction, so the redirect lands on the continuation and not on the instruction start",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "list_entry_cap",
            "RVA": f"{common.hexs(0x1E834)};{common.hexs(0x1E837)}",
            "fn": f"{BUILDER_FN};{SUBJECT_FN}",
            "target_expr": f"{LIST_ENTRY_CAP} entries, {common.hexs(LIST_CAPACITY_BYTES)} bytes owned by 0x28 and 0x30 inside the {common.hexs(RECORD_STRIDE)} byte stride",
            "caller_rvas": NOT_STATIC,
            "activation_cond": _gate(
                "the builder refuses the ninth entry, so the count can never exceed the eight stored bytes",
                "the subject masks the count to four bits, which is wider than the cap",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "suspend_result_unchecked",
            "RVA": common.hexs(0x1E109),
            "fn": SUBJECT_FN,
            "target_expr": "the return value of KERNEL32.dll!SuspendThread is discarded",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "no test follows the call before the context read",
                "a suspend that did not take effect leaves the context read and the apply racing a running thread",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "set_context_result_unchecked",
            "RVA": common.hexs(0x1E214),
            "fn": SUBJECT_FN,
            "target_expr": "the return value of KERNEL32.dll!SetThreadContext is discarded",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "no test follows the call, the next instruction reloads the record array",
                "the frame copy of the instruction pointer was already written, so a rejected apply still advances the value the next record compares against",
            ),
            "status": OBSERVED,
            "confidence": "MEDIUM",
        },
        {
            "mechanism": "error_branch_get_context",
            "RVA": common.hexs(0x1E127),
            "fn": SUBJECT_FN,
            "target_expr": "GetThreadContext returned zero",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "the handle is closed and the thread cursor advances",
                "no record is scanned and no status is propagated to the caller",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "error_branch_open_thread",
            "RVA": common.hexs(0x1E0FD),
            "fn": SUBJECT_FN,
            "target_expr": "OpenThread returned a null handle",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "the thread cursor advances without suspending, reading or writing anything",
                "the identifier stays in the array, so the caller still resumes a thread that was never suspended",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "error_branch_snapshot_and_alloc",
            "RVA": f"{common.hexs(0x1E032)};{common.hexs(0x1E052)};{common.hexs(0x1E0B1)};{common.hexs(0x1E0AE)};{common.hexs(0x1E1A9)}",
            "fn": SUBJECT_FN,
            "target_expr": "invalid snapshot handle, a failed first read, a failed allocation or a failed growth",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "every one of these ends the function without a status word",
                "the function has no return value, so none of them reaches the caller",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "no_general_purpose_registers_captured",
            "RVA": "none",
            "fn": SUBJECT_FN,
            "target_expr": "no field other than CONTEXT.Rip is read or written; the request mask selects the control group only",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "the redirected thread resumes with the register state of the old location, not of the new one",
                "the mechanism is therefore only sound where the target is a fresh entry that re-establishes state, which is not decidable from the file",
            ),
            "status": ABSENT,
            "confidence": "MEDIUM",
        },
        {
            "mechanism": "record_image_base_not_tested",
            "RVA": common.hexs(0x1E1FD),
            "fn": SUBJECT_FN,
            "target_expr": f"only the sum with rec + {common.hexs(RECORD_IMAGE_BASE_OFFSET)} is tested, never the field itself",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "a null image base combined with a non zero target byte passes the gate",
                "the writer of the field is the registrar, and whether it can publish a null is not decidable from the record layout alone",
            ),
            "status": OBSERVED,
            "confidence": "MEDIUM",
        },
        {
            "mechanism": "caller_dead_sentinel_branch",
            "RVA": f"{common.hexs(0x1E4D4)};{common.hexs(0x1E4D7)}",
            "fn": ORCHESTRATOR_FN,
            "target_expr": "the found record index is compared against the sentinel after a successful search",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "the search only succeeds for an index below the live count, which is non zero on this path",
                "so the branch cannot be taken and the single path never aborts here",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "caller_status_codes",
            "RVA": f"{common.hexs(0x1E3CC)};{common.hexs(0x1E3AE)};{common.hexs(0x1E4A6)};{common.hexs(0x1E4E3)};{common.hexs(0x1E502)}",
            "fn": ORCHESTRATOR_FN,
            "target_expr": "zero on the bulk success paths, 2 when the heap handle is unpublished, 4 when the single lookup finds nothing, 5 when the found record carries the skip bit, otherwise the code returned by the inline patcher",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "no code is produced for a redirect that did not happen, the subject has no return value",
                _predicate(0x1E400, "the bulk path discards whatever the subject leaves in the return register"),
                _predicate(0x1E4F6, "the single path discards it as well"),
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "subject_not_address_taken",
            "RVA": "none",
            "fn": SUBJECT_FN,
            "target_expr": "no absolute pointer, no rip relative reference and no function pointer slot refers to the subject",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "the only references are the two direct call sites and the exception directory entry",
                "no indirect invocation path exists in the file",
            ),
            "status": ABSENT,
            "confidence": "HIGH",
        },
        {
            "mechanism": "thread_handle_api_inventory",
            "RVA": f"{common.hexs(0x1E029)};{common.hexs(0x1E04B)};{common.hexs(0x1E1D7)};{common.hexs(0x1E0F4)};{common.hexs(0x1E109)};{common.hexs(0x1E11F)};{common.hexs(0x1E214)};{common.hexs(0x1E230)}",
            "fn": SUBJECT_FN,
            "target_expr": "CreateToolhelp32Snapshot, Thread32First, Thread32Next, OpenThread, SuspendThread, GetThreadContext, SetThreadContext, CloseHandle",
            "caller_rvas": CALLERS,
            "activation_cond": _gate(
                "eight distinct thread lifecycle imports and no others are referenced in the range",
                "the only writes performed are the two import thunks and the instruction pointer inside the frame copy",
            ),
            "status": OBSERVED,
            "confidence": "HIGH",
        },
        {
            "mechanism": "orchestrator_invocation_open",
            "RVA": "none",
            "fn": ORCHESTRATOR_FN,
            "target_expr": "the orchestrator that owns both call sites has no direct caller and no rip relative reference in the file",
            "caller_rvas": NOT_STATIC,
            "activation_cond": "not statically reachable, the activation of the whole mechanism is an open question",
            "status": UNRESOLVED,
            "confidence": "LOW",
        },
        {
            "mechanism": "record_instance_contents_open",
            "RVA": "none",
            "fn": REGISTRAR_FN,
            "target_expr": f"*(qword *)(0x{RECORD_TABLE_VA:X}) is zero filled in the file and the slot has no image relative initialiser",
            "caller_rvas": NOT_STATIC,
            "activation_cond": _gate(
                "no record can be enumerated statically, so no concrete anchor, image base or list content is known",
                "every per record statement stays conditional on run time instance data",
            ),
            "status": UNRESOLVED,
            "confidence": "LOW",
        },
    ]
    for row in rows:
        if len(row) != len(CSV_FIELDS):
            raise ValueError(f"row {row.get('mechanism')} has {len(row)} fields")
    return rows


# --------------------------------------------------------------------------- #
# JSON payload
# --------------------------------------------------------------------------- #


def build_payload(pe: pefile.PE, md: capstone.Cs, specimen_size: int) -> dict[str, Any]:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    iat = resolve_iat(pe)
    invariants = verify_anchors(pe, md)
    reach = reachable_functions(pe)

    subject = {}
    for rva in SUBJECT_RVAS:
        begin, end, unwind = function_bounds(pe, rva)
        subject[common.hexs(rva)] = {
            "begin_rva": common.hexs(begin),
            "end_rva": common.hexs(end),
            "size": common.hexs(end - begin),
            "unwind_info_rva": common.hexs(unwind),
        }

    def api(slot: int) -> str:
        return iat.get(slot, "unresolved")

    payload: dict[str, Any] = {
        "schema": SCHEMA_JSON,
        "mode": MODE,
        "generated_by": {
            "script": "reverse/scripts/patch_audit_1dff0.py",
            "python": common.python_summary(),
            "pefile": common.library_version("pefile", "pefile"),
            "capstone": common.library_version("capstone", "capstone"),
        },
        "specimen": {
            "path": SPECIMEN_RELATIVE,
            "size": specimen_size,
            "sha256": SPECIMEN_SHA256,
        },
        "companion_table": {
            "path": "reverse/evidence/patch_mechanisms_1dff0.csv",
            "schema": SCHEMA_CSV,
            "rows": len(build_mechanisms()),
        },
        "image": {
            "image_base": image_base,
            "image_base_hex": common.hexs(image_base),
        },
        "confidence_scale": CONFIDENCE_SCALE,
        "status_vocabulary": {
            OBSERVED: "the structure is present and settled by an instruction or an immediate",
            ABSENT: "the structure is proven not to exist inside the audited range",
            ASYMMETRIC: "the two halves of a cross function pair sit in different functions",
            UNRESOLVED: "the file does not decide the question",
        },
        "subject": {
            "function": {
                "name": "rip_redirect",
                "role": "moves a suspended thread from a recorded original address to the matching position in a rebuilt image",
                "rva": common.hexs(REDIRECT_RVA),
                "fn": SUBJECT_FN,
                "size": common.hexs(0x27A),
                "signature": "void f(LONG record_index_or_minus_one, THREADIDLIST* out), windows x64, out block in rcx, index in edx",
                "return_value": "none, the caller discards the return register at both call sites",
            },
            "functions": subject,
            "record_expression": EXPR_RECORD,
            "address_taken": reach["address_taken"],
            "reachability": reach,
        },
        "api_surface": {
            "enumeration": [
                {
                    "role": "snapshot",
                    "site_rva": common.hexs(0x1E029),
                    "iat_slot_rva": common.hexs(IAT_SNAPSHOT),
                    "thunk_rva": common.hexs(THUNK_SNAPSHOT_RVA),
                    "symbol": api(IAT_SNAPSHOT),
                    "arguments": "dwFlags=0x4 TH32CS_SNAPTHREAD, dwProcessId=0",
                },
                {
                    "role": "first",
                    "site_rva": common.hexs(0x1E04B),
                    "iat_slot_rva": common.hexs(IAT_FIRST),
                    "thunk_rva": common.hexs(THUNK_FIRST_RVA),
                    "symbol": api(IAT_FIRST),
                    "arguments": "snapshot handle, THREADENTRY32 at rsp+0x30 with dwSize 0x1C",
                },
                {
                    "role": "next",
                    "site_rva": common.hexs(0x1E1D7),
                    "iat_slot_rva": common.hexs(IAT_NEXT),
                    "thunk_rva": common.hexs(THUNK_NEXT_RVA),
                    "symbol": api(IAT_NEXT),
                    "arguments": "snapshot handle, dwSize re-armed to 0x1C before the call",
                },
            ],
            "selection": [
                {
                    "role": "owner_process",
                    "site_rva": common.hexs(0x1E063),
                    "iat_slot_rva": common.hexs(IAT_GET_PID),
                    "symbol": api(IAT_GET_PID),
                    "use": f"th32OwnerProcessID at structure offset {common.hexs(THREADENTRY32_PID_OFFSET)} must equal the result",
                },
                {
                    "role": "self",
                    "site_rva": common.hexs(0x1E075),
                    "iat_slot_rva": common.hexs(IAT_GET_TID),
                    "symbol": api(IAT_GET_TID),
                    "use": f"th32ThreadID at structure offset {common.hexs(THREADENTRY32_TID_OFFSET)} must differ from the result",
                },
            ],
            "thread_lifecycle": [
                {
                    "role": "open",
                    "site_rva": common.hexs(0x1E0F4),
                    "iat_slot_rva": common.hexs(IAT_OPEN_THREAD),
                    "symbol": api(IAT_OPEN_THREAD),
                    "arguments": f"dwDesiredAccess={common.hexs(OPEN_THREAD_ACCESS)}, bInheritHandle=FALSE, dwThreadId from the array",
                    "access_decomposition": {
                        common.hexs(OPEN_THREAD_ACCESS): access_decomposition(
                            OPEN_THREAD_ACCESS, OPEN_THREAD_ACCESS_PARTS
                        )
                    },
                    "result_checked": True,
                },
                {
                    "role": "suspend",
                    "site_rva": common.hexs(0x1E109),
                    "iat_slot_rva": common.hexs(IAT_SUSPEND_THREAD),
                    "symbol": api(IAT_SUSPEND_THREAD),
                    "result_checked": False,
                },
                {
                    "role": "get_context",
                    "site_rva": common.hexs(0x1E11F),
                    "iat_slot_rva": common.hexs(IAT_GET_CONTEXT),
                    "symbol": api(IAT_GET_CONTEXT),
                    "result_checked": True,
                },
                {
                    "role": "set_context",
                    "site_rva": common.hexs(0x1E214),
                    "iat_slot_rva": common.hexs(IAT_SET_CONTEXT),
                    "symbol": api(IAT_SET_CONTEXT),
                    "result_checked": False,
                },
                {
                    "role": "close",
                    "site_rva": f"{common.hexs(0x1E0BA)};{common.hexs(0x1E230)}",
                    "iat_slot_rva": common.hexs(IAT_CLOSE_HANDLE),
                    "symbol": api(IAT_CLOSE_HANDLE),
                    "arguments": "the snapshot handle, then one handle per opened thread",
                },
            ],
            "resume_absent_in_subject": {
                "iat_slot_rva": common.hexs(IAT_RESUME_THREAD),
                "symbol": api(IAT_RESUME_THREAD),
                "site_rvas_in_subject": [],
                "site_rvas_in_caller": [common.hexs(0x1E484), common.hexs(0x1E537)],
                "note": "the subject suspends and never resumes, the orchestrator owns the resume",
            },
            "heap": [
                {
                    "role": "allocate_identifier_array",
                    "site_rva": common.hexs(0x1E0A5),
                    "iat_slot_rva": common.hexs(IAT_HEAP_ALLOC),
                    "symbol": api(IAT_HEAP_ALLOC),
                    "heap_global": common.hexs(HEAP_HANDLE_VA),
                },
                {
                    "role": "grow_identifier_array",
                    "site_rva": common.hexs(0x1E1A0),
                    "iat_slot_rva": common.hexs(IAT_HEAP_REALLOC),
                    "symbol": api(IAT_HEAP_REALLOC),
                    "heap_global": common.hexs(HEAP_HANDLE_VA),
                },
                {
                    "role": "free_identifier_array",
                    "site_rva": common.hexs(0x1E55A),
                    "iat_slot_rva": common.hexs(IAT_HEAP_FREE),
                    "symbol": api(IAT_HEAP_FREE),
                    "heap_global": common.hexs(HEAP_HANDLE_VA),
                    "in_caller": True,
                },
            ],
            "stack_guard": {
                "site_rva": common.hexs(0x1E00A),
                "global": common.hexs(COOKIE_VA),
                "check_rva": common.hexs(COOKIE_CHECK_RVA),
            },
        },
        "thread_handles": [
            {
                "role": "snapshot",
                "obtain_rva": common.hexs(0x1E029),
                "obtain_expr": "CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)",
                "stored_in": "rbx",
                "invalid_test_rva": common.hexs(0x1E02E),
                "close_rva": common.hexs(0x1E0BA),
                "close_paths": [
                    "the first read returned zero",
                    "the allocation returned null",
                    "the growth returned null",
                    "the last read returned zero",
                ],
                "alive_during": "the enumeration only, the handle is closed before any thread is opened",
            },
            {
                "role": "thread",
                "obtain_rva": common.hexs(0x1E0F4),
                "obtain_expr": f"OpenThread({common.hexs(OPEN_THREAD_ACCESS)}, FALSE, out.array[i])",
                "stored_in": "rbx, the same register the snapshot handle used",
                "invalid_test_rva": common.hexs(0x1E0FD),
                "close_rva": common.hexs(0x1E230),
                "close_paths": [
                    "the context read failed",
                    "the start index is at or above the limit",
                    "the record scan ran to the exclusive limit",
                ],
                "reused_register_safe": True,
                "suspends": 1,
                "resumes_inside_subject": 0,
            },
            {
                "role": "resume",
                "obtain_rva": f"{common.hexs(0x1E473)};{common.hexs(0x1E526)}",
                "obtain_expr": f"OpenThread({common.hexs(OPEN_THREAD_ACCESS)}, FALSE, out.array[i]) in the caller",
                "stored_in": "rbx",
                "invalid_test_rva": f"{common.hexs(0x1E47C)};{common.hexs(0x1E52F)}",
                "close_rva": f"{common.hexs(0x1E48D)};{common.hexs(0x1E540)}",
                "close_paths": ["immediately after the resume call"],
                "independent_handle": True,
                "suspends": 0,
                "resumes_inside_subject": 1,
                "note": "a second, independent handle per identifier, so the resume does not depend on the handle the subject used",
            },
        ],
        "out_block": {
            "expression": "the caller's frame block, passed in rcx; the orchestrator passes its own rsp+0x28 on both call paths",
            "caller_block_rva": [common.hexs(0x1E3F6), common.hexs(0x1E4EF)],
            "size": 16,
            "zeroed_at": common.hexs(0x1E01F),
            "zeroing_source": common.hexs(0x1E01C),
            "zeroing_width": "one 128 bit store covers the pointer, the capacity and the count",
            "fields": [
                {"offset": 0, "name": "identifiers", "width": 8, "written_by": common.hexs(0x1E0AB)},
                {"offset": 8, "name": "capacity", "width": 4, "written_by": common.hexs(0x1E08F)},
                {"offset": 12, "name": "count", "width": 4, "written_by": common.hexs(0x1E1C0)},
            ],
            "element": {
                "width": ENTRY_SIZE_BYTES,
                "expression": EXPR_THREAD_ID,
                "value": f"a thread identifier read at structure offset {common.hexs(THREADENTRY32_TID_OFFSET)}",
                "store_rva": common.hexs(0x1E1C4),
                "capacity_model": {
                    "initial_entries": INITIAL_CAPACITY_ENTRIES,
                    "initial_bytes": INITIAL_CAPACITY_BYTES,
                    "growth": "doubling, the new byte count is capacity times two times the element size",
                },
                "bounds_safe": True,
                "bounds_evidence": f"{common.hexs(0x1E187)} compares the count with the capacity before every append",
            },
            "owner": {
                "allocates": SUBJECT_FN,
                "frees": ORCHESTRATOR_FN,
                "shared_globals": [common.hexs(HEAP_HANDLE_VA)],
            },
        },
        "context_buffer": {
            "expression": EXPR_CONTEXT_BASE,
            "stack_offset": common.hexs(CONTEXT_STACK_OFFSET),
            "structure_size": common.hexs(CONTEXT_SIZE),
            "frame_size": common.hexs(FRAME_SIZE),
            "frame_fits_exactly": CONTEXT_STACK_OFFSET + CONTEXT_SIZE == COOKIE_STACK_OFFSET,
            "frame_fit_note": "the structure starts at the frame offset above and ends exactly where the stack cookie is stored, so the frame is sized for one structure plus the cookie",
            "context_flags": {
                "field": "CONTEXT+0x30",
                "stack_offset": common.hexs(0x60),
                "value": common.hexs(CONTEXT_FLAGS_VALUE),
                "value_decimal": CONTEXT_FLAGS_VALUE,
                "contains": {
                    "CONTEXT_CONTROL": bool(CONTEXT_FLAGS_VALUE & CONTEXT_CONTROL_FLAG),
                },
                "note": "the low bit is the control selector of the CONTEXT group, the value is the control group request",
                "writer_rva": common.hexs(0x1E10F),
                "written_per_thread": True,
            },
            "rip": {
                "field": "CONTEXT+0xF8",
                "stack_offset": common.hexs(0x128),
                "reader_rva": common.hexs(0x1E173),
                "writer_rva": common.hexs(0x1E204),
                "kernel_applied": common.hexs(0x1E214),
                "read_frequency": "once per scanned record",
                "write_frequency": "at most once per record",
                "note": "the frame copy is updated before the apply, so the next record reads the value the previous record intended to install",
            },
            "fields_touched": ["ContextFlags", "Rip"],
            "fields_not_touched": "every other field of the structure, including the whole general purpose register group",
            "aliasing": {
                "shared_slot": "the thread entry structure and the context structure occupy the same frame slot",
                "enumeration_uses": [common.hexs(0x1E03B), common.hexs(0x1E1C7)],
                "context_uses": [
                    common.hexs(0x1E10F),
                    common.hexs(0x1E117),
                    common.hexs(0x1E173),
                    common.hexs(0x1E204),
                ],
                "overlap_in_time": False,
                "note": "the enumeration loop closes the snapshot handle before the thread loop opens the first context, so the two uses never interleave",
            },
        },
        "record_map": {
            "expression": EXPR_RECORD,
            "table_slot": common.hexs(RECORD_TABLE_VA),
            "count_slot": common.hexs(RECORD_COUNT_VA),
            "stride": common.hexs(RECORD_STRIDE),
            "shared_with": {
                "inline_patcher": PATCHER_FN,
                "orchestrator": ORCHESTRATOR_FN,
                "registrar": common.hexs(REGISTRAR_RVA),
                "arena": common.hexs(ARENA_RVA),
            },
            "fields_read_by_subject": [
                {
                    "offset": RECORD_ANCHOR_OFFSET,
                    "offset_hex": common.hexs(RECORD_ANCHOR_OFFSET),
                    "name": "anchor",
                    "width": 8,
                    "reader_rva": common.hexs(0x1E17B),
                    "role": "the address the 0x28 list offsets are added to",
                },
                {
                    "offset": RECORD_IMAGE_BASE_OFFSET,
                    "offset_hex": common.hexs(RECORD_IMAGE_BASE_OFFSET),
                    "name": "image_base",
                    "width": 8,
                    "reader_rva": common.hexs(0x1E1FD),
                    "role": "the base of the rebuilt image the 0x30 list offsets are added to",
                    "tested_for_null": False,
                },
                {
                    "offset": RECORD_FLAG_OFFSET,
                    "offset_hex": common.hexs(RECORD_FLAG_OFFSET),
                    "name": "flags",
                    "width": 1,
                    "reader_rva": common.hexs(0x1E156),
                    "role": "the skip bit hides the record from the rewrite",
                    "bits": [
                        {"mask": FLAG_TWO_SLOT, "name": "two_slot_layout", "reader_in_subject": False},
                        {"mask": FLAG_SKIP, "name": "skip", "reader_in_subject": True},
                        {"mask": FLAG_PATCHED, "name": "patched", "reader_in_subject": False},
                    ],
                },
                {
                    "offset": RECORD_COUNT_OFFSET,
                    "offset_hex": common.hexs(RECORD_COUNT_OFFSET),
                    "name": "entry_count",
                    "width": 4,
                    "reader_rva": common.hexs(0x1E161),
                    "role": "the number of parallel list entries, low nibble only",
                    "mask": common.hexs(LIST_COUNT_MASK),
                },
                {
                    "offset": RECORD_MATCH_LIST_OFFSET,
                    "offset_hex": common.hexs(RECORD_MATCH_LIST_OFFSET),
                    "name": "match_list",
                    "width": LIST_CAPACITY_BYTES,
                    "reader_rva": common.hexs(0x1E1E9),
                    "element_width": 1,
                    "meaning": EXPR_ENTRY_OFFSET,
                    "writer_rva": common.hexs(0x1E844),
                },
                {
                    "offset": RECORD_TARGET_LIST_OFFSET,
                    "offset_hex": common.hexs(RECORD_TARGET_LIST_OFFSET),
                    "name": "target_list",
                    "width": LIST_CAPACITY_BYTES,
                    "reader_rva": common.hexs(0x1E1F7),
                    "element_width": 1,
                    "meaning": EXPR_ENTRY_TARGET,
                    "writer_rva": common.hexs(0x1E849),
                },
            ],
            "fields_written_by_subject": [],
            "flag_interaction": {
                "patch_flag_mask": common.hexs(PATCH_FLAG_MASK),
                "patch_flag_writer_rva": common.hexs(0x1E336),
                "decomposition": [
                    {"mask": FLAG_SKIP, "name": "skip", "read_by": [common.hexs(0x1E156), common.hexs(0x1E3E0), common.hexs(0x1E41C), common.hexs(0x1E4E8)]},
                    {"mask": FLAG_PATCHED, "name": "patched", "read_by": []},
                ],
                "ordering": "the flag is written by the inline patcher, which the orchestrator runs after the redirect on both paths",
                "consequence": "a record is visible to the rewrite only on a pass that happens before the patcher has processed it",
            },
        },
        "rip_reconstruction": {
            "match_expression": EXPR_MATCH,
            "target_expression": EXPR_TARGET,
            "comparison": "exact 64 bit equality, the branch on inequality advances the entry cursor",
            "entry_cap": LIST_ENTRY_CAP,
            "list_capacity_bytes": LIST_CAPACITY_BYTES,
            "count_field": f"rec + {common.hexs(RECORD_COUNT_OFFSET)}, low nibble only",
            "parallel_lists": "one entry cursor drives both byte loads, so entry i of 0x28 pairs with entry i of 0x30",
            "per_entry_semantics": {
                "match_byte": "the offset of an instruction start from the record anchor",
                "target_byte": "the window cursor just past that instruction",
                "reading": "a suspended thread is redirected only when its instruction pointer sits exactly on a recorded instruction start",
                "landing": "the replacement is the same relative position in the rebuilt image, past the instruction that was about to run",
            },
            "window": {
                "cap_bytes": common.hexs(WINDOW_CAP),
                "cap_rva": common.hexs(0x1E82F),
                "consequence": "both list bytes stay representable in one unsigned byte, so the byte lists cannot wrap",
            },
            "applies_per_record": 1,
            "applies_per_thread": "at most the number of scanned records, because the cursor chain continues after an apply",
            "chaining": "the frame copy of the instruction pointer is rewritten before the apply, so the next record matches against the replacement value",
            "inert_conditions": [
                f"the skip bit {common.hexs(FLAG_SKIP)} is set on the record",
                f"the low nibble of rec + {common.hexs(RECORD_COUNT_OFFSET)} is zero",
                "the reconstructed target is zero",
                "the start index is at or above the exclusive limit",
            ],
        },
        "callers": [
            {
                "site_rva": common.hexs(CALLER_ALL_RVA),
                "site_va": common.hexs(CALLER_ALL_RVA + image_base),
                "target_rva": common.hexs(REDIRECT_RVA),
                "caller_function_rva": common.hexs(ORCHESTRATOR_RVA),
                "path": "orchestrator, null argument branch, every record",
                "selected_by": f"{common.hexs(0x1E3B8)} tests the argument, a null argument takes this path",
                "index_expression": EXPR_RECORD_INDEX,
                "index_value": ALL_RECORDS_SENTINEL,
                "start_index": 0,
                "limit": f"*(dword *)(0x{RECORD_COUNT_VA:X})",
                "preconditions": [
                    f"the once flag at 0x{SPIN_LOCK_VA:X} is taken",
                    f"the heap handle at 0x{HEAP_HANDLE_VA:X} is published, otherwise the call is not reached",
                    "the live record count is non zero",
                    "at least one record without the skip bit exists, otherwise the call is not reached",
                ],
                "ordering": f"redirect at {common.hexs(CALLER_ALL_RVA)}, inline patch loop from {common.hexs(0x1E418)}, resume loop from {common.hexs(0x1E465)}, free at {common.hexs(0x1E55A)}",
                "on_failure": "the subject has no return value, so a redirect that did not happen is invisible to the orchestrator",
                "confidence": "HIGH",
            },
            {
                "site_rva": common.hexs(CALLER_ONE_RVA),
                "site_va": common.hexs(CALLER_ONE_RVA + image_base),
                "target_rva": common.hexs(REDIRECT_RVA),
                "caller_function_rva": common.hexs(ORCHESTRATOR_RVA),
                "path": "orchestrator, non null argument branch, one record",
                "selected_by": f"{common.hexs(0x1E3BB)} branches on a non null argument",
                "index_expression": "rec + 0x00 == the caller argument, the index found by the linear search",
                "index_value": "the found index",
                "start_index": "the found index",
                "limit": "the found index plus one",
                "preconditions": [
                    f"the once flag at 0x{SPIN_LOCK_VA:X} is taken",
                    "the live record count is non zero, otherwise the path returns 4",
                    "a record with a matching anchor exists, otherwise the path returns 4",
                    "the found record does not carry the skip bit, otherwise the path returns 5",
                ],
                "ordering": f"redirect at {common.hexs(CALLER_ONE_RVA)}, inline patcher at {common.hexs(CALLER_ONE_PATCH_RVA)}, resume loop from {common.hexs(0x1E518)}, free at {common.hexs(0x1E55A)}",
                "on_failure": "the patcher status becomes the orchestrator status, the redirect outcome is not represented",
                "confidence": "HIGH",
            },
        ],
        "activation": {
            "caller_lock": {
                "take_rva": common.hexs(0x1E39A),
                "take_target": common.hexs(SPIN_LOCK_VA),
                "drop_rva": common.hexs(0x1E562),
                "contended_path": f"{common.hexs(0x1E38F)} sleeps and retries, so the subject runs at most once concurrently",
                "subject_takes_lock": False,
                "note": "the subject reads the record table and the record count without any lock of its own, which is sound only because both call sites sit inside the held region",
            },
            "heap_gate": {
                "site_rva": common.hexs(0x1E3A4),
                "target": common.hexs(HEAP_HANDLE_VA),
                "effect": "an unpublished heap handle makes the orchestrator return 2 before any call site",
            },
            "record_availability": {
                "count_global": common.hexs(RECORD_COUNT_VA),
                "zero_effect": "both paths return before any call site when the count is zero",
                "skip_bit": common.hexs(FLAG_SKIP),
                "skip_effect": "the bulk path needs one record without the bit, the single path refuses a record that has it",
            },
            "thread_availability": {
                "source": "the toolhelp snapshot, so a thread that does not exist at enumeration time is never redirected",
                "filters": [
                    "the owning process must be the current process",
                    "the calling thread is excluded",
                    "a reported structure size below 0x10 drops the entry",
                    "an identifier that cannot be opened is skipped by the subject but still resumed by the caller",
                ],
            },
            "ordering_matrix": [
                {
                    "step": 1,
                    "action": "enumerate the threads into the out block",
                    "rva": common.hexs(0x1E0C0),
                },
                {
                    "step": 2,
                    "action": "suspend, read the instruction pointer, rewrite it, apply the context, close the handle",
                    "rva": common.hexs(0x1E109),
                },
                {
                    "step": 3,
                    "action": "the inline patcher replaces the code bytes and raises the flag mask 0x06",
                    "rva": common.hexs(0x1E336),
                },
                {
                    "step": 4,
                    "action": "the caller reopens every collected thread, resumes it and closes that handle",
                    "rva": common.hexs(0x1E484),
                },
                {
                    "step": 5,
                    "action": "the caller frees the identifier array and releases the once flag",
                    "rva": common.hexs(0x1E55A),
                },
            ],
        },
        "error_branches": [
            {
                "id": "snapshot_invalid",
                "site_rva": common.hexs(0x1E02E),
                "branch_rva": common.hexs(0x1E032),
                "condition": "the snapshot handle equals 0xFFFFFFFFFFFFFFFF",
                "effect": "the enumeration and the thread pass are skipped, the function returns",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "first_read_failed",
                "site_rva": common.hexs(0x1E050),
                "branch_rva": common.hexs(0x1E052),
                "condition": "the first read returned zero",
                "effect": "the snapshot handle is closed and the function returns",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "entry_size_gate",
                "site_rva": common.hexs(0x1E054),
                "branch_rva": common.hexs(0x1E059),
                "condition": f"the reported structure size is below {common.hexs(THREADENTRY32_MIN_SIZE)}",
                "effect": "the thread is not appended and not processed, the enumeration continues",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "foreign_process",
                "site_rva": common.hexs(0x1E069),
                "branch_rva": common.hexs(0x1E06B),
                "condition": "the owner process differs from the current process",
                "effect": "the thread is skipped",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "self_thread",
                "site_rva": common.hexs(0x1E07B),
                "branch_rva": common.hexs(0x1E07D),
                "condition": "the identifier equals the current thread identifier",
                "effect": "the thread is skipped, so the walker never suspends its own thread",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "allocation_failed",
                "site_rva": common.hexs(0x1E0AE),
                "branch_rva": common.hexs(0x1E0B1),
                "condition": "the identifier array allocation returned null",
                "effect": "the snapshot handle is closed and the function returns",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "growth_failed",
                "site_rva": common.hexs(0x1E1A6),
                "branch_rva": common.hexs(0x1E1A9),
                "condition": "the identifier array growth returned null",
                "effect": "the snapshot handle is closed and the function returns",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "open_failed",
                "site_rva": common.hexs(0x1E0FA),
                "branch_rva": common.hexs(0x1E0FD),
                "condition": "the thread could not be opened",
                "effect": "the thread cursor advances, the identifier remains in the array and the caller still resumes it",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "get_context_failed",
                "site_rva": common.hexs(0x1E125),
                "branch_rva": common.hexs(0x1E127),
                "condition": "the context read failed",
                "effect": "the handle is closed and the record scan is skipped, the thread stays suspended until the caller resumes it",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "index_out_of_range",
                "site_rva": common.hexs(0x1E13C),
                "branch_rva": common.hexs(0x1E13F),
                "condition": "the start index is at or above the exclusive limit",
                "effect": "the handle is closed and no record is scanned",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "record_skipped",
                "site_rva": common.hexs(0x1E156),
                "branch_rva": common.hexs(0x1E15B),
                "condition": f"the skip bit {common.hexs(FLAG_SKIP)} is set",
                "effect": "the record cursor advances, the thread is closed and resumed by the caller without any change",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "record_inert",
                "site_rva": common.hexs(0x1E169),
                "branch_rva": common.hexs(0x1E169),
                "condition": f"the low nibble of rec + {common.hexs(RECORD_COUNT_OFFSET)} is zero",
                "effect": "the record is abandoned before the first list load",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "entry_exhausted",
                "site_rva": common.hexs(0x1E1E4),
                "branch_rva": common.hexs(0x1E1E7),
                "condition": "the entry cursor reached the masked count",
                "effect": "the record is abandoned",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "target_zero",
                "site_rva": common.hexs(0x1E202),
                "branch_rva": common.hexs(0x1E202),
                "condition": "the reconstructed target is zero",
                "effect": "the whole record is abandoned, not only the current entry",
                "status_reported": False,
                "confidence": "HIGH",
            },
            {
                "id": "suspend_result_ignored",
                "site_rva": common.hexs(0x1E109),
                "branch_rva": None,
                "condition": "the suspend return value is never tested",
                "effect": "a suspend that did not take effect leaves the read and the apply racing a running thread, and the caller still performs one resume",
                "status_reported": False,
                "confidence": "MEDIUM",
            },
            {
                "id": "set_context_result_ignored",
                "site_rva": common.hexs(0x1E214),
                "branch_rva": None,
                "condition": "the apply return value is never tested",
                "effect": "the frame copy was already updated, so the next record compares against a replacement the kernel may have rejected",
                "status_reported": False,
                "confidence": "MEDIUM",
            },
        ],
        "consistency": [
            {
                "id": "access_mask_matches_usage",
                "rule": "the requested access must cover every operation the sequence performs",
                "evidence": f"{common.hexs(OPEN_THREAD_ACCESS)} decomposes into the suspend, get context, set context and query information rights, one per operation used",
                "verdict": "matches",
                "confidence": "HIGH",
            },
            {
                "id": "three_argument_open",
                "rule": "only three argument registers are set before the open call",
                "evidence": "the open entry point takes three parameters, so the untouched fourth register is not a missing argument",
                "verdict": "consistent",
                "confidence": "HIGH",
            },
            {
                "id": "context_frame_fits",
                "rule": "the frame must hold the structure the code fills",
                "evidence": f"the structure at offset {common.hexs(CONTEXT_STACK_OFFSET)} of size {common.hexs(CONTEXT_SIZE)} ends exactly at the cookie offset {common.hexs(COOKIE_STACK_OFFSET)}",
                "verdict": "exact_fit",
                "confidence": "HIGH",
            },
            {
                "id": "context_offsets_are_control_group",
                "rule": "the two touched fields must belong to the requested group",
                "evidence": f"ContextFlags at structure offset {common.hexs(CONTEXT_CONTEXTFLAGS_OFFSET)} and Rip at {common.hexs(CONTEXT_RIP_OFFSET)} are both control group fields, and the request mask selects the control group",
                "verdict": "consistent",
                "confidence": "HIGH",
            },
            {
                "id": "suspend_resume_balance",
                "rule": "every suspend needs one resume",
                "evidence": "one suspend per opened thread in the subject, one resume per collected identifier in the caller, so a pre-existing suspend count is preserved",
                "verdict": "balanced_across_functions",
                "confidence": "HIGH",
            },
            {
                "id": "identifier_array_bounds",
                "rule": "the append must not pass the capacity",
                "evidence": f"{common.hexs(0x1E187)} compares the count with the capacity and grows first, so the count never exceeds the capacity",
                "verdict": "enforced",
                "confidence": "HIGH",
            },
            {
                "id": "identifier_array_freed",
                "rule": "an allocation must be released",
                "evidence": "the subject allocates and the caller frees, both on the same heap global, and every path that published the array reaches the free",
                "verdict": "cross_function_ownership",
                "confidence": "HIGH",
            },
            {
                "id": "entry_cap_fits_stride",
                "rule": "the two lists must fit inside the record stride",
                "evidence": f"the builder refuses a ninth entry and the two lists own {common.hexs(2 * LIST_CAPACITY_BYTES)} bytes of the {common.hexs(RECORD_STRIDE)} byte stride",
                "verdict": "enforced_by_builder",
                "confidence": "HIGH",
            },
            {
                "id": "count_mask_wider_than_cap",
                "rule": "the count read must not lose entries the builder produced",
                "evidence": "the builder caps the count at eight and the reader masks with 0xF, which is wider than the cap",
                "verdict": "consistent",
                "confidence": "HIGH",
            },
            {
                "id": "window_cap_keeps_bytes",
                "rule": "both list values must stay representable in one byte",
                "evidence": f"the window is capped at {common.hexs(WINDOW_CAP)} bytes, so neither the start offset nor the cursor past an instruction can exceed a byte",
                "verdict": "enforced_by_builder",
                "confidence": "HIGH",
            },
            {
                "id": "redirect_precedes_patch",
                "rule": "the thread must leave the original address before the bytes there change",
                "evidence": f"{common.hexs(CALLER_ALL_RVA)} precedes {common.hexs(CALLER_ALL_PATCH_RVA)} and {common.hexs(CALLER_ONE_RVA)} precedes {common.hexs(CALLER_ONE_PATCH_RVA)}",
                "verdict": "ordered",
                "confidence": "HIGH",
            },
            {
                "id": "flag_visibility_window",
                "rule": "the flag must not hide a record before its own rewrite",
                "evidence": f"the flag write at {common.hexs(0x1E336)} runs after the redirect on both paths, so the skip bit is clear while the rewrite is decided",
                "verdict": "ordered",
                "confidence": "HIGH",
            },
            {
                "id": "register_reuse_across_roles",
                "rule": "one register must not hold two live handles",
                "evidence": "the snapshot handle is closed at the enumeration exit, which is before the first thread open, so the reuse of rbx is safe",
                "verdict": "safe",
                "confidence": "HIGH",
            },
            {
                "id": "frame_slot_aliasing",
                "rule": "the enumeration structure and the context must not be live at the same time",
                "evidence": "the enumeration loop completes and the snapshot handle is closed before the thread loop reaches the first context use",
                "verdict": "safe",
                "confidence": "HIGH",
            },
            {
                "id": "table_pointer_refresh",
                "rule": "a table that can grow must be reloaded",
                "evidence": f"{common.hexs(0x1E21A)} reloads the array pointer after every applied context",
                "verdict": "defensive",
                "confidence": "HIGH",
            },
        ],
        "negative_findings": [
            {
                "id": "no_resume_in_subject",
                "statement": "KERNEL32.dll!ResumeThread is not referenced between the first and the last byte of the subject",
                "evidence": "the resume import slot is referenced only from the orchestrator",
                "consequence": "every thread this function suspends is left suspended when it returns, and only the two known callers undo it",
                "confidence": "HIGH",
            },
            {
                "id": "no_status_channel",
                "statement": "the subject has no return value and no output flag that reports whether a redirect happened",
                "evidence": "both call sites overwrite the return register with an unrelated load immediately after the call",
                "consequence": "the orchestrator cannot distinguish a completed rewrite from a skipped thread",
                "confidence": "HIGH",
            },
            {
                "id": "no_register_save",
                "statement": "no general purpose register is read from or written to the context",
                "evidence": "the request mask selects the control group and only the instruction pointer is touched",
                "consequence": "the redirected thread continues with the register state of the old location, which is only sound when the replacement is a fresh entry",
                "confidence": "MEDIUM",
            },
            {
                "id": "no_code_write",
                "statement": "the subject writes no executable bytes and requests no page protection change",
                "evidence": "no protection or cache flush import is referenced in the range, the only writes are into the frame copy and the out block",
                "consequence": "the mechanism is a control flow relocation only, the byte level patching is a separate function",
                "confidence": "HIGH",
            },
            {
                "id": "no_indirect_entry",
                "statement": "the subject is not address taken and has no thunk or function pointer referring to it",
                "evidence": "no absolute pointer literal, no rip relative reference and only the two direct call sites",
                "consequence": "the two audited call sites are the complete caller set for this build of the specimen",
                "confidence": "HIGH",
            },
            {
                "id": "no_image_base_null_test",
                "statement": "the record image base field is never tested on its own",
                "evidence": "only the sum with the target byte is compared against zero",
                "consequence": "a null image base with a non zero target byte would pass the gate and install a very small instruction pointer",
                "confidence": "MEDIUM",
            },
        ],
        "unresolved": [
            {
                "id": "orchestrator_invocation",
                "question": "what invokes the orchestrator, and therefore what activates the whole mechanism",
                "status": "OPEN",
                "confidence": "LOW",
                "reason": "the file contains no direct call site, no rip relative reference and no pointer literal for the orchestrator",
                "evidence": {"orchestrator_rva": common.hexs(ORCHESTRATOR_RVA), "call_sites": []},
            },
            {
                "id": "record_instances",
                "question": "which records exist at run time, and which module and export each anchor belongs to",
                "status": "OPEN",
                "confidence": "LOW",
                "reason": "the table slot is zero filled in the file and the registrar is only reachable from the builder, so no record can be enumerated statically",
                "evidence": {
                    "table_slot": common.hexs(RECORD_TABLE_VA),
                    "registrar_rva": common.hexs(REGISTRAR_RVA),
                    "builder_rva": common.hexs(BUILDER_RVA),
                },
            },
            {
                "id": "image_base_nullability",
                "question": "can the record image base field be published as zero",
                "status": "OPEN",
                "confidence": "LOW",
                "reason": "the field is written by the registrar from an arena block, and whether a null block can reach that store is not settled by the record layout alone",
                "evidence": {"field": common.hexs(RECORD_IMAGE_BASE_OFFSET)},
            },
            {
                "id": "hit_rate",
                "question": "how often a suspended thread is actually at one of the recorded instruction starts",
                "status": "OPEN",
                "confidence": "LOW",
                "reason": "the mechanism depends on the run time instruction pointer landing on a recorded offset, and no scheduling or timing data exists in the file",
                "evidence": {"entry_cap": LIST_ENTRY_CAP},
            },
        ],
        "invariants": invariants,
    }
    payload["summary"] = {
        "anchor_count": len(invariants),
        "anchor_failures": sum(1 for row in invariants if not row["ok"]),
        "mechanism_rows": len(build_mechanisms()),
        "api_imports_in_range": len(
            {
                entry["iat_slot_rva"]
                for group in ("enumeration", "selection", "thread_lifecycle", "heap")
                for entry in payload["api_surface"][group]
            }
        ),
        "direct_call_sites": reach["direct_call_site_count"],
        "address_taken": reach["address_taken"],
        "opens_per_thread": 2,
        "suspends_in_subject": 1,
        "resumes_in_subject": len(
            payload["api_surface"]["resume_absent_in_subject"]["site_rvas_in_subject"]
        ),
        "resumes_in_caller": len(
            payload["api_surface"]["resume_absent_in_subject"]["site_rvas_in_caller"]
        ),
        "context_fields_touched": len(payload["context_buffer"]["fields_touched"]),
        "record_fields_read": len(payload["record_map"]["fields_read_by_subject"]),
        "record_fields_written": len(payload["record_map"]["fields_written_by_subject"]),
        "error_branches": len(payload["error_branches"]),
        "consistency_checks": len(payload["consistency"]),
        "negative_findings": len(payload["negative_findings"]),
        "open_questions": len(payload["unresolved"]),
        "record_instance_status": "OPEN",
        "overall_confidence": "HIGH",
        "note": "the control flow, the handle lifecycle, the context layout and the cross function ordering are fully determined statically; only the record instances and the activation of the orchestrator stay open",
    }
    return payload


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _render_csv(rows: Sequence[Mapping[str, Any]]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer, fieldnames=list(CSV_FIELDS), lineterminator="\n", extrasaction="raise"
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({name: common.scalar_text(row.get(name)) for name in CSV_FIELDS})
    return buffer.getvalue()


def _render_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False, allow_nan=False) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description="Static thread-snapshot and CONTEXT audit of the 0x1DFF0 redirect walker"
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument(
        "--csv",
        type=Path,
        default=root / "reverse" / "evidence" / "patch_mechanisms_1dff0.csv",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=root / "reverse" / "evidence" / "thread_context_map.json",
    )
    parser.add_argument("--emit", action="store_true", help="write both artefacts")
    parser.add_argument("--verify", action="store_true", help="diff both artefacts against the files")
    parser.add_argument("--max-report", type=int, default=40, help="mismatches to print")
    args = parser.parse_args(argv)

    specimen = args.specimen.resolve()
    csv_path = args.csv.resolve()
    json_path = args.json.resolve()

    if not specimen.is_file():
        print(f"FAIL specimen missing: {specimen}")
        return 2
    digest = common.sha256_file(specimen)
    if digest != SPECIMEN_SHA256:
        print(f"FAIL specimen digest: expected={SPECIMEN_SHA256} actual={digest}")
        return 2

    pe = common.load_pe(specimen)
    try:
        md = _make_md()
        payload = build_payload(pe, md, specimen.stat().st_size)
        rows = build_mechanisms()

        failures = [row for row in payload["invariants"] if not row["ok"]]
        for row in failures[: args.max_report]:
            print(f"FAIL anchor {row['anchor']} at {row['site_rva']}: {row['problem']}")
        if len(failures) > args.max_report:
            print(f"FAIL ... {len(failures) - args.max_report} further anchor mismatches")
        if failures:
            return 1

        csv_text = _render_csv(rows)
        json_text = _render_json(payload)

        if args.emit:
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            with csv_path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(csv_text)
            with json_path.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(json_text)
            print(f"wrote {csv_path} ({len(rows)} rows)")
            print(f"wrote {json_path} ({len(payload['invariants'])} anchors)")

        if args.verify or not args.emit:
            for path, expected, label in (
                (csv_path, csv_text, "csv"),
                (json_path, json_text, "json"),
            ):
                if not path.is_file():
                    print(f"FAIL {label} missing: {path}")
                    return 1
                actual = path.read_text(encoding="utf-8")
                if actual != expected:
                    print(f"FAIL {label} differs from the recomputed table: {path}")
                    if label == "csv":
                        stored = _read_csv(path)
                        fresh = list(csv.DictReader(io.StringIO(expected)))
                        for index, (got, want) in enumerate(zip(stored, fresh)):
                            for name in CSV_FIELDS:
                                if got.get(name) != want.get(name):
                                    print(
                                        f"FAIL row {index} {name}: stored={got.get(name)} recomputed={want.get(name)}"
                                    )
                    else:
                        print(f"FAIL rerun the script with --emit to refresh {path}")
                    return 1
                print(f"ok {label} {path}")
    finally:
        pe.close()

    print(
        f"ok anchors={len(payload['invariants'])} rows={len(rows)} "
        f"callers={payload['summary']['direct_call_sites']} "
        f"branches={payload['summary']['error_branches']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
