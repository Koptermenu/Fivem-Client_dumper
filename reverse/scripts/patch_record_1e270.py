"""Static map of the RVA 0x1E270 inline-patch record table in adhesive.dll.

Static file parsing only. The specimen is read from disk and is never loaded,
mapped or executed. Every value written to the evidence set is either derived
from the file during the run or tied to a disassembly anchor that is verified
against the file, so a changed specimen fails loudly instead of silently
reusing stale text.

The output describes mechanism only: the symbolic address expressions the
existing code computes, the record field semantics, the private heap and the
hand written spin lock that guard the table, the activation gate that stands in
front of both patcher call sites, and the statically provable consistency limits.
No patch byte sequence, displacement value or ready to use patch step is emitted
by this script or written to its output.

Emits:
  reverse/evidence/patch_record_table.json
  reverse/evidence/patch_mechanisms_1e270.csv
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
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

sys.path.insert(0, str(Path(__file__).resolve().parent))

import common

SCHEMA: Final[str] = "adhesive-dumper.patch-record/1"

RECORD_STRIDE: Final[int] = 0x38
REGION_LIST_VA: Final[int] = 0x1830D44E0
LOCK_VA: Final[int] = 0x1830D44E8
HEAP_HANDLE_VA: Final[int] = 0x1830D44F0
TABLE_SLOT_VA: Final[int] = 0x1830D44F8
CAPACITY_VA: Final[int] = 0x1830D4500
COUNT_VA: Final[int] = 0x1830D4508

PATCHER_RVA: Final[int] = 0x1E270
ORCHESTRATOR_RVA: Final[int] = 0x1E360
RIP_REDIRECT_RVA: Final[int] = 0x1DFF0
REGISTRAR_RVA: Final[int] = 0x1DCF0
LIST_BUILDER_RVA: Final[int] = 0x1E590
ARENA_RVA: Final[int] = 0x1D280
INIT_RVA: Final[int] = 0x1DC80
DECODER_RVA: Final[int] = 0x1D550

CALLER_ALL_RVA: Final[int] = 0x1E425
CALLER_ONE_RVA: Final[int] = 0x1E4FD

PATCH_FLAG_MASK: Final[int] = 0x06
FIRST_FAILURE_CODE: Final[int] = 0x0A
LIST_ENTRY_CAP: Final[int] = 8
LIST_CAPACITY_BYTES: Final[int] = 8
LIST_COUNT_MASK: Final[int] = 0x0F
SCAN_LENGTH_CAP: Final[int] = 0x32
INITIAL_CAPACITY_RECORDS: Final[int] = 0x20
PAGE_EXECUTE_READWRITE: Final[int] = 0x40



SPIN_BACKOFF_CAP: Final[int] = 0x20
SLEEP_IAT_RVA: Final[int] = 0x2E4D588
HEAPCREATE_IAT_RVA: Final[int] = 0x2E4D418
HEAPFREE_IAT_RVA: Final[int] = 0x2E4D420
GETPROCESSHEAP_IAT_RVA: Final[int] = 0x2E4D3C0
HEAP_ALLOCATOR_IAT_RVAS: Final[tuple[int, ...]] = (0x2E4D410, 0x2E4D428)



HEAP_GATE_RVA: Final[int] = 0x1E3A4
ORCHESTRATOR_EXIT_RVA: Final[int] = 0x1E560
HEAP_GATE_FAIL_CODE: Final[int] = 0x02
SINGLE_PATH_EMPTY_CODE: Final[int] = 0x04
SINGLE_PATH_SKIP_CODE: Final[int] = 0x05


LOCK_HOLDERS: Final[tuple[tuple[str, int], ...]] = (
    ("init", 0x1DCA3),
    ("registrar", 0x1DD33),
    ("orchestrator", 0x1E39A),
)


COMPONENT_LOW_RVA: Final[int] = 0x1D280
COMPONENT_HIGH_RVA: Final[int] = 0x1E9D0


EXPR_RECORD: Final[str] = "rec = *(qword *)(0x1830D44F8) + index * 0x38"
EXPR_PATCH_SITE: Final[str] = "rec + 0x00 - 5 * (rec[0x20] & 1)"
EXPR_JUMP_DEST: Final[str] = "rec + 0x08"
EXPR_REL32: Final[str] = "rec + 0x08 - patch_site - 5"
EXPR_SHORT_JUMP_SITE: Final[str] = "rec + 0x00"
EXPR_REGION: Final[str] = "patch_site .. patch_site + 5 + 2 * (rec[0x20] & 1)"
EXPR_RIP_MATCH: Final[str] = "rec + 0x00 + rec[0x28][i]"
EXPR_RIP_TARGET: Final[str] = "rec + 0x10 + rec[0x30][i]"
EXPR_RECORD_LOOKUP: Final[str] = "rec + 0x00 == caller argument"
EXPR_HEAP_HANDLE: Final[str] = "qword *(0x1830D44F0)"
EXPR_HEAP_GATE: Final[str] = "cmp qword *(0x1830D44F0), 0"




EXPR_PATCH_SITE_GROUP: Final[str] = "patch_site .. patch_site + 5"
EXPR_ANCHOR_GROUP: Final[str] = "patch_site + 5 .. patch_site + 7"

CONFIDENCE_SCALE: Final[Mapping[str, str]] = {
    "H": "structurally proven from the file, an instruction or an immediate settles it",
    "M": "derived from the file but conditional on one run time precondition",
    "L": "weak, the mechanism is known but the instance data is absent from the file",
    "OPEN": "not decidable from the file alone, carried as an open question",
}

CSV_FIELDS: Final[tuple[str, ...]] = (
    "id",
    "component",
    "kind",
    "site_rva",
    "site_va",
    "record_offset",
    "field",
    "access",
    "width_expr",
    "value_expr",
    "target_expr",
    "readers",
    "writers",
    "confidence",
    "status",
    "note",
)

TRACKED_GLOBALS: Final[tuple[tuple[str, int, int, str], ...]] = (
    ("region_free_list", REGION_LIST_VA, 8, "head of the reusable region list owned by the arena"),
    (
        "spin_lock",
        LOCK_VA,
        4,
        "hand rolled interlocked spin lock, the contention counter is unbounded and every holder re-checks "
        "its own precondition, so it is a mutual exclusion lock and not a one shot initialiser",
    ),
    (
        "heap_handle",
        HEAP_HANDLE_VA,
        8,
        "private KERNEL32!HeapCreate(0, 0, 0) handle, zero in the file and published by its only writer, "
        "the init that itself has no direct caller",
    ),
    ("record_array", TABLE_SLOT_VA, 8, "pointer to the record array, zero until the registrar allocates it"),
    ("capacity", CAPACITY_VA, 4, "allocated record count of the array"),
    ("count", COUNT_VA, 4, "live record count and the upper bound of every index scan"),
)

_READ_WRITE_MNEMONICS: Final[frozenset[str]] = frozenset(
    {"xchg", "cmpxchg", "add", "or", "and", "shl", "shr", "sar", "inc", "dec", "not", "neg"}
)
_STORE_MNEMONICS: Final[frozenset[str]] = frozenset({"mov", "movzx", "movsx", "movsxd", "stosq", "stosd"})



_RIP_RELATIVE_MODRM: Final[tuple[int, ...]] = (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D)




_TRAILING_BYTES: Final[tuple[int, ...]] = (0, 1, 2, 4, 8)



_BRANCH_NAMES: Final[frozenset[str]] = frozenset({"call", "jmp"})
_BRANCH_PREFIX: Final[str] = "j"







@dataclass(frozen=True, slots=True)
class Insn:
    """One decoded instruction, reduced to the facts the evidence set needs.

    rip_targets holds resolved rvas, mem_disps and mem_sizes keep the raw operand
    displacements and widths, and call_target is the rva of a direct call or
    direct jump destination, None when the branch goes through a register or a
    memory slot.
    """

    rva: int
    size: int
    mnemonic: str
    rip_targets: tuple[int, ...]
    mem_disps: tuple[int, ...]
    mem_sizes: tuple[int, ...]
    immediates: tuple[int, ...]
    registers: tuple[str, ...]
    call_target: int | None
    indirect: bool
    memory_is_destination: bool


def _decode(pe: pefile.PE, md: capstone.Cs, start_rva: int, size: int) -> tuple[Insn, ...]:
    data = common.read_rva(pe, start_rva, size)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    decoded: list[Insn] = []
    for ins in md.disasm(data, image_base + start_rva):
        rip_targets: list[int] = []
        mem_disps: list[int] = []
        mem_sizes: list[int] = []
        immediates: list[int] = []
        registers: list[str] = []
        call_target: int | None = None
        for operand in ins.operands:
            if operand.type == X86_OP_IMM:
                immediates.append(operand.imm)
                if ins.mnemonic in _BRANCH_NAMES or ins.mnemonic.startswith(_BRANCH_PREFIX):
                    call_target = operand.imm - image_base
            else:
                registers.append(ins.reg_name(operand.reg))
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
                registers=tuple(registers),
                call_target=call_target,
                indirect=call_target is None,
                memory_is_destination=bool(ins.operands) and ins.operands[0].type == X86_OP_MEM,
            )
        )
    return tuple(decoded)


def runtime_functions(pe: pefile.PE) -> tuple[tuple[int, int, int], ...]:
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[common.EXCEPTION_DIRECTORY_INDEX]
    blob = common.read_rva(pe, int(directory.VirtualAddress), int(directory.Size))
    return tuple(struct.iter_unpack("<III", blob))


def function_bounds(pe: pefile.PE, rva: int) -> tuple[int, int, int]:
    """Resolve the pdata record that covers rva into (begin, end, unwind)."""
    for begin, end, unwind in runtime_functions(pe):
        if begin <= rva < end:
            return begin, end, unwind
    raise KeyError(common.hexs(rva))


def function_instructions(
    pe: pefile.PE, md: capstone.Cs, cache: dict[tuple[int, int], tuple[Insn, ...]], rva: int
) -> tuple[int, int, tuple[Insn, ...]]:
    begin, end, _ = function_bounds(pe, rva)
    key = (begin, end)
    if key not in cache:
        cache[key] = _decode(pe, md, begin, end - begin)
    return begin, end, cache[key]


def classify_access(insn: Insn) -> str:
    """Label a memory operand as a read, a write, a read write or an address computation."""
    if not insn.mem_disps:
        return "none"
    if insn.mnemonic == "lea":
        return "address"
    if insn.mnemonic in _READ_WRITE_MNEMONICS:
        return "read_write" if insn.memory_is_destination else "read"
    if insn.memory_is_destination and insn.mnemonic in _STORE_MNEMONICS:
        return "write"
    return "read"


def instruction_at(insns: Sequence[Insn], rva: int) -> Insn | None:
    for insn in insns:
        if insn.rva == rva:
            return insn
    return None


def instruction_covering(insns: Sequence[Insn], rva: int, targets: frozenset[int]) -> Insn | None:
    """The instruction that contains the byte at rva and whose rip operand reaches into targets."""
    for insn in insns:
        if not insn.rva <= rva < insn.rva + insn.size:
            continue
        if any(target in targets for target in insn.rip_targets):
            return insn
    return None


def _owner_begin(ordered_begins: Sequence[int], rva: int) -> int | None:
    low, high = 0, len(ordered_begins) - 1
    found: int | None = None
    while low <= high:
        middle = (low + high) // 2
        if ordered_begins[middle] <= rva:
            found = ordered_begins[middle]
            low = middle + 1
        else:
            high = middle - 1
    return found


def scan_rip_references(
    pe: pefile.PE, md: capstone.Cs, section: common.Section, targets: frozenset[int]
) -> list[dict[str, Any]]:
    """Every rip relative memory operand in the section that resolves into targets.

    The cheap filter locates the eight possible rip relative ModRM encodings, the
    decoder then confirms the instruction and the resolved target, so instructions
    that carry an immediate behind the displacement are attributed correctly.
    """
    blob = common.read_rva(pe, section.virtual_address, section.raw_size)
    base = section.virtual_address
    funcs = runtime_functions(pe)
    ordered_begins = sorted(record[0] for record in funcs)
    ends = {record[0]: record[1] for record in funcs}
    cache: dict[tuple[int, int], tuple[Insn, ...]] = {}
    found: list[dict[str, Any]] = []
    for modrm in _RIP_RELATIVE_MODRM:
        needle = bytes((modrm,))
        cursor = 0
        while True:
            index = blob.find(needle, cursor)
            if index < 0 or index + 5 > len(blob):
                break
            cursor = index + 1
            displacement = struct.unpack_from("<i", blob, index + 1)[0]
            field_end = base + index + 5
            if not any(field_end + tail + displacement in targets for tail in _TRAILING_BYTES):
                continue
            modrm_rva = base + index
            begin = _owner_begin(ordered_begins, modrm_rva)
            if begin is None:
                continue
            end = ends.get(begin, 0)
            if (begin, end) not in cache:
                cache[(begin, end)] = _decode(pe, md, begin, end - begin)
            insn = instruction_covering(cache[(begin, end)], modrm_rva, targets)
            if insn is None:
                continue
            found.append(
                {
                    "site_rva": common.hexs(modrm_rva),
                    "instruction_rva": common.hexs(insn.rva),
                    "function_rva": common.hexs(begin),
                    "mnemonic": insn.mnemonic,
                    "access": classify_access(insn),
                    "operand_recovered": True,
                    "target": next(item for item in insn.rip_targets if item in targets),
                }
            )
    found.sort(key=lambda entry: (entry["site_rva"], entry["target"]))
    return found


def scan_direct_calls(pe: pefile.PE, section: common.Section, targets: frozenset[int]) -> list[int]:
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
        target = base + index + 5 + struct.unpack_from("<i", blob, index + 1)[0]
        if target in targets:
            sites.append(base + index)
    sites.sort()
    return sites


def _section_bytes(pe: pefile.PE, section: common.Section) -> bytes:
    """The file backed bytes of one section, empty for a section without raw data."""
    if not section.raw_size:
        return b""
    return common.read_rva(pe, section.virtual_address, section.raw_size)


def scan_file_direct_calls(pe: pefile.PE, targets: frozenset[int]) -> list[int]:
    """Every relative call site anywhere in the file whose destination is in targets.

    The search covers all sections with file backed bytes, not only the code
    section, so an absent caller is a statement about the whole specimen.
    """
    sites: list[int] = []
    for section in common.sections(pe):
        if not section.raw_size:
            continue
        chunk = _section_bytes(pe, section)
        cursor = 0
        while True:
            index = chunk.find(b"\xe8", cursor)
            if index < 0 or index + 5 > len(chunk):
                break
            cursor = index + 1
            target = section.virtual_address + index + 5 + struct.unpack_from("<i", chunk, index + 1)[0]
            if target in targets:
                sites.append(section.virtual_address + index)
    sites.sort()
    return sites


def scan_rip_operand_sections(pe: pefile.PE, targets: frozenset[int]) -> dict[str, list[str]]:
    """The sections that hold a rip relative operand encoding resolving into targets.

    This is the cheap byte filter, it runs over every section and it does not
    resolve the instruction, so one site can be counted for more than one target
    and a count from it is not a reference count. Its only use is the negative
    statements: a target with no hit outside the code section is not read or
    written from a data section in that operand form.
    """
    raw: dict[str, set[str]] = {}
    for section in common.sections(pe):
        if not section.raw_size:
            continue
        chunk = _section_bytes(pe, section)
        for modrm in _RIP_RELATIVE_MODRM:
            needle = bytes((modrm,))
            cursor = 0
            while True:
                index = chunk.find(needle, cursor)
                if index < 0 or index + 5 > len(chunk):
                    break
                cursor = index + 1
                displacement = struct.unpack_from("<i", chunk, index + 1)[0]
                field_end = section.virtual_address + index + 5
                for tail in _TRAILING_BYTES:
                    candidate = field_end + tail + displacement
                    if candidate in targets:
                        raw.setdefault(common.hexs(candidate), set()).add(section.name)
    return {target: sorted(names) for target, names in sorted(raw.items())}


def scan_iat_calls(pe: pefile.PE, slots: frozenset[int]) -> dict[int, list[int]]:
    """Every indirect call through an import address table slot, keyed by that slot.

    The pattern is the six byte ff 15 form, so a thunk is reported at its own
    site rather than at the slot, and a data reference to a slot is not counted
    as a call.
    """
    sites: dict[int, list[int]] = {slot: [] for slot in slots}
    for section in common.sections(pe):
        if not section.raw_size:
            continue
        chunk = _section_bytes(pe, section)
        cursor = 0
        while True:
            index = chunk.find(b"\xff\x15", cursor)
            if index < 0 or index + 6 > len(chunk):
                break
            cursor = index + 1
            displacement = struct.unpack_from("<i", chunk, index + 2)[0]
            target = section.virtual_address + index + 6 + displacement
            if target in sites:
                sites[target].append(section.virtual_address + index)
    return {slot: sorted(values) for slot, values in sorted(sites.items())}


def resolve_iat(pe: pefile.PE) -> dict[int, str]:
    """Import address table slots, keyed by rva."""
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    table: dict[int, str] = {}
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = descriptor.dll.decode("ascii", errors="replace")
        for entry in descriptor.imports:
            name = entry.name.decode("ascii", errors="replace") if entry.name else f"ordinal_{entry.ordinal}"
            table[int(entry.address) - image_base] = f"{dll}!{name}"
    return table


def offset_hex(value: int) -> str:
    """Byte offset inside a record, zero padded to two digits."""
    return f"0x{value:02X}"







@dataclass(frozen=True, slots=True)
class Anchor:
    """One claim about one instruction, verified against the file on every run."""

    name: str
    rva: int
    mnemonic: str
    description: str
    rip_target: int | None = None
    mem_disp: int | None = None
    mem_size: int | None = None
    imm: int | None = None
    call_target: int | None = None


ANCHORS: Final[tuple[Anchor, ...]] = (
    Anchor("table_slot_load", 0x1E28A, "mov", "the patcher loads the record array pointer once per call", rip_target=0x30D44F8, mem_size=8),
    Anchor("table_slot_load_scan", 0x1E3D3, "mov", "the orchestrator loads the same array pointer", rip_target=0x30D44F8, mem_size=8),
    Anchor("table_slot_load_loop", 0x1E411, "mov", "the orchestrator reloads the array pointer inside the patch loop", rip_target=0x30D44F8, mem_size=8),
    Anchor("table_slot_load_lookup", 0x1E4B4, "mov", "the orchestrator loads the array pointer for the address lookup", rip_target=0x30D44F8, mem_size=8),
    Anchor("table_store_first_alloc", 0x1DEBB, "mov", "the first allocation result is stored into the table slot", rip_target=0x30D44F8, mem_size=8),
    Anchor("table_store_grow", 0x1DF0C, "mov", "a reallocation result replaces the table slot", rip_target=0x30D44F8, mem_size=8),
    Anchor("count_load_guard", 0x1E3C1, "mov", "the orchestrator reads the record count", rip_target=0x30D4508, mem_size=4),
    Anchor("count_store_increment", 0x1DF1C, "mov", "the registrar stores count plus one", rip_target=0x30D4508, mem_size=4),
    Anchor("capacity_store_initial", 0x1DE9C, "mov", "the initial capacity is expressed in records", rip_target=0x30D4500, mem_size=4, imm=INITIAL_CAPACITY_RECORDS),
    Anchor("capacity_double", 0x1DF06, "shl", "the capacity doubles after a growth", rip_target=0x30D4500, mem_size=4, imm=1),
    Anchor("first_allocation_bytes", 0x1DEAD, "mov", "the first allocation size equals the initial capacity times the stride", imm=INITIAL_CAPACITY_RECORDS * RECORD_STRIDE),
    Anchor("spin_lock_take_registrar", 0x1DD33, "cmpxchg", "the registrar takes the interlocked spin lock", rip_target=0x30D44E8, mem_size=4),
    Anchor("spin_lock_drop_registrar", 0x1DFBD, "xchg", "the registrar releases the interlocked spin lock", rip_target=0x30D44E8, mem_size=4),
    Anchor("spin_lock_take_orchestrator", 0x1E39A, "cmpxchg", "the orchestrator takes the same spin lock", rip_target=0x30D44E8, mem_size=4),
    Anchor("spin_lock_drop_orchestrator", 0x1E562, "xchg", "the orchestrator releases the same spin lock", rip_target=0x30D44E8, mem_size=4),
    Anchor("spin_lock_retry_threshold_init", 0x1DC91, "cmp", "the init backoff threshold only saturates the Sleep argument", imm=SPIN_BACKOFF_CAP),
    Anchor("spin_lock_backoff_init", 0x1DC98, "call", "the init contention path sleeps zero or one millisecond", rip_target=SLEEP_IAT_RVA),
    Anchor("spin_lock_retry_increment_init", 0x1DC9E, "inc", "the init retry counter grows without a bound"),
    Anchor("spin_lock_retry_threshold_registrar", 0x1DD21, "cmp", "the registrar backoff threshold only saturates the Sleep argument", imm=SPIN_BACKOFF_CAP),
    Anchor("spin_lock_backoff_registrar", 0x1DD28, "call", "the registrar contention path sleeps zero or one millisecond", rip_target=SLEEP_IAT_RVA),
    Anchor("spin_lock_retry_increment_registrar", 0x1DD2E, "inc", "the registrar retry counter grows without a bound"),
    Anchor("spin_lock_retry_threshold_orchestrator", 0x1E388, "cmp", "the orchestrator backoff threshold only saturates the Sleep argument", imm=SPIN_BACKOFF_CAP),
    Anchor("spin_lock_backoff_orchestrator", 0x1E38F, "call", "the orchestrator contention path sleeps zero or one millisecond", rip_target=SLEEP_IAT_RVA),
    Anchor("spin_lock_retry_increment_orchestrator", 0x1E395, "inc", "the orchestrator retry counter grows without a bound"),
    Anchor("spin_lock_recheck_init", 0x1DCAD, "cmp", "the init re-checks its own precondition, so the flag is a lock and not a one shot initialiser", rip_target=0x30D44F0, mem_size=8),
    Anchor("spin_lock_recheck_registrar", 0x1DD3D, "cmp", "the registrar re-checks its own precondition, so the flag is a lock and not a one shot initialiser", rip_target=0x30D44F0, mem_size=8),
    Anchor("spin_lock_recheck_orchestrator", 0x1E3A4, "cmp", "the orchestrator re-checks its own precondition, so the flag is a lock and not a one shot initialiser", rip_target=0x30D44F0, mem_size=8),
    Anchor("spin_lock_release_join", 0x1E560, "xor", "every orchestrator exit converges here and releases the lock exactly once"),
    Anchor("heap_create_args_first", 0x1DCB7, "xor", "the first HeapCreate argument is zeroed"),
    Anchor("heap_create_args_second", 0x1DCB9, "xor", "the second HeapCreate argument is zeroed"),
    Anchor("heap_create_args_third", 0x1DCBB, "xor", "the third HeapCreate argument is zeroed"),
    Anchor("heap_create_call", 0x1DCBE, "call", "the init creates a private heap with three zero arguments", rip_target=HEAPCREATE_IAT_RVA),
    Anchor("heap_handle_init", 0x1DCC4, "mov", "the only writer in the file publishes the private heap handle here", rip_target=0x30D44F0, mem_size=8),
    Anchor("heap_free_call", 0x1E55A, "call", "the orchestrator frees the same private heap before it releases the lock", rip_target=HEAPFREE_IAT_RVA),
    Anchor("heap_handle_guard", 0x1E3A4, "cmp", "the orchestrator refuses to run before the private heap handle is published", rip_target=0x30D44F0, mem_size=8),
    Anchor("activation_heap_gate_fail_code", 0x1E3AE, "mov", "an unpublished heap handle yields this failure code", imm=HEAP_GATE_FAIL_CODE),
    Anchor("activation_heap_gate_exit", 0x1E3B3, "jmp", "the gate failure leaves the orchestrator before either patcher call site", call_target=ORCHESTRATOR_EXIT_RVA),
    Anchor("activation_empty_table_code", 0x1E4A6, "mov", "the single record path reports an empty table with this code", imm=SINGLE_PATH_EMPTY_CODE),
    Anchor("activation_single_path_code", 0x1E4E3, "mov", "the single record path reports a skipped or unpatchable record with this code", imm=SINGLE_PATH_SKIP_CODE),
    Anchor("activation_single_skip_exit", 0x1E4ED, "jne", "a skipped record leaves the single record path before the patcher", call_target=ORCHESTRATOR_EXIT_RVA),
    Anchor("stride_patcher", 0x1E293, "imul", "index times 0x38 selects the record", imm=RECORD_STRIDE),
    Anchor("stride_lookup", 0x1E4BD, "imul", "the address lookup walks records with the same stride", imm=RECORD_STRIDE),
    Anchor("stride_rip_redirect", 0x1E152, "imul", "the context rewrite walks records with the same stride", imm=RECORD_STRIDE),
    Anchor("stride_capacity_bytes", 0x1DEE1, "imul", "a growth allocates the new capacity times 0x38 bytes", imm=RECORD_STRIDE),
    Anchor("stride_duplicate_scan", 0x1DDCC, "imul", "duplicate detection walks records with the same stride", imm=RECORD_STRIDE),
    Anchor("stride_orchestrator_scan", 0x1E3DC, "imul", "the orchestrator finds the first usable index with the same stride", imm=RECORD_STRIDE),
    Anchor("stride_orchestrator_loop", 0x1E418, "imul", "the orchestrator patch loop uses the same stride", imm=RECORD_STRIDE),
    Anchor("read_base", 0x1E297, "mov", "the patch anchor address is read from rec plus 0x00", mem_disp=0x00, mem_size=8),
    Anchor("read_flags", 0x1E29B, "movzx", "the flag byte is read from rec plus 0x20", mem_disp=0x20, mem_size=1),
    Anchor("read_destination", 0x1E2ED, "mov", "the jump destination is read from the low dword of rec plus 0x08", mem_disp=0x08, mem_size=4),
    Anchor("variant_test", 0x1E2A3, "test", "flag bit 0 selects the patch layout", imm=1),
    Anchor("variant_invert", 0x1E2A6, "sete", "the bit 0 test is inverted into a zero or one scale"),
    Anchor("variant_scale", 0x1E2A9, "lea", "the inverted bit is scaled by five", mem_disp=0),
    Anchor("site_sum", 0x1E2AD, "lea", "the anchor and the scaled bit are added", mem_disp=0),
    Anchor("site_bias", 0x1E2B1, "add", "the patch site is biased by minus five", imm=-5),
    Anchor("region_size", 0x1E2B8, "lea", "the region size is five plus twice the flag bit", mem_disp=5),
    Anchor("flag_field_pointer", 0x1E2E2, "lea", "a pointer to rec plus 0x20 is formed", mem_disp=0),
    Anchor("flag_field_bias", 0x1E2E6, "add", "the flag pointer is biased by 0x20", imm=0x20),
    Anchor("protect_request", 0x1E2CB, "mov", "the requested protection is executable read write", imm=PAGE_EXECUTE_READWRITE),
    Anchor("virtualprotect_open", 0x1E2D1, "call", "the first VirtualProtect makes the region writable"),
    Anchor("first_failure_code", 0x1E2DB, "mov", "the only failure code the patcher produces itself", imm=FIRST_FAILURE_CODE),
    Anchor("rel32_target_delta", 0x1E2F2, "sub", "destination minus patch site"),
    Anchor("rel32_bias", 0x1E2F4, "add", "the relative displacement is biased by minus five", imm=-5),
    Anchor("rel32_store", 0x1E2F7, "mov", "four displacement bytes are stored at patch site plus one", mem_disp=1, mem_size=4),
    Anchor("opcode_store", 0x1E2EA, "mov", "the first byte of the region is stored at the patch site itself", mem_disp=0, mem_size=1),
    Anchor("short_jump_test", 0x1E2FA, "test", "flag bit 0 also gates a second store", mem_disp=0, mem_size=1, imm=1),
    Anchor("short_jump_store", 0x1E306, "mov", "two bytes are stored at rec plus 0x00, the anchor, when bit 0 is set", mem_disp=0, mem_size=2),
    Anchor("virtualprotect_restore", 0x1E31B, "call", "the saved protection is restored, the result is dropped"),
    Anchor("current_process", 0x1E321, "call", "the current process pseudo handle feeds the cache flush"),
    Anchor("cache_flush", 0x1E330, "call", "the patched region is flushed, the result is dropped"),
    Anchor("patch_flag_write", 0x1E336, "or", "the record flag byte is updated with the patch state", mem_disp=0, mem_size=1, imm=PATCH_FLAG_MASK),
    Anchor("success_code", 0x1E33A, "xor", "the success path yields zero"),
    Anchor("return_value", 0x1E349, "mov", "the patcher returns the code it selected"),
    Anchor("caller_all_records", CALLER_ALL_RVA, "call", "first direct call site of the patcher", call_target=PATCHER_RVA),
    Anchor("caller_single_record", CALLER_ONE_RVA, "call", "second direct call site of the patcher", call_target=PATCHER_RVA),
    Anchor("caller_index_from_counter", 0x1E423, "mov", "the loop counter becomes the index argument"),
    Anchor("caller_index_from_search", 0x1E4FB, "mov", "the found index becomes the index argument"),
    Anchor("lookup_compare", 0x1E4C1, "cmp", "records are looked up by comparing rec plus 0x00 with the argument", mem_disp=0, mem_size=8),
    Anchor("orchestrator_skip_all", 0x1E3E0, "test", "flag bit 1 hides a record from the bulk path", mem_disp=0x20, mem_size=1, imm=2),
    Anchor("orchestrator_skip_loop", 0x1E41C, "test", "flag bit 1 hides a record from the patch loop", mem_disp=0x20, mem_size=1, imm=2),
    Anchor("orchestrator_skip_single", 0x1E4E8, "test", "flag bit 1 hides a record from the single path", mem_disp=0x20, mem_size=1, imm=2),
    Anchor("redirect_skip", 0x1E156, "test", "flag bit 1 hides a record from the context rewrite", mem_disp=0x20, mem_size=1, imm=2),
    Anchor("redirect_record_base", 0x1E16F, "lea", "the context rewrite keeps the record base in a register", mem_disp=0),
    Anchor("redirect_anchor_value", 0x1E17B, "mov", "rec plus 0x00 is loaded for the offset sum", mem_disp=0, mem_size=8),
    Anchor("redirect_count_load", 0x1E161, "mov", "the entry count dword is read from rec plus 0x24", mem_disp=0x24, mem_size=4),
    Anchor("redirect_count_mask", 0x1E165, "and", "only the low nibble of the count dword is used", imm=LIST_COUNT_MASK),
    Anchor("redirect_count_zero", 0x1E169, "je", "a zero count makes the record inert for the context rewrite"),
    Anchor("redirect_offset_load", 0x1E1E9, "movzx", "one offset byte is read from rec plus 0x28", mem_disp=0x28, mem_size=1),
    Anchor("redirect_offset_base", 0x1E1EF, "add", "the offset byte is added to rec plus 0x00"),
    Anchor("redirect_displacement_load", 0x1E1F7, "movzx", "one displacement byte is read from rec plus 0x30", mem_disp=0x30, mem_size=1),
    Anchor("redirect_displacement_base", 0x1E1FD, "add", "the displacement byte is added to rec plus 0x10", mem_disp=0x10, mem_size=8),
    Anchor("redirect_displacement_zero", 0x1E202, "je", "a zero result makes the matching entry inert"),
    Anchor("redirect_new_rip", 0x1E204, "mov", "the new instruction pointer is written into the context", mem_disp=0x128, mem_size=8),
    Anchor("redirect_apply", 0x1E214, "call", "the rewritten context is applied to the thread"),
    Anchor("list_count_load", 0x1E834, "mov", "the builder keeps its entry counter in the descriptor", mem_disp=0x24, mem_size=4),
    Anchor("list_count_cap", 0x1E837, "cmp", "the builder refuses a ninth entry", imm=LIST_ENTRY_CAP),
    Anchor("list_offset_store", 0x1E844, "mov", "an offset byte is appended at 0x28", mem_disp=0x28, mem_size=1),
    Anchor("list_displacement_store", 0x1E849, "mov", "the parallel displacement byte is appended at 0x30", mem_disp=0x30, mem_size=1),
    Anchor("list_count_store", 0x1E850, "mov", "the entry counter is incremented", mem_disp=0x24, mem_size=4),
    Anchor("scan_length_cap", 0x1E82F, "cmp", "the scanned window is capped", imm=SCAN_LENGTH_CAP),
    Anchor("prefix_probe_flag", 0x1E974, "mov", "the builder sets the flag dword when a five byte filler run precedes the anchor", mem_disp=0x20, mem_size=4, imm=1),
    Anchor("registrar_base_store", 0x1DF2B, "mov", "rec plus 0x00 is written from the descriptor", mem_disp=0, mem_size=8),
    Anchor("registrar_destination_store", 0x1DF34, "mov", "rec plus 0x08 is written from the descriptor", mem_disp=8, mem_size=8),
    Anchor("registrar_image_store", 0x1DF3E, "mov", "rec plus 0x10 is written from the arena block", mem_disp=0x10, mem_size=8),
    Anchor("original_bytes_store_long", 0x1DFA0, "mov", "the long original byte snapshot is stored at 0x1b", mem_disp=3, mem_size=4),
    Anchor("original_bytes_store_short", 0x1DFAA, "mov", "the short original byte snapshot is stored at 0x1c", mem_disp=4, mem_size=1),
    Anchor("original_bytes_store_head", 0x1DFAF, "mov", "the snapshot head is stored at 0x18", mem_disp=0, mem_size=4),
    Anchor("registrar_flag_new_bit", 0x1DF4F, "and", "only bit 0 of the new flag byte comes from the builder", imm=1),
    Anchor("registrar_flag_keep", 0x1DF53, "and", "the upper flag bits of the slot are preserved", imm=0xF8),
    Anchor("registrar_flag_merge", 0x1DF57, "or", "the new and the preserved flag bits are merged"),
    Anchor("registrar_flag_store", 0x1DF5A, "mov", "the merged flag byte is stored at rec plus 0x20", mem_disp=0x20, mem_size=1),
    Anchor("registrar_count_mask_new", 0x1DF69, "and", "only the low nibble of the new count is used", imm=LIST_COUNT_MASK),
    Anchor("registrar_count_keep", 0x1DF6D, "and", "the upper three bytes of the stored count dword are preserved", imm=0xFFFFFFF0),
    Anchor("registrar_count_store", 0x1DF74, "mov", "the merged count dword is stored at rec plus 0x24", mem_disp=0x24, mem_size=4),
    Anchor("registrar_offsets_store", 0x1DF7E, "mov", "all eight offset bytes are stored at rec plus 0x28", mem_disp=0x28, mem_size=8),
    Anchor("registrar_displacements_store", 0x1DF88, "mov", "all eight displacement bytes are stored at rec plus 0x30", mem_disp=0x30, mem_size=8),
    Anchor("registrar_duplicate_scan", 0x1DDD0, "cmp", "registration rejects an anchor that is already registered", mem_disp=0, mem_size=8),
    Anchor("registrar_arena_block", 0x1DE15, "mov", "the arena block becomes the descriptor image pointer", mem_disp=0x30, mem_size=8),
)


def verify_anchors(pe: pefile.PE, md: capstone.Cs) -> list[dict[str, Any]]:
    """Check every anchor against the file; the outcome becomes the invariants."""
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    cache: dict[tuple[int, int], tuple[Insn, ...]] = {}
    results: list[dict[str, Any]] = []
    for anchor in ANCHORS:
        begin, end, _ = function_instructions(pe, md, cache, anchor.rva)
        insn = instruction_at(cache[(begin, end)], anchor.rva)
        problems: list[str] = []
        if insn is None:
            problems.append("no instruction decodes at this rva")
        else:
            if insn.mnemonic != anchor.mnemonic:
                problems.append(f"mnemonic {insn.mnemonic} instead of {anchor.mnemonic}")
            if anchor.rip_target is not None and anchor.rip_target not in insn.rip_targets:
                problems.append(f"rip relative target {common.hexs(anchor.rip_target)} absent")
            if anchor.mem_disp is not None and anchor.mem_disp not in insn.mem_disps:
                problems.append(f"memory displacement {common.hexs(anchor.mem_disp)} absent")
            if anchor.mem_size is not None and anchor.mem_size not in insn.mem_sizes:
                problems.append(f"operand width {anchor.mem_size} absent")
            if anchor.imm is not None and anchor.imm not in insn.immediates:
                problems.append(f"immediate {common.hexs(anchor.imm)} absent")
            if anchor.call_target is not None and insn.call_target != anchor.call_target:
                problems.append(f"call destination {insn.call_target} instead of {common.hexs(anchor.call_target)}")
        results.append(
            {
                "anchor": anchor.name,
                "site_rva": common.hexs(anchor.rva),
                "site_va": common.hexs(image_base + anchor.rva),
                "function_rva": common.hexs(begin),
                "description": anchor.description,
                "ok": not problems,
                "problem": "; ".join(problems) if problems else None,
            }
        )
    return results







def _function_card(pe: pefile.PE, name: str, probe_rva: int, role: str) -> dict[str, Any]:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    begin, end, unwind = function_bounds(pe, probe_rva)
    return {
        "name": name,
        "role": role,
        "rva": common.hexs(begin),
        "va": common.hexs(image_base + begin),
        "end_rva": common.hexs(end),
        "size": common.hexs(end - begin),
        "unwind_info_rva": common.hexs(unwind),
    }


def _iat_symbol(iat: Mapping[int, str], insn: Insn) -> str | None:
    if insn.mnemonic != "call" or not insn.indirect or not insn.rip_targets:
        return None
    slot = insn.rip_targets[0]
    return iat.get(slot, f"unresolved_iat_{common.hexs(slot)}")


def _comparisons_between(insns: Sequence[Insn], low: int, high: int) -> list[Insn]:
    return [insn for insn in insns if low <= insn.rva < high and insn.mnemonic in ("cmp", "test")]


def _validation_window(
    name: str, watched_register: str, loaded_at: int, first_use: int, comparisons: Sequence[Insn]
) -> dict[str, Any]:
    """Report whether a value is compared between its load site and its first use.

    The window bounds are curated, both the comparison list and the subset that
    touches the watched register are derived from the file.
    """
    on_watched = [insn for insn in comparisons if watched_register in insn.registers]
    return {
        "input": name,
        "watched_register": watched_register,
        "loaded_at": common.hexs(loaded_at),
        "first_use": common.hexs(first_use),
        "comparisons_between": [common.hexs(insn.rva) for insn in comparisons],
        "guards_on_watched_register": [common.hexs(insn.rva) for insn in on_watched],
        "checked": bool(on_watched),
    }


def _last_before(insns: Sequence[Insn], take_rva: int, predicate: Any) -> Insn | None:
    """The last instruction before the take site that satisfies predicate."""
    matches = [insn for insn in insns if insn.rva < take_rva and predicate(insn)]
    return matches[-1] if matches else None


def lock_profile(
    pe: pefile.PE, md: capstone.Cs, iat: Mapping[int, str], globals_out: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """The mutual exclusion around the table, derived from the take and drop sites.

    Every holder of the flag re-checks its own precondition after the acquire,
    which is what separates this from a run once initialisation flag, and every
    holder reaches the acquire again through a counter that is incremented
    without a comparison against a bound.
    """
    lock = next(entry for entry in globals_out if entry["name"] == "spin_lock")
    heap = next(entry for entry in globals_out if entry["name"] == "heap_handle")
    holders: list[dict[str, Any]] = []
    for name, take_rva in LOCK_HOLDERS:
        begin, _, insns = function_instructions(pe, md, {}, take_rva)
        take = instruction_at(insns, take_rva)
        drop_rva = next(
            (site["instruction_rva"] for site in lock["references"] if site["function_rva"] == common.hexs(begin) and site["mnemonic"] == "xchg"),
            None,
        )
        recheck = next(
            (
                site
                for site in heap["references"]
                if site["function_rva"] == common.hexs(begin) and site["mnemonic"] == "cmp"
            ),
            None,
        )
        threshold = _last_before(insns, take_rva, lambda insn: SPIN_BACKOFF_CAP in insn.immediates)
        backoff = _last_before(
            insns,
            take_rva,
            lambda insn: insn.mnemonic == "call" and SLEEP_IAT_RVA in insn.rip_targets,
        )
        counter = _last_before(insns, take_rva, lambda insn: insn.mnemonic == "inc")
        holders.append(
            {
                "name": name,
                "function_rva": common.hexs(begin),
                "take_site_rva": common.hexs(take_rva) if take is not None else None,
                "take_primitive": "lock cmpxchg" if take is not None and take.mnemonic == "cmpxchg" else None,
                "drop_site_rva": drop_rva,
                "drop_primitive": "xchg with zero" if drop_rva is not None else None,
                "recheck_site_rva": recheck["instruction_rva"] if recheck is not None else None,
                "recheck_target": EXPR_HEAP_HANDLE if recheck is not None else None,
                "backoff_threshold_site_rva": common.hexs(threshold.rva) if threshold is not None else None,
                "backoff_call_site_rva": common.hexs(backoff.rva) if backoff is not None else None,
                "backoff_symbol": _iat_symbol(iat, backoff) if backoff is not None else None,
                "retry_counter_site_rva": common.hexs(counter.rva) if counter is not None else None,
                "retry_counter_bounded": False,
            }
        )
    return {
        "global": lock["va"],
        "kind": "hand_rolled_interlocked_spin_lock",
        "not_a_once_flag": "every holder re-checks its own precondition after the acquire, so the flag excludes holders "
        "instead of firing once",
        "holder_count": len(holders),
        "holders": holders,
        "contention_path": {
            "sequence": [
                "the threshold compare only saturates the Sleep argument",
                "Sleep is called with zero or one millisecond",
                "the retry counter is incremented and nothing is compared against it",
                "the jump returns to the same lock cmpxchg",
            ],
            "sleep_symbol": iat.get(SLEEP_IAT_RVA, f"unresolved_iat_{common.hexs(SLEEP_IAT_RVA)}"),
            "sleep_argument": f"0 below {common.hexs(SPIN_BACKOFF_CAP)}, 1 millisecond at and above it",
            "threshold": SPIN_BACKOFF_CAP,
            "threshold_hex": common.hexs(SPIN_BACKOFF_CAP),
            "attempt_cap": None,
            "timeout": None,
            "yield_policy": "a sleep of at most one millisecond, the counter itself is never bounded",
        },
        "single_release_point": {
            "function_rva": common.hexs(function_bounds(pe, ORCHESTRATOR_EXIT_RVA)[0]),
            "site_rva": common.hexs(ORCHESTRATOR_EXIT_RVA),
            "note": "every orchestrator exit path converges on this block, so the lock is released exactly once on "
            "each path, including the failure codes",
        },
        "guard_scope": ["the record table", "the arena free list", "the private heap publication"],
        "confidence": "H",
    }


def heap_profile(
    pe: pefile.PE, iat: Mapping[int, str], globals_out: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """The heap behind the global, and the four facts that make it a private one."""
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    handle = next(entry for entry in globals_out if entry["name"] == "heap_handle")
    slots = frozenset(
        {HEAPCREATE_IAT_RVA, HEAPFREE_IAT_RVA, GETPROCESSHEAP_IAT_RVA, *HEAP_ALLOCATOR_IAT_RVAS}
    )
    calls = scan_iat_calls(pe, slots)

    def card(slot: int) -> dict[str, Any]:
        sites = calls[slot]
        return {
            "symbol": iat.get(slot, f"unresolved_iat_{common.hexs(slot)}"),
            "iat_slot_rva": common.hexs(slot),
            "call_sites_in_file": [common.hexs(rva) for rva in sites],
            "call_site_count": len(sites),
        }

    get_process_heap_sites = calls[GETPROCESSHEAP_IAT_RVA]
    component_sites = [
        common.hexs(rva) for rva in get_process_heap_sites if COMPONENT_LOW_RVA <= rva < COMPONENT_HIGH_RVA
    ]
    handle_rva = HEAP_HANDLE_VA - image_base
    handle_operand_sections = scan_rip_operand_sections(pe, frozenset({handle_rva}))

    def owner(slot: int) -> str | None:
        sites = calls[slot]
        if not sites:
            return None
        return common.hexs(function_bounds(pe, sites[0])[0])

    return {
        "global": handle["va"],
        "kind": "private_heap",
        "is_process_heap": False,
        "expression": EXPR_HEAP_HANDLE,
        "creation": {
            **card(HEAPCREATE_IAT_RVA),
            "function_rva": owner(HEAPCREATE_IAT_RVA),
            "arguments": ["0", "0", "0"],
            "argument_sites": [common.hexs(rva) for rva in (0x1DCB7, 0x1DCB9, 0x1DCBB)],
            "store_site_rva": "0x1DCC4",
        },
        "release": {**card(HEAPFREE_IAT_RVA), "function_rva": owner(HEAPFREE_IAT_RVA)},
        "allocators": [card(slot) for slot in sorted(HEAP_ALLOCATOR_IAT_RVAS)],
        "why_not_the_process_heap": [
            "the only writer of the global is the instruction right after the single HeapCreate call site, so the "
            "handle is the return value of that call",
            "all three arguments of that call are zeroed immediately before it, so the call is HeapCreate(0, 0, 0)",
            f"KERNEL32.dll!GetProcessHeap is called from {len(get_process_heap_sites)} sites in the file and none of "
            f"them lies inside the component range {common.hexs(COMPONENT_LOW_RVA)}-{common.hexs(COMPONENT_HIGH_RVA)}",
            "the matching release is a KERNEL32.dll!HeapFree on the same handle, which is the private heap ownership "
            "contract and would be wrong for the process heap",
        ],
        "get_process_heap": {
            "iat_slot_rva": common.hexs(GETPROCESSHEAP_IAT_RVA),
            "call_sites_in_file": [common.hexs(rva) for rva in get_process_heap_sites],
            "call_sites_in_component": component_sites,
            "call_sites_in_component_count": len(component_sites),
        },
        "writers_in_file": handle["writers"],
        "writer_count": len(handle["writers"]),
        "rip_operand_form_sections": handle_operand_sections.get(common.hexs(handle_rva), []),
        "rip_operand_form_sections_outside_text": [
            name for name in handle_operand_sections.get(common.hexs(handle_rva), []) if name != ".text"
        ],
        "file_bytes_hex": handle["file_bytes_hex"],
        "initialised_in_file": handle["initialised_in_file"],
        "allocator": "KERNEL32!HeapAlloc and KERNEL32!HeapReAlloc on the private heap published at "
        f"{common.hexs(HEAP_HANDLE_VA)}, the record array and the thread id array share it",
        "confidence": "H",
    }


def patcher_profile(pe: pefile.PE, md: capstone.Cs, iat: Mapping[int, str]) -> dict[str, Any]:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    begin, end, unwind = function_bounds(pe, PATCHER_RVA)
    insns = _decode(pe, md, begin, end - begin)
    calls: list[dict[str, Any]] = []
    for position, insn in enumerate(insns):
        symbol = _iat_symbol(iat, insn)
        if symbol is None:
            continue
        following = insns[position + 1] if position + 1 < len(insns) else None
        checked = following is not None and following.mnemonic == "test"
        calls.append(
            {
                "site_rva": common.hexs(insn.rva),
                "symbol": symbol,
                "iat_slot_rva": common.hexs(insn.rip_targets[0]),
                "return_value_tested": checked,
            }
        )
    stride_sites = [
        common.hexs(insn.rva)
        for insn in insns
        if insn.mnemonic == "imul" and RECORD_STRIDE in insn.immediates
    ]
    bit_probes = [
        {"site_rva": common.hexs(insn.rva), "mask": common.hexs(mask), "tested_operand": "flag byte"}
        for insn in insns
        for mask in insn.immediates
        if insn.mnemonic == "test" and mask in (1, 2, 4, 8)
    ]
    flag_writes = [
        {"site_rva": common.hexs(insn.rva), "mask": common.hexs(mask), "target": "rec + 0x20"}
        for insn in insns
        for mask in insn.immediates
        if insn.mnemonic == "or" and 1 in insn.mem_sizes
    ]
    return {
        "rva": common.hexs(begin),
        "va": common.hexs(image_base + begin),
        "end_rva": common.hexs(end),
        "size": common.hexs(end - begin),
        "unwind_info_rva": common.hexs(unwind),
        "stride_sites": stride_sites,
        "flag_bit_probes": bit_probes,
        "flag_write_sites": flag_writes,
        "api_calls": calls,
        "api_calls_tested": sum(1 for call in calls if call["return_value_tested"]),
        "returns": {
            "success": "0",
            "first_protection_failure": common.hexs(FIRST_FAILURE_CODE),
            "restore_failure": "not represented in the return value",
            "cache_flush_failure": "not represented in the return value",
        },
        "validation": {
            "requested_protection": common.hexs(PAGE_EXECUTE_READWRITE),
            "note": "the window bounds are curated, every comparison inside them is derived from the file",
            "windows": [
                _validation_window("table pointer", "rbx", 0x1E28A, 0x1E297, _comparisons_between(insns, 0x1E28A, 0x1E297)),
                _validation_window("record pointer", "rax", 0x1E297, 0x1E2AD, _comparisons_between(insns, 0x1E297, 0x1E2AD)),
                _validation_window("index", "rax", 0x1E291, 0x1E293, _comparisons_between(insns, 0x1E291, 0x1E293)),
            ],
        },
    }


def table_profile(pe: pefile.PE, md: capstone.Cs, section_text: common.Section) -> dict[str, Any]:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    slot_rva = TABLE_SLOT_VA - image_base
    slot_raw = common.rva_to_raw(pe, slot_rva)
    slot_bytes = common.read_rva(pe, slot_rva, 8)
    window = common.read_rva(pe, slot_rva, 0x108)
    zero_run = next((index for index, byte in enumerate(window) if byte), len(window))
    slot_section = common.section_for_rva(pe, slot_rva)

    tracked = {va - image_base for _, va, _, _ in TRACKED_GLOBALS}
    references = scan_rip_references(pe, md, section_text, frozenset(tracked))
    grouped: dict[int, list[dict[str, Any]]] = {rva: [] for rva in tracked}
    for reference in references:
        target = reference.pop("target")
        grouped[target].append(reference)

    globals_out: list[dict[str, Any]] = []
    for name, va, size, purpose in TRACKED_GLOBALS:
        rva = va - image_base
        raw = common.rva_to_raw(pe, rva)
        owner = common.section_for_rva(pe, rva)
        data = common.read_rva(pe, rva, size)
        sites = grouped.get(rva, [])
        globals_out.append(
            {
                "name": name,
                "va": common.hexs(va),
                "rva": common.hexs(rva),
                "raw": common.hexs(raw) if raw is not None else None,
                "section": owner.name if owner is not None else None,
                "size": size,
                "purpose": purpose,
                "file_bytes_hex": data.hex(" "),
                "initialised_in_file": any(data),
                "reference_count": len(sites),
                "writers": [site["site_rva"] for site in sites if site["access"] in ("write", "read_write")],
                "readers": [site["site_rva"] for site in sites if site["access"] in ("read", "read_write", "address")],
                "references": sites,
            }
        )

    return {
        "slot": {
            "va": common.hexs(TABLE_SLOT_VA),
            "rva": common.hexs(slot_rva),
            "raw": common.hexs(slot_raw) if slot_raw is not None else None,
            "section": slot_section.name if slot_section is not None else None,
            "section_characteristics_hex": common.hexs(slot_section.characteristics) if slot_section is not None else None,
            "file_bytes_hex": slot_bytes.hex(" "),
            "holds": "pointer to an array of index times 0x38 records",
            "initialised_in_file": any(slot_bytes),
            "zero_run_from_slot": zero_run,
            "zero_run_from_slot_hex": common.hexs(zero_run),
        },
        "capacity_model": {
            "initial_capacity_records": INITIAL_CAPACITY_RECORDS,
            "initial_capacity_bytes": INITIAL_CAPACITY_RECORDS * RECORD_STRIDE,
            "growth": "doubling, the byte count is the new capacity times the stride",
            "allocator": "KERNEL32!HeapAlloc and KERNEL32!HeapReAlloc on the private heap published at "
            f"{common.hexs(HEAP_HANDLE_VA)}",
        },
        "globals": globals_out,
    }


def record_profile(pe: pefile.PE) -> dict[str, Any]:
    fields = (
        {
            "offset": 0x00,
            "name": "anchor",
            "width": 8,
            "target_expr": EXPR_PATCH_SITE,
            "value_expr": "absolute address of the patch anchor, resolved at registration time",
            "readers": [0x1E297, 0x1DDD0, 0x1E4C1, 0x1E17B],
            "writers": [0x1DF2B],
            "note": "identity key of the record, registration and lookup both compare it",
        },
        {
            "offset": 0x08,
            "name": "destination",
            "width": 8,
            "target_expr": EXPR_JUMP_DEST,
            "value_expr": "absolute address that the relative jump resolves to",
            "readers": [0x1E2ED],
            "writers": [0x1DF34],
            "note": "read as a low dword only, so the stored value has to fit in 32 bits",
        },
        {
            "offset": 0x10,
            "name": "image_base",
            "width": 8,
            "target_expr": EXPR_RIP_TARGET,
            "value_expr": "base of the executable image rebuilt for this record",
            "readers": [0x1E1FD],
            "writers": [0x1DF3E],
            "note": "taken from the arena block, the bytes inside it are produced by the list builder",
        },
        {
            "offset": 0x18,
            "name": "original_bytes",
            "width": 7,
            "target_expr": "snapshot of the bytes that occupy the patch region",
            "value_expr": "seven bytes when flag bit 0 is set, otherwise five",
            "readers": [],
            "writers": [0x1DFAF, 0x1DFA0, 0x1DFAA],
            "note": "copied from live target memory at registration time, no reader in the analysed set, its width "
            "equals the seven byte variant of the patch region",
        },
        {
            "offset": 0x20,
            "name": "flags",
            "width": 1,
            "target_expr": "rec + 0x20, one bit per gate",
            "value_expr": "bit 0 layout, bit 1 skip, bit 2 patched, upper bits preserved on merge",
            "readers": [0x1E29B, 0x1E156, 0x1E3E0, 0x1E41C, 0x1E4E8],
            "writers": [0x1DF5A, 0x1E336],
            "note": "the patcher mutates the record it has just consumed",
        },
        {
            "offset": 0x24,
            "name": "list_count",
            "width": 4,
            "target_expr": "rec + 0x24 & 0x0F, entry count of both lists",
            "value_expr": "low nibble of the dword, zero when the record carries no list",
            "readers": [0x1E161, 0x1E834],
            "writers": [0x1DF74],
            "note": "only the low nibble is replaced, the upper three bytes are preserved",
        },
        {
            "offset": 0x28,
            "name": "offset_list",
            "width": LIST_CAPACITY_BYTES,
            "target_expr": EXPR_RIP_MATCH,
            "value_expr": "one byte per entry, index zero is the oldest entry",
            "readers": [0x1E1E9],
            "writers": [0x1DF7E],
            "note": "parallel to 0x30, one index selects both halves",
        },
        {
            "offset": 0x30,
            "name": "displacement_list",
            "width": LIST_CAPACITY_BYTES,
            "target_expr": EXPR_RIP_TARGET,
            "value_expr": "one byte per entry, offset inside the rebuilt image",
            "readers": [0x1E1F7],
            "writers": [0x1DF88],
            "note": "a zero byte makes the matching entry inert",
        },
    )
    for field in fields:
        field["offset_hex"] = offset_hex(field["offset"])
        field["readers"] = [common.hexs(rva) for rva in field["readers"]]
        field["writers"] = [common.hexs(rva) for rva in field["writers"]]

    return {
        "stride": RECORD_STRIDE,
        "stride_hex": common.hexs(RECORD_STRIDE),
        "stride_is_eight_byte_aligned": RECORD_STRIDE % 8 == 0,
        "record_expression": EXPR_RECORD,
        "fields": list(fields),
        "list_builder_limits": {
            "entry_cap": LIST_ENTRY_CAP,
            "entry_cap_hex": common.hexs(LIST_ENTRY_CAP),
            "list_capacity_bytes": LIST_CAPACITY_BYTES,
            "scan_length_cap": SCAN_LENGTH_CAP,
            "scan_length_cap_hex": common.hexs(SCAN_LENGTH_CAP),
            "note": "both limits are compared inside the list builder, exceeding either one abandons the record instead of truncating it",
        },
        "producers": [
            _function_card(pe, "registrar", REGISTRAR_RVA, "allocates the record, fills every field, rejects duplicate anchors"),
            _function_card(pe, "list_builder", LIST_BUILDER_RVA, "walks the anchor with the length decoder and fills the two byte lists"),
            _function_card(pe, "arena", ARENA_RVA, "hands out executable blocks and keeps a reusable region list"),
            _function_card(pe, "init", INIT_RVA, "creates the private heap under the spin lock and publishes it, and has no direct caller in the file"),
            _function_card(pe, "decoder", DECODER_RVA, "supplies instruction lengths to the list builder"),
        ],
        "consumers": [
            _function_card(pe, "patcher", PATCHER_RVA, "consumes the anchor, the destination and the flag byte"),
            _function_card(pe, "rip_redirect", RIP_REDIRECT_RVA, "consumes both byte lists and the count nibble"),
            _function_card(pe, "orchestrator", ORCHESTRATOR_RVA, "enumerates records and dispatches both patcher call sites"),
        ],
    }


def redirect_profile(pe: pefile.PE) -> dict[str, Any]:
    return {
        "function": _function_card(pe, "rip_redirect", RIP_REDIRECT_RVA, "applies the replacement instruction pointer"),
        "match_expression": EXPR_RIP_MATCH,
        "replacement_expression": EXPR_RIP_TARGET,
        "count_field": "rec + 0x24, low nibble only",
        "count_mask": common.hexs(LIST_COUNT_MASK),
        "entry_cap": LIST_ENTRY_CAP,
        "list_capacity_bytes": LIST_CAPACITY_BYTES,
        "apply": "KERNEL32!SetThreadContext with CONTEXT_CONTROL",
        "resume_after_rewrite": "none inside this function",
        "inert_conditions": [
            "flag bit 1 is set on the record",
            "the low nibble of rec + 0x24 is zero",
            "rec + 0x10 plus the entry of rec + 0x30 is zero",
        ],
        "consistency": [
            {
                "id": "list_cap_matches_stride",
                "rule": f"the entry count has to stay inside the {LIST_CAPACITY_BYTES} bytes that 0x28 and 0x30 own inside the 0x38 stride",
                "evidence": f"the builder compares its counter with {common.hexs(LIST_ENTRY_CAP)} and abandons the record above it",
                "verdict": "enforced_by_builder",
                "confidence": "H",
            },
            {
                "id": "count_nibble_fits_cap",
                "rule": "the stored count dword is reduced to four bits, so a count above fifteen could not survive the merge",
                "evidence": f"the registrar masks the new count with {common.hexs(LIST_COUNT_MASK)} and the reader masks with {common.hexs(LIST_COUNT_MASK)}",
                "verdict": "consistent_with_cap",
                "confidence": "H",
            },
            {
                "id": "zero_count_means_empty",
                "rule": "a zero nibble makes the record inert for the context rewrite even when the eight stored bytes are not zero",
                "evidence": "the reader branches out before the first list load when the masked count is zero",
                "verdict": "inert_record",
                "confidence": "H",
            },
            {
                "id": "parallel_lists_share_index",
                "rule": "one loop counter drives both loads, so entry i of 0x28 always pairs with entry i of 0x30",
                "evidence": "the same counter appears in the address of both byte loads",
                "verdict": "parallel_by_construction",
                "confidence": "H",
            },
            {
                "id": "defined_but_unused_tail",
                "rule": "the registrar always stores all eight bytes of both lists, so entries beyond the count are defined but never read",
                "evidence": "two eight byte stores per record, independent of the count",
                "verdict": "defined_but_unused",
                "confidence": "M",
            },
        ],
    }


def flag_profile(pe: pefile.PE, md: capstone.Cs) -> dict[str, Any]:
    begin, end, _ = function_bounds(pe, PATCHER_RVA)
    insns = _decode(pe, md, begin, end - begin)
    write_sites = [
        {"site_rva": common.hexs(insn.rva), "mask": common.hexs(mask), "target": "rec + 0x20"}
        for insn in insns
        for mask in insn.immediates
        if insn.mnemonic == "or" and 1 in insn.mem_sizes
    ]
    return {
        "field": "rec + 0x20",
        "width": 1,
        "bits": [
            {
                "mask": 1,
                "mask_hex": common.hexs(1),
                "name": "two_slot_layout",
                "gate": "selector of the patch site expression",
                "meaning": "set when the anchor is preceded by a run of five identical filler bytes, so the relative jump is placed five bytes lower and the region grows to seven bytes",
                "readers": [common.hexs(0x1E2A3), common.hexs(0x1E2FA)],
                "writers": [common.hexs(0x1E974), common.hexs(0x1DF4F), common.hexs(0x1DF5A)],
                "confidence": "H",
            },
            {
                "mask": 2,
                "mask_hex": common.hexs(2),
                "name": "skip",
                "gate": "skip gate of every record enumeration",
                "meaning": "every enumeration in the analysed set ignores a record with this bit, and the patcher sets it together with bit 2",
                "readers": [common.hexs(0x1E156), common.hexs(0x1E3E0), common.hexs(0x1E41C), common.hexs(0x1E4E8)],
                "writers": [common.hexs(0x1E336)],
                "confidence": "H",
            },
            {
                "mask": 4,
                "mask_hex": common.hexs(4),
                "name": "patched",
                "gate": "marker that the patcher already processed the record",
                "meaning": "written only by the patcher flag update, never read by the analysed set",
                "readers": [],
                "writers": [common.hexs(0x1E336)],
                "confidence": "H",
            },
            {
                "mask": 0xF8,
                "mask_hex": common.hexs(0xF8),
                "name": "preserved_bits",
                "gate": "carried through the registrar merge untouched",
                "meaning": "bits 3 to 7 are never cleared by the registrar, which keeps the slot bits and merges only bit 0",
                "readers": [],
                "writers": [common.hexs(0x1DF53)],
                "confidence": "H",
            },
        ],
        "patch_flag": {
            "mask": PATCH_FLAG_MASK,
            "mask_hex": common.hexs(PATCH_FLAG_MASK),
            "decomposition": ["0x02 skip", "0x04 patched"],
            "write_sites": write_sites,
            "written_after": ["protection restore", "instruction cache flush"],
            "not_written_when": "the first protection change fails, the write sits on the success path only",
            "written_even_when": "the restore and the cache flush results are unchecked, so the state is published before the outcome is known",
            "effect": "a processed record is skipped by every later enumeration in the analysed set and no analysed code clears the skip bit again, so the analysed paths reach a record at most once",
            "confidence": "H",
        },
    }


def address_profile() -> dict[str, Any]:
    return {
        "record_expression": EXPR_RECORD,
        "patch_site": {
            "expression": EXPR_PATCH_SITE,
            "derivation": [
                "rec + 0x00 is loaded",
                "flag bit 0 is inverted into zero or one",
                "the inverted value is scaled by five",
                "the scaled value is added to the anchor address",
                "five is subtracted",
            ],
            "variants": {
                "flag_bit_0_clear": "the patch site equals rec + 0x00 and the region is five bytes",
                "flag_bit_0_set": "the patch site equals rec + 0x00 - 5 and the region is seven bytes",
            },
        },
        "jump_destination": {"expression": EXPR_JUMP_DEST, "read_width": 4},
        "relative_displacement": {
            "expression": EXPR_REL32,
            "stored_width": 4,
            "stored_at": "patch site + 1",
            "note": "described symbolically, no displacement value is emitted",
        },
        "second_store": {
            "expression": EXPR_SHORT_JUMP_SITE,
            "width": 2,
            "condition": "flag bit 0 is set",
            "lands_on": "the anchor, which is patch site + 5, the upper edge of the seven byte window",
            "note": "the store lands on the upper edge of the region, not below it, and the stored short jump is the "
            "only reference back into the lower five bytes of the region",
        },
        "region": {
            "expression": EXPR_REGION,
            "sizes": [5, 7],
            "protection": common.hexs(PAGE_EXECUTE_READWRITE),
            "restored": True,
            "cache_flushed": True,
            "single_contiguous_store": False,
            "write_group_count": 2,
            "write_groups": [
                {
                    "name": "patch_site",
                    "expression": EXPR_PATCH_SITE_GROUP,
                    "width": 5,
                    "condition": "unconditional",
                    "stores": [
                        {
                            "site_rva": "0x1E2EA",
                            "offset_in_group": 0,
                            "width": 1,
                            "role": "the leading byte of the five byte relative jump",
                        },
                        {
                            "site_rva": "0x1E2F7",
                            "offset_in_group": 1,
                            "width": 4,
                            "role": "the relative displacement",
                        },
                    ],
                },
                {
                    "name": "anchor",
                    "expression": EXPR_ANCHOR_GROUP,
                    "width": 2,
                    "condition": "flag bit 0 is set",
                    "stores": [
                        {
                            "site_rva": "0x1E306",
                            "offset_in_group": 0,
                            "width": 2,
                            "role": "a short jump that returns into the five byte group",
                        },
                    ],
                },
            ],
            "adjacency": "with flag bit 0 set the patch site is rec + 0x00 - 5, so the two groups are adjacent and "
            "together they cover the whole seven byte window",
            "coverage": {
                "flag_bit_0_clear": "only the five byte group runs, the region is the anchor itself",
                "flag_bit_0_set": "both groups run, the region is the five byte group plus the two byte group on top of it",
            },
            "note": "the patcher contains no target size, page boundary or per byte validation",
        },
    }


def activation_profile(
    pe: pefile.PE, section_text: common.Section, globals_out: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """The gate that stands in front of both patcher call sites, and its reachability.

    Both dispatch paths of the orchestrator pass through one test of the
    published heap handle. The only writer of that handle sits inside the init,
    and the init has no direct call site anywhere in the file, so the gate has
    no satisfying assignment inside the decoded control flow graph.
    """
    handle = next(entry for entry in globals_out if entry["name"] == "heap_handle")
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    begin, end, unwind = function_bounds(pe, HEAP_GATE_RVA)
    init_callers = scan_file_direct_calls(pe, frozenset({INIT_RVA}))
    init_operand_sections = scan_rip_operand_sections(pe, frozenset({INIT_RVA})).get(common.hexs(INIT_RVA), [])
    return {
        "gate": {
            "site_rva": common.hexs(HEAP_GATE_RVA),
            "site_va": common.hexs(image_base + HEAP_GATE_RVA),
            "function_rva": common.hexs(begin),
            "function_end_rva": common.hexs(end),
            "unwind_info_rva": common.hexs(unwind),
            "test": EXPR_HEAP_GATE,
            "on_zero": {
                "code": common.hexs(HEAP_GATE_FAIL_CODE),
                "code_site_rva": "0x1E3AE",
                "branch_site_rva": "0x1E3B3",
                "exit_rva": common.hexs(ORCHESTRATOR_EXIT_RVA),
                "note": "the failure branch jumps to the shared release and return block, so it leaves the function "
                "before any patcher call site",
            },
        },
        "gated_call_sites": [common.hexs(CALLER_ALL_RVA), common.hexs(CALLER_ONE_RVA)],
        "gated_call_site_count": 2,
        "reachable_inside_decoded_cfg": False,
        "reachability_evidence": {
            "handle_writers": handle["writers"],
            "handle_writer_count": len(handle["writers"]),
            "handle_writer_function_rva": common.hexs(INIT_RVA),
            "handle_rip_operand_form_sections": scan_rip_operand_sections(
                pe, frozenset({HEAP_HANDLE_VA - image_base})
            ).get(common.hexs(HEAP_HANDLE_VA - image_base), []),
            "init_direct_call_sites_in_file": [common.hexs(rva) for rva in init_callers],
            "init_direct_call_site_count": len(init_callers),
            "init_rip_operand_form_sections": init_operand_sections,
            "form_note": "the two rip operand fields count sections, not sites, and they cover the rip relative "
            "operand form only; an absolute pointer, an rva32 or va64 literal is a separate form and is not counted",
        },
        "reason": "the gate is the only thing that lets the orchestrator leave its early exits, the only writer of "
        "the tested handle is inside the init, and the init has no direct call site anywhere in the file, so no "
        "assignment reachable inside the decoded control flow graph satisfies the test",
        "status": "OPEN",
        "static_chain_confidence": "H",
        "runtime_reachability_confidence": "L",
        "runtime_caveat": "an indirect call, a function pointer, run time code generation or a writer outside the "
        "image cannot be excluded from the file, so the gate is not decidable at run time",
    }


def callers_profile(pe: pefile.PE, section_text: common.Section) -> list[dict[str, Any]]:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    known = {
        CALLER_ALL_RVA: {
            "path": "orchestrator, zero argument branch",
            "index_source": "a loop counter that starts at the first record without flag bit 1",
            "index_expression": "the loop counter value",
            "preconditions": "count is non zero, the array is published, the spin lock is taken",
            "on_failure": "the loop stops and the failure code becomes the return value",
            "path_gates": [
                {
                    "site_rva": common.hexs(HEAP_GATE_RVA),
                    "test": EXPR_HEAP_GATE,
                    "code": common.hexs(HEAP_GATE_FAIL_CODE),
                    "shared": True,
                }
            ],
        },
        CALLER_ONE_RVA: {
            "path": "orchestrator, non zero argument branch",
            "index_source": "the index of the record whose rec + 0x00 equals the argument",
            "index_expression": EXPR_RECORD_LOOKUP,
            "preconditions": "a record with a matching anchor exists and has flag bit 1 clear",
            "on_failure": "the failure code of the patcher becomes the return value",
            "path_gates": [
                {
                    "site_rva": common.hexs(HEAP_GATE_RVA),
                    "test": EXPR_HEAP_GATE,
                    "code": common.hexs(HEAP_GATE_FAIL_CODE),
                    "shared": True,
                },
                {
                    "site_rva": "0x1E4A6",
                    "test": "live record count is zero",
                    "code": common.hexs(SINGLE_PATH_EMPTY_CODE),
                    "shared": False,
                },
                {
                    "site_rva": "0x1E4E3",
                    "test": "flag bit 1 is set on the located record",
                    "code": common.hexs(SINGLE_PATH_SKIP_CODE),
                    "shared": False,
                },
            ],
        },
    }
    out: list[dict[str, Any]] = []
    for site in scan_direct_calls(pe, section_text, frozenset({PATCHER_RVA})):
        begin, end, unwind = function_bounds(pe, site)
        detail = known.get(
            site,
            {
                "path": "unclassified",
                "index_source": "unclassified",
                "index_expression": "unknown",
                "preconditions": "unknown",
                "on_failure": "unknown",
                "path_gates": [],
            },
        )
        gates = detail["path_gates"]
        shared = [gate for gate in gates if gate["shared"]]
        own = [gate for gate in gates if not gate["shared"]]
        out.append(
            {
                "site_rva": common.hexs(site),
                "site_va": common.hexs(image_base + site),
                "target_rva": common.hexs(PATCHER_RVA),
                "caller_function_rva": common.hexs(begin),
                "caller_function_end_rva": common.hexs(end),
                "unwind_info_rva": common.hexs(unwind),
                "path": detail["path"],
                "index_source": detail["index_source"],
                "index_expression": detail["index_expression"],
                "preconditions": detail["preconditions"],
                "on_failure": detail["on_failure"],
                "activation_gate_count": len(gates),
                "activation_gates": gates,
                "activation_gate_sites": [gate["site_rva"] for gate in gates],
                "activation_gate_codes": [gate["code"] for gate in gates],
                "activation_shared_gate_sites": [gate["site_rva"] for gate in shared],
                "activation_status": "OPEN",
                "activation_confidence": "H" if gates else "OPEN",
                "activation_reason": (
                    "the shared gate at "
                    + ", ".join(gate["site_rva"] for gate in shared)
                    + " tests the private heap handle, whose only writer is the uncalled init, so the path has no "
                    "satisfying assignment inside the decoded control flow graph"
                    if shared
                    else "no activation gate is classified for this call site, so its reachability is not decided here"
                )
                + (
                    " | the path specific gates "
                    + ", ".join(f"{gate['site_rva']} {gate['test']} -> {gate['code']}" for gate in own)
                    + " decide the path only after the shared gate is open"
                    if own
                    else ""
                ),
                "confidence": "H" if site in known else "OPEN",
            }
        )
    return out


def open_questions(pe: pefile.PE, section_text: common.Section, table: Mapping[str, Any]) -> list[dict[str, Any]]:
    registrar_callers = [common.hexs(rva) for rva in scan_direct_calls(pe, section_text, frozenset({REGISTRAR_RVA}))]
    orchestrator_callers = [
        common.hexs(rva) for rva in scan_direct_calls(pe, section_text, frozenset({ORCHESTRATOR_RVA}))
    ]
    init_callers = [common.hexs(rva) for rva in scan_file_direct_calls(pe, frozenset({INIT_RVA}))]
    array_global = next(entry for entry in table["globals"] if entry["name"] == "record_array")
    handle_global = next(entry for entry in table["globals"] if entry["name"] == "heap_handle")
    return [
        {
            "id": "record_instances",
            "question": "which records the table holds at run time, and which module and export each anchor belongs to",
            "status": "OPEN",
            "confidence": "L",
            "reason": "the table slot is zero filled in the file and its only writer takes already resolved addresses, so no instance can be enumerated statically",
            "evidence": {
                "table_slot_file_bytes": table["slot"]["file_bytes_hex"],
                "record_array_writers": array_global["writers"],
                "registrar_direct_callers": registrar_callers,
                "init_direct_callers": init_callers,
            },
        },
        {
            "id": "registrar_caller",
            "question": "what invokes the registrar and the init, that is, what supplies the anchor and destination pair and who publishes the private heap",
            "status": "OPEN",
            "confidence": "L",
            "reason": "the file contains no direct call site and no rip relative reference to either function, and the init is the only writer of the private heap handle",
            "evidence": {
                "registrar_direct_callers": registrar_callers,
                "init_direct_callers": init_callers,
                "heap_handle_writers": handle_global["writers"],
            },
        },
        {
            "id": "orchestrator_caller",
            "question": "what invokes the orchestrator that holds both patcher call sites",
            "status": "OPEN",
            "confidence": "L",
            "reason": "the file contains no direct call site and no rip relative reference to the orchestrator, and "
            f"its heap gate at {common.hexs(HEAP_GATE_RVA)} tests the private heap handle whose only writer is the "
            "uncalled init, so the gate has no satisfying assignment inside the decoded control flow graph and the "
            f"orchestrator returns {common.hexs(HEAP_GATE_FAIL_CODE)} before either call site",
            "evidence": {
                "orchestrator_direct_callers": orchestrator_callers,
                "gate_site_rva": common.hexs(HEAP_GATE_RVA),
                "gate_test": EXPR_HEAP_GATE,
                "gate_failure_code": common.hexs(HEAP_GATE_FAIL_CODE),
                "gated_call_sites": [common.hexs(CALLER_ALL_RVA), common.hexs(CALLER_ONE_RVA)],
                "heap_handle_writers": handle_global["writers"],
                "init_direct_callers": init_callers,
            },
        },
        {
            "id": "upper_flag_bits",
            "question": "what the flag bits 3 to 7 of a record mean and which code sets them",
            "status": "OPEN",
            "confidence": "L",
            "reason": "the analysed set only preserves those bits on merge, no reader and no other writer exists in the three consumers",
            "evidence": {"preserved_mask": common.hexs(0xF8), "merge_site": common.hexs(0x1DF53)},
        },
    ]







def build_evidence(root: Path, specimen: Path, relative_specimen: str) -> dict[str, Any]:
    script = Path(__file__).resolve()
    pe = common.load_pe(specimen)
    try:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        text = next(section for section in common.sections(pe) if section.name == ".text")
        iat = resolve_iat(pe)
        address = address_profile()
        table = table_profile(pe, md, text)
        lock = lock_profile(pe, md, iat, table["globals"])
        heap = heap_profile(pe, iat, table["globals"])
        activation = activation_profile(pe, text, table["globals"])
        anchors = verify_anchors(pe, md)
        callers = callers_profile(pe, text)
        unresolved = open_questions(pe, text, table)
        failures = [entry for entry in anchors if not entry["ok"]]
        return {
            "schema": SCHEMA,
            "mode": "static file parsing only, the specimen is never loaded or executed",
            "generated_by": {
                "script": script.relative_to(root).as_posix(),
                "script_sha256": common.sha256_file(script),
                "python": common.python_summary(),
                "pefile": common.library_version("pefile", "pefile"),
                "capstone": common.library_version("capstone", "capstone"),
            },
            "specimen": {
                "path": relative_specimen,
                "size": specimen.stat().st_size,
                "size_hex": common.hexs(specimen.stat().st_size),
                "sha256": common.sha256_file(specimen),
            },
            "image": {
                "image_base": image_base,
                "image_base_hex": common.hexs(image_base),
                "entry_point_rva_hex": common.hexs(int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)),
            },
            "confidence_scale": dict(CONFIDENCE_SCALE),
            "address_model": address,
            "table": table,
            "lock": lock,
            "heap": heap,
            "activation": activation,
            "record": record_profile(pe),
            "flags": flag_profile(pe, md),
            "rip_redirect": redirect_profile(pe),
            "patcher": patcher_profile(pe, md, iat),
            "callers": callers,
            "unresolved": unresolved,
            "invariants": anchors,
            "summary": {
                "anchor_count": len(anchors),
                "anchor_failures": len(failures),
                "patcher_direct_call_sites": len(callers),
                "gated_call_sites": activation["gated_call_site_count"],
                "record_array_static_instances": 0,
                "record_instances_status": "OPEN",
                "activation_status": activation["status"],
                "heap_kind": heap["kind"],
                "lock_kind": lock["kind"],
                "patch_region_write_groups": address["region"]["write_group_count"],
                "overall_confidence": "L",
                "note": "the mechanism is fully determined statically, the record instances and the activation of "
                "both dispatch paths are not, so every statement about a concrete patch target stays open",
            },
        }
    finally:
        pe.close()


def build_rows(evidence: Mapping[str, Any]) -> list[dict[str, str]]:
    image_base = int(evidence["image"]["image_base"])
    table = evidence["table"]
    record = evidence["record"]
    flags = evidence["flags"]
    redirect = evidence["rip_redirect"]
    address = evidence["address_model"]
    rows: list[dict[str, str]] = []

    def add(**values: Any) -> None:
        unknown = sorted(set(values) - set(CSV_FIELDS))
        if unknown:
            raise KeyError(f"unknown csv columns: {unknown}")
        payload = {name: "" for name in CSV_FIELDS}
        payload.update(values)
        rows.append({name: common.scalar_text(payload[name]) for name in CSV_FIELDS})

    def va(rva_hex: str) -> str:
        return common.hexs(image_base + int(rva_hex, 16))

    def access_of(readers: Sequence[str], writers: Sequence[str]) -> str:
        if readers and writers:
            return "read_write"
        if writers:
            return "write"
        if readers:
            return "read"
        return "none"

    lock = evidence["lock"]
    heap = evidence["heap"]
    purposes = {entry["name"]: entry["purpose"] for entry in table["globals"]}
    global_rows = {
        "spin_lock": (
            "H",
            "confirmed",
            f"{purposes['spin_lock']} | holders: "
            + ", ".join(
                f"{holder['name']} takes at {holder['take_site_rva']} and releases at {holder['drop_site_rva']}, "
                f"re-checks at {holder['recheck_site_rva']}"
                for holder in lock["holders"]
            )
            + f" | the contention counter at {lock['holders'][-1]['retry_counter_site_rva']} is never compared "
            "against a bound, there is no timeout and no attempt cap",
        ),
        "heap_handle": (
            "H",
            "confirmed",
            f"{purposes['heap_handle']} | created at {heap['creation']['call_sites_in_file'][0]} by "
            f"{heap['creation']['symbol']} with three zero arguments and stored at {heap['creation']['store_site_rva']} "
            f"| released at {heap['release']['call_sites_in_file'][0]} by {heap['release']['symbol']} on the same "
            f"handle | KERNEL32.dll!GetProcessHeap is called from "
            f"{len(heap['get_process_heap']['call_sites_in_file'])} sites in the file and "
            f"{heap['get_process_heap']['call_sites_in_component_count']} of them is inside the component, so this is "
            "a private heap and not the process heap",
        ),
    }

    for entry in table["globals"]:
        confidence, status, note = global_rows.get(entry["name"], ("H", "confirmed", entry["purpose"]))
        add(
            id=f"global.{entry['name']}",
            component="table",
            kind="global",
            site_rva=entry["rva"],
            site_va=entry["va"],
            field=entry["name"],
            access=access_of(entry["readers"], entry["writers"]),
            width_expr=str(entry["size"]),
            value_expr=entry["file_bytes_hex"],
            target_expr=EXPR_RECORD if entry["name"] == "record_array" else "",
            readers=";".join(entry["readers"]),
            writers=";".join(entry["writers"]),
            confidence=confidence,
            status="open" if not entry["reference_count"] else status,
            note=note,
        )

    for field in record["fields"]:
        add(
            id=f"record.{field['offset_hex']}",
            component="record",
            kind="record_field",
            record_offset=field["offset_hex"],
            field=field["name"],
            access=access_of(field["readers"], field["writers"]),
            width_expr=str(field["width"]),
            value_expr=field["value_expr"],
            target_expr=field["target_expr"],
            readers=";".join(field["readers"]),
            writers=";".join(field["writers"]),
            confidence="H",
            status="confirmed",
            note=field["note"],
        )

    second_store = address["second_store"]
    region = address["region"]
    expr_notes = {
        "second_store": (
            f"{second_store['note']} | symbolic expression only, no byte or displacement value is emitted"
        ),
        "region": (
            f"the region is covered by {region['write_group_count']} adjacent write groups and not by a single "
            f"contiguous store | {region['adjacency']} | symbolic expression only, no byte or displacement value "
            "is emitted"
        ),
    }
    for key, expression in (
        ("record", address["record_expression"]),
        ("patch_site", address["patch_site"]["expression"]),
        ("jump_destination", address["jump_destination"]["expression"]),
        ("relative_displacement", address["relative_displacement"]["expression"]),
        ("second_store", second_store["expression"]),
        ("region", region["expression"]),
        ("rip_match", redirect["match_expression"]),
        ("rip_replacement", redirect["replacement_expression"]),
    ):
        add(
            id=f"expr.{key}",
            component="address_model",
            kind="formula",
            field=key,
            target_expr=expression,
            confidence="H",
            status="confirmed",
            note=expr_notes.get(key, "symbolic expression only, no byte or displacement value is emitted"),
        )

    for bit in flags["bits"]:
        add(
            id=f"flag.{bit['mask_hex']}",
            component="flags",
            kind="flag_bit",
            record_offset="0x20",
            field=bit["name"],
            access=access_of(bit["readers"], bit["writers"]),
            value_expr=bit["mask_hex"],
            target_expr=bit["gate"],
            readers=";".join(bit["readers"]),
            writers=";".join(bit["writers"]),
            confidence=bit["confidence"],
            status="confirmed",
            note=bit["meaning"],
        )

    patch_flag = flags["patch_flag"]
    add(
        id="flag.patch_state",
        component="flags",
        kind="patch_flag",
        site_rva=";".join(site["site_rva"] for site in patch_flag["write_sites"]),
        site_va=";".join(va(site["site_rva"]) for site in patch_flag["write_sites"]),
        record_offset="0x20",
        field="patch_state",
        access="write",
        width_expr="1",
        value_expr=patch_flag["mask_hex"],
        target_expr="rec + 0x20",
        writers=";".join(site["site_rva"] for site in patch_flag["write_sites"]),
        confidence=patch_flag["confidence"],
        status="confirmed",
        note=f"{' plus '.join(patch_flag['decomposition'])}: {patch_flag['effect']}",
    )

    for rule in redirect["consistency"]:
        add(
            id=f"consistency.{rule['id']}",
            component="rip_redirect",
            kind="consistency",
            record_offset="0x24|0x28|0x30",
            field=rule["id"],
            value_expr=rule["verdict"],
            target_expr=f"{EXPR_RIP_MATCH} -> {EXPR_RIP_TARGET}",
            confidence=rule["confidence"],
            status="confirmed",
            note=f"{rule['rule']} | evidence: {rule['evidence']}",
        )

    for caller in evidence["callers"]:
        gates = "; ".join(
            f"gate {gate['site_rva']} {gate['test']} -> {gate['code']}" for gate in caller["activation_gates"]
        )
        add(
            id=f"caller.{caller['site_rva']}",
            component="patcher",
            kind="caller",
            site_rva=caller["site_rva"],
            site_va=caller["site_va"],
            value_expr=f"index = {caller['index_expression']}",
            target_expr=EXPR_PATCH_SITE,
            confidence=caller["confidence"],
            status=caller["activation_status"],
            note=f"{caller['path']} | index from {caller['index_source']} | preconditions: "
            f"{caller['preconditions']} | on failure: {caller['on_failure']} | activation: "
            f"{caller['activation_reason']}"
            + (f" | gates: {gates}" if gates else ""),
        )

    for role in ("producers", "consumers"):
        for item in record[role]:
            add(
                id=f"{'producer' if role == 'producers' else 'consumer'}.{item['name']}",
                component="record",
                kind=role[:-1],
                site_rva=item["rva"],
                site_va=item["va"],
                target_expr=EXPR_RECORD if item["name"] == "registrar" else "",
                confidence="H",
                status="confirmed",
                note=item["role"],
            )

    for call in evidence["patcher"]["api_calls"]:
        add(
            id=f"api.{call['site_rva']}",
            component="patcher",
            kind="api",
            site_rva=call["site_rva"],
            site_va=va(call["site_rva"]),
            field=call["symbol"],
            access="call",
            target_expr=address["region"]["expression"],
            confidence="H",
            status="confirmed",
            note=("return value tested" if call["return_value_tested"] else "return value not tested")
            + f" | the region is {region['write_group_count']} adjacent write groups, "
            + " and ".join(
                f"{group['width']} bytes at {group['expression']}" for group in region["write_groups"]
            ),
        )

    for item in evidence["unresolved"]:
        add(
            id=f"open.{item['id']}",
            component="unresolved",
            kind="open_question",
            field=item["id"],
            target_expr=EXPR_RECORD if item["id"] == "record_instances" else "",
            confidence=item["confidence"],
            status=item["status"],
            note=f"{item['question']} | {item['reason']}",
        )

    return rows


def _csv_text(rows: Sequence[Mapping[str, Any]]) -> str:
    """Render the rows exactly the way common.write_csv renders them."""
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=list(CSV_FIELDS),
        lineterminator="\n",
        extrasaction="raise",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({name: common.scalar_text(row.get(name)) for name in CSV_FIELDS})
    return buffer.getvalue()


def _json_text(payload: Mapping[str, Any]) -> str:
    """Render the payload exactly the way common.write_json renders it."""
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False, allow_nan=False) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description="Static map of the RVA 0x1E270 patch record table in adhesive.dll"
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument("--json", type=Path, default=root / "reverse" / "evidence" / "patch_record_table.json")
    parser.add_argument("--csv", type=Path, default=root / "reverse" / "evidence" / "patch_mechanisms_1e270.csv")
    parser.add_argument("--emit", action="store_true", help="write both evidence files, this is the default")
    parser.add_argument("--verify", action="store_true", help="compare the stored files with a fresh computation")
    args = parser.parse_args(argv)
    if args.emit and args.verify:
        parser.error("--emit and --verify are mutually exclusive")

    specimen = args.specimen.resolve()
    relative_specimen = specimen.relative_to(root).as_posix()
    evidence = build_evidence(root, specimen, relative_specimen)
    rows = build_rows(evidence)
    fresh = ((args.json, _json_text(evidence)), (args.csv, _csv_text(rows)))

    print(f"script    {script.relative_to(root).as_posix()}")
    print(f"specimen  {relative_specimen} sha256={evidence['specimen']['sha256']}")
    failures = evidence["summary"]["anchor_failures"]
    total = evidence["summary"]["anchor_count"]
    print(f"anchors   {total - failures}/{total} verified")
    print(f"callers   {evidence['summary']['patcher_direct_call_sites']} direct call sites of the patcher")
    print(
        f"region    {evidence['summary']['patch_region_write_groups']} adjacent write groups, "
        f"{evidence['summary']['heap_kind']}, {evidence['summary']['lock_kind']}"
    )
    print(
        f"activation {evidence['summary']['gated_call_sites']} gated call sites, "
        f"status {evidence['summary']['activation_status']}, gate "
        f"{evidence['activation']['gate']['site_rva']} {evidence['activation']['gate']['test']}"
    )
    print(f"rows      {len(rows)} csv rows")
    print(
        f"records   {evidence['summary']['record_instances_status']}, "
        f"{evidence['summary']['record_array_static_instances']} static instances, "
        f"overall confidence {evidence['summary']['overall_confidence']}"
    )

    if args.verify:
        mismatched = 0
        for path, expected in fresh:
            relative = path.relative_to(root).as_posix()
            actual = path.read_text(encoding="utf-8") if path.exists() else None
            if actual == expected:
                print(f"match     {relative}")
                continue
            mismatched += 1
            print(f"MISMATCH  {relative}")
            if actual is None:
                print("          file does not exist")
                continue
            stored_lines = actual.splitlines()
            fresh_lines = expected.splitlines()
            for index in range(max(len(stored_lines), len(fresh_lines))):
                stored = stored_lines[index] if index < len(stored_lines) else "<missing>"
                updated = fresh_lines[index] if index < len(fresh_lines) else "<missing>"
                if stored != updated:
                    print(f"          line {index + 1} stored={stored}")
                    print(f"          line {index + 1} fresh ={updated}")
                    break
        return 1 if mismatched or failures else 0

    common.write_json(args.json, evidence)
    common.write_csv(args.csv, rows, CSV_FIELDS)
    print(f"wrote     {args.json.relative_to(root).as_posix()}")
    print(f"wrote     {args.csv.relative_to(root).as_posix()}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
