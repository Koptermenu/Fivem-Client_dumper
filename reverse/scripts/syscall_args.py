"""Phase P0/S7 static syscall argument inventory for the adhesive.dll specimen.

Scope
-----
The specimen is only ever parsed as a file. It is never loaded, mapped for
execution, patched or run, no module is loaded and no code is executed. Every
cell of the emitted evidence is recomputed from the file image and from the phase
input csv files on each run, so the two output files are byte stable for a given
specimen and reruns are reproducible diffs.

This phase answers one question per valid `0F 05` candidate: which operand values
reach the four syscall argument registers and the argument stack slots. It
deliberately does not decode a service number, does not resolve a syscall to an
Nt/Zw service name, does not decide what a service does and does not produce an
exploit, a bypass or a patch recipe. The service name column of the inventory is
the literal string `UNRESOLVED` on every row and the class report records the same
value with the reason it was not attempted. The pseudo handle names used here are
x64 ABI constants, the `-1`, `-2`, ... handle values of the `NtCurrent*` family,
and are not service identifiers.

Inputs
------
All three input files are read; none of them is modified.

  * `reverse/evidence/syscall_candidates_raw.csv` the P0/S6 candidate census.
    Only its `valid_candidate == true` rows are in scope, which fixes the work
    list at 3627 sites. The candidate rva, the raw offset and the owning
    `IMAGE_RUNTIME_FUNCTION` bounds are taken from this file, and every one of them
    is re-verified against the specimen bytes and against the exception directory
    parsed out of the PE before the site is analysed.
  * `reverse/evidence/cfg_functions.csv` the CFG function census. It is joined on
    `pdata_function_index == func_index` and the begin/end rva of the join are
    compared with the P0/S6 columns, which turns the join into a checked join
    rather than an assumed one. Its `decode_status` is carried into the inventory
    so a reader can see whether the owning function was fully decoded.
  * `reverse/evidence/xref_edges.csv` the cross reference census. It is used for
    two things only: to name the import a `call` instruction of the analysis
    window targets (`category == iat`, `dst_symbol`), and with that name to
    recognise the allocator calls that feed an argument. It is not a per
    instruction memory access table, so the read/write census of this phase comes
    from the decoded window and not from this file.

Analysis window
---------------
The extraction window is the byte range in front of the candidate instruction, at
most `--window-bytes` bytes (default 40, allowed range 20..40), clamped to the
start of the owning runtime function. The window never crosses a function
boundary and never contains the candidate instruction itself. The window start is
an instruction boundary, not an arbitrary byte offset: the owning function is
swept linearly from its runtime function start with Capstone in rva space, and the
window is the tail of that sweep, so every instruction of the window is an
instruction start of the same linear channel that P0/S6 used to accept the
candidate. A `push`, `pop`, `sub rsp` or `lea rsp` inside the window moves the
stack pointer, so the window is walked once to accumulate the net stack delta per
instruction and a `[rsp + d]` operand is normalised to the offset it occupies at
the candidate.

Argument positions
------------------
The convention read here is the one the candidate can actually be reached through:
the service number in RAX, then the first four arguments in R10, RDX, R8, R9, then
further arguments on the stack at `[RSP + 0x28]`, `[RSP + 0x30]`, ... of the rsp
value at the candidate. The `[RSP + 0x28]` anchor assumes the stub was reached by
a `call`, which is what makes the callee shadow space the 32 bytes below rsp and
the first stack argument the slot above it. That assumption is a property of the
call site rather than of the candidate, so the offset is reported verbatim per
site and the consequence is listed in the report limitations. The inventory
enumerates the four register positions and the first two stack positions as fixed
columns, so the table keeps a constant width; every further stack slot the window
writes is counted in `stack_slots_detected` and classified in the class report.

Precedence
----------
The backward walk of the window resolves each argument position through an
ordered ladder, and the first step that fires decides the class. Every row carries
the deciding step in its `reason` cell, so no classification is silent.

  1. the nearest *definite* definition of the location inside the window,
  2. the nearest *conditional* definition of the location inside the window
     (`cmov` and friends), used only when no definite definition exists,
  3. otherwise the location is unresolved inside the window.

Two boundaries cut the walk further, both recorded per site:

  * a `call` in the window clobbers the volatile registers, so a definition of a
    volatile argument register that sits before the last `call` of the window is
    not accepted as the live value,
  * an unconditional jump or a return in the window ends the linear path, so a
    definition before the last one of those is not on the path that reaches the
    candidate.

Register to register copies are followed up to `COPY_CHAIN_MAX_DEPTH` hops, a
constant is folded only when every input of the operation is a known constant, and
a load is resolved through the file image with the DIR64 fixups of the relocation
table applied, which models a load at the preferred base.

Class ladder
------------
Applied per argument position, highest first:

  A1_PSEUDO_HANDLE  a resolved integer constant inside the pseudo handle window
                    `0xFFFFFFFFFFFFFF00..0xFFFFFFFFFFFFFFFF`; the named subset of
                    that window is listed in the report.
  A3_OUT_BUF       a resolved data address: an image virtual address, or frame or
  A3_INOUT_BUF     stack storage the site materialises itself. A3_INOUT_BUF
                    additionally requires an observed read *and* write through that
                    same address in the window; A3_OUT_BUF means the address is
                    passed without such a pair.
  A4_LEN           a resolved non-negative constant of at most 1 MiB in the argument
                    position immediately after a buffer position of the same site.
  A2_OBJ_CLASS     any other resolved non-negative constant literal.
  A6_SELF_HANDLE   the value chain terminates at an entry parameter of the owning
                    runtime function, that is the chain is a run of register to
                    register copies that ends at a register the function prologue
                    took from RCX/RDX/R8/R9, or at a frame slot the prologue filled
                    from one. The class says the stub hands on a handle it received
                    from its own caller.
  A5_STACK_SLOT    a stack argument slot whose stored value is not resolved to a
                    constant or an address.
  A7_REG_INDIRECT  a register argument whose value the window does not reduce to a
                    constant or an address.
  A8_UNKNOWN       the location has no definition in the window at all, or a
                    definition whose operand shape is not interpreted.

Constants, addresses and pseudo handles are decided by value, so a stack slot
that holds a resolved constant or address takes the class of that value and the
position stays visible in the `source`, `raw` and `def` cells; A5 is the residual
class of the stack positions. The class set has no input buffer class, so a read
only data address keeps an A3 class and is marked in the `reason` cell and in the
address cell.

Signals
-------
`argN_rw_pair` is a separate per argument flag. It is set when the window contains
at least one load and at least one store through the same resolved address, or
through the same normalised frame slot. Passing the address as the argument is not
counted as a read or as a write, so the flag means an observed read/write pair and
nothing else. The pair is a property of the address, not of the class, so an
argument classified A6 can carry a pair on the frame slot its value was spilled
to. The pair is window local: a pair outside the window is neither seen nor
claimed.

`argN_alloc_write` is a separate per argument flag. It is set when the value chain
of the argument terminates at the return value of a call whose import symbol,
resolved through the cross reference file, is in the allocator set, *and* the
window contains a store through that pointer. The allocation origin is reported in
the evidence cell even when no write is observed, so the negative case stays
visible.

Determinism
-----------
Rows are emitted in ascending raw offset order with a fixed column order, both
files are written through `common.write_csv` and `common.write_json` as UTF-8
without BOM and LF terminated, every result list is sorted, and no wall clock,
hostname or environment value reaches the payload. Reruns of the script on the
same inputs produce byte identical files.

Evidence
--------
`reverse/evidence/syscall_arg_inventory.csv` holds one row per valid candidate,
3627 rows, and is the site level record.
`reverse/evidence/syscall_arg_classes.json` holds the class census, the signal
census, the per position coverage and the validation results.

Both files are written only when every check of the validation block passes, so a
failed invariant never replaces a good evidence file. The per row validator runs
over all 3627 inventory rows and each row must satisfy the class domain, the
class/evidence consistency rules, the window bounds and the unresolved service
name. `--check-only` compares the stored csv with the regenerated rows cell by cell
instead of writing it. Exit status is `0` on success, `1` on a failed check and
`2` on a specimen or input structure error.
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
from typing import Any, Final, Sequence

import capstone

_SCRIPT_DIR: Final[Path] = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import common

SCHEMA_CSV: Final[str] = "adhesive-dumper.syscall-arg-inventory/1"
SCHEMA_JSON: Final[str] = "adhesive-dumper.syscall-arg-classes/1"
PHASE: Final[str] = "P0/S7"

SYSCALL_PATTERN: Final[bytes] = bytes((0x0F, 0x05))
SYSCALL_MNEMONIC: Final[str] = "syscall"
EXPECTED_RAW_HITS: Final[int] = 3881
EXPECTED_VALID_CANDIDATES: Final[int] = 3627
EXPECTED_RUNTIME_FUNCTIONS: Final[int] = common.EXPECTED_RUNTIME_FUNCTIONS
EXPECTED_XREF_EDGES: Final[int] = 57101
CANDIDATE_COLUMNS: Final[tuple[str, ...]] = (
    "hit_index",
    "raw_offset",
    "rva",
    "va",
    "bytes_hex",
    "in_pdata",
    "pdata_function_index",
    "pdata_function_start_rva_hex",
    "pdata_function_end_rva_hex",
    "valid_candidate",
)

WINDOW_BYTES: Final[int] = 40
WINDOW_BYTES_MIN: Final[int] = 20
WINDOW_BYTES_MAX: Final[int] = 40
COPY_CHAIN_MAX_DEPTH: Final[int] = 4
ENTRY_SPILL_INSNS: Final[int] = 16
ENTRY_SPILL_PROBE_BYTES: Final[int] = 96
MAX_PLAUSIBLE_LENGTH: Final[int] = 1 << 20
STACK_ARG_BASE_DISP: Final[int] = 0x28
CSV_STACK_SLOTS: Final[int] = 2
ARGUMENT_POSITIONS: Final[int] = 6
MAX_EXAMPLES: Final[int] = 5
MAX_REPORTED_SLOTS: Final[int] = 8
CELL_LIMIT: Final[int] = 200

SECTION_MEM_WRITE: Final[int] = 0x80000000
RELOC_TYPE_DIR64: Final[int] = 0x000A

NT_SERVICE_UNRESOLVED: Final[str] = "UNRESOLVED"
NT_SERVICE_STATUS: Final[str] = "UNRESOLVED_NOT_ATTEMPTED"

CLASS_A1: Final[str] = "A1_PSEUDO_HANDLE"
CLASS_A2: Final[str] = "A2_OBJ_CLASS"
CLASS_A3_OUT: Final[str] = "A3_OUT_BUF"
CLASS_A3_INOUT: Final[str] = "A3_INOUT_BUF"
CLASS_A4: Final[str] = "A4_LEN"
CLASS_A5: Final[str] = "A5_STACK_SLOT"
CLASS_A6: Final[str] = "A6_SELF_HANDLE"
CLASS_A7: Final[str] = "A7_REG_INDIRECT"
CLASS_A8: Final[str] = "A8_UNKNOWN"
ARG_CLASSES: Final[tuple[str, ...]] = (
    CLASS_A1,
    CLASS_A2,
    CLASS_A3_OUT,
    CLASS_A3_INOUT,
    CLASS_A4,
    CLASS_A5,
    CLASS_A6,
    CLASS_A7,
    CLASS_A8,
)
BUFFER_CLASSES: Final[frozenset[str]] = frozenset({CLASS_A3_OUT, CLASS_A3_INOUT})

ARG_REGISTERS: Final[tuple[tuple[int, int, str], ...]] = (
    (1, capstone.x86.X86_REG_R10, "R10"),
    (2, capstone.x86.X86_REG_RDX, "RDX"),
    (3, capstone.x86.X86_REG_R8, "R8"),
    (4, capstone.x86.X86_REG_R9, "R9"),
)
ENTRY_PARAMETERS: Final[tuple[tuple[int, str], ...]] = (
    (capstone.x86.X86_REG_RCX, "rcx"),
    (capstone.x86.X86_REG_RDX, "rdx"),
    (capstone.x86.X86_REG_R8, "r8"),
    (capstone.x86.X86_REG_R9, "r9"),
)
ENTRY_PARAMETER_NAMES: Final[dict[int, str]] = dict(ENTRY_PARAMETERS)

PSEUDO_HANDLE_NAMES: Final[dict[int, str]] = {
    0xFFFFFFFFFFFFFFFF: "current_process",
    0xFFFFFFFFFFFFFFFE: "current_thread",
    0xFFFFFFFFFFFFFFFD: "current_process_thread",
    0xFFFFFFFFFFFFFFFC: "current_console",
    0xFFFFFFFFFFFFFFFB: "current_input",
    0xFFFFFFFFFFFFFFFA: "current_input_queue",
    0xFFFFFFFFFFFFFFF9: "current_output",
    0xFFFFFFFFFFFFFFF8: "current_clipboard",
    0xFFFFFFFFFFFFFFF7: "current_window_station",
    0xFFFFFFFFFFFFFFF6: "current_desktop",
    0xFFFFFFFFFFFFFFF5: "current_directory",
    0xFFFFFFFFFFFFFFF4: "current_profile",
}
PSEUDO_HANDLE_WINDOW: Final[tuple[int, int]] = (0xFFFFFFFFFFFFFF00, 0xFFFFFFFFFFFFFFFF)

ALLOCATOR_SYMBOLS: Final[frozenset[str]] = frozenset(
    {
        "Calloc",
        "CoTaskMemAlloc",
        "HeapAlloc",
        "HeapCreate",
        "HeapReAlloc",
        "LocalAlloc",
        "MapViewOfFile",
        "NtAllocateVirtualMemory",
        "NtMapViewOfSection",
        "RtlAllocateHeap",
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualAllocExNuma",
        "_aligned_malloc",
        "calloc",
        "malloc",
        "realloc",
        "_recalloc",
    }
)

VOLATILE_REGISTERS: Final[frozenset[int]] = frozenset(
    {
        capstone.x86.X86_REG_RAX,
        capstone.x86.X86_REG_RCX,
        capstone.x86.X86_REG_RDX,
        capstone.x86.X86_REG_R8,
        capstone.x86.X86_REG_R9,
        capstone.x86.X86_REG_R10,
        capstone.x86.X86_REG_R11,
    }
)

GPR_FAMILIES: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("rax", ("eax", "ax", "al", "ah")),
    ("rcx", ("ecx", "cx", "cl", "ch")),
    ("rdx", ("edx", "dx", "dl", "dh")),
    ("rbx", ("ebx", "bx", "bl", "bh")),
    ("rsp", ("esp", "sp", "spl")),
    ("rbp", ("ebp", "bp", "bpl")),
    ("rsi", ("esi", "si", "sil")),
    ("rdi", ("edi", "di", "dil")),
    ("r8", ("r8d", "r8w", "r8b")),
    ("r9", ("r9d", "r9w", "r9b")),
    ("r10", ("r10d", "r10w", "r10b")),
    ("r11", ("r11d", "r11w", "r11b")),
    ("r12", ("r12d", "r12w", "r12b")),
    ("r13", ("r13d", "r13w", "r13b")),
    ("r14", ("r14d", "r14w", "r14b")),
    ("r15", ("r15d", "r15w", "r15b")),
)


def _register_id(name: str) -> int:
    return getattr(capstone.x86, f"X86_REG_{name.upper()}")


def _build_gpr_tables() -> tuple[dict[int, int], dict[int, str]]:
    aliases: dict[int, int] = {}
    names: dict[int, str] = {}
    for family, members in GPR_FAMILIES:
        canonical = _register_id(family)
        names[canonical] = family
        for member in (family, *members):
            aliases[_register_id(member)] = canonical
    return aliases, names


GPR_ALIASES, GPR_NAMES = _build_gpr_tables()

CONDITIONAL_MNEMONICS: Final[frozenset[str]] = frozenset(
    {
        "cmov", "cmova", "cmovae", "cmovb", "cmovbe", "cmove", "cmovg", "cmovge",
        "cmovl", "cmovle", "cmovne", "cmovno", "cmovnp", "cmovns", "cmovo", "cmovp",
        "cmovs", "cmovz", "cmovnz",
    }
)
FOLDABLE_MNEMONICS: Final[frozenset[str]] = frozenset(
    {
        "add", "adc", "and", "bswap", "imul", "inc", "dec", "neg", "not", "or",
        "rol", "ror", "sal", "sar", "shl", "shr", "sub", "sbb", "xor",
    }
)
UNINTERPRETED_MNEMONICS: Final[frozenset[str]] = frozenset(
    {
        "aesdec", "aesenc", "aesimc", "cpuid", "in", "ins", "out", "outs", "pause",
        "rdmsr", "rdpmc", "rdrand", "rdseed", "syscall", "sysenter", "sysexit",
        "sysret", "wrmsr", "xgetbv",
    }
)
CONTROL_FLOW_MNEMONICS: Final[frozenset[str]] = frozenset(
    {
        "call", "jmp", "ljmp", "ret", "retf", "iret", "iretd", "iretq", "int",
        "int1", "int3", "into", "jrcxz", "loop", "loope", "loopne", "loopnz", "loopz",
    }
)
FLOW_BREAK_MNEMONICS: Final[frozenset[str]] = frozenset(
    {
        "jmp", "ljmp", "ret", "retf", "iret", "iretd", "iretq", "jrcxz", "loop",
        "loope", "loopne", "loopnz", "loopz", "ud2", "int3",
    }
)
STRING_OPERATION_MNEMONICS: Final[frozenset[str]] = frozenset(
    {"stos", "movs", "ins", "outs", "scas", "cmps"}
)
IMPLICIT_WRITE_TABLES: Final[dict[str, tuple[int, ...]]] = {
    "div": (capstone.x86.X86_REG_RAX, capstone.x86.X86_REG_RDX),
    "idiv": (capstone.x86.X86_REG_RAX, capstone.x86.X86_REG_RDX),
    "mul": (capstone.x86.X86_REG_RAX, capstone.x86.X86_REG_RDX),
    "cpuid": (
        capstone.x86.X86_REG_RAX,
        capstone.x86.X86_REG_RBX,
        capstone.x86.X86_REG_RCX,
        capstone.x86.X86_REG_RDX,
    ),
}
IMPLICIT_WRITE_ONE_OPERAND: Final[frozenset[str]] = frozenset({"imul"})

KIND_CONST: Final[str] = "const"
KIND_ADDRESS: Final[str] = "address"
KIND_INDIRECT: Final[str] = "indirect"
KIND_NONE: Final[str] = "none"

SRC_IMMEDIATE: Final[str] = "immediate"
SRC_ZERO_IDENTITY: Final[str] = "zero_identity"
SRC_FOLDED: Final[str] = "folded_window_ops"
SRC_LOADED_IMAGE: Final[str] = "load_from_image_data"
SRC_SLOT_STORE: Final[str] = "stack_slot_store"
SRC_NONE: Final[str] = "none"

ADDR_IMAGE: Final[str] = "image_rip_relative"
ADDR_FRAME: Final[str] = "frame_relative"
ADDR_STACK: Final[str] = "stack_relative"
ADDR_LOADED: Final[str] = "image_data_pointer"

STALE_NONE: Final[str] = ""
STALE_CALL: Final[str] = "call_clobber"
STALE_FLOW: Final[str] = "flow_break"
STALE_CONDITIONAL: Final[str] = "conditional_def"

DECODE_OK: Final[str] = "window_decoded"
DECODE_EMPTY: Final[str] = "window_empty"
DECODE_MISMATCH: Final[str] = "window_redecode_mismatch"
DECODE_UNREACHED: Final[str] = "sweep_stopped_before_candidate"

ARG_CELL_SUFFIXES: Final[tuple[str, ...]] = (
    "source",
    "raw",
    "def",
    "const",
    "addr",
    "pseudo",
    "class",
    "len",
    "reason",
    "rw_pair",
    "alloc_write",
    "evidence",
)
SITE_COLUMNS: Final[tuple[str, ...]] = (
    "hit_index",
    "rva_hex",
    "va_hex",
    "raw_offset_hex",
    "section_name",
    "insn_mnemonic",
    "insn_bytes_hex",
    "pdata_function_index",
    "pdata_function_start_rva_hex",
    "pdata_function_end_rva_hex",
    "cfg_function_index",
    "cfg_function_begin_rva_hex",
    "cfg_function_end_rva_hex",
    "cfg_decode_status",
    "window_start_rva_hex",
    "window_bytes",
    "window_instruction_count",
    "window_decode_status",
    "window_stack_delta",
    "window_control_flow",
    "entry_spill",
    "stack_slots_detected",
    "allocation_calls",
    "site_signature",
    "rw_pair_arguments",
    "allocation_write_arguments",
    "nt_service",
    "nt_service_status",
)
CSV_COLUMNS: Final[tuple[str, ...]] = SITE_COLUMNS + tuple(
    f"arg{position}_{suffix}"
    for position in range(1, ARGUMENT_POSITIONS + 1)
    for suffix in ARG_CELL_SUFFIXES
)

LIMITATIONS: Final[tuple[str, ...]] = (
    "The specimen is parsed as a file only: nothing is loaded, mapped for "
    "execution, patched or run, so no observation here is a runtime observation.",
    "The service name of a candidate is not decoded and not resolved. The service "
    "number in RAX at the candidate is not read either, so the inventory cannot "
    "and does not name an Nt/Zw service.",
    "The argument window is linear. A value defined before a call that clobbers a "
    "volatile register, or before an unconditional jump or a return, is not "
    "accepted as the live value of a volatile argument. A definition path that "
    "leaves the register through a branch outside the window is not modelled.",
    "The [RSP + 0x28] anchor of the first stack argument holds when the stub was "
    "reached by a call, so the return address occupies [RSP] and the callee shadow "
    "space the 32 bytes below it. A stub entered without a call has no return "
    "address there and its first stack argument sits one slot lower.",
    "The read/write pair and the allocation to write signals are window local. A "
    "buffer filled by a call outside the window, or by a string operation whose "
    "pointer cannot be tied to the argument inside the window, is not counted as a "
    "pair and is not claimed as one.",
    "The value of a global slot is the file value with the DIR64 fixups of the "
    "relocation table applied, which models a load at the preferred base. A slot "
    "that another module or a runtime initialiser overwrites after load is not "
    "seen.",
    "The entry parameter channel reads the first ENTRY_SPILL_INSNS instructions of "
    "the owning runtime function and only connects rsp relative prologue spills "
    "that sit in the window itself. A prologue that spills its parameters later, "
    "or through an offset that cannot be tied to the candidate without decoding "
    "the whole function prefix, is not connected to the arguments of the "
    "candidate.",
    "The class ladder has no input buffer class, so a read only data address keeps "
    "an A3 class and is marked read only in the reason and address cells instead of "
    "being reported as a direction this phase cannot decide.",
    "A frame or stack address is localisable as a frame offset only. Its file "
    "address is not computable, because the frame base is a runtime value.",
)


def full_register(register: int) -> int:
    """Canonical 64 bit id of a general purpose register, or the id unchanged."""
    return GPR_ALIASES.get(register, register)


def register_name(register: int) -> str:
    canonical = full_register(register)
    return GPR_NAMES.get(canonical, f"reg{canonical}")


def _join(parts: Sequence[str]) -> str:
    return "; ".join(part for part in parts if part)


def _hex(value: int) -> str:
    return common.hexs(value)


def _insn_text(insn: capstone.CsInsn) -> str:
    return f"{insn.mnemonic} {insn.op_str}".strip()


def _cell(text: str) -> str:
    return text if len(text) <= CELL_LIMIT else text[: CELL_LIMIT - 3] + "..."


def _wrap64(value: int, size: int) -> int:
    """Apply the x86-64 write extension rule of an operand of `size` bytes."""
    if size >= 8:
        return value & 0xFFFFFFFFFFFFFFFF
    if size == 4:
        return value & 0xFFFFFFFF
    if size == 2:
        return value & 0xFFFF
    if size == 1:
        return value & 0xFF
    return value & 0xFFFFFFFFFFFFFFFF


def _pseudo_name(value: int) -> str:
    low, high = PSEUDO_HANDLE_WINDOW
    if not low <= value <= high:
        return ""
    return PSEUDO_HANDLE_NAMES.get(value, "")


def _is_pseudo_window(value: int) -> bool:
    low, high = PSEUDO_HANDLE_WINDOW
    return low <= value <= high







@dataclass(frozen=True, slots=True)
class RelocationTable:
    """DIR64 relocation targets, sorted, for a load time pointer rewrite."""

    rvas: tuple[int, ...]

    def covers(self, rva: int) -> bool:
        index = bisect.bisect_left(self.rvas, rva)
        return index < len(self.rvas) and self.rvas[index] == rva


class Image:
    """Read only view over the specimen file with the indexes this phase needs."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.blob: bytes = path.read_bytes()
        self.pe: Any = common.load_pe(path)
        self.image_base: int = int(self.pe.OPTIONAL_HEADER.ImageBase)
        self.sections: tuple[common.Section, ...] = common.sections(self.pe)
        self.relocations: RelocationTable = self._load_relocations()

    def close(self) -> None:
        self.pe.close()

    def _load_relocations(self) -> RelocationTable:
        directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[common.RELOC_DIRECTORY_INDEX]
        rva = int(directory.VirtualAddress)
        size = int(directory.Size)
        if rva == 0 or size == 0:
            return RelocationTable(())
        blob = self.at_rva(rva, size)
        targets: list[int] = []
        cursor = 0
        while cursor + 8 <= len(blob):
            page_rva, block_size = struct.unpack_from("<II", blob, cursor)
            if block_size < 8 or cursor + block_size > len(blob):
                break
            for offset in range(cursor + 8, cursor + block_size, 2):
                entry = struct.unpack_from("<H", blob, offset)[0]
                if entry >> 12 == RELOC_TYPE_DIR64:
                    targets.append(page_rva + (entry & 0x0FFF))
            cursor += block_size
        targets.sort()
        return RelocationTable(tuple(targets))

    def at_rva(self, rva: int, length: int) -> bytes:
        return common.read_rva(self.pe, rva, length)

    def section_of_rva(self, rva: int) -> common.Section | None:
        for section in self.sections:
            if section.contains_rva_in_raw(rva):
                return section
        return None

    def section_of_va(self, va: int) -> common.Section | None:
        return self.section_of_rva(va - self.image_base)

    def section_writable(self, va: int) -> bool:
        section = self.section_of_va(va)
        return section is not None and bool(section.characteristics & SECTION_MEM_WRITE)

    def qword_va(self, va: int) -> int | None:
        """File value of a 64 bit slot with DIR64 fixups applied, or None."""
        rva = va - self.image_base
        raw = common.rva_to_raw(self.pe, rva)
        if raw is None or raw + 8 > len(self.blob):
            return None
        value = int.from_bytes(self.blob[raw : raw + 8], "little")
        return value + self.image_base if self.relocations.covers(rva) else value







@dataclass(frozen=True, slots=True)
class Candidate:
    """One accepted P0/S6 candidate site."""

    hit_index: int
    raw: int
    rva: int
    va: int
    section: str
    pdata_index: int
    function_begin: int
    function_end: int


@dataclass(frozen=True, slots=True)
class CfgFunction:
    """The CFG census row a candidate joins onto."""

    index: int
    begin: int
    end: int
    decode_status: str


@dataclass(frozen=True, slots=True)
class PhaseInputs:
    """The three read only input files of the phase."""

    candidates: tuple[Candidate, ...]
    raw_rows: int
    runtime_functions: int
    cfg: dict[int, CfgFunction]
    cfg_rows: int
    iat_calls: dict[int, str]
    xref_rows: int
    digests: dict[str, str]


def read_csv(path: Path) -> tuple[list[dict[str, str]], tuple[str, ...]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        header = tuple(reader.fieldnames or ())
        return [dict(row) for row in reader], header


def load_runtime_functions(image: Image) -> tuple[tuple[int, int], ...]:
    directory = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[common.EXCEPTION_DIRECTORY_INDEX]
    rva = int(directory.VirtualAddress)
    size = int(directory.Size)
    if size == 0 or size % common.RUNTIME_FUNCTION_SIZE:
        raise ValueError(f"exception directory size {_hex(size)} is not a record multiple")
    blob = image.at_rva(rva, size)
    if len(blob) != size:
        raise ValueError(f"exception directory blob is {len(blob)} bytes, expected {size}")
    return tuple((record[0], record[1]) for record in struct.iter_unpack("<III", blob))


def load_inputs(
    image: Image, candidates_path: Path, cfg_path: Path, xref_path: Path
) -> PhaseInputs:
    """Read the three phase inputs and verify the candidate rows against the PE."""
    rows, header = read_csv(candidates_path)
    missing = [name for name in CANDIDATE_COLUMNS if name not in header]
    if missing:
        raise ValueError(f"{candidates_path.name} lacks column(s): {', '.join(missing)}")

    pdata = load_runtime_functions(image)
    candidates: list[Candidate] = []
    for row in rows:
        if row["valid_candidate"] != "true":
            continue
        index = int(row["pdata_function_index"])
        begin = int(row["pdata_function_start_rva_hex"], 16)
        end = int(row["pdata_function_end_rva_hex"], 16)
        if pdata[index] != (begin, end):
            raise ValueError(
                f"candidate hit {row['hit_index']} runtime function bounds disagree with "
                f"exception directory record {index}"
            )
        rva = int(row["rva"])
        if image.at_rva(rva, len(SYSCALL_PATTERN)) != SYSCALL_PATTERN:
            raise ValueError(
                f"candidate hit {row['hit_index']} at rva {_hex(rva)} is not 0F 05"
            )
        if int(row["raw_offset"]) != common.rva_to_raw(image.pe, rva):
            raise ValueError(
                f"candidate hit {row['hit_index']} raw offset does not map to its rva"
            )
        if common.rva_to_va(image.pe, rva) != int(row["va"]):
            raise ValueError(f"candidate hit {row['hit_index']} va column is not its rva")
        candidates.append(
            Candidate(
                hit_index=int(row["hit_index"]),
                raw=int(row["raw_offset"]),
                rva=rva,
                va=int(row["va"]),
                section=row["section_name"],
                pdata_index=index,
                function_begin=begin,
                function_end=end,
            )
        )
    candidates.sort(key=lambda item: item.raw)

    cfg_rows, cfg_header = read_csv(cfg_path)
    if not cfg_header:
        raise ValueError(f"{cfg_path.name} has no header")
    cfg = {
        int(row["func_index"]): CfgFunction(
            index=int(row["func_index"]),
            begin=int(row["begin_rva"]),
            end=int(row["end_rva"]),
            decode_status=row["decode_status"],
        )
        for row in cfg_rows
    }

    xref_rows, xref_header = read_csv(xref_path)
    if "dst_symbol" not in xref_header:
        raise ValueError(f"{xref_path.name} has no dst_symbol column")
    iat_calls: dict[int, str] = {}
    for row in xref_rows:
        if row["category"] == "iat" and row["dst_symbol"]:
            iat_calls[int(row["src_rva"])] = row["dst_symbol"]

    digests = {
        candidates_path.name: common.sha256_file(candidates_path),
        cfg_path.name: common.sha256_file(cfg_path),
        xref_path.name: common.sha256_file(xref_path),
    }
    return PhaseInputs(
        candidates=tuple(candidates),
        raw_rows=len(rows),
        runtime_functions=len(pdata),
        cfg=cfg,
        cfg_rows=len(cfg_rows),
        iat_calls=iat_calls,
        xref_rows=len(xref_rows),
        digests=digests,
    )







@dataclass(frozen=True, slots=True)
class FrameKey:
    """A stack storage address, normalised to the rsp value at the candidate."""

    anchor: str
    disp: int

    def location(self) -> str:
        return f"frame:{self.anchor}:{self.disp}"


@dataclass(frozen=True, slots=True)
class Access:
    """One resolved memory operand of a window instruction."""

    location: str
    base_register: int
    is_read: bool
    is_write: bool
    insn_rva: int
    text: str


@dataclass(frozen=True, slots=True)
class Value:
    """The resolved value of one argument position at the candidate."""

    kind: str
    const: int | None
    const_source: str
    address_va: int | None
    address_kind: str
    section: str
    writable: bool
    expr: str
    origin: str
    def_rva: int | None
    def_text: str
    def_dist: int
    alloc_symbol: str
    alloc_rva: int | None
    entry_param: str
    entry_param_rva: int | None
    slot_disp: int | None
    raw_operand: str
    chain: tuple[str, ...]
    regs: frozenset[int]
    stale: str
    frame: FrameKey | None

    @property
    def pseudo(self) -> str:
        if self.kind != KIND_CONST or self.const is None:
            return ""
        return _pseudo_name(self.const)

    @property
    def is_buffer(self) -> bool:
        return self.kind == KIND_ADDRESS and (
            self.address_va is not None or self.frame is not None
        )


def unknown_value(raw_operand: str, origin: str = SRC_NONE) -> Value:
    return Value(
        kind=KIND_NONE,
        const=None,
        const_source=SRC_NONE,
        address_va=None,
        address_kind="",
        section="",
        writable=False,
        expr=raw_operand,
        origin=origin,
        def_rva=None,
        def_text="",
        def_dist=0,
        alloc_symbol="",
        alloc_rva=None,
        entry_param="",
        entry_param_rva=None,
        slot_disp=None,
        raw_operand=raw_operand,
        chain=(),
        regs=frozenset(),
        stale=STALE_NONE,
        frame=None,
    )


def _merge(value: Value, **overrides: Any) -> Value:
    """Copy a value with the non None overrides applied."""
    fields = {name: getattr(value, name) for name in Value.__slots__}
    fields.update({name: item for name, item in overrides.items() if item is not None})
    return Value(**fields)


def rsp_delta(insn: capstone.CsInsn) -> int:
    """Change an instruction makes to rsp, positive when the stack grows down."""
    mnemonic = insn.mnemonic
    if mnemonic in ("push", "pushfq", "pushf"):
        return -8
    if mnemonic in ("pop", "popfq", "popf"):
        return 8
    operands = insn.operands
    if not operands:
        return 0
    first = operands[0]
    if first.type != capstone.x86.X86_OP_REG:
        return 0
    if full_register(first.reg) != capstone.x86.X86_REG_RSP:
        return 0
    if len(operands) < 2:
        return 0
    second = operands[1]
    if mnemonic in ("sub", "add") and second.type == capstone.x86.X86_OP_IMM:
        return -second.imm if mnemonic == "sub" else second.imm
    if mnemonic == "and" and second.type == capstone.x86.X86_OP_IMM:
        return -int(second.imm)
    if mnemonic == "lea" and second.type == capstone.x86.X86_OP_MEM:
        memory = second.mem
        if memory.base == capstone.x86.X86_REG_RSP and not memory.index:
            return memory.disp
    return 0


def apply_operation(
    mnemonic: str, op_str: str, left: int, right: int | None
) -> int | None:
    """Fold one window arithmetic operation, or return None when it is not foldable."""
    mask = 0xFFFFFFFFFFFFFFFF
    if right is None:
        if mnemonic == "not":
            return ~left & mask
        if mnemonic == "neg":
            return -left & mask
        if mnemonic == "inc":
            return left + 1
        if mnemonic == "dec":
            return left - 1
        if mnemonic == "bswap":
            return int.from_bytes((left & mask).to_bytes(8, "little"), "big")
        return None
    if mnemonic in ("add", "adc"):
        return left + right
    if mnemonic in ("sub", "sbb"):
        return left - right
    if mnemonic == "and":
        return left & right
    if mnemonic == "or":
        return left | right
    if mnemonic == "xor":
        return left ^ right
    if mnemonic == "imul":
        return left * right
    if mnemonic in ("shl", "sal"):
        shift = _shift_amount(op_str)
        return None if shift is None else left << shift
    if mnemonic == "shr":
        shift = _shift_amount(op_str)
        return None if shift is None else (left & mask) >> shift
    if mnemonic == "sar":
        shift = _shift_amount(op_str)
        if shift is None:
            return None
        return (left - (1 << 64) if left >> 63 else left) >> shift
    if mnemonic in ("rol", "ror"):
        shift = _shift_amount(op_str)
        if shift is None:
            return None
        return _rotate_left(left & mask, shift if mnemonic == "rol" else -shift)
    return None


def _shift_amount(op_str: str) -> int | None:
    tail = op_str.partition(",")[2].strip()
    if not tail:
        return 1
    try:
        return int(tail, 0)
    except ValueError:
        return None


def _rotate_left(value: int, amount: int) -> int:
    amount %= 64
    if amount == 0:
        return value
    return ((value << amount) | (value >> (64 - amount))) & 0xFFFFFFFFFFFFFFFF







class Window:
    """The analysis window of one candidate, with its window local indexes."""

    def __init__(
        self,
        image: Image,
        candidate: Candidate,
        instructions: Sequence[capstone.CsInsn],
        entry_spill: dict[Any, tuple[str, int]],
        entry_spill_text: str,
        iat_calls: dict[int, str],
    ) -> None:
        self.image = image
        self.candidate = candidate
        self.insns: tuple[capstone.CsInsn, ...] = tuple(instructions)
        self.entry_spill = entry_spill
        self.entry_spill_text = entry_spill_text
        self.iat_calls = iat_calls
        self.position: dict[int, int] = {
            insn.address: index for index, insn in enumerate(self.insns)
        }
        self.deltas: tuple[int, ...] = self._stack_deltas()
        self.last_call_rva: int = self._last_of(frozenset({"call"}))
        self.last_flow_rva: int = self._last_of(FLOW_BREAK_MNEMONICS)
        self._cache: dict[tuple[str, int, int], Value] = {}
        self._active: set[tuple[str, int, int]] = set()
        self.accesses: tuple[Access, ...] = self._memory_accesses()



    def _stack_deltas(self) -> tuple[int, ...]:
        """Net rsp change between each window instruction and the candidate."""
        deltas: list[int] = []
        running = 0
        for insn in reversed(self.insns):
            deltas.append(running)
            running += rsp_delta(insn)
        deltas.reverse()
        return tuple(deltas)

    def _last_of(self, mnemonics: frozenset[str]) -> int:
        for insn in reversed(self.insns):
            if insn.mnemonic in mnemonics:
                return insn.address
        return -1

    def _memory_accesses(self) -> tuple[Access, ...]:
        found: list[Access] = []
        for index, insn in enumerate(self.insns):
            if insn.mnemonic == "lea":
                continue
            for operand in insn.operands:
                if operand.type != capstone.x86.X86_OP_MEM:
                    continue
                location = self.location(insn, index, operand)
                if location is None:
                    continue
                found.append(
                    Access(
                        location=location,
                        base_register=full_register(operand.mem.base),
                        is_read=bool(operand.access & capstone.CS_AC_READ),
                        is_write=bool(operand.access & capstone.CS_AC_WRITE),
                        insn_rva=insn.address,
                        text=_insn_text(insn),
                    )
                )
        return tuple(found)

    @property
    def start_rva(self) -> int:
        return self.insns[0].address if self.insns else self.candidate.rva

    @property
    def byte_length(self) -> int:
        return self.candidate.rva - self.start_rva if self.insns else 0

    @property
    def stack_delta(self) -> int:
        return sum(rsp_delta(insn) for insn in self.insns)

    def control_flow(self) -> str:
        return _cell(
            _join(
                f"{_insn_text(insn)}@{_hex(insn.address)}"
                for insn in self.insns
                if insn.mnemonic in CONTROL_FLOW_MNEMONICS
            )
        )

    def argument_slots(self) -> tuple[int, ...]:
        """Every argument stack offset the window writes, ascending."""
        found: set[int] = set()
        for index, insn in enumerate(self.insns):
            for operand in insn.operands:
                if (
                    operand.type == capstone.x86.X86_OP_MEM
                    and operand.access & capstone.CS_AC_WRITE
                    and operand.mem.base == capstone.x86.X86_REG_RSP
                ):
                    offset = operand.mem.disp + self.deltas[index]
                    if offset >= STACK_ARG_BASE_DISP:
                        found.add(offset)
        return tuple(sorted(found))

    def allocation_calls(self) -> tuple[str, ...]:
        found = []
        for insn in self.insns:
            if insn.mnemonic != "call":
                continue
            symbol = self.iat_calls.get(insn.address, "")
            if symbol in ALLOCATOR_SYMBOLS:
                found.append(f"{symbol}@{_hex(insn.address)}")
        return tuple(found)



    def location(self, insn: capstone.CsInsn, index: int, operand: Any) -> str | None:
        """Normalised address of a memory operand, or None when unresolvable."""
        memory = operand.mem
        if memory.segment or memory.index:
            return None
        if memory.base == capstone.x86.X86_REG_RIP:
            return f"image:{insn.address + insn.size + memory.disp}"
        if memory.base == capstone.x86.X86_REG_RSP:
            return FrameKey("rsp", memory.disp + self.deltas[index]).location()
        if memory.base == capstone.x86.X86_REG_RBP:
            return FrameKey("rbp", memory.disp).location()
        if memory.base == 0:
            return f"image:{memory.disp}"
        resolved = self.resolve_register(memory.base, 1)
        if resolved.address_va is not None and resolved.address_kind in (
            ADDR_IMAGE,
            ADDR_LOADED,
        ):
            return f"image:{resolved.address_va + memory.disp}"
        if resolved.frame is not None:
            return FrameKey(
                resolved.frame.anchor, resolved.frame.disp + memory.disp
            ).location()
        return None

    def register_definitions(self, insn: capstone.CsInsn) -> dict[int, str]:
        """Register writes of an instruction, mapped to the canonical 64 bit id.

        The value is `definite`, `conditional` or `partial`; this mapping is the
        whole precedence channel of the backward walk.
        """
        found: dict[int, str] = {}
        conditional = insn.mnemonic in CONDITIONAL_MNEMONICS
        for operand in insn.operands:
            if operand.type != capstone.x86.X86_OP_REG:
                continue
            if not operand.access & capstone.CS_AC_WRITE:
                continue
            register = full_register(operand.reg)
            if register in (capstone.x86.X86_REG_RSP, capstone.x86.X86_REG_RBP):
                continue
            kind = "conditional" if conditional else "definite"
            if operand.size in (1, 2) or found.get(register) == "partial":
                kind = "partial"
            found[register] = kind
        implicit = IMPLICIT_WRITE_TABLES.get(insn.mnemonic)
        if implicit is None and (
            insn.mnemonic in IMPLICIT_WRITE_ONE_OPERAND and len(insn.operands) == 1
        ):
            implicit = (capstone.x86.X86_REG_RAX, capstone.x86.X86_REG_RDX)
        for register in implicit or ():
            found.setdefault(register, "definite")
        return found

    def find_definition(self, register: int) -> tuple[capstone.CsInsn, str] | None:
        """Nearest definite definition, else nearest conditional definition."""
        definite: capstone.CsInsn | None = None
        conditional: capstone.CsInsn | None = None
        for insn in reversed(self.insns):
            kind = self.register_definitions(insn).get(register)
            if kind is None:
                continue
            if kind == "definite" and definite is None:
                definite = insn
            elif kind == "conditional" and conditional is None:
                conditional = insn
            if definite is not None and conditional is not None:
                break
        if definite is not None:
            return definite, "definite"
        if conditional is not None:
            return conditional, "conditional"
        return None

    def find_slot_store(self, offset: int) -> capstone.CsInsn | None:
        """Instruction that writes the argument stack slot at `offset`."""
        for index, insn in enumerate(self.insns):
            for operand in insn.operands:
                if (
                    operand.type == capstone.x86.X86_OP_MEM
                    and operand.access & capstone.CS_AC_WRITE
                    and operand.mem.base == capstone.x86.X86_REG_RSP
                    and operand.mem.disp + self.deltas[index] == offset
                ):
                    return insn
        return None

    def find_frame_store(self, key: FrameKey) -> capstone.CsInsn | None:
        """Instruction that writes the normalised frame slot `key`."""
        for insn in self.insns:
            index = self.position[insn.address]
            for operand in insn.operands:
                if operand.type != capstone.x86.X86_OP_MEM:
                    continue
                if not operand.access & capstone.CS_AC_WRITE:
                    continue
                if self.location(insn, index, operand) == key.location():
                    return insn
        return None



    def stale_reason(self, insn: capstone.CsInsn, register: int | None) -> str:
        """Why a definition is not on the path that reaches the candidate.

        A call only invalidates a register definition, and only for a volatile
        register: a stack or frame slot above the callee shadow space survives a
        call, so a slot store is judged on the linear path only.
        """
        if register is not None and register in VOLATILE_REGISTERS:
            if self.last_call_rva >= 0 and insn.address < self.last_call_rva:
                return STALE_CALL
        if self.last_flow_rva >= 0 and insn.address < self.last_flow_rva:
            return STALE_FLOW
        return STALE_NONE

    def copy_set(self, insn: capstone.CsInsn, register: int) -> frozenset[int]:
        """Registers that hold the value of `register` at the candidate.

        A register copied from a member of the set inside the window joins the
        set, which is what lets a store through the pointer an allocation
        returned be attributed to the argument.
        """
        members = {register}
        for later in self.insns:
            if later.address <= insn.address or later.mnemonic not in ("mov", "movabs"):
                continue
            operands = later.operands
            if len(operands) != 2:
                continue
            destination, source = operands
            if destination.type != capstone.x86.X86_OP_REG or destination.size != 8:
                continue
            if source.type != capstone.x86.X86_OP_REG or source.size != 8:
                continue
            if full_register(source.reg) in members:
                members.add(full_register(destination.reg))
        return frozenset(members)

    def resolve_register(self, register: int, depth: int = 0) -> Value:
        canonical = full_register(register)
        key = ("reg", canonical, depth)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        if key in self._active:
            return unknown_value(register_name(canonical), "cyclic_definition")
        self._active.add(key)
        try:
            if depth > COPY_CHAIN_MAX_DEPTH:
                value = unknown_value(register_name(canonical), "depth_exhausted")
            else:
                value = self._resolve_register(canonical, depth)
        finally:
            self._active.discard(key)
        self._cache[key] = value
        return value

    def _resolve_register(self, register: int, depth: int) -> Value:
        found = self.find_definition(register)
        if found is None:
            return unknown_value(register_name(register))
        insn, kind = found
        stale = self.stale_reason(insn, register)
        if kind == "conditional":
            stale = stale or STALE_CONDITIONAL
        return self.instruction_value(insn, register, depth, _insn_text(insn), stale)

    def resolve_slot(self, offset: int, depth: int = 0) -> Value:
        key = ("slot", offset, depth)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        if key in self._active:
            return unknown_value(f"[RSP+{offset:#x}]", "cyclic_definition")
        self._active.add(key)
        try:
            if depth > COPY_CHAIN_MAX_DEPTH:
                value = unknown_value(f"[RSP+{offset:#x}]", "depth_exhausted")
            else:
                value = self._slot_value(offset, depth)
        finally:
            self._active.discard(key)
        self._cache[key] = value
        return value

    def _slot_value(self, offset: int, depth: int) -> Value:
        key = FrameKey("rsp", offset)
        base = Value(
            kind=KIND_INDIRECT,
            const=None,
            const_source=SRC_NONE,
            address_va=None,
            address_kind=ADDR_STACK,
            section="",
            writable=True,
            expr=f"stack slot +{offset:#x}",
            origin=SRC_SLOT_STORE,
            def_rva=None,
            def_text="",
            def_dist=0,
            alloc_symbol="",
            alloc_rva=None,
            entry_param="",
            entry_param_rva=None,
            slot_disp=offset,
            raw_operand=f"+{offset:#x}",
            chain=(f"[rsp+{offset:#x}]",),
            regs=frozenset(),
            stale=STALE_NONE,
            frame=key,
        )
        store = self.find_slot_store(offset)
        if store is None:
            spill = self.entry_spill.get(key)
            if spill is not None:
                return _merge(
                    base,
                    origin="entry_parameter_slot",
                    expr=f"stack slot +{offset:#x} = entry parameter {spill[0]}",
                    entry_param=spill[0],
                    entry_param_rva=spill[1],
                )
            return _merge(base, origin="stack_slot_unwritten")
        operands = store.operands
        stored = operands[1] if len(operands) > 1 else None
        stored_text = store.op_str.partition(",")[2].strip() or store.op_str
        store_stale = self.stale_reason(store, None)
        store_fields: dict[str, Any] = {
            "def_rva": store.address,
            "def_text": _insn_text(store),
            "def_dist": self.candidate.rva - store.address,
            "raw_operand": stored_text,
            "slot_disp": offset,
            "stale": store_stale,
            "chain": (
                f"[rsp+{offset:#x}]<-{stored_text}@{_hex(store.address)}",
            ),
        }
        if stored is not None and stored.type == capstone.x86.X86_OP_REG:
            source = self.resolve_register(stored.reg, depth + 1)
            return _merge(
                source,
                slot_disp=offset,
                raw_operand=stored_text,
                origin=source.origin if source.origin != SRC_NONE else SRC_SLOT_STORE,
                def_rva=store.address,
                def_text=_insn_text(store),
                def_dist=self.candidate.rva - store.address,
                chain=(*store_fields["chain"], *source.chain),
                regs=source.regs,
                stale=store_stale or source.stale,
            )
        if stored is not None and stored.type == capstone.x86.X86_OP_IMM:
            const = _wrap64(stored.imm, operands[0].size)
            return _merge(
                base,
                kind=KIND_CONST,
                const=const,
                const_source=SRC_SLOT_STORE,
                expr=f"{const} (0x{const:X})",
                **store_fields,
            )
        if stored is not None and stored.type == capstone.x86.X86_OP_MEM:
            location = self.location(store, self.position[store.address], stored)
            if location is not None and location.startswith("image:"):
                address = int(location.partition(":")[2])
                loaded = self.image.qword_va(address)
                if loaded is not None and self.image.section_of_va(loaded) is not None:
                    section = self.image.section_of_va(loaded)
                    return _merge(
                        base,
                        kind=KIND_ADDRESS,
                        const=None,
                        address_va=loaded,
                        address_kind=ADDR_LOADED,
                        section=section.name if section is not None else "",
                        writable=bool(section and section.characteristics & SECTION_MEM_WRITE),
                        expr=f"[rsp+{offset:#x}] <- qword @ {_hex(address)}",
                        origin=SRC_LOADED_IMAGE,
                        **store_fields,
                    )
                return _merge(
                    base,
                    kind=KIND_ADDRESS,
                    address_va=address,
                    address_kind=ADDR_IMAGE,
                    section=self.section_name(address),
                    writable=self.image.section_writable(address),
                    expr=f"[rsp+{offset:#x}] <- {_hex(address)}",
                    **store_fields,
                )
            if location is not None and location.startswith("frame:"):
                _, anchor, disp = location.split(":")
                return _merge(
                    base,
                    kind=KIND_ADDRESS,
                    address_va=None,
                    address_kind=ADDR_FRAME if anchor == "rbp" else ADDR_STACK,
                    expr=f"[rsp+{offset:#x}] <- frame {anchor}{int(disp):+d}",
                    frame=FrameKey(anchor, int(disp)),
                    **store_fields,
                )
        return _merge(
            base,
            expr=f"[rsp+{offset:#x}] <- {stored_text}",
            origin=SRC_SLOT_STORE,
            **store_fields,
        )



    def reads_and_writes(self, location: str) -> tuple[str, str]:
        """Load and store evidence of the window for one normalised address."""
        reads = _cell(
            _join(
                f"{item.text}@{_hex(item.insn_rva)}"
                for item in self.accesses
                if item.is_read and item.location == location
            )
        )
        writes = _cell(
            _join(
                f"{item.text}@{_hex(item.insn_rva)}"
                for item in self.accesses
                if item.is_write and item.location == location
            )
        )
        return reads, writes

    def value_location(self, value: Value) -> str | None:
        """Normalised address of a resolved value, or None when it has none."""
        if value.frame is not None:
            return value.frame.location()
        if value.address_va is not None and value.address_kind in (
            ADDR_IMAGE,
            ADDR_LOADED,
        ):
            return f"image:{value.address_va}"
        return None

    def allocation_write(self, value: Value) -> str:
        """Store site that writes through a pointer an allocation returned."""
        if not value.alloc_symbol or not value.regs:
            return ""
        for item in self.accesses:
            if item.is_write and item.base_register in value.regs:
                return _hex(item.insn_rva)
        return ""



    def instruction_value(
        self,
        insn: capstone.CsInsn,
        register: int,
        depth: int,
        text: str,
        stale: str,
    ) -> Value:
        """Value an instruction leaves in `register`, as far as the window knows."""
        name = register_name(register)
        base = Value(
            kind=KIND_INDIRECT,
            const=None,
            const_source=SRC_NONE,
            address_va=None,
            address_kind="",
            section="",
            writable=False,
            expr=text,
            origin="unresolved_operand",
            def_rva=insn.address,
            def_text=text,
            def_dist=self.candidate.rva - insn.address,
            alloc_symbol="",
            alloc_rva=None,
            entry_param="",
            entry_param_rva=None,
            slot_disp=None,
            raw_operand="",
            chain=(f"{name}<-{_insn_text(insn)}@{_hex(insn.address)}",),
            regs=frozenset({register}),
            stale=stale,
            frame=None,
        )
        mnemonic = insn.mnemonic
        operands = insn.operands

        if mnemonic == "call":
            symbol = self.iat_calls.get(insn.address, "")
            allocated = symbol in ALLOCATOR_SYMBOLS
            return _merge(
                base,
                expr=f"call {insn.op_str} -> rax",
                origin="call_result",
                alloc_symbol=symbol if allocated else "",
                alloc_rva=insn.address if allocated else None,
            )
        if mnemonic in UNINTERPRETED_MNEMONICS:
            return _merge(base, origin=f"uninterpreted_{mnemonic}")
        if not operands or operands[0].type != capstone.x86.X86_OP_REG:
            return _merge(base, origin="implicit_or_unsupported")
        if full_register(operands[0].reg) != register:
            return _merge(base, origin="writes_other_register")

        destination = operands[0]
        source = operands[1] if len(operands) > 1 else None
        raw_operand = insn.op_str.partition(",")[2].strip() or insn.op_str

        if mnemonic in ("mov", "movabs") and source is not None:
            if source.type == capstone.x86.X86_OP_IMM:
                const = _wrap64(source.imm, destination.size)
                return _merge(
                    base,
                    kind=KIND_CONST,
                    const=const,
                    const_source=SRC_IMMEDIATE,
                    expr=f"{const} (0x{const:X})",
                    origin=SRC_IMMEDIATE,
                    raw_operand=raw_operand,
                )
            if source.type == capstone.x86.X86_OP_REG:
                return self._copy_value(
                    base,
                    register,
                    full_register(source.reg),
                    depth,
                    raw_operand,
                    insn,
                    source.size,
                )
            if source.type == capstone.x86.X86_OP_MEM:
                return self._load_value(base, register, insn, source, raw_operand, depth)
        if (
            mnemonic == "lea"
            and source is not None
            and source.type == capstone.x86.X86_OP_MEM
        ):
            return self._lea_value(base, insn, source, raw_operand)
        if (
            mnemonic in ("xor", "sub")
            and source is not None
            and source.type == capstone.x86.X86_OP_REG
            and full_register(source.reg) == register
        ):
            return _merge(
                base,
                kind=KIND_CONST,
                const=0,
                const_source=SRC_ZERO_IDENTITY,
                expr="0",
                origin=SRC_ZERO_IDENTITY,
                raw_operand=raw_operand,
            )
        if mnemonic in FOLDABLE_MNEMONICS and source is not None:
            folded = self._fold(insn, register, depth)
            if folded is not None:
                return _merge(
                    folded,
                    def_rva=insn.address,
                    def_text=text,
                    def_dist=self.candidate.rva - insn.address,
                    stale=stale,
                    raw_operand=raw_operand or folded.raw_operand,
                    chain=(f"{name}<-{_insn_text(insn)}@{_hex(insn.address)}",),
                )
        if mnemonic in STRING_OPERATION_MNEMONICS:
            return _merge(base, origin=f"string_op_{mnemonic}")
        return _merge(base, origin="uninterpreted_form", raw_operand=raw_operand)

    def _copy_value(
        self,
        base: Value,
        register: int,
        source_register: int,
        depth: int,
        raw_operand: str,
        insn: capstone.CsInsn,
        width: int,
    ) -> Value:
        """Follow a register to register copy to the value it carries."""
        if depth + 1 > COPY_CHAIN_MAX_DEPTH:
            return _merge(
                base,
                origin="copy_depth_exhausted",
                expr=(
                    f"{register_name(register)} <- {raw_operand} "
                    f"(depth {COPY_CHAIN_MAX_DEPTH})"
                ),
                raw_operand=raw_operand,
            )
        source = self.resolve_register(source_register, depth + 1)
        spill = self.entry_spill.get(source_register)
        if spill is not None and not source.entry_param:
            source = _merge(
                source,
                entry_param=spill[0],
                entry_param_rva=spill[1],
                origin=source.origin if source.origin != SRC_NONE else "entry_parameter",
            )
        copied = _merge(
            source,
            def_rva=insn.address,
            def_text=_insn_text(insn),
            def_dist=base.def_dist,
            raw_operand=raw_operand,
            chain=(
                f"{register_name(register)}<-{raw_operand}@{_hex(insn.address)}",
                *source.chain,
            ),
            regs=self.copy_set(insn, source_register),
            stale=base.stale or source.stale,
        )
        if copied.kind == KIND_NONE and spill is not None:
            copied = _merge(
                copied,
                kind=KIND_INDIRECT,
                origin="entry_parameter",
                expr=f"entry parameter {spill[0]}",
            )
        elif copied.kind == KIND_NONE:
            copied = _merge(
                copied,
                kind=KIND_INDIRECT,
                origin=f"copy_of_undefined_{register_name(source_register)}",
                expr=f"{register_name(register)} <- {raw_operand} (undefined in window)",
            )
        if copied.entry_param and width < 8:
            copied = _merge(copied, origin=f"partial{width * 8}")
        return copied

    def _load_value(
        self,
        base: Value,
        register: int,
        insn: capstone.CsInsn,
        operand: Any,
        raw_operand: str,
        depth: int,
    ) -> Value:
        """Value a load from memory leaves in `register`."""
        location = self.location(insn, self.position[insn.address], operand)
        if location is None:
            return _merge(base, origin="unresolved_load", raw_operand=raw_operand)
        if location.startswith("frame:"):
            return self._frame_load_value(base, register, insn, location, raw_operand, depth)
        address = int(location.partition(":")[2])
        loaded = self.image.qword_va(address)
        if loaded is None:
            return _merge(
                base,
                kind=KIND_ADDRESS,
                address_va=address,
                address_kind=ADDR_IMAGE,
                section=self.section_name(address),
                writable=self.image.section_writable(address),
                expr=f"qword @ {_hex(address)} (no file bytes)",
                origin="image_data_load",
                raw_operand=raw_operand,
            )
        section = self.image.section_of_va(loaded)
        if section is not None:
            return _merge(
                base,
                kind=KIND_ADDRESS,
                address_va=loaded,
                address_kind=ADDR_LOADED,
                section=section.name,
                writable=bool(section.characteristics & SECTION_MEM_WRITE),
                expr=f"qword @ {_hex(address)} -> {_hex(loaded)}",
                origin="image_data_pointer",
                raw_operand=raw_operand,
            )
        if loaded <= MAX_PLAUSIBLE_LENGTH:
            return _merge(
                base,
                kind=KIND_CONST,
                const=loaded,
                const_source=SRC_LOADED_IMAGE,
                expr=f"qword @ {_hex(address)} = {loaded}",
                origin=SRC_LOADED_IMAGE,
                raw_operand=raw_operand,
            )
        return _merge(
            base,
            expr=f"qword @ {_hex(address)} = {_hex(loaded)}",
            origin=SRC_LOADED_IMAGE,
            raw_operand=raw_operand,
        )

    def _frame_load_value(
        self,
        base: Value,
        register: int,
        insn: capstone.CsInsn,
        location: str,
        raw_operand: str,
        depth: int,
    ) -> Value:
        """Value a load from frame or stack storage leaves in `register`."""
        _, anchor, disp = location.split(":")
        offset = int(disp)
        key = FrameKey(anchor, offset)
        if anchor == "rsp" and offset >= STACK_ARG_BASE_DISP:
            return self.resolve_slot(offset, depth + 1)
        store = self.find_frame_store(key)
        if store is not None and len(store.operands) > 1:
            stored = store.operands[1]
            if stored.type == capstone.x86.X86_OP_REG:
                source = self.resolve_register(stored.reg, depth + 1)
                return _merge(
                    source,
                    frame=source.frame,
                    raw_operand=raw_operand,
                    origin=source.origin,
                    def_rva=store.address,
                    def_text=_insn_text(store),
                    def_dist=self.candidate.rva - store.address,
                    chain=(
                        f"[{anchor}{offset:+d}]<-{_insn_text(store)}@{_hex(store.address)}",
                        *source.chain,
                    ),
                )
        spill = self.entry_spill.get(key)
        if spill is not None:
            return _merge(
                base,
                kind=KIND_INDIRECT,
                address_kind=ADDR_FRAME,
                expr=f"frame {anchor}{offset:+d} = entry parameter {spill[0]}",
                origin="entry_parameter_frame",
                raw_operand=raw_operand,
                entry_param=spill[0],
                entry_param_rva=spill[1],
                frame=key,
            )
        return _merge(
            base,
            kind=KIND_INDIRECT,
            address_kind=ADDR_FRAME,
            expr=f"frame {anchor}{offset:+d} (no store in window)",
            origin="frame_load_unresolved",
            raw_operand=raw_operand,
            frame=key,
        )

    def _lea_value(
        self, base: Value, insn: capstone.CsInsn, operand: Any, raw_operand: str
    ) -> Value:
        """Value an lea of an address leaves in the destination register."""
        location = self.location(insn, self.position[insn.address], operand)
        if location is None:
            return _merge(base, origin="unresolved_lea", raw_operand=raw_operand)
        if location.startswith("image:"):
            address = int(location.partition(":")[2])
            return _merge(
                base,
                kind=KIND_ADDRESS,
                address_va=address,
                address_kind=ADDR_IMAGE,
                section=self.section_name(address),
                writable=self.image.section_writable(address),
                expr=f"{raw_operand} -> {_hex(address)}",
                origin="lea_image",
                raw_operand=raw_operand,
            )
        if location.startswith("frame:"):
            _, anchor, disp = location.split(":")
            key = FrameKey(anchor, int(disp))
            return _merge(
                base,
                kind=KIND_ADDRESS,
                address_kind=ADDR_FRAME if anchor == "rbp" else ADDR_STACK,
                expr=f"{raw_operand} -> frame {anchor}{key.disp:+d}",
                origin="lea_frame",
                raw_operand=raw_operand,
                frame=key,
            )
        return _merge(base, origin="unresolved_lea", raw_operand=raw_operand)

    def _fold(self, insn: capstone.CsInsn, register: int, depth: int) -> Value | None:
        """Constant fold a window arithmetic instruction over known constants."""
        operands = insn.operands
        if not operands or operands[0].type != capstone.x86.X86_OP_REG:
            return None
        if full_register(operands[0].reg) != register:
            return None
        values: list[int] = []
        for operand in operands[1:]:
            if operand.type == capstone.x86.X86_OP_IMM:
                values.append(_wrap64(operand.imm, operand.size))
            elif operand.type == capstone.x86.X86_OP_REG:
                resolved = self.resolve_register(operand.reg, depth + 1)
                if resolved.kind != KIND_CONST or resolved.const is None:
                    return None
                values.append(resolved.const)
            else:
                return None
        if not values:
            return None
        try:
            folded = apply_operation(
                insn.mnemonic, insn.op_str, values[0], values[1] if len(values) > 1 else None
            )
        except (TypeError, ValueError, ZeroDivisionError):
            return None
        if folded is None:
            return None
        const = _wrap64(folded, operands[0].size)
        return Value(
            kind=KIND_CONST,
            const=const,
            const_source=SRC_FOLDED,
            address_va=None,
            address_kind="",
            section="",
            writable=False,
            expr=f"{const} (0x{const:X})",
            origin=SRC_FOLDED,
            def_rva=insn.address,
            def_text=_insn_text(insn),
            def_dist=self.candidate.rva - insn.address,
            alloc_symbol="",
            alloc_rva=None,
            entry_param="",
            entry_param_rva=None,
            slot_disp=None,
            raw_operand=insn.op_str,
            chain=(),
            regs=frozenset({register}),
            stale=STALE_NONE,
            frame=None,
        )

    def section_name(self, va: int) -> str:
        section = self.image.section_of_va(va)
        return "" if section is None else section.name







@dataclass(frozen=True, slots=True)
class ArgumentFacts:
    """One argument position of one candidate."""

    position: int
    source: str
    location: str
    value: Value
    klass: str
    reason: str
    length: int | None
    rw_pair: bool
    rw_evidence: str
    alloc_symbol: str
    alloc_rva: int | None
    alloc_write: bool
    alloc_evidence: str


@dataclass(frozen=True, slots=True)
class SiteFacts:
    """One analysed candidate site."""

    candidate: Candidate
    cfg: CfgFunction | None
    decode_status: str
    mnemonic: str
    window: Window
    arguments: tuple[ArgumentFacts, ...]
    extra_slots: tuple[int, ...]


def classify(
    value: Value, source: str, previous_is_buffer: bool, rw_pair: bool
) -> tuple[str, str, int | None]:
    """Apply the class ladder to one argument position.

    Returns the class, the reason code of the ladder step that fired and the
    length when the class is A4_LEN.
    """
    if value.stale in (STALE_CALL, STALE_FLOW, STALE_CONDITIONAL):
        if value.entry_param:
            width = value.origin if value.origin.startswith("partial") else ""
            return (
                CLASS_A6,
                f"entry_param_{value.entry_param}_{value.stale}{'_' + width if width else ''}",
                None,
            )
        if source == "stack_slot":
            return CLASS_A5, f"stack_{value.stale}", None
        return CLASS_A7, f"reg_{value.stale}", None
    if value.kind == KIND_CONST and value.const is not None and _is_pseudo_window(value.const):
        named = value.pseudo
        return CLASS_A1, f"pseudo_handle_{'named' if named else 'range'}", None
    if value.is_buffer:
        readonly = value.address_va is not None and not value.writable
        suffix = "_ro" if readonly else ""
        klass = CLASS_A3_INOUT if rw_pair else CLASS_A3_OUT
        return klass, f"address_{value.address_kind}{suffix}", None
    if value.kind == KIND_CONST and value.const is not None:
        if previous_is_buffer and 0 < value.const <= MAX_PLAUSIBLE_LENGTH:
            return CLASS_A4, f"const_after_buffer_{value.const_source}", value.const
        if value.const == 0:
            return CLASS_A2, f"const_literal_zero_{value.const_source}", None
        return CLASS_A2, f"const_literal_{value.const_source}", None
    if value.entry_param:
        width = value.origin if value.origin.startswith("partial") else ""
        spill = _hex(value.entry_param_rva) if value.entry_param_rva is not None else "none"
        return (
            CLASS_A6,
            f"entry_param_{value.entry_param}_spill_{spill}"
            + (f"_{width}" if width else ""),
            None,
        )
    if source == "stack_slot":
        return CLASS_A5, f"stack_unresolved_{value.origin}", None
    if value.kind == KIND_INDIRECT:
        return CLASS_A7, f"reg_{value.origin}", None
    if value.kind == KIND_NONE:
        reason = (
            "no_def_in_window"
            if value.def_rva is None
            else f"chain_tail_undefined_{value.origin}"
        )
        return CLASS_A8, reason, None
    return CLASS_A8, "unclassified", None


def argument_positions() -> tuple[tuple[int, int | None, str], ...]:
    """The enumerated argument positions: index, stack offset, location label."""
    positions = [(index, None, name) for index, _, name in ARG_REGISTERS]
    positions += [
        (
            len(ARG_REGISTERS) + slot + 1,
            STACK_ARG_BASE_DISP + slot * 8,
            f"[RSP+{STACK_ARG_BASE_DISP + slot * 8:#x}]",
        )
        for slot in range(CSV_STACK_SLOTS)
    ]
    return tuple(positions)


def site_arguments(window: Window) -> tuple[ArgumentFacts, ...]:
    """Resolve, signal and classify every enumerated argument position."""
    results: list[ArgumentFacts] = []
    previous_is_buffer = False
    for position, offset, label in argument_positions():
        if offset is None:
            source = "register"
            value = window.resolve_register(ARG_REGISTERS[position - 1][1])
        else:
            source = "stack_slot"
            value = window.resolve_slot(offset)
        address = window.value_location(value)
        reads, writes = window.reads_and_writes(address) if address else ("", "")
        rw_pair = bool(address and reads and writes)
        rw_evidence = _cell(
            _join(
                [
                    f"rw {address}" if address else "",
                    f"read {reads}" if reads else "",
                    f"write {writes}" if writes else "",
                ]
            )
        )
        write_rva = window.allocation_write(value)
        klass, reason, length = classify(value, source, previous_is_buffer, rw_pair)
        previous_is_buffer = klass in BUFFER_CLASSES
        results.append(
            ArgumentFacts(
                position=position,
                source=source,
                location=label,
                value=value,
                klass=klass,
                reason=reason,
                length=length,
                rw_pair=rw_pair,
                rw_evidence=rw_evidence,
                alloc_symbol=value.alloc_symbol,
                alloc_rva=value.alloc_rva,
                alloc_write=bool(write_rva),
                alloc_evidence=_cell(
                    _join(
                        [
                            f"alloc {value.alloc_symbol}@{_hex(value.alloc_rva)}"
                            if value.alloc_symbol
                            else "",
                            f"store {write_rva}" if write_rva else "",
                        ]
                    )
                ),
            )
        )
    return tuple(results)







def entry_spill_of(
    disassembler: capstone.Cs, code: bytes, begin: int
) -> tuple[dict[Any, tuple[str, int]], str, int]:
    """Parameters the function prologue takes from its own entry registers.

    A register to register copy of RCX/RDX/R8/R9 into another register, or a
    store of one of them into an rbp relative frame slot, marks that target as
    carrying the entry parameter. The scan covers the first
    `ENTRY_SPILL_INSNS` instructions of the function.
    """
    spills: dict[Any, tuple[str, int]] = {}
    texts: list[str] = []
    count = 0
    for insn in disassembler.disasm(code, begin):
        if count >= ENTRY_SPILL_INSNS:
            break
        count += 1
        operands = insn.operands
        if insn.mnemonic not in ("mov", "movabs") or len(operands) != 2:
            continue
        destination, source = operands
        if source.type != capstone.x86.X86_OP_REG:
            continue
        origin = full_register(source.reg)
        if origin not in ENTRY_PARAMETER_NAMES or destination.type == capstone.x86.X86_OP_REG and (
            full_register(destination.reg) in ENTRY_PARAMETER_NAMES
        ):
            continue
        name = ENTRY_PARAMETER_NAMES[origin]
        if destination.type == capstone.x86.X86_OP_REG:
            key: Any = full_register(destination.reg)
        elif (
            destination.type == capstone.x86.X86_OP_MEM
            and destination.mem.base == capstone.x86.X86_REG_RBP
        ):
            key = FrameKey("rbp", destination.mem.disp)
        else:
            continue
        if key in spills:
            continue
        spills[key] = (name, insn.address)
        if destination.type == capstone.x86.X86_OP_REG:
            target = register_name(full_register(destination.reg))
        else:
            target = f"rbp{destination.mem.disp:+d}"
        texts.append(f"{name}->{target}@{_hex(insn.address)}")
    return spills, _cell(_join(texts)), count


def sweep_function(
    disassembler: capstone.Cs, image: Image, begin: int, target: int
) -> list[capstone.CsInsn]:
    """Linear sweep from `begin` up to `target`.

    The sweep stops at the first byte it cannot consume, so the returned list is
    the contiguous decoded prefix. `target` is the last site of the function, so
    the sweep is the longest prefix the phase ever needs.
    """
    code = image.at_rva(begin, target - begin)
    return list(disassembler.disasm(code, begin))


def make_disassembler(detail: bool) -> capstone.Cs:
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    disassembler.detail = detail
    disassembler.skipdata = False
    return disassembler


def window_for(
    image: Image,
    candidate: Candidate,
    insns: Sequence[capstone.CsInsn],
    reached: bool,
    entry_spill: dict[Any, tuple[str, int]],
    entry_spill_text: str,
    iat_calls: dict[int, str],
    window_bytes: int,
    detailed: capstone.Cs,
) -> tuple[Window, str]:
    """Build the analysis window of a candidate out of the swept instructions.

    `insns` is the decoded prefix of the owning function that ends at the
    candidate, and `reached` says the sweep consumed every byte up to it. The
    tail of that prefix whose byte span fits the window budget is the window, so
    its first instruction is a real instruction boundary and its last byte is the
    first byte of the candidate. The same bytes are decoded again with operand
    detail and the two partitions are compared, which is the guard against a
    misaligned window start.
    """
    empty = Window(image, candidate, (), entry_spill, entry_spill_text, iat_calls)
    if not reached:
        return empty, DECODE_UNREACHED
    chosen: list[capstone.CsInsn] = []
    for insn in reversed(insns):
        if candidate.rva - insn.address > window_bytes:
            break
        chosen.append(insn)
    chosen.reverse()
    if not chosen:
        return empty, DECODE_EMPTY
    span = candidate.rva - chosen[0].address
    if span > window_bytes:
        return empty, DECODE_UNREACHED
    code = image.at_rva(chosen[0].address, span)
    detailed_list = list(detailed.disasm(code, chosen[0].address))
    if [insn.address for insn in detailed_list] != [insn.address for insn in chosen]:
        return empty, DECODE_MISMATCH
    if not detailed_list or detailed_list[-1].address + detailed_list[-1].size != candidate.rva:
        return empty, DECODE_MISMATCH
    window = Window(
        image, candidate, detailed_list, entry_spill, entry_spill_text, iat_calls
    )
    return window, DECODE_OK


def analyse(
    image: Image, inputs: PhaseInputs, window_bytes: int
) -> tuple[list[SiteFacts], Counter[str]]:
    """Build the site facts of every valid candidate, in raw offset order."""
    by_function: dict[int, list[Candidate]] = {}
    for candidate in inputs.candidates:
        by_function.setdefault(candidate.function_begin, []).append(candidate)

    sweep_disassembler = make_disassembler(detail=False)
    detail_disassembler = make_disassembler(detail=True)
    tally: Counter[str] = Counter()
    sites: list[SiteFacts] = []

    for begin in sorted(by_function):
        group = sorted(by_function[begin], key=lambda item: item.raw)
        insns = sweep_function(sweep_disassembler, image, begin, group[-1].rva)
        ends = [insn.address + insn.size for insn in insns]
        probe = image.at_rva(begin, ENTRY_SPILL_PROBE_BYTES)
        entry_spill, entry_text, spill_count = entry_spill_of(
            detail_disassembler, probe, begin
        )
        for candidate in group:
            count = bisect.bisect_right(ends, candidate.rva)
            reached = count > 0 and ends[count - 1] == candidate.rva
            window, status = window_for(
                image,
                candidate,
                insns[:count],
                reached,
                entry_spill,
                entry_text,
                inputs.iat_calls,
                window_bytes,
                detail_disassembler,
            )
            decoded = status == DECODE_OK
            arguments = site_arguments(window) if decoded else unreached_arguments()
            cfg = inputs.cfg.get(candidate.pdata_index)
            cfg_ok = cfg is not None and (cfg.begin, cfg.end) == (
                candidate.function_begin,
                candidate.function_end,
            )
            sites.append(
                SiteFacts(
                    candidate=candidate,
                    cfg=cfg,
                    decode_status=status,
                    mnemonic=SYSCALL_MNEMONIC if reached else "",
                    window=window,
                    arguments=arguments,
                    extra_slots=window.argument_slots() if decoded else (),
                )
            )
            tally["sites"] += 1
            tally[f"decode:{status}"] += 1
            tally["reached"] += int(reached)
            tally["cfg_joined"] += int(cfg is not None)
            tally["cfg_bounds_match"] += int(cfg_ok)
            tally["entry_spill_parameters"] += len(entry_spill)
            for facts in arguments:
                tally[f"class:{facts.klass}"] += 1
                tally["rw_pair"] += int(facts.rw_pair)
                tally["alloc_origin"] += int(bool(facts.alloc_symbol))
                tally["alloc_write"] += int(facts.alloc_write)
        tally["spill_insns"] += spill_count
    sites.sort(key=lambda site: site.candidate.raw)
    return sites, tally


def unreached_arguments() -> tuple[ArgumentFacts, ...]:
    """Placeholder arguments of a site whose sweep stopped before the candidate."""
    return tuple(
        ArgumentFacts(
            position=position,
            source="register" if offset is None else "stack_slot",
            location=label,
            value=unknown_value(label, "window_unavailable"),
            klass=CLASS_A8,
            reason="window_unavailable",
            length=None,
            rw_pair=False,
            rw_evidence="",
            alloc_symbol="",
            alloc_rva=None,
            alloc_write=False,
            alloc_evidence="",
        )
        for position, offset, label in argument_positions()
    )







def _const_cell(value: Value) -> str:
    if value.kind != KIND_CONST or value.const is None:
        return ""
    return _cell(f"0x{value.const:X}")


def _addr_cell(value: Value) -> str:
    if not value.is_buffer:
        return ""
    if value.address_va is not None:
        rva = value.address_va
        return _cell(
            f"VA {_hex(value.address_va)}|RVA {_hex(rva)}|{value.section or 'unmapped'}|"
            f"{'rw' if value.writable else 'ro'}|localizable"
        )
    if value.frame is not None:
        return _cell(f"frame {value.frame.anchor}{value.frame.disp:+d}|not_localizable")
    return ""


def _def_cell(facts: ArgumentFacts) -> str:
    value = facts.value
    if value.def_rva is None:
        return "none"
    return _cell(f"{_hex(value.def_rva)}(+{value.def_dist})|{value.def_text}")


def argument_cells(facts: ArgumentFacts) -> dict[str, Any]:
    """The per argument cells of one position."""
    prefix = f"arg{facts.position}"
    return {
        f"{prefix}_source": f"{facts.source}:{facts.location}",
        f"{prefix}_raw": _cell(facts.value.raw_operand or facts.value.expr),
        f"{prefix}_def": _def_cell(facts),
        f"{prefix}_const": _const_cell(facts.value),
        f"{prefix}_addr": _addr_cell(facts.value),
        f"{prefix}_pseudo": facts.value.pseudo or "unnamed"
        if facts.klass == CLASS_A1
        else "",
        f"{prefix}_class": facts.klass,
        f"{prefix}_len": facts.length if facts.length is not None else "",
        f"{prefix}_reason": _cell(facts.reason),
        f"{prefix}_rw_pair": facts.rw_pair,
        f"{prefix}_alloc_write": facts.alloc_write,
        f"{prefix}_evidence": _cell(
            _join(
                [
                    facts.rw_evidence,
                    facts.alloc_evidence,
                    f"chain {' <- '.join(facts.value.chain)}" if facts.value.chain else "",
                ]
            )
        ),
    }


def _slots_cell(slots: Sequence[int]) -> str:
    if not slots:
        return ""
    head = ";".join(f"0x{slot:X}" for slot in slots[:MAX_REPORTED_SLOTS])
    extra = len(slots) - MAX_REPORTED_SLOTS
    return f"{len(slots)}:{head}" + (f";+{extra}" if extra > 0 else "")


def site_row(site: SiteFacts) -> dict[str, Any]:
    """The inventory row of one analysed candidate."""
    candidate = site.candidate
    window = site.window
    cfg = site.cfg
    row: dict[str, Any] = {
        "hit_index": candidate.hit_index,
        "rva_hex": _hex(candidate.rva),
        "va_hex": _hex(candidate.va),
        "raw_offset_hex": _hex(candidate.raw),
        "section_name": candidate.section,
        "insn_mnemonic": site.mnemonic,
        "insn_bytes_hex": SYSCALL_PATTERN.hex().upper() if site.mnemonic else "",
        "pdata_function_index": candidate.pdata_index,
        "pdata_function_start_rva_hex": _hex(candidate.function_begin),
        "pdata_function_end_rva_hex": _hex(candidate.function_end),
        "cfg_function_index": cfg.index if cfg is not None else "",
        "cfg_function_begin_rva_hex": _hex(cfg.begin) if cfg is not None else "",
        "cfg_function_end_rva_hex": _hex(cfg.end) if cfg is not None else "",
        "cfg_decode_status": cfg.decode_status if cfg is not None else "",
        "window_start_rva_hex": _hex(window.start_rva),
        "window_bytes": window.byte_length,
        "window_instruction_count": len(window.insns),
        "window_decode_status": site.decode_status,
        "window_stack_delta": window.stack_delta,
        "window_control_flow": window.control_flow(),
        "entry_spill": window.entry_spill_text,
        "stack_slots_detected": _slots_cell(site.extra_slots),
        "allocation_calls": _join(window.allocation_calls()),
        "site_signature": "+".join(facts.klass for facts in site.arguments),
        "rw_pair_arguments": sum(1 for facts in site.arguments if facts.rw_pair),
        "allocation_write_arguments": sum(
            1 for facts in site.arguments if facts.alloc_write
        ),
        "nt_service": NT_SERVICE_UNRESOLVED,
        "nt_service_status": NT_SERVICE_STATUS,
    }
    for facts in site.arguments:
        row.update(argument_cells(facts))
    return row


def build_rows(sites: Sequence[SiteFacts]) -> list[dict[str, Any]]:
    return [site_row(site) for site in sites]







def validate_rows(
    rows: Sequence[dict[str, Any]], expected_valid: int, window_bytes: int
) -> list[common.Check]:
    """Check every inventory row and return the check list of the phase."""
    checks: list[common.Check] = [
        common.Check("inventory_rows", expected_valid, len(rows), len(rows) == expected_valid),
        common.Check(
            "columns",
            len(CSV_COLUMNS),
            len(rows[0]) if rows else 0,
            bool(rows) and len(rows[0]) == len(CSV_COLUMNS),
        ),
    ]
    faults: Counter[str] = Counter()
    for row in rows:
        if row["nt_service"] != NT_SERVICE_UNRESOLVED:
            faults["nt_service_not_unresolved"] += 1
        if not 0 <= int(row["window_bytes"]) <= window_bytes:
            faults["window_bytes_out_of_bounds"] += 1
        if row["window_decode_status"] not in (
            DECODE_OK,
            DECODE_EMPTY,
            DECODE_MISMATCH,
            DECODE_UNREACHED,
        ):
            faults["window_decode_status_unknown"] += 1
        for facts in range(1, ARGUMENT_POSITIONS + 1):
            klass = row[f"arg{facts}_class"]
            if klass not in ARG_CLASSES:
                faults["class_out_of_domain"] += 1
            if not row[f"arg{facts}_reason"]:
                faults["reason_missing"] += 1
            if (klass == CLASS_A1) != bool(row[f"arg{facts}_pseudo"]):
                faults["pseudo_column_mismatch"] += 1
            if (klass == CLASS_A4) != (row[f"arg{facts}_len"] != ""):
                faults["length_column_mismatch"] += 1
            if klass == CLASS_A3_INOUT and not row[f"arg{facts}_rw_pair"]:
                faults["inout_without_pair"] += 1
            if not isinstance(row[f"arg{facts}_rw_pair"], bool):
                faults["rw_pair_not_boolean"] += 1
            if not isinstance(row[f"arg{facts}_alloc_write"], bool):
                faults["alloc_write_not_boolean"] += 1
    for name in (
        "nt_service_not_unresolved",
        "window_bytes_out_of_bounds",
        "window_decode_status_unknown",
        "class_out_of_domain",
        "reason_missing",
        "pseudo_column_mismatch",
        "length_column_mismatch",
        "inout_without_pair",
        "rw_pair_not_boolean",
        "alloc_write_not_boolean",
    ):
        checks.append(
            common.Check(
                f"rows_validated.{name}", 0, faults[name], faults[name] == 0
            )
        )
    return checks






CLASS_RULES: Final[tuple[tuple[str, str], ...]] = (
    (CLASS_A1, "resolved constant inside the pseudo handle window"),
    (CLASS_A3_INOUT, "resolved data address with an observed read/write pair in the window"),
    (CLASS_A3_OUT, "resolved data address without such a pair"),
    (CLASS_A4, "resolved constant of at most 1 MiB directly after a buffer position"),
    (CLASS_A2, "any other resolved non-negative constant literal"),
    (CLASS_A6, "value chain ends at an entry parameter of the owning function"),
    (CLASS_A5, "stack argument slot whose stored value is not resolved"),
    (CLASS_A7, "register argument the window does not reduce to a constant or address"),
    (CLASS_A8, "no definition in the window, or a definition not interpreted"),
)


def _sorted_counts(counter: Counter[str]) -> dict[str, int]:
    return {name: counter[name] for name in sorted(counter)}


def _histogram(values: Counter[int], limit: int = 16) -> dict[str, int]:
    keys = sorted(values)
    head = {str(key): values[key] for key in keys[:limit]}
    tail = sum(values[key] for key in keys[limit:])
    if tail:
        head[f">={keys[limit]}" if len(keys) > limit else "rest"] = tail
    return head


def class_census(
    sites: Sequence[SiteFacts], rows: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    """Class, signal and coverage census of the analysed arguments."""
    by_class: dict[str, dict[str, Any]] = {
        name: {
            "arguments": 0,
            "sites": set(),
            "positions": Counter(),
            "sources": Counter(),
            "reasons": Counter(),
            "pseudohandles": Counter(),
            "example_sites": [],
        }
        for name in ARG_CLASSES
    }
    signatures: Counter[str] = Counter()
    window_bytes: Counter[int] = Counter()
    window_insts: Counter[int] = Counter()
    window_delta: Counter[int] = Counter()
    slots: Counter[int] = Counter()
    slot_class: dict[int, Counter[str]] = {}
    alloc_symbols: Counter[str] = Counter()
    alloc_rva: list[tuple[int, str, int | None]] = []
    rw_sites: list[int] = []
    alloc_sites: list[int] = []
    for site, row in zip(sites, rows, strict=True):
        signatures[row["site_signature"]] += 1
        window_bytes[int(row["window_bytes"])] += 1
        window_insts[int(row["window_instruction_count"])] += 1
        window_delta[int(row["window_stack_delta"])] += 1
        for offset in site.extra_slots:
            slots[offset] += 1
        for facts in site.arguments:
            bucket = by_class[facts.klass]
            bucket["arguments"] += 1
            bucket["sites"].add(site.candidate.rva)
            bucket["positions"][facts.location] += 1
            bucket["sources"][facts.source] += 1
            bucket["reasons"][facts.reason] += 1
            if facts.klass == CLASS_A1:
                bucket["pseudohandles"][facts.value.pseudo or "unnamed"] += 1
            if facts.value.slot_disp is not None:
                bucket = slot_class.setdefault(facts.value.slot_disp, Counter())
                bucket[facts.klass] += 1
            if facts.alloc_symbol:
                alloc_symbols[facts.alloc_symbol] += 1
                alloc_rva.append((site.candidate.rva, facts.alloc_symbol, facts.alloc_rva))
            if facts.rw_pair and len(rw_sites) < MAX_EXAMPLES * 10:
                rw_sites.append(site.candidate.rva)
            if facts.alloc_write:
                alloc_sites.append(site.candidate.rva)
    classes: dict[str, Any] = {}
    for name in ARG_CLASSES:
        bucket = by_class[name]
        examples = sorted(bucket["sites"])[:MAX_EXAMPLES]
        classes[name] = {
            "rule": dict(CLASS_RULES).get(name, ""),
            "arguments": bucket["arguments"],
            "sites": len(bucket["sites"]),
            "by_position": _sorted_counts(bucket["positions"]),
            "by_source": _sorted_counts(bucket["sources"]),
            "by_reason": _sorted_counts(bucket["reasons"]),
            "pseudohandles": _sorted_counts(bucket["pseudohandles"]),
            "example_site_rva": [_hex(item) for item in examples],
        }
    return {
        "classes": classes,
        "class_signatures": _sorted_counts(signatures),
        "windows": {
            "byte_span": _histogram(window_bytes),
            "instruction_count": _histogram(window_insts),
            "stack_delta": _histogram(window_delta),
        },
        "stack_slots": {
            "written_offsets": {
                _hex(offset): slots[offset] for offset in sorted(slots)
            },
            "class_by_offset": {
                _hex(offset): _sorted_counts(counters)
                for offset, counters in sorted(slot_class.items())
            },
        },
        "allocation_origins": {
            "by_symbol": _sorted_counts(alloc_symbols),
            "example_sites": [
                {"rva": _hex(rva), "symbol": symbol, "call_rva": _hex(call) if call else ""}
                for rva, symbol, call in sorted(set(alloc_rva))[:MAX_EXAMPLES]
            ],
        },
        "signal_sites": {
            "rw_pair": {
                "arguments": sum(
                    1 for site in sites for facts in site.arguments if facts.rw_pair
                ),
                "sites": len(set(rw_sites)),
                "example_site_rva": [_hex(item) for item in sorted(set(rw_sites))[:MAX_EXAMPLES]],
            },
            "allocation_to_write": {
                "arguments": sum(
                    1 for site in sites for facts in site.arguments if facts.alloc_write
                ),
                "sites": len(set(alloc_sites)),
                "example_site_rva": [
                    _hex(item) for item in sorted(set(alloc_sites))[:MAX_EXAMPLES]
                ],
            },
        },
    }


def build_report(
    root: Path,
    script: Path,
    specimen: Path,
    inputs: PhaseInputs,
    window_bytes: int,
    sites: Sequence[SiteFacts],
    rows: Sequence[dict[str, Any]],
    tally: Counter[str],
    checks: Sequence[common.Check],
) -> dict[str, Any]:
    """The deterministic class report payload."""
    census = class_census(sites, rows)
    arguments = sum(len(site.arguments) for site in sites)
    return {
        "schema": SCHEMA_JSON,
        "phase": PHASE,
        "scope": (
            "static file parsing only; the specimen is never loaded, mapped for "
            "execution, patched or run; no Nt/Zw service name is decoded or "
            "resolved"
        ),
        "inventory": {
            "path": "reverse/evidence/syscall_arg_inventory.csv",
            "schema": SCHEMA_CSV,
            "rows": len(rows),
            "columns": len(CSV_COLUMNS),
            "argument_positions": [
                {
                    "position": position,
                    "source": "register" if offset is None else "stack_slot",
                    "location": label,
                }
                for position, offset, label in argument_positions()
            ],
        },
        "generated_by": {
            "script": script.relative_to(root).as_posix(),
            "sha256": common.sha256_file(script),
        },
        "specimen": {
            "path": specimen.relative_to(root).as_posix(),
            "size": specimen.stat().st_size,
            "sha256": common.sha256_file(specimen),
        },
        "inputs": {
            "syscall_candidates_raw.csv": {
                "sha256": inputs.digests["syscall_candidates_raw.csv"],
                "rows": inputs.raw_rows,
                "valid_candidate_rows": len(inputs.candidates),
            },
            "cfg_functions.csv": {
                "sha256": inputs.digests["cfg_functions.csv"],
                "rows": inputs.cfg_rows,
            },
            "xref_edges.csv": {
                "sha256": inputs.digests["xref_edges.csv"],
                "rows": inputs.xref_rows,
                "iat_call_sites": len(inputs.iat_calls),
            },
            "exception_directory_records": inputs.runtime_functions,
        },
        "parameters": {
            "window_bytes": window_bytes,
            "window_bytes_range": [WINDOW_BYTES_MIN, WINDOW_BYTES_MAX],
            "copy_chain_max_depth": COPY_CHAIN_MAX_DEPTH,
            "entry_spill_instructions": ENTRY_SPILL_INSNS,
            "entry_spill_probe_bytes": ENTRY_SPILL_PROBE_BYTES,
            "max_plausible_length": MAX_PLAUSIBLE_LENGTH,
            "stack_arg_base_disp": _hex(STACK_ARG_BASE_DISP),
            "csv_stack_slots": CSV_STACK_SLOTS,
            "argument_registers": [name for _, _, name in ARG_REGISTERS],
        },
        "method": {
            "precedence": [
                "nearest definite definition of the location in the window",
                "nearest conditional definition of the location in the window",
                "unresolved in the window",
            ],
            "boundaries": [
                f"{STALE_CALL}: a volatile definition before the last call of the window",
                f"{STALE_FLOW}: a definition before the last unconditional jump or return",
            ],
            "class_ladder": [
                {"rank": rank, "code": code, "rule": rule}
                for rank, (code, rule) in enumerate(CLASS_RULES, start=1)
            ],
        },
        "pseudo_handles": {
            "window": [_hex(PSEUDO_HANDLE_WINDOW[0]), _hex(PSEUDO_HANDLE_WINDOW[1])],
            "named": {
                _hex(value): name for value, name in sorted(PSEUDO_HANDLE_NAMES.items())
            },
        },
        "allocator_symbols": sorted(ALLOCATOR_SYMBOLS),
        "nt_service": {
            "status": NT_SERVICE_UNRESOLVED,
            "reason": (
                "the phase does not decode the service number in RAX at the "
                "candidate and does not map any number to a service name"
            ),
            "rows": len(rows),
            "distinct_values": sorted({row["nt_service"] for row in rows}),
        },
        "totals": {
            "sites": len(sites),
            "arguments_enumerated": arguments,
            "owning_functions": len({site.candidate.function_begin for site in sites}),
            "sweep_reached": tally["reached"],
            "cfg_joined": tally["cfg_joined"],
            "cfg_bounds_match": tally["cfg_bounds_match"],
        },
        "decode_status": _sorted_counts(
            Counter({status: tally[f"decode:{status}"] for status in sorted(
                {row["window_decode_status"] for row in rows}
            )})
        ),
        "census": census["classes"],
        "class_signatures": census["class_signatures"],
        "windows": census["windows"],
        "stack_slots": census["stack_slots"],
        "allocation_origins": census["allocation_origins"],
        "signal_sites": census["signal_sites"],
        "validation": {
            "rows_validated": len(rows),
            "checks": [check.as_row() for check in checks],
        },
        "limitations": list(LIMITATIONS),
    }







def read_stored_rows(path: Path) -> list[dict[str, str]]:
    """Read the stored inventory back, insisting on the exact column order."""
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != CSV_COLUMNS:
            raise ValueError(f"unexpected csv header: {reader.fieldnames}")
        return [dict(row) for row in reader]


def compare_stored(path: Path, rows: Sequence[dict[str, Any]]) -> int:
    """Compare the stored csv with the regenerated rows, cell by cell."""
    stored = read_stored_rows(path)
    fresh = [{name: common.scalar_text(row.get(name)) for name in CSV_COLUMNS} for row in rows]
    if stored == fresh:
        print(f"csv       {path.name} matches the regenerated rows cell by cell")
        return 0
    print(f"csv       {path.name} differs from the regenerated rows")
    for index in range(max(len(stored), len(fresh))):
        left = stored[index] if index < len(stored) else {}
        right = fresh[index] if index < len(fresh) else {}
        if left == right:
            continue
        print(f"FAIL row {index}:")
        for name in CSV_COLUMNS:
            if left.get(name) != right.get(name):
                print(f"  {name}\n    stored {left.get(name)!r}\n    fresh  {right.get(name)!r}")
        if index >= 20:
            print(f"FAIL ... further differing rows not listed")
            break
    return 1


def _display(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def report(
    root: Path,
    inputs: PhaseInputs,
    window_bytes: int,
    sites: Sequence[SiteFacts],
    rows: Sequence[dict[str, Any]],
    tally: Counter[str],
    written_csv: Path | None,
    written_json: Path | None,
    check_only: bool,
) -> None:
    print(
        f"phase     {PHASE} static syscall argument inventory, no service name decoding"
    )
    print(
        f"inputs    candidates={inputs.raw_rows} valid={len(inputs.candidates)} "
        f"cfg={inputs.cfg_rows} xref={inputs.xref_rows} "
        f"pdata={inputs.runtime_functions}"
    )
    print(
        f"window    bytes<={window_bytes} arguments={ARGUMENT_POSITIONS} "
        f"positions={'+'.join(label for _, _, label in argument_positions())}"
    )
    print(
        f"decode    {DECODE_OK}={tally[f'decode:{DECODE_OK}']} "
        f"{DECODE_UNREACHED}={tally[f'decode:{DECODE_UNREACHED}']} "
        f"{DECODE_MISMATCH}={tally[f'decode:{DECODE_MISMATCH}']} "
        f"sweep_reached={tally['reached']}"
    )
    print(
        f"join      cfg_joined={tally['cfg_joined']} "
        f"cfg_bounds_match={tally['cfg_bounds_match']} "
        f"entry_spill_parameters={tally['entry_spill_parameters']}"
    )
    for name in ARG_CLASSES:
        print(f"class     {name:20s} {tally[f'class:{name}']}")
    print(
        f"signals   rw_pair={tally['rw_pair']} alloc_origin={tally['alloc_origin']} "
        f"alloc_write={tally['alloc_write']}"
    )
    print(
        f"service   nt_service={NT_SERVICE_UNRESOLVED} on all {len(rows)} rows "
        f"({NT_SERVICE_STATUS})"
    )
    for label, path in (("csv", written_csv), ("json", written_json)):
        if path is None:
            note = (
                "check-only, nothing written"
                if check_only
                else "not written, an invariant failed"
            )
            print(f"{label:9s} {note}")
        else:
            print(f"{label:9s} {_display(root, path)}")


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    evidence = root / "reverse" / "evidence"
    parser = argparse.ArgumentParser(
        description=(
            "Static syscall argument inventory: precedence resolved R10/RDX/R8/R9 "
            "and argument stack slots from the 20..40 byte window in front of every "
            "valid 0F 05 candidate, with class, length, pseudo handle, localisable "
            "buffer, read/write pair and allocation to write signals. No Nt service "
            "identification, no runtime observation."
        )
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument(
        "--candidates", type=Path, default=evidence / "syscall_candidates_raw.csv"
    )
    parser.add_argument("--cfg", type=Path, default=evidence / "cfg_functions.csv")
    parser.add_argument("--xref", type=Path, default=evidence / "xref_edges.csv")
    parser.add_argument("--out", type=Path, default=evidence / "syscall_arg_inventory.csv")
    parser.add_argument(
        "--classes", type=Path, default=evidence / "syscall_arg_classes.json"
    )
    parser.add_argument(
        "--window-bytes",
        type=int,
        default=WINDOW_BYTES,
        help=f"analysis window in bytes, {WINDOW_BYTES_MIN}..{WINDOW_BYTES_MAX}",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="compare the stored csv with the regenerated rows instead of writing it",
    )
    parser.add_argument("--expect-raw-hits", type=int, default=EXPECTED_RAW_HITS)
    parser.add_argument(
        "--expect-valid", type=int, default=EXPECTED_VALID_CANDIDATES
    )
    parser.add_argument(
        "--expect-cfg-functions",
        type=int,
        default=EXPECTED_RUNTIME_FUNCTIONS,
    )
    parser.add_argument("--expect-xref-edges", type=int, default=EXPECTED_XREF_EDGES)
    args = parser.parse_args(argv)

    if not WINDOW_BYTES_MIN <= args.window_bytes <= WINDOW_BYTES_MAX:
        parser.error(
            f"--window-bytes must be between {WINDOW_BYTES_MIN} and {WINDOW_BYTES_MAX}"
        )
    specimen = args.specimen.resolve()
    if not specimen.is_file():
        print(f"ERROR specimen {specimen} is missing")
        return 2

    image = Image(specimen)
    try:
        try:
            inputs = load_inputs(image, args.candidates, args.cfg, args.xref)
        except (OSError, ValueError, KeyError) as error:
            print(f"ERROR {error}")
            return 2
        sites, tally = analyse(image, inputs, args.window_bytes)
        rows = build_rows(sites)
    finally:
        image.close()

    checks = validate_rows(rows, args.expect_valid, args.window_bytes)
    checks += [
        common.Check(
            "raw_hit_rows",
            args.expect_raw_hits,
            inputs.raw_rows,
            inputs.raw_rows == args.expect_raw_hits,
        ),
        common.Check(
            "valid_candidate_rows",
            args.expect_valid,
            len(inputs.candidates),
            len(inputs.candidates) == args.expect_valid,
        ),
        common.Check(
            "cfg_function_rows",
            args.expect_cfg_functions,
            inputs.cfg_rows,
            inputs.cfg_rows == args.expect_cfg_functions,
        ),
        common.Check(
            "runtime_functions",
            args.expect_cfg_functions,
            inputs.runtime_functions,
            inputs.runtime_functions == args.expect_cfg_functions,
        ),
        common.Check(
            "xref_edge_rows",
            args.expect_xref_edges,
            inputs.xref_rows,
            inputs.xref_rows == args.expect_xref_edges,
        ),
        common.Check(
            "sweep_reached_every_site",
            len(sites),
            tally["reached"],
            tally["reached"] == len(sites),
        ),
        common.Check(
            "cfg_bounds_match_every_site",
            len(sites),
            tally["cfg_bounds_match"],
            tally["cfg_bounds_match"] == len(sites),
        ),
    ]
    failed = [check for check in checks if not check.ok]
    payload = build_report(
        root, script, specimen, inputs, args.window_bytes, sites, rows, tally, checks
    )
    payload["validation"]["checks"].append(
        {
            "check": "all_checks_passed",
            "expected": "true",
            "actual": "true" if not failed else "false",
            "ok": "false" if failed else "true",
        }
    )

    written_csv: Path | None = None
    written_json: Path | None = None
    status = 0
    if args.check_only:
        try:
            status = compare_stored(args.out, rows)
        except (OSError, ValueError) as error:
            print(f"ERROR stored csv unreadable: {error}")
            status = 1
    elif failed:
        status = 1
    else:
        common.write_json(args.classes, payload)
        common.write_csv(args.out, rows, CSV_COLUMNS)
        written_csv = args.out
        written_json = args.classes

    report(
        root,
        inputs,
        args.window_bytes,
        sites,
        rows,
        tally,
        written_csv,
        written_json,
        args.check_only,
    )
    for check in failed:
        print(
            f"FAIL {check.name}: expected={common.scalar_text(check.expected)} "
            f"actual={common.scalar_text(check.actual)}"
        )
    print(f"checks    {len(checks) - len(failed)}/{len(checks)} passed")
    if not args.check_only:
        print(
            f"nt_service {NT_SERVICE_UNRESOLVED} on {len(rows)} rows, "
            f"status {NT_SERVICE_STATUS}"
        )
    return 1 if failed or status else 0


if __name__ == "__main__":
    raise SystemExit(main())
