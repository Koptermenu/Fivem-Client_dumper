"""Static P0/S11 patch-mechanism audit for the reverse/adhesive.dll specimen.

Scope
-----
Audits the runtime code-write mechanisms of the specimen and emits a
mechanism-level evidence table.  The audited subjects are the Toolhelp stub
installer, its restore counterpart, and the constant-fill helper.  The
whole-image call / thunk / global-function-pointer writer inventory, the
unaligned save+restore symmetry, the protection and instruction-cache handling,
and the activation conditions of every mechanism are derived from one sweep.

Method
------
Static file parsing only.  pefile resolves the PE layout, the exception
directory supplies the exact function extents, and a single linear capstone
sweep over every RUNTIME_FUNCTION body collects the inventory.  The specimen is
never loaded as an image and never executed.  No byte-level encoding step, patch
recipe, or bypass procedure is produced or recorded: the emitted rows describe
mechanism structure, target resolution and control-flow predicates only.

The sweep is linear in the size of the code, so a full run takes minutes on the
53 MB specimen; the emitted evidence does not depend on how long it takes.

Determinism
-----------
The specimen digest is pinned, every collection is ordered before it is
rendered, and the CSV is written through common.write_csv (UTF-8, no BOM, LF,
fixed column order, no timestamps).  A changed specimen fails the baseline
checks instead of silently reusing stale findings, and --verify recomputes the
table and diffs it against the stored file.

Emits:
  reverse/evidence/patch_mechanisms_helpers.csv
"""

from __future__ import annotations

import argparse
import bisect
import csv
import io
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Iterator, Mapping, Sequence

import capstone
import pefile

sys.path.insert(0, str(Path(__file__).resolve().parent))

import common  # noqa: E402  (the path bootstrap has to run before the import)

SCHEMA: Final[str] = "adhesive-dumper.patch-mechanisms/1"

SPECIMEN_SHA256: Final[str] = "91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e"
EXPECTED_RUNTIME_FUNCTIONS: Final[int] = common.EXPECTED_RUNTIME_FUNCTIONS
MACHINE_AMD64: Final[int] = 0x8664

CSV_FIELDS: Final[tuple[str, ...]] = (
    "mechanism",
    "RVA",
    "fn",
    "target_kind",
    "target_expr",
    "caller_rvas",
    "activation_cond",
    "status",
    "confidence",
)

INSTALLER_RVA: Final[int] = 0xC8CE70
RESTORE_RVA: Final[int] = 0xC8F470
FILL_HELPER_RVA: Final[int] = 0x1754520
SUBJECT_RVAS: Final[tuple[int, ...]] = (INSTALLER_RVA, RESTORE_RVA, FILL_HELPER_RVA)
SUBJECT_PREFIXES: Final[dict[int, str]] = {
    INSTALLER_RVA: "toolhelp_install",
    RESTORE_RVA: "toolhelp_restore",
    FILL_HELPER_RVA: "fill_helper",
}

RECORD_DRIVEN_PATCHER_RVA: Final[int] = 0x1E270
RECORD_DRIVER_RVA: Final[int] = 0x1E360
RECORD_REGISTRAR_RVA: Final[int] = 0x1DCF0
RECORD_TABLE_WALKER_RVA: Final[int] = 0x1DFF0
NAME_KEYED_SLOT_REWRITER_RVA: Final[int] = 0x29213D0
LOADER_PROTECT_HELPER_RVA: Final[int] = 0x2BEB88C
COMPARATOR_RVAS: Final[tuple[int, ...]] = (
    RECORD_DRIVEN_PATCHER_RVA,
    RECORD_DRIVER_RVA,
    RECORD_REGISTRAR_RVA,
    RECORD_TABLE_WALKER_RVA,
    NAME_KEYED_SLOT_REWRITER_RVA,
    LOADER_PROTECT_HELPER_RVA,
)
SHARED_INIT_HELPERS: Final[tuple[int, ...]] = (0x2AB27B0, 0x2AB2864, 0x2AB3500)

EXPORT_CACHE_GLOBAL_RVA: Final[int] = 0x317E398
INSTALL_GUARD_GLOBAL_RVA: Final[int] = 0x317E3A0
RECORD_TABLE_GLOBAL_RVA: Final[int] = 0x30D44F8
RELOCATION_BASE_GLOBAL_RVA: Final[int] = 0x3227D40
STACK_GUARD_GLOBAL_RVA: Final[int] = 0x30B9140

WATCHED_GLOBAL_RVAS: Final[frozenset[int]] = frozenset(
    {
        EXPORT_CACHE_GLOBAL_RVA,
        INSTALL_GUARD_GLOBAL_RVA,
        RECORD_TABLE_GLOBAL_RVA,
        RELOCATION_BASE_GLOBAL_RVA,
        STACK_GUARD_GLOBAL_RVA,
    }
)

WATCHED_APIS: Final[frozenset[str]] = frozenset(
    {
        "VirtualProtect",
        "FlushInstructionCache",
        "GetProcAddress",
        "GetModuleHandleA",
        "GetModuleHandleW",
        "GetModuleHandleExW",
        "GetCurrentProcess",
    }
)

PROTECT_API: Final[str] = "VirtualProtect"
FLUSH_API: Final[str] = "FlushInstructionCache"
RESOLVE_API: Final[str] = "GetProcAddress"

ARGUMENT_REGISTERS: Final[tuple[str, ...]] = ("rcx", "rdx", "r8", "r9")
ARGUMENT_INCOMING: Final[str] = "incoming"

TARGET_KINDS: Final[frozenset[str]] = frozenset(
    {
        "import_iat_slot",
        "resolved_export",
        "export_prologue",
        "internal_rva",
        "global_rw_data",
        "global_ro_data",
        "caller_argument",
        "record_table",
        "table_slot",
        "teb_guard",
        "cross_function_pair",
        "whole_image_set",
        "absent_mechanism",
    }
)

STATUS_OBSERVED: Final[str] = "OBSERVED"
STATUS_ABSENT: Final[str] = "ABSENT"
STATUS_ASYMMETRIC: Final[str] = "ASYMMETRIC"
STATUS_UNRESOLVED: Final[str] = "UNRESOLVED"

CONFIDENCE_HIGH: Final[str] = "HIGH"
CONFIDENCE_MEDIUM: Final[str] = "MEDIUM"
CONFIDENCE_LOW: Final[str] = "LOW"

UNALIGNED_COPY_WIDTH: Final[int] = 16
NARROW_STORE_WIDTHS: Final[tuple[int, ...]] = (1, 2, 4)
NARROW_STORE_RUN_MINIMUM: Final[int] = 3
NARROW_STORE_RUN_WINDOW: Final[int] = 64
RETURN_TEST_WINDOW: Final[int] = 2
FILL_LOOP_WINDOW: Final[int] = 48

X86_OP_IMM: Final[int] = capstone.x86.X86_OP_IMM
X86_OP_REG: Final[int] = capstone.x86.X86_OP_REG
X86_OP_MEM: Final[int] = capstone.x86.X86_OP_MEM
X86_REG_RIP: Final[int] = capstone.x86.X86_REG_RIP

CONDITIONAL_BRANCHES: Final[frozenset[str]] = frozenset(
    {
        "ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle",
        "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl",
        "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js",
        "jz", "loop", "loope", "loopne",
    }
)

COPY_MNEMONICS: Final[frozenset[str]] = frozenset({"movups", "movdqu", "movaps", "movdqa"})
FILL_STORE_SIZES: Final[frozenset[int]] = frozenset({1})
STACK_BASES: Final[frozenset[str]] = frozenset({"rsp", "rbp"})
# Microsoft x64: RAX, RCX, RDX and R8-R11 are volatile; RBX, RBP, RDI, RSI,
# RSP and R12-R15 are non-volatile.
VOLATILE_REGISTERS: Final[tuple[str, ...]] = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")
CANONICAL_REGISTERS: Final[Mapping[str, str]] = {
    "al": "rax", "ah": "rax", "ax": "rax", "eax": "rax", "rax": "rax",
    "bl": "rbx", "bh": "rbx", "bx": "rbx", "ebx": "rbx", "rbx": "rbx",
    "cl": "rcx", "ch": "rcx", "cx": "rcx", "ecx": "rcx", "rcx": "rcx",
    "dl": "rdx", "dh": "rdx", "dx": "rdx", "edx": "rdx", "rdx": "rdx",
    "sil": "rsi", "si": "rsi", "esi": "rsi", "rsi": "rsi",
    "dil": "rdi", "di": "rdi", "edi": "rdi", "rdi": "rdi",
    "spl": "rsp", "sp": "rsp", "esp": "rsp", "rsp": "rsp",
    "bpl": "rbp", "bp": "rbp", "ebp": "rbp", "rbp": "rbp",
    "r8b": "r8", "r8w": "r8", "r8d": "r8", "r8": "r8",
    "r9b": "r9", "r9w": "r9", "r9d": "r9", "r9": "r9",
    "r10b": "r10", "r10w": "r10", "r10d": "r10", "r10": "r10",
    "r11b": "r11", "r11w": "r11", "r11d": "r11", "r11": "r11",
    "r12b": "r12", "r12w": "r12", "r12d": "r12", "r12": "r12",
    "r13b": "r13", "r13w": "r13", "r13d": "r13", "r13": "r13",
    "r14b": "r14", "r14w": "r14", "r14d": "r14", "r14": "r14",
    "r15b": "r15", "r15w": "r15", "r15d": "r15", "r15": "r15",
}
ORIGIN_HOP_LIMIT: Final[int] = 6
GUARD_TEXT_LIMIT: Final[int] = 4
# Register writes whose symbolic effect the argument tracker models explicitly.
# Any other instruction that writes a tracked register invalidates its entry.
_MODELLED_WRITES: Final[Mapping[str, frozenset[str]]] = {
    "call": frozenset(VOLATILE_REGISTERS),
    "jmp": frozenset(),
    "lea": frozenset(ARGUMENT_REGISTERS + ("rax",)),
    "mov": frozenset(ARGUMENT_REGISTERS + ("rax",)),
    "movabs": frozenset(ARGUMENT_REGISTERS + ("rax",)),
    "xor": frozenset(ARGUMENT_REGISTERS + ("rax",)),
}
# Instructions that can destroy a tracked register value in place; only these
# need an invalidation scan, which keeps the per-instruction cost bounded.
_IN_PLACE_WRITES: Final[frozenset[str]] = frozenset(
    {
        "add", "sub", "and", "or", "inc", "dec", "shl", "shr", "sar",
        "imul", "neg", "not", "xchg", "pop", "movzx", "movsx", "movsxd", "bts", "btr",
    }
)
_IN_PLACE_PREFIXES: Final[tuple[str, ...]] = ("cmov", "set")


def _invalidates_tracked(mnemonic: str) -> bool:
    return mnemonic in _IN_PLACE_WRITES or mnemonic.startswith(_IN_PLACE_PREFIXES)


@dataclass(frozen=True, slots=True)
class Guard:
    """A conditional predicate that gates a block inside a function."""

    rva: int
    compare_rva: int
    mnemonic: str
    global_rva: int | None
    width: int | None
    immediate: int | None
    register: str | None
    memory_text: str
    branch_rva: int
    branch_mnemonic: str
    branch_target: int
    forward: bool


@dataclass(frozen=True, slots=True)
class CallSite:
    """A resolved indirect call/jump or a direct internal call."""

    rva: int
    mnemonic: str
    api: str
    slot_rva: int
    internal_rva: int | None
    arguments: tuple[str, ...]
    return_tested: bool


@dataclass(frozen=True, slots=True)
class SlotWrite:
    """A register-sized or wider store of a register into memory."""

    rva: int
    bits: int
    base_register: str
    origin: str
    rip_target: int | None


@dataclass(frozen=True, slots=True)
class FillLoop:
    """A back-branching loop whose body stores a constant byte to memory."""

    branch_rva: int
    head_rva: int
    store_rva: int
    base_register: str
    counter_register: str | None


@dataclass(frozen=True, slots=True)
class FunctionFacts:
    """Everything the row builders need about one function body."""

    begin: int
    end: int
    calls: tuple[CallSite, ...]
    guards: tuple[Guard, ...]
    conditional_moves: tuple[tuple[int, int, int, str], ...]
    unaligned_copies: tuple[tuple[int, str, str], ...]
    narrow_store_runs: tuple[tuple[int, int, str], ...]
    slot_writes: tuple[SlotWrite, ...]
    fill_loops: tuple[FillLoop, ...]
    state_updates: tuple[tuple[int, str, int, str], ...]
    bitmask_predicates: tuple[tuple[int, str, int, str], ...]
    derived_constants: tuple[tuple[int, str, int], ...]
    global_refs: tuple[tuple[int, int, int, str], ...]


@dataclass(slots=True)
class Inventory:
    """Whole-image results of the single linear sweep."""

    runtime_function_count: int = 0
    decoded_function_count: int = 0
    swept_instruction_count: int = 0
    undecoded_bytes: int = 0
    api_call_sites: dict[str, tuple[int, ...]] = field(default_factory=dict)
    api_tail_thunks: dict[str, tuple[int, ...]] = field(default_factory=dict)
    protect_calls: tuple[CallSite, ...] = ()
    protect_thunks: tuple[CallSite, ...] = ()
    flush_calls: tuple[CallSite, ...] = ()
    protect_functions: tuple[tuple[int, int], ...] = ()
    protect_with_unaligned_copy: tuple[tuple[int, int], ...] = ()
    direct_callers: dict[int, tuple[int, ...]] = field(default_factory=dict)
    literal_occurrences: dict[int, tuple[int, int, int]] = field(default_factory=dict)
    watched_global_refs: dict[int, tuple[tuple[int, int, str], ...]] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# specimen access
# --------------------------------------------------------------------------- #


def _count_occurrences(blob: bytes, needle: bytes) -> int:
    total = 0
    offset = blob.find(needle)
    while offset >= 0:
        total += 1
        offset = blob.find(needle, offset + 1)
    return total


class Specimen:
    """Static reader over the specimen. Owns the pefile handle and the engine."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.image_base = 0
        self.pe: pefile.PE | None = None
        self._iat: dict[int, str] = {}
        self._functions: tuple[tuple[int, int, int], ...] = ()
        self._begins: tuple[int, ...] = ()
        self._image: bytes | None = None
        self._engine: capstone.Cs | None = None
        self._open()

    def _open(self) -> None:
        self.pe = common.load_pe(self.path)
        self.image_base = int(self.pe.OPTIONAL_HEADER.ImageBase)
        for descriptor in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
            module = descriptor.dll.decode("ascii", errors="replace")
            for entry in descriptor.imports:
                symbol = entry.name.decode("ascii", errors="replace") if entry.name else f"ord{entry.ordinal}"
                self._iat.setdefault(int(entry.address) - self.image_base, f"{module}!{symbol}")
        directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[common.EXCEPTION_DIRECTORY_INDEX]
        self._functions = tuple(
            struct.iter_unpack("<III", common.read_rva(self.pe, int(directory.VirtualAddress), int(directory.Size)))
        )
        self._begins = tuple(record[0] for record in self._functions)
        engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        engine.detail = True
        engine.skipdata = True
        self._engine = engine

    def close(self) -> None:
        if self.pe is not None:
            self.pe.close()
            self.pe = None

    def __enter__(self) -> Specimen:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def function_count(self) -> int:
        return len(self._functions)

    @property
    def machine(self) -> int:
        return int(self.pe.FILE_HEADER.Machine) if self.pe is not None else -1

    def functions(self) -> tuple[tuple[int, int, int], ...]:
        return self._functions

    def function_at(self, rva: int) -> tuple[int, int, int] | None:
        index = bisect.bisect_right(self._begins, rva) - 1
        if index < 0:
            return None
        begin, end, unwind = self._functions[index]
        return (begin, end, unwind) if begin <= rva < end else None

    def decode(self, begin: int, end: int) -> Iterator[capstone.CsInsn]:
        assert self.pe is not None and self._engine is not None
        code = common.read_rva(self.pe, begin, end - begin)
        yield from self._engine.disasm(code, self.image_base + begin)

    def decoded(self, begin: int, end: int) -> list[capstone.CsInsn]:
        return [insn for insn in self.decode(begin, end) if not _is_skipdata(insn)]

    def span_label(self, begin: int, end: int) -> str:
        return f"{common.hexs(begin)}-{common.hexs(end)}"

    def function_label(self, rva: int) -> str:
        record = self.function_at(rva)
        return "unmapped" if record is None else self.span_label(record[0], record[1])

    def image_bytes(self) -> bytes:
        if self._image is None:
            self._image = self.path.read_bytes()
        return self._image

    def api_name(self, slot_rva: int) -> str | None:
        return self._iat.get(slot_rva)

    def cstring(self, rva: int, limit: int = 96) -> str | None:
        if self.pe is None or rva < 0:
            return None
        try:
            blob = common.read_rva(self.pe, rva, limit)
        except Exception:
            return None
        end = blob.find(b"\x00")
        if end <= 0:
            return None
        try:
            text = blob[:end].decode("ascii")
        except UnicodeDecodeError:
            return None
        return text if all(32 <= ord(character) < 127 for character in text) else None

    def section_label(self, rva: int) -> str:
        if self.pe is None:
            return "unmapped"
        section = common.section_for_rva(self.pe, rva)
        if section is not None:
            return section.name
        for candidate in common.sections(self.pe):
            if candidate.virtual_address <= rva < candidate.virtual_end:
                return f"{candidate.name}:uninitialised-tail"
        return "unmapped"

    def section_writable(self, rva: int) -> bool:
        if self.pe is None:
            return False
        for section in common.sections(self.pe):
            if section.contains_rva_in_raw(rva) or section.virtual_address <= rva < section.virtual_end:
                return bool(section.characteristics & 0x80000000)
        return False

    def literal_occurrences(self, rva: int) -> tuple[int, int, int]:
        """Count 4-byte RVA and 8-byte VA encodings of an address in the file."""
        blob = self.image_bytes()
        packed_rva = struct.pack("<I", rva)
        pdata_raw = None
        pdata_size = 0
        if self.pe is not None:
            directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[common.EXCEPTION_DIRECTORY_INDEX]
            pdata_raw = common.rva_to_raw(self.pe, int(directory.VirtualAddress))
            pdata_size = int(directory.Size)
        rva_hits = 0
        in_pdata = 0
        offset = blob.find(packed_rva)
        while offset >= 0:
            rva_hits += 1
            if pdata_raw is not None and pdata_raw <= offset < pdata_raw + pdata_size:
                in_pdata += 1
            offset = blob.find(packed_rva, offset + 1)
        va_hits = _count_occurrences(blob, struct.pack("<Q", self.image_base + rva))
        return rva_hits, va_hits, in_pdata


# --------------------------------------------------------------------------- #
# instruction classification
# --------------------------------------------------------------------------- #


def _is_skipdata(insn: capstone.CsInsn) -> bool:
    try:
        insn.operands
    except capstone.CsError:
        return True
    return False


def _rva(insn: capstone.CsInsn, image_base: int) -> int:
    return insn.address - image_base


def _canonical(name: str) -> str:
    """Map a sub-register spelling to its 64-bit name, leaving unknowns intact."""
    return CANONICAL_REGISTERS.get(name, name)


def _reg(insn: capstone.CsInsn, index: int) -> str:
    return _canonical(insn.reg_name(insn.operands[index].reg))


def _mem_base(insn: capstone.CsInsn, operand_index: int) -> str:
    operand = insn.operands[operand_index]
    return _canonical(insn.reg_name(operand.mem.base)) if operand.mem.base else ""


def _writes_register(insn: capstone.CsInsn, register: str) -> bool:
    """True when the instruction is a definition of the given canonical register."""
    if insn.mnemonic == "call":
        return register in VOLATILE_REGISTERS
    operands = insn.operands
    if not operands:
        return False
    if insn.mnemonic.startswith("cmov") or insn.mnemonic.startswith("set"):
        return operands[0].type == X86_OP_REG and _reg(insn, 0) == register
    if operands[0].type != X86_OP_REG:
        return False
    if insn.mnemonic in (
        "mov", "movabs", "movzx", "movsx", "movsxd", "lea", "xor", "pop",
        "and", "or", "add", "sub", "inc", "dec", "shl", "shr", "sar", "imul", "neg", "not",
    ):
        return _reg(insn, 0) == register
    return False


def _rip_slot(insn: capstone.CsInsn, image_base: int) -> int | None:
    for operand in insn.operands:
        if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
            return _rva(insn, image_base) + insn.size + operand.mem.disp
    return None


def _rip_targets(insn: capstone.CsInsn, image_base: int) -> tuple[tuple[int, int], ...]:
    rva = _rva(insn, image_base)
    return tuple(
        (rva + insn.size + operand.mem.disp, operand.size)
        for operand in insn.operands
        if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP
    )


def _return_tested(insns: Sequence[capstone.CsInsn], index: int) -> bool:
    """True when the return register is compared immediately after a call.

    The window is deliberately two instructions: a compiler-tested return value
    is compared in place, so a comparison further down the basic block cannot be
    attributed to the call result.
    """
    for offset in range(index + 1, min(index + 1 + RETURN_TEST_WINDOW, len(insns))):
        probe = insns[offset]
        if probe.mnemonic not in ("test", "cmp") or len(probe.operands) != 2:
            continue
        first, second = probe.operands
        if first.type != X86_OP_REG or _reg(probe, 0) != "rax":
            continue
        if probe.mnemonic == "cmp" and second.type == X86_OP_IMM and second.imm != 0:
            continue
        return True
    return False


def _argument_state(spec: Specimen, insns: Sequence[capstone.CsInsn]) -> dict[int, dict[str, str]]:
    """Track symbolic register contents and snapshot them at every call."""
    state: dict[str, str] = {}
    snapshots: dict[int, dict[str, str]] = {}
    for insn in insns:
        operands = insn.operands
        rva = _rva(insn, spec.image_base)
        mnemonic = insn.mnemonic
        if _invalidates_tracked(mnemonic):
            modelled = _MODELLED_WRITES.get(mnemonic, frozenset())
            for register in [name for name in state if name not in modelled and _writes_register(insn, name)]:
                state.pop(register)
        if mnemonic == "jmp":
            snapshots[rva] = dict(state)
            continue
        if mnemonic == "call":
            snapshots[rva] = dict(state)
            slot = _rip_slot(insn, spec.image_base)
            if slot is not None:
                name = spec.api_name(slot)
                if name is not None:
                    state["rax"] = f"api_return:{name}"
            elif operands and operands[0].type == X86_OP_IMM:
                state["rax"] = f"internal_return:{common.hexs(operands[0].imm - spec.image_base)}"
            for register in ("rcx", "rdx", "r8", "r9", "r10", "r11"):
                state.pop(register, None)
            continue
        if mnemonic == "lea" and operands[0].type == X86_OP_REG:
            slot = _rip_slot(insn, spec.image_base)
            if slot is not None:
                target = rva + insn.size + operands[1].mem.disp
                kind = "rip_string" if spec.cstring(target) is not None else "rip_data"
                state[_reg(insn, 0)] = f"{kind}:{common.hexs(target)}"
            elif _mem_base(insn, 1) in STACK_BASES:
                state[_reg(insn, 0)] = f"stack_addr:{common.hexs(operands[1].mem.disp)}"
            else:
                state[_reg(insn, 0)] = f"address:{insn.op_str}"
            continue
        if mnemonic in ("mov", "movabs") and len(operands) == 2:
            destination, source = operands
            if destination.type == X86_OP_REG and source.type == X86_OP_REG:
                state[_reg(insn, 0)] = state.get(_reg(insn, 1), f"register:{_reg(insn, 1)}")
            elif destination.type == X86_OP_REG and source.type == X86_OP_IMM:
                state[_reg(insn, 0)] = f"immediate:{common.hexs(source.imm)}"
            elif destination.type == X86_OP_REG and source.type == X86_OP_MEM:
                if source.mem.base == X86_REG_RIP:
                    target = rva + insn.size + source.mem.disp
                    kind = "rip_string" if spec.cstring(target) is not None else "rip_data"
                    state[_reg(insn, 0)] = f"{kind}:{common.hexs(target)}"
                elif _mem_base(insn, 1) in STACK_BASES:
                    state[_reg(insn, 0)] = f"stack_read:{common.hexs(source.mem.disp)}"
                else:
                    state[_reg(insn, 0)] = f"memory:{insn.op_str}"
            continue
        if mnemonic == "xor" and len(operands) == 2:
            if operands[0].type == X86_OP_REG and _reg(insn, 0) == _reg(insn, 1):
                state[_reg(insn, 0)] = "zero"
    return snapshots


def _argument_shape(spec: Specimen, insns: Sequence[capstone.CsInsn], index: int) -> tuple[str, ...]:
    """Symbolic values of the four integer argument registers at one call site.

    A register with no observed definition in the decoded body is reported as
    ``incoming``: the value is whatever the caller supplied.
    """
    snapshots = _argument_state(spec, insns)
    rva = _rva(insns[index], spec.image_base)
    state = snapshots.get(rva, {})
    return tuple(state.get(register, ARGUMENT_INCOMING) for register in ARGUMENT_REGISTERS)


def _argument_text(site: CallSite) -> str:
    return "; ".join(
        f"{register}={value}" for register, value in zip(ARGUMENT_REGISTERS, site.arguments)
    )


def _call_sites(spec: Specimen, insns: Sequence[capstone.CsInsn]) -> tuple[CallSite, ...]:
    sites: list[CallSite] = []
    for index, insn in enumerate(insns):
        if insn.mnemonic not in ("call", "jmp"):
            continue
        rva = _rva(insn, spec.image_base)
        slot = _rip_slot(insn, spec.image_base)
        api = spec.api_name(slot) if slot is not None else None
        internal = None
        if api is None and insn.operands and insn.operands[0].type == X86_OP_IMM:
            internal = insn.operands[0].imm - spec.image_base
        if api is None and internal is None:
            continue
        if api is not None and _symbol(api) not in WATCHED_APIS:
            continue
        sites.append(
            CallSite(
                rva=rva,
                mnemonic=insn.mnemonic,
                api=api or "",
                slot_rva=slot if slot is not None else -1,
                internal_rva=internal,
                arguments=_argument_shape(spec, insns, index),
                return_tested=_return_tested(insns, index) if insn.mnemonic == "call" else False,
            )
        )
    return tuple(sites)


def _symbol(name: str) -> str:
    return name.rsplit("!", 1)[-1] if "!" in name else name


def _guards(spec: Specimen, insns: Sequence[capstone.CsInsn]) -> tuple[Guard, ...]:
    guards: list[Guard] = []
    for index in range(len(insns) - 1):
        insn = insns[index]
        branch = insns[index + 1]
        if branch.mnemonic not in CONDITIONAL_BRANCHES:
            continue
        if not branch.operands or branch.operands[0].type != X86_OP_IMM:
            continue
        rva = _rva(insn, spec.image_base)
        branch_rva = _rva(branch, spec.image_base)
        target = branch.operands[0].imm - spec.image_base
        operands = insn.operands
        global_rva: int | None = None
        width: int | None = None
        immediate: int | None = None
        register: str | None = None
        memory_text = ""
        if insn.mnemonic == "test" and len(operands) == 2 and operands[0].type == X86_OP_REG:
            register = _reg(insn, 0)
            if operands[1].type == X86_OP_IMM:
                immediate = operands[1].imm
        elif insn.mnemonic == "cmp" and len(operands) == 2:
            first, second = operands
            if first.type == X86_OP_MEM and first.mem.base == X86_REG_RIP:
                global_rva = rva + insn.size + first.mem.disp
                width = first.size
                if second.type == X86_OP_IMM:
                    immediate = second.imm
            elif first.type == X86_OP_REG and second.type == X86_OP_MEM:
                register = _reg(insn, 0)
                memory_text = _memory_operand_text(insn, 1)
                if second.mem.base == X86_REG_RIP:
                    global_rva = rva + insn.size + second.mem.disp
                    width = second.size
            elif first.type == X86_OP_REG and second.type == X86_OP_REG:
                register = _reg(insn, 0)
                memory_text = _reg(insn, 1)
            elif first.type == X86_OP_REG and second.type == X86_OP_IMM:
                register = _reg(insn, 0)
                immediate = second.imm
            elif second.type == X86_OP_IMM:
                immediate = second.imm
        else:
            continue
        guards.append(
            Guard(
                rva=rva,
                compare_rva=rva,
                mnemonic=insn.mnemonic,
                global_rva=global_rva,
                width=width,
                immediate=immediate,
                register=register,
                memory_text=memory_text,
                branch_rva=branch_rva,
                branch_mnemonic=branch.mnemonic,
                branch_target=target,
                forward=target > branch_rva,
            )
        )
    return tuple(guards)


def _conditional_moves(spec: Specimen, insns: Sequence[capstone.CsInsn]) -> tuple[tuple[int, int, int, str], ...]:
    moves: list[tuple[int, int, int, str]] = []
    for index in range(1, len(insns)):
        insn = insns[index]
        if not insn.mnemonic.startswith("cmov"):
            continue
        previous = insns[index - 1]
        if previous.mnemonic != "cmp" or len(previous.operands) != 2:
            continue
        if previous.operands[1].type != X86_OP_IMM:
            continue
        moves.append(
            (
                _rva(insn, spec.image_base),
                _rva(previous, spec.image_base),
                previous.operands[1].imm,
                f"{previous.mnemonic}/{insn.mnemonic}",
            )
        )
    return tuple(moves)


def _unaligned_copies(spec: Specimen, insns: Sequence[capstone.CsInsn]) -> tuple[tuple[int, str, str], ...]:
    copies = []
    for insn in insns:
        if insn.mnemonic not in COPY_MNEMONICS:
            continue
        if any(operand.size == UNALIGNED_COPY_WIDTH for operand in insn.operands):
            copies.append((_rva(insn, spec.image_base), insn.mnemonic, insn.op_str))
    return tuple(copies)


def _register_origin(spec: Specimen, insns: Sequence[capstone.CsInsn], index: int, register: str) -> str:
    """Backward-slice a base register to the instruction that produced its value.

    The cursor advances to the definition site on every hop, so a value that a
    callee-saved register captured before an intervening call is attributed to
    that capture rather than to the call.
    """
    cursor = index
    current = register
    for _hop in range(ORIGIN_HOP_LIMIT):
        definition: tuple[int, capstone.CsInsn] | None = None
        for position in range(cursor - 1, -1, -1):
            probe = insns[position]
            if _writes_register(probe, current):
                definition = (position, probe)
                break
        if definition is None:
            return "unknown"
        position, probe = definition
        if probe.mnemonic == "call":
            slot = _rip_slot(probe, spec.image_base)
            name = spec.api_name(slot) if slot is not None else None
            if name is not None:
                return f"after_call:{name}"
            if probe.operands and probe.operands[0].type == X86_OP_IMM:
                return f"after_call:internal:{common.hexs(probe.operands[0].imm - spec.image_base)}"
            return "after_call:unknown"
        if probe.mnemonic in ("mov", "movabs", "lea") and len(probe.operands) == 2:
            if probe.mnemonic == "lea":
                slot = _rip_slot(probe, spec.image_base)
                return f"rip_data:{common.hexs(slot)}" if slot is not None else "computed"
            source = probe.operands[1]
            if source.type == X86_OP_REG:
                followed = _reg(probe, 1)
                if followed in STACK_BASES:
                    return "stack_frame"
                cursor, current = position, followed
                continue
            if source.type == X86_OP_IMM:
                return f"immediate:{common.hexs(source.imm)}"
            return "computed"
        return "computed"
    return "unknown"


def _memory_stores(
    spec: Specimen, insns: Sequence[capstone.CsInsn], index: int
) -> Iterator[tuple[int, int, str, str, int | None]]:
    """Yield (rva, size_in_bytes, base_register, source_kind, rip_target) for stores."""
    insn = insns[index]
    operands = insn.operands
    if len(operands) != 2 or operands[0].type != X86_OP_MEM:
        return
    destination = operands[0]
    source = operands[1]
    rip_target = None
    if destination.mem.base == X86_REG_RIP:
        rip_target = _rva(insn, spec.image_base) + insn.size + destination.mem.disp
    if source.type == X86_OP_REG:
        kind = "register"
    elif source.type == X86_OP_IMM:
        kind = "immediate"
    elif source.type == X86_OP_MEM:
        kind = "memory"
    else:
        kind = "other"
    base = _canonical(insn.reg_name(destination.mem.base)) if destination.mem.base else ""
    yield (_rva(insn, spec.image_base), destination.size, base, kind, rip_target)


def _slot_writes(spec: Specimen, insns: Sequence[capstone.CsInsn]) -> tuple[SlotWrite, ...]:
    writes = []
    for index, insn in enumerate(insns):
        if insn.mnemonic not in ("mov", "movups", "movaps", "movdqu", "movdqa"):
            continue
        for rva, size, base, kind, rip_target in _memory_stores(spec, insns, index):
            if kind != "register":
                continue
            if rip_target is None and (not base or base in STACK_BASES):
                continue
            origin = f"rip_data:{common.hexs(rip_target)}" if rip_target is not None else _register_origin(
                spec, insns, index, base
            )
            if origin == "stack_frame":
                continue
            writes.append(
                SlotWrite(
                    rva=rva,
                    bits=size * 8,
                    base_register=base or "rip",
                    origin=origin,
                    rip_target=rip_target,
                )
            )
    return tuple(writes)


def _narrow_store_runs(spec: Specimen, insns: Sequence[capstone.CsInsn]) -> tuple[tuple[int, int, str], ...]:
    """Group narrow immediate stores sharing a base register inside a short window.

    This is the structural signature of inline code materialisation: several
    sub-word constant stores aimed at one register-derived destination with no
    intervening call.
    """
    runs: list[tuple[int, int, str]] = []
    pending: list[tuple[int, str]] = []
    pending_base: str | None = None
    for index, insn in enumerate(insns):
        if insn.mnemonic in ("call", "syscall", "int"):
            pending, pending_base = [], None
            continue
        if insn.mnemonic not in ("mov", "movabs"):
            continue
        for rva, size, base, kind, rip_target in _memory_stores(spec, insns, index):
            if kind != "immediate" or rip_target is not None or base in STACK_BASES:
                continue
            if size not in NARROW_STORE_WIDTHS:
                continue
            if base != pending_base or (pending and rva - pending[0][0] > NARROW_STORE_RUN_WINDOW):
                if len(pending) >= NARROW_STORE_RUN_MINIMUM:
                    runs.append((pending[0][0], pending[-1][0], pending_base or "unknown"))
                pending, pending_base = [], base
            pending.append((rva, base))
            break
    if len(pending) >= NARROW_STORE_RUN_MINIMUM:
        runs.append((pending[0][0], pending[-1][0], pending_base or "unknown"))
    return tuple(runs)


def _fill_loops(spec: Specimen, insns: Sequence[capstone.CsInsn]) -> tuple[FillLoop, ...]:
    """Detect back-branching loops whose body stores a constant byte to memory."""
    loops: list[FillLoop] = []
    for index, insn in enumerate(insns):
        if insn.mnemonic not in CONDITIONAL_BRANCHES or not insn.operands:
            continue
        if insn.operands[0].type != X86_OP_IMM:
            continue
        target = insn.operands[0].imm - spec.image_base
        branch_rva = _rva(insn, spec.image_base)
        if target >= branch_rva or branch_rva - target > FILL_LOOP_WINDOW:
            continue
        body = [probe for probe in insns if target <= _rva(probe, spec.image_base) < branch_rva]
        store = None
        for offset, probe in enumerate(body):
            if probe.mnemonic not in ("mov", "movabs"):
                continue
            for rva, size, base, kind, rip_target in _memory_stores(spec, body, offset):
                if kind != "immediate" or size not in FILL_STORE_SIZES:
                    continue
                if rip_target is None and base not in STACK_BASES:
                    store = (rva, base)
                    break
            if store is not None:
                break
        if store is None:
            continue
        counter = None
        for probe in body:
            if probe.mnemonic in ("inc", "add") and probe.operands and probe.operands[0].type == X86_OP_REG:
                counter = _reg(probe, 0)
                break
        loops.append(
            FillLoop(
                branch_rva=branch_rva,
                head_rva=target,
                store_rva=store[0],
                base_register=store[1],
                counter_register=counter,
            )
        )
    return tuple(loops)


def _mask_text(value: int, width: int | None = None) -> str:
    """Render a bit mask as an unsigned literal of the compared width."""
    if width:
        return common.hexs(value & ((1 << (8 * width)) - 1))
    return common.hexs(value & 0xFFFFFFFFFFFFFFFF)


def _memory_operand_text(insn: capstone.CsInsn, index: int) -> str:
    """Render a non-rip memory operand as base+displacement for reporting."""
    operand = insn.operands[index]
    if operand.mem.base == X86_REG_RIP:
        return "[rip]"
    base = _canonical(insn.reg_name(operand.mem.base))
    index_register = _canonical(insn.reg_name(operand.mem.index)) if operand.mem.index else ""
    text = base or "memory"
    if index_register:
        text = f"{base}+{index_register}*{operand.mem.scale}" if base else f"{index_register}*{operand.mem.scale}"
    if operand.mem.disp:
        text = f"{text}{'+' if text else ''}{common.hexs(operand.mem.disp)}"
    return text


def _memory_slot_text(spec: Specimen, insn: capstone.CsInsn) -> str:
    operand = insn.operands[0]
    if operand.mem.base == X86_REG_RIP:
        return common.hexs(_rva(insn, spec.image_base) + insn.size + operand.mem.disp)
    return _memory_operand_text(insn, 0)


def _bitmask_predicates(spec: Specimen, insns: Sequence[capstone.CsInsn]) -> tuple[tuple[int, str, int, str], ...]:
    """Detect flag-bit tests against an immediate mask.

    Record-driven patch activation is expressed as bit tests on a flag byte
    rather than as a comparison against a whole value, so the generic guard
    detector cannot attribute it.
    """
    predicates = []
    for insn in insns:
        if insn.mnemonic not in ("test", "and") or len(insn.operands) != 2:
            continue
        first, second = insn.operands
        if second.type != X86_OP_IMM or first.type == X86_OP_MEM and first.mem.base == X86_REG_RIP:
            continue
        if first.type == X86_OP_REG:
            target = _reg(insn, 0)
        elif first.type == X86_OP_MEM:
            target = _memory_slot_text(spec, insn)
        else:
            continue
        if not target:
            continue
        predicates.append((_rva(insn, spec.image_base), insn.mnemonic, second.imm, target))
    return tuple(predicates)


def _derived_constants(spec: Specimen, insns: Sequence[capstone.CsInsn]) -> tuple[tuple[int, str, int], ...]:
    """Fold an immediate load immediately followed by an immediate add/sub.

    Bound comparisons are frequently written against a register that a
    two-instruction constant fold materialised, so the effective bound does not
    appear as a compare immediate.
    """
    folded = []
    for index in range(len(insns) - 1):
        load, adjust = insns[index], insns[index + 1]
        if load.mnemonic not in ("mov", "movabs") or len(load.operands) != 2:
            continue
        if adjust.mnemonic not in ("add", "sub") or len(adjust.operands) != 2:
            continue
        if load.operands[0].type != X86_OP_REG or load.operands[1].type != X86_OP_IMM:
            continue
        if adjust.operands[0].type != X86_OP_REG or adjust.operands[1].type != X86_OP_IMM:
            continue
        if _reg(load, 0) != _reg(adjust, 0):
            continue
        value = load.operands[1].imm
        folded.append(
            (
                _rva(load, spec.image_base),
                adjust.mnemonic,
                value + adjust.operands[1].imm if adjust.mnemonic == "add" else value - adjust.operands[1].imm,
            )
        )
    return tuple(folded)


def _state_updates(spec: Specimen, insns: Sequence[capstone.CsInsn]) -> tuple[tuple[int, str, int, str], ...]:
    """Detect read-modify-write updates of a non-stack memory slot.

    A committed patch state is normally recorded by setting flag bits in place
    rather than by a plain store, so the store detectors above cannot see it.
    """
    updates = []
    for insn in insns:
        if insn.mnemonic not in ("or", "and", "xor"):
            continue
        operands = insn.operands
        if len(operands) != 2 or operands[0].type != X86_OP_MEM or operands[1].type != X86_OP_IMM:
            continue
        if operands[0].mem.base == X86_REG_RIP:
            continue
        base = _canonical(insn.reg_name(operands[0].mem.base))
        if not base or base in STACK_BASES:
            continue
        updates.append((_rva(insn, spec.image_base), insn.mnemonic, operands[1].imm, base))
    return tuple(updates)


def _global_refs(spec: Specimen, insns: Sequence[capstone.CsInsn]) -> tuple[tuple[int, int, int, str], ...]:
    refs = []
    for insn in insns:
        rva = _rva(insn, spec.image_base)
        for target, size in _rip_targets(insn, spec.image_base):
            if target in WATCHED_GLOBAL_RVAS:
                refs.append((rva, target, size, insn.mnemonic))
    return tuple(refs)


def _function_facts(spec: Specimen, begin: int, end: int) -> FunctionFacts:
    insns = spec.decoded(begin, end)
    return FunctionFacts(
        begin=begin,
        end=end,
        calls=_call_sites(spec, insns),
        guards=_guards(spec, insns),
        conditional_moves=_conditional_moves(spec, insns),
        unaligned_copies=_unaligned_copies(spec, insns),
        narrow_store_runs=_narrow_store_runs(spec, insns),
        slot_writes=_slot_writes(spec, insns),
        fill_loops=_fill_loops(spec, insns),
        state_updates=_state_updates(spec, insns),
        bitmask_predicates=_bitmask_predicates(spec, insns),
        derived_constants=_derived_constants(spec, insns),
        global_refs=_global_refs(spec, insns),
    )


# --------------------------------------------------------------------------- #
# whole-image sweep
# --------------------------------------------------------------------------- #


def _stub_site(rva: int, mnemonic: str, api: str, slot_rva: int) -> CallSite:
    return CallSite(
        rva=rva,
        mnemonic=mnemonic,
        api=api,
        slot_rva=slot_rva,
        internal_rva=None,
        arguments=(),
        return_tested=False,
    )


def build_inventory(spec: Specimen) -> Inventory:
    """One linear sweep over every RUNTIME_FUNCTION body."""
    inventory = Inventory(runtime_function_count=spec.function_count)
    api_calls: dict[str, list[int]] = {}
    api_thunks: dict[str, list[int]] = {}
    direct_callers: dict[int, list[int]] = {}
    watched_refs: dict[int, list[tuple[int, int, str]]] = {}
    protect_calls: list[tuple[int, str, int]] = []
    protect_thunks: list[tuple[int, str, int]] = []
    flush_calls: list[tuple[int, str, int]] = []
    protect_functions: list[tuple[int, int]] = []
    protect_with_copy: list[tuple[int, int]] = []
    image_base = spec.image_base

    for begin, end, _unwind in spec.functions():
        insns = spec.decoded(begin, end)
        inventory.swept_instruction_count += len(insns)
        decoded_bytes = 0
        protect_here = False
        copy_here = False
        for insn in insns:
            rva = insn.address - image_base
            decoded_bytes += insn.size
            mnemonic = insn.mnemonic
            for operand in insn.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    target = rva + insn.size + operand.mem.disp
                    if target in WATCHED_GLOBAL_RVAS:
                        watched_refs.setdefault(target, []).append((rva, operand.size, mnemonic))
            if mnemonic == "call":
                operands = insn.operands
                if operands and operands[0].type == X86_OP_IMM:
                    callee = operands[0].imm - image_base
                    if callee in SUBJECT_RVAS or callee in COMPARATOR_RVAS or callee in SHARED_INIT_HELPERS:
                        direct_callers.setdefault(callee, []).append(rva)
            if mnemonic in ("call", "jmp"):
                slot = _rip_slot(insn, image_base)
                if slot is None:
                    continue
                name = spec.api_name(slot)
                if name is None or _symbol(name) not in WATCHED_APIS:
                    continue
                symbol = _symbol(name)
                bucket = api_thunks if mnemonic == "jmp" else api_calls
                bucket.setdefault(name, []).append(rva)
                if symbol == PROTECT_API:
                    protect_here = True
                    (protect_thunks if mnemonic == "jmp" else protect_calls).append((rva, name, slot))
                elif symbol == FLUSH_API and mnemonic == "call":
                    flush_calls.append((rva, name, slot))
            elif mnemonic in COPY_MNEMONICS:
                for operand in insn.operands:
                    if operand.size == UNALIGNED_COPY_WIDTH:
                        copy_here = True
                        break
        inventory.undecoded_bytes += (end - begin) - decoded_bytes
        if insns and insns[-1].address + insns[-1].size == image_base + end:
            inventory.decoded_function_count += 1
        if protect_here:
            protect_functions.append((begin, end))
            if copy_here:
                protect_with_copy.append((begin, end))

    protect_records = sorted(
        {(entry[0], spec.function_at(entry[0])) for entry in protect_calls + protect_thunks}
    )
    resolved_protect_calls = []
    for rva, record in protect_records:
        if record is None:
            continue
        for site in _function_facts(spec, record[0], record[1]).calls:
            if site.rva == rva and site.mnemonic == "call" and _symbol(site.api) == PROTECT_API:
                resolved_protect_calls.append(site)
                break

    inventory.api_call_sites = {name: tuple(sorted(rvas)) for name, rvas in sorted(api_calls.items())}
    inventory.api_tail_thunks = {name: tuple(sorted(rvas)) for name, rvas in sorted(api_thunks.items())}
    inventory.protect_calls = tuple(sorted(resolved_protect_calls, key=lambda site: site.rva))
    inventory.protect_thunks = tuple(_stub_site(rva, "jmp", name, slot) for rva, name, slot in protect_thunks)
    inventory.flush_calls = tuple(_stub_site(rva, "call", name, slot) for rva, name, slot in flush_calls)
    inventory.protect_functions = tuple(sorted(protect_functions))
    inventory.protect_with_unaligned_copy = tuple(sorted(protect_with_copy))
    inventory.direct_callers = {rva: tuple(sorted(set(calls))) for rva, calls in sorted(direct_callers.items())}
    inventory.watched_global_refs = {rva: tuple(refs) for rva, refs in sorted(watched_refs.items())}
    inventory.literal_occurrences = {
        rva: spec.literal_occurrences(rva)
        for rva in sorted(set(SUBJECT_RVAS) | set(COMPARATOR_RVAS) | set(SHARED_INIT_HELPERS))
    }
    return inventory


# --------------------------------------------------------------------------- #
# inventory accessors
# --------------------------------------------------------------------------- #


def _callers_text(inventory: Inventory, rva: int) -> str:
    callers = inventory.direct_callers.get(rva, ())
    return ";".join(common.hexs(value) for value in callers) if callers else "none_static"


def _api_call_rvas(inventory: Inventory, symbol: str) -> tuple[int, ...]:
    collected: list[int] = []
    for name, rvas in inventory.api_call_sites.items():
        if _symbol(name) == symbol:
            collected.extend(rvas)
    return tuple(sorted(collected))


def _api_thunk_rvas(inventory: Inventory, symbol: str) -> tuple[int, ...]:
    collected: list[int] = []
    for name, rvas in inventory.api_tail_thunks.items():
        if _symbol(name) == symbol:
            collected.extend(rvas)
    return tuple(sorted(collected))


def _rvas_text(rvas: Sequence[int]) -> str:
    return ";".join(common.hexs(rva) for rva in rvas) if rvas else "none"


def _find_call(facts: FunctionFacts, symbol: str, mnemonic: str = "call") -> CallSite | None:
    for site in facts.calls:
        if site.mnemonic == mnemonic and _symbol(site.api) == symbol:
            return site
    return None


def _find_all_calls(facts: FunctionFacts, symbol: str, mnemonic: str | None = "call") -> tuple[CallSite, ...]:
    return tuple(
        site
        for site in facts.calls
        if _symbol(site.api) == symbol and (mnemonic is None or site.mnemonic == mnemonic)
    )


def _write_expression(site: CallSite | None) -> str:
    if site is None:
        return "not resolved"
    if site.slot_rva >= 0:
        return f"IAT {common.hexs(site.slot_rva)} {site.api}"
    if site.internal_rva is not None:
        return f"internal {common.hexs(site.internal_rva)}"
    return "unresolved"


def _export_expression(spec: Specimen, site: CallSite | None) -> str:
    if site is None:
        return "not resolved"
    state = dict(zip(ARGUMENT_REGISTERS, site.arguments))

    def describe(descriptor: str) -> str:
        kind, _, value = descriptor.partition(":")
        if kind == "rip_string":
            return spec.cstring(int(value, 16)) or f"string@{value}"
        if kind == "api_return":
            return value
        if kind == "internal_return":
            return f"internal {value} result"
        return descriptor

    return f"module={describe(state['rcx'])} symbol={describe(state['rdx'])}"


def _argument_value(site: CallSite | None, register: str) -> str | None:
    if site is None or register not in ARGUMENT_REGISTERS:
        return None
    return site.arguments[ARGUMENT_REGISTERS.index(register)]


def _guard_text(guard: Guard, spec: Specimen) -> str:
    if guard.global_rva is not None:
        owner = spec.section_label(guard.global_rva)
        if guard.immediate is not None:
            predicate = f"{common.hexs(guard.global_rva)} ({owner}) == {_mask_text(guard.immediate, guard.width)}"
        else:
            predicate = f"{common.hexs(guard.global_rva)} ({owner}) {guard.width or 0}-bit tested"
    elif guard.register is not None and guard.memory_text:
        predicate = f"{guard.register} == {guard.memory_text}"
    elif guard.register is not None and guard.immediate is not None:
        predicate = f"{guard.register} == {_mask_text(guard.immediate)}"
    elif guard.register is not None:
        predicate = f"{guard.register} != 0"
    else:
        predicate = f"compare == {_mask_text(guard.immediate or 0)}"
    return f"{predicate} [{guard.branch_mnemonic} -> {common.hexs(guard.branch_target)}]"


def _guard_kind(guard: Guard, spec: Specimen) -> str:
    if guard.global_rva is not None:
        return _global_kind(spec, guard.global_rva)
    if guard.register is not None and guard.memory_text:
        return "teb_guard"
    return "caller_argument"


def _guards_before(facts: FunctionFacts, rva: int) -> tuple[Guard, ...]:
    """Only the predicates that are textually in front of an instruction."""
    return tuple(guard for guard in facts.guards if guard.compare_rva < rva)


def _guards_text(guards: Sequence[Guard], spec: Specimen) -> str:
    if not guards:
        return "unconditional"
    parts = [_guard_text(guard, spec) for guard in guards[:GUARD_TEXT_LIMIT]]
    if len(guards) > GUARD_TEXT_LIMIT:
        parts.append(f"(+{len(guards) - GUARD_TEXT_LIMIT} further predicates)")
    return " AND ".join(parts)


def _global_kind(spec: Specimen, rva: int) -> str:
    return "global_rw_data" if spec.section_writable(rva) else "global_ro_data"


def _row(
    mechanism: str,
    rva: str,
    fn: str,
    target_kind: str,
    target_expr: str,
    caller_rvas: str,
    activation_cond: str,
    status: str,
    confidence: str,
) -> dict[str, Any]:
    if target_kind not in TARGET_KINDS:
        raise ValueError(f"unknown target_kind {target_kind!r}")
    return {
        "mechanism": mechanism,
        "RVA": _clean(rva),
        "fn": _clean(fn),
        "target_kind": target_kind,
        "target_expr": _clean(target_expr),
        "caller_rvas": _clean(caller_rvas),
        "activation_cond": _clean(activation_cond),
        "status": status,
        "confidence": confidence,
    }


def _clean(value: Any) -> str:
    return " ".join(str(value).split())


# --------------------------------------------------------------------------- #
# row builders
# --------------------------------------------------------------------------- #


def _subject_rows(
    spec: Specimen, inventory: Inventory, facts: FunctionFacts, subject_rva: int
) -> list[dict[str, Any]]:
    prefix = SUBJECT_PREFIXES[subject_rva]
    rows: list[dict[str, Any]] = []
    span = spec.span_label(facts.begin, facts.end)
    callers = _callers_text(inventory, subject_rva)
    literals = inventory.literal_occurrences.get(subject_rva, (0, 0, 0))
    rva_hits, va_hits, pdata_hits = literals
    unreachable = callers == "none_static" and rva_hits == pdata_hits and va_hits == 0
    guard_text = _guards_text(facts.guards, spec)

    rows.append(
        _row(
            f"{prefix}_entry",
            common.hexs(subject_rva),
            span,
            "internal_rva",
            "no direct call, no RVA/VA literal, no static function pointer"
            if unreachable
            else "a static reference to this entry exists",
            callers,
            "not statically reachable" if unreachable else f"static callers {callers}",
            STATUS_UNRESOLVED if unreachable else STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        )
    )
    rows.append(
        _row(
            f"{prefix}_address_literals",
            common.hexs(subject_rva),
            span,
            "whole_image_set",
            f"whole-file occurrences of this entry: rva32={rva_hits} va64={va_hits}; "
            f"rva32 occurrences inside the exception directory={pdata_hits}",
            "n/a",
            "n/a",
            STATUS_ABSENT if unreachable else STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        )
    )
    for site in _find_all_calls(facts, "GetModuleHandleA"):
        rows.append(
            _row(
                f"{prefix}_module_handle",
                common.hexs(site.rva),
                span,
                "import_iat_slot",
                _write_expression(site) + "; " + _argument_text(site),
                "n/a",
                guard_text,
                STATUS_OBSERVED,
                CONFIDENCE_HIGH,
            )
        )
    for site in _find_all_calls(facts, RESOLVE_API):
        rows.append(
            _row(
                f"{prefix}_target_resolution",
                common.hexs(site.rva),
                span,
                "resolved_export",
                _export_expression(spec, site),
                "n/a",
                guard_text,
                STATUS_OBSERVED,
                CONFIDENCE_HIGH,
            )
        )
        rows.append(
            _row(
                f"{prefix}_target_null_check",
                common.hexs(site.rva),
                span,
                "absent_mechanism",
                "export-resolution return value is not compared before use"
                if not site.return_tested
                else "export-resolution return value is compared before use",
                "n/a",
                "n/a",
                STATUS_ABSENT if not site.return_tested else STATUS_OBSERVED,
                CONFIDENCE_HIGH,
            )
        )
    for site in _find_all_calls(facts, PROTECT_API, "call"):
        size_argument = _argument_value(site, "rdx")
        preceding = _guards_before(facts, site.rva)
        rows.append(
            _row(
                f"{prefix}_protect_call_{common.hexs(site.rva).lower()}",
                common.hexs(site.rva),
                span,
                "import_iat_slot",
                _write_expression(site) + "; " + _argument_text(site),
                "n/a",
                _guards_text(preceding, spec),
                STATUS_OBSERVED,
                CONFIDENCE_HIGH,
            )
        )
        rows.append(
            _row(
                f"{prefix}_protect_result_check_{common.hexs(site.rva).lower()}",
                common.hexs(site.rva),
                span,
                "absent_mechanism",
                "return value of this protection call is not compared"
                if not site.return_tested
                else "return value of this protection call is compared",
                "n/a",
                "n/a",
                STATUS_ABSENT if not site.return_tested else STATUS_OBSERVED,
                CONFIDENCE_HIGH,
            )
        )
        rows.append(
            _row(
                f"{prefix}_protect_size_argument_{common.hexs(site.rva).lower()}",
                common.hexs(site.rva),
                span,
                "caller_argument",
                f"size argument is {size_argument or 'not resolved'}; "
                "no bound check against the target page extent precedes the write",
                "n/a",
                "n/a",
                STATUS_OBSERVED,
                CONFIDENCE_HIGH,
            )
        )
    for site in _find_all_calls(facts, PROTECT_API, "jmp"):
        rows.append(
            _row(
                f"{prefix}_protect_tail_transfer",
                common.hexs(site.rva),
                span,
                "import_iat_slot",
                _write_expression(site) + "; tail transfer, no return value is observable at this site",
                "n/a",
                "unconditional",
                STATUS_OBSERVED,
                CONFIDENCE_HIGH,
            )
        )
    flush_sites = _find_all_calls(facts, FLUSH_API)
    rows.append(
        _row(
            f"{prefix}_cache_flush",
            common.hexs(facts.begin),
            span,
            "absent_mechanism",
            "no instruction-cache flush call in this function"
            if not flush_sites
            else "flush at " + _rvas_text([site.rva for site in flush_sites]),
            "n/a",
            "n/a",
            STATUS_ABSENT if not flush_sites else STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        )
    )
    for rva, target, size, mnemonic in facts.global_refs:
        is_predicate = mnemonic in ("cmp", "test")
        rows.append(
            _row(
                f"{prefix}_global_ref_{common.hexs(rva).lower()}",
                common.hexs(rva),
                span,
                _global_kind(spec, target),
                f"{mnemonic} of {size * 8} bits at {common.hexs(target)} in {spec.section_label(target)}",
                "n/a",
                _guards_text(
                    [guard for guard in facts.guards if guard.compare_rva == rva], spec
                )
                if is_predicate
                else "unconditional",
                STATUS_OBSERVED,
                CONFIDENCE_HIGH,
            )
        )
    for copy_rva, mnemonic, text in facts.unaligned_copies:
        rows.append(
            _row(
                f"{prefix}_unaligned_copy_{common.hexs(copy_rva).lower()}",
                common.hexs(copy_rva),
                span,
                _copy_target_kind(facts),
                f"{mnemonic} of {UNALIGNED_COPY_WIDTH * 8} bits: {text}",
                "n/a",
                "unconditional",
                STATUS_OBSERVED,
                CONFIDENCE_HIGH,
            )
        )
    for start, end, base in facts.narrow_store_runs:
        rows.append(
            _row(
                f"{prefix}_inline_materialisation_{common.hexs(start).lower()}",
                f"{common.hexs(start)}|{common.hexs(end)}",
                span,
                _copy_target_kind(facts),
                f"run of narrow constant stores to one register-derived base={base} "
                f"spanning {common.hexs(start)}..{common.hexs(end)}; store widths="
                + ",".join(
                    str(bits)
                    for bits in sorted(
                        {
                            insn.operands[0].size * 8
                            for insn in spec.decoded(facts.begin, facts.end)
                            if insn.address - spec.image_base in (start, end)
                        }
                    )
                ),
                "n/a",
                "unconditional",
                STATUS_OBSERVED,
                CONFIDENCE_HIGH,
            )
        )
    for loop in facts.fill_loops:
        rows.append(
            _row(
                f"{prefix}_constant_fill_loop_{common.hexs(loop.store_rva).lower()}",
                f"{common.hexs(loop.head_rva)}|{common.hexs(loop.branch_rva)}",
                span,
                "caller_argument",
                f"back-branching loop {common.hexs(loop.head_rva)}..{common.hexs(loop.branch_rva)} "
                f"storing one constant byte per iteration to base={loop.base_register}"
                + (f" counter={loop.counter_register}" if loop.counter_register else ""),
                "n/a",
                guard_text,
                STATUS_OBSERVED,
                CONFIDENCE_HIGH,
            )
        )
    for write in facts.slot_writes:
        rows.append(
            _row(
                f"{prefix}_slot_write_{common.hexs(write.rva).lower()}",
                common.hexs(write.rva),
                span,
                _slot_target_kind(spec, write),
                f"{write.bits}-bit register store to base={write.base_register}; "
                f"base origin={write.origin}; section="
                + (
                    f"{spec.section_label(write.rip_target)}"
                    f" ({'writable' if spec.section_writable(write.rip_target) else 'not writable'})"
                    if write.rip_target is not None
                    else "not a rip-relative slot"
                ),
                "n/a",
                "unconditional",
                STATUS_OBSERVED,
                CONFIDENCE_HIGH if write.rip_target is not None else CONFIDENCE_MEDIUM,
            )
        )
    return rows


def _copy_target_kind(facts: FunctionFacts) -> str:
    """Classify the memory a wide copy or a constant store run targets."""
    if any(ref[1] == EXPORT_CACHE_GLOBAL_RVA and ref[3] == "mov" for ref in facts.global_refs):
        return "export_prologue"
    return "caller_argument"


def _slot_target_kind(spec: Specimen, write: SlotWrite) -> str:
    if write.rip_target is not None:
        return _global_kind(spec, write.rip_target)
    if write.origin.startswith("after_call:"):
        return "resolved_export"
    if write.origin.startswith("rip_data:"):
        return _global_kind(spec, int(write.origin.rsplit(":", 1)[-1], 16))
    if write.origin.startswith("computed"):
        return "table_slot"
    return "caller_argument"


def _symmetry_rows(
    spec: Specimen, inventory: Inventory, install: FunctionFacts, restore: FunctionFacts
) -> list[dict[str, Any]]:
    install_span = spec.span_label(install.begin, install.end)
    restore_span = spec.span_label(restore.begin, restore.end)
    paired = install.unaligned_copies and restore.unaligned_copies
    install_protect = _find_call(install, PROTECT_API, "call")
    restore_sites = _find_all_calls(restore, PROTECT_API, None)
    restore_protect = restore_sites[0] if restore_sites else None
    restore_shares_cache = any(ref[1] == EXPORT_CACHE_GLOBAL_RVA for ref in restore.global_refs)
    size_match = (
        install_protect is not None
        and restore_protect is not None
        and _argument_value(install_protect, "rdx") == _argument_value(restore_protect, "rdx")
    )
    install_restore_tail = _find_call(restore, PROTECT_API, "jmp")
    rows = [
        _row(
            "symmetry_unaligned_pair",
            f"{common.hexs(install.unaligned_copies[0][0])}|{common.hexs(restore.unaligned_copies[0][0])}"
            if paired
            else "not established",
            f"{install_span}|{restore_span}",
            "cross_function_pair",
            f"install side moves {UNALIGNED_COPY_WIDTH * 8} bit at {common.hexs(install.unaligned_copies[0][0])}; "
            f"restore side moves {UNALIGNED_COPY_WIDTH * 8} bit at {common.hexs(restore.unaligned_copies[0][0])}"
            if paired
            else "no unaligned copy on at least one side",
            f"install {_callers_text(inventory, INSTALLER_RVA)}; restore {_callers_text(inventory, RESTORE_RVA)}",
            "both halves must execute; neither half is statically reachable",
            STATUS_OBSERVED if paired else STATUS_UNRESOLVED,
            CONFIDENCE_HIGH,
        ),
        _row(
            "symmetry_save_restore_shape",
            f"{common.hexs(install.unaligned_copies[0][0])}|{common.hexs(restore.unaligned_copies[0][0])}"
            if paired
            else "not established",
            f"{install_span}|{restore_span}",
            "cross_function_pair",
            f"unaligned instruction count install={len(install.unaligned_copies)} "
            f"restore={len(restore.unaligned_copies)}; width={UNALIGNED_COPY_WIDTH * 8} bit on both sides",
            "n/a",
            "n/a",
            STATUS_OBSERVED
            if paired and len(install.unaligned_copies) == len(restore.unaligned_copies)
            else STATUS_ASYMMETRIC,
            CONFIDENCE_HIGH,
        ),
        _row(
            "symmetry_size_argument",
            common.hexs(RESTORE_RVA),
            f"{install_span}|{restore_span}",
            "cross_function_pair",
            f"install side size argument={_argument_value(install_protect, 'rdx') or 'unresolved'}; "
            f"restore side size argument={_argument_value(restore_protect, 'rdx') or 'unresolved'}; "
            f"identical={size_match}",
            "n/a",
            "n/a",
            STATUS_OBSERVED if size_match else STATUS_ASYMMETRIC,
            CONFIDENCE_HIGH,
        ),
        _row(
            "symmetry_protection_restore_path",
            common.hexs(install_protect.rva) if install_protect else common.hexs(RESTORE_RVA),
            f"{install_span}|{restore_span}",
            "cross_function_pair",
            "the previous protection value is carried to the restore side through the caller-supplied "
            "record, so the halves are symmetric only when the same record is reused; "
            f"restore side transfer is {'a tail jump' if install_restore_tail else 'a plain call'} at "
            f"{common.hexs(install_restore_tail.rva) if install_restore_tail else 'n/a'}",
            "n/a",
            "requires the install side to have produced a record for the restore side",
            STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        ),
        _row(
            "symmetry_target_source",
            common.hexs(RESTORE_RVA),
            f"{install_span}|{restore_span}",
            "cross_function_pair",
            f"install side references the export cache global {common.hexs(EXPORT_CACHE_GLOBAL_RVA)}: "
            f"{any(ref[1] == EXPORT_CACHE_GLOBAL_RVA for ref in install.global_refs)}; "
            f"restore side references it: {restore_shares_cache}",
            "n/a",
            "both halves require successful export resolution at run time",
            STATUS_ASYMMETRIC if not restore_shares_cache else STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        ),
        _row(
            "symmetry_image_inventory",
            common.hexs(INSTALLER_RVA),
            "whole-image",
            "whole_image_set",
            f"functions with a protection call: {len(inventory.protect_functions)}; "
            f"of those also containing an unaligned copy: {len(inventory.protect_with_unaligned_copy)}; "
            "matching spans: "
            + (",".join(spec.span_label(b, e) for b, e in inventory.protect_with_unaligned_copy) or "none"),
            "n/a",
            "n/a",
            STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        ),
    ]
    return rows


def _writer_inventory_rows(spec: Specimen, inventory: Inventory) -> list[dict[str, Any]]:
    protect_functions = ",".join(spec.span_label(b, e) for b, e in inventory.protect_functions)
    checked = _rvas_text([site.rva for site in inventory.protect_calls if site.return_tested])
    unchecked = _rvas_text([site.rva for site in inventory.protect_calls if not site.return_tested])
    flush_functions = ",".join(
        spec.function_label(site.rva) for site in inventory.flush_calls
    )
    return [
        _row(
            "writer_protection_call_inventory",
            _rvas_text([site.rva for site in inventory.protect_calls]),
            "whole-image",
            "import_iat_slot",
            f"{len(inventory.protect_calls)} protection call sites in {len(inventory.protect_functions)} "
            f"functions ({protect_functions}); protection tail-jump thunks: "
            f"{_rvas_text([site.rva for site in inventory.protect_thunks])}",
            "n/a",
            "n/a",
            STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        ),
        _row(
            "writer_protection_result_checked",
            checked,
            "whole-image",
            "import_iat_slot",
            f"protection call sites with a compared return value: {checked}; without: {unchecked}",
            "n/a",
            "n/a",
            STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        ),
        _row(
            "writer_cache_flush_inventory",
            _rvas_text([site.rva for site in inventory.flush_calls]),
            "whole-image",
            "import_iat_slot",
            f"{len(inventory.flush_calls)} instruction-cache flush call sites in the image, in {flush_functions}",
            "n/a",
            "n/a",
            STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        ),
        _row(
            "writer_import_tail_thunk_inventory",
            _rvas_text(_api_thunk_rvas(inventory, PROTECT_API)),
            "whole-image",
            "import_iat_slot",
            f"tail-jump import thunks: {sum(len(v) for v in inventory.api_tail_thunks.values())} in total; "
            f"{len(_api_thunk_rvas(inventory, PROTECT_API))} for the protection entry",
            "n/a",
            "n/a",
            STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        ),
        _row(
            "writer_export_resolution_inventory",
            _rvas_text(_api_call_rvas(inventory, RESOLVE_API)),
            "whole-image",
            "resolved_export",
            f"export-resolution call sites: {len(_api_call_rvas(inventory, RESOLVE_API))}; "
            f"module-handle sites: A={len(_api_call_rvas(inventory, 'GetModuleHandleA'))} "
            f"W={len(_api_call_rvas(inventory, 'GetModuleHandleW'))} "
            f"ExW={len(_api_call_rvas(inventory, 'GetModuleHandleExW'))}",
            "n/a",
            "n/a",
            STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        ),
        _row(
            "writer_global_function_pointer_cache",
            common.hexs(EXPORT_CACHE_GLOBAL_RVA),
            spec.function_label(INSTALLER_RVA),
            _global_kind(spec, EXPORT_CACHE_GLOBAL_RVA),
            f"export address cache at {common.hexs(EXPORT_CACHE_GLOBAL_RVA)} in "
            f"{spec.section_label(EXPORT_CACHE_GLOBAL_RVA)} "
            f"({'writable' if spec.section_writable(EXPORT_CACHE_GLOBAL_RVA) else 'not writable'}); "
            f"static references={len(inventory.watched_global_refs.get(EXPORT_CACHE_GLOBAL_RVA, ()))}",
            _callers_text(inventory, INSTALLER_RVA),
            "written only on the one-shot resolution path",
            STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        ),
        _row(
            "writer_global_guard_state",
            common.hexs(INSTALL_GUARD_GLOBAL_RVA),
            spec.function_label(INSTALLER_RVA),
            _global_kind(spec, INSTALL_GUARD_GLOBAL_RVA),
            f"install gate at {common.hexs(INSTALL_GUARD_GLOBAL_RVA)} in "
            f"{spec.section_label(INSTALL_GUARD_GLOBAL_RVA)}; "
            f"static references={len(inventory.watched_global_refs.get(INSTALL_GUARD_GLOBAL_RVA, ()))}",
            _callers_text(inventory, INSTALLER_RVA),
            "one-shot: the resolution path is skipped once the gate is set",
            STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        ),
    ]


def _operand_bits(spec: Specimen, facts: FunctionFacts, rva: int) -> int:
    for insn in spec.decoded(facts.begin, facts.end):
        if _rva(insn, spec.image_base) == rva and insn.operands:
            return insn.operands[0].size * 8
    return 0


def _comparator_rows(spec: Specimen, inventory: Inventory) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for rva in COMPARATOR_RVAS:
        record = spec.function_at(rva)
        if record is None:
            continue
        facts = _function_facts(spec, record[0], record[1])
        span = spec.span_label(record[0], record[1])
        callers = _callers_text(inventory, rva)
        guard_text = _guards_text(facts.guards, spec)
        table_refs = [ref for ref in facts.global_refs if ref[1] == RECORD_TABLE_GLOBAL_RVA]
        if table_refs:
            rows.append(
                _row(
                    f"comparator_record_table_{common.hexs(rva)}",
                    _rvas_text([ref[0] for ref in table_refs]),
                    span,
                    "record_table",
                    f"{len(table_refs)} references to the record table at "
                    f"{common.hexs(RECORD_TABLE_GLOBAL_RVA)} in {spec.section_label(RECORD_TABLE_GLOBAL_RVA)}",
                    callers,
                    guard_text,
                    STATUS_OBSERVED,
                    CONFIDENCE_HIGH,
                )
            )
        for site in _find_all_calls(facts, PROTECT_API):
            rows.append(
                _row(
                    f"comparator_protect_{common.hexs(site.rva)}",
                    common.hexs(site.rva),
                    span,
                    "import_iat_slot",
                    _write_expression(site) + "; " + _argument_text(site)
                    + "; return value "
                    + ("compared" if site.return_tested else "not compared"),
                    callers,
                    guard_text,
                    STATUS_OBSERVED,
                    CONFIDENCE_HIGH,
                )
            )
        for site in _find_all_calls(facts, FLUSH_API):
            rows.append(
                _row(
                    f"comparator_cache_flush_{common.hexs(site.rva)}",
                    common.hexs(site.rva),
                    span,
                    "import_iat_slot",
                    _write_expression(site) + "; return value "
                    + ("compared" if site.return_tested else "not compared"),
                    callers,
                    guard_text,
                    STATUS_OBSERVED,
                    CONFIDENCE_HIGH,
                )
            )
        for start, end, base in facts.narrow_store_runs:
            rows.append(
                _row(
                    f"comparator_inline_write_{common.hexs(start)}",
                    f"{common.hexs(start)}|{common.hexs(end)}",
                    span,
                    _slot_target_kind(spec, SlotWrite(start, 0, base, "unknown", None)),
                    f"narrow constant store run base={base} spanning {common.hexs(start)}..{common.hexs(end)}",
                    callers,
                    guard_text,
                    STATUS_OBSERVED,
                    CONFIDENCE_HIGH,
                )
            )
        for move_rva, compare_rva, bound, mnemonic in facts.conditional_moves:
            rows.append(
                _row(
                    f"comparator_conditional_move_{common.hexs(move_rva)}",
                    common.hexs(move_rva),
                    span,
                    "caller_argument",
                    f"{mnemonic}: compare at {common.hexs(compare_rva)} against {common.hexs(bound)} "
                    "selects the effective target address",
                    callers,
                    "target address depends on the supplied value range",
                    STATUS_OBSERVED,
                    CONFIDENCE_HIGH,
                )
            )
        for write in facts.slot_writes:
            rows.append(
                _row(
                    f"comparator_slot_write_{common.hexs(write.rva)}",
                    common.hexs(write.rva),
                    span,
                    _slot_target_kind(spec, write),
                    f"{write.bits}-bit register store to base={write.base_register}; "
                    f"base origin={write.origin}",
                    callers,
                    guard_text,
                    STATUS_OBSERVED,
                    CONFIDENCE_HIGH if write.rip_target is not None else CONFIDENCE_MEDIUM,
                )
            )
        for update_rva, mnemonic, mask, base in facts.state_updates:
            rows.append(
                _row(
                    f"comparator_state_commit_{common.hexs(update_rva)}",
                    common.hexs(update_rva),
                    span,
                    "record_table",
                    f"{mnemonic} with {_mask_text(mask)} on a {_operand_bits(spec, facts, update_rva)}-bit slot "
                    f"reached through base={base}",
                    callers,
                    "the state slot is set on this path without a preceding comparison of the outcome",
                    STATUS_OBSERVED,
                    CONFIDENCE_HIGH,
                )
            )
        rva_hits, va_hits, pdata_hits = inventory.literal_occurrences.get(rva, (0, 0, 0))
        rows.append(
            _row(
                f"comparator_entry_{common.hexs(rva)}",
                common.hexs(rva),
                span,
                "internal_rva",
                f"direct callers={callers}; whole-file literals rva32={rva_hits} va64={va_hits} "
                f"exception-directory={pdata_hits}",
                callers,
                "statically unreachable" if callers == "none_static" else "statically reachable",
                STATUS_UNRESOLVED if callers == "none_static" else STATUS_OBSERVED,
                CONFIDENCE_HIGH,
            )
        )
    return rows


def _activation_rows(
    spec: Specimen, inventory: Inventory, subjects: dict[int, FunctionFacts]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for rva, facts in sorted(subjects.items()):
        span = spec.span_label(facts.begin, facts.end)
        for guard in facts.guards:
            if guard.global_rva is None and guard.immediate is None and guard.register is None:
                continue
            rows.append(
                _row(
                    f"activation_guard_{common.hexs(guard.branch_rva)}",
                    common.hexs(guard.branch_rva),
                    span,
                _guard_kind(guard, spec),
                f"{guard.mnemonic} at {common.hexs(guard.compare_rva)} followed by "
                    f"{guard.branch_mnemonic} to {common.hexs(guard.branch_target)} "
                    f"({'forward' if guard.forward else 'backward'} branch)",
                    _callers_text(inventory, rva),
                    _guard_text(guard, spec),
                    STATUS_OBSERVED,
                    CONFIDENCE_HIGH,
                )
            )
    fill = subjects[FILL_HELPER_RVA]
    if fill.conditional_moves:
        lower_bounds = [
            common.hexs(item[2] * (1 << 30)) for item in fill.conditional_moves if 0 < item[2] <= 63
        ]
        rows.append(
            _row(
                "activation_fill_helper_target_window",
                _rvas_text([item[0] for item in fill.conditional_moves]),
                spec.span_label(fill.begin, fill.end),
                _global_kind(spec, RELOCATION_BASE_GLOBAL_RVA),
                "the supplied value is rebased onto "
                f"{common.hexs(RELOCATION_BASE_GLOBAL_RVA)} when it falls inside a fixed window and is "
                "otherwise used unchanged; window bounds are "
                + (",".join(lower_bounds) or "not resolved")
                + " from the shift/compare immediates and "
                + ",".join(
                    f"{_mask_text(value)} folded at {common.hexs(rva)} by {op}"
                    for rva, op, value in fill.derived_constants
                )
                + " from immediate load/add pairs",
                _callers_text(inventory, FILL_HELPER_RVA),
                "write target depends on the supplied value and on the rebasing base being initialised",
                STATUS_OBSERVED,
                CONFIDENCE_MEDIUM,
            )
        )
    rows.append(
        _row(
            "activation_subject_reachability",
            "|".join(common.hexs(rva) for rva in SUBJECT_RVAS),
            "whole-image",
            "whole_image_set",
            "; ".join(
                f"{common.hexs(rva)} direct_callers={_callers_text(inventory, rva)} "
                f"literals={inventory.literal_occurrences.get(rva, (0, 0, 0))}"
                for rva in SUBJECT_RVAS
            ),
            "n/a",
            "no static activation path is derivable for any audited subject",
            STATUS_UNRESOLVED,
            CONFIDENCE_HIGH,
        )
    )
    install = subjects[INSTALLER_RVA]
    gate_refs = [ref for ref in install.global_refs if ref[1] == INSTALL_GUARD_GLOBAL_RVA]
    helper_sites = [
        (call_rva, operands[0].imm - spec.image_base)
        for call_rva, operands in (
            (
                _rva(insn, spec.image_base),
                insn.operands,
            )
            for insn in spec.decoded(install.begin, install.end)
            if insn.mnemonic == "call" and insn.operands and insn.operands[0].type == X86_OP_IMM
        )
        if operands[0].imm - spec.image_base in SHARED_INIT_HELPERS
    ]
    rows.append(
        _row(
            "activation_installer_one_shot_gate",
            _rvas_text([ref[0] for ref in gate_refs]) or "not observed",
            spec.span_label(install.begin, install.end),
            _global_kind(spec, INSTALL_GUARD_GLOBAL_RVA),
            f"install gate at {common.hexs(INSTALL_GUARD_GLOBAL_RVA)} in "
            f"{spec.section_label(INSTALL_GUARD_GLOBAL_RVA)}; static references="
            f"{len(gate_refs)}; shared internal helper calls on the gated path="
            + (_rvas_text([call for call, _target in helper_sites]) or "none"),
            _callers_text(inventory, INSTALLER_RVA),
            "the resolution path runs once per gate value; the write path is reached from a block the "
            "gate branch does not skip",
            STATUS_OBSERVED,
            CONFIDENCE_MEDIUM,
        )
    )
    for rva in (RECORD_DRIVEN_PATCHER_RVA, RECORD_DRIVER_RVA, RECORD_TABLE_WALKER_RVA, RECORD_REGISTRAR_RVA):
        record = spec.function_at(rva)
        if record is None:
            continue
        facts = _function_facts(spec, record[0], record[1])
        if not facts.bitmask_predicates:
            continue
        rows.append(
            _row(
                f"activation_bitmask_predicate_{common.hexs(rva)}",
                _rvas_text([item[0] for item in facts.bitmask_predicates]),
                spec.span_label(record[0], record[1]),
                "record_table",
                "; ".join(
                    f"{item[1]} {item[3]}, {_mask_text(item[2])} at {common.hexs(item[0])}"
                    for item in facts.bitmask_predicates
                )
                + f"; state slots updated at {_rvas_text([item[0] for item in facts.state_updates]) or 'none'}",
                _callers_text(inventory, rva),
                " AND ".join(
                    f"{item[3]} & {_mask_text(item[2])}" for item in facts.bitmask_predicates[:GUARD_TEXT_LIMIT]
                ),
                STATUS_OBSERVED,
                CONFIDENCE_HIGH,
            )
        )
    for helper in SHARED_INIT_HELPERS:
        rows.append(
            _row(
                f"activation_shared_helper_{common.hexs(helper)}",
                common.hexs(helper),
                spec.function_label(helper),
                "internal_rva",
                f"shared internal helper reached from the audited subjects; "
                f"static call sites in the image={len(inventory.direct_callers.get(helper, ()))}",
                _callers_text(inventory, helper),
                "utility behaviour, not a subject-specific activation path",
                STATUS_OBSERVED,
                CONFIDENCE_MEDIUM,
            )
        )
    return rows


def _limit_rows(spec: Specimen, inventory: Inventory) -> list[dict[str, Any]]:
    return [
        _row(
            "method_sweep_coverage",
            common.hexs(0x1000),
            "whole-image",
            "whole_image_set",
            f"exception-directory records={inventory.runtime_function_count}; "
            f"fully decoded={inventory.decoded_function_count}; "
            f"decoded instructions={inventory.swept_instruction_count}; "
            f"bytes not covered by a decoded instruction={common.hexs(inventory.undecoded_bytes)}",
            "n/a",
            "n/a",
            STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        ),
        _row(
            "method_decode_shortfall",
            common.hexs(0x1000),
            "whole-image",
            "whole_image_set",
            f"{inventory.runtime_function_count - inventory.decoded_function_count} function bodies and "
            f"{common.hexs(inventory.undecoded_bytes)} bytes are not fully decoded by the linear sweep; "
            "findings inside those bodies are not covered by this audit",
            "n/a",
            "n/a",
            STATUS_UNRESOLVED
            if inventory.runtime_function_count != inventory.decoded_function_count
            else STATUS_OBSERVED,
            CONFIDENCE_HIGH,
        ),
        _row(
            "method_target_module_permissions",
            common.hexs(INSTALLER_RVA),
            "whole-image",
            "resolved_export",
            "the written target lives in another module, so its page protection is decided at run time; "
            "this audit observes only the requested protection arguments, never the target page state",
            "n/a",
            "requires a successful export resolution in the target module",
            STATUS_UNRESOLVED,
            CONFIDENCE_MEDIUM,
        ),
        _row(
            "method_structural_heuristics",
            common.hexs(INSTALLER_RVA),
            "whole-image",
            "absent_mechanism",
            "the narrow-store-run, constant-fill-loop, slot-write and bitmask detectors are structural: a "
            "match shows the shape only and is not by itself proof of an executable-code write. The "
            "argument tracker is a linear scan of the decoded body and ignores basic-block "
            "reachability, so a register redefined only on a non-taken path can be reported with that "
            "path's value",
            "n/a",
            "n/a",
            STATUS_UNRESOLVED,
            CONFIDENCE_LOW,
        ),
    ]


def build_rows(spec: Specimen, inventory: Inventory) -> list[dict[str, Any]]:
    subjects: dict[int, FunctionFacts] = {}
    for rva in SUBJECT_RVAS:
        record = spec.function_at(rva)
        if record is None:
            raise SystemExit(f"subject {common.hexs(rva)} is not covered by the exception directory")
        subjects[rva] = _function_facts(spec, record[0], record[1])
    rows: list[dict[str, Any]] = []
    for rva in SUBJECT_RVAS:
        rows.extend(_subject_rows(spec, inventory, subjects[rva], rva))
    rows.extend(_symmetry_rows(spec, inventory, subjects[INSTALLER_RVA], subjects[RESTORE_RVA]))
    rows.extend(_writer_inventory_rows(spec, inventory))
    rows.extend(_comparator_rows(spec, inventory))
    rows.extend(_activation_rows(spec, inventory, subjects))
    rows.extend(_limit_rows(spec, inventory))
    return rows


def verify_baseline(spec: Specimen) -> list[common.Check]:
    digest = common.sha256_file(spec.path)
    return [
        common.Check(
            name="specimen.sha256", expected=SPECIMEN_SHA256, actual=digest, ok=digest == SPECIMEN_SHA256
        ),
        common.Check(
            name="specimen.runtime_function_count",
            expected=EXPECTED_RUNTIME_FUNCTIONS,
            actual=spec.function_count,
            ok=spec.function_count == EXPECTED_RUNTIME_FUNCTIONS,
        ),
        common.Check(
            name="specimen.machine_amd64",
            expected=MACHINE_AMD64,
            actual=spec.machine,
            ok=spec.machine == MACHINE_AMD64,
        ),
    ]


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


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description="Static patch-mechanism audit for the adhesive.dll specimen (no execution, no patching)"
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument(
        "--csv",
        type=Path,
        default=root / "reverse" / "evidence" / "patch_mechanisms_helpers.csv",
    )
    parser.add_argument("--emit", action="store_true", help="write the csv, this is the default")
    parser.add_argument("--verify", action="store_true", help="compare the stored csv with a fresh computation")
    parser.add_argument("--list-rows", action="store_true", help="print the emitted rows")
    parser.add_argument("--max-report", type=int, default=20)
    args = parser.parse_args(argv)
    if args.emit and args.verify:
        parser.error("--emit and --verify are mutually exclusive")

    print(f"script    {_relative(script, root)}")
    print(f"schema    {SCHEMA}")
    print(f"sha256    {common.sha256_file(script)}")
    if not args.specimen.is_file():
        print(f"specimen  {_relative(args.specimen, root)} does not exist")
        return 1
    print(f"specimen  {_relative(args.specimen, root)} sha256={common.sha256_file(args.specimen)}")

    try:
        specimen = Specimen(args.specimen.resolve())
    except pefile.PEFormatError as error:
        print(f"specimen  {_relative(args.specimen, root)} is not a PE image: {error}")
        return 1

    with specimen as spec:
        checks = verify_baseline(spec)
        common.report_checks(checks, args.max_report)
        failures = sum(1 for check in checks if not check.ok)
        for check in checks:
            print(f"check     {check.name} {'ok' if check.ok else 'FAILED'}")
        if failures:
            print("baseline  refusing to emit: the specimen does not match the pinned baseline")
            return 1
        print("sweep     linear scan of every exception-directory function body")
        started = time.monotonic()
        inventory = build_inventory(spec)
        elapsed = time.monotonic() - started
        print(
            f"sweep     functions={inventory.runtime_function_count} "
            f"decoded={inventory.decoded_function_count} "
            f"instructions={inventory.swept_instruction_count} "
            f"seconds={elapsed:.1f}"
        )
        print(
            f"sweep     protection_calls={len(inventory.protect_calls)} "
            f"protection_tail_thunks={len(inventory.protect_thunks)} "
            f"cache_flush_calls={len(inventory.flush_calls)}"
        )
        rows = build_rows(spec, inventory)
    expected = _csv_text(rows)
    print(f"rows      {len(rows)} csv rows, {len(CSV_FIELDS)} fields")

    if args.verify:
        actual = args.csv.read_text(encoding="utf-8") if args.csv.exists() else None
        if actual == expected:
            print(f"match     {_relative(args.csv, root)}")
            return 0
        print(f"MISMATCH  {_relative(args.csv, root)}")
        if actual is None:
            print("          file does not exist")
            return 1
        stored_lines = actual.splitlines()
        fresh_lines = expected.splitlines()
        for index in range(max(len(stored_lines), len(fresh_lines))):
            stored = stored_lines[index] if index < len(stored_lines) else "<missing>"
            updated = fresh_lines[index] if index < len(fresh_lines) else "<missing>"
            if stored != updated:
                print(f"          line {index + 1} stored={stored[:200]}")
                print(f"          line {index + 1} fresh ={updated[:200]}")
                break
        return 1

    common.write_csv(args.csv, rows, CSV_FIELDS)
    print(f"wrote     {_relative(args.csv, root)}")
    if args.list_rows:
        for row in rows:
            print(f"  {row['mechanism']:<46} {row['RVA'][:44]:<44} {row['status']:<11} {row['confidence']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
