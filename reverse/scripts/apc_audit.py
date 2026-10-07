"""Static audit of every QueueUserAPC call site in the adhesive.dll specimen.

The specimen is only ever parsed as a file: it is never loaded, mapped, patched
or executed. Every CSV cell is recomputed from the file image on each run, so
the emitted evidence file is byte-stable for a given specimen and two runs are
reproducible diffs.

For each QueueUserAPC call site the audit records:

* the IMAGE_RUNTIME_FUNCTION range that bounds the call site, every direct
  rel32 caller of that range, and every data slot that stores its entry VA;
* the decoded APC routine target: instruction bytes, unwind coverage and the
  other RIP-relative references of the same address, plus the data slots that
  store the target address itself, which is a different address from the entry
  VA of the enclosing function and is counted separately;
* the three Win32 argument registers plus the provenance of the thread handle
  back to the instruction that produced it;
* the image-wide read/write census of the mode switch that picks the
  QueueUserAPC arm or the TerminateThread arm, including an exhaustive search
  for writers of that switch;
* the branch condition that selects the arm, the guard chain in front of it and
  the alternative TerminateThread arm with its own arguments;
* the static activation verdict for the block and a confidence grade.

The audit is descriptive. A negative result such as "no static writer of the mode
switch" only rules out the writer forms these scans cover: direct RIP-relative
stores, absolute address materialised as an immediate, and base relocations on
the slot. A store through a register-computed address, a runtime modification of
the image or a writer in another module stays outside the evidence, and every
such limit is written into the cell it qualifies.

Determinism: every search is a whole-image byte scan or a linear sweep over a
fixed instruction range, every result list is sorted, and no wall-clock,
hostname or environment value reaches the output.
"""

from __future__ import annotations

import argparse
import array
import bisect
import csv
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Sequence

import capstone
import numpy as np
import pefile

_SCRIPT_DIR: Final[Path] = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import common

CSV_COLUMNS: Final[tuple[str, ...]] = (
    "callsite",
    "fn",
    "target",
    "args",
    "global read/write",
    "branch condition",
    "activation status",
    "confidence",
)

QUEUE_USER_APC: Final[str] = "QueueUserAPC"
TERMINATE_THREAD: Final[str] = "TerminateThread"
BEGIN_THREAD_EX: Final[str] = "_beginthreadex"
ALERTABLE_WAIT_API: Final[str] = "GetQueuedCompletionStatus"
SUSPEND_THREAD_API: Final[str] = "SuspendThread"

EXPECTED_QUEUE_USER_APC_SITES: Final[int] = 7
EXPECTED_TERMINATE_THREAD_SITES: Final[int] = 7
EXPECTED_QUEUE_USER_APC_TARGET: Final[int] = 0x1170
EXPECTED_GLOBAL_VA: Final[int] = 0x183254270

CODE_SECTION_NAME: Final[str] = ".text"
DATA_SECTION_NAMES: Final[tuple[str, ...]] = (".rdata", ".data")
GLOBAL_NEIGHBOURHOOD_RADIUS: Final[int] = 0x100
GUARD_WINDOW_BYTES: Final[int] = 0x200
MAX_GUARDS_PER_SITE: Final[int] = 4
MAX_INSN_LENGTH: Final[int] = 15
TARGET_DECODE_BYTES: Final[int] = 8
TARGET_TAIL_BYTES: Final[int] = 16
ARGUMENT_LOOKBACK_BYTES: Final[int] = 0x40
ARGUMENT_PROVENANCE_BYTES: Final[int] = 0x200
POST_CALL_INSNS: Final[int] = 8
POST_CALL_TEXT_INSNS: Final[int] = 3
MAX_LISTED_SLOTS: Final[int] = 4
CHUNK_BYTES: Final[int] = 1 << 22

_TERMINATORS: Final[frozenset[str]] = frozenset(
    {"ret", "retf", "iret", "iretd", "iretq", "ud2", "int3", "hlt"}
)
_JUMP_IF_TRUE: Final[frozenset[str]] = frozenset({"jne", "jnz"})
_JUMP_IF_FALSE: Final[frozenset[str]] = frozenset({"je", "jz"})
_VOLATILE_GPR: Final[frozenset[int]] = frozenset(
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
_GPR_ALIAS: Final[dict[int, int]] = {
    capstone.x86.X86_REG_AL: capstone.x86.X86_REG_RAX,
    capstone.x86.X86_REG_CL: capstone.x86.X86_REG_RCX,
    capstone.x86.X86_REG_DL: capstone.x86.X86_REG_RDX,
    capstone.x86.X86_REG_BL: capstone.x86.X86_REG_RBX,
    capstone.x86.X86_REG_SPL: capstone.x86.X86_REG_RSP,
    capstone.x86.X86_REG_BPL: capstone.x86.X86_REG_RBP,
    capstone.x86.X86_REG_SIL: capstone.x86.X86_REG_RSI,
    capstone.x86.X86_REG_DIL: capstone.x86.X86_REG_RDI,
    capstone.x86.X86_REG_R8D: capstone.x86.X86_REG_R8,
    capstone.x86.X86_REG_R8W: capstone.x86.X86_REG_R8,
    capstone.x86.X86_REG_R8B: capstone.x86.X86_REG_R8,
    capstone.x86.X86_REG_R9D: capstone.x86.X86_REG_R9,
    capstone.x86.X86_REG_R9W: capstone.x86.X86_REG_R9,
    capstone.x86.X86_REG_R9B: capstone.x86.X86_REG_R9,
    capstone.x86.X86_REG_R10D: capstone.x86.X86_REG_R10,
    capstone.x86.X86_REG_R10W: capstone.x86.X86_REG_R10,
    capstone.x86.X86_REG_R10B: capstone.x86.X86_REG_R10,
    capstone.x86.X86_REG_R11D: capstone.x86.X86_REG_R11,
    capstone.x86.X86_REG_R11W: capstone.x86.X86_REG_R11,
    capstone.x86.X86_REG_R11B: capstone.x86.X86_REG_R11,
    capstone.x86.X86_REG_EAX: capstone.x86.X86_REG_RAX,
    capstone.x86.X86_REG_ECX: capstone.x86.X86_REG_RCX,
    capstone.x86.X86_REG_EDX: capstone.x86.X86_REG_RDX,
    capstone.x86.X86_REG_EBX: capstone.x86.X86_REG_RBX,
    capstone.x86.X86_REG_ESP: capstone.x86.X86_REG_RSP,
    capstone.x86.X86_REG_EBP: capstone.x86.X86_REG_RBP,
    capstone.x86.X86_REG_ESI: capstone.x86.X86_REG_RSI,
    capstone.x86.X86_REG_EDI: capstone.x86.X86_REG_RDI,
}


def _join(parts: Sequence[str]) -> str:
    return "; ".join(part for part in parts if part)


def _slot_list(rvas: Sequence[int], limit: int = MAX_LISTED_SLOTS) -> str:
    head = ", ".join(f"RVA 0x{item:X}" for item in rvas[:limit])
    rest = len(rvas) - limit
    return f"{head} and {rest} more" if rest > 0 else head


def _hex(value: int) -> str:
    return common.hexs(value)


def _full_register(register: int) -> int:
    return _GPR_ALIAS.get(register, register)







class Image:
    """Read-only view over the specimen file with the indexes the audit needs."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.blob: bytes = path.read_bytes()
        self.pe: pefile.PE = common.load_pe(path)
        self.image_base: int = int(self.pe.OPTIONAL_HEADER.ImageBase)
        self.sections = common.sections(self.pe)
        code = [section for section in self.sections if section.name == CODE_SECTION_NAME]
        if len(code) != 1:
            raise ValueError(f"expected one {CODE_SECTION_NAME} section, found {len(code)}")
        self.code_section = code[0]
        self.code_va = common.rva_to_va(self.pe, self.code_section.virtual_address)
        self.code_raw = self.code_section.raw_pointer
        self.code = self.blob[self.code_raw : self.code_raw + self.code_section.raw_size]
        self.code_len = len(self.code)
        self.disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.disassembler.detail = True
        self._xref_cache: dict[tuple[int, int], list[dict[str, Any]]] = {}
        self._call_cache: dict[tuple[str, int], list[int]] = {}
        self._function_cache: dict[tuple[int, int], list[capstone.CsInsn]] = {}
        self._build_iat_index()
        self._build_pdata_index()
        self._build_vector_index()

    def close(self) -> None:
        self.pe.close()



    def _build_iat_index(self) -> None:
        self.iat: dict[str, int] = {}
        self.symbol_by_rva: dict[int, str] = {}
        for descriptor in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = descriptor.dll.decode("ascii", errors="replace")
            for entry in descriptor.imports:
                if entry.name is None:
                    continue
                name = entry.name.decode("ascii", errors="replace")
                rva = int(entry.address) - self.image_base
                self.iat.setdefault(name, rva)
                self.symbol_by_rva.setdefault(rva, f"{dll}!{name}")

    def iat_slot(self, name: str) -> int:
        """IAT slot RVA of one imported name; raises when the name is absent."""
        if name not in self.iat:
            raise KeyError(f"import not found: {name}")
        return self.iat[name]



    def _build_pdata_index(self) -> None:
        summary = common.pdata_summary(self.pe)
        flat = array.array("I")
        flat.frombytes(common.read_rva(self.pe, int(summary["rva"]), int(summary["size"])))
        self.runtime_begins: list[int] = flat[0::3]
        self.runtime_ends: list[int] = flat[1::3]

    def runtime_function(self, rva: int) -> tuple[int, int, int] | None:
        index = bisect.bisect_right(self.runtime_begins, rva) - 1
        if index < 0:
            return None
        begin, end = self.runtime_begins[index], self.runtime_ends[index]
        return (begin, end, index) if begin <= rva < end else None



    def _build_vector_index(self) -> None:
        self._u8 = np.frombuffer(self.code, dtype=np.uint8)
        self._dwords: tuple[np.ndarray, ...] = tuple(
            np.frombuffer(
                self.code[1 + residue : 1 + residue + ((self.code_len - 1 - residue) // 4) * 4],
                dtype="<i4",
            )
            for residue in range(4)
        )

    def dword_at(self, positions: Sequence[int], delta: int) -> np.ndarray:
        """Vectorised little-endian int32 at byte offset position + delta."""
        if len(positions) == 0:
            return np.zeros(0, dtype=np.int64)
        index = np.asarray(positions, dtype=np.int64)
        out = np.empty(index.size, dtype=np.int64)
        for residue in range(4):
            selector = (index + delta - 1 - residue) % 4 == 0
            if not selector.any():
                continue
            picked = index[selector]
            out[selector] = self._dwords[residue][(picked + delta - 1 - residue) // 4]
        return out

    def direct_call_offsets(self, target_rva: int) -> list[int]:
        """Blob offsets of every E8 rel32 call whose destination is target_rva."""
        cached = self._call_cache.get(("rel32", target_rva))
        if cached is not None:
            return cached
        index = np.nonzero(self._u8 == 0xE8)[0]
        index = index[index + 5 <= self.code_len]
        if index.size == 0:
            return []
        displacement = self.dword_at(index.tolist(), 1)
        wanted = target_rva - self.code_section.virtual_address - (index + 5)
        found = sorted(int(offset) for offset in index[displacement == wanted])
        self._call_cache[("rel32", target_rva)] = found
        return found

    def indirect_call_offsets(self, iat_rva: int) -> list[int]:
        """Blob offsets of every FF 15 call that dispatches through one IAT slot."""
        cached = self._call_cache.get(("indirect", iat_rva))
        if cached is not None:
            return cached
        index = np.nonzero(self._u8 == 0xFF)[0]
        index = index[index + 6 <= self.code_len]
        if index.size == 0:
            return []
        index = index[self._u8[index + 1] == 0x15]
        if index.size == 0:
            return []
        displacement = self.dword_at(index.tolist(), 2)
        wanted = iat_rva - self.code_section.virtual_address - (index + 6)
        found = sorted(int(offset) for offset in index[displacement == wanted])
        self._call_cache[("indirect", iat_rva)] = found
        return found

    def rip_reference_ends(self, low_rva: int, high_rva: int) -> list[int]:
        """Blob offsets of instruction ends whose RIP-relative target is in range.

        A RIP-relative displacement is always the last four bytes of the
        encoding, so the byte-wide filter below is exact for candidate
        selection; every candidate is then decoded before it is reported.
        """
        ends: list[int] = []
        for base in range(0, self.code_len - 4, CHUNK_BYTES):
            limit = min(base + CHUNK_BYTES, self.code_len - 4)
            for residue in range(4):
                count = (limit - base - residue) // 4
                if count <= 0:
                    continue
                start = base + residue
                displacement = np.frombuffer(
                    self.code[start : start + count * 4], dtype="<i4"
                ).astype(np.int64)
                position = np.arange(count, dtype=np.int64) * 4 + start + 4
                target = self.code_section.virtual_address + position + displacement
                selected = np.nonzero((target >= low_rva) & (target <= high_rva))[0]
                ends.extend(int(position[item]) for item in selected)
        return sorted(set(ends))

    def count_occurrences(self, needle: bytes) -> int:
        total = 0
        start = 0
        while True:
            index = self.blob.find(needle, start)
            if index < 0:
                return total
            total += 1
            start = index + 1



    def offset_to_rva(self, offset: int) -> int:
        """Map a blob offset inside the code section to an RVA."""
        return self.code_section.virtual_address + offset

    def rva_to_offset(self, rva: int) -> int:
        """Map an RVA to a blob offset inside the code section."""
        return rva - self.code_section.virtual_address

    def instruction_at(self, rva: int) -> capstone.CsInsn | None:
        """Decode the single instruction that starts at rva, or None."""
        offset = self.rva_to_offset(rva)
        if offset < 0 or offset >= self.code_len:
            return None
        for instruction in self.disassembler.disasm(
            self.code[offset : offset + MAX_INSN_LENGTH], self.image_base + rva, count=1
        ):
            return instruction
        return None

    def decode(self, begin: int, end: int) -> list[capstone.CsInsn]:
        """Linear sweep of [begin, end), skipping positions capstone cannot decode.

        Callers that need a guaranteed boundary use function_instructions.
        """
        window = self.code[max(0, self.rva_to_offset(begin)) : max(0, self.rva_to_offset(end))]
        return [
            instruction
            for instruction in self.disassembler.disasm(window, self.image_base + begin)
            if instruction.id != 0
        ]

    def function_instructions(self, begin: int, end: int) -> list[capstone.CsInsn]:
        """Linear sweep of one IMAGE_RUNTIME_FUNCTION range, decoded from begin.

        Every look-back in this module goes through this helper: begin is a real
        function entry, so the sweep starts on an instruction boundary and no
        window can be decoded from a misaligned address.
        """
        cached = self._function_cache.get((begin, end))
        if cached is None:
            cached = self.decode(begin, end)
            self._function_cache[(begin, end)] = cached
        return cached

    def window_before(
        self, begin: int, end: int, before_rva: int, limit: int
    ) -> list[capstone.CsInsn]:
        """Instructions of the range that lie in [before_rva - limit, before_rva)."""
        return [
            instruction
            for instruction in self.function_instructions(begin, end)
            if before_rva - limit <= instruction.address - self.image_base < before_rva
        ]

    def insn_text(self, instruction: capstone.CsInsn) -> str:
        """Mnemonic and operands on one line, as capstone renders them."""
        return f"{instruction.mnemonic} {instruction.op_str}".replace("  ", " ").strip()

    def annotated_text(self, instruction: capstone.CsInsn) -> str:
        """Instruction text, with the imported name appended for an IAT dispatch."""
        target = self.resolve_rip(instruction)
        symbol = self.symbol_by_rva.get(target) if target is not None else None
        text = self.insn_text(instruction)
        return f"{text} -> {symbol}" if symbol else text

    def resolve_rip(self, instruction: capstone.CsInsn) -> int | None:
        """RVA of the first RIP-relative memory operand, or None."""
        for operand in instruction.operands:
            if operand.type != capstone.x86.X86_OP_MEM:
                continue
            if operand.mem.base != capstone.x86.X86_REG_RIP:
                continue
            return instruction.address + instruction.size + operand.mem.disp - self.image_base
        return None

    def rip_xrefs(self, low_rva: int, high_rva: int) -> list[dict[str, Any]]:
        """Validated RIP-relative references into an RVA range, sorted by site."""
        cached = self._xref_cache.get((low_rva, high_rva))
        if cached is not None:
            return cached
        records: list[dict[str, Any]] = []
        for end in self.rip_reference_ends(low_rva, high_rva):
            instruction = self.instruction_ending_at(end, low_rva, high_rva)
            if instruction is None:
                continue
            target = self.resolve_rip(instruction)
            if target is None or not low_rva <= target <= high_rva:
                continue
            write = False
            for operand in instruction.operands:
                if (
                    operand.type == capstone.x86.X86_OP_MEM
                    and operand.mem.base == capstone.x86.X86_REG_RIP
                ):
                    write = bool(operand.access & capstone.CS_AC_WRITE)
                    break
            records.append(
                {
                    "rva": instruction.address - self.image_base,
                    "text": self.insn_text(instruction),
                    "target_rva": target,
                    "access": "W" if write else "R",
                }
            )
        records.sort(key=lambda item: (item["target_rva"], item["rva"]))
        self._xref_cache[(low_rva, high_rva)] = records
        return records

    def instruction_ending_at(
        self, end_offset: int, low_rva: int | None = None, high_rva: int | None = None
    ) -> capstone.CsInsn | None:
        """Instruction that ends exactly at end_offset, longest encoding first.

        A short window inside a longer instruction can decode on its own, so
        every window is tried and the longest match wins. When a target range is
        supplied, only matches whose RIP-relative target falls inside it are
        considered, which makes the choice unambiguous for the reference scans.
        """
        longest: capstone.CsInsn | None = None
        in_range: capstone.CsInsn | None = None
        for back in range(1, MAX_INSN_LENGTH + 1):
            start = end_offset - back
            if start < 0:
                break
            for instruction in self.disassembler.disasm(
                self.code[start:end_offset], self.code_va + start, count=1
            ):
                start_rva = instruction.address - self.image_base
                finish = self.rva_to_offset(start_rva) + instruction.size
                if finish != end_offset:
                    break
                if longest is None or instruction.size > longest.size:
                    longest = instruction
                if low_rva is not None and high_rva is not None:
                    target = self.resolve_rip(instruction)
                    if target is not None and low_rva <= target <= high_rva:
                        if in_range is None or instruction.size > in_range.size:
                            in_range = instruction
                break
        return in_range if in_range is not None else longest

    def is_data_rva(self, rva: int) -> bool:
        """True when the RVA falls inside a scanned data section."""
        return any(
            section.name in DATA_SECTION_NAMES
            and section.virtual_address <= rva < section.virtual_end
            for section in self.sections
        )

    def data_pointer_rvas(self, value_va: int) -> list[int]:
        """RVAs of the data slots that store value_va as a little-endian qword."""
        needle = struct.pack("<Q", value_va)
        found: list[int] = []
        start = 0
        while True:
            index = self.blob.find(needle, start)
            if index < 0:
                return found
            rva = common.raw_to_rva(self.pe, index)
            if rva is not None and self.is_data_rva(rva):
                found.append(rva)
            start = index + 1

    def base_relocations(self) -> set[int]:
        """RVAs that carry a non-absolute base relocation, i.e. pointer slots."""
        return {
            int(entry.rva)
            for block in getattr(self.pe, "DIRECTORY_ENTRY_BASERELOC", [])
            for entry in block.entries
            if int(entry.type) != 0
        }







def _branch_target(instruction: capstone.CsInsn) -> int | None:
    """Absolute branch destination as capstone reports it, or None."""
    if instruction.id == 0 or not instruction.group(capstone.CS_GRP_JUMP):
        return None
    if not instruction.operands:
        return None
    operand = instruction.operands[0]
    return operand.imm if operand.type == capstone.x86.X86_OP_IMM else None


def _branch_target_rva(image: Image, instruction: capstone.CsInsn) -> int | None:
    """Branch destination as an RVA, or None for indirect or non-branch forms."""
    target = _branch_target(instruction)
    return None if target is None else target - image.image_base


def _defines(instruction: capstone.CsInsn) -> int | None:
    """Full 64-bit register written as the destination, or None for no register."""
    if not instruction.operands or instruction.mnemonic in _TERMINATORS:
        return None
    first = instruction.operands[0]
    if first.type != capstone.x86.X86_OP_REG:
        return None
    if not first.access & capstone.CS_AC_WRITE:
        return None
    return _full_register(first.reg)


def _walk_back(
    image: Image,
    function_begin: int,
    function_end: int,
    before_rva: int,
    register: int,
    stop_on_any_branch: bool,
) -> list[capstone.CsInsn]:
    """Linear pre-image of before_rva, used for argument provenance.

    Terminators, unconditional jumps and backward branches always end the walk.
    When stop_on_any_branch is set the walk also ends at the first forward
    conditional branch, which yields the straight-line block that the audited
    call sits in. When it is not set, forward conditional branches are crossed,
    which yields the path in front of an arm split, where a value defined in
    front of the split dominates the audited block. For the volatile registers
    of the x64 Windows ABI the walk additionally ends at the first call.

    The result is a pre-image and not a dominator proof; the CSV states that.
    """
    path: list[capstone.CsInsn] = []
    volatile = register in _VOLATILE_GPR
    window = image.window_before(
        function_begin, function_end, before_rva, ARGUMENT_PROVENANCE_BYTES
    )
    for instruction in reversed(window):
        rva = instruction.address - image.image_base
        if instruction.mnemonic in _TERMINATORS or instruction.mnemonic == "jmp":
            break
        target = _branch_target_rva(image, instruction)
        if target is not None and (stop_on_any_branch or target <= rva):
            break
        if volatile and instruction.mnemonic == "call":
            break
        path.append(instruction)
    path.reverse()
    return path


def _defining_site(
    image: Image, preimage: Sequence[capstone.CsInsn], register: int
) -> tuple[int, str] | None:
    """Last definition of register on a linear pre-image, highest address first.

    A straight-line pre-image has no competing paths, so the definition closest
    to the use is the one that takes effect. The pre-image itself is not a
    dominator proof, and the CSV states that limit.
    """
    found: tuple[int, str] | None = None
    for instruction in preimage:
        if _defines(instruction) == register:
            found = (instruction.address - image.image_base, image.insn_text(instruction))
    return found


def _block_preimage(
    image: Image, function_begin: int, function_end: int, callsite: int, register: int
) -> list[capstone.CsInsn]:
    """Straight-line block that the audited call belongs to."""
    return _walk_back(image, function_begin, function_end, callsite, register, True)


def _common_preimage(
    image: Image, function_begin: int, function_end: int, before_rva: int, register: int
) -> list[capstone.CsInsn]:
    """Path in front of an arm split, with the split branch itself crossed."""
    return _walk_back(image, function_begin, function_end, before_rva, register, False)


def _first_operand_register(image: Image, instruction: capstone.CsInsn) -> int | None:
    """Full 64-bit register named by the first operand, or None."""
    for operand in instruction.operands:
        if operand.type == capstone.x86.X86_OP_REG:
            return _full_register(operand.reg)
    return None


def _constant_of(image: Image, instruction: capstone.CsInsn) -> str:
    operands = [item.strip() for item in instruction.op_str.split(",")]
    if instruction.mnemonic == "xor" and len(operands) == 2 and operands[0] == operands[1]:
        return "0"
    for operand in instruction.operands[1:]:
        if operand.type == capstone.x86.X86_OP_IMM:
            return _hex(operand.imm)
        if operand.type == capstone.x86.X86_OP_REG:
            return f"the value of {image.disassembler.reg_name(operand.reg)}"
    return f"'{instruction.mnemonic} {instruction.op_str}'"


@dataclass(frozen=True, slots=True)
class Guard:
    """A branch that gates the audited block."""

    jcc_rva: int
    jcc_text: str
    flag_rva: int
    flag_text: str
    flag_register: int | None
    predicate: str
    edge: str

    def describe(self) -> str:
        return (
            f"{self.predicate} (flags from '{self.flag_text}' @RVA 0x{self.flag_rva:X}, "
            f"'{self.jcc_text}' @RVA 0x{self.jcc_rva:X}, block on the {self.edge} edge)"
        )


def _branch_text(image: Image, instruction: capstone.CsInsn) -> str:
    """Branch text with the destination rendered as an RVA like every other address."""
    target = _branch_target_rva(image, instruction)
    return instruction.mnemonic if target is None else f"{instruction.mnemonic} 0x{target:X}"


def _predicate(flag: capstone.CsInsn, jcc: capstone.CsInsn, edge: str) -> str:
    """Render the condition that must hold for the audited block to be reached."""
    if jcc.mnemonic not in _JUMP_IF_TRUE and jcc.mnemonic not in _JUMP_IF_FALSE:
        return f"{jcc.mnemonic} taken and {flag.mnemonic} {flag.op_str}"
    holds = (jcc.mnemonic in _JUMP_IF_TRUE) == (edge == "taken")
    operands = [item.strip() for item in flag.op_str.split(",")]
    if flag.mnemonic == "test" and len(operands) == 2 and operands[0] == operands[1]:
        return f"{operands[0]} != 0" if holds else f"{operands[0]} == 0"
    if flag.mnemonic == "cmp" and len(operands) == 2 and operands[1].lstrip("-").isdigit():
        if int(operands[1], 0) == 0:
            return f"{operands[0]} != 0" if holds else f"{operands[0]} == 0"
    comparison = f"{flag.mnemonic} {flag.op_str}"
    return f"{comparison} holds" if holds else f"{comparison} does not hold"


def _build_guard(
    image: Image,
    jcc: capstone.CsInsn,
    flag: capstone.CsInsn | None,
    target_rva: int,
    block_start: int,
) -> Guard:
    """Turn a decoded branch into a guard, taking the flag source from the sweep.

    The flag instruction is the sweep element in front of the branch, so it is
    always the real predecessor; re-decoding backwards from the branch address
    would be free to pick a longer spurious encoding.
    """
    jcc_rva = jcc.address - image.image_base
    edge = "taken" if target_rva == block_start else "fallthrough"
    if flag is None:
        return Guard(
            jcc_rva,
            _branch_text(image, jcc),
            jcc_rva,
            "<unresolved>",
            None,
            "<unresolved>",
            edge,
        )
    return Guard(
        jcc_rva=jcc_rva,
        jcc_text=_branch_text(image, jcc),
        flag_rva=flag.address - image.image_base,
        flag_text=image.insn_text(flag),
        flag_register=_first_operand_register(image, flag),
        predicate=_predicate(flag, jcc, edge),
        edge=edge,
    )


def _guard_chain(
    image: Image, function_begin: int, function_end: int, block_start: int
) -> tuple[Guard | None, list[Guard]]:
    """The branch that enters the block plus the conditional guards in front."""
    selector: Guard | None = None
    guards: list[Guard] = []
    window = image.window_before(function_begin, function_end, block_start, GUARD_WINDOW_BYTES)
    for index, instruction in enumerate(window):
        target = _branch_target_rva(image, instruction)
        if target is None or instruction.mnemonic == "jmp":
            continue
        rva = instruction.address - image.image_base
        flag = window[index - 1] if index else None
        if target == block_start:
            if selector is None:
                selector = _build_guard(image, instruction, flag, target, block_start)
        elif rva + instruction.size <= block_start < target:
            guards.append(_build_guard(image, instruction, flag, target, block_start))
    guards.sort(key=lambda guard: guard.jcc_rva, reverse=True)
    return selector, guards[:MAX_GUARDS_PER_SITE]


def _rip_load_into(
    image: Image, function_begin: int, function_end: int, before_rva: int, register: int
) -> tuple[int, str, int, int] | None:
    """Nearest preceding RIP-relative store into register, with target and width."""
    window = image.window_before(function_begin, function_end, before_rva, ARGUMENT_LOOKBACK_BYTES)
    for instruction in reversed(window):
        if _defines(instruction) != register:
            continue
        target = image.resolve_rip(instruction)
        if target is None:
            return None
        width = next(
            (
                operand.size
                for operand in instruction.operands
                if operand.type == capstone.x86.X86_OP_MEM
            ),
            0,
        )
        return instruction.address - image.image_base, image.insn_text(instruction), target, width
    return None


def _return_value_checked(image: Image, callsite: int) -> bool:
    """True when EAX from the call is tested before it is overwritten."""
    for instruction in image.decode(callsite, callsite + 0x40)[:POST_CALL_INSNS]:
        if _defines(instruction) == capstone.x86.X86_REG_RAX:
            return False
        if instruction.mnemonic in {"test", "cmp"} and instruction.op_str.startswith("eax"):
            return True
    return False


def _iat_call_in_range(image: Image, iat_rva: int, begin: int, end: int) -> int | None:
    """RVA of the first call through iat_rva inside [begin, end), or None."""
    for offset in image.indirect_call_offsets(iat_rva):
        rva = image.offset_to_rva(offset)
        if begin <= rva < end:
            return rva
    return None







@dataclass(frozen=True, slots=True)
class TargetFacts:
    """What the audit states about the APC routine address."""

    rva: int
    va: int
    instructions: tuple[str, ...]
    consumed_bytes: str
    tail_bytes: str
    has_unwind_entry: bool
    rip_xref_count: int
    apc_load_count: int
    data_slot_rvas: tuple[int, ...]

    def column(self) -> str:
        return _join(
            [
                f"RVA 0x{self.rva:X} (VA 0x{self.va:X}) in {CODE_SECTION_NAME}",
                f"{len(self.instructions)} instruction(s): {_join(self.instructions)}",
                f"bytes {self.consumed_bytes}, following {self.tail_bytes}",
                f"IMAGE_RUNTIME_FUNCTION entry: {'yes' if self.has_unwind_entry else 'no'}",
                f"image-wide RIP-relative references to the address: {self.rip_xref_count}, "
                f"of which {self.apc_load_count} build this call's argument",
                f"{len(self.data_slot_rvas)} data slots store the pointer VA 0x{self.va:X} of "
                f"RVA 0x{self.rva:X} ({_slot_list(self.data_slot_rvas)}), which is consistent "
                f"with a shared placeholder for an empty routine rather than a routine specific "
                f"to this call; the entry VA of the enclosing function is a different address "
                f"and the slots that store it are counted in the fn column",
            ]
        )


@dataclass(frozen=True, slots=True)
class GlobalFacts:
    """Image-wide census of the mode switch that selects the arm."""

    rva: int
    va: int
    section: str
    file_value: int
    has_base_relocation: bool
    references: tuple[dict[str, Any], ...]
    neighbourhood: tuple[dict[str, Any], ...]
    imm64_hits: int
    imm32_va_hits: int
    imm32_rva_hits: int

    @property
    def reads(self) -> tuple[dict[str, Any], ...]:
        return tuple(item for item in self.references if item["access"] == "R")

    @property
    def writes(self) -> tuple[dict[str, Any], ...]:
        return tuple(item for item in self.references if item["access"] == "W")

    def column(self, read_rva: int, read_text: str, read_width: int) -> str:
        if self.writes:
            writers = _join(
                f"store at RVA 0x{item['rva']:X} '{item['text']}'" for item in self.writes
            )
        else:
            writers = (
                f"none found - 0 RIP-relative stores image-wide, 0 absolute-immediate stores, "
                f"no base relocation on the slot, file image value {_hex(self.file_value)}"
            )
        neighbour_targets = sorted({item["target_rva"] for item in self.neighbourhood})
        neighbour_writes = sum(1 for item in self.neighbourhood if item["access"] == "W")
        neighbour_text = ", ".join(f"0x{item:X}" for item in neighbour_targets) or "none"
        return _join(
            [
                f"switch RVA 0x{self.rva:X} (VA 0x{self.va:X}) in {self.section}, file image value "
                f"{_hex(self.file_value)}, base relocation: "
                f"{'yes' if self.has_base_relocation else 'no'}",
                f"read for this call site at RVA 0x{read_rva:X} '{read_text}' "
                f"({read_width}-byte load)",
                f"image-wide references to the switch address: {len(self.reads)} read / "
                f"{len(self.writes)} write",
                f"writers: {writers}",
                f"absolute-address scan over the whole file: VA-as-imm64 {self.imm64_hits}, "
                f"VA-low-as-imm32 {self.imm32_va_hits}, RVA-as-imm32 {self.imm32_rva_hits}",
                f"neighbourhood scan +-{GLOBAL_NEIGHBOURHOOD_RADIUS:#x} RVA: "
                f"{len(self.neighbourhood)} references ({neighbour_writes} writes) to "
                f"{neighbour_text}; none of them targets 0x{self.rva:X} itself",
                "coverage limit: a store through a register-computed address, a runtime image "
                "modification or a writer outside this image is not excluded by these scans",
            ]
        )


@dataclass(frozen=True, slots=True)
class HandleOrigin:
    """Where the thread handle passed to QueueUserAPC is produced."""

    field_offset: int
    load_rva: int
    load_text: str
    base_rva: int
    base_text: str
    producer_callsite: int
    producer_store_rva: int
    producer_function: tuple[int, int, int]
    producer_callers: tuple[int, ...]
    producer_suspends: int | None

    def column(self) -> str:
        return _join(
            [
                f"hThread = '{self.load_text}' @RVA 0x{self.load_rva:X} = "
                f"[base{self.field_offset:+#x}], base = '{self.base_text}' "
                f"@RVA 0x{self.base_rva:X}",
                f"field +0x{self.field_offset:X} receives the {BEGIN_THREAD_EX} return value "
                f"at RVA 0x{self.producer_store_rva:X} of function "
                f"[0x{self.producer_function[0]:X},0x{self.producer_function[1]:X})",
                f"{BEGIN_THREAD_EX} call site RVA 0x{self.producer_callsite:X}, direct rel32 "
                f"callers: "
                + (", ".join(f"RVA 0x{item:X}" for item in self.producer_callers) or "none"),
                f"producer calls {SUSPEND_THREAD_API}: "
                + (
                    f"yes, RVA 0x{self.producer_suspends:X}"
                    if self.producer_suspends is not None
                    else "no"
                ),
            ]
        )


@dataclass(frozen=True, slots=True)
class ArmFacts:
    """The alternative arm of the same conditional."""

    kind: str
    callsite: int
    text: str
    first_argument: str
    second_argument: str

    def column(self) -> str:
        return (
            f"{self.kind} at RVA 0x{self.callsite:X} '{self.text}', "
            f"RCX={self.first_argument}, RDX={self.second_argument}"
        )


@dataclass(frozen=True, slots=True)
class ApcSite:
    """One audited QueueUserAPC call site with every derived fact attached."""

    callsite: int
    function: tuple[int, int, int]
    function_va: int
    function_fully_decoded: bool
    direct_callers: tuple[int, ...]
    data_slots: tuple[int, ...]
    target: TargetFacts
    target_load_rva: int
    target_load_text: str
    thread_load_rva: int
    thread_load_text: str
    base_load_rva: int
    base_load_text: str
    third_argument: str
    handle: HandleOrigin
    global_read_rva: int
    global_read_text: str
    global_read_width: int
    global_facts: GlobalFacts
    selector: Guard | None
    guards: tuple[Guard, ...]
    arm: ArmFacts
    post_call: str
    returns_checked: bool
    alertable_wait_rva: int | None
    activation: str
    confidence: str
    confidence_notes: tuple[str, ...]

    def row(self) -> dict[str, str]:
        return {
            "callsite": f"0x{self.callsite:X}",
            "fn": self.column_fn(),
            "target": self.column_target(),
            "args": self.column_args(),
            "global read/write": self.column_global(),
            "branch condition": self.column_branch(),
            "activation status": self.activation,
            "confidence": self.column_confidence(),
        }

    def column_fn(self) -> str:
        begin, end, index = self.function
        callers = ", ".join(f"RVA 0x{item:X}" for item in self.direct_callers) or "none"
        decoded = (
            "decodes end to end"
            if self.function_fully_decoded
            else "linear sweep desynchronises"
        )
        reached = [
            "direct rel32" if self.direct_callers else "no direct rel32",
            "data pointer" if self.data_slots else "no data pointer",
        ]
        return _join(
            [
                f"IMAGE_RUNTIME_FUNCTION[{index}] [0x{begin:X},0x{end:X}) size 0x{end - begin:X}",
                f"sweep of the range {decoded}",
                f"direct rel32 callers of RVA 0x{begin:X}: {callers}",
                f"data slots storing the entry VA 0x{self.function_va:X} (RVA 0x{begin:X}): "
                f"{_slot_list(self.data_slots) or 'none'}",
                f"entry reach: {', '.join(reached)}"
                + (
                    ""
                    if self.direct_callers or self.data_slots
                    else " - referenced by neither form"
                ),
            ]
        )

    def column_target(self) -> str:
        return _join(
            [
                self.target.column(),
                f"argument built by '{self.target_load_text}' @RVA 0x{self.target_load_rva:X}",
            ]
        )

    def column_args(self) -> str:
        return _join(
            [
                f"RCX = '{self.target_load_text}' @RVA 0x{self.target_load_rva:X} "
                f"-> RVA 0x{self.target.rva:X}",
                f"RDX = '{self.thread_load_text}' @RVA 0x{self.thread_load_rva:X} "
                f"(hThread)",
                f"R8  = {self.third_argument}",
                f"base register of the hThread load: '{self.base_load_text}' "
                f"@RVA 0x{self.base_load_rva:X}",
                self.handle.column(),
                "argument provenance is the last definition on a linear backward walk inside the "
                "enclosing IMAGE_RUNTIME_FUNCTION: forward branches are crossed and volatile "
                "registers stop at calls, so this is a pre-image and not a dominator proof",
            ]
        )

    def column_global(self) -> str:
        return self.global_facts.column(
            self.global_read_rva, self.global_read_text, self.global_read_width
        )

    def column_branch(self) -> str:
        selector = (
            self.selector.describe()
            if self.selector is not None
            else "<no selector branch resolved>"
        )
        guards = (
            "guards in front of the block: " + _join(guard.predicate for guard in self.guards)
            if self.guards
            else "guards in front of the block: none inside the scanned window"
        )
        return _join(
            [
                f"arm selector: {selector}",
                guards,
                f"selector reads the switch with '{self.global_read_text}' "
                f"@RVA 0x{self.global_read_rva:X}",
                f"alternative arm: {self.arm.column()}",
            ]
        )

    def column_confidence(self) -> str:
        if not self.confidence_notes:
            return self.confidence
        return f"{self.confidence} ({_join(self.confidence_notes)})"


@dataclass(slots=True)
class AuditResult:
    """Everything one audit run produced."""

    image: Image
    sites: list[ApcSite]
    target: TargetFacts
    global_facts: GlobalFacts
    handle: HandleOrigin
    queue_user_apc_sites: list[int]
    terminate_thread_sites: list[int]
    rows: list[dict[str, str]] = field(default_factory=list)
    checks: list[common.Check] = field(default_factory=list)

    @property
    def failed(self) -> list[common.Check]:
        return [check for check in self.checks if not check.ok]







def _function_fully_decoded(image: Image, begin: int, end: int) -> bool:
    """True when the sweep of the range ends exactly on the range end."""
    decoded = image.function_instructions(begin, end)
    if not decoded:
        return False
    last = decoded[-1]
    return last.address - image.image_base + last.size == end


def _build_target_facts(image: Image, rva: int, apc_load_rva: int) -> TargetFacts:
    va = common.rva_to_va(image.pe, rva)
    instructions: list[capstone.CsInsn] = []
    consumed = 0
    for instruction in image.decode(rva, rva + TARGET_DECODE_BYTES):
        instructions.append(instruction)
        consumed = instruction.address - image.image_base + instruction.size - rva
        if instruction.mnemonic in _TERMINATORS:
            break
    window = image.code[
        image.rva_to_offset(rva) : image.rva_to_offset(rva) + consumed
    ]
    tail = image.code[
        image.rva_to_offset(rva) + consumed
        : image.rva_to_offset(rva) + consumed + TARGET_TAIL_BYTES
    ]
    xrefs = image.rip_xrefs(rva, rva)
    return TargetFacts(
        rva=rva,
        va=va,
        instructions=tuple(image.insn_text(instruction) for instruction in instructions),
        consumed_bytes=window.hex(" "),
        tail_bytes=tail.hex(" "),
        has_unwind_entry=image.runtime_function(rva) is not None,
        rip_xref_count=len(xrefs),
        apc_load_count=sum(1 for item in xrefs if item["rva"] == apc_load_rva),
        data_slot_rvas=tuple(image.data_pointer_rvas(va)),
    )


def _build_global_facts(image: Image, rva: int) -> GlobalFacts:
    section = common.section_for_rva(image.pe, rva)
    raw = common.rva_to_raw(image.pe, rva)
    file_value = struct.unpack_from("<I", image.blob, raw)[0] if raw is not None else 0
    return GlobalFacts(
        rva=rva,
        va=common.rva_to_va(image.pe, rva),
        section=section.name if section is not None else "<unmapped>",
        file_value=file_value,
        has_base_relocation=rva in image.base_relocations(),
        references=tuple(image.rip_xrefs(rva, rva)),
        neighbourhood=tuple(
            image.rip_xrefs(rva - GLOBAL_NEIGHBOURHOOD_RADIUS, rva + GLOBAL_NEIGHBOURHOOD_RADIUS)
        ),
        imm64_hits=image.count_occurrences(struct.pack("<Q", common.rva_to_va(image.pe, rva))),
        imm32_va_hits=image.count_occurrences(
            struct.pack("<I", common.rva_to_va(image.pe, rva) & 0xFFFFFFFF)
        ),
        imm32_rva_hits=image.count_occurrences(struct.pack("<I", rva)),
    )


def _find_producer_store(image: Image, field_offset: int) -> tuple[int, int] | None:
    """The store that puts a BEGIN_THREAD_EX return value into [reg+field_offset]."""
    matches: list[tuple[int, int]] = []
    for offset in image.indirect_call_offsets(image.iat_slot(BEGIN_THREAD_EX)):
        callsite = image.offset_to_rva(offset)
        for instruction in image.decode(callsite + 6, callsite + 6 + 0x20):
            if instruction.mnemonic != "mov" or len(instruction.operands) < 2:
                continue
            destination, source = instruction.operands[0], instruction.operands[1]
            if destination.type != capstone.x86.X86_OP_MEM or destination.mem.disp != field_offset:
                continue
            if (
                source.type != capstone.x86.X86_OP_REG
                or _full_register(source.reg) != capstone.x86.X86_REG_RAX
            ):
                continue
            matches.append((callsite, instruction.address - image.image_base))
            break
    return matches[0] if len(matches) == 1 else None


def _build_handle_origin(
    image: Image, field_offset: int, load_rva: int, load_text: str, base_rva: int, base_text: str
) -> HandleOrigin:
    producer = _find_producer_store(image, field_offset)
    if producer is None:
        raise LookupError(f"no unique {BEGIN_THREAD_EX} store into +0x{field_offset:X}")
    callsite, store_rva = producer
    function = image.runtime_function(store_rva)
    if function is None:
        raise LookupError(f"producer store RVA 0x{store_rva:X} has no IMAGE_RUNTIME_FUNCTION entry")
    callers = tuple(
        image.offset_to_rva(offset) for offset in image.direct_call_offsets(function[0])
    )
    suspend = _iat_call_in_range(
        image, image.iat_slot(SUSPEND_THREAD_API), function[0], function[1]
    )
    return HandleOrigin(
        field_offset=field_offset,
        load_rva=load_rva,
        load_text=load_text,
        base_rva=base_rva,
        base_text=base_text,
        producer_callsite=callsite,
        producer_store_rva=store_rva,
        producer_function=function,
        producer_callers=callers,
        producer_suspends=suspend,
    )


def _argument_constant(
    image: Image, preimage: Sequence[capstone.CsInsn], register: int
) -> str:
    definition = _defining_site(image, preimage, register)
    if definition is None:
        return "<unresolved>"
    rva, text = definition
    instruction = image.instruction_at(rva)
    if instruction is None:
        return f"{text} @RVA 0x{rva:X}"
    return f"{_constant_of(image, instruction)} (from '{text}' @RVA 0x{rva:X})"


def _arm_argument(
    image: Image, function_begin: int, function_end: int, anchor_rva: int, register: int
) -> str:
    """Argument text of the alternative arm, walked from its own call site.

    The walk crosses the selector branch so that definitions inside the
    alternative arm are preferred over the ones in the shared path in front of
    the split, and it stops at the first call for volatile registers.
    """
    preimage = _common_preimage(image, function_begin, function_end, anchor_rva, register)
    definition = _defining_site(image, preimage, register)
    if definition is None:
        return "<unresolved>"
    rva, text = definition
    instruction = image.instruction_at(rva)
    constant = _constant_of(image, instruction) if instruction is not None else "<unresolved>"
    return f"{text} @RVA 0x{rva:X} = {constant}"


def _post_call_text(image: Image, callsite: int) -> str:
    parts = [
        image.annotated_text(instruction)
        for instruction in image.decode(callsite + 6, callsite + 6 + 0x40)[:POST_CALL_TEXT_INSNS]
    ]
    return ", ".join(parts)


def _audit_site(
    image: Image,
    callsite: int,
    terminate_thread_sites: list[int],
    alertable_wait_offsets: list[int],
) -> ApcSite:
    """Audit one QueueUserAPC call site and return every derived fact about it.

    Nothing here is hard coded: the enclosing function, the arm split, the switch
    address, the thread handle producer and the alternative arm are all located
    from the file image, and an unresolved step raises instead of guessing.
    """
    notes: list[str] = []
    function = image.runtime_function(callsite)
    if function is None:
        raise LookupError(
            f"{QUEUE_USER_APC} call site RVA 0x{callsite:X} has no IMAGE_RUNTIME_FUNCTION entry"
        )
    begin, end, _ = function

    block = _block_preimage(image, begin, end, callsite, capstone.x86.X86_REG_RCX)
    if not block:
        raise LookupError(f"the call block at RVA 0x{callsite:X} does not decode")
    block_start = block[0].address - image.image_base
    target_load = _defining_site(image, block, capstone.x86.X86_REG_RCX)
    if target_load is None:
        raise LookupError(f"RCX is not defined inside the call block at RVA 0x{callsite:X}")
    target_load_rva, target_load_text = target_load

    target_instruction = image.instruction_at(target_load_rva)
    target_rva = image.resolve_rip(target_instruction) if target_instruction is not None else None
    if target_rva is None:
        raise LookupError(f"RCX is not RIP-relative at RVA 0x{target_load_rva:X}")

    selector, guards = _guard_chain(image, begin, end, block_start)
    common_anchor = block_start if selector is None else selector.jcc_rva
    if selector is None:
        notes.append(f"no branch selects the block at RVA 0x{block_start:X}")

    thread_preimage = _common_preimage(
        image, begin, end, common_anchor, capstone.x86.X86_REG_RDX
    )
    thread_load = _defining_site(image, thread_preimage, capstone.x86.X86_REG_RDX)
    if thread_load is None:
        notes.append("RDX provenance unresolved in front of the arm split")
        raise LookupError(f"RDX provenance unresolved at RVA 0x{callsite:X}")
    thread_load_rva, thread_load_text = thread_load

    thread_instruction = image.instruction_at(thread_load_rva)
    memory = next(
        (
            operand
            for operand in (thread_instruction.operands if thread_instruction else ())
            if operand.type == capstone.x86.X86_OP_MEM
        ),
        None,
    )
    if memory is None or memory.mem.base == 0:
        raise LookupError(f"RDX is not a memory load at RVA 0x{thread_load_rva:X}")
    field_offset = int(memory.mem.disp)
    base_register = _full_register(memory.mem.base)
    base_load = _defining_site(
        image, _common_preimage(image, begin, end, thread_load_rva, base_register), base_register
    )
    if base_load is None:
        raise LookupError(
            f"base register of the hThread load unresolved at RVA 0x{thread_load_rva:X}"
        )
    base_load_rva, base_load_text = base_load

    handle = _build_handle_origin(
        image, field_offset, thread_load_rva, thread_load_text, base_load_rva, base_load_text
    )

    if selector is None:
        global_read_rva, global_read_text, global_read_width, global_rva = (
            0,
            "<unresolved>",
            0,
            0,
        )
    else:
        loaded = (
            _rip_load_into(image, begin, end, selector.flag_rva, selector.flag_register)
            if selector.flag_register is not None
            else None
        )
        if loaded is None:
            notes.append("the selector flag register is not loaded from a RIP-relative address")
            global_read_rva, global_read_text, global_read_width, global_rva = (
                0,
                "<unresolved>",
                0,
                0,
            )
        else:
            global_read_rva, global_read_text, global_rva, global_read_width = loaded
    global_facts = _build_global_facts(image, global_rva) if global_rva else _empty_global_facts()

    arm_sites = [site for site in terminate_thread_sites if begin <= site < end]
    if arm_sites:
        arm_rva = min(arm_sites, key=lambda item: abs(item - callsite))
        arm_instruction = image.instruction_at(arm_rva)
        arm = ArmFacts(
            kind=TERMINATE_THREAD,
            callsite=arm_rva,
            text=image.insn_text(arm_instruction) if arm_instruction else "<undecoded>",
            first_argument=_arm_argument(
                image, begin, end, arm_rva, capstone.x86.X86_REG_RCX
            ),
            second_argument=_arm_argument(
                image, begin, end, arm_rva, capstone.x86.X86_REG_RDX
            ),
        )
    else:
        notes.append(f"no {TERMINATE_THREAD} call site inside the enclosing function")
        arm = ArmFacts(TERMINATE_THREAD, 0, "<none>", "<unresolved>", "<unresolved>")

    target = _build_target_facts(image, target_rva, target_load_rva)
    alertable = next(
        (
            image.offset_to_rva(offset)
            for offset in alertable_wait_offsets
            if begin <= image.offset_to_rva(offset) < end
        ),
        None,
    )
    returns_checked = _return_value_checked(image, callsite)
    guards_tuple = tuple(guards)
    predicates = [guard.predicate for guard in guards_tuple]
    if selector is not None:
        predicates.append(selector.predicate)
    activation = _join(
        [
            "static-live: the block is a branch target inside a registered IMAGE_RUNTIME_FUNCTION",
            f"switch file image value {_hex(global_facts.file_value)} with "
            f"{len(global_facts.writes)} static writer(s) found, so the {QUEUE_USER_APC} arm "
            f"is the statically selected arm of the selector",
            "runtime predicates for the block: " + (_join(predicates) or "none"),
            f"{QUEUE_USER_APC} return value {'is tested' if returns_checked else 'is discarded'}",
            f"instructions after the call: {_post_call_text(image, callsite)}",
            f"{ALERTABLE_WAIT_API} call in the same function: "
            + (f"present at RVA 0x{alertable:X}" if alertable is not None else "absent"),
            f"the routine address holds {_join(target.instructions)} and the handle is a "
            f"self-created {BEGIN_THREAD_EX} handle, so no static evidence points at a foreign "
            f"thread or at code injected through this arm",
        ]
    )
    for label, value in (
        ("RCX", target_load_text),
        ("RDX", thread_load_text),
        ("base of the hThread load", base_load_text),
    ):
        if not value:
            notes.append(f"{label} unresolved")
    if "<unresolved>" in _argument_constant(image, block, capstone.x86.X86_REG_R8):
        notes.append("R8 unresolved")
    if selector is None:
        notes.append("no selector branch")
    if any("<unresolved>" in guard.predicate for guard in guards_tuple):
        notes.append("a guard predicate is unresolved")
    if "<unresolved>" in arm.first_argument or "<unresolved>" in arm.second_argument:
        notes.append(f"{TERMINATE_THREAD} arm arguments unresolved")
    confidence_notes = tuple(dict.fromkeys(notes))
    return ApcSite(
        callsite=callsite,
        function=function,
        function_va=common.rva_to_va(image.pe, begin),
        function_fully_decoded=_function_fully_decoded(image, begin, end),
        direct_callers=tuple(
            image.offset_to_rva(offset) for offset in image.direct_call_offsets(begin)
        ),
        data_slots=tuple(image.data_pointer_rvas(common.rva_to_va(image.pe, begin))),
        target=target,
        target_load_rva=target_load_rva,
        target_load_text=target_load_text,
        thread_load_rva=thread_load_rva,
        thread_load_text=thread_load_text,
        base_load_rva=base_load_rva,
        base_load_text=base_load_text,
        third_argument=_argument_constant(image, block, capstone.x86.X86_REG_R8),
        handle=handle,
        global_read_rva=global_read_rva,
        global_read_text=global_read_text,
        global_read_width=global_read_width,
        global_facts=global_facts,
        selector=selector,
        guards=guards_tuple,
        arm=arm,
        post_call=_post_call_text(image, callsite),
        returns_checked=returns_checked,
        alertable_wait_rva=alertable,
        activation=activation,
        confidence="high" if not confidence_notes else "medium",
        confidence_notes=confidence_notes,
    )


def _empty_global_facts() -> GlobalFacts:
    """Placeholder census used when the selector branch could not be resolved."""
    return GlobalFacts(
        rva=0,
        va=0,
        section="<unresolved>",
        file_value=0,
        has_base_relocation=False,
        references=(),
        neighbourhood=(),
        imm64_hits=0,
        imm32_va_hits=0,
        imm32_rva_hits=0,
    )


def audit(specimen: Path) -> AuditResult:
    """Run the whole audit over one specimen file and evaluate its invariants."""
    image = Image(specimen)
    queue_offsets = image.indirect_call_offsets(image.iat_slot(QUEUE_USER_APC))
    terminate_offsets = image.indirect_call_offsets(image.iat_slot(TERMINATE_THREAD))
    queue_sites = [image.offset_to_rva(offset) for offset in queue_offsets]
    terminate_sites = [image.offset_to_rva(offset) for offset in terminate_offsets]
    alertable_offsets = image.indirect_call_offsets(image.iat_slot(ALERTABLE_WAIT_API))

    sites = [
        _audit_site(image, callsite, terminate_sites, alertable_offsets) for callsite in queue_sites
    ]
    result = AuditResult(
        image=image,
        sites=sites,
        target=sites[0].target,
        global_facts=sites[0].global_facts,
        handle=sites[0].handle,
        queue_user_apc_sites=queue_sites,
        terminate_thread_sites=terminate_sites,
        rows=[site.row() for site in sites],
    )
    result.checks = _build_checks(result)
    return result


def _build_checks(result: AuditResult) -> list[common.Check]:
    """Invariants the emitted evidence must satisfy, one Check per claim."""
    image = result.image
    first = result.sites[0]
    target_section = common.section_for_rva(image.pe, first.target.rva)
    target_bytes = common.read_rva(image.pe, first.target.rva, 1)
    checks = [
        common.Check(
            "queue_user_apc_direct_call_sites",
            EXPECTED_QUEUE_USER_APC_SITES,
            len(result.queue_user_apc_sites),
            len(result.queue_user_apc_sites) == EXPECTED_QUEUE_USER_APC_SITES,
        ),
        common.Check(
            "terminate_thread_direct_call_sites",
            EXPECTED_TERMINATE_THREAD_SITES,
            len(result.terminate_thread_sites),
            len(result.terminate_thread_sites) == EXPECTED_TERMINATE_THREAD_SITES,
        ),
        common.Check(
            "terminate_thread_sites_pair_with_apc_sites",
            EXPECTED_QUEUE_USER_APC_SITES,
            len(result.terminate_thread_sites),
            len(result.terminate_thread_sites) == len(result.queue_user_apc_sites),
        ),
        common.Check(
            "single_shared_apc_routine_target",
            1,
            len({site.target.rva for site in result.sites}),
            len({site.target.rva for site in result.sites}) == 1,
        ),
        common.Check(
            "apc_routine_target_rva",
            _hex(EXPECTED_QUEUE_USER_APC_TARGET),
            _hex(first.target.rva),
            first.target.rva == EXPECTED_QUEUE_USER_APC_TARGET,
        ),
        common.Check(
            "apc_routine_first_byte_is_ret",
            "0xc3",
            f"0x{target_bytes[0]:02x}",
            target_bytes[0] == 0xC3,
        ),
        common.Check(
            "apc_routine_target_is_no_enclosing_function_entry",
            0,
            sum(1 for site in result.sites if site.target.rva == site.function[0]),
            all(site.target.rva != site.function[0] for site in result.sites),
        ),
        common.Check(
            "apc_routine_target_in_code_section",
            CODE_SECTION_NAME,
            target_section.name if target_section is not None else "<unmapped>",
            target_section is not None and target_section.name == CODE_SECTION_NAME,
        ),
        common.Check(
            "single_shared_mode_switch",
            1,
            len({site.global_facts.rva for site in result.sites}),
            len({site.global_facts.rva for site in result.sites}) == 1,
        ),
        common.Check(
            "mode_switch_va",
            _hex(EXPECTED_GLOBAL_VA),
            _hex(result.global_facts.va),
            result.global_facts.va == EXPECTED_GLOBAL_VA,
        ),
        common.Check(
            "mode_switch_file_value_is_zero",
            0,
            result.global_facts.file_value,
            result.global_facts.file_value == 0,
        ),
        common.Check(
            "mode_switch_static_writers",
            0,
            len(result.global_facts.writes),
            not result.global_facts.writes,
        ),
        common.Check(
            "mode_switch_references_equal_apc_site_count",
            len(result.queue_user_apc_sites),
            len(result.global_facts.reads),
            len(result.global_facts.reads) == len(result.queue_user_apc_sites),
        ),
        common.Check(
            "mode_switch_reads_precede_every_apc_site",
            "0 write, 1 read per function",
            _join(
                f"0x{site.global_read_rva:X}:{site.callsite:X}"
                for site in result.sites
                if site.global_read_rva >= site.callsite
            )
            or "all reads precede their call site",
            all(site.global_read_rva < site.callsite for site in result.sites),
        ),
        common.Check(
            "mode_switch_absolute_address_absent",
            "0 imm64, 0 imm32",
            f"{result.global_facts.imm64_hits} imm64, {result.global_facts.imm32_va_hits} imm32",
            result.global_facts.imm64_hits == 0 and result.global_facts.imm32_va_hits == 0,
        ),
        common.Check(
            "mode_switch_has_no_base_relocation",
            False,
            first.global_facts.has_base_relocation,
            not first.global_facts.has_base_relocation,
        ),
        common.Check(
            "single_shared_thread_handle_field",
            1,
            len({site.handle.field_offset for site in result.sites}),
            len({site.handle.field_offset for site in result.sites}) == 1,
        ),
        common.Check(
            "single_shared_thread_handle_producer",
            1,
            len({site.handle.producer_store_rva for site in result.sites}),
            len({site.handle.producer_store_rva for site in result.sites}) == 1,
        ),
        common.Check(
            "thread_handle_producer_never_suspends",
            "absent",
            first.handle.producer_suspends,
            first.handle.producer_suspends is None,
        ),
        common.Check(
            "every_apc_site_resolves_its_arguments",
            EXPECTED_QUEUE_USER_APC_SITES,
            sum(
                1
                for site in result.sites
                if site.target_load_text and site.thread_load_text and site.base_load_text
            ),
            all(
                site.target_load_text and site.thread_load_text and site.base_load_text
                for site in result.sites
            ),
        ),
        common.Check(
            "every_apc_site_has_a_selector_branch",
            EXPECTED_QUEUE_USER_APC_SITES,
            sum(1 for site in result.sites if site.selector is not None),
            all(site.selector is not None for site in result.sites),
        ),
        common.Check(
            "every_apc_site_has_a_terminate_thread_alternative",
            EXPECTED_QUEUE_USER_APC_SITES,
            sum(1 for site in result.sites if site.arm.callsite),
            all(site.arm.callsite for site in result.sites),
        ),
        common.Check(
            "alternative_arms_are_distinct_per_site",
            EXPECTED_QUEUE_USER_APC_SITES,
            len({site.arm.callsite for site in result.sites}),
            len({site.arm.callsite for site in result.sites}) == len(result.queue_user_apc_sites),
        ),
        common.Check(
            "alternative_arms_lie_in_front_of_their_apc_site",
            "one per site",
            _join(
                f"0x{site.arm.callsite:X}<0x{site.callsite:X}"
                for site in result.sites
                if not site.arm.callsite or site.arm.callsite >= site.callsite
            )
            or "all arms precede their apc site",
            all(site.arm.callsite and site.arm.callsite < site.callsite for site in result.sites),
        ),
        common.Check(
            "enclosing_functions_collapse_two_sites_into_one",
            EXPECTED_QUEUE_USER_APC_SITES - 1,
            len({site.function[0] for site in result.sites}),
            len({site.function[0] for site in result.sites}) == EXPECTED_QUEUE_USER_APC_SITES - 1,
        ),
        common.Check(
            "enclosing_functions_decode_end_to_end",
            EXPECTED_QUEUE_USER_APC_SITES,
            sum(1 for site in result.sites if site.function_fully_decoded),
            all(site.function_fully_decoded for site in result.sites),
        ),
        common.Check(
            "every_row_scored_high_confidence",
            EXPECTED_QUEUE_USER_APC_SITES,
            sum(1 for site in result.sites if site.confidence == "high"),
            all(site.confidence == "high" for site in result.sites),
        ),
    ]
    return checks







def _read_rows(path: Path) -> list[dict[str, str]]:
    """Read the evidence csv back, insisting on the exact audited column order."""
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != CSV_COLUMNS:
            raise ValueError(f"unexpected csv header: {reader.fieldnames}")
        return [dict(row) for row in reader]


def _verify_rows(path: Path, expected: list[dict[str, str]]) -> int:
    """Compare the stored csv with the regenerated rows and report every difference."""
    actual = _read_rows(path)
    if actual == expected:
        print(f"csv       {path} matches the regenerated rows")
        return 0
    print(f"csv       {path} differs from the regenerated rows")
    for index in range(max(len(actual), len(expected))):
        left = actual[index] if index < len(actual) else None
        right = expected[index] if index < len(expected) else None
        if left == right:
            continue
        print(f"FAIL row {index}:")
        for column in CSV_COLUMNS:
            stored = (left or {}).get(column, "<missing>")
            fresh = (right or {}).get(column, "<missing>")
            if stored != fresh:
                print(f"  {column}\n    stored {stored}\n    fresh  {fresh}")
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description="Static audit of the QueueUserAPC call sites in adhesive.dll"
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument(
        "--csv", type=Path, default=root / "reverse" / "evidence" / "apc_sites.csv"
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="compare the stored csv with the regenerated rows instead of writing it",
    )
    parser.add_argument("--max-report", type=int, default=20, help="failed checks to print")
    args = parser.parse_args(argv)

    specimen = args.specimen.resolve()
    print(f"script    {script.relative_to(root).as_posix()}")
    print(f"sha256    {common.sha256_file(script)}")
    print(
        f"specimen  {specimen.relative_to(root).as_posix()} size={specimen.stat().st_size} "
        f"sha256={common.sha256_file(specimen)}"
    )

    result = audit(specimen)
    try:
        print(
            f"apc       {len(result.queue_user_apc_sites)} {QUEUE_USER_APC} call sites: "
            + ", ".join(f"0x{item:X}" for item in result.queue_user_apc_sites)
        )
        print(
            f"terminate {len(result.terminate_thread_sites)} {TERMINATE_THREAD} call sites: "
            + ", ".join(f"0x{item:X}" for item in result.terminate_thread_sites)
        )
        print(
            f"target    RVA {_hex(result.target.rva)} = "
            + _join(result.target.instructions)
            + f" | unwind entry: {result.target.has_unwind_entry}"
        )
        print(
            f"switch    RVA {_hex(result.global_facts.rva)} (VA {_hex(result.global_facts.va)}) "
            f"file value {_hex(result.global_facts.file_value)} | "
            f"{len(result.global_facts.reads)} reads / {len(result.global_facts.writes)} writes"
        )
        print(
            f"handle    field +0x{result.handle.field_offset:X} from {BEGIN_THREAD_EX} store "
            f"RVA {_hex(result.handle.producer_store_rva)} in function "
            f"[{_hex(result.handle.producer_function[0])},"
            f"{_hex(result.handle.producer_function[1])})"
        )
        print(
            f"functions {len({site.function[0] for site in result.sites})} distinct "
            f"enclosing functions"
        )

        if args.check_only:
            try:
                status = _verify_rows(args.csv, result.rows)
            except (OSError, ValueError) as error:
                print(f"FAIL csv unreadable: {error}")
                status = 1
        else:
            common.write_csv(args.csv, result.rows, CSV_COLUMNS)
            print(
                f"csv       {args.csv.relative_to(root).as_posix()} written with "
                f"{len(result.rows)} rows"
            )
            status = 0

        failed = result.failed
        for check in failed[: args.max_report]:
            print(
                f"FAIL {check.name}: expected={common.scalar_text(check.expected)} "
                f"actual={common.scalar_text(check.actual)}"
            )
        if len(failed) > args.max_report:
            print(f"FAIL ... {len(failed) - args.max_report} further failed checks")
        print(f"checks    {len(result.checks) - len(failed)}/{len(result.checks)} matched")
        return 1 if failed or status else 0
    finally:
        result.image.close()


if __name__ == "__main__":
    raise SystemExit(main())
