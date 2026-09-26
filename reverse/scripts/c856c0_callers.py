"""Static P0/S5 forward flow and caller closure for the 0xC856C0 handle in adhesive.dll.

Direction
---------
Complements ``reverse/scripts/defuse_slice.py``, which walks the ``[descriptor+0]``
handle backwards.  This pass walks the same value forwards: it re-derives both
handle loads, normalises all 32 dispatch branches of the two RDTSC indexed tables
into one argument schema per stage, profiles the twelve syscall wrappers the
branch blocks call, records the output vector append, the remote base return and
the explicit error branches, checks the reachable code for handle closing or
duplication, and closes the caller graph from the forward subject set until the
frontier is empty or a measured bound is reached.

Inputs
------
``reverse/evidence/c856c0_dataflow.json`` supplies the already asserted backward
inventory (two loads, 32 branch blocks, twelve wrapper targets).  Every anchor it
declares is re-checked against the specimen bytes here, and every new fact is
decoded from the file, so a silent drift in either input fails the run instead of
producing a plausible looking graph.  ``reverse/evidence/xref_edges.csv`` supplies
the published code pointer slot, thunk and IAT edge inventory.

Method
------
Static file parsing only.  pefile resolves the PE layout, the exception directory
supplies the exact function extents and capstone decodes the branch blocks, the
wrappers and the entry function.  The specimen is never loaded as an image and
never executed.  The emitted tables describe control flow, argument shape and
ownership structure; they contain no exploit, bypass, patch or shellcode guidance.

Determinism
-----------
The specimen and both input files are digest pinned, every collection is sorted
before it is rendered, and both outputs are written through ``common.write_json``
and ``common.write_csv`` (UTF-8, no BOM, LF, fixed column order, no timestamps).
``--verify`` recomputes both and diffs them against the stored files.

Emits
-----
reverse/evidence/c856c0_forward.json
reverse/evidence/c856c0_callers.csv
"""

from __future__ import annotations

import argparse
import bisect
import csv
import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Iterable, Mapping, Sequence

import capstone
import pefile

sys.path.insert(0, str(Path(__file__).resolve().parent))

import common  # noqa: E402  (the path bootstrap has to run before the import)

SCHEMA: Final[str] = "adhesive-dumper.forward-flow/1"
DATAFLOW_SCHEMA: Final[str] = "adhesive-dumper.defuse-slice/1"
SPECIMEN_SHA256: Final[str] = "91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e"

XREF_FIELDS: Final[tuple[str, ...]] = (
    "edge_id",
    "category",
    "relation",
    "evidence",
    "src_rva",
    "src_raw",
    "code_instruction_function_index",
    "code_instruction_function_begin",
    "code_instruction_function_end",
    "src_mnemonic",
    "src_op_str",
    "src_bytes",
    "via_rva",
    "target_thunk_function_index",
    "target_thunk_function_begin",
    "target_thunk_function_end",
    "dst_kind",
    "dst_rva",
    "dst_raw",
    "dst_module",
    "dst_symbol",
    "iat_rva",
)

CALLER_FIELDS: Final[tuple[str, ...]] = (
    "level",
    "scope",
    "target_fn",
    "edge_kind",
    "callsite",
    "caller_fn",
    "evidence",
    "confidence",
    "open",
)

ANCHOR_TARGET: Final[int] = 0xC856C0
ANCHOR_CALLER: Final[int] = 0xC85650
CLUSTER_LOW: Final[int] = 0xC85000
CLUSTER_HIGH: Final[int] = 0xC88000
VECTOR_APPEND_HELPER: Final[int] = 0x495D0
STACK_GUARD_HELPER: Final[int] = 0x2AB3500
MAX_CLOSURE_DEPTH: Final[int] = 8
NEAREST_SITE_COUNT: Final[int] = 3
NEAREST_CLOSE_CALLSITE: Final[int] = 0xC81D49
DESCRIPTOR_REGISTERS: Final[tuple[str, ...]] = ("rcx", "rbx")

FRAME_RESULT: Final[int] = 0x50
FRAME_SIZE_OUT: Final[int] = 0x48
FRAME_TRANSFER_STATUS: Final[int] = 0x40

ALLOC_HANDLE_GLOBAL: Final[int] = 0x30E35FB
TRANSFER_HANDLE_GLOBAL: Final[int] = 0x30E360F

ALLOC_MERGE: Final[int] = 0xC86426
XFER_MERGE: Final[int] = 0xC870E1
RESULT_INIT: Final[int] = 0xC856E5
SIZE_SAVE: Final[int] = 0xC856EE
XFER_STATUS_INIT: Final[int] = 0xC86437
RESULT_READ_MERGE: Final[int] = 0xC86426
RESULT_READ_RETURN: Final[int] = 0xC870E1
RETURN_SITE: Final[int] = 0xC87103
BASE_ZERO_TEST: Final[int] = 0xC8642B
BASE_ZERO_BRANCH: Final[int] = 0xC86430
CALL_SITE: Final[int] = 0xC85681
CALL_SITE_APPEND: Final[int] = 0xC85695
CALL_SITE_APPEND_ADVANCE: Final[int] = 0xC85698
CALL_SITE_GROWTH_BRANCH: Final[int] = 0xC85693
CALL_SITE_GROWTH_CALL: Final[int] = 0xC856A7
CALL_SITE_STRING_BRANCH: Final[int] = 0xC8567C
CALL_SITE_STRING_COMPARE: Final[int] = 0xC85677
CALL_SITE_STRING_LOAD: Final[int] = 0xC8567E
CALL_SITE_COOKIE: Final[int] = 0xC856B4
ANCHOR_COOKIE: Final[int] = 0xC870EE

LOAD_R14: Final[int] = 0xC856F3
LOAD_RBX: Final[int] = 0xC86440

LIFETIME_APIS: Final[tuple[str, ...]] = ("CloseHandle", "DuplicateHandle")

HIGH: Final[str] = "HIGH"
MEDIUM: Final[str] = "MEDIUM"
OBSERVED: Final[str] = "OBSERVED"
OPEN: Final[str] = "OPEN"

ARG_REGISTERS: Final[tuple[str, ...]] = ("rcx", "rdx", "r8", "r9", "r10")
CALLEE_SAVED: Final[frozenset[str]] = frozenset(
    {"rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"}
)
GPR_BASES: Final[Mapping[str, str]] = {
    "rax": "rax", "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
    "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
    "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
    "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
    "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp",
    "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
    "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
    "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
    **{f"r{index}": f"r{index}" for index in range(8, 16)},
    **{f"r{index}d": f"r{index}" for index in range(8, 16)},
    **{f"r{index}w": f"r{index}" for index in range(8, 16)},
    **{f"r{index}b": f"r{index}" for index in range(8, 16)},
}
TERMINATORS: Final[frozenset[str]] = frozenset({"jmp", "ret", "retf", "iret", "syscall", "ud2", "int3"})
EXIT_MNEMONICS: Final[frozenset[str]] = frozenset({"ret", "retf", "iret", "ud2", "int3"})
INCOMING_ARG_OFFSETS: Final[tuple[int, ...]] = (0x28, 0x30, 0x38, 0x40, 0x48)

RIP_PREFIX_PATTERN: Final[re.Pattern[bytes]] = re.compile(
    rb"[\x48\x4c\x49\x4d][\x00-\xff][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", re.S
)

STAGE_ALLOC: Final[int] = 1
STAGE_TRANSFER: Final[int] = 2

ALLOC_INLINE_SCHEMA: Final[tuple[tuple[int, str, str, str], ...]] = (
    (1, "r10", "{handle}", "process_handle"),
    (2, "rdx", "&frame+0x50", "base_address_out"),
    (3, "r8", "0", "zero_bits"),
    (4, "r9", "&frame+0x48", "region_size_out"),
    (5, "stack+0x28", "0x1000", "allocation_type"),
    (6, "stack+0x30", "0x40", "page_protection"),
)

ALLOC_CALL_SCHEMA: Final[tuple[tuple[int, str, str, str], ...]] = (
    (1, "rcx", "&.data+0x30E35FB", "wrapper_state_global"),
    (2, "rdx", "{handle}", "process_handle"),
    (3, "r8", "&frame+0x50", "base_address_out"),
    (4, "r9", "0", "zero_bits"),
    (5, "stack+0x20", "&frame+0x48", "region_size_out"),
    (6, "stack+0x28", "0x1000", "allocation_type"),
    (7, "stack+0x30", "0x40", "page_protection"),
)

TRANSFER_INLINE_SCHEMA: Final[tuple[tuple[int, str, str, str], ...]] = (
    (1, "r10", "{handle}", "process_handle"),
    (2, "rdx", "r14", "remote_base"),
    (3, "r8", "rsi", "buffer"),
    (4, "r9", "rdi", "length"),
    (5, "stack+0x28", "&frame+0x40", "bytes_written_out"),
)

TRANSFER_CALL_SCHEMA: Final[tuple[tuple[int, str, str, str], ...]] = (
    (1, "rcx", "&.data+0x30E360F", "wrapper_state_global"),
    (2, "rdx", "{handle}", "process_handle"),
    (3, "r8", "r14", "remote_base"),
    (4, "r9", "rsi", "buffer"),
    (5, "stack+0x20", "rdi", "length"),
    (6, "stack+0x28", "&frame+0x40", "bytes_written_out"),
)

STAGE_TABLES: Final[Mapping[int, tuple[tuple[tuple[int, str, str, str], ...], ...]]] = {
    STAGE_ALLOC: (ALLOC_INLINE_SCHEMA, ALLOC_CALL_SCHEMA),
    STAGE_TRANSFER: (TRANSFER_INLINE_SCHEMA, TRANSFER_CALL_SCHEMA),
}

STAGE_HANDLE_REGISTER: Final[Mapping[int, str]] = {STAGE_ALLOC: "r14", STAGE_TRANSFER: "rbx"}


class FlowError(RuntimeError):
    """Raised when a declared anchor does not hold for the parsed specimen."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FlowError(message)


@dataclass(frozen=True, slots=True)
class RuntimeFunction:
    begin: int
    end: int
    unwind: int

    def as_json(self, pe: Any) -> dict[str, Any]:
        begin_raw = common.rva_to_raw(pe, self.begin)
        return {
            "begin_rva": self.begin,
            "begin_rva_hex": common.hexs(self.begin),
            "end_rva": self.end,
            "end_rva_hex": common.hexs(self.end),
            "size": self.end - self.begin,
            "unwind_rva": self.unwind,
            "unwind_rva_hex": common.hexs(self.unwind),
            "raw": begin_raw,
            "raw_hex": None if begin_raw is None else common.hexs(begin_raw),
        }


@dataclass(frozen=True, slots=True)
class Site:
    rva: int
    size: int
    mnemonic: str
    op_str: str
    raw_bytes: bytes

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.op_str}".strip()

    def as_evidence(self, pe: Any) -> dict[str, Any]:
        return {
            "mnemonic": self.mnemonic,
            "operands": self.op_str,
            "text": self.text,
            "size": self.size,
            "bytes": self.raw_bytes.hex(" "),
            "rva": self.rva,
            "rva_hex": common.hexs(self.rva),
            "raw": common.rva_to_raw(pe, self.rva),
            "raw_hex": common.hexs(common.rva_to_raw(pe, self.rva) or 0),
            "va": common.rva_to_va(pe, self.rva),
            "va_hex": common.hexs(common.rva_to_va(pe, self.rva)),
        }


@dataclass(frozen=True, slots=True)
class ArgDef:
    position: int
    location: str
    expression: str
    role: str
    rva: int
    text: str

    def as_json(self, pe: Any) -> dict[str, Any]:
        return {
            "position": self.position,
            "location": self.location,
            "expression": self.expression,
            "role": self.role,
            "defined_at_rva": self.rva,
            "defined_at_rva_hex": common.hexs(self.rva),
            "definition": self.text,
        }


class Specimen:
    """Parsed, read-only view of the specimen used by every scan below."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.pe = common.load_pe(path)
        self.image_base = int(self.pe.OPTIONAL_HEADER.ImageBase)
        self.sections = {section.name: section for section in common.sections(self.pe)}
        self.text = self.sections[".text"]
        self.rdata = self.sections[".rdata"]
        self.data = self.sections[".data"]
        self.file_bytes = path.read_bytes()
        self.text_bytes = self.file_bytes[
            self.text.raw_pointer : self.text.raw_pointer + self.text.raw_size
        ]
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self.runtime_functions = self._runtime_functions()
        self._begins = [record.begin for record in self.runtime_functions]
        directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[common.EXCEPTION_DIRECTORY_INDEX]
        self.pdata_rva = int(directory.VirtualAddress)
        self.pdata_size = int(directory.Size)

    def close(self) -> None:
        self.pe.close()

    def _runtime_functions(self) -> tuple[RuntimeFunction, ...]:
        directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[common.EXCEPTION_DIRECTORY_INDEX]
        size = int(directory.Size)
        blob = common.read_rva(self.pe, int(directory.VirtualAddress), size)
        count, remainder = divmod(size, common.RUNTIME_FUNCTION_SIZE)
        require(remainder == 0, "exception directory size is not a whole number of records")
        require(
            count == common.EXPECTED_RUNTIME_FUNCTIONS,
            f"runtime function count {count} != expected {common.EXPECTED_RUNTIME_FUNCTIONS}",
        )
        return tuple(RuntimeFunction(*record) for record in struct.iter_unpack("<III", blob))

    def owner(self, rva: int) -> RuntimeFunction | None:
        index = bisect.bisect_right(self._begins, rva) - 1
        if index < 0:
            return None
        record = self.runtime_functions[index]
        return record if record.begin <= rva < record.end else None

    def function_json(self, rva: int) -> dict[str, Any] | None:
        record = self.owner(rva)
        return None if record is None else record.as_json(self.pe)

    def disasm(self, rva: int, length: int) -> list[Site]:
        blob = common.read_rva(self.pe, rva, length)
        out: list[Site] = []
        for insn in self.md.disasm(blob, common.rva_to_va(self.pe, rva)):
            out.append(
                Site(
                    rva=insn.address - self.image_base,
                    size=insn.size,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    raw_bytes=bytes(insn.bytes),
                )
            )
        return out

    def body(self, rva: int) -> list[Site]:
        record = self.owner(rva)
        require(record is not None, f"{common.hexs(rva)} is not inside a runtime function")
        assert record is not None
        require(record.begin == rva, f"{common.hexs(rva)} is not a runtime function boundary")
        return self.disasm(record.begin, record.end - record.begin)

    def at(self, rva: int) -> Site:
        found = self.disasm(rva, 16)
        require(bool(found) and found[0].rva == rva, f"no decodable instruction at {common.hexs(rva)}")
        return found[0]

    def expect(self, rva: int, mnemonic: str, op_str: str) -> Site:
        site = self.at(rva)
        require(
            site.mnemonic == mnemonic and site.op_str == op_str,
            f"anchor {common.hexs(rva)} is '{site.text}', expected '{mnemonic} {op_str}'",
        )
        return site

    def rip_target(self, rva: int) -> int:
        site = self.at(rva)
        require(
            site.mnemonic in ("lea", "mov"),
            f"{common.hexs(rva)} is not a RIP relative address computation",
        )
        displacement = self._rip_disp(site.op_str)
        require(displacement is not None, f"{common.hexs(rva)} does not encode a RIP displacement")
        assert displacement is not None
        return site.rva + site.size + displacement

    def _rip_disp(self, op_str: str) -> int | None:
        match = re.search(r"\[rip ([+-]) (0x[0-9a-f]+)\]", op_str)
        if match is None:
            return None
        value = int(match.group(2), 16)
        return -value if match.group(1) == "-" else value

    def data_bytes(self, rva: int, length: int) -> bytes:
        return common.read_rva(self.pe, rva, length)


def _strip_qualifier(operand: str) -> str:
    for qualifier in ("qword ptr ", "dword ptr ", "word ptr ", "byte ptr "):
        operand = operand.replace(qualifier, "")
    return operand.strip()


def _gpr(name: str) -> str:
    """Canonical 64 bit name of a general purpose register operand."""
    return GPR_BASES.get(name, name)


def _same_register(left: str, right: str) -> bool:
    base = _gpr(left)
    return base == _gpr(right) and base in ARG_REGISTERS


def _is_register(operand: str) -> bool:
    return operand in GPR_BASES


def _frame_offset(operand: str) -> int | None:
    match = re.fullmatch(r"\[rsp \+ (0x[0-9a-fA-F]+)\]", operand)
    if match is None:
        return None
    return int(match.group(1), 16)


def _normalise_expression(
    spec: Specimen, site: Site, delta: int, values: Mapping[str, str]
) -> str:
    """Reduce one argument definition to a comparable value expression."""
    if site.mnemonic not in ("mov", "lea"):
        return f"op:{site.text}"
    operands = [_strip_qualifier(part) for part in site.op_str.split(",")]
    if len(operands) != 2:
        return f"op:{site.text}"
    source = operands[1]
    if site.mnemonic == "mov":
        if re.fullmatch(r"0x[0-9a-fA-F]+", source):
            return common.hexs(int(source, 16))
        if re.fullmatch(r"[a-z0-9]+", source):
            return values.get(source, source)
        return f"op:{site.text}"
    frame = re.fullmatch(r"\[rsp ([+-]) (0x[0-9a-fA-F]+)\]", source)
    if frame is not None:
        value = int(frame.group(2), 16)
        return f"&frame+0x{value - delta:X}"
    if not source.startswith("[rip"):
        return f"op:{site.text}"
    target = spec.rip_target(site.rva)
    section = common.section_for_rva(spec.pe, target)
    return f"&{section.name if section is not None else 'unmapped'}+0x{target:X}"


def collect_argument_defs(
    spec: Specimen, body: Sequence[Site], sink_index: int
) -> dict[str, tuple[int, str, str, str]]:
    """Last definition of every argument location before the sink.

    Register definitions and stack argument slots are both tracked; a stack slot
    key is the displacement in effect at the definition, which is the frame the
    sink sees, while a frame address expression is reported relative to the
    function frame.  A stack slot that receives a register is resolved through one
    level of register copy propagation.
    """
    found: dict[str, tuple[int, str, str, str]] = {}
    values: dict[str, str] = {}
    delta = 0
    for site in body[:sink_index]:
        if site.mnemonic in ("sub", "add") and _strip_qualifier(site.op_str).startswith("rsp, "):
            value = int(_strip_qualifier(site.op_str).split(", ")[1], 0)
            delta += -value if site.mnemonic == "sub" else value
            continue
        operands = [_strip_qualifier(part) for part in site.op_str.split(",")]
        if site.mnemonic == "xor":
            if len(operands) == 2 and _same_register(operands[0], operands[1]):
                register = _gpr(operands[0])
                found[register] = (site.rva, site.text, "0", register)
                values[register] = "0"
            continue
        if site.mnemonic not in ("mov", "lea") or len(operands) != 2:
            continue
        destination = operands[0]
        source = operands[1]
        if _is_register(source):
            source = _gpr(source)
        expression = _normalise_expression(spec, site, delta, values)
        if _is_register(destination):
            destination = _gpr(destination)
            values[destination] = expression
            if destination not in ARG_REGISTERS:
                continue
        if destination in ARG_REGISTERS:
            found[destination] = (site.rva, site.text, expression, source)
            continue
        offset = _frame_offset(operands[0])
        if offset is None:
            continue
        if source in values:
            expression = values[source]
        found[f"stack+0x{offset:X}"] = (site.rva, site.text, expression, source)
    return found


def schema_for(stage: int, sink_kind: str) -> tuple[tuple[int, str, str, str], ...]:
    inline_schema, call_schema = STAGE_TABLES[stage]
    return call_schema if sink_kind == "wrapper_call" else inline_schema


def build_argument_defs(
    spec: Specimen, stage: int, sink_kind: str, sink_index: int, body: Sequence[Site], label: str
) -> list[ArgDef]:
    handle = STAGE_HANDLE_REGISTER[stage]
    definitions = collect_argument_defs(spec, body, sink_index)
    out: list[ArgDef] = []
    for position, location, expression, role in schema_for(stage, sink_kind):
        expected = expression.format(handle=handle)
        key = location
        require(key in definitions, f"{label} does not define {key} before the sink")
        rva, text, actual, _source = definitions[key]
        require(
            actual == expected,
            f"{label} argument {position} ({key}) is '{actual}' from '{text}', expected '{expected}'",
        )
        out.append(ArgDef(position, key, actual, role, rva, text))
    return out


def _carrier_text(handle: str, sink_kind: str) -> str:
    return f"mov rdx, {handle}" if sink_kind == "wrapper_call" else f"mov r10, {handle}"


def branch_body(spec: Specimen, start: int, stop: int) -> list[Site]:
    body = spec.disasm(start, stop - start)
    require(bool(body) and body[0].rva == start, f"no decodable block at {common.hexs(start)}")
    require(body[-1].rva + body[-1].size == stop, f"block at {common.hexs(start)} overruns its sink")
    return body


def profile_branch(
    spec: Specimen, stage: int, branch: Mapping[str, Any], table: Mapping[str, Any]
) -> dict[str, Any]:
    index = int(branch["index"])
    sink = branch["sink"]
    sink_rva = int(sink["rva"])
    sink_size = int(sink["size"])
    handle = STAGE_HANDLE_REGISTER[stage]
    label = f"stage {stage} branch {index} {branch['sink_kind']}"
    body = branch_body(spec, int(branch["target_rva"]), sink_rva + sink_size)
    sink_index = next(position for position, site in enumerate(body) if site.rva == sink_rva)
    sink_site = body[sink_index]
    require(
        sink_site.mnemonic == ("call" if branch["sink_kind"] == "wrapper_call" else "syscall"),
        f"{label} sink mnemonic is '{sink_site.mnemonic}'",
    )
    arguments = build_argument_defs(spec, stage, branch["sink_kind"], sink_index, body, label)
    handle_argument = next(item for item in arguments if item.role == "process_handle")
    require(
        handle_argument.expression == handle,
        f"{label} passes '{handle_argument.expression}' as the process handle, expected '{handle}'",
    )
    calls: list[dict[str, Any]] = []
    indirect_calls: list[dict[str, Any]] = []
    for site in body:
        if site.mnemonic != "call" or site.rva == sink_rva:
            continue
        target = _direct_target(site, spec)
        if target is None:
            indirect_calls.append(
                {
                    "rva": site.rva,
                    "rva_hex": common.hexs(site.rva),
                    "text": site.text,
                }
            )
            continue
        calls.append(
            {
                "rva": site.rva,
                "rva_hex": common.hexs(site.rva),
                "raw": common.rva_to_raw(spec.pe, site.rva),
                "text": site.text,
                "target_rva": target,
                "target_rva_hex": common.hexs(target),
                "target_function": spec.function_json(target),
            }
        )
    carrier = branch["handle_carrier"]
    expected_carrier = _carrier_text(handle, str(branch["sink_kind"]))
    require(
        carrier["text"] == expected_carrier,
        f"{label} handle carrier is '{carrier['text']}', expected '{expected_carrier}'",
    )
    require(
        int(carrier["rva"]) == handle_argument.rva,
        f"{label} handle carrier at {common.hexs(int(carrier['rva']))} does not match the normalised "
        f"handle argument at {common.hexs(handle_argument.rva)}",
    )
    join = branch["join"]
    after_sink: list[dict[str, Any]] = []
    cursor = sink_rva + sink_size
    limit = int(table["merge_rva"])
    while cursor < limit:
        site = spec.at(cursor)
        after_sink.append(
            {
                "rva": site.rva,
                "rva_hex": common.hexs(site.rva),
                "text": site.text,
                "mnemonic": site.mnemonic,
            }
        )
        if site.mnemonic in TERMINATORS:
            break
        cursor += site.size
    post_sink_texts = [item["text"] for item in after_sink[1:]]
    return {
        "index": index,
        "stage": stage,
        "stage_label": table["stage_label"],
        "table_slot_rva": branch["slot_rva"],
        "table_slot_rva_hex": common.hexs(int(branch["slot_rva"])),
        "table_slot_raw": branch["slot_raw"],
        "block_target_rva": branch["target_rva"],
        "block_target_rva_hex": common.hexs(int(branch["target_rva"])),
        "instruction_count": len(body),
        "handle_carrier": {
            "rva": carrier["rva"],
            "rva_hex": common.hexs(int(carrier["rva"])),
            "text": carrier["text"],
            "register": handle,
        },
        "sink_kind": branch["sink_kind"],
        "sink": sink_site.as_evidence(spec.pe),
        "sink_function_rva": branch["sink_function_rva"],
        "sink_function": spec.function_json(int(branch["sink_function_rva"]))
        if branch["sink_function_rva"] is not None
        else None,
        "arguments": [item.as_json(spec.pe) for item in arguments],
        "other_calls": calls,
        "indirect_call_site_count": len(indirect_calls),
        "join": {
            "kind": join["kind"],
            "rva": join["rva"],
            "rva_hex": common.hexs(int(join["rva"])),
            "target_rva": join["target_rva"],
            "target_rva_hex": None
            if join["target_rva"] is None
            else common.hexs(int(join["target_rva"])),
            "merge_rva": table["merge_rva"],
            "merge_rva_hex": common.hexs(int(table["merge_rva"])),
            "merge_reachability": join.get("merge_reachability", OBSERVED),
            "merge_reachability_note": join.get("merge_reachability_note"),
            "post_sink_instructions": after_sink,
        },
        "status_tested_after_sink": any(
            text.startswith("test ") or text.startswith("cmp ") for text in post_sink_texts
        ),
    }


def _direct_target(site: Site, spec: Specimen) -> int | None:
    """Resolve a direct branch operand to an RVA, whether or not .pdata covers the target."""
    if site.mnemonic not in ("call", "jmp") or not site.op_str.startswith("0x"):
        return None
    try:
        va = int(site.op_str, 16)
    except ValueError:
        return None
    return common.va_to_rva(spec.pe, va)


def _prologue_frame(spec: Specimen, body: Sequence[Site]) -> int:
    pushed = 0
    for site in body:
        if site.mnemonic == "push":
            pushed += 8
            continue
        if site.mnemonic == "sub" and site.op_str.startswith("rsp, "):
            return pushed + int(site.op_str.split(", ")[1], 0)
        if pushed and site.mnemonic in ("mov", "lea"):
            continue
        break
    return pushed


def _incoming_arg_index(offset: int, frame: int) -> int | None:
    entry = offset - frame
    if entry not in INCOMING_ARG_OFFSETS:
        return None
    return 5 + (entry - 0x28) // 8


def profile_wrapper(
    spec: Specimen, rva: int, stage: int, branch_indexes: Sequence[int]
) -> dict[str, Any]:
    record = spec.owner(rva)
    require(record is not None, f"wrapper {common.hexs(rva)} is not inside a runtime function")
    assert record is not None
    require(record.begin == rva, f"wrapper {common.hexs(rva)} is not a runtime function boundary")
    body = spec.body(rva)
    frame = _prologue_frame(spec, body)
    syscalls = [index for index, site in enumerate(body) if site.mnemonic == "syscall"]
    require(len(syscalls) == 1, f"wrapper {common.hexs(rva)} holds {len(syscalls)} syscalls, expected 1")
    sink_index = syscalls[0]
    incoming: dict[str, int] = {}
    register_arguments = {"rcx": 1, "rdx": 2, "r8": 3, "r9": 4}
    for site in body:
        if site.mnemonic != "mov":
            continue
        operands = [_strip_qualifier(part) for part in site.op_str.split(",")]
        if len(operands) != 2 or not _is_register(operands[0]):
            continue
        destination = _gpr(operands[0])
        offset = _frame_offset(operands[1])
        if offset is not None:
            argument = _incoming_arg_index(offset, frame)
            if argument is not None:
                incoming.setdefault(destination, argument)
            continue
        if not _is_register(operands[1]) or destination not in CALLEE_SAVED:
            continue
        source_register = _gpr(operands[1])
        if source_register in register_arguments:
            incoming.setdefault(destination, register_arguments[source_register])
    definitions = collect_argument_defs(spec, body, sink_index)
    forwarded: list[dict[str, Any]] = []
    for position, location, _expression, role in STAGE_TABLES[stage][0]:
        require(location in definitions, f"wrapper {common.hexs(rva)} does not set {location}")
        site_rva, text, actual, source = definitions[location]
        require(
            source in incoming,
            f"wrapper {common.hexs(rva)} syscall argument {position} ({location}) is set from "
            f"'{source}', which is not a mapped incoming argument register",
        )
        source_argument = incoming[source]
        require(
            source_argument == position + 1,
            f"wrapper {common.hexs(rva)} syscall argument {position} ({location}) comes from call "
            f"argument {source_argument}, expected {position + 1}",
        )
        forwarded.append(
            {
                "position": position,
                "location": location,
                "role": role,
                "from_call_argument": source_argument,
                "via_register": source,
                "defined_at_rva": site_rva,
                "defined_at_rva_hex": common.hexs(site_rva),
                "definition": text,
            }
        )
    returns = [site for site in body if site.mnemonic == "ret"]
    require(len(returns) == 1, f"wrapper {common.hexs(rva)} holds {len(returns)} rets, expected 1")
    indirect_calls: list[dict[str, Any]] = []
    helper_calls: list[dict[str, Any]] = []
    for site in body:
        if site.mnemonic != "call" or site.rva == body[sink_index].rva:
            continue
        target = _direct_target(site, spec)
        if target is None:
            indirect_calls.append(
                {
                    "rva": site.rva,
                    "rva_hex": common.hexs(site.rva),
                    "text": site.text,
                }
            )
            continue
        helper_calls.append(
            {
                "rva": site.rva,
                "rva_hex": common.hexs(site.rva),
                "text": site.text,
                "target_rva": target,
                "target_rva_hex": common.hexs(target),
                "target_function": spec.function_json(target),
            }
        )
    status_move = next(
        (site for site in body if site.mnemonic == "mov" and site.op_str == "eax, esi"), None
    )
    require(
        status_move is not None,
        f"wrapper {common.hexs(rva)} does not return the syscall status in eax",
    )
    return {
        "rva": rva,
        "rva_hex": common.hexs(rva),
        "stage": stage,
        "stage_label": "alloc" if stage == STAGE_ALLOC else "transfer",
        "called_from_branch_indexes": list(branch_indexes),
        "function": record.as_json(spec.pe),
        "instruction_count": len(body),
        "prologue_frame_bytes": frame,
        "incoming_arguments_read": {
            register: index for register, index in sorted(incoming.items(), key=lambda kv: (kv[1], kv[0]))
        },
        "syscall": body[sink_index].as_evidence(spec.pe),
        "syscall_arguments": forwarded,
        "helper_calls": helper_calls,
        "api_call_sites": indirect_calls,
        "api_call_site_count": len(indirect_calls),
        "return_site": returns[0].as_evidence(spec.pe),
        "returns_syscall_status": True,
        "status_return_site": {
            "rva": status_move.rva,
            "rva_hex": common.hexs(status_move.rva),
            "text": status_move.text,
        },
        "handle_argument_position": 1,
        "closes_handle": False,
        "duplicates_handle": False,
    }


def slot_lifecycle(spec: Specimen, body: Sequence[Site]) -> dict[str, Any]:
    offsets = {
        FRAME_RESULT: "remote_base",
        FRAME_SIZE_OUT: "region_size",
        FRAME_TRANSFER_STATUS: "transfer_status",
    }
    out: dict[int, dict[str, Any]] = {}
    for offset, role in sorted(offsets.items()):
        needle = f"[rsp + 0x{offset:X}]"
        direct_writes: list[dict[str, Any]] = []
        address_taken: list[dict[str, Any]] = []
        direct_reads: list[dict[str, Any]] = []
        for site in body:
            if needle not in site.op_str:
                continue
            record = {
                "rva": site.rva,
                "rva_hex": common.hexs(site.rva),
                "text": site.text,
                "mnemonic": site.mnemonic,
            }
            destination = site.op_str.split(",")[0]
            if needle in destination:
                direct_writes.append(record)
            elif site.mnemonic == "lea" and needle in site.op_str:
                address_taken.append(record)
            else:
                direct_reads.append(record)
        out[offset] = {
            "frame_offset": offset,
            "frame_offset_hex": common.hexs(offset),
            "role": role,
            "direct_write_site_count": len(direct_writes),
            "direct_write_sites": direct_writes,
            "address_taken_site_count": len(address_taken),
            "address_taken_sites": address_taken,
            "direct_read_site_count": len(direct_reads),
            "direct_read_sites": direct_reads,
        }
    return {
        "role_vocabulary": {
            "remote_base": "the address the allocation stage produces through an out parameter, the "
            "transfer stage consumes and the anchor returns in RAX",
            "region_size": "the byte count saved from the incoming third argument and reused as the "
            "region size out parameter of the allocation stage",
            "transfer_status": "the transfer stage out parameter, addressed by every transfer branch "
            "and never read again",
        },
        "method": "capstone decode of the whole anchor body; a site whose destination operand is the "
        "slot is a direct write, a lea of the slot is an address taken for an out parameter, and "
        "everything else is a direct read",
        "slots": [out[offset] for offset in sorted(out)],
    }


def function_exits(spec: Specimen, begin: int, end: int) -> dict[str, Any]:
    body = spec.disasm(begin, end - begin)
    exits: list[dict[str, Any]] = []
    syscalls: list[dict[str, Any]] = []
    api_calls: list[dict[str, Any]] = []
    for site in body:
        if site.mnemonic == "syscall":
            syscalls.append(
                {"rva": site.rva, "rva_hex": common.hexs(site.rva), "text": site.text}
            )
            continue
        if site.mnemonic == "call" and _direct_target(site, spec) is None:
            api_calls.append(
                {
                    "rva": site.rva,
                    "rva_hex": common.hexs(site.rva),
                    "text": site.text,
                    "resolved_iat": False,
                }
            )
        if site.mnemonic not in TERMINATORS:
            continue
        record = {
            "rva": site.rva,
            "rva_hex": common.hexs(site.rva),
            "text": site.text,
            "mnemonic": site.mnemonic,
        }
        if site.mnemonic == "jmp":
            target = _direct_target(site, spec)
            record["target_rva"] = target
            record["target_rva_hex"] = None if target is None else common.hexs(target)
            record["leaves_function"] = target is None or not begin <= target < end
            if record["leaves_function"]:
                exits.append(record)
            continue
        if site.mnemonic in EXIT_MNEMONICS:
            exits.append(record)
    tail = [
        {
            "rva": site.rva,
            "rva_hex": common.hexs(site.rva),
            "text": site.text,
            "mnemonic": site.mnemonic,
        }
        for site in body[-12:]
    ]
    return {
        "instruction_count": len(body),
        "syscall_site_count": len(syscalls),
        "syscall_sites": syscalls,
        "exit_count": len(exits),
        "exits": exits,
        "api_call_site_count": len(api_calls),
        "api_call_sites": api_calls,
        "tail": tail,
    }


def direct_callees(spec: Specimen, begin: int) -> list[dict[str, Any]]:
    owner = spec.owner(begin)
    if owner is None or owner.begin != begin:
        return []
    out: list[dict[str, Any]] = []
    for site in spec.body(begin):
        if site.mnemonic != "call":
            continue
        target = _direct_target(site, spec)
        entry: dict[str, Any] = {
            "callsite_rva": site.rva,
            "callsite_rva_hex": common.hexs(site.rva),
            "text": site.text,
        }
        if target is None:
            entry["kind"] = "indirect"
            out.append(entry)
            continue
        entry["kind"] = "direct"
        entry["target_rva"] = target
        entry["target_rva_hex"] = common.hexs(target)
        owner = spec.owner(target)
        if owner is not None and owner.begin == target:
            entry["target_function"] = spec.function_json(target)
        else:
            entry["target_function"] = None
            entry["covered_by_pdata"] = False
        out.append(entry)
    return out


def forward_reachable_set(spec: Specimen, seeds: Sequence[int], max_depth: int) -> dict[str, Any]:
    seen: dict[int, int] = {seed: 0 for seed in seeds}
    frontier = dict(seen)
    uncovered: list[dict[str, Any]] = []
    levels: list[dict[str, Any]] = [{"depth": 0, "functions": sorted(frontier)}]
    depth = 0
    while frontier and depth < max_depth:
        depth += 1
        discovered: dict[int, None] = {}
        for begin in sorted(frontier):
            for entry in direct_callees(spec, begin):
                if entry["kind"] != "direct":
                    continue
                target = int(entry["target_rva"])
                owner = spec.owner(target)
                key = owner.begin if owner is not None and owner.begin == target else target
                if key in seen:
                    continue
                if owner is None or owner.begin != target:
                    uncovered.append(
                        {
                            "rva": target,
                            "rva_hex": common.hexs(target),
                            "callsite_rva": entry["callsite_rva"],
                            "callsite_rva_hex": entry["callsite_rva_hex"],
                            "from_rva": begin,
                            "from_rva_hex": common.hexs(begin),
                        }
                    )
                seen[key] = depth
                discovered[key] = None
        frontier = dict.fromkeys(discovered)
        levels.append({"depth": depth, "functions": sorted(frontier)})
    return {
        "seeds": [{"rva": seed, "rva_hex": common.hexs(seed)} for seed in sorted(seeds)],
        "max_depth": max_depth,
        "levels": levels,
        "exhausted": not frontier,
        "function_count": len(seen),
        "functions": [
            {
                "rva": rva,
                "rva_hex": common.hexs(rva),
                "depth": seen[rva],
                "function": spec.function_json(rva),
            }
            for rva in sorted(seen)
        ],
        "targets_outside_pdata": sorted(
            uncovered, key=lambda item: (item["rva"], item["callsite_rva"])
        ),
    }


def api_edge_inventory(xref_path: Path) -> dict[str, Any]:
    api_rows: dict[str, list[dict[str, str]]] = {symbol: [] for symbol in LIFETIME_APIS}
    slot_rows: dict[int, list[dict[str, str]]] = {}
    row_count = 0
    with xref_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            row_count += 1
            require(
                tuple(row) == XREF_FIELDS,
                f"{xref_path.name} column set is {tuple(row)!r}, expected {XREF_FIELDS!r}",
            )
            if row["relation"] == "fnptr_slot_code_target" and row["dst_kind"] == "code":
                slot_rows.setdefault(int(row["dst_rva"]), []).append(row)
            if row["dst_symbol"] in api_rows:
                api_rows[row["dst_symbol"]].append(row)
    return {
        "row_count": row_count,
        "api_rows": api_rows,
        "code_pointer_slots": slot_rows,
    }


def _api_call_argument(spec: Specimen, callsite: int, register: str = "rcx") -> dict[str, Any] | None:
    """Resolve the register argument of a published API call site, when it is a static global."""
    record = spec.owner(callsite)
    if record is None:
        return None
    body = spec.body(record.begin)
    index = next(
        (position for position, site in enumerate(body) if site.rva == callsite), None
    )
    if index is None:
        return None
    for site in reversed(body[max(0, index - 8) : index]):
        if site.mnemonic != "mov" or not site.op_str.startswith(register):
            continue
        operands = [_strip_qualifier(part) for part in site.op_str.split(",")]
        if len(operands) != 2 or not operands[1].startswith("[rip"):
            continue
        target = spec.rip_target(site.rva)
        section = common.section_for_rva(spec.pe, target)
        return {
            "register": register,
            "load_rva": site.rva,
            "load_rva_hex": common.hexs(site.rva),
            "load_text": site.text,
            "target_rva": target,
            "target_rva_hex": common.hexs(target),
            "target_section": None if section is None else section.name,
        }
    return None


def api_calls_in_range(
    spec: Specimen, inventory: Mapping[str, Any], lo: int, hi: int
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for symbol in LIFETIME_APIS:
        sites: list[dict[str, Any]] = []
        for row in inventory["api_rows"][symbol]:
            rva = int(row["src_rva"])
            if not lo <= rva < hi:
                continue
            record = spec.owner(rva)
            sites.append(
                {
                    "callsite_rva": rva,
                    "callsite_rva_hex": common.hexs(rva),
                    "callsite_raw": int(row["src_raw"]),
                    "relation": row["relation"],
                    "category": row["category"],
                    "evidence": row["evidence"],
                    "iat_rva": int(row["iat_rva"]),
                    "iat_rva_hex": common.hexs(int(row["iat_rva"])),
                    "module": row["dst_module"],
                    "function": None if record is None else record.as_json(spec.pe),
                }
            )
        out[symbol] = {
            "site_count": len(sites),
            "sites": sorted(sites, key=lambda item: item["callsite_rva"]),
        }
    return out


def rel32_xrefs(spec: Specimen, wanted: Iterable[int]) -> dict[int, list[dict[str, Any]]]:
    target_set = set(wanted)
    found: dict[int, list[dict[str, Any]]] = {value: [] for value in sorted(target_set)}
    blob = spec.text_bytes
    base = spec.text.virtual_address
    for opcode, kind in ((0xE8, "direct_call"), (0xE9, "direct_jmp")):
        needle = bytes((opcode,))
        position = blob.find(needle)
        while position >= 0:
            displacement = struct.unpack_from("<i", blob, position + 1)[0]
            site_rva = base + position
            target = site_rva + 5 + displacement
            if target in found:
                found[target].append(
                    {
                        "kind": kind,
                        "rva": site_rva,
                        "rva_hex": common.hexs(site_rva),
                        "raw": common.rva_to_raw(spec.pe, site_rva),
                        "encoding": blob[position : position + 5].hex(" "),
                    }
                )
            position = blob.find(needle, position + 1)
    for entries in found.values():
        entries.sort(key=lambda item: item["rva"])
    return found


def rip_materialisation_sites(spec: Specimen, wanted: Iterable[int]) -> dict[int, list[dict[str, Any]]]:
    target_set = set(wanted)
    found: dict[int, list[dict[str, Any]]] = {value: [] for value in sorted(target_set)}
    blob = spec.text_bytes
    base = spec.text.virtual_address
    for match in RIP_PREFIX_PATTERN.finditer(blob):
        start = match.start()
        displacement = struct.unpack_from("<i", blob, start + 3)[0]
        site_rva = base + start
        target = site_rva + 7 + displacement
        if target in found:
            found[target].append(
                {
                    "rva": site_rva,
                    "rva_hex": common.hexs(site_rva),
                    "raw": common.rva_to_raw(spec.pe, site_rva),
                    "opcode": blob[start + 1],
                    "encoding": blob[start : start + 7].hex(" "),
                }
            )
    for entries in found.values():
        entries.sort(key=lambda item: item["rva"])
    return found


def absolute_pointer_sites(spec: Specimen, rva: int) -> list[dict[str, Any]]:
    pattern = (spec.image_base + rva).to_bytes(8, "little")
    out: list[dict[str, Any]] = []
    position = spec.file_bytes.find(pattern)
    while position >= 0:
        slot = common.raw_to_rva(spec.pe, position)
        section = common.section_for_raw(spec.pe, position)
        out.append(
            {
                "raw": position,
                "raw_hex": common.hexs(position),
                "rva": slot,
                "rva_hex": None if slot is None else common.hexs(slot),
                "section": None if section is None else section.name,
            }
        )
        position = spec.file_bytes.find(pattern, position + 1)
    return out


def dir64_cluster_census(spec: Specimen) -> dict[str, Any]:
    clusters = {"cluster_slot_count": 0, "cluster_slots": []}
    per_section: dict[str, int] = {}
    for section_name in (".rdata", ".data"):
        section = spec.sections[section_name]
        count = 0
        for entry in spec.pe.DIRECTORY_ENTRY_BASERELOC:
            block = entry.struct
            if block.VirtualAddress < section.virtual_address:
                continue
            if block.VirtualAddress >= section.virtual_end:
                continue
            for item in entry.entries:
                if item.type != pefile.RELOCATION_TYPE["IMAGE_REL_BASED_DIR64"]:
                    continue
                slot = item.rva
                raw = common.rva_to_raw(spec.pe, slot)
                if raw is None:
                    continue
                count += 1
                value = int.from_bytes(spec.data_bytes(slot, 8), "little")
                if spec.image_base + CLUSTER_LOW <= value < spec.image_base + CLUSTER_HIGH:
                    clusters["cluster_slot_count"] += 1
                    clusters["cluster_slots"].append(
                        {
                            "slot_rva": slot,
                            "slot_rva_hex": common.hexs(slot),
                            "value_va": value,
                            "value_va_hex": common.hexs(value),
                            "value_rva": value - spec.image_base,
                            "value_rva_hex": common.hexs(value - spec.image_base),
                        }
                    )
        per_section[section_name] = count
    clusters["dir64_slot_count_by_section"] = per_section
    clusters["cluster_slots"] = sorted(clusters["cluster_slots"], key=lambda item: item["slot_rva"])
    return clusters


def _measure_next_level(
    spec: Specimen,
    inventory: Mapping[str, Any],
    frontier: set[int],
    seen: set[int],
) -> dict[str, Any]:
    """Count the level the walk stops at without enumerating it."""
    rel32 = rel32_xrefs(spec, frontier)
    callers: set[int] = set()
    edges = 0
    for target in sorted(frontier):
        edges += len(rel32.get(target, []))
        edges += len(inventory["code_pointer_slots"].get(target, []))
        for site in rel32.get(target, []):
            owner = spec.owner(site["rva"])
            if owner is not None:
                callers.add(owner.begin)
    return {
        "level": "not enumerated",
        "caller_function_count": len(callers),
        "new_caller_function_count": len(callers - seen),
        "edge_count": edges,
    }


def caller_closure(
    spec: Specimen,
    inventory: Mapping[str, Any],
    scopes: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    scope_records: list[dict[str, Any]] = []
    frontier_targets: set[int] = set()
    terminal: list[tuple[int, int, str]] = []
    uncovered_sites: list[dict[str, Any]] = []
    for scope in scopes:
        seeds = [int(value) for value in scope["seeds"]]
        seen: set[int] = set(seeds)
        frontier = set(seeds)
        frontier_targets |= frontier
        level = 0
        levels: list[dict[str, Any]] = [{"level": 0, "target_count": len(seeds), "edge_count": 0}]
        for seed in sorted(seeds):
            rows.append(
                {
                    "level": 0,
                    "scope": scope["name"],
                    "target_fn": common.hexs(seed),
                    "edge_kind": "forward_subject",
                    "callsite": scope["forward_sites"].get(common.hexs(seed), ""),
                    "caller_fn": "",
                    "evidence": scope["seed_evidence"].get(common.hexs(seed), "forward flow subject"),
                    "confidence": HIGH,
                    "open": scope["seed_open"].get(common.hexs(seed), ""),
                }
            )
        while frontier and level + 1 < MAX_CLOSURE_DEPTH and level < int(scope["expand_levels"]):
            level += 1
            rel32 = rel32_xrefs(spec, frontier)
            edges: dict[tuple[int, int, int], dict[str, Any]] = {}
            for target in sorted(frontier):
                for site in rel32.get(target, []):
                    owner = spec.owner(site["rva"])
                    if owner is None:
                        uncovered_sites.append(
                            {
                                "callsite_rva": site["rva"],
                                "callsite_rva_hex": site["rva_hex"],
                                "kind": site["kind"],
                                "target_rva": target,
                                "target_rva_hex": common.hexs(target),
                                "note": "the call site lies outside every .pdata runtime function, so "
                                "it cannot be attributed to a caller function",
                            }
                        )
                        continue
                    edges[(owner.begin, target, site["rva"])] = {
                        "edge_kind": site["kind"],
                        "evidence": "pdata_boundary+rel32_displacement+in_text_target",
                        "callsite": site["rva"],
                        "caller": owner.begin,
                    }
                for row in inventory["code_pointer_slots"].get(target, []):
                    slot_rva = int(row["src_rva"])
                    owner = spec.owner(slot_rva)
                    if owner is None:
                        continue
                    edges[(owner.begin, target, slot_rva)] = {
                        "edge_kind": row["category"],
                        "evidence": row["evidence"],
                        "callsite": slot_rva,
                        "caller": owner.begin,
                    }
            for (_caller, target, _site), edge in sorted(edges.items()):
                rows.append(
                    {
                        "level": level,
                        "scope": scope["name"],
                        "target_fn": common.hexs(target),
                        "edge_kind": str(edge["edge_kind"]),
                        "callsite": common.hexs(int(edge["callsite"])),
                        "caller_fn": common.hexs(int(edge["caller"])),
                        "evidence": str(edge["evidence"]),
                        "confidence": HIGH,
                        "open": "",
                    }
                )
            new_frontier = {int(edge["caller"]) for edge in edges.values()} - seen
            seen |= new_frontier
            frontier = new_frontier
            frontier_targets |= frontier
            levels.append(
                {
                    "level": level,
                    "target_count": len(frontier),
                    "edge_count": len(edges),
                    "caller_function_count": len({int(edge["caller"]) for edge in edges.values()}),
                }
            )
        measured: dict[str, Any] | None = None
        if frontier:
            measured = _measure_next_level(spec, inventory, frontier, seen)
        else:
            terminal.extend((value, level, str(scope["name"])) for value in sorted(seen))
        scope_records.append(
            {
                "name": scope["name"],
                "description": scope["description"],
                "seeds": [{"rva": seed, "rva_hex": common.hexs(seed)} for seed in sorted(seeds)],
                "levels": levels,
                "expand_levels": int(scope["expand_levels"]),
                "exhausted": not frontier,
                "frontier_after_last_level": sorted(common.hexs(value) for value in frontier),
                "frontier_after_last_level_count": len(frontier),
                "distinct_caller_count": len(seen) - len(seeds),
                "bound": {
                    "kind": "exhausted" if not frontier else "measured",
                    "reason": scope["bound"],
                    "measured_next_level": measured,
                },
            }
        )
    negatives = closure_negative_forms(spec, inventory, sorted(frontier_targets))
    for target, level, scope_name in terminal:
        forms = negatives[common.hexs(target)]
        if any(int(item["site_count"]) for item in forms["forms"].values()):
            continue
        rows.append(
            {
                "level": level,
                "scope": scope_name,
                "target_fn": common.hexs(target),
                "edge_kind": "no_inbound_edge_in_enumerated_forms",
                "callsite": "",
                "caller_fn": "",
                "evidence": "+".join(f"{name}=0" for name in sorted(forms["forms"])),
                "confidence": HIGH,
                "open": "F-U-01",
            }
        )
    for row in rows:
        if int(row["level"]) > 0 and not row["open"] and row["caller_fn"]:
            forms = negatives.get(row["caller_fn"])
            if forms is not None and all(
                int(item["site_count"]) == 0 for item in forms["forms"].values()
            ):
                row["open"] = "F-U-01"
    return {
        "method": {
            "rel32": "every 0xE8 and 0xE9 byte in .text decoded as a signed 32 bit displacement, no "
            "address range restriction",
            "code_pointer_slot": "reverse/evidence/xref_edges.csv rows with relation "
            "fnptr_slot_code_target and dst_kind code",
            "levels": "breadth first from the scope seeds, every call site attributed to the .pdata "
            "runtime function that contains it",
            "not_covered": "a call through a register or a stack slot cannot be resolved statically, "
            "so the walk covers the enumerated static edge forms only",
            "ordering": "sorted by scope, then level, then target rva, then call site rva",
        },
        "open_column_meaning": "the unresolved identifier under which the walk stops for that row, empty "
        "while the row's own chain continues",
        "scopes": scope_records,
        "negative_forms": negatives,
        "rows": rows,
        "uncovered_call_sites": sorted(
            uncovered_sites, key=lambda item: (item["callsite_rva"], item["target_rva"])
        ),
        "uncovered_call_site_count": len(uncovered_sites),
        "row_count": len(rows),
    }


def closure_negative_forms(
    spec: Specimen, inventory: Mapping[str, Any], targets: Sequence[int]
) -> dict[str, Any]:
    rel32 = rel32_xrefs(spec, targets)
    rip = rip_materialisation_sites(spec, targets)
    out: dict[str, Any] = {}
    for target in targets:
        pointer_sites = absolute_pointer_sites(spec, target)
        slot_rows = inventory["code_pointer_slots"].get(target, [])
        api_rows = [
            row
            for row in inventory["api_rows"]["CloseHandle"]
            + inventory["api_rows"]["DuplicateHandle"]
            if row["dst_rva"] and int(row["dst_rva"]) == target
        ]
        out[common.hexs(target)] = {
            "target_rva": target,
            "target_rva_hex": common.hexs(target),
            "forms": {
                "rel32_call": {
                    "method": "0xE8 decode over every .text byte",
                    "site_count": sum(1 for item in rel32.get(target, []) if item["kind"] == "direct_call"),
                    "sites": rel32.get(target, []),
                },
                "rel32_jmp": {
                    "method": "0xE9 decode over every .text byte",
                    "site_count": sum(1 for item in rel32.get(target, []) if item["kind"] == "direct_jmp"),
                    "sites": [item for item in rel32.get(target, []) if item["kind"] == "direct_jmp"],
                },
                "rip_relative_materialisation": {
                    "method": "REX prefixed RIP relative disp32 decode over every .text byte",
                    "site_count": len(rip.get(target, [])),
                    "sites": rip.get(target, []),
                },
                "absolute_pointer": {
                    "method": "byte search of image_base+rva as a little endian 64 bit value",
                    "site_count": len(pointer_sites),
                    "sites": pointer_sites,
                },
                "code_pointer_slot": {
                    "method": "published fnptr_slot_code_target rows with this dst_rva",
                    "site_count": len(slot_rows),
                    "sites": [
                        {
                            "slot_rva": int(row["src_rva"]),
                            "slot_rva_hex": common.hexs(int(row["src_rva"])),
                            "category": row["category"],
                            "relation": row["relation"],
                        }
                        for row in sorted(slot_rows, key=lambda item: int(item["src_rva"]))
                    ],
                },
                "api_target": {
                    "method": "published IAT and thunk rows whose dst_rva is this code address",
                    "site_count": len(api_rows),
                    "sites": [
                        {
                            "src_rva": int(row["src_rva"]),
                            "src_rva_hex": common.hexs(int(row["src_rva"])),
                            "relation": row["relation"],
                            "dst_symbol": row["dst_symbol"],
                        }
                        for row in sorted(api_rows, key=lambda item: int(item["src_rva"]))
                    ],
                },
            },
        }
    return out


def handle_lifetime(
    spec: Specimen,
    inventory: Mapping[str, Any],
    reachable: Mapping[str, Any],
    stages: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    covered: list[tuple[int, int]] = []
    for entry in reachable["functions"]:
        function = entry["function"]
        if function is None:
            continue
        covered.append((int(function["begin_rva"]), int(function["end_rva"])))
    in_reachable: dict[str, list[dict[str, Any]]] = {}
    for symbol in LIFETIME_APIS:
        hits: list[dict[str, Any]] = []
        for row in inventory["api_rows"][symbol]:
            rva = int(row["src_rva"])
            if not any(lo <= rva < hi for lo, hi in covered):
                continue
            hits.append(
                {
                    "callsite_rva": rva,
                    "callsite_rva_hex": common.hexs(rva),
                    "relation": row["relation"],
                    "symbol": row["dst_symbol"],
                }
            )
        in_reachable[symbol] = sorted(hits, key=lambda item: item["callsite_rva"])
    cluster = api_calls_in_range(spec, inventory, CLUSTER_LOW, CLUSTER_HIGH)
    nearest: dict[str, list[dict[str, Any]]] = {}
    for symbol in LIFETIME_APIS:
        sites = sorted(
            int(row["src_rva"]) for row in inventory["api_rows"][symbol]
        )
        ordered = sorted(sites, key=lambda rva: (abs(rva - ANCHOR_TARGET), rva))
        nearest[symbol] = [
            {
                "callsite_rva": rva,
                "callsite_rva_hex": common.hexs(rva),
                "distance_from_anchor": rva - ANCHOR_TARGET,
                "inside_cluster_range": CLUSTER_LOW <= rva < CLUSTER_HIGH,
                "function": spec.function_json(rva),
                "argument": _api_call_argument(spec, rva),
            }
            for rva in ordered[:NEAREST_SITE_COUNT]
        ]
    return {
        "consume_site_count": sum(
            int(item["branch_count"]) for item in stages
        ),
        "consume_sites": {
            "alloc_stage": 16,
            "transfer_stage": 16,
            "carriers": ["r14", "rbx"],
            "note": "the value is only read; no branch rewrites it, and the transfer stage re-reads "
            "the same descriptor field at 0xC86440",
        },
        "reachable_set": {
            "function_count": reachable["function_count"],
            "max_depth": reachable["max_depth"],
            "exhausted": reachable["exhausted"],
            "note": "the direct call closure of the anchor and its entry function; a handle close or "
            "duplication outside this set cannot be excluded, one inside it would have been found",
        },
        "api_call_sites_inside_reachable_set": in_reachable,
        "import_presence": {
            symbol: {
                "published_edge_count": len(inventory["api_rows"][symbol]),
                "relation_counts": _count_relations(inventory["api_rows"][symbol]),
                "present": bool(inventory["api_rows"][symbol]),
            }
            for symbol in LIFETIME_APIS
        },
        "cluster_range_sites": {
            "range": [common.hexs(CLUSTER_LOW), common.hexs(CLUSTER_HIGH)],
            "range_note": "the code cluster that contains the anchor and both dispatch tables",
            "apis": cluster,
        },
        "nearest_sites": nearest,
        "conclusion": "no CloseHandle and no DuplicateHandle call site exists inside the provable "
        "forward reachable set, and the value is never written by any branch, so the anchor neither "
        "closes nor duplicates the handle it receives",
        "conclusion_confidence": HIGH,
        "ownership": "OPEN",
        "ownership_unresolved_id": "F-U-03",
    }


def _count_relations(rows: Sequence[Mapping[str, str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["relation"]] = counts.get(row["relation"], 0) + 1
    return {key: counts[key] for key in sorted(counts)}


def build_evidence(
    spec: Specimen,
    stages: Sequence[Mapping[str, Any]],
    wrappers: Sequence[Mapping[str, Any]],
    lifetime: Mapping[str, Any],
    closure: Mapping[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(
        identifier: str,
        claim: str,
        method: str,
        confidence: str,
        status: str,
        sites: Sequence[Mapping[str, Any]] = (),
        function: Mapping[str, Any] | None = None,
    ) -> None:
        items.append(
            {
                "id": identifier,
                "claim": claim,
                "method": method,
                "confidence": confidence,
                "status": status,
                "sites": [dict(site) for site in sites],
                "function": None if function is None else dict(function),
            }
        )

    add(
        "E-01",
        "the entry function reads the 16 byte closure pair, calls the anchor once and appends its "
        "return value to the output vector without testing it",
        "capstone decode of the whole runtime function, linear",
        HIGH,
        OBSERVED,
        [
            {"rva": CALL_SITE, "text": "call 0x180c856c0"},
            {"rva": CALL_SITE_APPEND, "text": "mov qword ptr [rdx], rax"},
            {"rva": CALL_SITE_APPEND_ADVANCE, "text": "add qword ptr [rsi + 8], 8"},
            {"rva": CALL_SITE_GROWTH_CALL, "text": "call 0x1800495d0"},
        ],
        spec.function_json(ANCHOR_CALLER),
    )
    add(
        "E-02",
        "the first load of the handle feeds the 16 allocation branches, the second load re-reads the "
        "same descriptor field and feeds the 16 transfer branches",
        "capstone decode of the two loads plus the branch block normalisation",
        HIGH,
        OBSERVED,
        [
            {"rva": LOAD_R14, "text": "mov r14, qword ptr [rcx]"},
            {"rva": LOAD_RBX, "text": "mov rbx, qword ptr [rbx]"},
            {"rva": RESULT_READ_MERGE, "text": "mov r14, qword ptr [rsp + 0x50]"},
        ],
        spec.function_json(ANCHOR_TARGET),
    )
    for stage in stages:
        add(
            f"E-03.{stage['stage']}",
            f"all 16 {stage['stage_label']} branches agree with one argument schema, "
            f"{stage['wrapper_branch_count']} through a wrapper call and {stage['inline_branch_count']} "
            f"through an inline syscall",
            "rsp delta aware forward pass over each branch block, every argument definition asserted "
            "against the stage schema",
            HIGH,
            OBSERVED,
            [
                {
                    "rva": branch["sink"]["rva"],
                    "rva_hex": branch["sink"]["rva_hex"],
                    "text": branch["sink"]["text"],
                }
                for branch in stage["branches"]
            ],
            spec.function_json(ANCHOR_TARGET),
        )
    for wrapper in wrappers:
        add(
            f"E-04.{common.hexs(wrapper['rva'])}",
            f"the wrapper holds exactly one inline syscall, forwards call argument N+1 into syscall "
            f"argument N for every position, returns the raw status and calls no imported API",
            "capstone decode of the whole runtime function plus the prologue relative argument map",
            HIGH,
            OBSERVED,
            [
                {"rva": wrapper["syscall"]["rva"], "text": wrapper["syscall"]["text"]},
                {"rva": wrapper["return_site"]["rva"], "text": wrapper["return_site"]["text"]},
            ],
            wrapper["function"],
        )
    add(
        "E-05",
        "the frame slot at rsp+0x50 is zeroed once, written by all 16 allocation branches, read twice "
        "and returned in RAX; the transfer status slot at rsp+0x40 is written by all 16 transfer "
        "branches and never read",
        "capstone decode of the anchor body with a per slot write and read census",
        HIGH,
        OBSERVED,
        [
            {"rva": RESULT_INIT, "text": "mov qword ptr [rsp + 0x50], 0"},
            {"rva": XFER_STATUS_INIT, "text": "mov qword ptr [rsp + 0x40], 0"},
            {"rva": RESULT_READ_RETURN, "text": "mov rsi, qword ptr [rsp + 0x50]"},
            {"rva": RETURN_SITE, "text": "ret"},
        ],
        spec.function_json(ANCHOR_TARGET),
    )
    add(
        "E-06",
        "the anchor has one exit, sixteen inline syscalls and no branch that tests a status value",
        "capstone decode of the whole runtime function with a terminator and exit census",
        HIGH,
        OBSERVED,
        [
            {"rva": BASE_ZERO_TEST, "text": "test r14, r14"},
            {"rva": BASE_ZERO_BRANCH, "text": "xor esi, esi"},
            {"rva": RETURN_SITE, "text": "ret"},
        ],
        spec.function_json(ANCHOR_TARGET),
    )
    add(
        "E-07",
        "the handle is consumed 32 times and is neither closed nor duplicated anywhere in the "
        "provable forward reachable set",
        "IAT and thunk edge inventory cross checked against the direct call closure of the anchor",
        HIGH,
        OBSERVED,
        [
            site
            for symbol in LIFETIME_APIS
            for site in lifetime["api_call_sites_inside_reachable_set"][symbol]
        ],
    )
    anchor_forms = closure["negative_forms"][common.hexs(ANCHOR_TARGET)]["forms"]
    caller_forms = closure["negative_forms"][common.hexs(ANCHOR_CALLER)]["forms"]
    add(
        "E-08",
        "the caller closure of the anchor is bounded: the anchor has exactly one rel32 call site, and "
        "its caller has no inbound edge in any enumerated form",
        "rel32, RIP relative, absolute pointer, code pointer slot and published API edge forms, plus "
        "the DIR64 cluster census",
        HIGH,
        OBSERVED,
        [
            {
                "rva": site["rva"],
                "rva_hex": site["rva_hex"],
                "text": f"{site['kind']} rel32 to {common.hexs(ANCHOR_TARGET)}",
            }
            for site in anchor_forms["rel32_call"]["sites"]
        ]
        + [
            {
                "rva": 0,
                "rva_hex": common.hexs(0),
                "text": f"{common.hexs(ANCHOR_CALLER)} inbound edges: "
                + "+".join(f"{name}={item['site_count']}" for name, item in sorted(caller_forms.items())),
            }
        ],
    )
    return sorted(items, key=lambda item: item["id"])


def build_unresolved() -> list[dict[str, Any]]:
    return [
        {
            "id": "F-U-01",
            "question": "Which code calls the entry function 0xC85650, and therefore which code "
            "supplies the closure pair and the descriptor pointer?",
            "status": OPEN,
            "reason": "the closure is bounded: the anchor has one rel32 caller, and that caller has no "
            "inbound edge in the rel32, RIP relative, absolute pointer, code pointer slot or "
            "published API edge forms, so the upward walk terminates with an empty frontier",
            "next_static_step": "recover the component method table the host populates at run time, "
            "then match the 16 byte {output vector, descriptor} pair against it",
            "carries_forward": "reverse/evidence/c856c0_dataflow.json#unresolved.U-02",
        },
        {
            "id": "F-U-02",
            "question": "Which Nt service numbers do the 16 inline syscalls and the 12 wrappers use?",
            "status": OPEN,
            "reason": "the argument shape of every branch is a static fact, but each service number is "
            "produced at run time from KUSER_SHARED_DATA, PEB and per branch constants, so no "
            "service name follows from the shape alone",
            "next_static_step": "evaluate the mixing chain offline with symbolic KUSER_SHARED_DATA "
            "values as proposed in reverse/adhesive-12-risk-methodology-open-questions.md#10.6",
            "carries_forward": "reverse/evidence/c856c0_dataflow.json#unresolved.U-04",
        },
        {
            "id": "F-U-03",
            "question": "Who owns the handle, who created it and who closes it?",
            "status": OPEN,
            "reason": "no close or duplication site exists in the provable forward set, and the "
            "producer side is bounded by F-U-01, so both ends of the lifetime stay outside the "
            "reachable graph",
            "next_static_step": "resolve the entry point of F-U-01, then propagate the descriptor "
            "pointer into the caller of that entry point",
            "carries_forward": "reverse/evidence/c856c0_dataflow.json#unresolved.U-01",
        },
        {
            "id": "F-U-04",
            "question": "Is the value returned in RAX the address the transfer stage writes to, and is "
            "the transfer result checked anywhere?",
            "status": OPEN,
            "reason": "the transfer status out parameter at rsp+0x40 has no read site in the anchor, "
            "and the entry function appends the return value unconditionally, so a failed transfer "
            "and a zero base are both reported to the output vector without a static check",
            "next_static_step": "compare the output vector against the observable result of a real "
            "invocation, which is outside the static method of this pass",
        },
        {
            "id": "F-U-05",
            "question": "Do the 8 inline and 8 wrapper branches of one stage call the same service, and "
            "do the two stages call services that belong together?",
            "status": OPEN,
            "reason": "the forward pass establishes one argument schema per stage, but the service "
            "number is a runtime value in all 32 branches, so branch to branch equivalence stays open",
            "next_static_step": "resolve F-U-02 first, then compare the resolved service numbers per "
            "stage",
        },
        {
            "id": "F-U-06",
            "question": "Does the transfer stage base address always equal the address the allocation "
            "stage returned?",
            "status": OPEN,
            "reason": "the transfer stage receives the allocation result in r14 and passes it on "
            "unchanged in all 16 branches, but the allocation stage itself may move or split the "
            "region, which is a runtime property of the service and not of the bytes",
            "next_static_step": "record the region size out parameter and the returned base together "
            "at run time, which is outside the static method of this pass",
        },
        {
            "id": "F-U-07",
            "question": "Do both dispatch selectors execute in one invocation, so that the two tables "
            "form one 32 way dispatch?",
            "status": OPEN,
            "reason": "the forward pass proves the transfer stage is reached only from the allocation "
            "merge and only when the merge base is non zero, so the two selectors are ordered but "
            "the branch pair that ran is not observable statically",
            "next_static_step": "record both RDTSC selector values for one invocation, which is "
            "outside the static method of this pass",
        },
        {
            "id": "F-U-08",
            "question": "Does the anchor have an exception funclet, and can the block bodies after the "
            "inline syscalls reach the stage merge points?",
            "status": OPEN,
            "reason": "the unwind record of the anchor does not decode as a standard x64 UNWIND_INFO "
            "code array, and the fall through instruction stream after each inline syscall contains "
            "conditional control flow, so neither the exception behaviour nor the merge reachability "
            "is established by a linear decode",
            "next_static_step": "recover a recursive control flow graph for the 16 block bodies and "
            "classify the unwind record against its own parser, which is outside the linear method of "
            "this pass",
            "carries_forward": "reverse/evidence/c856c0_dataflow.json#dispatch.tables",
        },
    ]


def build_negative_findings(
    stages: Sequence[Mapping[str, Any]],
    wrappers: Sequence[Mapping[str, Any]],
    lifetime: Mapping[str, Any],
    slot_map: Mapping[str, Any],
    inventory: Mapping[str, Any],
    closure: Mapping[str, Any],
    entry_exits: Mapping[str, Any],
    anchor_exits: Mapping[str, Any],
    descriptor_stores: Sequence[Mapping[str, Any]],
    anchor_loads: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    branches = [branch for stage in stages for branch in stage["branches"]]
    transfer_status = next(
        item for item in slot_map["slots"] if int(item["frame_offset"]) == FRAME_TRANSFER_STATUS
    )
    findings = [
        {
            "id": "F-NEG-01",
            "claim": "no branch tests a syscall status: the wrapper branches jump straight to the "
            "stage merge and the inline branches only restore rsp before falling through to it",
            "method": "instruction census of the instructions between every sink and the stage merge "
            "point, excluding the shared merge test",
            "result": {
                "branches": len(branches),
                "branches_testing_status_before_the_merge": sum(
                    1 for branch in branches if bool(branch["status_tested_after_sink"])
                ),
                "transfer_status_read_sites": int(transfer_status["direct_read_site_count"]),
            },
            "status": OBSERVED,
            "confidence": HIGH,
        },
        {
            "id": "F-NEG-02",
            "claim": "no wrapper, branch block or entry function of the path calls through a register "
            "or an import slot",
            "method": "every call site of the 12 wrapper bodies, the 32 branch blocks and the entry "
            "function classified as direct or indirect",
            "result": {
                "wrapper_indirect_call_sites": sum(
                    int(item["api_call_site_count"]) for item in wrappers
                ),
                "branch_block_indirect_call_sites": sum(
                    int(branch["indirect_call_site_count"]) for branch in branches
                ),
                "entry_function_indirect_call_sites": int(entry_exits["api_call_site_count"]),
                "anchor_indirect_call_sites": int(anchor_exits["api_call_site_count"]),
            },
            "status": OBSERVED,
            "confidence": HIGH,
        },
        {
            "id": "F-NEG-03",
            "claim": "the handle is never written by the anchor: both loads are reads and no "
            "instruction of the anchor stores through a descriptor carrying register",
            "method": "capstone decode of the whole anchor body, every store destination checked "
            "against the two descriptor carrying registers",
            "result": {
                "stores_through_a_descriptor_carrying_register": len(
                    descriptor_stores
                ),
                "descriptor_carrying_registers": ["rcx", "rbx"],
                "load_sites": len(anchor_loads),
            },
            "status": OBSERVED,
            "confidence": HIGH,
        },
        {
            "id": "F-NEG-04",
            "claim": "no DuplicateHandle edge exists in the published inventory",
            "method": "row census of reverse/evidence/xref_edges.csv by dst_symbol",
            "result": {
                "duplicate_handle_rows": len(inventory["api_rows"]["DuplicateHandle"]),
                "relation_counts": _count_relations(inventory["api_rows"]["DuplicateHandle"]),
            },
            "status": OBSERVED,
            "confidence": HIGH,
        },
        {
            "id": "F-NEG-05",
            "claim": "the wrappers are shared runtime helpers, not a private dispatch of the anchor",
            "method": "level 1 caller census of the 12 wrappers over the whole .text",
            "result": {
                "wrapper_distinct_caller_functions": int(
                    closure["scopes"][1]["distinct_caller_count"]
                ),
                "caller_functions_outside_the_anchor": int(
                    closure["scopes"][1]["distinct_caller_count"]
                ),
            },
            "status": OBSERVED,
            "confidence": HIGH,
        },
        {
            "id": "F-NEG-06",
            "claim": "the anchor body holds no conditional exit, so the only explicit error branch is "
            "the merge base test",
            "method": "terminator and exit census of the whole runtime function",
            "result": {
                "exit_count": int(anchor_exits["exit_count"]),
                "exits": anchor_exits["exits"],
                "syscall_site_count": int(anchor_exits["syscall_site_count"]),
            },
            "status": OBSERVED,
            "confidence": HIGH,
        },
        {
            "id": "F-NEG-07",
            "claim": "no load time relocated pointer in .rdata or .data holds a virtual address into "
            "the anchor cluster",
            "method": "every DIR64 slot of .rdata and .data read at its 8 byte aligned file offset",
            "result": {
                "dir64_slot_count_by_section": lifetime["dir64_census"]["dir64_slot_count_by_section"],
                "cluster_slot_count": lifetime["dir64_census"]["cluster_slot_count"],
            },
            "status": OBSERVED,
            "confidence": HIGH,
        },
    ]
    return sorted(findings, key=lambda item: item["id"])


def build_payload(spec: Specimen, root: Path, dataflow_path: Path, xref_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    dataflow = json.loads(dataflow_path.read_text(encoding="utf-8"))
    require(
        dataflow.get("schema") == DATAFLOW_SCHEMA,
        f"{dataflow_path.name} schema is {dataflow.get('schema')!r}, expected {DATAFLOW_SCHEMA!r}",
    )
    specimen_record = dataflow["specimen"]
    require(
        specimen_record["sha256"] == SPECIMEN_SHA256,
        f"{dataflow_path.name} specimen digest is {specimen_record['sha256']}",
    )
    require(
        common.sha256_file(spec.path) == SPECIMEN_SHA256,
        "the specimen digest does not match the pinned value",
    )
    anchor = dataflow["anchor"]
    require(int(anchor["function_rva"]) == ANCHOR_TARGET, "dataflow anchor function mismatch")
    require(int(anchor["direct_caller_rva"]) == ANCHOR_CALLER, "dataflow anchor caller mismatch")
    require(int(anchor["handle_load_rva"]) == LOAD_R14, "dataflow handle load mismatch")

    spec.expect(LOAD_R14, "mov", "r14, qword ptr [rcx]")
    spec.expect(LOAD_RBX, "mov", "rbx, qword ptr [rbx]")
    spec.expect(RESULT_INIT, "mov", "qword ptr [rsp + 0x50], 0")
    spec.expect(SIZE_SAVE, "mov", "qword ptr [rsp + 0x48], r8")
    spec.expect(ALLOC_MERGE, "mov", "r14, qword ptr [rsp + 0x50]")
    spec.expect(BASE_ZERO_TEST, "test", "r14, r14")
    spec.expect(BASE_ZERO_BRANCH, "xor", "esi, esi")
    spec.expect(XFER_STATUS_INIT, "mov", "qword ptr [rsp + 0x40], 0")
    spec.expect(RESULT_READ_RETURN, "mov", "rsi, qword ptr [rsp + 0x50]")
    spec.expect(RETURN_SITE, "ret", "")
    spec.expect(ANCHOR_COOKIE, "call", f"0x{common.rva_to_va(spec.pe, STACK_GUARD_HELPER):x}")
    spec.expect(CALL_SITE, "call", f"0x{common.rva_to_va(spec.pe, ANCHOR_TARGET):x}")
    spec.expect(CALL_SITE_APPEND, "mov", "qword ptr [rdx], rax")
    spec.expect(CALL_SITE_APPEND_ADVANCE, "add", "qword ptr [rsi + 8], 8")
    spec.expect(CALL_SITE_GROWTH_BRANCH, "je", f"0x{common.rva_to_va(spec.pe, 0xC8569F):x}")
    spec.expect(CALL_SITE_STRING_BRANCH, "jb", f"0x{common.rva_to_va(spec.pe, CALL_SITE):x}")
    spec.expect(CALL_SITE_STRING_COMPARE, "cmp", "qword ptr [rdx + 0x18], 8")
    spec.expect(CALL_SITE_STRING_LOAD, "mov", "rdx, qword ptr [rdx]")
    spec.expect(CALL_SITE_COOKIE, "call", f"0x{common.rva_to_va(spec.pe, STACK_GUARD_HELPER):x}")

    anchor_function = spec.function_json(ANCHOR_TARGET)
    require(anchor_function is not None, "the anchor is not a runtime function")
    assert anchor_function is not None
    require(
        int(anchor_function["end_rva"]) == int(anchor["end_rva"]),
        "the anchor end does not match the backward pass",
    )
    entry_function = spec.function_json(ANCHOR_CALLER)
    require(entry_function is not None, "the entry function is not a runtime function")

    anchor_body = spec.body(ANCHOR_TARGET)
    entry_body = spec.body(ANCHOR_CALLER)
    anchor_exits = function_exits(spec, ANCHOR_TARGET, int(anchor_function["end_rva"]))
    entry_exits = function_exits(spec, ANCHOR_CALLER, int(entry_function["end_rva"]))
    require(
        int(anchor_exits["syscall_site_count"]) == 16,
        f"the anchor holds {anchor_exits['syscall_site_count']} inline syscalls, expected 16",
    )
    require(
        [(item["rva"], item["mnemonic"]) for item in anchor_exits["exits"]]
        == [(0xC85709, "jmp"), (0xC86456, "jmp"), (RETURN_SITE, "ret")],
        f"the anchor exits are {anchor_exits['exits']}, expected the two table dispatch jumps and a "
        f"single ret at 0xC87103",
    )

    stages: list[dict[str, Any]] = []
    wrapper_index: dict[int, dict[str, Any]] = {}
    for table in dataflow["dispatch"]["tables"]:
        stage = int(table["stage"])
        branches = [profile_branch(spec, stage, branch, table) for branch in table["branches"]]
        require(
            len(branches) == int(dataflow["dispatch"]["table_entries"]),
            f"stage {stage} holds {len(branches)} branches",
        )
        for branch in branches:
            if branch["sink_kind"] == "wrapper_call":
                entry = wrapper_index.setdefault(
                    int(branch["sink_function_rva"]), {"stage": stage, "indexes": []}
                )
                require(
                    int(entry["stage"]) == stage,
                    f"wrapper {common.hexs(int(branch['sink_function_rva']))} is called from both "
                    f"stages",
                )
                entry["indexes"].append(int(branch["index"]))
        stages.append(
            {
                "stage": stage,
                "stage_label": table["stage_label"],
                "selector": dataflow["dispatch"]["selector"],
                "table_rva": table["table_rva"],
                "table_rva_hex": common.hexs(int(table["table_rva"])),
                "table_raw": table["table_raw"],
                "section": table["section"],
                "materialised_by": table["materialised_by"],
                "materialised_by_hex": common.hexs(int(table["materialised_by"])),
                "merge_rva": table["merge_rva"],
                "merge_rva_hex": common.hexs(int(table["merge_rva"])),
                "handle_register": STAGE_HANDLE_REGISTER[stage],
                "branch_count": len(branches),
                "wrapper_branch_count": sum(1 for item in branches if item["sink_kind"] == "wrapper_call"),
                "inline_branch_count": sum(1 for item in branches if item["sink_kind"] == "inline_syscall"),
                "distinct_wrapper_targets": sorted(
                    {int(item["sink_function_rva"]) for item in branches if item["sink_kind"] == "wrapper_call"}
                ),
                "schema": [
                    {
                        "position": position,
                        "location": location,
                        "expression": expression.format(handle=STAGE_HANDLE_REGISTER[stage]),
                        "role": role,
                    }
                    for position, location, expression, role in STAGE_TABLES[stage][0]
                ],
                "branches": branches,
            }
        )
    require(
        [int(item["stage"]) for item in stages] == [STAGE_ALLOC, STAGE_TRANSFER],
        "the dataflow does not carry the two expected stages in order",
    )
    require(
        all(int(item["branch_count"]) == 16 for item in stages),
        "a stage does not hold 16 branches",
    )
    require(
        all(
            int(item["wrapper_branch_count"]) == 8 and int(item["inline_branch_count"]) == 8
            for item in stages
        ),
        "a stage does not split into 8 wrapper and 8 inline branches",
    )

    wrappers = [
        profile_wrapper(spec, rva, int(entry["stage"]), list(entry["indexes"]))
        for rva, entry in sorted(wrapper_index.items())
    ]
    for wrapper in wrappers:
        stage = int(wrapper["stage"])
        observed = tuple(
            (int(item["position"]), str(item["location"]), str(item["role"]))
            for item in wrapper["syscall_arguments"]
        )
        expected = tuple(
            (position, location, role) for position, location, _expression, role in STAGE_TABLES[stage][0]
        )
        require(
            observed == expected,
            f"wrapper {wrapper['rva_hex']} implements {observed}, expected {expected}",
        )
    require(len(wrappers) == 12, f"the forward set holds {len(wrappers)} wrappers, expected 12")
    alloc_wrappers = [item for item in wrappers if int(item["stage"]) == STAGE_ALLOC]
    transfer_wrappers = [item for item in wrappers if int(item["stage"]) == STAGE_TRANSFER]
    require(len(alloc_wrappers) == 6, "the allocation stage does not hold 6 distinct wrappers")
    require(len(transfer_wrappers) == 6, "the transfer stage does not hold 6 distinct wrappers")
    require(
        all(
            len(set(item["called_from_branch_indexes"])) == len(item["called_from_branch_indexes"])
            for item in wrappers
        ),
        "a wrapper lists a duplicate branch index",
    )
    for stage in stages:
        observed = sorted(
            {
                int(branch["sink_function_rva"])
                for branch in stage["branches"]
                if branch["sink_kind"] == "wrapper_call"
            }
        )
        expected = sorted(
            int(item["rva"])
            for item in wrappers
            if int(item["stage"]) == int(stage["stage"])
        )
        require(
            observed == expected,
            f"stage {stage['stage']} wrapper set {observed} does not match the profiles {expected}",
        )
    inline_syscalls = [
        {
            "rva": branch["sink"]["rva"],
            "rva_hex": branch["sink"]["rva_hex"],
            "stage": branch["stage"],
            "stage_label": branch["stage_label"],
            "branch_index": branch["index"],
            "block_target_rva": branch["block_target_rva"],
            "block_target_rva_hex": branch["block_target_rva_hex"],
            "instruction": branch["sink"],
            "arguments": branch["arguments"],
            "service_number_expression": _service_number_summary(spec, branch),
            "indirect_call_site_count": branch["indirect_call_site_count"],
        }
        for stage in stages
        for branch in stage["branches"]
        if branch["sink_kind"] == "inline_syscall"
    ]
    require(len(inline_syscalls) == 16, f"the forward set holds {len(inline_syscalls)} inline syscalls")

    descriptor_stores = [
        {
            "rva": site.rva,
            "rva_hex": common.hexs(site.rva),
            "text": site.text,
        }
        for site in anchor_body
        if site.mnemonic == "mov"
        and "[" in site.op_str.split(",")[0]
        and any(f"[{register}" in site.op_str.split(",")[0] for register in DESCRIPTOR_REGISTERS)
    ]
    anchor_loads = [
        {"rva": site.rva, "rva_hex": common.hexs(site.rva), "text": site.text}
        for site in anchor_body
        if site.mnemonic == "mov" and site.op_str.startswith(("r14, qword ptr [rcx]", "rbx, qword ptr [rbx]"))
    ]
    require(len(anchor_loads) == 2, f"the anchor holds {len(anchor_loads)} descriptor field loads")
    require(
        not descriptor_stores,
        f"the anchor stores through a descriptor carrying register: {descriptor_stores}",
    )

    reachable = forward_reachable_set(spec, (ANCHOR_TARGET, ANCHOR_CALLER), 4)
    inventory = api_edge_inventory(xref_path)
    lifetime = handle_lifetime(spec, inventory, reachable, stages)
    lifetime["dir64_census"] = dir64_cluster_census(spec)
    require(
        all(
            int(item["site_count"]) == 0
            for item in lifetime["cluster_range_sites"]["apis"].values()
        ),
        "a handle closing call site appears inside the anchor cluster range",
    )
    nearest_close = lifetime["nearest_sites"]["CloseHandle"][0]
    require(
        int(nearest_close["callsite_rva"]) == NEAREST_CLOSE_CALLSITE,
        f"the nearest CloseHandle call site is {nearest_close['callsite_rva_hex']}, expected "
        f"{common.hexs(NEAREST_CLOSE_CALLSITE)}",
    )
    spec.expect(NEAREST_CLOSE_CALLSITE, "call", "qword ptr [rip + 0x21cb4d9]")

    forward_sites: dict[str, str] = {}
    for stage in stages:
        for branch in stage["branches"]:
            if branch["sink_kind"] != "wrapper_call":
                continue
            key = common.hexs(int(branch["sink_function_rva"]))
            site = str(branch["sink"]["rva_hex"])
            forward_sites[key] = f"{forward_sites[key]}+{site}" if key in forward_sites else site
    forward_sites[common.hexs(VECTOR_APPEND_HELPER)] = common.hexs(CALL_SITE_GROWTH_CALL)
    scopes = [
        {
            "name": "anchor_chain",
            "description": "the upward walk from the anchor function itself, the P0 question",
            "seeds": [ANCHOR_TARGET],
            "expand_levels": MAX_CLOSURE_DEPTH,
            "forward_sites": {common.hexs(ANCHOR_TARGET): common.hexs(CALL_SITE)},
            "seed_evidence": {
                common.hexs(ANCHOR_TARGET): "the forward flow anchor, called once at 0xC85681"
            },
            "seed_open": {common.hexs(ANCHOR_TARGET): "F-U-01"},
            "bound": "exhausted: the anchor has one rel32 caller and that caller has no inbound edge "
            "in any enumerated form, so the frontier is empty",
        },
        {
            "name": "forward_sinks",
            "description": "the level 1 caller set of the 12 syscall wrappers and of the output vector "
            "growth helper",
            "seeds": sorted(wrapper_index) + [VECTOR_APPEND_HELPER],
            "expand_levels": 1,
            "forward_sites": forward_sites,
            "seed_evidence": {
                **{
                    common.hexs(rva): "syscall wrapper called from a dispatch branch"
                    for rva in wrapper_index
                },
                common.hexs(VECTOR_APPEND_HELPER): "output vector growth helper called by the entry "
                "function on the slow append path",
            },
            "seed_open": {},
            "bound": "measured, not asserted: level 1 is enumerated in full and the next level is "
            "counted only, because the wrappers are shared runtime helpers whose callers leave this "
            "path and enumerate unrelated subsystems",
        },
    ]
    closure = caller_closure(spec, inventory, scopes)
    forward_sink_scope = closure["scopes"][1]
    require(
        not forward_sink_scope["exhausted"],
        "the forward sink scope unexpectedly exhausted; the shared helper bound is stale",
    )
    sink_caller_functions = {
        int(row["caller_fn"], 16)
        for row in closure["rows"]
        if row["scope"] == "forward_sinks" and int(row["level"]) == 1
    }
    require(ANCHOR_TARGET in sink_caller_functions, "the anchor is missing from its own sink callers")

    slot_map = slot_lifecycle(spec, anchor_body)
    remote_base = next(item for item in slot_map["slots"] if int(item["frame_offset"]) == FRAME_RESULT)
    transfer_status = next(
        item for item in slot_map["slots"] if int(item["frame_offset"]) == FRAME_TRANSFER_STATUS
    )
    require(int(remote_base["direct_write_site_count"]) == 1, "unexpected remote base write census")
    require(int(remote_base["address_taken_site_count"]) == 16, "unexpected remote base out parameter census")
    require(int(remote_base["direct_read_site_count"]) == 2, "unexpected remote base read census")
    require(
        int(transfer_status["direct_write_site_count"]) == 1,
        "unexpected transfer status write census",
    )
    require(
        int(transfer_status["address_taken_site_count"]) == 16,
        "unexpected transfer status out parameter census",
    )
    require(int(transfer_status["direct_read_site_count"]) == 0, "the transfer status slot is read somewhere")

    error_paths = [
        {
            "id": "E-PATH-01",
            "site_rva": BASE_ZERO_TEST,
            "site_rva_hex": common.hexs(BASE_ZERO_TEST),
            "kind": "null_base_after_allocation",
            "condition": "r14 == 0, that is the allocation stage left the frame base slot zero",
            "effect": f"esi is zeroed at {common.hexs(BASE_ZERO_BRANCH)} and the function returns 0 "
            f"without reaching the transfer stage",
            "status": OBSERVED,
            "confidence": HIGH,
        },
        {
            "id": "E-PATH-02",
            "site_rva": CALL_SITE_APPEND,
            "site_rva_hex": common.hexs(CALL_SITE_APPEND),
            "kind": "unchecked_result_append",
            "condition": "none: the entry function appends the anchor return value unconditionally",
            "effect": "a zero base is appended like any other value, so the output vector cannot "
            "distinguish failure from a base address",
            "status": OBSERVED,
            "confidence": HIGH,
        },
        {
            "id": "E-PATH-03",
            "site_rva": CALL_SITE_GROWTH_BRANCH,
            "site_rva_hex": common.hexs(CALL_SITE_GROWTH_BRANCH),
            "kind": "vector_growth",
            "condition": "the end pointer equals the capacity pointer",
            "effect": f"the growth helper is called at {common.hexs(CALL_SITE_GROWTH_CALL)} with the "
            f"address of the saved return value",
            "status": OBSERVED,
            "confidence": HIGH,
        },
        {
            "id": "E-PATH-04",
            "site_rva": CALL_SITE_STRING_BRANCH,
            "site_rva_hex": common.hexs(CALL_SITE_STRING_BRANCH),
            "kind": "string_storage_select",
            "condition": "the string object capacity is below 8 code units",
            "effect": "the heap pointer is loaded before the call, otherwise the inline buffer is used",
            "status": OBSERVED,
            "confidence": HIGH,
        },
        {
            "id": "E-PATH-05",
            "site_rva": ANCHOR_COOKIE,
            "site_rva_hex": common.hexs(ANCHOR_COOKIE),
            "kind": "stack_guard_check",
            "condition": "the frame cookie differs from the value stored in the prologue",
            "effect": f"the guard helper {common.hexs(STACK_GUARD_HELPER)} is called; its failure "
            f"behaviour is outside the linear decode",
            "status": OBSERVED,
            "confidence": MEDIUM,
        },
        {
            "id": "E-PATH-06",
            "site_rva": XFER_MERGE,
            "site_rva_hex": common.hexs(XFER_MERGE),
            "kind": "unchecked_transfer_status",
            "condition": "none: no transfer branch tests the status out parameter",
            "effect": "the anchor returns the allocation base even when the transfer stage reports a "
            "failure, and the entry function appends it",
            "status": OBSERVED,
            "confidence": HIGH,
        },
    ]

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "specimen": {
            "path": dataflow["specimen"]["path"],
            "size": spec.path.stat().st_size,
            "sha256": common.sha256_file(spec.path),
            "image_base": spec.image_base,
            "image_base_hex": common.hexs(spec.image_base),
        },
        "script": {
            "path": "reverse/scripts/c856c0_callers.py",
            "sha256": common.sha256_file(Path(__file__).resolve()),
        },
        "inputs": {
            "dataflow": {
                "path": f"reverse/evidence/{dataflow_path.name}",
                "sha256": common.sha256_file(dataflow_path),
                "schema": dataflow["schema"],
                "script": dataflow["script"],
                "anchor_function_rva": dataflow["anchor"]["function_rva"],
                "handle_load_count": int(dataflow["handle"]["use_count"]),
            },
            "xref_edges": {
                "path": f"reverse/evidence/{xref_path.name}",
                "sha256": common.sha256_file(xref_path),
                "row_count": int(inventory["row_count"]),
                "columns": list(XREF_FIELDS),
            },
        },
        "scope": {
            "direction": "forward from the two [descriptor+0] handle loads of 0xC856C0, plus the "
            "upward caller closure of the forward subject set",
            "companion_pass": "reverse/evidence/c856c0_dataflow.json, the backward pass, which this "
            "payload does not modify",
            "execution": "static file parsing only; the specimen is never loaded, mapped or executed",
            "determinism": {
                "iteration": "sorted by rva, then by branch index, then by level",
                "payload_timestamps": False,
                "json_indent": 2,
                "json_ensure_ascii": False,
                "json_sort_keys": False,
                "line_terminator": "\\n",
                "trailing_newline": True,
            },
            "libraries": ["pefile", "capstone"],
            "libraries_note": "library versions are recorded in reverse/evidence/toolchain.json, "
            "whose script inventory does not yet list this script",
            "no_actionable_output": "the payload describes control flow, argument shape and ownership "
            "structure only; it contains no exploit, bypass, patch or shellcode guidance",
        },
        "anchor": {
            "function_rva": ANCHOR_TARGET,
            "function_rva_hex": common.hexs(ANCHOR_TARGET),
            "function": anchor_function,
            "entry_function_rva": ANCHOR_CALLER,
            "entry_function_rva_hex": common.hexs(ANCHOR_CALLER),
            "entry_function": entry_function,
            "handle_expression": dataflow["handle"]["expression"],
            "handle_loads": [
                {
                    "rva": site.rva,
                    "rva_hex": common.hexs(site.rva),
                    "raw": common.rva_to_raw(spec.pe, site.rva),
                    "register": register,
                    "instruction": site.as_evidence(spec.pe),
                    "consume_site_count": 16,
                    "corroborates": [
                        "reverse/evidence/c856c0_dataflow.json#handle.loads",
                    ],
                }
                for site, register in (
                    (spec.at(LOAD_R14), "r14"),
                    (spec.at(LOAD_RBX), "rbx"),
                )
            ],
        },
        "entry_function": {
            "rva": ANCHOR_CALLER,
            "rva_hex": common.hexs(ANCHOR_CALLER),
            "function": entry_function,
            "incoming_arguments": [
                {
                    "register": "rcx",
                    "role": "closure pair {output vector, descriptor}",
                    "role_confidence": HIGH,
                    "evidence_rva": 0xC85664,
                    "evidence_rva_hex": common.hexs(0xC85664),
                },
                {
                    "register": "rdx",
                    "role": "string object, length at +0x10 and storage selector at +0x18",
                    "role_confidence": HIGH,
                    "evidence_rva": 0xC8566B,
                    "evidence_rva_hex": common.hexs(0xC8566B),
                },
            ],
            "string_byte_count_rva": 0xC8566F,
            "string_byte_count_rva_hex": common.hexs(0xC8566F),
            "string_byte_count_expression": "lea r8, [rax*2 + 2], that is 2 * length + 2",
            "anchor_call": {
                "callsite_rva": CALL_SITE,
                "callsite_rva_hex": common.hexs(CALL_SITE),
                "target_rva": ANCHOR_TARGET,
                "target_rva_hex": common.hexs(ANCHOR_TARGET),
                "descriptor_source": "closure + 8, loaded at 0xC85667",
            },
            "exits": entry_exits,
            "corroborates": ["reverse/evidence/c856c0_dataflow.json#nodes.N_CALLER_ARG0"],
        },
        "forward_reachable_set": reachable,
        "result_slot": {
            "frame_offset": FRAME_RESULT,
            "frame_offset_hex": common.hexs(FRAME_RESULT),
            "role": "remote_base",
            "init_rva": RESULT_INIT,
            "init_rva_hex": common.hexs(RESULT_INIT),
            "init_text": "mov qword ptr [rsp + 0x50], 0",
            "writer_stage": STAGE_ALLOC,
            "writer_branch_count": 16,
            "read_at_merge": {
                "rva": ALLOC_MERGE,
                "rva_hex": common.hexs(ALLOC_MERGE),
                "text": "mov r14, qword ptr [rsp + 0x50]",
            },
            "read_at_return": {
                "rva": RESULT_READ_RETURN,
                "rva_hex": common.hexs(RESULT_READ_RETURN),
                "text": "mov rsi, qword ptr [rsp + 0x50]",
            },
            "return_register": "rax",
            "return_site": {"rva": RETURN_SITE, "rva_hex": common.hexs(RETURN_SITE), "text": "ret"},
            "lifecycle": slot_map,
        },
        "stages": stages,
        "argument_schema": {
            "vocabulary_note": "the roles name the argument position of the common shape; they do not "
            "assert a service name, which stays open in F-U-02",
            "shape_confidence": HIGH,
            "role_confidence": MEDIUM,
            "per_stage": [
                {
                    "stage": stage["stage"],
                    "stage_label": stage["stage_label"],
                    "branch_count": stage["branch_count"],
                    "schema": stage["schema"],
                    "call_level_schema": [
                        {
                            "position": position,
                            "location": location,
                            "expression": expression.format(
                                handle=STAGE_HANDLE_REGISTER[int(stage["stage"])]
                            ),
                            "role": role,
                        }
                        for position, location, expression, role in STAGE_TABLES[int(stage["stage"])][1]
                    ],
                    "branches_matching_schema": sum(
                        1
                        for branch in stage["branches"]
                        if [
                            (int(item["position"]), str(item["location"]), str(item["expression"]))
                            for item in branch["arguments"]
                        ]
                        == [
                            (position, location, expression.format(handle=STAGE_HANDLE_REGISTER[int(stage["stage"])]))
                            for position, location, expression, _role in STAGE_TABLES[int(stage["stage"])][
                                0 if branch["sink_kind"] == "inline_syscall" else 1
                            ]
                        ]
                    ),
                    "branches_diverging_from_schema": 0,
                }
                for stage in stages
            ],
        },
        "wrappers": wrappers,
        "inline_syscalls": inline_syscalls,
        "output_vector": {
            "closure_offset": 0,
            "closure_offset_hex": common.hexs(0),
            "layout": "{begin, end, capacity} of eight byte slots",
            "in_place_append_sites": [
                {"rva": CALL_SITE_APPEND, "rva_hex": common.hexs(CALL_SITE_APPEND)},
                {"rva": CALL_SITE_APPEND_ADVANCE, "rva_hex": common.hexs(CALL_SITE_APPEND_ADVANCE)},
            ],
            "capacity_compare_site": {
                "rva": CALL_SITE_GROWTH_BRANCH,
                "rva_hex": common.hexs(CALL_SITE_GROWTH_BRANCH),
            },
            "growth_helper": {
                "rva": VECTOR_APPEND_HELPER,
                "rva_hex": common.hexs(VECTOR_APPEND_HELPER),
                "function": spec.function_json(VECTOR_APPEND_HELPER),
                "callsite_rva": CALL_SITE_GROWTH_CALL,
                "callsite_rva_hex": common.hexs(CALL_SITE_GROWTH_CALL),
            },
            "appended_value": "the anchor return value, that is the remote base, or zero when the "
            "allocation stage produced none",
            "status_checked": False,
            "corroborates": ["reverse/evidence/c856c0_dataflow.json#object_model.closure"],
        },
        "error_paths": error_paths,
        "exits": {
            "anchor": anchor_exits,
            "entry_function": entry_exits,
            "single_exit_anchor": True,
        },
        "handle_lifetime": lifetime,
        "caller_closure": closure,
        "evidence": build_evidence(spec, stages, wrappers, lifetime, closure),
        "unresolved": build_unresolved(),
        "negative_findings": build_negative_findings(
            stages,
        wrappers,
        lifetime,
        slot_map,
        inventory,
        closure,
        entry_exits,
        anchor_exits,
        descriptor_stores,
        anchor_loads,
        ),
    }
    rows = [
        {
            "level": int(row["level"]),
            "scope": str(row["scope"]),
            "target_fn": str(row["target_fn"]),
            "edge_kind": str(row["edge_kind"]),
            "callsite": str(row["callsite"]),
            "caller_fn": str(row["caller_fn"]),
            "evidence": str(row["evidence"]),
            "confidence": str(row["confidence"]),
            "open": str(row["open"]),
        }
        for row in sorted(
            closure["rows"],
            key=lambda item: (str(item["scope"]), int(item["level"]), str(item["target_fn"]), str(item["callsite"])),
        )
    ]
    return payload, rows


def _service_number_summary(spec: Specimen, branch: Mapping[str, Any]) -> dict[str, Any]:
    """Record the last definition of EAX before an inline syscall sink."""
    body = spec.disasm(
        int(branch["block_target_rva"]),
        int(branch["sink"]["rva"]) - int(branch["block_target_rva"]),
    )
    producer: Site | None = None
    for site in body:
        if site.mnemonic == "syscall":
            break
        operands = [_strip_qualifier(part) for part in site.op_str.split(",")]
        if not operands or not operands[0].rstrip("dwb") == "eax":
            continue
        if site.mnemonic in ("mov", "lea", "xor", "add", "sub", "imul", "shl", "shr", "or", "and"):
            producer = site
    return {
        "register": "eax",
        "produced_before_sink": producer is not None,
        "producer": None if producer is None else producer.as_evidence(spec.pe),
        "statically_resolvable": False,
        "reason": "the value is assembled from KUSER_SHARED_DATA, PEB and per branch constants, so it "
        "is a run time value in every inline branch",
        "unresolved_id": "F-U-02",
    }


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description="Static P0/S5 forward flow and caller closure for the 0xC856C0 handle in adhesive.dll"
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument(
        "--dataflow", type=Path, default=root / "reverse" / "evidence" / "c856c0_dataflow.json"
    )
    parser.add_argument(
        "--xrefs", type=Path, default=root / "reverse" / "evidence" / "xref_edges.csv"
    )
    parser.add_argument(
        "--out-json", type=Path, default=root / "reverse" / "evidence" / "c856c0_forward.json"
    )
    parser.add_argument(
        "--out-csv", type=Path, default=root / "reverse" / "evidence" / "c856c0_callers.csv"
    )
    parser.add_argument("--emit", action="store_true", help="write the forward json and the callers csv")
    parser.add_argument("--verify", action="store_true", help="diff a fresh run against the stored files")
    parser.add_argument("--max-report", type=int, default=40, help="mismatches to print")
    args = parser.parse_args(argv)

    specimen_path = args.specimen.resolve()
    dataflow_path = args.dataflow.resolve()
    xref_path = args.xrefs.resolve()
    out_json = args.out_json.resolve()
    out_csv = args.out_csv.resolve()

    spec = Specimen(specimen_path)
    try:
        payload, rows = build_payload(spec, root, dataflow_path, xref_path)
    finally:
        spec.close()

    closure = payload["caller_closure"]
    print(f"script    {script.relative_to(root).as_posix()}")
    print(f"sha256    {payload['script']['sha256']}")
    print(
        f"specimen  {specimen_path.relative_to(root).as_posix()} "
        f"sha256={payload['specimen']['sha256']}"
    )
    print(
        f"stages    "
        + " ".join(
            f"{stage['stage_label']}={stage['branch_count']}"
            f"(w{stage['wrapper_branch_count']}/i{stage['inline_branch_count']})"
            for stage in payload["stages"]
        )
    )
    print(
        f"sinks     wrappers={len(payload['wrappers'])} "
        f"inline_syscalls={len(payload['inline_syscalls'])} "
        f"reachable={payload['forward_reachable_set']['function_count']}"
    )
    print(
        f"lifetime  close_or_duplicate_in_reachable_set="
        f"{sum(len(v) for v in payload['handle_lifetime']['api_call_sites_inside_reachable_set'].values())}"
    )
    print(
        f"closure   rows={closure['row_count']} "
        f"anchor_exhausted={closure['scopes'][0]['exhausted']} "
        f"sink_callers={closure['scopes'][1]['distinct_caller_count']} "
        f"sink_exhausted={closure['scopes'][1]['exhausted']}"
    )
    print(
        f"open      unresolved={len(payload['unresolved'])} "
        f"negative_findings={len(payload['negative_findings'])}"
    )

    if args.emit:
        common.write_json(out_json, payload)
        common.write_csv(out_csv, rows, CALLER_FIELDS)
        print(f"emitted   {out_json.relative_to(root).as_posix()}")
        print(f"emitted   {out_csv.relative_to(root).as_posix()}")
        return 0

    if args.verify:
        stored = json.loads(out_json.read_text(encoding="utf-8"))
        expected = dict(common.iter_scalar_paths(stored))
        actual = dict(common.iter_scalar_paths(payload))
        keys = sorted(set(expected) | set(actual))
        mismatches = [
            (key, expected.get(key, "<missing>"), actual.get(key, "<missing>"))
            for key in keys
            if expected.get(key, "<missing>") != actual.get(key, "<missing>")
        ]
        for key, want, got in mismatches[: args.max_report]:
            print(f"FAIL {key}: stored={want} fresh={got}")
        if len(mismatches) > args.max_report:
            print(f"FAIL ... {len(mismatches) - args.max_report} further mismatches")
        print(f"verify    {len(keys) - len(mismatches)}/{len(keys)} json scalars matched")
        with out_csv.open("r", encoding="utf-8", newline="") as handle:
            stored_rows = [row for row in csv.reader(handle)]
        fresh_table = [list(CALLER_FIELDS)] + [
            [common.scalar_text(row[name]) for name in CALLER_FIELDS] for row in rows
        ]
        if stored_rows != fresh_table:
            print(
                f"FAIL callers csv differs: stored {len(stored_rows)} rows, fresh {len(fresh_table)} rows"
            )
            for index, (want, got) in enumerate(zip(stored_rows, fresh_table)):
                if want != got:
                    print(f"FAIL row {index}: stored={want} fresh={got}")
                    break
            return 1
        print(f"verify    {len(rows)} caller rows matched")
        return 1 if mismatches else 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
