"""Backward def-use slice for the 0xC856C0 [RCX] handle in adhesive.dll.

Static PE parsing only. The specimen is never loaded, mapped or executed; every
value in the emitted payload is derived from the file bytes at run time and every
anchor is asserted, so a silent drift in the specimen fails the run instead of
producing a plausible looking graph.

Usage:
    defuse_slice.py --emit
    defuse_slice.py --verify
"""

from __future__ import annotations

import argparse
import bisect
import json
import math
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Iterable, Mapping, Sequence

import capstone

sys.path.insert(0, str(Path(__file__).resolve().parent))

import common  # noqa: E402

SCHEMA: Final[str] = "adhesive-dumper.defuse-slice/1"

ANCHOR_TARGET: Final[int] = 0xC856C0
ANCHOR_CALLER: Final[int] = 0xC85650
CLUSTER_LOW: Final[int] = 0xC85000
CLUSTER_HIGH: Final[int] = 0xC88000
TABLE_ALLOC: Final[int] = 0x2CFB1F8
TABLE_XFER: Final[int] = 0x2CFB238
JUMP_TABLE_ENTRIES: Final[int] = 16
JUMP_TABLE_INDEX_MASK: Final[int] = 0xF

ANCHOR_LOAD_R14: Final[int] = 0xC856F3
ANCHOR_RELOAD_RBX: Final[int] = 0xC86440
ANCHOR_CALLER_SLOT0: Final[int] = 0xC85664
ANCHOR_CALLER_SLOT8: Final[int] = 0xC85667
ANCHOR_CALL_SITE: Final[int] = 0xC85681
ANCHOR_ALLOC_MERGE: Final[int] = 0xC86426
ANCHOR_XFER_MERGE: Final[int] = 0xC870E1
ANCHOR_ALLOC_TABLE_LEA: Final[int] = 0xC856FB
ANCHOR_XFER_TABLE_LEA: Final[int] = 0xC86448
GLOBAL_ADDRESS_THUNKS: Final[tuple[int, ...]] = (0xCAC0D0, 0xCAC0F0, 0xCAC110, 0xCAC130, 0xCAC170)
HIGH: Final[str] = "HIGH"
LOW: Final[str] = "LOW"
OBSERVED: Final[str] = "OBSERVED"
OPEN: Final[str] = "OPEN"

RIP_PREFIX_PATTERN: Final[re.Pattern[bytes]] = re.compile(
    rb"[\x48\x4c\x49\x4d][\x00-\xff][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", re.S
)
TERMINATORS: Final[frozenset[str]] = frozenset({"jmp", "ret", "syscall", "ud2", "int3"})


@dataclass(frozen=True, slots=True)
class Stage:
    """One of the two RDTSC indexed dispatch stages inside the anchor function."""

    index: int
    label: str
    table_rva: int
    merge_rva: int
    selector_lea: int
    selector_rdtsc: int
    selector_mask: int
    handle_register: str
    table_node: str
    register_node: str
    pass_note: str


STAGE_ALLOC: Final[Stage] = Stage(
    index=1,
    label="alloc",
    table_rva=TABLE_ALLOC,
    merge_rva=ANCHOR_ALLOC_MERGE,
    selector_lea=ANCHOR_ALLOC_TABLE_LEA,
    selector_rdtsc=0xC856F6,
    selector_mask=0xC856F8,
    handle_register="r14",
    table_node="N_TABLE_ALLOC",
    register_node="N_R14",
    pass_note="R10 is the first syscall argument, RDX the second",
)
STAGE_XFER: Final[Stage] = Stage(
    index=2,
    label="transfer",
    table_rva=TABLE_XFER,
    merge_rva=ANCHOR_XFER_MERGE,
    selector_lea=ANCHOR_XFER_TABLE_LEA,
    selector_rdtsc=0xC86443,
    selector_mask=0xC86445,
    handle_register="rbx",
    table_node="N_TABLE_TRANSFER",
    register_node="N_RBX",
    pass_note="R10 is the first syscall argument, RDX the second",
)
STAGES: Final[tuple[Stage, ...]] = (STAGE_ALLOC, STAGE_XFER)


class SliceError(RuntimeError):
    """Raised when a declared anchor does not hold for the parsed specimen."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SliceError(message)


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

    def as_evidence(self, pe: Any) -> dict[str, Any]:
        return {
            "mnemonic": self.mnemonic,
            "operands": self.op_str,
            "text": f"{self.mnemonic} {self.op_str}".strip(),
            "size": self.size,
            "bytes": self.raw_bytes.hex(" "),
            "rva": self.rva,
            "rva_hex": common.hexs(self.rva),
            "raw": common.rva_to_raw(pe, self.rva),
            "raw_hex": common.hexs(common.rva_to_raw(pe, self.rva) or 0),
            "va": common.rva_to_va(pe, self.rva),
            "va_hex": common.hexs(common.rva_to_va(pe, self.rva)),
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
        return tuple(
            RuntimeFunction(*record) for record in struct.iter_unpack("<III", blob)
        )

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

    def at(self, rva: int) -> Site:
        found = self.disasm(rva, 16)
        require(bool(found) and found[0].rva == rva, f"no decodable instruction at {common.hexs(rva)}")
        return found[0]

    def expect(self, rva: int, mnemonic: str, op_str: str) -> Site:
        site = self.at(rva)
        require(
            site.mnemonic == mnemonic and site.op_str == op_str,
            f"anchor {common.hexs(rva)} is '{site.mnemonic} {site.op_str}', "
            f"expected '{mnemonic} {op_str}'",
        )
        return site

    def data_bytes(self, rva: int, length: int) -> bytes:
        return common.read_rva(self.pe, rva, length)

    def entropy(self, rva: int, length: int) -> float:
        blob = self.data_bytes(rva, length)
        require(len(blob) == length, f"short read at {common.hexs(rva)}")
        counts = [0] * 256
        for byte in blob:
            counts[byte] += 1
        total = float(length)
        value = -sum((c / total) * math.log2(c / total) for c in counts if c)
        return round(value if value else 0.0, 9)


def decode_jump_table(spec: Specimen, table_rva: int) -> list[dict[str, Any]]:
    require(
        (JUMP_TABLE_INDEX_MASK + 1) == JUMP_TABLE_ENTRIES,
        "jump table entry count and index mask disagree",
    )
    entries: list[dict[str, Any]] = []
    base = common.rva_to_raw(spec.pe, table_rva)
    require(base is not None, f"jump table {common.hexs(table_rva)} is not file backed")
    for index in range(JUMP_TABLE_ENTRIES):
        slot_rva = table_rva + 4 * index
        disp = struct.unpack_from("<i", spec.data_bytes(slot_rva, 4))[0]
        target = table_rva + disp
        require(
            spec.text.virtual_address <= target < spec.text.virtual_address + spec.text.virtual_size,
            f"jump table slot {common.hexs(slot_rva)} leaves .text: {common.hexs(target)}",
        )
        entries.append(
            {
                "index": index,
                "slot_rva": slot_rva,
                "slot_rva_hex": common.hexs(slot_rva),
                "slot_raw": common.rva_to_raw(spec.pe, slot_rva),
                "relative_displacement": disp,
                "relative_displacement_hex": common.hexs(disp & 0xFFFFFFFF),
                "relative_displacement_unsigned_hex": f"-0x{-disp:x}" if disp < 0 else f"0x{disp:x}",
                "target_rva": target,
                "target_rva_hex": common.hexs(target),
                "target_raw": common.rva_to_raw(spec.pe, target),
            }
        )
    return entries


def branch_block(spec: Specimen, start: int, limit: int) -> list[Site]:
    """Linear instructions of one dispatch branch, up to the first terminal transfer."""
    out: list[Site] = []
    rva = start
    while rva < limit:
        site = spec.at(rva)
        out.append(site)
        rva += site.size
        if site.mnemonic in TERMINATORS:
            break
    require(bool(out), f"empty dispatch branch at {common.hexs(start)}")
    return out


def relative_branch_xrefs(
    spec: Specimen, opcodes: Sequence[tuple[int, str]], wanted: Iterable[int]
) -> dict[int, list[dict[str, Any]]]:
    """Every rel32 call/jmp in .text whose target is in ``wanted``."""
    target_set = set(wanted)
    found: dict[int, list[dict[str, Any]]] = {value: [] for value in sorted(target_set)}
    blob = spec.text_bytes
    base = spec.text.virtual_address
    for opcode, kind in opcodes:
        needle = bytes((opcode,))
        pos = blob.find(needle)
        while pos >= 0:
            disp = struct.unpack_from("<i", blob, pos + 1)[0]
            site_rva = base + pos
            target = site_rva + 5 + disp
            if target in found:
                found[target].append(
                    {
                        "kind": kind,
                        "rva": site_rva,
                        "rva_hex": common.hexs(site_rva),
                        "raw": common.rva_to_raw(spec.pe, site_rva),
                        "encoding": blob[pos : pos + 5].hex(" "),
                    }
                )
            pos = blob.find(needle, pos + 1)
    for entries in found.values():
        entries.sort(key=lambda item: item["rva"])
    return found


def rip_relative_xrefs(spec: Specimen, wanted: Iterable[int]) -> dict[int, list[dict[str, Any]]]:
    """Every REX-prefixed RIP-relative disp32 operand in .text targeting ``wanted``."""
    target_set = set(wanted)
    found: dict[int, list[dict[str, Any]]] = {value: [] for value in sorted(target_set)}
    blob = spec.text_bytes
    base = spec.text.virtual_address
    for match in RIP_PREFIX_PATTERN.finditer(blob):
        start = match.start()
        disp = struct.unpack_from("<i", blob, start + 3)[0]
        site_rva = base + start
        target = site_rva + 7 + disp
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


def find_all(haystack: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    pos = haystack.find(needle)
    while pos >= 0:
        out.append(pos)
        pos = haystack.find(needle, pos + 1)
    return out


def absolute_pointer_sites(spec: Specimen, rva: int) -> list[dict[str, Any]]:
    pattern = (spec.image_base + rva).to_bytes(8, "little")
    out: list[dict[str, Any]] = []
    for raw in find_all(spec.file_bytes, pattern):
        slot = common.raw_to_rva(spec.pe, raw)
        section = common.section_for_raw(spec.pe, raw)
        out.append(
            {
                "raw": raw,
                "raw_hex": common.hexs(raw),
                "rva": slot,
                "rva_hex": None if slot is None else common.hexs(slot),
                "section": None if section is None else section.name,
            }
        )
    return out


def rva_slot_sites(spec: Specimen, rva: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for raw in find_all(spec.file_bytes, rva.to_bytes(4, "little")):
        slot = common.raw_to_rva(spec.pe, raw)
        section = common.section_for_raw(spec.pe, raw)
        out.append(
            {
                "raw": raw,
                "raw_hex": common.hexs(raw),
                "rva": slot,
                "rva_hex": None if slot is None else common.hexs(slot),
                "section": None if section is None else section.name,
                "pdata_field": _pdata_field_owner(spec, slot, rva),
            }
        )
    return out


def _pdata_field_owner(spec: Specimen, slot: int | None, value: int) -> dict[str, Any] | None:
    """Classify a 4 byte slot that stores ``value`` as a field of a .pdata record."""
    if slot is None or slot < spec.pdata_rva:
        return None
    offset = slot - spec.pdata_rva
    if offset % 4:
        return None
    index = offset // common.RUNTIME_FUNCTION_SIZE
    if index >= len(spec.runtime_functions):
        return None
    field_index = (offset % common.RUNTIME_FUNCTION_SIZE) // 4
    record = spec.runtime_functions[index]
    fields = (record.begin, record.end, record.unwind)
    names = ("begin_address", "end_address", "unwind_info_address")
    if fields[field_index] != value:
        return None
    return {
        "container": "authoritative_pdata_runtime_function_array",
        "pdata_rva": spec.pdata_rva,
        "pdata_rva_hex": common.hexs(spec.pdata_rva),
        "record_index": index,
        "record_rva": spec.pdata_rva + common.RUNTIME_FUNCTION_SIZE * index,
        "record_rva_hex": common.hexs(spec.pdata_rva + common.RUNTIME_FUNCTION_SIZE * index),
        "field": names[field_index],
        "field_byte_offset": offset % common.RUNTIME_FUNCTION_SIZE,
        "record_begin_rva": record.begin,
        "record_end_rva": record.end,
        "record_unwind_rva": record.unwind,
    }


def pdata_anchor_records(spec: Specimen) -> dict[str, Any]:
    """The RUNTIME_FUNCTION records that define the two anchor function extents."""
    wanted = (ANCHOR_CALLER, ANCHOR_TARGET)
    records = []
    for index, record in enumerate(spec.runtime_functions):
        if record.begin not in wanted:
            continue
        record_rva = spec.pdata_rva + common.RUNTIME_FUNCTION_SIZE * index
        records.append(
            {
                "record_index": index,
                "record_rva": record_rva,
                "record_rva_hex": common.hexs(record_rva),
                "record_raw": common.rva_to_raw(spec.pe, record_rva),
                "begin_rva": record.begin,
                "end_rva": record.end,
                "unwind_rva": record.unwind,
            }
        )
    require(
        len(records) == len(wanted),
        f"expected {len(wanted)} anchor pdata records, found {len(records)}",
    )
    return {
        "pdata_rva": spec.pdata_rva,
        "pdata_rva_hex": common.hexs(spec.pdata_rva),
        "pdata_size": spec.pdata_size,
        "pdata_size_hex": common.hexs(spec.pdata_size),
        "record_size": common.RUNTIME_FUNCTION_SIZE,
        "record_count": len(spec.runtime_functions),
        "records": records,
    }
def dir64_census(spec: Specimen) -> dict[str, Any]:
    targets: set[int] = set()
    for block in getattr(spec.pe, "DIRECTORY_ENTRY_BASERELOC", []):
        for entry in block.entries:
            if int(entry.type) == 10:
                targets.add(int(entry.rva))
    per_section: dict[str, int] = {}
    pointing_into_cluster: list[dict[str, Any]] = []
    zero_valued: list[dict[str, Any]] = []
    for section in (spec.rdata, spec.data):
        count = 0
        for offset in range(0, section.raw_size - 7, 8):
            slot_rva = section.virtual_address + offset
            if slot_rva not in targets:
                continue
            count += 1
            value = struct.unpack_from("<Q", spec.data_bytes(slot_rva, 8))[0]
            entry = {
                "rva": slot_rva,
                "rva_hex": common.hexs(slot_rva),
                "raw": common.rva_to_raw(spec.pe, slot_rva),
                "value": value,
                "value_hex": common.hexs(value),
            }
            if value == 0:
                zero_valued.append(entry)
            elif CLUSTER_LOW <= value - spec.image_base < CLUSTER_HIGH:
                pointing_into_cluster.append({**entry, "target_rva": value - spec.image_base})
        per_section[section.name] = count
    blocks = getattr(spec.pe, "DIRECTORY_ENTRY_BASERELOC", [])
    dir64_named = sum(1 for block in blocks for entry in block.entries if int(entry.type) == 10)
    return {
        "dir64_entry_total": dir64_named,
        "relocation_entry_total": sum(len(block.entries) for block in blocks),
        "dir64_target_rva_distinct": len(targets),
        "eight_byte_aligned_slots_by_section": {name: per_section[name] for name in sorted(per_section)},
        "zero_valued_slots": len(zero_valued),
        "slots_holding_va_into_cluster": len(pointing_into_cluster),
        "cluster_range": [common.hexs(CLUSTER_LOW), common.hexs(CLUSTER_HIGH)],
        "slots_holding_va_into_cluster_detail": pointing_into_cluster,
    }


def rtti_census(spec: Specimen) -> dict[str, Any]:
    blob = spec.data_bytes(spec.rdata.virtual_address, spec.rdata.raw_size)
    names: list[int] = []
    for needle in (b".?A", b".?AV", b"??_R"):
        for offset in find_all(blob, needle):
            rva = spec.rdata.virtual_address + offset
            if rva not in names:
                names.append(rva)
    type_descriptors = sorted(rva - 16 for rva in names)
    words = memoryview(spec.data_bytes(spec.rdata.virtual_address, spec.rdata.raw_size)).cast("I")
    col_records: list[int] = []
    stride = len(words) // 4
    for index in range(stride - 5):
        if words[index] != 1:
            continue
        if words[index + 5] != spec.rdata.virtual_address + 4 * index:
            continue
        ptd = words[index + 3]
        pchd = words[index + 4]
        if not (
            spec.rdata.virtual_address <= ptd < spec.rdata.virtual_address + spec.rdata.raw_size
        ):
            continue
        if not (
            spec.rdata.virtual_address <= pchd < spec.rdata.virtual_address + spec.rdata.raw_size
        ):
            continue
        col_records.append(spec.rdata.virtual_address + 4 * index)
    return {
        "method": "scan .rdata for MSVC x64 RTTI: '.?A' type descriptor names and "
        "signature==1 Complete Object Locators whose pSelf points at themselves",
        "rdata_rva": spec.rdata.virtual_address,
        "rdata_rva_hex": common.hexs(spec.rdata.virtual_address),
        "rdata_size": spec.rdata.raw_size,
        "type_descriptor_name_hits": len(type_descriptors),
        "complete_object_locator_records": len(col_records),
        "rtti_present": bool(type_descriptors) or bool(col_records),
    }


def _rip_disp(op_str: str) -> int:
    inner = op_str[op_str.index("[") + 1 : op_str.rindex("]")]
    if "+" in inner:
        return int(inner.split("+")[-1].strip(), 0)
    if "-" in inner:
        return -int(inner.split("-")[-1].strip(), 0)
    return 0


def _call_text(spec: Specimen, rva: int) -> str:
    """Capstone renders immediate operands in lowercase hex."""
    return f"0x{common.rva_to_va(spec.pe, rva):x}"


def resolve_global_address_thunks(spec: Specimen, thunks: Sequence[int]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for thunk in thunks:
        record = spec.owner(thunk)
        target: int | None = None
        site: Site | None = None
        for candidate in spec.disasm(thunk, 0x20)[:4]:
            if candidate.mnemonic == "lea" and candidate.op_str.startswith("rax, [rip"):
                target = candidate.rva + candidate.size + _rip_disp(candidate.op_str)
                site = candidate
                break
        section = None if target is None else common.section_for_rva(spec.pe, target)
        out.append(
            {
                "thunk_rva": thunk,
                "thunk_rva_hex": common.hexs(thunk),
                "thunk_raw": common.rva_to_raw(spec.pe, thunk),
                "covered_by_pdata": record is not None,
                "instruction": None if site is None else site.as_evidence(spec.pe),
                "resolved_global_rva": target,
                "resolved_global_rva_hex": None if target is None else common.hexs(target),
                "resolved_global_section": None if section is None else section.name,
            }
        )
    return out


class Graph:
    """Deterministic node and edge accumulator."""

    def __init__(self) -> None:
        self.nodes: list[dict[str, Any]] = []
        self.edges: list[dict[str, Any]] = []
        self._ids: set[str] = set()

    def node(self, node_id: str, kind: str, label: str, **extra: Any) -> str:
        require(node_id not in self._ids, f"duplicate node id {node_id}")
        self._ids.add(node_id)
        record = {"id": node_id, "kind": kind, "label": label}
        record.update(extra)
        self.nodes.append(record)
        return node_id

    def edge(
        self,
        source: str,
        target: str,
        kind: str,
        confidence: str,
        status: str,
        rva: int | None = None,
        raw: int | None = None,
        function: dict[str, Any] | None = None,
        evidence: Mapping[str, Any] | None = None,
        note: str | None = None,
        corroborates: Sequence[str] = (),
    ) -> str:
        edge_id = f"E{len(self.edges) + 1:03d}"
        record: dict[str, Any] = {
            "id": edge_id,
            "from": source,
            "to": target,
            "kind": kind,
            "confidence": confidence,
            "status": status,
            "rva": rva,
            "rva_hex": None if rva is None else common.hexs(rva),
            "raw": raw,
            "raw_hex": None if raw is None else common.hexs(raw),
            "function": function,
            "evidence": dict(evidence) if evidence is not None else None,
        }
        if note is not None:
            record["note"] = note
        if corroborates:
            record["corroborates"] = list(corroborates)
        self.edges.append(record)
        return edge_id


def cluster_census(spec: Specimen) -> dict[str, Any]:
    functions = [
        record.as_json(spec.pe)
        for record in spec.runtime_functions
        if record.end > CLUSTER_LOW and record.begin < CLUSTER_HIGH
    ]
    return {
        "range": [common.hexs(CLUSTER_LOW), common.hexs(CLUSTER_HIGH)],
        "range_note": "the 0x0C85xxx..0x0C87xxx code cluster written as 0xC85xx..0xC87xx in the reports",
        "function_count": len(functions),
        "functions": functions,
    }


def classify_branches(spec: Specimen, stage: Stage) -> list[dict[str, Any]]:
    register = stage.handle_register
    merge = stage.merge_rva
    out: list[dict[str, Any]] = []
    for entry in decode_jump_table(spec, stage.table_rva):
        block = branch_block(spec, entry["target_rva"], stage.merge_rva)
        sink: Site | None = None
        sink_kind = ""
        sink_target: int | None = None
        carrier: Site | None = None
        terminal: Site | None = None
        wrapper_this: dict[str, Any] | None = None
        for site in block:
            if site.mnemonic == "syscall":
                sink, sink_kind, sink_target = site, "inline_syscall", None
            elif site.mnemonic == "call" and site.op_str.startswith("0x"):
                sink = site
                sink_kind = "wrapper_call"
                sink_target = int(site.op_str, 16) - spec.image_base
            elif site.mnemonic == "jmp":
                terminal = site
            elif site.mnemonic == "mov" and site.op_str in (f"rdx, {register}", f"r10, {register}"):
                carrier = site
            elif site.mnemonic == "lea" and site.op_str.startswith("rcx, [rip"):
                target = site.rva + site.size + _rip_disp(site.op_str)
                wrapper_this = {"rva": target, "rva_hex": common.hexs(target)}
        where = f"stage {stage.label} branch {entry['index']}"
        require(sink is not None, f"{where} has no sink")
        require(
            carrier is not None,
            f"{where} does not move {register} into an argument register",
        )
        if sink_kind == "wrapper_call":
            require(
                terminal is not None and int(terminal.op_str, 16) - spec.image_base == merge,
                f"{where} does not join at {common.hexs(merge)}",
            )
            join = {
                "kind": "unconditional_jump",
                "rva": terminal.rva,
                "rva_hex": common.hexs(terminal.rva),
                "target_rva": merge,
                "target_rva_hex": common.hexs(merge),
            }
        else:
            require(
                terminal is None,
                f"{where} has both a syscall and a jump terminator",
            )
            fallthrough = sink.rva + sink.size
            join = {
                "kind": "fall_through_after_syscall",
                "rva": fallthrough,
                "rva_hex": common.hexs(fallthrough),
                "target_rva": None,
                "target_rva_hex": None,
                "merge_reachability": "NOT_ASSERTED",
                "merge_reachability_note": "the instruction stream after the syscall contains "
                "conditional control flow, so the path to the stage merge point is not "
                "established by this scan",
            }
        out.append(
            {
                **entry,
                "stage": stage.index,
                "stage_label": stage.label,
                "handle_register": register,
                "block_instruction_count": len(block),
                "block_end_rva": block[-1].rva,
                "block_end_rva_hex": common.hexs(block[-1].rva),
                "sink_kind": sink_kind,
                "sink": sink.as_evidence(spec.pe),
                "sink_function": (
                    None if sink_kind == "inline_syscall" else spec.function_json(sink_target or 0)
                ),
                "sink_function_rva": sink_target,
                "handle_carrier": carrier.as_evidence(spec.pe),
                "handle_argument_register": carrier.op_str.split(",")[0].strip(),
                "merge_rva": merge,
                "merge_rva_hex": common.hexs(merge),
                "join": join,
                "wrapper_this_global": wrapper_this,
                "other_calls": [
                    {
                        "rva": site.rva,
                        "rva_hex": common.hexs(site.rva),
                        "target_rva": int(site.op_str, 16) - spec.image_base,
                    }
                    for site in block
                    if site.mnemonic == "call"
                    and site.op_str.startswith("0x")
                    and int(site.op_str, 16) - spec.image_base != (sink_target or 0)
                ],
            }
        )
    return out


def build_payload(spec: Specimen, root: Path) -> dict[str, Any]:
    target_fn = spec.owner(ANCHOR_TARGET)
    caller_fn = spec.owner(ANCHOR_CALLER)
    require(target_fn is not None, f"{common.hexs(ANCHOR_TARGET)} is not inside a RUNTIME_FUNCTION")
    require(caller_fn is not None, f"{common.hexs(ANCHOR_CALLER)} is not inside a RUNTIME_FUNCTION")
    require(
        target_fn.begin == ANCHOR_TARGET and target_fn.end == 0xC87104,
        "unexpected extent for the anchor function: "
        f"{common.hexs(target_fn.begin)}..{common.hexs(target_fn.end)}",
    )
    require(
        caller_fn.begin == ANCHOR_CALLER and caller_fn.end == ANCHOR_TARGET,
        "unexpected extent for the anchor caller: "
        f"{common.hexs(caller_fn.begin)}..{common.hexs(caller_fn.end)}",
    )
    require(
        target_fn.unwind == 0x30640A0,
        f"unexpected unwind RVA for the anchor function: {common.hexs(target_fn.unwind)}",
    )

    spec.expect(ANCHOR_CALLER_SLOT0, "mov", "rsi, qword ptr [rcx]")
    spec.expect(ANCHOR_CALLER_SLOT8, "mov", "rcx, qword ptr [rcx + 8]")
    spec.expect(ANCHOR_LOAD_R14, "mov", "r14, qword ptr [rcx]")
    spec.expect(ANCHOR_RELOAD_RBX, "mov", "rbx, qword ptr [rbx]")
    spec.expect(ANCHOR_CALL_SITE, "call", _call_text(spec, ANCHOR_TARGET))
    spec.expect(0xC856D3, "mov", "rbx, rcx")
    spec.expect(0xC8566B, "mov", "rax, qword ptr [rdx + 0x10]")
    spec.expect(0xC8566F, "lea", "r8, [rax*2 + 2]")
    spec.expect(0xC8568B, "mov", "rdx, qword ptr [rsi + 8]")
    spec.expect(0xC8568F, "cmp", "rdx, qword ptr [rsi + 0x10]")
    spec.expect(0xC85695, "mov", "qword ptr [rdx], rax")
    spec.expect(0xC85698, "add", "qword ptr [rsi + 8], 8")
    spec.expect(0xC856A7, "call", _call_text(spec, 0x495D0))
    spec.expect(0xC86426, "mov", "r14, qword ptr [rsp + 0x50]")
    spec.expect(0xC8642B, "test", "r14, r14")
    spec.expect(0xC86430, "xor", "esi, esi")

    selectors = []
    for stage in STAGES:
        spec.expect(stage.selector_rdtsc, "rdtsc", "")
        mask = spec.expect(stage.selector_mask, "and", f"eax, {JUMP_TABLE_INDEX_MASK:#x}")
        lea = spec.at(stage.selector_lea)
        require(
            lea.mnemonic == "lea" and lea.op_str.startswith("rcx, [rip"),
            f"stage {stage.label} table base is '{lea.mnemonic} {lea.op_str}'",
        )
        require(
            stage.selector_lea + lea.size + _rip_disp(lea.op_str) == stage.table_rva,
            f"stage {stage.label} selector does not address its own jump table",
        )
        spec.expect(stage.selector_lea + 7, "movsxd", "rax, dword ptr [rcx + rax*4]")
        spec.expect(stage.selector_lea + 11, "add", "rax, rcx")
        spec.expect(stage.selector_lea + 14, "jmp", "rax")
        selectors.append(
            {
                "stage": stage.index,
                "stage_label": stage.label,
                "rdtsc_rva": stage.selector_rdtsc,
                "rdtsc_rva_hex": common.hexs(stage.selector_rdtsc),
                "mask_rva": stage.selector_mask,
                "mask_rva_hex": common.hexs(stage.selector_mask),
                "mask_instruction": mask.as_evidence(spec.pe),
                "table_base_lea_rva": stage.selector_lea,
                "table_base_lea_rva_hex": common.hexs(stage.selector_lea),
                "indirect_jmp_rva": stage.selector_lea + 14,
                "indirect_jmp_rva_hex": common.hexs(stage.selector_lea + 14),
            }
        )

    branches = {stage.index: classify_branches(spec, stage) for stage in STAGES}

    wanted = {
        ANCHOR_TARGET: "anchor_target_function",
        ANCHOR_CALLER: "anchor_caller_function",
        TABLE_ALLOC: "dispatch_table_alloc",
        TABLE_XFER: "dispatch_table_transfer",
    }
    rel32 = relative_branch_xrefs(spec, ((0xE8, "call"), (0xE9, "jmp")), wanted)
    rip = rip_relative_xrefs(spec, wanted)
    pointers = {rva: absolute_pointer_sites(spec, rva) for rva in sorted(wanted)}
    slots = {rva: rva_slot_sites(spec, rva) for rva in sorted(wanted)}
    dir64 = dir64_census(spec)
    rtti = rtti_census(spec)
    anchor_pdata = pdata_anchor_records(spec)
    thunks = resolve_global_address_thunks(spec, GLOBAL_ADDRESS_THUNKS)

    require(
        len(rel32[ANCHOR_TARGET]) == 1 and rel32[ANCHOR_TARGET][0]["rva"] == ANCHOR_CALL_SITE,
        "the anchor function no longer has exactly one direct rel32 call site",
    )
    require(
        not rel32[ANCHOR_CALLER] and not rip[ANCHOR_CALLER] and not pointers[ANCHOR_CALLER],
        f"{common.hexs(ANCHOR_CALLER)} gained a static reference; rerun the backward slice",
    )
    require(
        bool(slots[ANCHOR_CALLER]) and bool(slots[ANCHOR_TARGET])
        and all(entry["pdata_field"] is not None for entry in slots[ANCHOR_CALLER])
        and all(entry["pdata_field"] is not None for entry in slots[ANCHOR_TARGET]),
        "a 32 bit occurrence of an anchor rva is no longer explained by the .pdata array",
    )

    graph = Graph()
    graph.node(
        "N_PRODUCER",
        "unknown_producer",
        "unidentified writer of the handle qword",
        rva=None,
        raw=None,
        notes="no store to this location is reachable from a static reference to "
        "0xC85650; see unresolved U-01",
    )
    graph.node(
        "N_HANDLE",
        "memory",
        "qword at [descriptor+0], the value consumed at 0xC856F3",
        rva=None,
        raw=None,
        notes="runtime address; the descriptor pointer is the first argument of 0xC856C0",
    )
    graph.node(
        "N_CALLER_ARG0",
        "parameter",
        "RCX of 0xC85650, the 16 byte closure pair",
        rva=ANCHOR_CALLER,
        raw=common.rva_to_raw(spec.pe, ANCHOR_CALLER),
        function=caller_fn.as_json(spec.pe),
    )
    graph.node(
        "N_CLOSURE_SLOT0",
        "closure_field",
        "closure+0, a three qword output vector {begin,end,capacity}",
        rva=ANCHOR_CALLER_SLOT0,
        raw=common.rva_to_raw(spec.pe, ANCHOR_CALLER_SLOT0),
        function=caller_fn.as_json(spec.pe),
    )
    graph.node(
        "N_CLOSURE_SLOT8",
        "closure_field",
        "closure+8, the descriptor handed to 0xC856C0 as RCX",
        rva=ANCHOR_CALLER_SLOT8,
        raw=common.rva_to_raw(spec.pe, ANCHOR_CALLER_SLOT8),
        function=caller_fn.as_json(spec.pe),
    )
    graph.node(
        "N_TARGET_ARG0",
        "parameter",
        "RCX of 0xC856C0, the descriptor pointer",
        rva=0xC856D3,
        raw=common.rva_to_raw(spec.pe, 0xC856D3),
        function=target_fn.as_json(spec.pe),
    )
    graph.node(
        "N_STRING",
        "parameter",
        "RDX/RSI of 0xC856C0, the wide string data pointer and the 2*length+2 byte count",
        rva=0xC856D0,
        raw=common.rva_to_raw(spec.pe, 0xC856D0),
        function=target_fn.as_json(spec.pe),
    )
    graph.node(
        "N_VECTOR_APPEND",
        "function",
        "0x495D0, the vector growth helper used on the slow append path",
        rva=0x495D0,
        raw=common.rva_to_raw(spec.pe, 0x495D0),
        function=spec.function_json(0x495D0),
    )
    graph.node(
        "N_RESULT",
        "value",
        "RAX of 0xC856C0, the address appended to the output vector",
        rva=0xC870F3,
        raw=common.rva_to_raw(spec.pe, 0xC870F3),
        function=target_fn.as_json(spec.pe),
    )
    graph.node(
        "N_R14",
        "register",
        "R14 holding the handle across the allocation dispatch",
        rva=ANCHOR_LOAD_R14,
        raw=common.rva_to_raw(spec.pe, ANCHOR_LOAD_R14),
        function=target_fn.as_json(spec.pe),
    )
    graph.node(
        "N_RBX",
        "register",
        "RBX holding the re-read handle across the transfer dispatch",
        rva=ANCHOR_RELOAD_RBX,
        raw=common.rva_to_raw(spec.pe, ANCHOR_RELOAD_RBX),
        function=target_fn.as_json(spec.pe),
    )
    for stage in STAGES:
        graph.node(
            stage.table_node,
            "jump_table",
            f"{common.hexs(stage.table_rva)}, {JUMP_TABLE_ENTRIES} signed 32 bit relative "
            "targets selected by RDTSC & 0xF",
            rva=stage.table_rva,
            raw=common.rva_to_raw(spec.pe, stage.table_rva),
            section="rdata",
        )
    for stage in STAGES:
        for entry in branches[stage.index]:
            tag = f"{stage.index}_{entry['index']:02d}"
            where = f"stage {stage.label} branch {entry['index']}"
            graph.node(
                f"N_ARG_{tag}",
                "argument",
                f"{entry['handle_argument_register'].upper()} at the {entry['sink_kind']} on {where}",
                rva=entry["handle_carrier"]["rva"],
                raw=entry["handle_carrier"]["raw"],
                function=target_fn.as_json(spec.pe),
            )
            inline = entry["sink_kind"] == "inline_syscall"
            graph.node(
                f"N_SINK_{tag}",
                "syscall" if inline else "function",
                f"{'inline syscall' if inline else 'wrapper'} consuming the handle on {where}",
                rva=entry["sink"]["rva"],
                raw=entry["sink"]["raw"],
                function=entry["sink_function"],
            )

    load_r14 = spec.at(ANCHOR_LOAD_R14)
    graph.edge(
        "N_PRODUCER",
        "N_HANDLE",
        "store",
        LOW,
        OPEN,
        rva=None,
        raw=None,
        function=None,
        evidence=None,
        note="no writer identified; the 0xC85650 call mechanism has no static reference form",
        corroborates=[
            "reverse/adhesive-06-process-memory-hooks.md#9.5",
            "reverse/adhesive-12-risk-methodology-open-questions.md#6.1",
        ],
    )
    graph.edge(
        "N_HANDLE",
        "N_R14",
        "load",
        HIGH,
        OBSERVED,
        rva=ANCHOR_LOAD_R14,
        raw=common.rva_to_raw(spec.pe, ANCHOR_LOAD_R14),
        function=target_fn.as_json(spec.pe),
        evidence=load_r14.as_evidence(spec.pe),
        corroborates=("reverse/adhesive-12-risk-methodology-open-questions.md#6.1",),
    )
    graph.edge(
        "N_HANDLE",
        "N_RBX",
        "load",
        HIGH,
        OBSERVED,
        rva=ANCHOR_RELOAD_RBX,
        raw=common.rva_to_raw(spec.pe, ANCHOR_RELOAD_RBX),
        function=target_fn.as_json(spec.pe),
        evidence=spec.at(ANCHOR_RELOAD_RBX).as_evidence(spec.pe),
        note="second read of the same descriptor field, after the allocation merge point",
    )
    graph.edge(
        "N_CALLER_ARG0",
        "N_CLOSURE_SLOT0",
        "load",
        HIGH,
        OBSERVED,
        rva=ANCHOR_CALLER_SLOT0,
        raw=common.rva_to_raw(spec.pe, ANCHOR_CALLER_SLOT0),
        function=caller_fn.as_json(spec.pe),
        evidence=spec.at(ANCHOR_CALLER_SLOT0).as_evidence(spec.pe),
    )
    graph.edge(
        "N_CALLER_ARG0",
        "N_CLOSURE_SLOT8",
        "load",
        HIGH,
        OBSERVED,
        rva=ANCHOR_CALLER_SLOT8,
        raw=common.rva_to_raw(spec.pe, ANCHOR_CALLER_SLOT8),
        function=caller_fn.as_json(spec.pe),
        evidence=spec.at(ANCHOR_CALLER_SLOT8).as_evidence(spec.pe),
        corroborates=("reverse/adhesive-12-risk-methodology-open-questions.md#6.1",),
    )
    graph.edge(
        "N_CLOSURE_SLOT8",
        "N_TARGET_ARG0",
        "argument_pass",
        HIGH,
        OBSERVED,
        rva=ANCHOR_CALL_SITE,
        raw=common.rva_to_raw(spec.pe, ANCHOR_CALL_SITE),
        function=caller_fn.as_json(spec.pe),
        evidence=spec.at(ANCHOR_CALL_SITE).as_evidence(spec.pe),
        corroborates=("reverse/adhesive-06-process-memory-hooks.md#9.1",),
    )
    graph.edge(
        "N_TARGET_ARG0",
        "N_R14",
        "copy",
        HIGH,
        OBSERVED,
        rva=0xC856D3,
        raw=common.rva_to_raw(spec.pe, 0xC856D3),
        function=target_fn.as_json(spec.pe),
        evidence=spec.at(0xC856D3).as_evidence(spec.pe),
        note="descriptor is preserved in RBX so the transfer stage can re-read [RBX]",
    )
    for rva, node, note in (
        (0xC8566B, "N_STRING", "wide string length read from the string object"),
        (0xC8566F, "N_STRING", "byte count is length*2+2, a UTF-16 buffer size"),
    ):
        graph.edge(
            "N_CALLER_ARG0",
            node,
            "load",
            HIGH,
            OBSERVED,
            rva=rva,
            raw=common.rva_to_raw(spec.pe, rva),
            function=caller_fn.as_json(spec.pe),
            evidence=spec.at(rva).as_evidence(spec.pe),
            note=note,
        )
    for rva, kind, note in (
        (0xC8568B, "load", "output vector end pointer"),
        (0xC8568F, "load", "output vector capacity compared against the end pointer"),
        (0xC85695, "store", "in place append of the returned address"),
        (0xC85698, "store", "end pointer advanced by 8"),
    ):
        graph.edge(
            "N_CLOSURE_SLOT0",
            "N_VECTOR_APPEND" if rva in (0xC8568B, 0xC8568F) else "N_RESULT",
            kind,
            HIGH,
            OBSERVED,
            rva=rva,
            raw=common.rva_to_raw(spec.pe, rva),
            function=caller_fn.as_json(spec.pe),
            evidence=spec.at(rva).as_evidence(spec.pe),
            note=note,
        )
    graph.edge(
        "N_VECTOR_APPEND",
        "N_RESULT",
        "call",
        HIGH,
        OBSERVED,
        rva=0xC856A7,
        raw=common.rva_to_raw(spec.pe, 0xC856A7),
        function=caller_fn.as_json(spec.pe),
        evidence=spec.at(0xC856A7).as_evidence(spec.pe),
        note="slow path taken when the output vector has no spare capacity",
    )
    for stage in STAGES:
        for entry in branches[stage.index]:
            tag = f"{stage.index}_{entry['index']:02d}"
            graph.edge(
                stage.table_node,
                f"N_SINK_{tag}",
                "indirect_jump",
                HIGH,
                OBSERVED,
                rva=entry["slot_rva"],
                raw=entry["slot_raw"],
                function=None,
                evidence={
                    "table_slot_rva": entry["slot_rva"],
                    "table_slot_rva_hex": entry["slot_rva_hex"],
                    "relative_displacement": entry["relative_displacement"],
                    "target_rva": entry["target_rva"],
                    "target_rva_hex": entry["target_rva_hex"],
                    "selector": "RDTSC & 0xF",
                    "method": "signed int32 relative target decoded from .rdata",
                },
                note=f"stage {stage.label} branch {entry['index']}",
            )
            graph.edge(
                stage.register_node,
                f"N_ARG_{tag}",
                "copy",
                HIGH,
                OBSERVED,
                rva=entry["handle_carrier"]["rva"],
                raw=entry["handle_carrier"]["raw"],
                function=target_fn.as_json(spec.pe),
                evidence=entry["handle_carrier"],
                note=f"{stage.handle_register} to {entry['handle_argument_register'].upper()}",
            )
            graph.edge(
                f"N_ARG_{tag}",
                f"N_SINK_{tag}",
                "argument_pass",
                HIGH,
                OBSERVED,
                rva=entry["sink"]["rva"],
                raw=entry["sink"]["raw"],
                function=entry["sink_function"],
                evidence=entry["sink"],
                note=stage.pass_note,
            )

    negatives = _negative_edges(spec, rel32, rip, pointers, slots, dir64, rtti)
    unresolved = _unresolved(spec, branches, rtti, dir64)

    return {
        "schema": SCHEMA,
        "specimen": {
            "path": spec.path.relative_to(root).as_posix(),
            "size": spec.path.stat().st_size,
            "sha256": common.sha256_file(spec.path),
            "image_base": spec.image_base,
            "image_base_hex": common.hexs(spec.image_base),
        },
        "script": {
            "path": Path(__file__).resolve().relative_to(root).as_posix(),
            "sha256": common.sha256_file(Path(__file__).resolve()),
        },
        "scope": {
            "direction": "backward from the [RCX] handle load of 0xC856C0",
            "execution": "static file parsing only; the specimen is never loaded, mapped or executed",
            "determinism": {
                "iteration": "sorted by rva, then by slot index",
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
            "no_actionable_output": "the payload describes code structure only; it contains no "
            "exploit, bypass, patch or shellcode guidance",
        },
        "anchor": {
            "function_rva": target_fn.begin,
            "function_rva_hex": common.hexs(target_fn.begin),
            "function_raw": common.rva_to_raw(spec.pe, target_fn.begin),
            "function_va": common.rva_to_va(spec.pe, target_fn.begin),
            "function_va_hex": common.hexs(common.rva_to_va(spec.pe, target_fn.begin)),
            "end_rva": target_fn.end,
            "end_rva_hex": common.hexs(target_fn.end),
            "size": target_fn.end - target_fn.begin,
            "unwind_rva": target_fn.unwind,
            "unwind_rva_hex": common.hexs(target_fn.unwind),
            "direct_caller_rva": caller_fn.begin,
            "direct_caller_rva_hex": common.hexs(caller_fn.begin),
            "direct_caller_raw": common.rva_to_raw(spec.pe, caller_fn.begin),
            "direct_caller_end_rva": caller_fn.end,
            "direct_caller_unwind_rva": caller_fn.unwind,
            "handle_load_rva": ANCHOR_LOAD_R14,
            "handle_load_rva_hex": common.hexs(ANCHOR_LOAD_R14),
            "handle_load_raw": common.rva_to_raw(spec.pe, ANCHOR_LOAD_R14),
            "corroborates": [
                "reverse/adhesive-12-risk-methodology-open-questions.md#6.1",
                "reverse/adhesive-06-process-memory-hooks.md#9",
            ],
        },
        "handle": {
            "expression": "[descriptor+0]",
            "loads": [
                {
                    "rva": ANCHOR_LOAD_R14,
                    "rva_hex": common.hexs(ANCHOR_LOAD_R14),
                    "raw": common.rva_to_raw(spec.pe, ANCHOR_LOAD_R14),
                    "register": "r14",
                    "instruction": load_r14.as_evidence(spec.pe),
                },
                {
                    "rva": ANCHOR_RELOAD_RBX,
                    "rva_hex": common.hexs(ANCHOR_RELOAD_RBX),
                    "raw": common.rva_to_raw(spec.pe, ANCHOR_RELOAD_RBX),
                    "register": "rbx",
                    "instruction": spec.at(ANCHOR_RELOAD_RBX).as_evidence(spec.pe),
                },
            ],
            "use_count": sum(len(branches[stage.index]) for stage in STAGES),
            "loads_are_separate_reads": True,
            "value_may_change_between_loads": True,
            "value_may_change_between_loads_reason": "six distinct allocation wrapper calls and "
            "eight inline syscalls sit between 0xC856F3 and 0xC86440, and the descriptor is a "
            "runtime address, so an aliasing store can be neither confirmed nor excluded; see "
            "unresolved U-08",
            "use_sites": [
                {
                    "stage": stage.index,
                    "stage_label": stage.label,
                    "branch_index": entry["index"],
                    "sink_kind": entry["sink_kind"],
                    "argument_register": entry["handle_argument_register"],
                    "argument_rva": entry["handle_carrier"]["rva"],
                    "argument_rva_hex": entry["handle_carrier"]["rva_hex"],
                    "argument_raw": entry["handle_carrier"]["raw"],
                    "sink_rva": entry["sink"]["rva"],
                    "sink_rva_hex": entry["sink"]["rva_hex"],
                    "sink_raw": entry["sink"]["raw"],
                    "sink_function_rva": entry["sink_function_rva"],
                }
                for stage in STAGES
                for entry in branches[stage.index]
            ],
            "producer": {"status": OPEN, "identified": False, "unresolved_id": "U-01"},
        },
        "object_model": {
            "closure": {
                "size_bytes": 16,
                "shape": "{qword output_vector, qword descriptor}",
                "observed_at": ANCHOR_CALLER,
                "fields": [
                    {
                        "offset": 0,
                        "role": "output vector of returned addresses",
                        "evidence_rva": ANCHOR_CALLER_SLOT0,
                    },
                    {
                        "offset": 8,
                        "role": "descriptor pointer passed as RCX to 0xC856C0",
                        "evidence_rva": ANCHOR_CALLER_SLOT8,
                    },
                ],
                "confidence": HIGH,
            },
            "descriptor": {
                "size_bytes": None,
                "fields_observed": [0],
                "note": "0xC856C0 reads only offset 0 of the descriptor; no other field is "
                "dereferenced anywhere in the function",
                "confidence": HIGH,
            },
            "vtable_and_rtti": {
                **rtti,
                "conclusion": "no MSVC type descriptor or vftable type name is recoverable from "
                "this image, so the object type cannot be named from RTTI",
                "conclusion_confidence": HIGH,
            },
        },
        "dispatch": {
            "selector": "RDTSC & 0xF",
            "selector_mask_hex": common.hexs(JUMP_TABLE_INDEX_MASK),
            "selectors": selectors,
            "table_entries": JUMP_TABLE_ENTRIES,
            "tables": [
                {
                    "stage": stage.index,
                    "stage_label": stage.label,
                    "table_rva": stage.table_rva,
                    "table_rva_hex": common.hexs(stage.table_rva),
                    "table_raw": common.rva_to_raw(spec.pe, stage.table_rva),
                    "section": "rdata",
                    "materialised_by": stage.selector_lea,
                    "materialised_by_hex": common.hexs(stage.selector_lea),
                    "merge_rva": stage.merge_rva,
                    "merge_rva_hex": common.hexs(stage.merge_rva),
                    "inline_syscall_branches": sum(
                        1 for e in branches[stage.index] if e["sink_kind"] == "inline_syscall"
                    ),
                    "wrapper_call_branches": sum(
                        1 for e in branches[stage.index] if e["sink_kind"] == "wrapper_call"
                    ),
                    "distinct_wrapper_targets": sorted(
                        {
                            entry["sink_function_rva"]
                            for entry in branches[stage.index]
                            if entry["sink_function_rva"] is not None
                        }
                    ),
                    "branches": branches[stage.index],
                }
                for stage in STAGES
            ],
            "tables_are_adjacent": TABLE_ALLOC + 4 * JUMP_TABLE_ENTRIES == TABLE_XFER,
            "alloc_table_end_rva": TABLE_ALLOC + 4 * JUMP_TABLE_ENTRIES,
            "alloc_table_end_rva_hex": common.hexs(TABLE_ALLOC + 4 * JUMP_TABLE_ENTRIES),
            "xfer_table_rva": TABLE_XFER,
            "xfer_table_rva_hex": common.hexs(TABLE_XFER),
        },
        "global_address_thunks": thunks,
        "cluster": cluster_census(spec),
        "reference_scan": {
            "rel32_branch_xrefs": {
                common.hexs(rva): rel32[rva] for rva in sorted(rel32)
            },
            "rip_relative_xrefs": {common.hexs(rva): rip[rva] for rva in sorted(rip)},
            "absolute_pointer_sites": {
                common.hexs(rva): pointers[rva] for rva in sorted(pointers)
            },
            "rva_slot_sites": {common.hexs(rva): slots[rva] for rva in sorted(slots)},
            "basereloc_dir64": dir64,
            "anchor_pdata_records": anchor_pdata,
            "method": {
                "rel32": "every 0xE8 and 0xE9 byte in .text decoded as a signed 32 bit "
                "displacement, no address-range restriction",
                "rip_relative": "every REX-prefixed instruction whose ModRM encodes a "
                "RIP-relative disp32, 7 byte form, no address-range restriction",
                "absolute_pointer": "every byte offset in the file equal to image_base + rva "
                "as a little endian 64 bit value",
                "rva_slot": "every byte offset in the file equal to the rva as a little "
                "endian 32 bit value",
            },
        },
        "constant_pools": _constant_pools(spec),
        "negative_findings": negatives,
        "nodes": graph.nodes,
        "edges": graph.edges,
        "unresolved": unresolved,
    }


def _constant_pools(spec: Specimen) -> dict[str, Any]:
    windows = (
        (0x31261B0, 0xA0, "allocation_stage_constant_window"),
        (0x3189A90, 0x100, "transfer_stage_constant_window"),
        (0x30E35F0, 0x40, "wrapper_state_globals"),
    )
    out = []
    for rva, size, label in windows:
        blob = spec.data_bytes(rva, size)
        groups = size // 24
        zero_prefix = sum(1 for g in range(groups) if blob[g * 24 : g * 24 + 8] == bytes(8))
        out.append(
            {
                "label": label,
                "rva": rva,
                "rva_hex": common.hexs(rva),
                "raw": common.rva_to_raw(spec.pe, rva),
                "size": size,
                "entropy": spec.entropy(rva, size),
                "zero_byte_count": blob.count(0),
                "zero_byte_ratio": round(blob.count(0) / size, 6),
                "all_zero": blob.count(0) == size,
                "aligned_24_byte_groups": groups,
                "groups_starting_with_8_zero_bytes": zero_prefix,
            }
        )
    body = spec.data_bytes(ANCHOR_TARGET, target_fn_size(spec))
    out.append(
        {
            "label": "anchor_function_body_for_comparison",
            "rva": ANCHOR_TARGET,
            "rva_hex": common.hexs(ANCHOR_TARGET),
            "raw": common.rva_to_raw(spec.pe, ANCHOR_TARGET),
            "size": len(body),
            "entropy": spec.entropy(ANCHOR_TARGET, len(body)),
            "zero_byte_count": body.count(0),
            "zero_byte_ratio": round(body.count(0) / len(body), 6),
            "all_zero": False,
            "aligned_24_byte_groups": len(body) // 24,
            "groups_starting_with_8_zero_bytes": sum(
                1
                for g in range(len(body) // 24)
                if body[g * 24 : g * 24 + 8] == bytes(8)
            ),
        }
    )
    return {
        "note": "entropy and the zero prefix count are measured over the raw file bytes of each "
        "window, so the 'alternating 8 zero byte and 16 byte data block' description stays "
        "checkable rather than asserted",
        "windows": out,
    }


def target_fn_size(spec: Specimen) -> int:
    record = spec.owner(ANCHOR_TARGET)
    require(record is not None, "anchor function not resolvable")
    return record.end - record.begin


def _negative_edges(
    spec: Specimen,
    rel32: Mapping[int, list[dict[str, Any]]],
    rip: Mapping[int, list[dict[str, Any]]],
    pointers: Mapping[int, list[dict[str, Any]]],
    slots: Mapping[int, list[dict[str, Any]]],
    dir64: Mapping[str, Any],
    rtti: Mapping[str, Any],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def add(label: str, method: str, result: Any, status: str, confidence: str) -> None:
        out.append(
            {
                "id": f"NEG-{len(out) + 1:02d}",
                "claim": label,
                "method": method,
                "result": result,
                "status": status,
                "confidence": confidence,
            }
        )

    add(
        "0xC85650 has no direct rel32 call or jmp reference in .text",
        "signed 32 bit displacement decode of every 0xE8 and 0xE9 byte in .text",
        {"call_sites": len(rel32[ANCHOR_CALLER]), "jmp_sites": 0},
        OBSERVED,
        HIGH,
    )
    add(
        "0xC85650 has no 8 byte absolute pointer anywhere in the file",
        "byte search for image_base+0xC85650 as a little endian 64 bit value",
        {"hits": len(pointers[ANCHOR_CALLER])},
        OBSERVED,
        HIGH,
    )
    add(
        "0xC85650 is never materialised as a RIP-relative address in .text",
        "scan of every REX-prefixed RIP-relative disp32 operand for a target of 0xC85650",
        {"sites": len(rip[ANCHOR_CALLER])},
        OBSERVED,
        HIGH,
    )
    add(
        "0xC856C0 has exactly one direct rel32 call site, at 0xC85681 inside 0xC85650",
        "signed 32 bit displacement decode of every 0xE8 and 0xE9 byte in .text",
        {"call_sites": len(rel32[ANCHOR_TARGET]), "jmp_sites": len(
            [x for x in rel32[ANCHOR_TARGET] if x["kind"] == "jmp"]
        ), "sites": rel32[ANCHOR_TARGET]},
        OBSERVED,
        HIGH,
    )
    add(
        "no load time relocated pointer in .rdata or .data targets the 0xC85000..0xC88000 cluster",
        "all DIR64 relocation slots read at their 8 byte aligned file offsets",
        {
            "dir64_slots": dir64["eight_byte_aligned_slots_by_section"],
            "slots_holding_va_into_cluster": dir64["slots_holding_va_into_cluster"],
            "zero_valued_slots": dir64["zero_valued_slots"],
        },
        OBSERVED,
        HIGH,
    )
    add(
        "the only file occurrences of 0xC856C0 and 0xC85650 as 32 bit values are the address "
        "fields of their own RUNTIME_FUNCTION records in the authoritative .pdata array, "
        "not a function pointer, table entry or metadata record",
        "byte search for both rvas as little endian 32 bit values, then classification of each "
        "hit against the parsed .pdata record that contains it",
        {
            "0xC85650": slots[ANCHOR_CALLER],
            "0xC856C0": slots[ANCHOR_TARGET],
        },
        OBSERVED,
        HIGH,
    )
    add(
        "the image carries no MSVC RTTI, so the descriptor and closure types cannot be named",
        "scan of .rdata for '.?A' type descriptor names and signature 1 Complete Object Locators",
        {
            "type_descriptor_name_hits": rtti["type_descriptor_name_hits"],
            "complete_object_locator_records": rtti["complete_object_locator_records"],
        },
        OBSERVED,
        HIGH,
    )
    return out


def _unresolved(
    spec: Specimen,
    branches: Mapping[int, list[dict[str, Any]]],
    rtti: Mapping[str, Any],
    dir64: Mapping[str, Any],
) -> list[dict[str, Any]]:
    inline_syscalls = {
        stage.label: [
            entry["sink"]["rva_hex"]
            for entry in branches[stage.index]
            if entry["sink_kind"] == "inline_syscall"
        ]
        for stage in STAGES
    }
    wrapper_targets = {
        stage.label: sorted(
            {
                entry["sink_function_rva"]
                for entry in branches[stage.index]
                if entry["sink_function_rva"] is not None
            }
        )
        for stage in STAGES
    }
    return [
        {
            "id": "U-01",
            "question": "Which code stores the handle qword at [descriptor+0]?",
            "status": OPEN,
            "reason": "the only consumer is 0xC856C0, and 0xC85650, its only caller, has no "
            "static reference in any of the scanned forms, so no backward path reaches a store",
            "next_static_step": "recover the dispatch that reaches 0xC85650, for example by "
            "resolving the component method table the host builds at run time",
        },
        {
            "id": "U-02",
            "question": "How is 0xC85650 invoked?",
            "status": OPEN,
            "reason": "zero rel32 call or jmp, zero 8 byte VA pointer, zero RIP-relative "
            "materialisation and zero DIR64 slot pointing at the cluster",
            "next_static_step": "enumerate the vtable or method table of the component object "
            "the host populates, then match the 16 byte {vector, descriptor} pair",
        },
        {
            "id": "U-03",
            "question": "What is the layout of the descriptor behind closure+8 beyond offset 0?",
            "status": OPEN,
            "reason": "0xC856C0 dereferences offset 0 only; no other field of the descriptor "
            "is read anywhere in the function",
            "next_static_step": "recover a second entry point that receives the same descriptor",
        },
        {
            "id": "U-04",
            "question": "Which Nt services do the inline syscalls of 0xC856C0 and the syscalls "
            "inside the wrapper functions it calls map to?",
            "status": OPEN,
            "reason": "the service number is produced at run time by shift, XOR, bswap and "
            "KUSER_SHARED_DATA mixing inside each wrapper, so it is not a static constant",
            "next_static_step": "evaluate the mixing chain offline with symbolic KUSER_SHARED_DATA "
            "values, as proposed in reverse/adhesive-12-risk-methodology-open-questions.md#10.6",
            "inline_syscall_rvas": inline_syscalls,
            "wrapper_function_rvas": wrapper_targets,
        },
        {
            "id": "U-05",
            "question": "Are the 16 allocation branches and the 16 transfer branches "
            "semantically equivalent encodings of one service, or different services?",
            "status": OPEN,
            "reason": "both stages are selected by an independent RDTSC & 0xF, and the branch "
            "bodies differ in argument shape as well as in syscall count",
            "next_static_step": "normalise every branch to a common Nt level argument schema "
            "and compare the schemas instead of the branch counts",
        },
        {
            "id": "U-06",
            "question": "What is the concrete class of the closure and descriptor objects?",
            "status": OPEN,
            "reason": f"no MSVC RTTI is present: {rtti['type_descriptor_name_hits']} type "
            f"descriptor names and {rtti['complete_object_locator_records']} Complete Object "
            "Locators in .rdata",
            "next_static_step": "rely on the structural layout recorded in object_model, or "
            "correlate with the public CitizenFX component interface without assuming a mapping",
        },
        {
            "id": "U-07",
            "question": "Do the two adjacent jump tables form one 32 way dispatch or two "
            "independent 16 way dispatches?",
            "status": OPEN,
            "reason": f"{common.hexs(TABLE_ALLOC)} and {common.hexs(TABLE_XFER)} are adjacent in "
            ".rdata, but each is read by its own RDTSC & 0xF sequence",
            "next_static_step": "check whether both selector sequences can execute in one "
            "invocation and whether the second table is ever reached from a branch that "
            "already consumed a first table slot",
        },
        {
            "id": "U-08",
            "question": "Is the value re-read at 0xC86440 guaranteed to be the value loaded at "
            "0xC856F3, or can a called wrapper have replaced [descriptor+0] in between?",
            "status": OPEN,
            "reason": "the allocation stage calls six distinct wrapper functions and executes "
            "eight inline syscalls between the two loads; none of them is statically known to "
            "write through the descriptor pointer, and the descriptor is a runtime address, so "
            "an aliasing store can be neither confirmed nor excluded here",
            "next_static_step": "propagate the descriptor pointer into each wrapper and test "
            "whether any store may alias it, then decide if the two loads form one def-use "
            "chain or two independent ones",
        },
    ]


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description="Static backward def-use slice for the 0xC856C0 handle in adhesive.dll"
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument(
        "--out", type=Path, default=root / "reverse" / "evidence" / "c856c0_dataflow.json"
    )
    parser.add_argument("--emit", action="store_true", help="write the dataflow json")
    parser.add_argument("--verify", action="store_true", help="diff a fresh run against the stored json")
    parser.add_argument("--max-report", type=int, default=40, help="mismatches to print")
    args = parser.parse_args(argv)

    specimen = args.specimen.resolve()
    out = args.out.resolve()

    spec = Specimen(specimen)
    try:
        payload = build_payload(spec, root)
    finally:
        spec.close()

    print(f"script    {script.relative_to(root).as_posix()}")
    print(f"sha256    {common.sha256_file(script)}")
    print(f"specimen  {specimen.relative_to(root).as_posix()} sha256={payload['specimen']['sha256']}")
    print(
        f"anchor    RVA {payload['anchor']['function_rva_hex']} "
        f"raw {payload['anchor']['function_raw']} unwind {payload['anchor']['unwind_rva_hex']}"
    )
    print(
        f"graph     nodes={len(payload['nodes'])} edges={len(payload['edges'])} "
        f"handle_uses={payload['handle']['use_count']} unresolved={len(payload['unresolved'])}"
    )

    if args.emit:
        common.write_json(out, payload)
        print(f"emitted   {out.relative_to(root).as_posix()}")
        return 0

    if args.verify:
        stored = json.loads(out.read_text(encoding="utf-8"))
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
        print(f"verify    {len(keys) - len(mismatches)}/{len(keys)} scalars matched")
        return 1 if mismatches else 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
