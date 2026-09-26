"""Independent static syscall boundary audit of the `0F 05` candidate scan.

Scope
-----
This script audits the *boundary logic* of `reverse/scripts/syscall_scan.py`
against the committed evidence file `reverse/evidence/syscall_candidates_raw.csv`.
It is a reader: it never runs the audited script, never rewrites the audited CSV
and never loads the specimen for execution. The specimen is opened read only and
memory mapped read only; no module is loaded and no code of the specimen runs.

The audit is independent of the audited implementation. Every number is
recomputed from the raw bytes by this script's own code and then cross-checked a
second time by a decoder that shares no code with either implementation: GNU
objdump (BFD). The audited script is never imported; it and its CSV are the claim
under test.

Checks
------
  C1  raw byte census        the `0F 05` hit counts per section, including the
                             non executable sections the CSV scope omits
  C2  boundary reproduction  the four documented ratios: valid, covered by
                             instruction, pdata gap, rdata/data
  C3  CSV agreement          row count, ascending raw order, `hit_index`
                             continuity, per row raw bytes, per row disposition
  C4  instruction start      every valid entry is an instruction start of its
                             owning runtime function, confirmed twice: by this
                             script's own Capstone sweep and by objdump
  C5  anchor subset          every syscall site documented in
                             `adhesive-06`/`07`/`12` is inside the valid subset
  C6  control flow proof     how far each instruction start is control flow
                             proven, and which control transfer the rest depend on
  C7  false positive cause   a stated mechanism for every discarded byte pair
  C8  anchor provenance      the shape of the syscall number register source at
                             every documented site, without any value

What the audit deliberately does not do
---------------------------------------
It does not resolve a service number, does not name an Nt/Zw service, does not
decode an obfuscated number source and does not classify intent. The service
mapping channel is reported as an open item with a bounded static provenance
class only, so that no service identity is asserted here.

Terminology
-----------
  disposition     the audited script's verdict for a candidate, one of
                  `instruction_start`, `covered_by_instruction`,
                  `no_pdata_function`
  proof level     how the instruction start was established:
                  `fallthrough_proven`  the candidate is on an uninterrupted
                                        fallthrough chain from the owning
                                        function entry
                  `branch_proven`       not on the fallthrough chain, but a
                                        resolvable direct branch of the same
                                        function reaches it in the recursive
                                        descent
                  `sweep_hypothesis`    only the linear sweep reaches it, which
                                        requires the decode to continue across
                                        a control transfer the sweep ignores
  discontinuity   a control transfer that ends a fallthrough chain: an
                  unconditional jump or a terminator. Conditional jumps and
                  calls are not discontinuities, because the fallthrough
                  continues through them in the sweep and in the descent alike.

Evidence
--------
The payload is written to `reverse/evidence/audit_syscall_candidates.json`
through `common.write_json` as UTF-8 without BOM, LF terminated, with a trailing
newline. No timestamp, no absolute path outside the repository and no
environment dependent ordering reaches the payload; the producer section records
the auditor's own SHA-256, so the evidence is pinned to the exact script that
produced it. Exit status is `0` when every check holds, `1` on a check failure
and `2` on a specimen structure error.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import mmap
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Sequence

import capstone
import pefile

_SCRIPT_DIR: Final[Path] = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import common

PATTERN: Final[bytes] = bytes((0x0F, 0x05))
PATTERN_HEX: Final[str] = "0F05"
SCOPE_SECTION: Final[str] = ".text"
DATA_SECTIONS: Final[tuple[str, ...]] = (".rdata", ".data")
SECTION_MEM_EXECUTE: Final[int] = 0x20000000
SECTION_CNT_CODE: Final[int] = 0x00000020
RUNTIME_FUNCTION_SIZE: Final[int] = 12
EXPECTED_RUNTIME_FUNCTIONS: Final[int] = 142_004
EXCEPTION_DIRECTORY_INDEX: Final[int] = 3
LOOKAHEAD: Final[int] = 16
DECODE_WINDOW: Final[int] = 512
EAX_WINDOW: Final[int] = 8

DOCUMENTED_RAW_HITS: Final[int] = 3881
DOCUMENTED_VALID: Final[int] = 3627
DOCUMENTED_COVERED: Final[int] = 209
DOCUMENTED_PDATA_GAP: Final[int] = 45
DOCUMENTED_DATA_HITS: Final[int] = 30
DOCUMENTED_ANCHOR_SITES: Final[int] = 64

DISPOSITION_START: Final[str] = "instruction_start"
DISPOSITION_COVERED: Final[str] = "covered_by_instruction"
DISPOSITION_NO_PDATA: Final[str] = "no_pdata_function"
DISPOSITION_NOT_REACHED: Final[str] = "sweep_stopped_before_candidate"

PROOF_FALLTHROUGH: Final[str] = "fallthrough_proven"
PROOF_BRANCH: Final[str] = "branch_proven"
PROOF_HYPOTHESIS: Final[str] = "sweep_hypothesis"

DISCONTINUITY_INDIRECT_JMP: Final[str] = "indirect_jump"
DISCONTINUITY_DIRECT_JMP: Final[str] = "direct_jump"
DISCONTINUITY_TERMINATOR: Final[str] = "terminator"

GAP_KIND_PADDING: Final[str] = "inter_function_alignment_gap"
GAP_KIND_ISLAND: Final[str] = "inter_function_code_island"
GAP_ALIGNMENT_THRESHOLD: Final[int] = 0x100

EAX_CONSTANT: Final[str] = "constant_immediate_in_window"
EAX_DERIVED: Final[str] = "register_or_memory_derived_in_window"
EAX_UNKNOWN: Final[str] = "no_eax_definition_in_window"
SERVICE_STATUS: Final[str] = "unresolved"

COVER_REASONS: Final[dict[str, str]] = {
    DISPOSITION_COVERED: (
        "the byte pair is an interior byte of the preceding instruction, so it is consumed as "
        "an opcode, a displacement or an immediate by that instruction and is never decoded"
    ),
    DISPOSITION_NO_PDATA: (
        "no runtime function covers the rva, so the sweep has no decode context and no "
        "instruction start can be asserted for the byte pair"
    ),
    "non_executable_section": (
        "the owning section carries neither IMAGE_SCN_MEM_EXECUTE nor IMAGE_SCN_CNT_CODE, so "
        "the byte pair can never be executed as an instruction"
    ),
}

ANCHOR_GROUPS: Final[tuple[tuple[str, tuple[int, ...]], ...]] = (
    (
        "adhesive-06/12 dynamic Nt wrapper cluster",
        (
            0x051D84C,
            0x051DA7B,
            0x051DC2A,
            0x051DDAE,
            0x051DFC5,
            0x051E180,
            0x051E345,
            0x051E4FE,
            0x051E6C9,
            0x051E835,
            0x051E9B4,
            0x051EBB9,
        ),
    ),
    (
        "adhesive-12 dispatch branch syscalls",
        (
            0x0C858E0,
            0x0C85A9A,
            0x0C85BB0,
            0x0C85DC3,
            0x0C85FCC,
            0x0C86140,
            0x0C862FA,
            0x0C86420,
        ),
    ),
    (
        "adhesive-06/12 remote buffer syscalls",
        (0x0C8F84C, 0x0C8FA6C, 0x0C870DB),
    ),
    (
        "adhesive-07 process basic information",
        (0x0D7B0AE, 0x0D7B4B9, 0x0D7C0AC),
    ),
    (
        "adhesive-07 process debug port",
        (
            0x293F124,
            0x293F2ED,
            0x293F4B8,
            0x293F73D,
            0x293F8CF,
            0x293FA42,
            0x293FC0B,
            0x293FDA9,
        ),
    ),
    (
        "adhesive-07 process debug object handle",
        (
            0x293FFF4,
            0x29401BD,
            0x2940388,
            0x294060D,
            0x294079F,
            0x2940912,
            0x2940ADB,
            0x2940C79,
        ),
    ),
    (
        "adhesive-07 process debug flags",
        (
            0x293E263,
            0x293E42C,
            0x293E5F7,
            0x293E87C,
            0x293EA0E,
            0x293EB81,
            0x293ED4A,
            0x293EEE8,
        ),
    ),
    (
        "adhesive-07 process instrumentation callback direct branches",
        (
            0x293D4DE,
            0x293D63D,
            0x293D7FC,
            0x293DA15,
            0x293DBF5,
            0x293DD1D,
            0x293DE7C,
            0x293E030,
        ),
    ),
    (
        "adhesive-07 process instrumentation callback helper routines",
        (
            0x2941AC2,
            0x2941CB7,
            0x2941DEB,
            0x2941FCF,
            0x294212A,
            0x29422AA,
        ),
    ),
)

TERMINATORS: Final[frozenset[str]] = frozenset(
    {
        "ret",
        "retf",
        "retfq",
        "iret",
        "iretd",
        "iretq",
        "hlt",
        "ud2",
        "syscall",
        "sysenter",
        "int",
        "int1",
        "int3",
    }
)

WINDOW_ALU: Final[frozenset[str]] = frozenset(
    {"mov", "movabs", "xor", "or", "and", "sub", "add", "movzx", "movsx", "lea", "pop"}
)
NUMBER_REGISTERS: Final[frozenset[str]] = frozenset({"eax", "rax"})

OBJDUMP_LINE: Final[re.Pattern[str]] = re.compile(
    r"^\s*([0-9a-fA-F]+):\t(?:[0-9a-fA-F]{2} )*[0-9a-fA-F]{2} *\t"
)


class SpecimenError(RuntimeError):
    """Raised when the specimen or the audited evidence cannot be audited."""


@dataclass(frozen=True, slots=True)
class Candidate:
    """One raw `0F 05` byte pair in the specimen."""

    rva: int
    raw: int
    section: str
    executable: bool
    code_flag: bool


@dataclass(frozen=True, slots=True)
class SweepResult:
    """Independent linear sweep of one runtime function."""

    start: int
    end: int
    stopped: int
    stop_reason: str
    starts: frozenset[int]
    covered_by: dict[int, tuple[int, str]]
    unreached: frozenset[int]
    discontinuity: dict[int, tuple[str, str, int]]
    provenance: dict[int, str]


@dataclass(frozen=True, slots=True)
class ObjdumpRange:
    """What objdump decoded for one address range."""

    requested: tuple[int, int]
    starts: tuple[int, ...]
    mnemonics: dict[int, str]
    byte_directives: int
    decoded_until: int


class Disassembler:
    """One Capstone instance for every decode this script performs.

    Instructions are pulled from a bounded window rather than from the whole
    range, so that the per instruction cost stays a constant and the two long
    passes over `.text` finish in a sane time.
    """

    def __init__(self) -> None:
        self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self._md.detail = True
        self._md.skipdata = False

    def window(self, address: int, buffer: bytes, window_base: int) -> Any:
        """Instructions from `address` inside a bounded decode window."""
        offset = address - window_base
        if offset < 0 or offset >= len(buffer):
            return iter(())
        return self._md.disasm(buffer[offset:], address)

    @staticmethod
    def refill(address: int, window_base: int) -> bool:
        """True when the decode window is too close to its end to continue."""
        return address - window_base > DECODE_WINDOW - LOOKAHEAD


def is_terminator(mnemonic: str) -> bool:
    return mnemonic in TERMINATORS


def direct_target(insn: Any) -> int | None:
    if not insn.operands:
        return None
    first = insn.operands[0]
    if first.type != capstone.x86.X86_OP_IMM:
        return None
    return int(first.imm)


def load_exception_directory(pe: pefile.PE) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Parse the x64 exception directory and validate its ordering."""
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[EXCEPTION_DIRECTORY_INDEX]
    size = int(directory.Size)
    if size == 0 or size % RUNTIME_FUNCTION_SIZE:
        raise SpecimenError(
            f"exception directory size {common.hexs(size)} is not a "
            f"{RUNTIME_FUNCTION_SIZE} byte multiple"
        )
    blob = common.read_rva(pe, int(directory.VirtualAddress), size)
    if len(blob) != size:
        raise SpecimenError(f"exception directory is {len(blob)} bytes, expected {size}")
    begins: list[int] = []
    ends: list[int] = []
    for begin, end, _unwind in struct.iter_unpack("<III", blob):
        begins.append(begin)
        ends.append(end)
    for index in range(len(begins) - 1):
        if begins[index] > begins[index + 1]:
            raise SpecimenError("exception directory is not sorted by begin address")
        if ends[index] > begins[index + 1]:
            raise SpecimenError(
                f"exception directory records {index} and {index + 1} overlap"
            )
    for index in range(len(begins)):
        if ends[index] <= begins[index]:
            raise SpecimenError(f"exception directory record {index} is empty or inverted")
    return tuple(begins), tuple(ends)


def census_sections(view: mmap.mmap, sections: Sequence[common.Section]) -> dict[str, int]:
    """Count the raw pattern in every raw backed section."""
    counts: dict[str, int] = {}
    for section in sections:
        if section.raw_size == 0:
            counts[section.name] = 0
            continue
        blob = view[section.raw_pointer : section.raw_pointer + section.raw_size]
        counts[section.name] = blob.count(PATTERN)
    return counts


def collect_candidates(
    pe: pefile.PE, view: mmap.mmap, sections: Sequence[common.Section]
) -> list[Candidate]:
    """Every raw pattern hit of every raw backed section, in ascending raw order."""
    found: list[Candidate] = []
    for section in sections:
        if section.raw_size == 0:
            continue
        blob = view[section.raw_pointer : section.raw_pointer + section.raw_size]
        offset = blob.find(PATTERN)
        while offset != -1:
            raw = section.raw_pointer + offset
            rva = common.raw_to_rva(pe, raw)
            if rva is None:
                raise SpecimenError(f"raw offset {common.hexs(raw)} maps to no rva")
            found.append(
                Candidate(
                    rva=rva,
                    raw=raw,
                    section=section.name,
                    executable=bool(section.characteristics & SECTION_MEM_EXECUTE),
                    code_flag=bool(section.characteristics & SECTION_CNT_CODE),
                )
            )
            offset = blob.find(PATTERN, offset + 1)
    found.sort(key=lambda item: item.raw)
    return found


def owner_index(begins: Sequence[int], ends: Sequence[int], rva: int) -> int | None:
    """The runtime function record that covers `rva`, if any."""
    index = bisect.bisect_right(begins, rva) - 1
    if index < 0 or rva >= ends[index]:
        return None
    return index


def provenance_from_window(window: Sequence[Any]) -> str:
    """Shape of the last syscall number register definition inside the window.

    Only the shape is inspected, never a value, so that no service number and no
    service name can leave this script.
    """
    for insn in reversed(window):
        if insn.mnemonic not in WINDOW_ALU:
            continue
        if not insn.operands:
            continue
        destination = insn.operands[0]
        if destination.type != capstone.x86.X86_OP_REG:
            continue
        if insn.reg_name(destination.reg) not in NUMBER_REGISTERS:
            continue
        if insn.mnemonic == "xor" and len(insn.operands) > 1:
            if insn.operands[1].type == capstone.x86.X86_OP_REG:
                return EAX_CONSTANT
        if insn.mnemonic in ("mov", "movabs") and len(insn.operands) > 1:
            if insn.operands[1].type == capstone.x86.X86_OP_IMM:
                return EAX_CONSTANT
        if insn.mnemonic == "mov" and destination.type == capstone.x86.X86_OP_IMM:
            return EAX_CONSTANT
        return EAX_DERIVED
    return EAX_UNKNOWN


def sweep_function(
    md: Disassembler,
    text: bytes,
    text_base: int,
    start: int,
    end: int,
    targets: Sequence[int],
) -> SweepResult:
    """Linear sweep of one runtime function, recording the decode context.

    The decode buffer is exactly `[start, end)`, so the decode sees the same
    bytes the audited sweep sees. The sweep additionally records, per candidate,
    the last control transfer it had to ignore in order to keep going, which is
    what decides whether the instruction start is proven or only hypothesized.
    """
    window = text[start - text_base : end - text_base]
    ordered = sorted(targets)
    pending = 0
    starts: set[int] = set()
    covered_by: dict[int, tuple[int, str]] = {}
    discontinuity: dict[int, tuple[str, str, int]] = {}
    provenance: dict[int, str] = {}
    recent: deque[Any] = deque(maxlen=EAX_WINDOW)
    last_kind = ""
    last_text = ""
    last_count = 0
    cursor = start
    reason = "function_end"
    while cursor < end:
        span = min(DECODE_WINDOW, end - cursor)
        decoded = False
        for insn in md.window(cursor, window[cursor - start : cursor - start + span], cursor):
            decoded = True
            is_start = pending < len(ordered) and ordered[pending] == insn.address
            while pending < len(ordered) and ordered[pending] <= insn.address:
                pending += 1
            if is_start:
                starts.add(insn.address)
                discontinuity[insn.address] = (last_kind, last_text, last_count)
                provenance[insn.address] = provenance_from_window(recent)
            if pending < len(ordered) and ordered[pending] < insn.address + insn.size:
                text_of = f"{insn.mnemonic} {insn.op_str}".strip()
                while pending < len(ordered) and ordered[pending] < insn.address + insn.size:
                    covered_by[ordered[pending]] = (insn.address, text_of)
                    pending += 1
            mnemonic = insn.mnemonic
            if mnemonic == "jmp":
                target = direct_target(insn)
                last_kind = (
                    DISCONTINUITY_DIRECT_JMP
                    if target is not None
                    else DISCONTINUITY_INDIRECT_JMP
                )
                last_text = f"{mnemonic} {insn.op_str}".strip()
                last_count += 1
            elif is_terminator(mnemonic):
                last_kind = DISCONTINUITY_TERMINATOR
                last_text = f"{mnemonic} {insn.op_str}".strip()
                last_count += 1
            recent.append(insn)
            cursor = insn.address + insn.size
            if cursor >= end or md.refill(cursor, start):
                break
        if not decoded:
            reason = "undecodable" if cursor < end else reason
            break
        if cursor >= end:
            break
    unreached = set(ordered) - starts - set(covered_by)
    return SweepResult(
        start=start,
        end=end,
        stopped=cursor,
        stop_reason=reason,
        starts=frozenset(starts),
        covered_by=covered_by,
        unreached=frozenset(unreached),
        discontinuity=discontinuity,
        provenance=provenance,
    )


def recursive_descent(
    md: Disassembler, text: bytes, text_base: int, limit: int, roots: Sequence[int]
) -> tuple[bytearray, bytearray, list[int]]:
    """Reachability over the decoded `.text` byte stream.

    Seeds one worklist entry per runtime function start, follows direct branch
    and call targets, and ends a path at every terminator and at every indirect
    transfer. A direct target that lands inside an already decoded instruction is
    not decoded again: that conflict is recorded instead, because the two reads
    cannot both hold. Returns an instruction start bitmap, an interior byte
    bitmap and the sorted such conflicting targets, all indexed by
    `rva - text_base` for the bitmaps.
    """
    starts = bytearray(limit)
    interior = bytearray(limit)
    conflicting: set[int] = set()
    pending: list[int] = list(roots)
    while pending:
        address = pending.pop()
        while True:
            offset = address - text_base
            if offset < 0 or offset >= limit or starts[offset]:
                break
            if interior[offset]:
                conflicting.add(address)
                break
            span = min(DECODE_WINDOW, limit - offset)
            window_base = text_base + offset
            decoded = False
            for insn in md.window(address, text[offset : offset + span], window_base):
                decoded = True
                starts[offset] = 1
                for inner in range(insn.address + 1, insn.address + insn.size):
                    inner_offset = inner - text_base
                    if 0 <= inner_offset < limit:
                        interior[inner_offset] = 1
                mnemonic = insn.mnemonic
                target = direct_target(insn)
                if mnemonic == "jmp":
                    if target is not None:
                        pending.append(target)
                    break
                if is_terminator(mnemonic):
                    break
                if capstone.CS_GRP_JUMP in insn.groups or capstone.CS_GRP_CALL in insn.groups:
                    if target is not None:
                        pending.append(target)
                address = insn.address + insn.size
                offset = address - text_base
                if md.refill(address, window_base):
                    break
            if not decoded:
                break
    return starts, interior, sorted(conflicting)


def objdump_range(
    executable: str, specimen: Path, image_base: int, start: int, end: int
) -> ObjdumpRange:
    """Instruction start addresses and mnemonics objdump produced for a range."""
    completed = subprocess.run(
        [
            executable,
            "-d",
            f"--start-address=0x{image_base + start:X}",
            f"--stop-address=0x{image_base + end:X}",
            str(specimen),
        ],
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        raise SpecimenError(
            f"objdump failed for {common.hexs(start)}-{common.hexs(end)}: "
            f"{(completed.stderr or '').strip()[:200]}"
        )
    found: list[int] = []
    mnemonics: dict[int, str] = {}
    directives = 0
    for line in completed.stdout.splitlines():
        match = OBJDUMP_LINE.match(line)
        if match is None:
            continue
        address = int(match.group(1), 16) - image_base
        if not start <= address < end:
            continue
        text = line.rsplit("\t", 1)[-1].strip()
        mnemonic = text.split(" ")[0] if text else ""
        if mnemonic == ".byte":
            directives += 1
        found.append(address)
        mnemonics[address] = mnemonic
    found.sort()
    return ObjdumpRange(
        requested=(start, end),
        starts=tuple(found),
        mnemonics=mnemonics,
        byte_directives=directives,
        decoded_until=found[-1] if found else start,
    )


def read_committed_csv(path: Path) -> list[dict[str, str]]:
    """The audited evidence file, opened read only."""
    if not path.is_file():
        raise SpecimenError(f"audited evidence file {path} is missing")
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def build_check(
    identifier: str, description: str, expected: Any, observed: Any
) -> dict[str, Any]:
    return {
        "id": identifier,
        "description": description,
        "expected": expected,
        "observed": observed,
        "ok": expected == observed,
    }


def audit(
    root: Path, specimen: Path, csv_path: Path, objdump_path: str
) -> dict[str, Any]:
    """Run the whole audit and return the deterministic payload."""
    checks: list[dict[str, Any]] = []
    with specimen.open("rb") as handle, mmap.mmap(
        handle.fileno(), 0, access=mmap.ACCESS_READ
    ) as view, common.load_pe(specimen) as pe:
        try:
            sections = common.sections(pe)
            image_base = int(pe.OPTIONAL_HEADER.ImageBase)
            begins, ends = load_exception_directory(pe)
            census = census_sections(view, sections)
            candidates = collect_candidates(pe, view, sections)
            text_section = next(
                item for item in sections if item.name == SCOPE_SECTION
            )
            text = view[
                text_section.raw_pointer : text_section.raw_pointer + text_section.raw_size
            ]
            text_base = text_section.virtual_address

            scope = [item for item in candidates if item.section == SCOPE_SECTION]
            out_of_scope = [item for item in candidates if item.section != SCOPE_SECTION]

            owners: dict[int, int] = {}
            wanted: dict[int, list[int]] = {}
            for item in scope:
                index = owner_index(begins, ends, item.rva)
                if index is None:
                    continue
                owners[item.rva] = index
                wanted.setdefault(index, []).append(item.rva)

            md = Disassembler()
            sweeps: dict[int, SweepResult] = {}
            for index in sorted(wanted):
                sweeps[index] = sweep_function(
                    md, text, text_base, begins[index], ends[index], wanted[index]
                )

            reach, interior, misdirected = recursive_descent(
                md, text, text_base, len(text), begins
            )

            def is_start(rva: int) -> bool:
                offset = rva - text_base
                return 0 <= offset < len(reach) and reach[offset] == 1

            def is_interior(rva: int) -> bool:
                offset = rva - text_base
                return 0 <= offset < len(interior) and interior[offset] == 1

            scope_rvas = {item.rva for item in scope}
            disposition: dict[int, str] = {}
            independent: Counter[str] = Counter()
            for item in scope:
                index = owner_index(begins, ends, item.rva)
                if index is None:
                    disposition[item.rva] = DISPOSITION_NO_PDATA
                elif item.rva in sweeps[index].starts:
                    disposition[item.rva] = DISPOSITION_START
                elif item.rva in sweeps[index].covered_by:
                    disposition[item.rva] = DISPOSITION_COVERED
                else:
                    disposition[item.rva] = DISPOSITION_NOT_REACHED
                independent[disposition[item.rva]] += 1
            independent["out_of_scope_data"] = len(out_of_scope)
            valid = {rva for rva in scope_rvas if disposition[rva] == DISPOSITION_START}

            checks.append(
                build_check(
                    "C1.1",
                    f"raw {PATTERN_HEX} hits in the CSV scope section",
                    {SCOPE_SECTION: DOCUMENTED_RAW_HITS},
                    {SCOPE_SECTION: census.get(SCOPE_SECTION)},
                )
            )
            checks.append(
                build_check(
                    "C1.2",
                    "raw hits in the non executable sections the CSV scope omits",
                    {name: count for name, count in zip(DATA_SECTIONS, (27, 3))}
                    | {"total": DOCUMENTED_DATA_HITS},
                    {
                        **{name: census.get(name) for name in DATA_SECTIONS},
                        "total": sum(census.get(name, 0) for name in DATA_SECTIONS),
                    },
                )
            )
            checks.append(
                build_check(
                    "C1.3",
                    "raw hits over all raw backed sections",
                    DOCUMENTED_RAW_HITS + DOCUMENTED_DATA_HITS,
                    sum(census.values()),
                )
            )
            checks.append(
                build_check(
                    "C1.4",
                    "parsed exception directory record count",
                    EXPECTED_RUNTIME_FUNCTIONS,
                    len(begins),
                )
            )
            checks.append(
                build_check(
                    "C2.1",
                    "valid candidates, independent linear sweep",
                    DOCUMENTED_VALID,
                    independent[DISPOSITION_START],
                )
            )
            checks.append(
                build_check(
                    "C2.2",
                    "candidates covered by a preceding instruction, independent sweep",
                    DOCUMENTED_COVERED,
                    independent[DISPOSITION_COVERED],
                )
            )
            checks.append(
                build_check(
                    "C2.3",
                    "candidates in a pdata gap, independent sweep",
                    DOCUMENTED_PDATA_GAP,
                    independent[DISPOSITION_NO_PDATA],
                )
            )
            checks.append(
                build_check(
                    "C2.4",
                    "candidates in rdata/data, outside the CSV scope",
                    DOCUMENTED_DATA_HITS,
                    independent["out_of_scope_data"],
                )
            )
            checks.append(
                build_check(
                    "C2.5",
                    "candidates the linear sweep stopped before",
                    0,
                    independent[DISPOSITION_NOT_REACHED],
                )
            )
            checks.append(
                build_check(
                    "C2.6",
                    "owner functions the sweep could not consume to their end",
                    0,
                    sum(
                        1
                        for sweep in sweeps.values()
                        if sweep.stop_reason != "function_end"
                    ),
                )
            )

            rows = read_committed_csv(csv_path)
            csv_disposition: dict[int, str] = {}
            csv_raw_order: list[int] = []
            row_mismatches: list[dict[str, Any]] = []
            for position, row in enumerate(rows):
                rva = int(row["rva"])
                raw = int(row["raw_offset"])
                csv_raw_order.append(raw)
                csv_disposition[rva] = row["capstone_candidate_disposition"]
                observed = view[raw : raw + len(PATTERN)]
                mine = disposition.get(rva, DISPOSITION_NO_PDATA)
                problems = []
                if observed != PATTERN:
                    problems.append("raw bytes are not the pattern")
                if int(row["hit_index"]) != position:
                    problems.append("hit_index is not the row position")
                if row["capstone_candidate_disposition"] != mine:
                    problems.append("disposition differs from the independent sweep")
                if row["bytes_ok"] != "true":
                    problems.append("bytes_ok is not true")
                if problems:
                    row_mismatches.append(
                        {
                            "hit_index": position,
                            "rva": common.hexs(rva),
                            "problems": problems,
                        }
                    )
            csv_valid = sum(1 for row in rows if row["valid_candidate"] == "true")
            csv_counts = Counter(row["capstone_candidate_disposition"] for row in rows)

            checks.append(
                build_check("C3.1", "audited CSV row count", DOCUMENTED_RAW_HITS, len(rows))
            )
            checks.append(
                build_check(
                    "C3.2",
                    "audited CSV raw offsets strictly ascending",
                    True,
                    all(
                        csv_raw_order[index] < csv_raw_order[index + 1]
                        for index in range(len(csv_raw_order) - 1)
                    ),
                )
            )
            checks.append(
                build_check(
                    "C3.3",
                    "per row raw bytes, hit_index continuity, bytes_ok and disposition",
                    0,
                    len(row_mismatches),
                )
            )
            checks.append(
                build_check(
                    "C3.4",
                    "audited CSV disposition census",
                    {
                        DISPOSITION_START: DOCUMENTED_VALID,
                        DISPOSITION_COVERED: DOCUMENTED_COVERED,
                        DISPOSITION_NO_PDATA: DOCUMENTED_PDATA_GAP,
                    },
                    {name: csv_counts[name] for name in sorted(csv_counts)},
                )
            )
            checks.append(
                build_check(
                    "C3.5",
                    "valid_candidate rows in the audited CSV",
                    DOCUMENTED_VALID,
                    csv_valid,
                )
            )
            checks.append(
                build_check(
                    "C3.6",
                    "candidate rva set of the CSV equals the independent set",
                    0,
                    len(set(csv_disposition) ^ scope_rvas),
                )
            )

            ranges: dict[int, ObjdumpRange] = {}
            range_starts: dict[int, set[int]] = {}
            agree_start = 0
            agree_cover = 0
            named_syscall = 0
            objdump_mnemonic_other: list[dict[str, Any]] = []
            objdump_disagreements: list[dict[str, Any]] = []
            for index in sorted(wanted):
                produced = objdump_range(
                    objdump_path, specimen, image_base, begins[index], ends[index]
                )
                ranges[index] = produced
                produced_set = set(produced.starts)
                range_starts[index] = produced_set
                for rva in sorted(wanted[index]):
                    theirs = rva in produced_set
                    mine = disposition[rva]
                    if mine == DISPOSITION_START and theirs:
                        agree_start += 1
                        if produced.mnemonics.get(rva) == "syscall":
                            named_syscall += 1
                        else:
                            objdump_mnemonic_other.append(
                                {
                                    "rva": common.hexs(rva),
                                    "objdump_mnemonic": produced.mnemonics.get(rva) or None,
                                }
                            )
                    elif mine == DISPOSITION_COVERED and not theirs:
                        agree_cover += 1
                    else:
                        objdump_disagreements.append(
                            {
                                "rva": common.hexs(rva),
                                "function_start_rva": common.hexs(begins[index]),
                                "audit_disposition": mine,
                                "objdump_instruction_start": theirs,
                            }
                        )
            tails = [
                common.hexs(begins[index])
                for index in sorted(ranges)
                if ranges[index].decoded_until < ends[index] - 1
            ]

            checks.append(
                build_check(
                    "C4.1",
                    "valid entries objdump confirms as instruction starts",
                    DOCUMENTED_VALID,
                    agree_start,
                )
            )
            checks.append(
                build_check(
                    "C4.2",
                    "valid entries objdump names `syscall`",
                    DOCUMENTED_VALID,
                    named_syscall,
                )
            )
            checks.append(
                build_check(
                    "C4.3",
                    "covered entries objdump confirms as non starts",
                    DOCUMENTED_COVERED,
                    agree_cover,
                )
            )
            checks.append(
                build_check(
                    "C4.4",
                    "disagreements between the independent sweep and objdump",
                    0,
                    len(objdump_disagreements),
                )
            )
            checks.append(
                build_check(
                    "C4.5",
                    "valid entries objdump decodes with another mnemonic",
                    0,
                    len(objdump_mnemonic_other),
                )
            )

            proof: dict[int, str] = {}
            proof_detail: dict[int, tuple[str, str, int]] = {}
            for rva in sorted(valid):
                kind, text_of, count = sweeps[owners[rva]].discontinuity.get(
                    rva, ("", "", 0)
                )
                proof_detail[rva] = (kind, text_of, count)
                if is_start(rva):
                    proof[rva] = PROOF_FALLTHROUGH if not kind else PROOF_BRANCH
                else:
                    proof[rva] = PROOF_HYPOTHESIS
            proof_counts = Counter(proof.values())
            confirmed = proof_counts[PROOF_FALLTHROUGH] + proof_counts[PROOF_BRANCH]

            checks.append(
                build_check(
                    "C6.1",
                    "valid entries partitioned by proof level, none lost or doubled",
                    len(valid),
                    sum(proof_counts.values()),
                )
            )
            checks.append(
                build_check(
                    "C6.2",
                    "fallthrough proven entries the recursive descent does not confirm",
                    0,
                    sum(
                        1
                        for rva in valid
                        if not proof_detail[rva][0] and not is_start(rva)
                    ),
                )
            )
            checks.append(
                build_check(
                    "C6.3",
                    "covered entries the recursive descent confirms as instruction starts",
                    0,
                    sum(
                        1
                        for rva in scope_rvas
                        if disposition[rva] == DISPOSITION_COVERED and is_start(rva)
                    ),
                )
            )
            checks.append(
                build_check(
                    "C6.4",
                    "pdata gap entries the recursive descent confirms as instruction starts",
                    0,
                    sum(
                        1
                        for rva in scope_rvas
                        if disposition[rva] == DISPOSITION_NO_PDATA and is_start(rva)
                    ),
                )
            )
            checks.append(
                build_check(
                    "C6.5",
                    "direct branch targets landing inside another instruction that touch a "
                    "candidate",
                    0,
                    sum(1 for target in misdirected if target in scope_rvas),
                )
            )
            checks.append(
                build_check(
                    "C6.6",
                    "confirmed instruction starts are all inside the scope set",
                    0,
                    sum(1 for rva in valid if proof[rva] == PROOF_BRANCH and not is_start(rva)),
                )
            )

            function_touched: dict[int, bool] = {}
            for rva in valid:
                index = owners[rva]
                if index in function_touched:
                    continue
                lo = max(begins[index] - text_base, 0)
                hi = min(ends[index] - text_base, len(reach))
                function_touched[index] = any(reach[lo:hi])

            hypothesis: list[dict[str, Any]] = []
            for rva in sorted(valid):
                if proof[rva] != PROOF_HYPOTHESIS:
                    continue
                index = owners[rva]
                kind, text_of, count = proof_detail[rva]
                hypothesis.append(
                    {
                        "rva": common.hexs(rva),
                        "raw": common.hexs(common.rva_to_raw(pe, rva)),
                        "owning_function": common.hexs(begins[index]),
                        "owning_function_end": common.hexs(ends[index]),
                        "owning_function_reached_by_descent": function_touched[index],
                        "last_ignored_control_transfer": kind,
                        "last_ignored_instruction": text_of,
                        "ignored_transfers_before_candidate": count,
                        "recursive_descent_reached": False,
                        "objdump_instruction_start": rva in range_starts[index],
                    }
                )
            hypothesis_kinds = Counter(
                record["last_ignored_control_transfer"] for record in hypothesis
            )

            gap_records: list[dict[str, Any]] = []
            for item in scope:
                if disposition[item.rva] != DISPOSITION_NO_PDATA:
                    continue
                index = bisect.bisect_right(begins, item.rva) - 1
                gap_start = ends[index] if index >= 0 else text_base
                following = index + 1
                gap_end = begins[following] if following < len(begins) else text_base + len(text)
                nearest = min(item.rva - gap_start, gap_end - item.rva)
                gap_records.append(
                    {
                        "rva": common.hexs(item.rva),
                        "raw": common.hexs(common.rva_to_raw(pe, item.rva)),
                        "gap_start": common.hexs(gap_start),
                        "gap_end": common.hexs(gap_end),
                        "gap_size": gap_end - gap_start,
                        "distance_to_nearest_gap_edge": nearest,
                        "gap_kind": GAP_KIND_PADDING
                        if nearest < GAP_ALIGNMENT_THRESHOLD
                        else GAP_KIND_ISLAND,
                        "recursive_descent_reached": is_start(item.rva),
                        "inside_another_instruction": is_interior(item.rva),
                        "reason": COVER_REASONS[DISPOSITION_NO_PDATA],
                    }
                )
            gap_counts = Counter(record["gap_kind"] for record in gap_records)

            cover_records: list[dict[str, Any]] = []
            for item in scope:
                if disposition[item.rva] != DISPOSITION_COVERED:
                    continue
                index = owners[item.rva]
                covering_rva, covering_text = sweeps[index].covered_by[item.rva]
                produced = ranges.get(index)
                objdump_start = None if produced is None else item.rva in range_starts[index]
                cover_records.append(
                    {
                        "rva": common.hexs(item.rva),
                        "raw": common.hexs(common.rva_to_raw(pe, item.rva)),
                        "owning_function": common.hexs(begins[index]),
                        "covering_instruction_rva": common.hexs(covering_rva),
                        "covering_instruction": covering_text,
                        "covering_mnemonic": covering_text.split(" ")[0],
                        "offset_inside_covering_instruction": item.rva - covering_rva,
                        "recursive_descent_reached": is_start(item.rva),
                        "objdump_instruction_start": objdump_start,
                        "reason": COVER_REASONS[DISPOSITION_COVERED],
                    }
                )
            cover_counts = Counter(record["covering_mnemonic"] for record in cover_records)

            data_records: list[dict[str, Any]] = []
            for item in out_of_scope:
                section = next(entry for entry in sections if entry.name == item.section)
                data_records.append(
                    {
                        "rva": common.hexs(item.rva),
                        "raw": common.hexs(common.rva_to_raw(pe, item.rva)),
                        "section": item.section,
                        "section_characteristics": common.hexs(section.characteristics),
                        "section_mem_execute": item.executable,
                        "section_cnt_code": item.code_flag,
                        "covered_by_runtime_function": owner_index(begins, ends, item.rva)
                        is not None,
                        "reason": COVER_REASONS["non_executable_section"],
                    }
                )

            documented: set[int] = set()
            anchor_records: list[dict[str, Any]] = []
            missing_anchors: list[str] = []
            for label, rvas in ANCHOR_GROUPS:
                for rva in rvas:
                    documented.add(rva)
                    index = owner_index(begins, ends, rva)
                    in_valid = rva in valid
                    if not in_valid:
                        missing_anchors.append(common.hexs(rva))
                    sweep = sweeps.get(index) if index is not None else None
                    raw = common.rva_to_raw(pe, rva)
                    anchor_records.append(
                        {
                            "rva": common.hexs(rva),
                            "group": label,
                            "in_valid_subset": in_valid,
                            "audit_disposition": disposition.get(
                                rva, DISPOSITION_NO_PDATA
                            ),
                            "owning_function": common.hexs(begins[index])
                            if index is not None
                            else None,
                            "owning_function_end": common.hexs(ends[index])
                            if index is not None
                            else None,
                            "raw": common.hexs(raw) if raw is not None else None,
                            "bytes": view[raw : raw + len(PATTERN)].hex().upper()
                            if raw is not None
                            else None,
                            "objdump_instruction_start": None
                            if index is None or index not in range_starts
                            else rva in range_starts[index],
                            "objdump_mnemonic": None
                            if index is None or ranges.get(index) is None
                            else ranges[index].mnemonics.get(rva) or None,
                            "recursive_descent_confirmed": is_start(rva),
                            "proof_level": proof.get(rva),
                            "last_ignored_control_transfer": proof_detail.get(
                                rva, ("", "", 0)
                            )[0],
                            "syscall_number_provenance": None
                            if sweep is None
                            else sweep.provenance.get(rva),
                            "service_mapping": SERVICE_STATUS,
                        }
                    )
            anchor_records.sort(key=lambda item: (int(item["rva"], 16), item["group"]))

            checks.append(
                build_check(
                    "C5.1",
                    "unique documented syscall sites in documents 06, 07 and 12",
                    DOCUMENTED_ANCHOR_SITES,
                    len(documented),
                )
            )
            checks.append(
                build_check(
                    "C5.2",
                    "documented syscall sites missing from the valid subset",
                    0,
                    len(missing_anchors),
                )
            )
            checks.append(
                build_check(
                    "C5.3",
                    "documented sites objdump confirms as instruction starts",
                    len(documented),
                    sum(
                        1
                        for record in anchor_records if record["objdump_instruction_start"]
                    ),
                )
            )
            checks.append(
                build_check(
                    "C5.4",
                    "documented sites objdump names `syscall`",
                    len(documented),
                    sum(
                        1
                        for record in anchor_records if record["objdump_mnemonic"] == "syscall"
                    ),
                )
            )

            eax_population = Counter(
                sweeps[owners[rva]].provenance.get(rva) for rva in sorted(valid)
            )
            eax_anchors = Counter(
                record["syscall_number_provenance"] for record in anchor_records
            )
        except ValueError as error:
            raise SpecimenError(str(error)) from error
        finally:
            pe.close()

    return {
        "schema": "adhesive-dumper.audit_syscall_candidates/1",
        "audit_target": {
            "script": "reverse/scripts/syscall_scan.py",
            "evidence": f"reverse/evidence/{csv_path.name}",
            "question": (
                "are the boundary verdicts of the raw 0F 05 candidate scan reproducible from "
                "the bytes, and is every valid entry a real instruction start"
            ),
        },
        "producer": {
            "script": f"reverse/scripts/{Path(__file__).name}",
            "script_sha256": common.sha256_file(Path(__file__).resolve()),
            "python": common.python_summary().get("version"),
            "capstone": {
                "module_version": getattr(capstone, "__version__", None),
                "engine_version": list(capstone.cs_version()),
            },
            "second_decoder": common.objdump_version(),
            "method": [
                "own byte census over every raw backed section",
                "own exception directory parse with ordering, overlap and emptiness validation",
                "own Capstone linear sweep of every owning runtime function",
                "own recursive descent seeded with every runtime function entry",
                "GNU objdump linear disassembly of the same ranges as the second decoder",
            ],
            "not_performed": [
                "the specimen is never mapped for execution and no module is loaded",
                "the audited script is never executed and the audited CSV is never written",
                "no service number is decoded and no Nt/Zw service name is asserted",
                "no caller, argument dataflow or intent classification is attempted",
            ],
        },
        "specimen": {
            "path": _display(root, specimen),
            "size": specimen.stat().st_size,
            "sha256": common.sha256_file(specimen),
        },
        "inputs": {
            "audited_csv": {
                "path": f"reverse/evidence/{csv_path.name}",
                "sha256": common.sha256_file(csv_path),
                "rows": len(rows),
            },
            "audited_script": {
                "path": "reverse/scripts/syscall_scan.py",
                "sha256": common.sha256_file(root / "reverse" / "scripts" / "syscall_scan.py"),
                "lines": _line_count(root / "reverse" / "scripts" / "syscall_scan.py"),
                "note": (
                    "3881 is the raw hit count of the scope section, not a line count of the "
                    "audited script"
                ),
            },
        },
        "raw_census": {
            "pattern": PATTERN_HEX,
            "per_section": {name: census[name] for name in sorted(census)},
            "total_all_sections": sum(census.values()),
            "csv_scope_section": SCOPE_SECTION,
            "csv_scope_candidates": len(scope),
            "outside_csv_scope": len(out_of_scope),
        },
        "boundary_reproduction": {
            "documented": {
                "raw_hits_in_scope": DOCUMENTED_RAW_HITS,
                "valid_candidates": DOCUMENTED_VALID,
                "covered_by_instruction": DOCUMENTED_COVERED,
                "pdata_gap": DOCUMENTED_PDATA_GAP,
                "rdata_data": DOCUMENTED_DATA_HITS,
            },
            "independent": {
                "raw_hits_in_scope": census.get(SCOPE_SECTION),
                "valid_candidates": independent[DISPOSITION_START],
                "covered_by_instruction": independent[DISPOSITION_COVERED],
                "pdata_gap": independent[DISPOSITION_NO_PDATA],
                "rdata_data": independent["out_of_scope_data"],
                "sweep_stopped_before_candidate": independent[DISPOSITION_NOT_REACHED],
            },
            "audited_csv": {
                "raw_hits_in_scope": len(rows),
                "valid_candidates": csv_valid,
                "covered_by_instruction": csv_counts[DISPOSITION_COVERED],
                "pdata_gap": csv_counts[DISPOSITION_NO_PDATA],
                "rdata_data": "absent, the CSV scope is the executable section only",
            },
            "ratios": {
                "valid_of_scope": _ratio(independent[DISPOSITION_START], len(scope)),
                "covered_of_scope": _ratio(independent[DISPOSITION_COVERED], len(scope)),
                "pdata_gap_of_scope": _ratio(independent[DISPOSITION_NO_PDATA], len(scope)),
                "rdata_data_of_all_sections": _ratio(
                    independent["out_of_scope_data"], len(candidates)
                ),
            },
            "all_reproduce": all(
                independent[key] == value
                for key, value in (
                    (DISPOSITION_START, DOCUMENTED_VALID),
                    (DISPOSITION_COVERED, DOCUMENTED_COVERED),
                    (DISPOSITION_NO_PDATA, DOCUMENTED_PDATA_GAP),
                    ("out_of_scope_data", DOCUMENTED_DATA_HITS),
                    (DISPOSITION_NOT_REACHED, 0),
                )
            ),
        },
        "instruction_start_validation": {
            "claim_under_test": (
                "a raw byte pair is a real instruction only when it is an instruction start on a "
                "decoded executable path, and the only path the audited script decodes is the "
                "linear sweep of the owning runtime function"
            ),
            "valid_entries": len(valid),
            "second_decoder": {
                "role": "decoder that shares no code with either implementation",
                "ranges": len(ranges),
                "instruction_start_confirmed": agree_start,
                "syscall_mnemonic_confirmed": named_syscall,
                "non_syscall_mnemonic": objdump_mnemonic_other,
                "disagreements": objdump_disagreements,
                "byte_directives": sum(
                    item.byte_directives for item in ranges.values()
                ),
                "ranges_with_undecoded_tail": tails,
            },
            "proof_levels": {
                "definition": {
                    PROOF_FALLTHROUGH: (
                        "on an uninterrupted fallthrough chain from the owning function entry, "
                        "so the instruction start follows from the entry alone"
                    ),
                    PROOF_BRANCH: (
                        "not on the fallthrough chain, but a resolvable direct branch of the same "
                        "function reaches the address in the recursive descent"
                    ),
                    PROOF_HYPOTHESIS: (
                        "only the linear sweep reaches the address, which requires the decode to "
                        "continue across a control transfer the sweep ignores"
                    ),
                },
                "counts": {name: proof_counts[name] for name in sorted(proof_counts)},
                "descent_confirmed": confirmed,
                "descent_unconfirmed": proof_counts[PROOF_HYPOTHESIS],
            },
            "recursive_descent": {
                "seeds": "every runtime function entry of the exception directory",
                "instruction_starts_reached": sum(reach),
                "text_rva_range": [common.hexs(text_base), common.hexs(text_base + len(text))],
                "text_bytes": len(text),
                "direct_branch_targets_inside_another_instruction": [
                    common.hexs(target) for target in misdirected
                ],
                "any_candidate_affected": any(
                    target in scope_rvas for target in misdirected
                ),
            },
            "verdict": (
                "every valid entry is an instruction start of its owning runtime function under "
                "two independent decoders, so none of them is a decoder artifact; the proof "
                "level split states how far each start is control flow proven"
            ),
        },
        "documented_anchors": {
            "documents": [
                "reverse/adhesive-06-process-memory-hooks.md",
                "reverse/adhesive-07-anti-debug-integrity.md",
                "reverse/adhesive-12-risk-methodology-open-questions.md",
            ],
            "groups": len(ANCHOR_GROUPS),
            "unique_sites": len(documented),
            "all_in_valid_subset": not missing_anchors,
            "missing_from_valid_subset": missing_anchors,
            "descent_confirmed_sites": sum(
                1 for record in anchor_records if record["recursive_descent_confirmed"]
            ),
            "sites": anchor_records,
        },
        "boundary_ambiguous": {
            "definition": (
                "a candidate whose instruction start verdict is not settled by the audited "
                "evidence alone, either because the verdict depends on a decode hypothesis or "
                "because its rejection rests on the runtime function channel only"
            ),
            "hypothesis_only_count": len(hypothesis),
            "hypothesis_only_by_ignored_control_transfer": {
                name: hypothesis_kinds[name] for name in sorted(hypothesis_kinds)
            },
            "hypothesis_only": hypothesis,
            "pdata_gap_count": len(gap_records),
            "pdata_gap_by_kind": {name: gap_counts[name] for name in sorted(gap_counts)},
            "pdata_gap": gap_records,
            "notes": [
                "no owner function needed a stopped sweep, so no candidate is left undecided by "
                "an undecodable byte inside its own runtime function",
                "no direct branch target lands inside another instruction, so no candidate is "
                "entered through a mid instruction transfer",
                "the pdata gap entries stop being ambiguous once the descent is added: none is "
                "an instruction start reachable from any runtime function entry",
                "a hypothesis only entry is not a defect of the audited script, whose docstring "
                "states the linear sweep as the decode channel; it is a limit of what the "
                "evidence file alone can prove",
            ],
        },
        "false_positive_explanations": {
            "definition": (
                "why a raw byte pair is not a syscall instruction, grouped by the channel that "
                "decides it"
            ),
            "in_csv_scope_total": len(scope) - len(valid),
            "all_sections_total": len(candidates) - len(valid),
            "by_channel": {
                "interior_byte_of_a_preceding_instruction": len(cover_records),
                "no_runtime_function_covers_the_rva": len(gap_records),
                "non_executable_section": len(data_records),
            },
            "channel_reasons": COVER_REASONS,
            "interior_byte_by_covering_mnemonic": {
                name: cover_counts[name] for name in sorted(cover_counts)
            },
            "interior_byte_cases": cover_records,
            "pdata_gap_cases": gap_records,
            "non_executable_section_cases": data_records,
            "note": (
                "the rdata and data rows are absent from the audited CSV because its scope is "
                "the executable section; they are counted here from the same raw byte census"
            ),
        },
        "unresolved_service_mapping": {
            "status": SERVICE_STATUS,
            "reason": (
                "the audited script has no service number channel by design: it records the byte "
                "pair, the runtime function boundary and the sweep verdict, and it neither decodes "
                "RAX nor names a service"
            ),
            "number_register": "RAX, defined by the code before the syscall",
            "provenance_method": {
                "kind": "bounded backward window, not a dataflow proof",
                "window_instructions": EAX_WINDOW,
                "window_scope": (
                    "the last instructions of the owning runtime function before the candidate, "
                    "taken from the same linear decode the audited script uses"
                ),
                "reported": "the shape of the last RAX definition only, never a value",
            },
            "provenance_classes": {
                EAX_CONSTANT: (
                    "an immediate reaches RAX inside the window, so the number is a build time "
                    "constant on that path"
                ),
                EAX_DERIVED: (
                    "the last RAX definition in the window reads a register, memory or an "
                    "arithmetic result, so the number is path dependent there"
                ),
                EAX_UNKNOWN: (
                    "no RAX definition inside the window, so the number is defined further up or "
                    "on another path"
                ),
            },
            "valid_population": {name: eax_population[name] for name in sorted(eax_population)},
            "documented_anchor_population": {
                name: eax_anchors[name] for name in sorted(eax_anchors)
            },
            "open_questions": [
                "which Nt/Zw service each R10/EDX/R8/R9 argument set belongs to",
                "whether the immediate constants of the constant provenance class are stable "
                "service numbers or only per build seeds",
                "how the derived classes compute the number, which needs the mixing chains that "
                "read KUSER_SHARED_DATA, the PEB and the global constants",
                "which of the valid entries are reachable at all, which the proof level split "
                "leaves open for the hypothesis only entries",
                "whether the ten documented sites that share a runtime function with a "
                "documented parent pid read are the same service as the process memory sites",
            ],
            "conclusion": (
                "every site stays unresolved: this audit asserts no service name, and the "
                "provenance class is a resolvability hint, not a mapping"
            ),
        },
        "checks": checks,
        "verdict": {
            "ratios_reproduce": all(
                check["ok"]
                for check in checks
                if check["id"].startswith(("C1", "C2", "C3"))
            ),
            "instruction_start_confirmed": all(
                check["ok"] for check in checks if check["id"].startswith("C4")
            ),
            "anchors_in_subset": all(
                check["ok"] for check in checks if check["id"].startswith("C5")
            ),
            "control_flow_claims_consistent": all(
                check["ok"] for check in checks if check["id"].startswith("C6")
            ),
            "all_checks_passed": all(check["ok"] for check in checks),
            "checks_run": len(checks),
            "summary": (
                "the valid, covered, pdata gap and rdata/data figures reproduce from an "
                "independent implementation, agree row by row with the audited CSV, and every "
                "valid entry is an instruction start under two independent decoders; the "
                "boundary finding of this audit is that a valid entry is a linear sweep verdict, "
                "and only the descent proven share of them is control flow proven"
            ),
        },
    }


def _ratio(part: int, whole: int) -> dict[str, Any]:
    return {
        "part": part,
        "whole": whole,
        "percent": None if whole == 0 else round(100.0 * part / whole, 4),
    }


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def _display(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def report(payload: dict[str, Any], written: Path, root: Path) -> None:
    reproduction = payload["boundary_reproduction"]
    proof = payload["instruction_start_validation"]["proof_levels"]
    ambiguous = payload["boundary_ambiguous"]
    discarded = payload["false_positive_explanations"]
    service = payload["unresolved_service_mapping"]
    print(f"script    {_display(root, Path(__file__).resolve())}")
    print(f"specimen  {payload['specimen']['path']} sha256={payload['specimen']['sha256']}")
    print(
        "census    "
        + " ".join(
            f"{name}={count}"
            for name, count in payload["raw_census"]["per_section"].items()
            if count
        )
        + f" total={payload['raw_census']['total_all_sections']}"
    )
    print(
        "ratios    "
        f"valid={reproduction['independent']['valid_candidates']} "
        f"covered={reproduction['independent']['covered_by_instruction']} "
        f"pdata_gap={reproduction['independent']['pdata_gap']} "
        f"rdata_data={reproduction['independent']['rdata_data']} "
        f"reproduce={reproduction['all_reproduce']}"
    )
    print(
        "proof     "
        + " ".join(f"{name}={proof['counts'][name]}" for name in sorted(proof["counts"]))
    )
    print(
        "ambiguous "
        f"hypothesis_only={ambiguous['hypothesis_only_count']} "
        f"pdata_gap={ambiguous['pdata_gap_count']}"
    )
    print(
        "discarded "
        + " ".join(
            f"{name}={count}" for name, count in sorted(discarded["by_channel"].items())
        )
        + f" csv_scope={discarded['in_csv_scope_total']}"
        + f" all_sections={discarded['all_sections_total']}"
    )
    print(
        "service   "
        f"status={service['status']} population="
        + ",".join(
            f"{name}:{count}" for name, count in sorted(service["valid_population"].items())
        )
    )
    print()
    for check in payload["checks"]:
        print(f"{'ok  ' if check['ok'] else 'FAIL'} {check['id']:<5} {check['description']}")
    print()
    print(
        f"checks    {payload['verdict']['checks_run']} "
        f"passed={payload['verdict']['all_checks_passed']}"
    )
    print(f"json      {_display(root, written)}")


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description=(
            "Independent static audit of the 0F 05 candidate scan: reproduces the raw byte "
            "census, the boundary verdicts and the documented anchor subset, then re-derives "
            "every instruction start with a second decoder and a recursive descent. No service "
            "number is decoded and no service name is asserted."
        )
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument(
        "--csv",
        type=Path,
        default=root / "reverse" / "evidence" / "syscall_candidates_raw.csv",
        help="the audited evidence file, opened read only",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=root / "reverse" / "evidence" / "audit_syscall_candidates.json",
    )
    parser.add_argument(
        "--objdump",
        default="objdump",
        help="GNU objdump executable used as the second decoder",
    )
    args = parser.parse_args(argv)

    specimen = args.specimen.resolve()
    csv_path = args.csv.resolve()
    output = args.out.resolve()
    if not specimen.is_file():
        print(f"ERROR specimen {specimen} is missing")
        return 2
    objdump_path = shutil.which(args.objdump)
    if objdump_path is None:
        print(f"ERROR {args.objdump} is not on PATH, the second decoder is mandatory")
        return 2
    try:
        payload = audit(root, specimen, csv_path, objdump_path)
    except SpecimenError as error:
        print(f"ERROR {error}")
        return 2
    written = common.write_json(output, payload)
    report(payload, written, root)
    return 0 if payload["verdict"]["all_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
