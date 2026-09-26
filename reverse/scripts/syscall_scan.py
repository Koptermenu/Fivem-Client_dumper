"""Phase P0/S6 static 0F 05 candidate scan for the adhesive.dll specimen.

Static file parsing only: the specimen is never mapped for execution, no module
is loaded and no code is run. This phase inventories raw `0F 05` byte pairs and
records the structural facts that are decidable without executing the image. It
deliberately does not resolve a syscall number to an Nt/Zw service name, does
not decode service numbers, and does not classify intent; service mapping is a
later phase.

Scope and word channel
----------------------
`0F 05` is the x86-64 `syscall` encoding, but a raw byte pair only proves that
those two bytes exist at that file offset. A candidate is a real instruction
only when the byte pair is an instruction start on a decoded, executable path.
The only structural channel in this image that declares where an instruction
stream may begin and end is the `.pdata` exception directory, so every boundary
fact below is expressed relative to the owning `IMAGE_RUNTIME_FUNCTION`:

  * `pdata_function_*`        the runtime function that covers the candidate RVA,
                             taken from the parsed exception directory.
  * `pdata_word_boundary_ok`  whether the candidate RVA sits on a 4-byte word
                             boundary of that function, that is
                             `(rva - function_start) % 4 == 0`. Four bytes is
                             the x86-64 natural word granularity that
                             RIP-relative displacements, base relocations and
                             unwind code slots are all built from, so it is the
                             word channel granularity of the function. x86-64
                             does not require instruction starts to be word
                             aligned, so this column is advisory triage and
                             never on its own marks or clears a candidate.
  * `capstone_*`              a linear Capstone sweep started at the runtime
                             function start and run to the runtime function
                             end. The sweep is addressed in RVA space, so its
                             instruction starts line up with the `rva` column.
                             `capstone_linear_stop_rva` is the first byte the
                             sweep could not consume as an instruction, and
                             `capstone_boundary_ok` records whether the
                             candidate is one of the instruction starts the
                             sweep produced. A candidate that the sweep passed
                             over without starting an instruction there is
                             covered by the instruction named in
                             `capstone_covering_instruction`, and
                             `capstone_candidate_disposition` names the case:
                             `instruction_start`, `covered_by_instruction`,
                             `sweep_stopped_before_candidate` or
                             `no_pdata_function`.

Classification
--------------
  bytes_ok            the mapped raw bytes at the offset really are `0F 05`.
  in_code             the owning section is an executable code section.
  in_data             the owning section is not executable, so the byte pair
                      can never be executed as an instruction.
  in_pdata            the candidate RVA is covered by a runtime function.
  false_positive_ok   the candidate survived every check above, that is it is a
                      confirmed `syscall` instruction start on the linear sweep
                      of its own runtime function.
  valid_candidate     `bytes_ok and in_code and in_pdata and false_positive_ok`.

Determinism
-----------
Rows are emitted in ascending raw offset order with a fixed column order, the
CSV is written through `common.write_csv` as UTF-8 without BOM and LF line
terminators, and no timestamp or environment value reaches the payload. Reruns
of the script on the same specimen produce a byte identical CSV.

Evidence
--------
The default scope is the `.text` raw byte stream, which must reproduce the
`3 881` raw hits recorded in
`reverse/adhesive-12-risk-methodology-open-questions.md` ("Direct syscall
scope"). Every raw backed section is swept and reported on stdout as well, so
raw hits in non-executable sections stay visible even though they sit outside
the CSV scope.

The CSV is written only when the raw hit count and, when `--expect-valid` is
given, the valid candidate count match their expected values, so a failed
invariant never replaces a good evidence file. Exit status is `0` on success,
`1` on an expectation mismatch and `2` on a specimen structure error. The
valid candidate count is also reported on its own line, separate from the CSV.
"""

from __future__ import annotations

import argparse
import bisect
import mmap
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

PATTERN: Final[bytes] = bytes((0x0F, 0x05))
DEFAULT_SCAN_SECTIONS: Final[tuple[str, ...]] = (".text",)
EXPECTED_RAW_HITS: Final[int] = 3881
EXPECTED_RAW_HITS_SOURCE: Final[str] = (
    "reverse/adhesive-12-risk-methodology-open-questions.md#direct-syscall-scope"
)
WORD_ALIGNMENT: Final[int] = 4
SECTION_CNT_CODE: Final[int] = 0x00000020
SECTION_MEM_EXECUTE: Final[int] = 0x20000000
STOP_FUNCTION_END: Final[str] = "function_end"
STOP_UNDECODABLE: Final[str] = "undecodable"
STOP_EMPTY_RANGE: Final[str] = "empty_range"
STOP_UNMAPPED: Final[str] = "unmapped"
REASON_NO_PDATA: Final[str] = "no_pdata_function"
REASON_INSTRUCTION_START: Final[str] = "instruction_start"
REASON_COVERED: Final[str] = "covered_by_instruction"
REASON_NOT_REACHED: Final[str] = "sweep_stopped_before_candidate"

CSV_FIELDS: Final[tuple[str, ...]] = (
    "hit_index",
    "section_name",
    "section_characteristics_hex",
    "raw_offset",
    "raw_offset_hex",
    "rva",
    "rva_hex",
    "va",
    "va_hex",
    "bytes_hex",
    "bytes_ok",
    "in_code",
    "in_data",
    "in_pdata",
    "pdata_function_index",
    "pdata_function_start_rva_hex",
    "pdata_function_end_rva_hex",
    "pdata_function_size",
    "pdata_function_offset",
    "pdata_function_offset_hex",
    "pdata_word_boundary_ok",
    "capstone_checked",
    "capstone_instruction",
    "capstone_instruction_size",
    "capstone_covering_rva_hex",
    "capstone_covering_instruction",
    "capstone_linear_stop_rva_hex",
    "capstone_linear_stop_reason",
    "capstone_candidate_disposition",
    "capstone_boundary_ok",
    "false_positive",
    "false_positive_ok",
    "valid_candidate",
)


class RawImage:
    """File offset and RVA reader over a read only memory map of the specimen."""

    __slots__ = ("_pe", "_view")

    def __init__(self, pe: Any, view: mmap.mmap) -> None:
        self._pe = pe
        self._view = view

    def at_raw(self, raw: int, length: int) -> bytes:
        return self._view[raw : raw + length]

    def at_rva(self, rva: int, length: int) -> bytes | None:
        raw = common.rva_to_raw(self._pe, rva)
        if raw is None:
            return None
        return self.at_raw(raw, length)


@dataclass(frozen=True, slots=True)
class RuntimeFunctionTable:
    """Parsed x64 exception directory, sorted by begin address."""

    begins: tuple[int, ...]
    ends: tuple[int, ...]
    unwinds: tuple[int, ...]

    def locate(self, rva: int) -> int | None:
        index = bisect.bisect_right(self.begins, rva) - 1
        if index < 0 or rva >= self.ends[index]:
            return None
        return index


@dataclass(frozen=True, slots=True)
class FunctionSweep:
    """Outcome of one linear Capstone sweep over a runtime function."""

    stop_rva: int
    stop_reason: str
    instructions: dict[int, tuple[str, int]]
    covering: dict[int, tuple[int, str]]


@dataclass(frozen=True, slots=True)
class RawHit:
    raw: int
    rva: int
    section: common.Section
    in_code: bool


def load_runtime_function_table(pe: Any) -> RuntimeFunctionTable:
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[common.EXCEPTION_DIRECTORY_INDEX]
    rva = int(directory.VirtualAddress)
    size = int(directory.Size)
    if size == 0 or size % common.RUNTIME_FUNCTION_SIZE:
        raise ValueError(
            f"exception directory size {common.hexs(size)} is not a record multiple"
        )
    blob = common.read_rva(pe, rva, size)
    if len(blob) != size:
        raise ValueError(f"exception directory blob is {len(blob)} bytes, expected {size}")
    records = tuple(struct.iter_unpack("<III", blob))
    if len(records) * common.RUNTIME_FUNCTION_SIZE != size:
        raise ValueError("exception directory record count does not match its size")
    begins = tuple(record[0] for record in records)
    if any(begins[index] > begins[index + 1] for index in range(len(begins) - 1)):
        raise ValueError("exception directory is not sorted by begin address")
    return RuntimeFunctionTable(
        begins=begins,
        ends=tuple(record[1] for record in records),
        unwinds=tuple(record[2] for record in records),
    )


def find_pattern(blob: bytes, pattern: bytes) -> list[int]:
    offsets: list[int] = []
    index = blob.find(pattern)
    while index != -1:
        offsets.append(index)
        index = blob.find(pattern, index + 1)
    return offsets


def scan_sections(
    pe: Any, image: RawImage, sections: Sequence[common.Section]
) -> tuple[list[RawHit], dict[str, int]]:
    """Collect raw pattern hits for every raw backed section, in raw order."""
    hits: list[RawHit] = []
    census: dict[str, int] = {}
    for section in sections:
        if section.raw_size == 0:
            continue
        blob = image.at_raw(section.raw_pointer, section.raw_size)
        found = find_pattern(blob, PATTERN)
        census[section.name] = len(found)
        in_code = bool(section.characteristics & SECTION_MEM_EXECUTE) and bool(
            section.characteristics & SECTION_CNT_CODE
        )
        for offset in found:
            raw = section.raw_pointer + offset
            rva = common.raw_to_rva(pe, raw)
            if rva is None:
                raise ValueError(f"raw offset {common.hexs(raw)} maps to no rva")
            hits.append(RawHit(raw=raw, rva=rva, section=section, in_code=in_code))
    hits.sort(key=lambda hit: hit.raw)
    return hits, census


def linear_sweep(
    disassembler: capstone.Cs,
    image: RawImage,
    start: int,
    end: int,
    wanted: set[int],
) -> FunctionSweep:
    """Decode linearly from `start` to `end` and report the reached starts.

    `wanted` holds the candidate RVAs that live in this function. For each of
    them the sweep records either that it is an instruction start or the
    instruction whose encoding swallows its bytes.
    """
    if end <= start:
        return FunctionSweep(end, STOP_EMPTY_RANGE, {}, {})
    code = image.at_rva(start, end - start)
    if code is None:
        return FunctionSweep(start, STOP_UNMAPPED, {}, {})
    if not code:
        return FunctionSweep(start, STOP_UNDECODABLE, {}, {})
    ordered = sorted(wanted)
    cursor = start
    pending = 0
    instructions: dict[int, tuple[str, int]] = {}
    covering: dict[int, tuple[int, str]] = {}
    for insn in disassembler.disasm(code, start):
        insn_end = insn.address + insn.size
        is_start = insn.address in wanted
        while pending < len(ordered) and ordered[pending] <= insn.address:
            pending += 1
        swallowed = (
            ordered[pending]
            if pending < len(ordered) and ordered[pending] < insn_end
            else None
        )
        if is_start or swallowed is not None:
            text = f"{insn.mnemonic} {insn.op_str}".strip()
            if is_start:
                instructions[insn.address] = (text, insn.size)
            else:
                covering[swallowed] = (insn.address, text)
        cursor = insn_end
    reason = STOP_FUNCTION_END if cursor >= end else STOP_UNDECODABLE
    return FunctionSweep(cursor, reason, instructions, covering)


def build_rows(
    pe: Any,
    image: RawImage,
    hits: Sequence[RawHit],
    table: RuntimeFunctionTable,
) -> tuple[list[dict[str, Any]], Counter[str]]:
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    disassembler.detail = False
    disassembler.skipdata = False

    owner: dict[int, int] = {}
    wanted_by_function: dict[int, set[int]] = {}
    for hit in hits:
        index = table.locate(hit.rva)
        if index is None:
            continue
        owner[hit.raw] = index
        wanted_by_function.setdefault(index, set()).add(hit.rva)

    sweeps: dict[int, FunctionSweep] = {}
    for index in sorted(wanted_by_function):
        sweeps[index] = linear_sweep(
            disassembler,
            image,
            table.begins[index],
            table.ends[index],
            wanted_by_function[index],
        )

    tally: Counter[str] = Counter()
    rows: list[dict[str, Any]] = []
    for position, hit in enumerate(hits):
        observed = image.at_raw(hit.raw, len(PATTERN))
        bytes_ok = observed == PATTERN
        va = common.rva_to_va(pe, hit.rva)
        index = owner.get(hit.raw)
        sweep = None if index is None else sweeps[index]
        entry = None if sweep is None else sweep.instructions.get(hit.rva)
        cover = None if (sweep is None or entry is not None) else sweep.covering.get(hit.rva)
        if entry is not None:
            instruction_text, instruction_size = entry
        else:
            instruction_text, instruction_size = "", 0
        if index is None:
            function_offset = None
            stop_rva_hex = ""
            stop_reason = REASON_NO_PDATA
        else:
            function_offset = hit.rva - table.begins[index]
            stop_rva_hex = common.hexs(sweep.stop_rva)
            stop_reason = sweep.stop_reason
        boundary_ok = entry is not None
        in_code = hit.in_code
        in_data = not in_code
        in_pdata = index is not None
        word_boundary_ok = (
            function_offset is not None and function_offset % WORD_ALIGNMENT == 0
        )
        false_positive = not (bytes_ok and in_code and boundary_ok)
        valid_candidate = bool(bytes_ok and in_code and in_pdata and not false_positive)
        if index is None:
            disposition = REASON_NO_PDATA
        elif boundary_ok:
            disposition = REASON_INSTRUCTION_START
        elif cover is not None:
            disposition = REASON_COVERED
        else:
            disposition = REASON_NOT_REACHED

        rows.append(
            {
                "hit_index": position,
                "section_name": hit.section.name,
                "section_characteristics_hex": common.hexs(hit.section.characteristics),
                "raw_offset": hit.raw,
                "raw_offset_hex": common.hexs(hit.raw),
                "rva": hit.rva,
                "rva_hex": common.hexs(hit.rva),
                "va": va,
                "va_hex": common.hexs(va),
                "bytes_hex": observed.hex().upper(),
                "bytes_ok": bytes_ok,
                "in_code": in_code,
                "in_data": in_data,
                "in_pdata": in_pdata,
                "pdata_function_index": index if index is not None else "",
                "pdata_function_start_rva_hex": common.hexs(table.begins[index])
                if index is not None
                else "",
                "pdata_function_end_rva_hex": common.hexs(table.ends[index])
                if index is not None
                else "",
                "pdata_function_size": table.ends[index] - table.begins[index]
                if index is not None
                else "",
                "pdata_function_offset": function_offset
                if function_offset is not None
                else "",
                "pdata_function_offset_hex": common.hexs(function_offset)
                if function_offset is not None
                else "",
                "pdata_word_boundary_ok": word_boundary_ok,
                "capstone_checked": sweep is not None,
                "capstone_instruction": instruction_text,
                "capstone_instruction_size": instruction_size,
                "capstone_covering_rva_hex": common.hexs(cover[0]) if cover else "",
                "capstone_covering_instruction": cover[1] if cover else "",
                "capstone_linear_stop_rva_hex": stop_rva_hex,
                "capstone_linear_stop_reason": stop_reason,
                "capstone_candidate_disposition": disposition,
                "capstone_boundary_ok": boundary_ok,
                "false_positive": false_positive,
                "false_positive_ok": not false_positive,
                "valid_candidate": valid_candidate,
            }
        )

        tally["rows"] += 1
        tally["bytes_ok"] += int(bytes_ok)
        tally["in_code"] += int(in_code)
        tally["in_data"] += int(in_data)
        tally["in_pdata"] += int(in_pdata)
        tally["word_boundary_ok"] += int(word_boundary_ok)
        tally["capstone_checked"] += int(sweep is not None)
        tally["capstone_boundary_ok"] += int(boundary_ok)
        tally[disposition] += 1
        tally[f"stop:{stop_reason}"] += 1
        tally["false_positive"] += int(false_positive)
        tally["valid_candidate"] += int(valid_candidate)

    return rows, tally


def resolve_sections(
    sections: Sequence[common.Section], names: Sequence[str]
) -> tuple[common.Section, ...]:
    by_name = {section.name: section for section in sections}
    missing = [name for name in names if name not in by_name]
    if missing:
        raise ValueError(f"unknown section name(s): {', '.join(missing)}")
    return tuple(by_name[name] for name in names)


def _stop_reasons(tally: Counter[str]) -> str:
    reasons = (
        STOP_FUNCTION_END,
        STOP_UNDECODABLE,
        STOP_EMPTY_RANGE,
        STOP_UNMAPPED,
        REASON_NO_PDATA,
    )
    return " ".join(
        f"{name}={tally['stop:' + name]}" for name in reasons if tally["stop:" + name]
    )


def _display(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def report(
    root: Path,
    specimen: Path,
    relative_specimen: str,
    scope_names: Sequence[str],
    census: dict[str, int],
    table: RuntimeFunctionTable,
    rows: Sequence[dict[str, Any]],
    tally: Counter[str],
    output: Path,
    written: Path | None,
    expected_raw_hits: int,
) -> None:
    print(f"script    {_display(root, Path(__file__).resolve())}")
    print(
        f"specimen  {relative_specimen} size={specimen.stat().st_size} "
        f"sha256={common.sha256_file(specimen)}"
    )
    print(f"pattern   {PATTERN.hex().upper()}")
    print(f"scope     {', '.join(scope_names)}")
    print(
        "census    "
        + " ".join(f"{name}={count}" for name, count in sorted(census.items()))
        + f" total={sum(census.values())}"
    )
    print(
        f"pdata     records={len(table.begins)} "
        f"expected={common.EXPECTED_RUNTIME_FUNCTIONS} "
        f"ok={len(table.begins) == common.EXPECTED_RUNTIME_FUNCTIONS}"
    )
    print(
        f"raw hits  {len(rows)} expected={expected_raw_hits} "
        f"ok={len(rows) == expected_raw_hits} source={EXPECTED_RAW_HITS_SOURCE}"
    )
    print(
        f"rows      bytes_ok={tally['bytes_ok']} in_code={tally['in_code']} "
        f"in_data={tally['in_data']} in_pdata={tally['in_pdata']} "
        f"word_boundary_ok={tally['word_boundary_ok']}"
    )
    print(
        f"capstone  checked={tally['capstone_checked']} "
        f"boundary_ok={tally['capstone_boundary_ok']} "
        f"stop={_stop_reasons(tally)}"
    )
    print(
        f"candidate {REASON_INSTRUCTION_START}={tally[REASON_INSTRUCTION_START]} "
        f"{REASON_COVERED}={tally[REASON_COVERED]} "
        f"{REASON_NOT_REACHED}={tally[REASON_NOT_REACHED]} "
        f"{REASON_NO_PDATA}={tally[REASON_NO_PDATA]}"
    )
    print(
        f"discarded false_positive={tally['false_positive']} "
        f"false_positive_ok={tally['rows'] - tally['false_positive']}"
    )
    if written is None:
        print(f"csv       {_display(root, output)} not written, invariant failed")
    else:
        print(f"csv       {_display(root, written)} rows={tally['rows']}")
    print()
    print(f"VALID CANDIDATES (checked, false_positive_ok): {tally['valid_candidate']}")


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description=(
            "Static 0F 05 candidate scan: raw offset, rva, section, pdata function, "
            "pdata word boundary, Capstone linear sweep boundary, bytes_ok, in_code, "
            "in_data and false_positive verdict. No Nt service identification."
        )
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument(
        "--out",
        type=Path,
        default=root / "reverse" / "evidence" / "syscall_candidates_raw.csv",
    )
    parser.add_argument(
        "--scan-sections",
        default=",".join(DEFAULT_SCAN_SECTIONS),
        help="comma separated section names to emit rows for",
    )
    parser.add_argument("--expect-raw-hits", type=int, default=EXPECTED_RAW_HITS)
    parser.add_argument(
        "--expect-runtime-functions",
        type=int,
        default=common.EXPECTED_RUNTIME_FUNCTIONS,
    )
    parser.add_argument("--expect-valid", type=int, default=None)
    args = parser.parse_args(argv)

    specimen = args.specimen.resolve()
    relative_specimen = specimen.relative_to(root).as_posix()
    scope_names = tuple(
        name.strip() for name in args.scan_sections.split(",") if name.strip()
    )
    if not scope_names:
        parser.error("--scan-sections needs at least one section name")

    with specimen.open("rb") as handle, mmap.mmap(
        handle.fileno(), 0, access=mmap.ACCESS_READ
    ) as view, common.load_pe(specimen) as pe:
        try:
            all_sections = common.sections(pe)
            image = RawImage(pe, view)
            table = load_runtime_function_table(pe)
            if len(table.begins) != args.expect_runtime_functions:
                raise ValueError(
                    f"runtime function count {len(table.begins)} does not match "
                    f"expected {args.expect_runtime_functions}"
                )
            resolve_sections(all_sections, scope_names)
            hits, census = scan_sections(
                pe, image, [item for item in all_sections if item.raw_size]
            )
            scope = set(scope_names)
            in_scope = [hit for hit in hits if hit.section.name in scope]
            rows, tally = build_rows(pe, image, in_scope, table)
        except ValueError as error:
            print(f"ERROR {error}")
            return 2
        finally:
            pe.close()

    raw_hits_ok = len(rows) == args.expect_raw_hits
    valid_ok = args.expect_valid is None or tally["valid_candidate"] == args.expect_valid
    written = None
    if raw_hits_ok and valid_ok:
        written = common.write_csv(args.out, rows, CSV_FIELDS)
    report(
        root,
        specimen,
        relative_specimen,
        scope_names,
        census,
        table,
        rows,
        tally,
        args.out,
        written,
        args.expect_raw_hits,
    )

    if not raw_hits_ok:
        print(
            f"ERROR raw hit count {len(rows)} does not match expected {args.expect_raw_hits}"
        )
        return 1
    if not valid_ok:
        print(
            f"ERROR valid candidate count {tally['valid_candidate']} does not match "
            f"expected {args.expect_valid}"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
