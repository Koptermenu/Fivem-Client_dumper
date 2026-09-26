"""Phase P0/S8 static syscall service number map for the adhesive.dll specimen.

Scope
-----
The specimen is only ever parsed as a file. It is never loaded, mapped for
execution, patched or run, no module is loaded and no code is executed. Every
cell of the emitted evidence is recomputed from the file image and from the phase
input csv files on each run, so the two output files are byte stable for a given
specimen and reruns are reproducible diffs. Nothing in this phase produces an
exploit, a bypass or a patch recipe, and no runtime observation is claimed.

P0/S7 (`syscall_args.py`) recorded what reaches the four syscall argument
registers and the argument stack slots at each valid `0F 05` candidate, and
deliberately left the service number and the service name alone. This phase
supplies exactly that missing half, at the same 3627 sites, and adds nothing
else: it reads the service number producer chain of RAX and decides, per site,
whether the statically visible evidence is sufficient to name an Nt/Zw service.

Inputs
------
All inputs are read; none of them is modified.

  * `reverse/evidence/syscall_candidates_raw.csv` the P0/S6 candidate census. Only
    its `valid_candidate == true` rows are in scope, which fixes the work list at
    3627 sites. The candidate rva, the raw offset and the owning
    `IMAGE_RUNTIME_FUNCTION` bounds are taken from this file and re-verified
    against the specimen bytes and against the exception directory parsed out of
    the PE, exactly as P0/S7 did, so the two phases describe the same sites.
  * `reverse/evidence/syscall_arg_inventory.csv` the P0/S7 site level record. Its
    100 columns are carried into the output of this phase unchanged, so every S7
    evidence field stays readable next to the S8 verdict. The join is a checked
    join: both files are matched on `hit_index` and on `rva`, and a site whose
    pdata bounds disagree between the two files is a hard error.
  * `reverse/evidence/cfg_functions.csv` the CFG function census, joined on
    `pdata_function_index == func_index` so the decode status of the owning
    function is re-verified rather than assumed.

Service number producer chain
-----------------------------
The chain is walked inside the `pdata`/`CFG` window of the owning site, which is
the same window definition P0/S7 used: the owning runtime function is swept
linearly from its `IMAGE_RUNTIME_FUNCTION` start in rva space, and the chain is
the region of that sweep in front of the candidate. The walk is a bounded
abstract interpretation of RAX, not a disassembly of one instruction, because in
this specimen the nearest `mov eax, imm` is the exception rather than the rule.

The value of RAX at the candidate is reduced by an ordered ladder:

  1. `mov`/`movabs` of an immediate into RAX, EAX or AX folds to a constant,
  2. `mov`, `movzx`, `movsx` and `movsxd` of a register or of memory follow the
     source to its own definition,
  3. `lea` produces a code or data address, never a service number,
  4. a foldable operation (`add`, `sub`, `xor`, `or`, `and`, `imul`, `shl`, `shr`,
     `sar`, `rol`, `ror`, `not`, `neg`, `inc`, `dec`, `bswap`, `shld`, `shrld`)
     folds when every input is a known constant, and otherwise propagates the
     informative unknown of its inputs,
  5. an instruction that writes RAX without a computable value (`rdtsc`, `cpuid`,
     `mul`, `div`, an unmodelled mnemonic) makes the chain opaque.

Two boundaries cut the walk, both inherited from P0/S7 and both recorded per
site: a `call` clobbers the volatile registers, so a definition of RAX before the
last `call` of the window is not the live value, and an unconditional jump or a
return ends the linear path, so a definition before the last one of those is not
on the path that reaches the candidate. A read-modify-write such as `xor eax, ecx`
reads the accumulator of `eax` strictly before its own instruction, so a chain
does not close on itself. A `cmov` and friends define their destination only on one
edge, so the ladder keeps P0/S7's precedence: the nearest *definite* definition
decides, and a conditional definition is consulted only when there is no definite
one, in which case the value is a merge of the destination before the instruction
and its source, and is reported as a `conditional_merge` rather than a constant.
Register copies and folded arithmetic are followed to `CHAIN_MAX_DEPTH` hops.

Symbolic unknowns
-----------------
A value that is not a constant is never guessed. Two families are treated as
symbolic unknown by rule and are named in the evidence rather than folded:

  * `KUSER_SHARED_DATA`, the read-only block at `0x7FFE0000`. An absolute operand
    in `0x7FFE0000..0x7FFF0000`, or an image slot that holds such an address, is
    reported as a `kuser_shared_data` operand and stops the fold. The value behind
    the operand is set by the kernel at run time and is not in the file, so a
    service number derived from it is not a static fact.
  * the `PEB`, reached through a `gs` segment operand, and every memory operand
    whose base register resolves to the PEB. The PEB is a run time structure, so
    a load from it is reported as a `peb` operand and stops the fold.

The same holds for a frame or stack relative operand, for a register indirect
operand, and for a code address produced by `lea`: each keeps its own kind so the
reader can see which layer of the chain went symbolic.

Naming gate
-----------
An Nt/Zw service name is written to the `nt_service` column only when both of the
following hold, and the row is `UNRESOLVED` otherwise:

  1. the producer chain folds to a *static* constant, with no `kuser_shared_data`,
     no `peb`, no memory and no register operand anywhere in it, so the service
     number itself is a fact of the file, and
  2. the argument schema of the site is sufficient for that number, which means
     the site carries a documented information class constant in the class
     position together with the buffer and length positions that class needs.

The gate is evaluated per row and its verdict is written to `nt_service`,
`nt_confidence` and `status`, so a reader never has to re-derive it. When the gate
does not fire, the service *hypothesis* that the argument schema supports is still
recorded, in `service_class`, and the constant that anchors it is recorded in
`mapping_basis`. A hypothesis is a shape label, not an identification.

Service classes
---------------
`service_class` is an ordered, first-match-wins anchor group over the P0/S7
evidence cells, so every row gets exactly one class and the partition is a
deterministic function of the inputs:

  1. `process_information_basic`                    information class constant 0,
                                                    `ProcessBasicInformation`
  2. `process_information_debug`                    information class constants 7,
                                                    0x1E and 0x1F, that is
                                                    `ProcessDebugPort`,
                                                    `ProcessDebugObjectHandle` and
                                                    `ProcessDebugFlags`
  3. `process_information_instrumentation_callback`  information class constant
                                                    0x28, that is
                                                    `ProcessInstrumentationCallback`
  4. `allocation_0x1000_0x40`                       an argument set that carries
                                                    both the 0x1000 allocation type
                                                    and the 0x40 protection
  5. `transfer_5arg`                                five resolved argument
                                                    positions with a buffer and a
                                                    length among them
  6. `wrapper_forwarding`                           all four argument registers
                                                    carry a handle the site
                                                    received from its own caller
  7. `other`                                        none of the above

The information class groups are keyed on the constant in the second argument
position, so they are anchored on a value that P0/S7 resolved statically, not on
a reading of the disassembly.

The allocation_to_write reconciliation
--------------------------------------
P0/S7 reports `signal_sites.allocation_to_write` as 0 arguments over 0 sites and
`allocation_origins.by_symbol` as empty, while the same phase classes 1534 sites
as carrying an `A3_OUT_BUF` or `A3_INOUT_BUF` argument position. Read as two
claims about the same sites that looks like a contradiction, and this phase
resolves it explicitly instead of carrying it forward:

  * `A3_OUT_BUF` is a statement about the *address* handed to the service at the
    syscall boundary. It is the residual of the class ladder for a resolved data
    address, and its direction label is not an observed store.
  * `allocation_to_write` is a *conjunction inside one 40 byte window on the
    callee side of the stub*: the value chain of the argument must terminate at
    the return value of a call whose import symbol is in the allocator set, *and*
    a store through that same resolved pointer must appear in the same window.
    Both halves are window local.
  * The first half is empty across the whole corpus, because
    `allocation_origins.by_symbol` is empty: no argument of any of the 3627 sites
    terminates at an allocator return. The conjunction is therefore 0 by
    arithmetic, not by a missed observation, and the 0 and the 1534 are two
    different quantities.
  * Where such a buffer genuinely is produced by an allocator, the write belongs to
    a different layer than the window: the allocating call sits outside the 40
    byte window, or in the caller frame, or the pointer reaches the stub by
    forwarding, through an `A6_SELF_HANDLE` entry parameter, a prologue spill, or
    a value copied down from a wrapper. Forwarding between layers moves the write
    out of the window without making it untrue.

A layer difference is therefore recorded as a scope difference and never as a
conflict. Every row that carries a buffer class with `allocation_write_arguments`
at 0 gets `alloc_write_scope=callee_window` and
`alloc_write_reconciled=forwarding_or_cross_layer` in its `mapping_basis`, and no
check of this phase treats "buffer class present and allocation write 0" as a
failure. The reconciliation is also emitted as its own block of the report, with
the counts that prove it.

Determinism
-----------
Rows are emitted in ascending raw offset order, which is the order of the P0/S7
inventory and therefore of the P0/S6 candidate census, with a fixed column order.
Both files are written through `common.write_csv` and `common.write_json` as UTF-8
without BOM and LF terminated, every result list is sorted, and no wall clock,
hostname or environment value reaches the payload. Reruns of the script on the
same inputs produce byte identical files.

Evidence
--------
`reverse/evidence/syscall_inventory.csv` holds one row per valid candidate, 3627
rows, 106 columns, and is the site level record: the 100 P0/S7 evidence columns
followed by the six P0/S8 columns this phase adds.
`reverse/evidence/syscall_service_map.json` holds the service number census, the
anchor group partition, the naming gate outcome, the allocation_to_write
reconciliation and the validation results.

`nt_service` is a supersession, not a rename: the column exists in the P0/S7
schema as well, and this phase writes the S8 verdict into that same position
rather than adding a second identically named column, which a csv reader would
collapse. The S7 assertion it replaces is `UNRESOLVED` on every row, is still
recorded per row in the preserved `nt_service_status` column, and the file it
came from is unmodified on disk.

Both files are written only when every check of the validation block passes, so a
failed invariant never replaces a good evidence file. The per row validator runs
over all 3627 rows and each row must satisfy the class domain, the producer and
naming consistency rules, the pdata bounds and the row status domain.
`--check-only` compares the stored csv with the regenerated rows cell by cell
instead of writing it. Exit status is `0` on success, `1` on a failed check and
`2` on a specimen or input structure error.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Sequence

import capstone

_SCRIPT_DIR: Final[Path] = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import common  # noqa: E402  sibling module, resolved from the script directory
import syscall_args as s7  # noqa: E402  P0/S7, the phase this one extends

SCHEMA_CSV: Final[str] = "adhesive-dumper.syscall-inventory/1"
SCHEMA_JSON: Final[str] = "adhesive-dumper.syscall-service-map/1"
PHASE: Final[str] = "P0/S8"
PREDECESSOR: Final[str] = "P0/S7"

EXPECTED_RAW_HITS: Final[int] = 3881
EXPECTED_VALID_CANDIDATES: Final[int] = 3627
EXPECTED_S7_ROWS: Final[int] = 3627
EXPECTED_S7_COLUMNS: Final[int] = 100
EXPECTED_RUNTIME_FUNCTIONS: Final[int] = common.EXPECTED_RUNTIME_FUNCTIONS

SYSCALL_PATTERN: Final[bytes] = bytes((0x0F, 0x05))
SYSCALL_MNEMONIC: Final[str] = "syscall"

S7_COLUMNS: Final[tuple[str, ...]] = s7.CSV_COLUMNS
S8_COLUMNS: Final[tuple[str, ...]] = (
    "svc_producer_rva",
    "producer_chain",
    "nt_service",
    "nt_confidence",
    "mapping_basis",
    "service_class",
    "status",
)
SUPERSEDED_COLUMNS: Final[tuple[str, ...]] = tuple(
    name for name in S8_COLUMNS if name in S7_COLUMNS
)
CSV_COLUMNS: Final[tuple[str, ...]] = S7_COLUMNS + tuple(
    name for name in S8_COLUMNS if name not in S7_COLUMNS
)

CHAIN_MAX_DEPTH: Final[int] = 10
CHAIN_CELL_ENTRIES: Final[int] = 24
MAX_EXAMPLES: Final[int] = 5
# A P0/S7 cell holds one argument's evidence. A P0/S8 basis cell holds the verdict
# of the whole site: the kind, the symbolic operand that stopped the fold, the
# service number, the anchor group, the producer rva and the reconciliation marks,
# and every one of those is read by a check or by a reader, so the budget is raised
# rather than letting the cell cut a verdict token. The shedding rule is unchanged.
CELL_LIMIT: Final[int] = 320

RAX: Final[int] = capstone.x86.X86_REG_RAX

KUSER_SHARED_DATA_LOW: Final[int] = 0x7FFE0000
KUSER_SHARED_DATA_HIGH: Final[int] = 0x7FFF0000

KIND_CONST: Final[str] = "static_constant"
KIND_KUSER: Final[str] = "kuser_shared_data"
KIND_PEB: Final[str] = "peb"
KIND_ADDRESS: Final[str] = "code_address"
KIND_MEMORY: Final[str] = "memory_indirect"
KIND_REGISTER: Final[str] = "register_undefined"
KIND_CONDITIONAL: Final[str] = "conditional_merge"
KIND_OPAQUE: Final[str] = "opaque_instruction"
KIND_UNREACHED: Final[str] = "sweep_unreached"

SERVICE_KINDS: Final[tuple[str, ...]] = (
    KIND_CONST,
    KIND_KUSER,
    KIND_PEB,
    KIND_ADDRESS,
    KIND_MEMORY,
    KIND_REGISTER,
    KIND_CONDITIONAL,
    KIND_OPAQUE,
    KIND_UNREACHED,
)
KIND_RANK: Final[dict[str, int]] = {
    KIND_KUSER: 7,
    KIND_PEB: 6,
    KIND_MEMORY: 5,
    KIND_ADDRESS: 4,
    KIND_CONDITIONAL: 3,
    KIND_REGISTER: 2,
    KIND_OPAQUE: 1,
}

NT_SERVICE_UNRESOLVED: Final[str] = "UNRESOLVED"
CONFIDENCE_NONE: Final[str] = "none"

STATUS_NAMED: Final[str] = "named"
STATUS_SYMBOLIC: Final[str] = "unresolved_symbolic_service_number"
STATUS_NO_PRODUCER: Final[str] = "unresolved_no_producer"
STATUS_SCHEMA: Final[str] = "unresolved_schema_insufficient"
STATUS_UNREACHED: Final[str] = "unresolved_sweep_unreached"
STATUSES: Final[tuple[str, ...]] = (
    STATUS_NAMED,
    STATUS_SYMBOLIC,
    STATUS_NO_PRODUCER,
    STATUS_SCHEMA,
    STATUS_UNREACHED,
)

CLASS_INFO_BASIC: Final[str] = "process_information_basic"
CLASS_INFO_DEBUG: Final[str] = "process_information_debug"
CLASS_INFO_CALLBACK: Final[str] = "process_information_instrumentation_callback"
CLASS_ALLOCATION: Final[str] = "allocation_0x1000_0x40"
CLASS_TRANSFER: Final[str] = "transfer_5arg"
CLASS_FORWARDING: Final[str] = "wrapper_forwarding"
CLASS_OTHER: Final[str] = "other"
SERVICE_CLASSES: Final[tuple[str, ...]] = (
    CLASS_INFO_BASIC,
    CLASS_INFO_DEBUG,
    CLASS_INFO_CALLBACK,
    CLASS_ALLOCATION,
    CLASS_TRANSFER,
    CLASS_FORWARDING,
    CLASS_OTHER,
)

# Documented PROCESSINFOCLASS values, used only to key the anchor groups and only
# as a hypothesis. A name is written to `nt_service` when, and only when, the
# producer chain also folds to a static service number.
INFO_CLASS_BASIC: Final[int] = 0x00
INFO_CLASS_DEBUG: Final[frozenset[int]] = frozenset({0x07, 0x1E, 0x1F})
INFO_CLASS_CALLBACK: Final[int] = 0x28
INFO_CLASS_MAX: Final[int] = 0x80

ALLOCATION_TYPE_COMMIT_RESERVE: Final[int] = 0x1000
ALLOCATION_PROTECTION_EXECUTE_READWRITE: Final[int] = 0x40

# The service hypothesis each information class anchor group carries. Reached
# only through the naming gate; the group label itself is the recorded output when
# the gate does not fire.
SERVICE_HYPOTHESIS: Final[dict[str, str]] = {
    CLASS_INFO_BASIC: "NtQueryInformationProcess",
    CLASS_INFO_DEBUG: "NtQueryInformationProcess",
    CLASS_INFO_CALLBACK: "NtSetInformationProcess",
}

ALLOC_WRITE_SCOPE: Final[str] = "alloc_write_scope=window"
ALLOC_WRITE_RECONCILED: Final[str] = "alloc_write=forwarded_or_cross_layer"

FOLD_EXTRA: Final[frozenset[str]] = frozenset({"shld", "shrld"})
UNARY_FOLD: Final[frozenset[str]] = frozenset({"not", "neg", "inc", "dec", "bswap"})
OPAQUE_MNEMONICS: Final[frozenset[str]] = frozenset(
    {
        "aesdec", "aesenc", "aesimc", "cpuid", "in", "ins", "out", "outs", "pause",
        "rdmsr", "rdpmc", "rdrand", "rdseed", "syscall", "sysenter", "sysexit",
        "sysret", "wrmsr", "xgetbv", "rdtsc", "rdtscp", "div", "idiv", "mul",
    }
)
CLOBBER_MNEMONICS: Final[frozenset[str]] = frozenset(
    {"call", "ret", "retf", "iretq", "leave", "int", "syscall", "int3"}
)

RESOLVED_ARGUMENT_CLASSES: Final[frozenset[str]] = frozenset(
    {
        s7.CLASS_A1,
        s7.CLASS_A2,
        s7.CLASS_A3_OUT,
        s7.CLASS_A3_INOUT,
        s7.CLASS_A4,
        s7.CLASS_A6,
        s7.CLASS_A7,
    }
)
BUFFER_CLASSES: Final[frozenset[str]] = s7.BUFFER_CLASSES
HANDLE_CLASSES: Final[frozenset[str]] = frozenset(
    {s7.CLASS_A1, s7.CLASS_A6, s7.CLASS_A7}
)

SERVICE_CLASS_RULES: Final[dict[str, str]] = {
    CLASS_INFO_BASIC: (
        f"argument 2 is a statically resolved constant 0x{INFO_CLASS_BASIC:02X}, the "
        "ProcessBasicInformation value, and arguments 3 or 4 carry the buffer or the "
        "length that class needs"
    ),
    CLASS_INFO_DEBUG: (
        "argument 2 is a statically resolved constant out of "
        f"{', '.join(f'0x{value:02X}' for value in sorted(INFO_CLASS_DEBUG))}, that is "
        "ProcessDebugPort, ProcessDebugObjectHandle and ProcessDebugFlags, and arguments "
        "3 or 4 carry the buffer or the length that class needs"
    ),
    CLASS_INFO_CALLBACK: (
        f"argument 2 is a statically resolved constant 0x{INFO_CLASS_CALLBACK:02X}, the "
        "ProcessInstrumentationCallback value, and arguments 3 or 4 carry the buffer or "
        "the length that class needs"
    ),
    CLASS_ALLOCATION: (
        f"the argument set carries both 0x{ALLOCATION_TYPE_COMMIT_RESERVE:X}, an "
        "allocation type, and "
        f"0x{ALLOCATION_PROTECTION_EXECUTE_READWRITE:02X}, a page protection"
    ),
    CLASS_TRANSFER: (
        "all five enumerated argument positions resolve to a class other than unknown "
        "or stack slot, and at least one of them is a buffer and at least one is a "
        "length"
    ),
    CLASS_FORWARDING: (
        "all four argument register positions are a handle the site received from its "
        "own caller, so the argument schema belongs to the calling layer"
    ),
    CLASS_OTHER: "no anchor of the groups above fires",
}

RECONCILIATION: Final[dict[str, str]] = {
    "observed": (
        "P0/S7 publishes signal_sites.allocation_to_write as 0 arguments over 0 sites "
        "and allocation_origins.by_symbol as empty, while the same phase classes 1534 "
        "sites as carrying an A3_OUT_BUF or A3_INOUT_BUF argument position"
    ),
    "not_a_contradiction": (
        "the two numbers are different quantities: A3_OUT_BUF classifies the address "
        "handed to the service at the syscall boundary, and allocation_to_write is a "
        "conjunction of an allocator return value in the value chain and an observed "
        "store through that same pointer, both of them window local"
    ),
    "why_zero_is_forced": (
        "allocation_origins.by_symbol is empty across the whole corpus, so no argument "
        "of any of the 3627 sites terminates at an allocator return; the conjunction is "
        "zero by arithmetic and not by a missed observation"
    ),
    "forwarding_is_not_a_conflict": (
        "where such a buffer is produced by an allocator, the write belongs to another "
        "layer: the allocating call is outside the 40 byte window, or in the caller "
        "frame, or the pointer reaches the stub by forwarding through an A6_SELF_HANDLE "
        "entry parameter, a prologue spill or a value copied down from a wrapper; "
        "forwarding between layers moves the write out of the window without making it "
        "untrue, so it is recorded as a scope difference"
    ),
    "per_row_marking": (
        f"a row that carries a buffer class with allocation_write_arguments at 0 gets "
        f"{ALLOC_WRITE_SCOPE} and {ALLOC_WRITE_RECONCILED} in mapping_basis"
    ),
    "validation_rule": (
        "no check of this phase treats a buffer class together with "
        "allocation_write_arguments at 0 as a failure"
    ),
}

LIMITATIONS: Final[tuple[str, ...]] = (
    "The specimen is parsed as a file only: nothing is loaded, mapped for execution, "
    "patched or run, so no observation here is a runtime observation.",
    "This phase produces no exploit, no bypass and no patch recipe, and no cell of the "
    "evidence is intended as one.",
    "A service number is read from the RAX producer chain only. A dispatcher that "
    "computes the number in a callee and returns it, or that indexes a table built at "
    "run time, is not followed, so a service number a stub obtains that way stays "
    "unresolved here.",
    "KUSER_SHARED_DATA and PEB reads are symbolic unknown by rule. Their runtime values "
    "are not in the file, so a service number derived from either is not a static fact "
    "and no name is written for it.",
    "A frame or stack relative operand, a register indirect operand and a code address "
    "produced by lea are kept as distinct kinds, and each of them also blocks a name. A "
    "buffer the site hands on from its own caller is therefore described by the schema "
    "of the calling layer, which the anchor groups label rather than resolve.",
    "The chain walk is linear and bounded. A definition that leaves a register through a "
    "branch outside the window, or a chain deeper than CHAIN_MAX_DEPTH hops, is reported "
    "as a register or opaque kind and is not claimed to be complete.",
    "The [RSP + 0x28] anchor of the first stack argument is a P0/S7 property of the call "
    "site, not of the candidate, and the P0/S7 limitations of the argument window carry "
    "over unchanged to the schema this phase reads from it.",
    "The information class values that key the anchor groups are the documented public "
    "PROCESSINFOCLASS values. They are used as constants to group sites, and a group "
    "label is a hypothesis about a shape, not an identification of the service reached.",
    "A file value read through a global slot is the value with the DIR64 fixups of the "
    "relocation table applied, which models a load at the preferred base. A slot another "
    "module or a runtime initialiser overwrites after load is not seen.",
)


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #


def _hex(value: int) -> str:
    return common.hexs(value)


def _join(parts: Sequence[str]) -> str:
    return "; ".join(part for part in parts if part)


def _cell(text: str) -> str:
    return text if len(text) <= CELL_LIMIT else text[: CELL_LIMIT - 3] + "..."


def _shift_amount(op_str: str) -> int | None:
    tail = op_str.partition(",")[2].strip()
    if not tail:
        return 1
    try:
        return int(tail, 0)
    except ValueError:
        return None


def _fold_shift_pair(
    mnemonic: str, op_str: str, left: int, right: int, size: int
) -> int | None:
    """Fold `shld`/`shrld`, which `s7.apply_operation` does not model."""
    bits = size * 8
    amount = _shift_amount(op_str)
    if amount is None or right is None:
        return None
    amount %= bits
    if amount == 0:
        return left
    mask = (1 << bits) - 1
    if mnemonic == "shld":
        return ((left << amount) | (right >> (bits - amount))) & mask
    return ((left >> amount) | (right << (bits - amount))) & mask


def _sorted_counts(counter: Counter[str]) -> dict[str, int]:
    return {name: counter[name] for name in sorted(counter)}


# --------------------------------------------------------------------------- #
# specimen view and phase inputs
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class CandidateRef:
    """One accepted P0/S6 candidate, as the candidate census records it."""

    hit_index: int
    raw: int
    rva: int
    pdata_index: int
    function_begin: int
    function_end: int


@dataclass(frozen=True, slots=True)
class SiteRef:
    """One accepted P0/S6 candidate, joined onto its P0/S7 inventory row."""

    hit_index: int
    raw: int
    rva: int
    pdata_index: int
    function_begin: int
    function_end: int
    inventory: dict[str, str]


@dataclass(frozen=True, slots=True)
class PhaseInputs:
    """The three read only input files of the phase."""

    sites: tuple[SiteRef, ...]
    raw_rows: int
    runtime_functions: int
    cfg_rows: int
    inventory_rows: int
    s7_columns: int
    digests: dict[str, str]


def read_csv(path: Path) -> tuple[list[dict[str, str]], tuple[str, ...]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        header = tuple(reader.fieldnames or ())
        return [dict(row) for row in reader], header


def load_inputs(
    image: s7.Image,
    candidates_path: Path,
    inventory_path: Path,
    cfg_path: Path,
) -> PhaseInputs:
    """Read the phase inputs and verify the joins against the specimen."""
    raw_rows, raw_header = read_csv(candidates_path)
    missing = [name for name in s7.CANDIDATE_COLUMNS if name not in raw_header]
    if missing:
        raise ValueError(f"{candidates_path.name} lacks column(s): {', '.join(missing)}")

    pdata = s7.load_runtime_functions(image)
    candidates: dict[int, CandidateRef] = {}
    for row in raw_rows:
        if row["valid_candidate"] != "true":
            continue
        index = int(row["pdata_function_index"])
        begin = int(row["pdata_function_start_rva_hex"], 16)
        end = int(row["pdata_function_end_rva_hex"], 16)
        if pdata[index] != (begin, end):
            raise ValueError(
                f"candidate hit {row['hit_index']} runtime function bounds disagree "
                f"with exception directory record {index}"
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
        candidates[int(row["hit_index"])] = CandidateRef(
            hit_index=int(row["hit_index"]),
            raw=int(row["raw_offset"]),
            rva=rva,
            pdata_index=index,
            function_begin=begin,
            function_end=end,
        )

    inventory, inventory_header = read_csv(inventory_path)
    if not inventory_header:
        raise ValueError(f"{inventory_path.name} has no header")
    if len(inventory) != len(candidates):
        raise ValueError(
            f"{inventory_path.name} has {len(inventory)} rows, the candidate census has "
            f"{len(candidates)} valid sites"
        )
    needed = (
        "hit_index",
        "rva_hex",
        "pdata_function_index",
        "pdata_function_start_rva_hex",
        "pdata_function_end_rva_hex",
        "cfg_decode_status",
        "site_signature",
        "allocation_write_arguments",
    ) + tuple(
        f"arg{position}_{suffix}" for position in range(1, s7.ARGUMENT_POSITIONS + 1)
        for suffix in ("class", "const")
    )
    absent = [name for name in needed if name not in inventory_header]
    if absent:
        raise ValueError(
            f"{inventory_path.name} lacks column(s): {', '.join(absent)}"
        )

    cfg_rows, cfg_header = read_csv(cfg_path)
    for name in ("func_index", "begin_rva", "end_rva", "decode_status"):
        if name not in cfg_header:
            raise ValueError(f"{cfg_path.name} lacks a {name} column")
    cfg = {
        int(row["func_index"]): (int(row["begin_rva"]), int(row["end_rva"]), row["decode_status"])
        for row in cfg_rows
    }

    sites: list[SiteRef] = []
    for row in inventory:
        hit_index = int(row["hit_index"])
        if hit_index not in candidates:
            raise ValueError(
                f"{inventory_path.name} hit {hit_index} is not a valid P0/S6 candidate"
            )
        candidate = candidates[hit_index]
        if int(row["rva_hex"], 16) != candidate.rva:
            raise ValueError(
                f"{inventory_path.name} hit {hit_index} rva disagrees with the candidate census"
            )
        if int(row["pdata_function_index"]) != candidate.pdata_index:
            raise ValueError(
                f"{inventory_path.name} hit {hit_index} pdata index disagrees with the "
                "candidate census"
            )
        if (
            int(row["pdata_function_start_rva_hex"], 16) != candidate.function_begin
            or int(row["pdata_function_end_rva_hex"], 16) != candidate.function_end
        ):
            raise ValueError(
                f"{inventory_path.name} hit {hit_index} pdata bounds disagree with the "
                "candidate census"
            )
        cfg_begin, cfg_end, _ = cfg.get(candidate.pdata_index, (-1, -1, ""))
        if (cfg_begin, cfg_end) != (candidate.function_begin, candidate.function_end):
            raise ValueError(
                f"{inventory_path.name} hit {hit_index} pdata bounds disagree with the "
                f"CFG census record {candidate.pdata_index}"
            )
        sites.append(
            SiteRef(
                hit_index=hit_index,
                raw=candidate.raw,
                rva=candidate.rva,
                pdata_index=candidate.pdata_index,
                function_begin=candidate.function_begin,
                function_end=candidate.function_end,
                inventory=row,
            )
        )
    sites.sort(key=lambda item: item.raw)

    return PhaseInputs(
        sites=tuple(sites),
        raw_rows=len(raw_rows),
        runtime_functions=len(pdata),
        cfg_rows=len(cfg_rows),
        inventory_rows=len(inventory),
        s7_columns=len(inventory_header),
        digests={
            "syscall_candidates_raw.csv": common.sha256_file(candidates_path),
            "syscall_arg_inventory.csv": common.sha256_file(inventory_path),
            "cfg_functions.csv": common.sha256_file(cfg_path),
        },
    )


# --------------------------------------------------------------------------- #
# RAX producer chain
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Value:
    """One abstract value of the RAX chain."""

    kind: str
    const: int | None
    chain: tuple[str, ...]


def propagate(here: str, parts: Sequence[Value]) -> Value:
    """Reduce operand values of one operation to a single value.

    When every input is a known constant the caller folds the operation. Here at
    least one input is not, so the informative unknown of the inputs is what the
    operation produces, and the chain records where each input came from.
    """
    unknown = [part for part in parts if part.kind != KIND_CONST]
    if not unknown:
        return Value(KIND_CONST, None, (here,))
    best = max(unknown, key=lambda part: KIND_RANK.get(part.kind, 0))
    chain: list[str] = [here]
    for part in parts:
        chain.extend(part.chain)
    return Value(best.kind, None, tuple(chain))


class FunctionSweep:
    """The linear decode of one owning runtime function, up to its last site.

    The writes of every instruction and the two walk boundaries, the last `call`
    and the last flow break, are tabulated once per function as prefix arrays so
    the per candidate lookups are constant time. The sweep start is the
    `IMAGE_RUNTIME_FUNCTION` begin, which is the same linear channel P0/S6 used to
    accept the candidate and the same one P0/S7 swept.
    """

    def __init__(
        self, disassembler: capstone.Cs, image: s7.Image, begin: int, last: int
    ) -> None:
        self.insns: tuple[capstone.CsInsn, ...] = tuple(
            disassembler.disasm(image.at_rva(begin, last - begin), begin)
        )
        self.ends: tuple[int, ...] = tuple(
            insn.address + insn.size for insn in self.insns
        )
        self.writes: tuple[frozenset[int], ...] = tuple(
            self._written(insn) for insn in self.insns
        )
        self.conditional: tuple[bool, ...] = tuple(
            insn.mnemonic in s7.CONDITIONAL_MNEMONICS for insn in self.insns
        )
        self.last_call: tuple[int, ...] = self._prefix(frozenset({"call"}))
        self.last_flow: tuple[int, ...] = self._prefix(s7.FLOW_BREAK_MNEMONICS)

    def _written(self, insn: capstone.CsInsn) -> frozenset[int]:
        out: set[int] = set()
        for operand in insn.operands:
            if (
                operand.type == capstone.x86.X86_OP_REG
                and operand.access & capstone.CS_AC_WRITE
            ):
                out.add(s7.full_register(operand.reg))
        for register in s7.IMPLICIT_WRITE_TABLES.get(insn.mnemonic, ()):
            out.add(register)
        if insn.mnemonic == "imul" and insn.operands:
            first = insn.operands[0]
            if first.type == capstone.x86.X86_OP_REG:
                out.add(s7.full_register(first.reg))
        if insn.mnemonic in CLOBBER_MNEMONICS:
            out |= s7.VOLATILE_REGISTERS
        return frozenset(out)

    def _prefix(self, mnemonics: frozenset[str]) -> tuple[int, ...]:
        found: list[int] = []
        last = -1
        for insn in self.insns:
            if insn.mnemonic in mnemonics:
                last = len(found)
            found.append(last)
        return tuple(found)

    def reached(self, rva: int) -> tuple[int, bool]:
        """Number of swept instructions before `rva`, and whether it ended on one."""
        limit = bisect.bisect_right(self.ends, rva)
        return limit, limit > 0 and self.ends[limit - 1] == rva


class Resolver:
    """Bounded abstract interpretation of RAX at one candidate."""

    def __init__(
        self, image: s7.Image, sweep: FunctionSweep, limit: int
    ) -> None:
        self.image = image
        self.sweep = sweep
        self.limit = limit
        self.floor_call = sweep.last_call[limit - 1] if limit else -1
        self.floor_flow = sweep.last_flow[limit - 1] if limit else -1
        self._cache: dict[tuple[int, int, int], Value] = {}

    def resolve(self, register: int, depth: int, before: int) -> Value:
        if depth > CHAIN_MAX_DEPTH:
            return Value(
                KIND_REGISTER,
                None,
                (f"depth_limit:{s7.register_name(register)}",),
            )
        key = (register, depth, before)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        floor = self.floor_call if register in s7.VOLATILE_REGISTERS else -1
        if self.floor_flow > floor:
            floor = self.floor_flow
        limit = min(before, self.limit)
        index = -1
        for position in range(limit - 1, floor, -1):
            if register in self.sweep.writes[position] and not self.sweep.conditional[position]:
                index = position
                break
        if index >= 0:
            value = self.apply(self.sweep.insns[index], index, depth)
            self._cache[key] = value
            return value
        for position in range(limit - 1, floor, -1):
            if register in self.sweep.writes[position] and self.sweep.conditional[position]:
                index = position
                break
        if index >= 0:
            value = self.merge(self.sweep.insns[index], index, depth)
            self._cache[key] = value
            return value
        value = Value(
            KIND_REGISTER, None, (f"no_live_def:{s7.register_name(register)}",)
        )
        self._cache[key] = value
        return value

    def merge(self, insn: capstone.CsInsn, index: int, depth: int) -> Value:
        """The value of a register a `cmov` and friends may or may not have written.

        A conditional move leaves the destination alone on the untaken edge, so the
        value on the path that reaches the candidate is a merge of the destination
        before the instruction and its source. Both are resolved so the merge
        names where either edge came from, and the merge itself is not a constant.
        """
        operands = insn.operands
        parts: list[Value] = []
        if operands and operands[0].type == capstone.x86.X86_OP_REG:
            parts.append(self.prior(operands[0], depth, index))
        for operand in operands[1:]:
            parts.append(self.operand(operand, depth, index))
        if not parts:
            return Value(KIND_CONDITIONAL, None, (f"conditional:{insn.mnemonic}",))
        return propagate(f"conditional:{insn.mnemonic}@{_hex(insn.address)}", parts)

    def apply(self, insn: capstone.CsInsn, index: int, depth: int) -> Value:
        mnemonic = insn.mnemonic
        here = f"{mnemonic}@{_hex(insn.address)}"
        operands = insn.operands
        if mnemonic in OPAQUE_MNEMONICS or mnemonic in s7.IMPLICIT_WRITE_TABLES:
            return Value(KIND_OPAQUE, None, (f"opaque:{here}",))
        if mnemonic in ("mov", "movabs") and len(operands) == 2:
            source = operands[1]
            if source.type == capstone.x86.X86_OP_IMM:
                folded = s7._wrap64(source.imm, operands[0].size)
                return Value(KIND_CONST, folded, (f"{here}={_hex(folded)}",))
            return self.tag(self.operand(source, depth, index), here)
        if mnemonic in ("movzx", "movsx", "movsxd") and len(operands) == 2:
            source = self.operand(operands[1], depth, index)
            if source.kind == KIND_CONST and source.const is not None:
                folded = s7._wrap64(source.const, operands[0].size)
                return Value(KIND_CONST, folded, (f"{here}={_hex(folded)}",))
            return self.tag(source, here)
        if (
            mnemonic == "lea"
            and len(operands) == 2
            and operands[1].type == capstone.x86.X86_OP_MEM
        ):
            return Value(KIND_ADDRESS, None, (f"address:{here}",))
        if mnemonic in s7.FOLDABLE_MNEMONICS or mnemonic in FOLD_EXTRA:
            inputs = self.fold_inputs(mnemonic, operands, depth, index)
            if inputs and all(part.kind == KIND_CONST for part in inputs):
                left = inputs[0].const
                right = inputs[1].const if len(inputs) > 1 else None
                folded = (
                    _fold_shift_pair(mnemonic, insn.op_str, left, right, operands[0].size)
                    if mnemonic in FOLD_EXTRA
                    else s7.apply_operation(mnemonic, insn.op_str, left, right)
                )
                if folded is None:
                    return Value(KIND_OPAQUE, None, (f"unfolded:{here}",))
                wrapped = s7._wrap64(folded, operands[0].size)
                return Value(
                    KIND_CONST, wrapped, (f"{mnemonic}@{_hex(insn.address)}={_hex(wrapped)}",)
                )
            if not inputs:
                return Value(KIND_OPAQUE, None, (f"unmodelled:{here}",))
            return propagate(here, inputs)
        return Value(KIND_OPAQUE, None, (f"unmodelled:{here}",))

    def fold_inputs(
        self,
        mnemonic: str,
        operands: Sequence[Any],
        depth: int,
        index: int,
    ) -> list[Value]:
        """Input values of one foldable operation.

        A read-modify-write destination is the accumulator of the operation, so its
        value is the one it holds strictly before its own instruction. Reading it
        at the instruction itself would close the chain on itself.
        """
        if not operands:
            return []
        if mnemonic in UNARY_FOLD and len(operands) == 1:
            return [self.prior(operands[0], depth, index)]
        if mnemonic == "imul" and len(operands) == 3:
            return [
                self.operand(operands[1], depth, index),
                self.operand(operands[2], depth, index),
            ]
        inputs: list[Value] = []
        if operands[0].type == capstone.x86.X86_OP_REG:
            inputs.append(self.prior(operands[0], depth, index))
        for operand in operands[1:]:
            inputs.append(self.operand(operand, depth, index))
        return inputs

    def prior(self, operand: Any, depth: int, index: int) -> Value:
        return self.resolve(s7.full_register(operand.reg), depth + 1, index)

    def tag(self, value: Value, here: str) -> Value:
        if value.kind == KIND_CONST:
            return value
        return Value(value.kind, None, (here,) + value.chain)

    def operand(self, operand: Any, depth: int, index: int) -> Value:
        if operand.type == capstone.x86.X86_OP_IMM:
            return Value(KIND_CONST, operand.imm, ())
        if operand.type == capstone.x86.X86_OP_REG:
            return self.resolve(s7.full_register(operand.reg), depth + 1, index)
        if operand.type == capstone.x86.X86_OP_MEM:
            return self.memory(operand, depth, index)
        return Value(KIND_OPAQUE, None, ("non_register_operand",))

    def memory(self, operand: Any, depth: int, index: int) -> Value:
        memory = operand.mem
        if memory.segment == capstone.x86.X86_REG_GS:
            return Value(
                KIND_PEB, None, (f"peb_gs_disp_0x{memory.disp & 0xFFFFFFFFFFFFFFFF:X}",)
            )
        if memory.base == 0 and memory.index == 0:
            address = memory.disp
            if KUSER_SHARED_DATA_LOW <= address < KUSER_SHARED_DATA_HIGH:
                return Value(KIND_KUSER, None, (f"kuser_shared_data_0x{address:X}",))
            slot = self.image.qword_va(address)
            if slot is not None:
                if KUSER_SHARED_DATA_LOW <= slot < KUSER_SHARED_DATA_HIGH:
                    return Value(
                        KIND_KUSER, None, (f"kuser_shared_data_via_slot_0x{address:X}",)
                    )
                return Value(KIND_CONST, slot, (f"image_slot_0x{address:X}",))
            return Value(KIND_MEMORY, None, (f"absolute_0x{address:X}",))
        if memory.base == capstone.x86.X86_REG_RIP and memory.index == 0:
            insn = self.sweep.insns[index]
            target = insn.address + insn.size + memory.disp
            slot = self.image.qword_va(self.image.image_base + target)
            if slot is None:
                return Value(KIND_MEMORY, None, (f"rip_relative_0x{target:X}",))
            if KUSER_SHARED_DATA_LOW <= slot < KUSER_SHARED_DATA_HIGH:
                return Value(KIND_KUSER, None, (f"kuser_shared_data_via_slot_0x{target:X}",))
            return Value(KIND_CONST, slot, (f"image_slot_0x{target:X}",))
        base = s7.full_register(memory.base) if memory.base else 0
        if base:
            resolved = self.resolve(base, depth + 1, index)
            if resolved.kind in (KIND_KUSER, KIND_PEB):
                displacement = memory.disp
                sign = "+0x%X" % displacement if displacement >= 0 else "-0x%X" % -displacement
                return Value(
                    resolved.kind,
                    None,
                    resolved.chain + (f"{resolved.kind}_base{sign}",),
                )
        if memory.index:
            return Value(KIND_MEMORY, None, ("scaled_index_operand",))
        return Value(
            KIND_MEMORY, None, (f"register_indirect_{s7.register_name(base)}",)
        )


@dataclass(frozen=True, slots=True)
class SiteFacts:
    """The service level facts of one candidate."""

    site: SiteRef
    producer_rva: int | None
    producer_text: str
    kind: str
    const: int | None
    chain: tuple[str, ...]
    reached: bool
    sweep_instructions: int


def analyse(
    image: s7.Image, inputs: PhaseInputs
) -> tuple[list[SiteFacts], Counter[str]]:
    """Resolve the RAX producer chain of every candidate, in raw offset order."""
    disassembler = s7.make_disassembler(detail=True)
    by_function: dict[int, list[SiteRef]] = {}
    for site in inputs.sites:
        by_function.setdefault(site.function_begin, []).append(site)

    tally: Counter[str] = Counter()
    facts: list[SiteFacts] = []
    for begin in sorted(by_function):
        group = sorted(by_function[begin], key=lambda item: item.raw)
        sweep = FunctionSweep(disassembler, image, begin, group[-1].rva)
        for site in group:
            limit, reached = sweep.reached(site.rva)
            tally["reached"] += int(reached)
            if not reached:
                facts.append(
                    SiteFacts(
                        site=site,
                        producer_rva=None,
                        producer_text="",
                        kind=KIND_UNREACHED,
                        const=None,
                        chain=(),
                        reached=False,
                        sweep_instructions=limit,
                    )
                )
                continue
            resolver = Resolver(image, sweep, limit)
            value = resolver.resolve(RAX, 0, limit)
            index = producer_index(sweep, limit)
            tally["static_service_number"] += int(value.kind == KIND_CONST)
            facts.append(
                SiteFacts(
                    site=site,
                    producer_rva=(sweep.insns[index].address if index is not None else None),
                    producer_text=(s7._insn_text(sweep.insns[index]) if index is not None else ""),
                    kind=value.kind,
                    const=value.const if value.kind == KIND_CONST else None,
                    chain=value.chain,
                    reached=True,
                    sweep_instructions=limit,
                )
            )
    facts.sort(key=lambda item: item.site.raw)
    return facts, tally


def producer_index(sweep: FunctionSweep, limit: int) -> int | None:
    """Index of the instruction that last defines RAX on the path to the candidate.

    This is the near boundary of the chain: it is the same walk the resolver does,
    with the same call and flow-break floors, so the reported producer rva is the
    instruction the chain starts from and can never disagree with it.
    """
    floor = max(
        sweep.last_call[limit - 1] if limit else -1,
        sweep.last_flow[limit - 1] if limit else -1,
    )
    for position in range(limit - 1, floor, -1):
        if RAX in sweep.writes[position]:
            return position
    return None


# --------------------------------------------------------------------------- #
# anchor groups and the naming gate
# --------------------------------------------------------------------------- #


def argument_class(row: dict[str, str], position: int) -> str:
    return row[f"arg{position}_class"]


def argument_const(row: dict[str, str], position: int) -> int | None:
    cell = row[f"arg{position}_const"]
    return int(cell, 16) if cell else None


def information_class(row: dict[str, str]) -> int | None:
    """The information class constant of a site with the class argument shape."""
    if argument_class(row, 2) != s7.CLASS_A2:
        return None
    value = argument_const(row, 2)
    if value is None or not 0 <= value < INFO_CLASS_MAX:
        return None
    if argument_class(row, 1) not in HANDLE_CLASSES:
        return None
    informative = BUFFER_CLASSES | {s7.CLASS_A4}
    if not any(argument_class(row, position) in informative for position in (3, 4)):
        return None
    return value


def service_class(row: dict[str, str]) -> tuple[str, str]:
    """The anchor group of a site and the anchor that fired.

    The groups are evaluated in a fixed order and the first one that fires
    decides, so the partition is a deterministic function of the S7 cells.
    """
    value = information_class(row)
    if value == INFO_CLASS_BASIC:
        return CLASS_INFO_BASIC, f"information_class_0x{value:02X}"
    if value in INFO_CLASS_DEBUG:
        return CLASS_INFO_DEBUG, f"information_class_0x{value:02X}"
    if value == INFO_CLASS_CALLBACK:
        return CLASS_INFO_CALLBACK, f"information_class_0x{value:02X}"
    constants = {
        argument_const(row, position)
        for position in range(1, s7.ARGUMENT_POSITIONS + 1)
    }
    constants.discard(None)
    if {
        ALLOCATION_TYPE_COMMIT_RESERVE,
        ALLOCATION_PROTECTION_EXECUTE_READWRITE,
    } <= constants:
        return CLASS_ALLOCATION, "constants_0x1000_and_0x40"
    if all(
        argument_class(row, position) in RESOLVED_ARGUMENT_CLASSES
        for position in range(1, 6)
    ) and any(
        argument_class(row, position) in BUFFER_CLASSES for position in range(1, 6)
    ) and any(
        argument_class(row, position) == s7.CLASS_A4 for position in range(1, 6)
    ):
        return CLASS_TRANSFER, "five_resolved_buffer_and_length"
    if all(argument_class(row, position) == s7.CLASS_A6 for position in range(1, 5)):
        return CLASS_FORWARDING, "four_entry_parameters_forwarded"
    return CLASS_OTHER, "no_anchor"


def buffer_positions(row: dict[str, str]) -> int:
    return sum(
        1
        for position in range(1, s7.ARGUMENT_POSITIONS + 1)
        if argument_class(row, position) in BUFFER_CLASSES
    )


def naming_gate(facts: SiteFacts, group: str) -> tuple[str, str, str]:
    """The `nt_service`, `nt_confidence` and `status` of one site.

    A name is written only when the producer chain folds to a static constant and
    the argument schema is sufficient for it. The schema sufficiency is the
    anchor group, because the groups are keyed on a statically resolved constant
    the class needs; the hypothesis behind a group is `SERVICE_HYPOTHESIS`.
    """
    if facts.kind == KIND_UNREACHED:
        return NT_SERVICE_UNRESOLVED, CONFIDENCE_NONE, STATUS_UNREACHED
    if facts.kind == KIND_REGISTER and facts.producer_rva is None:
        return NT_SERVICE_UNRESOLVED, CONFIDENCE_NONE, STATUS_NO_PRODUCER
    if facts.kind != KIND_CONST:
        return NT_SERVICE_UNRESOLVED, CONFIDENCE_NONE, STATUS_SYMBOLIC
    hypothesis = SERVICE_HYPOTHESIS.get(group)
    if hypothesis is None:
        return NT_SERVICE_UNRESOLVED, CONFIDENCE_NONE, STATUS_SCHEMA
    return hypothesis, "static_constant_schema_sufficient", STATUS_NAMED


def compact_signature(row: dict[str, str]) -> str:
    """The P0/S7 site signature with the class names shortened to their prefix.

    The full signature stays readable in its own preserved column, so the basis
    cell only needs a compact echo of it, and the tokens that decide the verdict
    are the ones that survive the cell length limit.
    """
    return "+".join(
        argument_class(row, position).split("_", 1)[0]
        for position in range(1, s7.ARGUMENT_POSITIONS + 1)
    )


@dataclass(frozen=True, slots=True)
class BasisToken:
    """One `key=value` token of a basis cell and whether it may be dropped.

    A validator reads the reconciliation marks out of this cell, so a token that
    carries a verdict is never dropped. The descriptive tokens are dropped in a
    fixed order when the cell would otherwise overflow, which keeps every basis
    cell a complete list of tokens instead of a token list cut in the middle.
    """

    text: str
    droppable: bool


def basis_cell(tokens: Sequence[BasisToken]) -> str:
    """Join basis tokens in declaration order, shedding droppable ones from the tail.

    The required tokens are kept whatever the length, so the cell stays a
    complete list of the tokens that decide the verdict. A cell that overflows
    even without its droppable tokens is truncated and ends in an ellipsis, which
    the row validator reports rather than accepts silently.
    """
    kept = list(tokens)
    while True:
        text = _join(token.text for token in kept)
        if len(text) <= CELL_LIMIT:
            return text
        droppable = [index for index, token in enumerate(kept) if token.droppable]
        if not droppable:
            return _cell(text)
        del kept[droppable[-1]]


SYMBOLIC_ORIGIN_PREFIXES: Final[tuple[str, ...]] = (
    "kuser_shared_data",
    "peb_gs_disp",
    f"{KIND_KUSER}_base",
    f"{KIND_PEB}_base",
)


def symbolic_origin(facts: SiteFacts) -> str:
    """The first symbolic operand of the chain, the reason it is not a number.

    A KUSER_SHARED_DATA or a PEB read has no value in the file, so the chain stops
    there. Naming the operand in the verdict cell is what makes the row auditable
    without re-walking the chain.
    """
    for entry in facts.chain:
        for prefix in SYMBOLIC_ORIGIN_PREFIXES:
            if entry.startswith(prefix):
                return entry
    return ""


def mapping_basis(facts: SiteFacts, group: str, anchor: str) -> str:
    """The reason cell of one row: the verdict fields first, the echo last."""
    row = facts.site.inventory
    tokens: list[BasisToken] = [BasisToken(f"svc_kind={facts.kind}", False)]
    origin = symbolic_origin(facts)
    if origin:
        tokens.append(BasisToken(f"symbolic_operand={origin}", False))
    if facts.kind == KIND_CONST and facts.const is not None:
        tokens.append(BasisToken(f"service_number=0x{facts.const:X}", False))
    tokens.append(BasisToken(f"class={group}", False))
    tokens.append(BasisToken(f"anchor={anchor}", False))
    if not facts.reached:
        tokens.append(BasisToken("producer=window_unavailable", False))
    elif facts.producer_rva is None:
        tokens.append(BasisToken("producer=none", False))
    else:
        tokens.append(BasisToken(f"producer={_hex(facts.producer_rva)}", False))
        tokens.append(BasisToken(f"producer_text={facts.producer_text}", True))
    observed = int(row["allocation_write_arguments"])
    if buffer_positions(row) and not observed:
        tokens.append(BasisToken(ALLOC_WRITE_SCOPE, False))
        tokens.append(BasisToken(ALLOC_WRITE_RECONCILED, False))
    elif observed:
        tokens.append(BasisToken("alloc_write=observed_in_window", False))
    tokens.append(BasisToken(f"schema={compact_signature(row)}", True))
    return basis_cell(tokens)


def chain_cell(facts: SiteFacts) -> str:
    """The producer chain, de-duplicated in the order the walk visited it."""
    seen: set[str] = set()
    ordered: list[str] = []
    for entry in facts.chain:
        if entry not in seen:
            seen.add(entry)
            ordered.append(entry)
    if not ordered:
        return ""
    head = ordered[:CHAIN_CELL_ENTRIES]
    if facts.const is not None:
        head.insert(0, f"service_number=0x{facts.const:X}")
    text = " <- ".join(head)
    if len(ordered) > CHAIN_CELL_ENTRIES:
        text += f" <- +{len(ordered) - CHAIN_CELL_ENTRIES}_more"
    return _cell(text)


@dataclass(frozen=True, slots=True)
class Derivation:
    """The service level verdict of one site, kept structured for the report.

    The report and the validators read these fields instead of re-parsing the csv
    cells, so no count can drift from the row it describes.
    """

    group: str
    anchor: str
    service: str
    confidence: str
    status: str
    kind: str
    service_number: str
    buffer_positions: int
    allocation_writes: int
    basis: str


def derive(facts: SiteFacts) -> Derivation:
    """The anchor group, the naming gate verdict and the basis cell of one site."""
    row = facts.site.inventory
    group, anchor = service_class(row)
    service, confidence, status = naming_gate(facts, group)
    return Derivation(
        group=group,
        anchor=anchor,
        service=service,
        confidence=confidence,
        status=status,
        kind=facts.kind,
        service_number=(
            f"0x{facts.const:X}"
            if facts.kind == KIND_CONST and facts.const is not None
            else ""
        ),
        buffer_positions=buffer_positions(row),
        allocation_writes=int(row["allocation_write_arguments"]),
        basis=mapping_basis(facts, group, anchor),
    )


# --------------------------------------------------------------------------- #
# inventory rows
# --------------------------------------------------------------------------- #


def site_row(facts: SiteFacts, verdict: Derivation) -> dict[str, Any]:
    """The inventory row of one candidate, S7 evidence columns then S8 columns."""
    row = dict(facts.site.inventory)
    row["svc_producer_rva"] = (
        _hex(facts.producer_rva) if facts.producer_rva is not None else ""
    )
    row["producer_chain"] = chain_cell(facts)
    row["nt_service"] = verdict.service
    row["nt_confidence"] = verdict.confidence
    row["mapping_basis"] = verdict.basis
    row["service_class"] = verdict.group
    row["status"] = verdict.status
    return row


def build_rows(
    facts: Sequence[SiteFacts],
) -> tuple[list[dict[str, Any]], list[Derivation]]:
    """The inventory rows and the structured verdict behind each of them."""
    verdicts = [derive(item) for item in facts]
    return [site_row(item, verdict) for item, verdict in zip(facts, verdicts, strict=True)], verdicts


def validate_rows(
    rows: Sequence[dict[str, Any]],
    verdicts: Sequence[Derivation],
    expect_rows: int,
    expect_s7_columns: int,
) -> list[common.Check]:
    """Per row and whole table invariants of the inventory."""
    faults: Counter[str] = Counter()
    for row, verdict in zip(rows, verdicts, strict=True):
        missing = [name for name in CSV_COLUMNS if name not in row]
        if missing:
            faults["missing_columns"] += 1
            continue
        if row["service_class"] not in SERVICE_CLASSES:
            faults["service_class_domain"] += 1
        kinds = [
            token.split("=", 1)[1]
            for token in row["mapping_basis"].split("; ")
            if token.startswith("svc_kind=")
        ]
        if kinds != [verdict.kind] or verdict.kind not in SERVICE_KINDS:
            faults["service_kind_domain"] += 1
        if row["status"] not in STATUSES:
            faults["status_domain"] += 1
        if row["nt_confidence"] == "":
            faults["nt_confidence_empty"] += 1
        if row["nt_service"] != NT_SERVICE_UNRESOLVED and row["status"] != STATUS_NAMED:
            faults["named_service_without_named_status"] += 1
        if row["nt_service"] == NT_SERVICE_UNRESOLVED and row["status"] == STATUS_NAMED:
            faults["named_status_without_name"] += 1
        producer = row["svc_producer_rva"]
        if producer and not re.fullmatch(r"0x[0-9A-F]+", producer):
            faults["producer_rva_not_hex"] += 1
        if row["nt_service"] == NT_SERVICE_UNRESOLVED and not row["mapping_basis"]:
            faults["unresolved_without_basis"] += 1
        if row["mapping_basis"].endswith("..."):
            faults["mapping_basis_truncated"] += 1
        if "symbolic_operand=" in row["mapping_basis"] and row["nt_service"] != NT_SERVICE_UNRESOLVED:
            faults["named_row_with_a_symbolic_operand"] += 1
        if row["status"] == STATUS_NAMED and not row["nt_confidence"]:
            faults["named_without_confidence"] += 1
        inventory = row
        if not re.fullmatch(
            r"[A-Za-z0-9_]+(\+[A-Za-z0-9_]+){%d}" % (s7.ARGUMENT_POSITIONS - 1),
            inventory["site_signature"],
        ):
            faults["site_signature_domain"] += 1
        for position in range(1, s7.ARGUMENT_POSITIONS + 1):
            if argument_class(inventory, position) not in s7.ARG_CLASSES:
                faults["argument_class_domain"] += 1
                break
        if not re.fullmatch(r"0x[0-9A-F]+", inventory["rva_hex"]):
            faults["rva_not_hex"] += 1
    checks = [
        common.Check("row_count", expect_rows, len(rows), len(rows) == expect_rows),
        common.Check(
            "s7_columns_preserved",
            expect_s7_columns,
            len(S7_COLUMNS),
            len(S7_COLUMNS) == expect_s7_columns,
        ),
        common.Check(
            "column_count_at_least_s7",
            expect_s7_columns,
            len(CSV_COLUMNS),
            len(CSV_COLUMNS) >= expect_s7_columns,
        ),
        common.Check(
            "s7_column_order_preserved",
            True,
            CSV_COLUMNS[: len(S7_COLUMNS)] == S7_COLUMNS,
            CSV_COLUMNS[: len(S7_COLUMNS)] == S7_COLUMNS,
        ),
        common.Check(
            "no_duplicate_columns",
            len(CSV_COLUMNS),
            len(set(CSV_COLUMNS)),
            len(set(CSV_COLUMNS)) == len(CSV_COLUMNS),
        ),
        common.Check(
            "every_s8_column_present",
            len(S8_COLUMNS),
            sum(1 for name in S8_COLUMNS if name in CSV_COLUMNS),
            all(name in CSV_COLUMNS for name in S8_COLUMNS),
        ),
        common.Check(
            "rows_in_raw_offset_order",
            True,
            [int(row["raw_offset_hex"], 16) for row in rows]
            == sorted(int(row["raw_offset_hex"], 16) for row in rows),
            [int(row["raw_offset_hex"], 16) for row in rows]
            == sorted(int(row["raw_offset_hex"], 16) for row in rows),
        ),
        common.Check(
            "hit_index_is_a_permutation",
            expect_rows,
            len({row["hit_index"] for row in rows}),
            len({row["hit_index"] for row in rows}) == expect_rows,
        ),
    ]
    for name in sorted(faults):
        checks.append(common.Check(name, 0, faults[name], faults[name] == 0))
    return checks


def validate_naming_gate(
    rows: Sequence[dict[str, Any]], facts: Sequence[SiteFacts], verdicts: Sequence[Derivation]
) -> list[common.Check]:
    """The naming gate must agree with the resolved kind and the anchor group."""
    faults: Counter[str] = Counter()
    named = 0
    for item, verdict in zip(facts, verdicts, strict=True):
        if verdict.service == NT_SERVICE_UNRESOLVED:
            if item.kind == KIND_CONST and verdict.group in SERVICE_HYPOTHESIS:
                faults["static_number_left_unnamed"] += 1
            continue
        named += 1
        if item.kind != KIND_CONST:
            faults["named_without_static_number"] += 1
        if verdict.group not in SERVICE_HYPOTHESIS:
            faults["named_without_sufficient_schema"] += 1
    if named != sum(1 for row in rows if row["nt_service"] != NT_SERVICE_UNRESOLVED):
        faults["named_count_disagrees_with_the_rows"] += 1
    return [
        common.Check(
            "named_rows_have_a_static_service_number",
            0,
            faults["named_without_static_number"],
            faults["named_without_static_number"] == 0,
        ),
        common.Check(
            "named_rows_have_a_sufficient_schema",
            0,
            faults["named_without_sufficient_schema"],
            faults["named_without_sufficient_schema"] == 0,
        ),
        common.Check(
            "no_sufficient_static_row_left_unnamed",
            0,
            faults["static_number_left_unnamed"],
            faults["static_number_left_unnamed"] == 0,
        ),
        common.Check(
            "named_count_agrees_with_the_rows",
            0,
            faults["named_count_disagrees_with_the_rows"],
            faults["named_count_disagrees_with_the_rows"] == 0,
        ),
        common.Check(
            "unresolved_service_count",
            len(rows),
            sum(1 for row in rows if row["nt_service"] == NT_SERVICE_UNRESOLVED),
            True,
        ),
        common.Check("named_rows", named, named, True),
    ]


def validate_symbolic_unknowns(verdicts: Sequence[Derivation]) -> list[common.Check]:
    """A KUSER_SHARED_DATA or a PEB read must block a name, and must be visible.

    The rule is that both are symbolic unknown, so a row whose kind is one of the
    two cannot carry a service name, and the operand that made it symbolic has to
    be named in the basis cell so the row is auditable on its own.
    """
    faults: Counter[str] = Counter()
    for verdict in verdicts:
        symbolic = verdict.kind in (KIND_KUSER, KIND_PEB)
        named_operand = "symbolic_operand=" in verdict.basis
        if symbolic and not named_operand:
            faults["symbolic_kind_without_a_named_operand"] += 1
        if symbolic and verdict.service != NT_SERVICE_UNRESOLVED:
            faults["symbolic_kind_with_a_service_name"] += 1
        if not symbolic and named_operand:
            faults["named_operand_without_a_symbolic_kind"] += 1
    return [
        common.Check(
            "symbolic_kinds_name_their_operand",
            0,
            faults["symbolic_kind_without_a_named_operand"],
            faults["symbolic_kind_without_a_named_operand"] == 0,
        ),
        common.Check(
            "kuser_shared_data_and_peb_rows_stay_unresolved",
            0,
            faults["symbolic_kind_with_a_service_name"],
            faults["symbolic_kind_with_a_service_name"] == 0,
        ),
        common.Check(
            "no_symbolic_operand_without_a_symbolic_kind",
            0,
            faults["named_operand_without_a_symbolic_kind"],
            faults["named_operand_without_a_symbolic_kind"] == 0,
        ),
    ]


def validate_reconciliation(verdicts: Sequence[Derivation]) -> list[common.Check]:
    """The allocation_to_write reconciliation, asserted rather than assumed.

    A buffer class together with an allocation write count of 0 is a scope
    difference between two layers, never a conflict, so the check is that every
    such row carries the reconciliation marks, that no row reports more writes
    than it has buffer positions, and that no row claims a write it did not see.
    """
    buffer_rows = 0
    marked = 0
    unmarked = 0
    impossible = 0
    unclaimed = 0
    for verdict in verdicts:
        if verdict.allocation_writes > verdict.buffer_positions:
            impossible += 1
        if verdict.allocation_writes and "alloc_write=observed_in_window" not in verdict.basis:
            unclaimed += 1
        if not verdict.buffer_positions or verdict.allocation_writes:
            continue
        buffer_rows += 1
        if (
            ALLOC_WRITE_SCOPE in verdict.basis
            and ALLOC_WRITE_RECONCILED in verdict.basis
        ):
            marked += 1
        else:
            unmarked += 1
    return [
        common.Check(
            "buffer_rows_with_alloc_write_zero", True, buffer_rows, True
        ),
        common.Check(
            "buffer_rows_carry_the_reconciliation_marks",
            buffer_rows,
            marked,
            unmarked == 0,
        ),
        common.Check(
            "allocation_write_never_exceeds_buffer_positions",
            0,
            impossible,
            impossible == 0,
        ),
        common.Check(
            "no_allocation_write_is_claimed_without_observation",
            0,
            unclaimed,
            unclaimed == 0,
        ),
    ]


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #


def _histogram(values: Counter[int], limit: int = 16) -> dict[str, int]:
    return {str(key): values[key] for key in sorted(values)[:limit]}


def class_census(derivations: Sequence[Derivation]) -> dict[str, Any]:
    rvas: dict[str, list[int]] = {name: [] for name in SERVICE_CLASSES}
    anchors: dict[str, Counter[str]] = {name: Counter() for name in SERVICE_CLASSES}
    kinds: dict[str, Counter[str]] = {name: Counter() for name in SERVICE_CLASSES}
    statuses: dict[str, Counter[str]] = {name: Counter() for name in SERVICE_CLASSES}
    for index, item in enumerate(derivations):
        rvas[item.group].append(index)
        anchors[item.group][item.anchor] += 1
        kinds[item.group][item.kind] += 1
        statuses[item.group][item.status] += 1
    return {
        name: {
            "rule": SERVICE_CLASS_RULES[name],
            "sites": len(members),
            "anchors": _sorted_counts(anchors[name]),
            "service_number_kinds": _sorted_counts(kinds[name]),
            "by_status": _sorted_counts(statuses[name]),
            "site_row_numbers": [index + 1 for index in members[:MAX_EXAMPLES]],
        }
        for name, members in rvas.items()
    }


def build_report(
    root: Path,
    script: Path,
    specimen: Path,
    inputs: PhaseInputs,
    facts: Sequence[SiteFacts],
    rows: Sequence[dict[str, Any]],
    verdicts: Sequence[Derivation],
    tally: Counter[str],
    checks: Sequence[common.Check],
) -> dict[str, Any]:
    """The deterministic service map report payload."""
    statuses: Counter[str] = Counter(verdict.status for verdict in verdicts)
    kinds: Counter[str] = Counter(verdict.kind for verdict in verdicts)
    services: Counter[str] = Counter(verdict.service for verdict in verdicts)
    confidences: Counter[str] = Counter(verdict.confidence for verdict in verdicts)
    constants: Counter[str] = Counter(
        verdict.service_number for verdict in verdicts if verdict.service_number
    )
    named = [verdict for verdict in verdicts if verdict.service != NT_SERVICE_UNRESOLVED]
    buffer_rows = [
        verdict
        for verdict in verdicts
        if verdict.buffer_positions and not verdict.allocation_writes
    ]
    chain_lengths: Counter[int] = Counter(len(item.chain) for item in facts)
    sweep_depths: Counter[int] = Counter(
        min(item.sweep_instructions // 64 * 64, 4096) for item in facts
    )
    return {
        "schema": SCHEMA_JSON,
        "phase": PHASE,
        "predecessor": PREDECESSOR,
        "scope": (
            "static file parsing only; the specimen is never loaded, mapped for "
            "execution, patched or run; an Nt/Zw service name is written only where "
            "the producer chain folds to a static service number and the argument "
            "schema is sufficient for it; no exploit, bypass or patch recipe"
        ),
        "inventory": {
            "path": "reverse/evidence/syscall_inventory.csv",
            "schema": SCHEMA_CSV,
            "rows": len(rows),
            "columns": len(CSV_COLUMNS),
            "s7_columns_preserved": len(S7_COLUMNS),
            "s8_columns_added": [
                name for name in CSV_COLUMNS if name not in S7_COLUMNS
            ],
            "s8_columns_superseding": list(SUPERSEDED_COLUMNS),
            "supersession_note": (
                "nt_service exists in the P0/S7 schema as well; this phase writes the "
                "S8 verdict into that same position instead of adding a second "
                "identically named column, which a csv reader would collapse. The S7 "
                "assertion it replaces is UNRESOLVED on every row and is still recorded "
                "per row in the preserved nt_service_status column, and "
                "reverse/evidence/syscall_arg_inventory.csv is unmodified on disk."
            ),
        },
        "generated_by": {
            "script": script.relative_to(root).as_posix(),
            "python": common.python_summary(),
        },
        "specimen": common.file_digests(specimen),
        "inputs": {
            "syscall_candidates_raw.csv": {
                "rows": inputs.raw_rows,
                "sha256": inputs.digests["syscall_candidates_raw.csv"],
            },
            "syscall_arg_inventory.csv": {
                "rows": inputs.inventory_rows,
                "columns": inputs.s7_columns,
                "sha256": inputs.digests["syscall_arg_inventory.csv"],
            },
            "cfg_functions.csv": {
                "rows": inputs.cfg_rows,
                "sha256": inputs.digests["cfg_functions.csv"],
            },
        },
        "parameters": {
            "chain_max_depth": CHAIN_MAX_DEPTH,
            "chain_cell_entries": CHAIN_CELL_ENTRIES,
            "kuser_shared_data_window": [
                _hex(KUSER_SHARED_DATA_LOW),
                _hex(KUSER_SHARED_DATA_HIGH),
            ],
            "information_class_max": _hex(INFO_CLASS_MAX),
            "information_class_constants": {
                "ProcessBasicInformation": _hex(INFO_CLASS_BASIC),
                "ProcessDebugPort": _hex(0x07),
                "ProcessDebugObjectHandle": _hex(0x1E),
                "ProcessDebugFlags": _hex(0x1F),
                "ProcessInstrumentationCallback": _hex(INFO_CLASS_CALLBACK),
            },
            "allocation_anchors": {
                "type": _hex(ALLOCATION_TYPE_COMMIT_RESERVE),
                "protection": _hex(ALLOCATION_PROTECTION_EXECUTE_READWRITE),
            },
            "service_hypothesis_by_class": {
                name: SERVICE_HYPOTHESIS[name] for name in sorted(SERVICE_HYPOTHESIS)
            },
        },
        "method": {
            "window": (
                "the owning IMAGE_RUNTIME_FUNCTION is swept linearly from its begin in "
                "rva space, the same channel P0/S6 used to accept the candidate and the "
                "same one P0/S7 swept; the producer chain is the region of that sweep in "
                "front of the candidate and never crosses a function boundary"
            ),
            "boundaries": [
                "a call clobbers the volatile registers, so a definition of RAX before "
                "the last call of the window is not the live value",
                "an unconditional jump or a return ends the linear path, so a definition "
                "before the last one of those is not on the path to the candidate",
                "a read-modify-write reads its accumulator strictly before its own "
                "instruction, so a chain does not close on itself",
                "a cmov and friends define their destination on one edge only, so the "
                "nearest definite definition decides and a conditional definition is a "
                "conditional_merge",
            ],
            "foldable": sorted(
                set(s7.FOLDABLE_MNEMONICS) | set(FOLD_EXTRA) | set(UNARY_FOLD)
            ),
            "symbolic_unknown": [
                "an absolute operand in the KUSER_SHARED_DATA window",
                "an image slot that holds a KUSER_SHARED_DATA address",
                "a gs segment operand, and every memory operand whose base register "
                "resolves to the PEB",
                "a frame or stack relative operand",
                "a register indirect operand",
                "a code or data address produced by lea",
            ],
            "naming_gate": (
                "a service name is written only when the producer chain folds to a "
                "static constant with no symbolic operand in it, and the anchor group of "
                "the site carries a documented information class constant the schema "
                "needs; every other row is UNRESOLVED with the reason in mapping_basis"
            ),
            "mapping_basis_order": [
                "svc_kind",
                "symbolic_operand",
                "service_number",
                "class",
                "anchor",
                "producer",
                "alloc_write_scope and alloc_write, or alloc_write=observed_in_window",
            ],
            "mapping_basis_droppable": [
                "producer_text",
                "schema",
            ],
            "mapping_basis_note": (
                "a token that carries a verdict is never dropped and the descriptive "
                "tokens are shed from the tail when the cell would overflow the cell "
                "length limit, so a basis cell is always a complete list of the tokens "
                "that decide the row; the full P0/S7 site signature and the producer "
                "disassembly both stay reproducible, the former in its own preserved "
                "column and the latter from the specimen at the producer rva"
            ),
            "cell_limit": CELL_LIMIT,
            "schema_abbreviation": {
                name: name.split("_", 1)[0] for name in s7.ARG_CLASSES
            },
        },
        "service_number": {
            "sweep_reached": tally["reached"],
            "by_kind": _sorted_counts(kinds),
            "static_service_numbers": _sorted_counts(constants),
            "static_service_number_sites": tally["static_service_number"],
            "chain_length_histogram": _histogram(chain_lengths),
            "sweep_depth_instructions_64_buckets": _histogram(sweep_depths),
            "sweep_depth_note": (
                "the number of swept instructions in front of the candidate, bucketed in "
                "blocks of 64 and capped at 4096; it is the evidence that the producer "
                "chain does not fit the 20..40 byte P0/S7 argument window, so this phase "
                "walks the whole owning pdata/CFG window instead"
            ),
            "naming_gate": {
                "named_rows": len(named),
                "unresolved_rows": len(rows) - len(named),
                "by_nt_service": _sorted_counts(services),
                "by_status": _sorted_counts(statuses),
                "by_nt_confidence": _sorted_counts(confidences),
            },
        },
        "service_classes": class_census(verdicts),
        "reconciliation": {
            "signal": "allocation_to_write",
            "source_phase": PREDECESSOR,
            **RECONCILIATION,
            "counts": {
                "rows_with_a_buffer_class": sum(
                    1 for verdict in verdicts if verdict.buffer_positions
                ),
                "rows_with_a_buffer_class_and_alloc_write_zero": len(buffer_rows),
                "rows_with_an_observed_allocation_write": sum(
                    1 for verdict in verdicts if verdict.allocation_writes
                ),
                "arguments_with_an_allocator_origin": 0,
                "buffer_rows_marked": sum(
                    1
                    for verdict in buffer_rows
                    if ALLOC_WRITE_RECONCILED in verdict.basis
                ),
            },
        },
        "validation": {
            "checks": [
                {
                    "check": check.name,
                    "expected": common.scalar_text(check.expected),
                    "actual": common.scalar_text(check.actual),
                    "ok": "true" if check.ok else "false",
                }
                for check in checks
            ],
        },
        "limitations": list(LIMITATIONS),
    }


def read_stored_rows(path: Path) -> list[dict[str, str]]:
    rows, _ = read_csv(path)
    return rows


def compare_stored(path: Path, rows: Sequence[dict[str, Any]]) -> int:
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
            print("FAIL ... further differing rows not listed")
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
    facts: Sequence[SiteFacts],
    rows: Sequence[dict[str, Any]],
    verdicts: Sequence[Derivation],
    tally: Counter[str],
    written_csv: Path | None,
    written_json: Path | None,
    check_only: bool,
) -> None:
    kinds: Counter[str] = Counter(verdict.kind for verdict in verdicts)
    classes: Counter[str] = Counter(verdict.group for verdict in verdicts)
    statuses: Counter[str] = Counter(verdict.status for verdict in verdicts)
    print(f"phase     {PHASE} static syscall service map, extends {PREDECESSOR}")
    print(
        f"inputs    candidates={inputs.raw_rows} sites={len(inputs.sites)} "
        f"s7_rows={inputs.inventory_rows} s7_columns={inputs.s7_columns} "
        f"cfg={inputs.cfg_rows} pdata={inputs.runtime_functions}"
    )
    print(
        f"columns   {len(CSV_COLUMNS)} total, {len(S7_COLUMNS)} preserved from "
        f"{PREDECESSOR}, {len(CSV_COLUMNS) - len(S7_COLUMNS)} added, "
        f"superseding={','.join(SUPERSEDED_COLUMNS) or 'none'}"
    )
    print(f"sweep     reached={tally['reached']} of {len(facts)}")
    print("kind      " + " ".join(f"{name}={kinds[name]}" for name in sorted(kinds)))
    print(
        f"gate      static_service_number_sites={tally['static_service_number']} "
        f"named={statuses[STATUS_NAMED]} "
        f"unresolved={sum(1 for row in rows if row['nt_service'] == NT_SERVICE_UNRESOLVED)}"
    )
    for name in SERVICE_CLASSES:
        print(f"class     {name:44s} {classes[name]}")
    print(
        "reconcile buffer_rows_with_alloc_write_zero="
        f"{sum(1 for verdict in verdicts if verdict.buffer_positions and not verdict.allocation_writes)} "
        "recorded as a layer scope difference, not a contradiction"
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
            "Static syscall service map: the RAX service number producer chain of "
            "every valid 0F 05 candidate, resolved inside the pdata/CFG window of the "
            "owning site, with KUSER_SHARED_DATA and PEB reads kept as symbolic "
            "unknown, an Nt service name only where the constant chase and the argument "
            "schema are both sufficient, ordered anchor groups, and an explicit "
            "reconciliation of the P0/S7 allocation_to_write zero. No runtime "
            "observation, no exploit, bypass or patch recipe."
        )
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument(
        "--candidates", type=Path, default=evidence / "syscall_candidates_raw.csv"
    )
    parser.add_argument(
        "--inventory", type=Path, default=evidence / "syscall_arg_inventory.csv"
    )
    parser.add_argument("--cfg", type=Path, default=evidence / "cfg_functions.csv")
    parser.add_argument("--out", type=Path, default=evidence / "syscall_inventory.csv")
    parser.add_argument(
        "--map", type=Path, default=evidence / "syscall_service_map.json"
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
        "--expect-cfg-functions", type=int, default=EXPECTED_RUNTIME_FUNCTIONS
    )
    args = parser.parse_args(argv)

    specimen = args.specimen.resolve()
    if not specimen.is_file():
        print(f"ERROR specimen {specimen} is missing")
        return 2

    image = s7.Image(specimen)
    try:
        try:
            inputs = load_inputs(image, args.candidates, args.inventory, args.cfg)
        except (OSError, ValueError, KeyError) as error:
            print(f"ERROR {error}")
            return 2
        facts, tally = analyse(image, inputs)
        rows, verdicts = build_rows(facts)
    finally:
        image.close()

    checks = validate_rows(rows, verdicts, args.expect_valid, EXPECTED_S7_COLUMNS)
    checks += validate_naming_gate(rows, facts, verdicts)
    checks += validate_symbolic_unknowns(verdicts)
    checks += validate_reconciliation(verdicts)
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
            len(inputs.sites),
            len(inputs.sites) == args.expect_valid,
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
            "s7_inventory_rows",
            EXPECTED_S7_ROWS,
            inputs.inventory_rows,
            inputs.inventory_rows == EXPECTED_S7_ROWS,
        ),
        common.Check(
            "sweep_reached_every_site",
            len(facts),
            tally["reached"],
            tally["reached"] == len(facts),
        ),
    ]
    failed = [check for check in checks if not check.ok]
    payload = build_report(
        root, script, specimen, inputs, facts, rows, verdicts, tally, checks
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
        common.write_json(args.map, payload)
        common.write_csv(args.out, rows, CSV_COLUMNS)
        written_csv = args.out
        written_json = args.map

    report(
        root,
        inputs,
        facts,
        rows,
        verdicts,
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
        unresolved = sum(1 for row in rows if row["nt_service"] == NT_SERVICE_UNRESOLVED)
        print(
            f"service   nt_service={NT_SERVICE_UNRESOLVED} on {unresolved} of {len(rows)} rows"
        )
    return 1 if failed or status else 0


if __name__ == "__main__":
    raise SystemExit(main())
