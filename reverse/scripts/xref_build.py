"""Static xref graph builder for the adhesive.dll evidence set (P0/S3).

Static file parsing only: nothing in this module loads or executes the specimen.
The import-mediated call graph, the indirect-dispatch surface and the divergence
record are rebuilt from disk on every run, and the two evidence CSVs are rewritten
byte-identically for identical input.

Method
------
The import CALL-xref methodology is reproduced from
``reverse/adhesive-03-imports-exports.md#9``:

* every regular and delay import IAT slot is materialised with its RVA/raw pair;
* the ``.text`` byte range is scanned raw for ``FF 15 disp32`` and ``FF 25 disp32``
  candidates that resolve exactly onto an IAT slot;
* all 142 004 ``.pdata`` runtime-function ranges are decoded linearly with Capstone
  from ``BeginAddress`` to ``EndAddress``;
* a raw ``FF 15`` candidate is accepted as a direct xref only when the same RVA is
  also a decoded six-byte ``call qword ptr [rip+disp]`` at a linear instruction
  boundary inside a runtime function;
* a raw six-byte ``FF 25`` sequence resolving onto an IAT slot is an import thunk;
* a decoded ``call rel32`` whose target is one of those thunks is a thunk-mediated
  xref.

Extensions beyond doc 03 are recorded in ``build_divergences`` and never silently
applied. They add stable ``src -> target`` edges for direct ``call``/``jmp`` into
catalogued nodes, for import-thunk stubs, for IAT slot-to-symbol bindings, and for
read-only and writable code-pointer slots together with the code target behind
every slot. ``indirect_sites.csv`` enumerates every register-indirect and
memory-indirect ``call``/``jmp`` plus every statically resolvable write site, each
with an annotation.

Evidence schema: two distinct code objects
-------------------------------------------
A row names a source instruction and, for a row that crosses an import thunk, a
target thunk. Those are different objects with different ``.pdata`` relationships,
so neither evidence file carries a single ambiguous function column:

* ``code_instruction_function_index`` / ``_begin`` / ``_end`` is the
  ``IMAGE_RUNTIME_FUNCTION`` record that contains the row's *source code
  instruction*, meaning a decoded instruction that starts at the row's
  ``src_rva``/``insn_rva``. It is empty whenever no decoded instruction starts
  there: a data slot, a raw ``FF 15`` candidate that is not a linear instruction
  boundary, or a six-byte import-thunk stub RVA that turns out to be an interior
  byte of a longer instruction.
* ``target_thunk_function_index`` / ``_begin`` / ``_end`` is the runtime-function
  record that contains the *import thunk* the row lands on: the ``via_rva`` of a
  ``call``/``jmp`` rel32 thunk edge, the stub of an ``iat_jmp_thunk_stub`` row, or
  the instruction of a ``jmp``-through-IAT site row, because on such a row the
  instruction *is* the thunk. It is empty when the row crosses no thunk or the
  thunk RVA lies outside every runtime-function range.

The two columns are equal only on a row whose own instruction is a jmp-through-IAT
that a runtime function contains; there both statements are the same fact. Keeping
them apart is what lets a consumer tell a stub that is a standalone instruction
from a stub RVA that merely falls inside a runtime function: the doc 03 raw scan
matches the six bytes ``FF 25 disp32`` at any byte offset, so a ``48 FF 25``
REX.W jump also matches one byte into itself. Such a stub RVA is reported with an
empty ``code_instruction_function_index`` and a populated
``target_thunk_function_index``, never as an instruction of its own.

Scope boundaries
----------------
* ``direct_call``/``direct_jmp`` edges are emitted only for direct relative
  branches whose destination is a catalogued node: an import thunk, or the code
  target of a read-only/writable code-pointer slot. The unrestricted intra-image
  direct call graph is out of scope; its population is reported as a bounded
  negative rather than dropped silently. When a branch target is both an import
  thunk and a code-pointer-slot target the ``thunk`` category wins, so the doc 03
  counts stay exact and no branch is emitted twice.
* Write sites are emitted only for stores whose memory destination is RIP-relative
  and therefore statically resolvable. Stores through a base register are counted
  and reported, not enumerated. A write site mutates a slot and is not itself a
  control-flow transfer, so it is annotated in ``indirect_sites.csv`` and
  deliberately produces no edge in ``xref_edges.csv``; the corresponding
  ``fnptr_slot_code_target`` edge already carries the slot's static value.
* An import thunk is defined exactly as in doc 03: a six-byte ``FF 25 disp32``
  sequence. That definition does not see REX.W-prefixed ``48 FF 25`` jumps; the
  gap is measured and recorded as divergence D09 rather than folded into the
  published figure. The same six-byte marker also matches one byte into such a
  REX.W jump, because the scan is a raw byte search with no alignment rule; those
  interior matches carry no instruction of their own and are described as such in
  both evidence files rather than as unanchored stubs.
* Code-pointer slots are searched on 8-byte stride inside the data sections only
  (``.text``, ``.rsrc`` and ``.reloc`` excluded). A slot qualifies when its static
  64-bit value is ``ImageBase + rva`` with ``rva`` inside an executable section.
  Read-only sections classify as ``vtable``, writable sections as
  ``global_fnptr``. Per-section slot counts are reported. An RVA that lands behind
  ``SizeOfRawData`` but inside ``VirtualSize`` is reported as ``virtual_tail``:
  loader zero fill, not a file object, and never a code-pointer slot.

No exploit, bypass or patch guidance is produced by this script.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import struct
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Mapping, Sequence

SCRIPT_DIR: Final[Path] = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import pefile  # noqa: E402  (the path shim above is load-bearing)

import common  # noqa: E402
from capstone import (  # noqa: E402
    CS_AC_WRITE,
    CS_ARCH_X86,
    CS_MODE_64,
    Cs,
)
from capstone.x86 import (  # noqa: E402
    X86_INS_CALL,
    X86_INS_JMP,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_RIP,
)

DOC03_SUMMARY: Final[str] = "reverse/adhesive-03-imports-exports.md#2"
DOC03_METHOD: Final[str] = "reverse/adhesive-03-imports-exports.md#9"
DOC03_DELAY: Final[str] = "reverse/adhesive-03-imports-exports.md#9.1"
DOC03_TABLES: Final[str] = "reverse/adhesive-03-imports-exports.md#10"
DOC03_CHECKS: Final[str] = "reverse/adhesive-03-imports-exports.md#13"

ROOT: Final[Path] = SCRIPT_DIR.parent.parent
DEFAULT_SPECIMEN: Final[Path] = ROOT / "reverse" / "adhesive.dll"
DEFAULT_EDGES: Final[Path] = ROOT / "reverse" / "evidence" / "xref_edges.csv"
DEFAULT_SITES: Final[Path] = ROOT / "reverse" / "evidence" / "indirect_sites.csv"

RUNTIME_FUNCTION_SIZE: Final[int] = common.RUNTIME_FUNCTION_SIZE
CODE_POINTER_STRIDE: Final[int] = 8
BYTES_IN_ANNOTATION: Final[int] = 16
RIP_INDIRECT_SIZE: Final[int] = 6
REX_W_INDIRECT_SIZE: Final[int] = RIP_INDIRECT_SIZE + 1
EXECUTABLE_CHARACTERISTIC: Final[int] = 0x20000000
WRITABLE_CHARACTERISTIC: Final[int] = 0x80000000
CODE_POINTER_EXCLUDED_SECTIONS: Final[frozenset[str]] = frozenset({".text", ".rsrc", ".reloc"})
UNMAPPED: Final[str] = "UNMAPPED"

IMPLICIT_WRITE_MNEMONICS: Final[frozenset[str]] = frozenset(
    {"cmpxchg", "cmpxchg8b", "cmpxchg16b", "xadd", "xchg"}
)

CATEGORY_ORDER: Final[tuple[str, ...]] = (
    "direct_call",
    "direct_jmp",
    "thunk",
    "iat",
    "vtable",
    "global_fnptr",
)
CATEGORY_RANK: Final[Mapping[str, int]] = MappingProxyType(
    {name: index for index, name in enumerate(CATEGORY_ORDER)}
)
DIRECT_RELATION: Final[Mapping[str, str]] = MappingProxyType(
    {"call": "call_rel_to_code", "jmp": "jmp_rel_to_code"}
)
THUNK_RELATION: Final[Mapping[str, str]] = MappingProxyType(
    {"call": "call_rel32_to_thunk", "jmp": "jmp_rel32_to_thunk"}
)
INDIRECT_MARKER_BYTES: Final[tuple[bytes, ...]] = (b"\xff\x15", b"\xff\x25")
REX_W_PREFIX: Final[int] = 0x48
CALL_REL32_OPCODE: Final[int] = 0xE8
ORDINAL_FLAG_64: Final[int] = 1 << 63
ADDRESS_MASK_64: Final[int] = 0x7FFFFFFFFFFFFFFF
MAX_IMPORT_NAME_BYTES: Final[int] = 4096
MAX_DETAIL_CHARS: Final[int] = 256
U32_ANNOTATION_STRIDE: Final[int] = 4
U32_ANNOTATION_WORDS: Final[int] = 8
REJECTED_ANNOTATION: Final[str] = (
    "raw_ff15_candidate_outside_every_pdata_runtime_function"
    "+never_a_linear_instruction_boundary"
    "+rejected_by_doc03_method"
)
RAW_THUNK_ANNOTATION: Final[str] = "import_thunk_stub_outside_every_pdata_runtime_function"
RAW_THUNK_INTERIOR_ANNOTATION: Final[str] = (
    "import_thunk_stub_interior_byte_of_a_decoded_jmp_inside_a_pdata_function"
)
VIRTUAL_TAIL: Final[str] = "virtual_tail"
OUTSIDE_IMAGE: Final[str] = "outside_image"
WRITE_ANNOTATION: Final[Mapping[str, str]] = MappingProxyType(
    {
        "iat_slot": "static_store_into_iat_slot",
        "vtable_slot": "static_store_into_readonly_code_pointer_slot",
        "global_fnptr_slot": "static_store_into_writable_code_pointer_slot",
        "data": "static_store_into_data_address_without_static_code_pointer",
        VIRTUAL_TAIL: "static_store_into_loader_zero_fill_virtual_tail",
        OUTSIDE_IMAGE: "static_store_into_address_outside_every_section",
    }
)

EDGE_FIELDS: Final[tuple[str, ...]] = (
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

SITE_FIELDS: Final[tuple[str, ...]] = (
    "site_id",
    "kind",
    "source",
    "insn_rva",
    "insn_raw",
    "code_instruction_function_index",
    "code_instruction_function_begin",
    "code_instruction_function_end",
    "mnemonic",
    "op_str",
    "bytes",
    "operand_kind",
    "operand_reg",
    "mem_base",
    "mem_index",
    "mem_scale",
    "mem_disp",
    "target_kind",
    "target_rva",
    "target_section",
    "target_code_rva",
    "target_thunk_function_index",
    "target_thunk_function_begin",
    "target_thunk_function_end",
    "iat_rva",
    "dll",
    "symbol",
    "annotation",
)

DOC03_EXPECTATIONS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "runtime_function_count": 142_004,
        "runtime_function_record_size": RUNTIME_FUNCTION_SIZE,
        "iat_slot_count_total": 629,
        "iat_slot_count_regular": 628,
        "iat_slot_count_delay": 1,
        "int_equals_iat_qword": 628,
        "raw_direct_call_iat_candidates": 3_148,
        "raw_direct_call_iat_rejected": 16,
        "direct_call_iat_xrefs": 3_132,
        "direct_call_iat_xrefs_regular": 3_131,
        "direct_call_iat_xrefs_delay": 1,
        "import_thunk_count": 355,
        "thunk_mediated_call_xrefs": 6_304,
        "thunks_reached_by_call": 193,
        "total_statistical_call_xrefs": 9_436,
        "iat_slots_reached_direct": 364,
        "iat_slots_reached_via_thunk": 193,
        "iat_slots_touched": 527,
        "iat_slots_untouched": 102,
        "xref_runtime_functions": 6_039,
        "xref_runtime_function_bytes": 5_353_470,
        "delay_xref_call_rva": 0x10FB79,
        "delay_xref_iat_rva": 0x3306F60,
    }
)
DOC03_EXPECTATION_LABELS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "runtime_function_count": "doc03#9 .pdata runtime functions decoded",
        "runtime_function_record_size": "doc03#3 IMAGE_RUNTIME_FUNCTION record size",
        "iat_slot_count_total": "doc03#2 regular + delay IAT slots",
        "iat_slot_count_regular": "doc03#2 regular IAT slots",
        "iat_slot_count_delay": "doc03#2 delay IAT slots",
        "int_equals_iat_qword": "doc03#13 equal INT/IAT qword pairs",
        "raw_direct_call_iat_candidates": "doc03#9 raw FF 15 candidates onto an IAT slot",
        "raw_direct_call_iat_rejected": "doc03#9 raw candidates dropped by the .pdata filter",
        "direct_call_iat_xrefs": "doc03#2 accepted direct call [IAT] xrefs",
        "direct_call_iat_xrefs_regular": "doc03#2 accepted direct call [IAT] xrefs on a regular slot",
        "direct_call_iat_xrefs_delay": "doc03#2 accepted direct call [IAT] xrefs on a delay slot",
        "import_thunk_count": "doc03#2 FF 25 import thunks",
        "thunk_mediated_call_xrefs": "doc03#2 call rel32 xrefs through an import thunk",
        "thunks_reached_by_call": "doc03#2 import thunks reached by at least one CALL xref",
        "total_statistical_call_xrefs": "doc03#2 all statistical CALL xrefs",
        "iat_slots_reached_direct": "doc03#2 IAT slots with a direct CALL xref",
        "iat_slots_reached_via_thunk": "doc03#2 IAT slots reached through an import thunk",
        "iat_slots_touched": "doc03#2 IAT slots touched by either xref kind",
        "iat_slots_untouched": "doc03#2 IAT slots untouched by either xref kind",
        "xref_runtime_functions": "doc03#9 runtime functions carrying an accepted xref",
        "xref_runtime_function_bytes": "doc03#9 bytes of those runtime functions",
        "delay_xref_call_rva": "doc03#9.1 the single delay-import xref CALL RVA",
        "delay_xref_iat_rva": "doc03#9.1 the single delay-import xref IAT RVA",
    }
)


class BuildError(RuntimeError):
    """Raised when the specimen cannot be parsed into the structures the xref pass needs."""


@dataclass(frozen=True, slots=True)
class ImageMap:
    """Section lookup for an RVA, distinguishing file-backed data from loader zero fill."""

    raw_ranges: tuple[tuple[int, int, str], ...]
    virtual_ranges: tuple[tuple[int, int, str], ...]

    @classmethod
    def from_pe(cls, pe: pefile.PE) -> ImageMap:
        parsed = common.sections(pe)
        return cls(
            raw_ranges=tuple((s.virtual_address, s.virtual_address + s.raw_size, s.name) for s in parsed),
            virtual_ranges=tuple((s.virtual_address, s.virtual_end, s.name) for s in parsed),
        )

    def raw_section(self, rva: int) -> str | None:
        return next((name for start, stop, name in self.raw_ranges if start <= rva < stop), None)

    def virtual_section(self, rva: int) -> str | None:
        return next((name for start, stop, name in self.virtual_ranges if start <= rva < stop), None)

    def label(self, rva: int) -> tuple[str, str]:
        name = self.raw_section(rva)
        if name is not None:
            return "data", name
        name = self.virtual_section(rva)
        if name is not None:
            return VIRTUAL_TAIL, name
        return OUTSIDE_IMAGE, UNMAPPED


@dataclass(frozen=True, slots=True)
class IatSlot:
    """One materialised import address table slot.

    ``symbol`` follows the doc 03 rendering: a named import keeps its name, an
    ordinal-only import becomes ``#<ordinal> (ordinal)``. ``secondary_name`` keeps
    the name pefile derives from its own ordinal table for such an entry, clearly
    separated from the file-backed identity.
    """

    rva: int
    raw: int
    module: str
    symbol: str
    is_delay: bool
    ordinal: int | None
    secondary_name: str

    @property
    def import_kind(self) -> str:
        return "delay" if self.is_delay else "regular"

    def evidence_suffix(self) -> str:
        parts = [f"import_kind_{self.import_kind}"]
        if self.ordinal is not None:
            parts.append(f"int_ordinal_{self.ordinal}")
        if self.secondary_name:
            parts.append(f"ordlookup_name={self.secondary_name}")
        return "+".join(parts)

    def reach_evidence(self, direct: bool, via_thunk: bool) -> str:
        marks = [name for name, hit in (("reached_direct", direct), ("reached_thunk", via_thunk)) if hit]
        return "+".join(marks) if marks else "reached_none"


@dataclass(frozen=True, slots=True)
class NameCheck:
    """How the file-backed import name compares with the library-supplied one."""

    mismatches: int
    mismatch_iat_rvas: tuple[int, ...]
    shortest_mismatched_file_bytes: int
    longest_file_bytes: int


@dataclass(frozen=True, slots=True)
class CodePointerSlot:
    """A data-section 8-byte slot whose static value is ImageBase + executable RVA."""

    rva: int
    raw: int
    section: str
    category: str
    code_rva: int
    run_length: int
    run_index: int


@dataclass(frozen=True, slots=True)
class RuntimeFunction:
    """One IMAGE_RUNTIME_FUNCTION entry from the x64 exception directory."""

    index: int
    begin: int
    end: int
    unwind_info: int
    raw_begin: int
    raw_end: int
    byte_length: int


@dataclass(frozen=True, slots=True)
class Branch:
    """A decoded direct relative branch inside a runtime-function range."""

    form: str
    rva: int
    raw: int
    function_index: int
    function_begin: int
    function_end: int
    target_rva: int
    mnemonic: str
    op_str: str
    raw_bytes: str


@dataclass(frozen=True, slots=True)
class ThunkStubPlacement:
    """Where a raw-scan import-thunk stub RVA sits in the linear ``.pdata`` decode.

    The doc 03 stub scan is a raw byte search for ``FF 25 disp32``, so it also
    matches one byte into a ``48 FF 25`` REX.W jump. A stub RVA can therefore be
    the first byte of a decoded instruction, or an interior byte of one, or covered
    by no decoded instruction at all. ``function_*`` is the runtime function that
    decoded the covering instruction, which is also the function whose byte range
    contains the stub RVA.
    """

    rva: int
    at_instruction_boundary: bool
    covering_rva: int
    covering_size: int
    covering_mnemonic: str
    covering_first_byte: int
    function_index: int
    function_begin: int
    function_end: int

    def evidence_suffix(self) -> str:
        if self.at_instruction_boundary:
            return (
                f"stub_is_the_first_byte_of_a_decoded_{self.covering_size}_byte_"
                f"{self.covering_mnemonic}_at_{common.hexs(self.covering_rva)}"
            )
        return (
            f"stub_is_byte_{self.rva - self.covering_rva}_of_a_decoded_{self.covering_size}_byte_"
            f"{self.covering_mnemonic}_at_{common.hexs(self.covering_rva)}"
            f"+covering_first_byte=0x{self.covering_first_byte:02x}"
        )


@dataclass(frozen=True, slots=True)
class Edge:
    """A single stable src -> target hop of the interop graph.

    ``code_instruction_function_*`` describes the source instruction and
    ``target_thunk_function_index`` and its range describe the import thunk the
    edge lands on; the two are separate because a source RVA and a thunk RVA have
    independent ``.pdata`` containment.
    """

    category: str
    relation: str
    evidence: str
    src_rva: int
    src_raw: int
    code_instruction_function_index: int | None
    code_instruction_function_begin: int | None
    code_instruction_function_end: int | None
    src_mnemonic: str
    src_op_str: str
    src_bytes: str
    via_rva: int | None
    target_thunk_function_index: int | None
    target_thunk_function_begin: int | None
    target_thunk_function_end: int | None
    dst_kind: str
    dst_rva: int | None
    dst_raw: int | None
    dst_module: str
    dst_symbol: str
    iat_rva: int | None

    def sort_key(self) -> tuple[int, int, str, int, int, str, str]:
        return (
            CATEGORY_RANK[self.category],
            self.src_rva,
            self.relation,
            self.via_rva if self.via_rva is not None else -1,
            self.dst_rva if self.dst_rva is not None else -1,
            self.dst_module,
            self.dst_symbol,
        )

    def as_row(self, edge_id: int) -> dict[str, Any]:
        return {
            "edge_id": edge_id,
            "category": self.category,
            "relation": self.relation,
            "evidence": self.evidence,
            "src_rva": self.src_rva,
            "src_raw": self.src_raw,
            "code_instruction_function_index": blank(self.code_instruction_function_index),
            "code_instruction_function_begin": blank(self.code_instruction_function_begin),
            "code_instruction_function_end": blank(self.code_instruction_function_end),
            "src_mnemonic": self.src_mnemonic,
            "src_op_str": self.src_op_str,
            "src_bytes": self.src_bytes,
            "via_rva": blank(self.via_rva),
            "target_thunk_function_index": blank(self.target_thunk_function_index),
            "target_thunk_function_begin": blank(self.target_thunk_function_begin),
            "target_thunk_function_end": blank(self.target_thunk_function_end),
            "dst_kind": self.dst_kind,
            "dst_rva": blank(self.dst_rva),
            "dst_raw": blank(self.dst_raw),
            "dst_module": self.dst_module,
            "dst_symbol": self.dst_symbol,
            "iat_rva": blank(self.iat_rva),
        }


@dataclass(frozen=True, slots=True)
class IndirectSite:
    """A register-indirect or memory-indirect branch, or a resolvable write site.

    ``code_instruction_function_*`` names the runtime function that decoded the
    site instruction. ``target_thunk_function_*`` names the runtime function that
    contains the import thunk this site lands on, which is the site instruction
    itself on a ``jmp``-through-IAT row and the six-byte stub on a raw-scan thunk
    row, and is empty on a row that crosses no thunk.
    """

    kind: str
    source: str
    insn_rva: int
    insn_raw: int
    code_instruction_function_index: int | None
    code_instruction_function_begin: int | None
    code_instruction_function_end: int | None
    mnemonic: str
    op_str: str
    raw_bytes: str
    operand_kind: str
    operand_reg: str
    mem_base: str
    mem_index: str
    mem_scale: str
    mem_disp: int | None
    target_kind: str
    target_rva: int | None
    target_section: str
    target_code_rva: int | None
    target_thunk_function_index: int | None
    target_thunk_function_begin: int | None
    target_thunk_function_end: int | None
    iat_rva: int | None
    module: str
    symbol: str
    annotation: str

    def sort_key(self) -> tuple[int, str, str, int, int, int]:
        return (
            self.insn_rva,
            self.kind,
            self.source,
            self.code_instruction_function_index
            if self.code_instruction_function_index is not None
            else -1,
            self.target_rva if self.target_rva is not None else -1,
            self.target_code_rva if self.target_code_rva is not None else -1,
        )

    def as_row(self, site_id: int) -> dict[str, Any]:
        return {
            "site_id": site_id,
            "kind": self.kind,
            "source": self.source,
            "insn_rva": self.insn_rva,
            "insn_raw": self.insn_raw,
            "code_instruction_function_index": blank(self.code_instruction_function_index),
            "code_instruction_function_begin": blank(self.code_instruction_function_begin),
            "code_instruction_function_end": blank(self.code_instruction_function_end),
            "mnemonic": self.mnemonic,
            "op_str": self.op_str,
            "bytes": self.raw_bytes,
            "operand_kind": self.operand_kind,
            "operand_reg": self.operand_reg,
            "mem_base": self.mem_base,
            "mem_index": self.mem_index,
            "mem_scale": self.mem_scale,
            "mem_disp": blank(self.mem_disp),
            "target_kind": self.target_kind,
            "target_rva": blank(self.target_rva),
            "target_section": self.target_section,
            "target_code_rva": blank(self.target_code_rva),
            "target_thunk_function_index": blank(self.target_thunk_function_index),
            "target_thunk_function_begin": blank(self.target_thunk_function_begin),
            "target_thunk_function_end": blank(self.target_thunk_function_end),
            "iat_rva": blank(self.iat_rva),
            "dll": self.module,
            "symbol": self.symbol,
            "annotation": self.annotation,
        }


@dataclass(frozen=True, slots=True)
class Divergence:
    """A recorded difference from, extension of, or boundary around the doc 03 evidence."""

    identifier: str
    kind: str
    doc03_ref: str
    doc03_claim: str
    observed: str
    impact: str
    disposition: str

    def as_lines(self) -> tuple[str, ...]:
        return (
            f"{self.identifier} [{self.kind}] {self.doc03_ref}",
            f"    claim       {self.doc03_claim}",
            f"    observed    {self.observed}",
            f"    impact      {self.impact}",
            f"    disposition {self.disposition}",
        )


@dataclass(slots=True)
class DecodeResult:
    """Everything the linear .pdata decode produced."""

    functions: list[RuntimeFunction]
    direct_iat: list[Branch]
    direct_iat_slot: dict[int, int]
    to_thunk: list[Branch]
    to_fnptr: list[Branch]
    sites: list[IndirectSite]
    decoded_rip_indirect: set[int]
    thunk_stub_placements: dict[int, ThunkStubPlacement]
    uncatalogued_direct_calls: int
    thunk_fnptr_overlap_targets: set[int]
    rex_w_iat_jmps: int
    zero_instruction_functions: tuple[RuntimeFunction, ...]
    excluded_store_count: int
    excluded_store_mnemonics: Counter[str]
    instruction_total: int
    decoded_bytes: int


@dataclass(slots=True)
class BuildResult:
    """Deterministic build output plus the counters the report is derived from."""

    edges: list[Edge]
    sites: list[IndirectSite]
    stats: dict[str, Any]
    rejected: tuple[tuple[int, int, int, str], ...]


def blank(value: int | None) -> Any:
    """Empty cell for an absent numeric field, so an absent value never reads as a number."""
    return "" if value is None else value


def hex_bytes(payload: bytes) -> str:
    return " ".join(f"{byte:02x}" for byte in payload[:BYTES_IN_ANNOTATION])


def text_section(pe: pefile.PE) -> common.Section:
    section = next((item for item in common.sections(pe) if item.name == ".text"), None)
    if section is None:
        raise BuildError("specimen has no .text section")
    return section


def classify_rip_target(
    image_map: ImageMap,
    target_rva: int,
    slot_by_rva: Mapping[int, CodePointerSlot],
    iat_by_rva: Mapping[int, IatSlot],
) -> tuple[str, str, int | None, int | None, str, str]:
    """Resolve a RIP-relative destination to a target kind, section, code RVA and IAT identity.

    An RVA that lands behind ``SizeOfRawData`` but inside a section's ``VirtualSize``
    is reported as ``virtual_tail``: it is loader-supplied zero fill, not a file
    object, and it carries no code-pointer value.
    """
    iat_slot = iat_by_rva.get(target_rva)
    if iat_slot is not None:
        section = image_map.raw_section(target_rva) or image_map.virtual_section(target_rva) or UNMAPPED
        return "iat_slot", section, None, target_rva, iat_slot.module, iat_slot.symbol
    slot = slot_by_rva.get(target_rva)
    if slot is not None:
        return f"{slot.category}_slot", slot.section, slot.code_rva, None, "", ""
    kind, section = image_map.label(target_rva)
    return kind, section, None, None, "", ""


def read_import_name(pe: pefile.PE, hint_rva: int) -> str:
    """Read an IMAGE_IMPORT_BY_NAME payload straight from the file.

    pefile's own import-name field is capped, and this specimen contains one
    603-byte MSVC-mangled name that pefile truncates. The evidence set must carry
    the name the file actually holds, so the hint/name record is read directly.
    """
    record = common.read_rva(pe, hint_rva, MAX_IMPORT_NAME_BYTES)
    terminator = record.find(b"\x00", 2)
    if terminator < 0:
        raise BuildError(
            f"import name at RVA {common.hexs(hint_rva)} has no terminator "
            f"within {MAX_IMPORT_NAME_BYTES} bytes"
        )
    return record[2:terminator].decode("ascii", errors="replace")


def load_iat_slots(pe: pefile.PE) -> tuple[tuple[IatSlot, ...], int, NameCheck]:
    """Materialise every regular and delay IAT slot and check the INT/IAT precondition.

    Names come from the IMAGE_IMPORT_BY_NAME record in the file, and the result also
    records where that differs from the library-supplied name so the tool boundary
    is measured rather than asserted.
    """
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    entries: dict[int, IatSlot] = {}
    int_equal = 0
    mismatches: list[int] = []
    shortest_mismatch = 0
    longest_name = 0

    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        module = descriptor.dll.decode("ascii", errors="replace")
        int_rva = int(descriptor.struct.OriginalFirstThunk)
        for index, entry in enumerate(descriptor.imports):
            rva = int(entry.address) - image_base
            int_slot = int_rva + index * CODE_POINTER_STRIDE
            if common.rva_to_raw(pe, int_slot) is None or common.rva_to_raw(pe, rva) is None:
                continue
            thunk_value = struct.unpack("<Q", common.read_rva(pe, int_slot, CODE_POINTER_STRIDE))[0]
            if common.read_rva(pe, int_slot, CODE_POINTER_STRIDE) == common.read_rva(
                pe, rva, CODE_POINTER_STRIDE
            ):
                int_equal += 1
            if thunk_value & ORDINAL_FLAG_64:
                ordinal = int(thunk_value & 0xFFFF)
                symbol = f"#{ordinal} (ordinal)"
                secondary = entry.name.decode("ascii", errors="replace") if entry.name else ""
                entries[rva] = IatSlot(rva, 0, module, symbol, False, ordinal, secondary)
                continue
            name = read_import_name(pe, int(thunk_value & ADDRESS_MASK_64))
            longest_name = max(longest_name, len(name))
            supplied = entry.name.decode("ascii", errors="replace") if entry.name else ""
            if supplied != name:
                mismatches.append(rva)
                shortest_mismatch = len(name) if shortest_mismatch == 0 else min(shortest_mismatch, len(name))
            entries[rva] = IatSlot(rva, 0, module, name, False, None, "")

    for descriptor in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
        module = descriptor.dll.decode("ascii", errors="replace")
        for entry in descriptor.imports:
            rva = int(entry.address) - image_base
            symbol = (
                entry.name.decode("ascii", errors="replace") if entry.name else f"#{int(entry.ordinal)} (ordinal)"
            )
            entries[rva] = IatSlot(rva, 0, module, symbol, True, None, "")

    slots: list[IatSlot] = []
    for rva in sorted(entries):
        slot = entries[rva]
        raw = common.rva_to_raw(pe, rva)
        if raw is None:
            raise BuildError(f"IAT slot RVA {common.hexs(rva)} has no file backing")
        slots.append(
            IatSlot(
                rva=slot.rva,
                raw=raw,
                module=slot.module,
                symbol=slot.symbol,
                is_delay=slot.is_delay,
                ordinal=slot.ordinal,
                secondary_name=slot.secondary_name,
            )
        )
    check = NameCheck(
        mismatches=len(mismatches),
        mismatch_iat_rvas=tuple(mismatches),
        shortest_mismatched_file_bytes=shortest_mismatch,
        longest_file_bytes=longest_name,
    )
    return tuple(slots), int_equal, check


def scan_text_markers(pe: pefile.PE, iat_rvas: frozenset[int]) -> tuple[dict[int, int], dict[int, int]]:
    """Raw-scan .text for FF 15 and FF 25 sequences landing exactly on an IAT slot.

    Returns the FF 15 candidate map and the FF 25 import-thunk stub map, both keyed
    by the site RVA and valued with the resolved IAT slot RVA.
    """
    section = text_section(pe)
    payload = common.read_rva(pe, section.virtual_address, section.raw_size)
    base = section.virtual_address
    maps: dict[bytes, dict[int, int]] = {b"\xff\x15": {}, b"\xff\x25": {}}
    for opcode, table in maps.items():
        cursor = 0
        while True:
            cursor = payload.find(opcode, cursor)
            if cursor < 0:
                break
            if cursor + RIP_INDIRECT_SIZE <= len(payload):
                displacement = struct.unpack_from("<i", payload, cursor + 2)[0]
                site_rva = base + cursor
                target = site_rva + RIP_INDIRECT_SIZE + displacement
                if target in iat_rvas:
                    table[site_rva] = target
            cursor += 1
    return maps[b"\xff\x15"], maps[b"\xff\x25"]


def read_runtime_functions(pe: pefile.PE) -> tuple[tuple[int, int, int], ...]:
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[common.EXCEPTION_DIRECTORY_INDEX]
    rva = int(directory.VirtualAddress)
    size = int(directory.Size)
    if rva == 0 or size == 0:
        raise BuildError("specimen has no x64 exception directory")
    if size % RUNTIME_FUNCTION_SIZE:
        raise BuildError(f"exception directory size {size} is not a multiple of {RUNTIME_FUNCTION_SIZE}")
    return tuple(struct.iter_unpack("<III", common.read_rva(pe, rva, size)))


def build_function_index(
    pe: pefile.PE, records: Sequence[tuple[int, int, int]]
) -> tuple[list[RuntimeFunction], list[int]]:
    functions: list[RuntimeFunction] = []
    for index, (begin, end, unwind_info) in enumerate(records):
        raw_begin = common.rva_to_raw(pe, begin)
        raw_end = common.rva_to_raw(pe, end)
        if raw_begin is None or raw_end is None or raw_end < raw_begin:
            raise BuildError(
                f"runtime function {index} range {common.hexs(begin)}-{common.hexs(end)} is not file backed"
            )
        functions.append(
            RuntimeFunction(
                index=index,
                begin=begin,
                end=end,
                unwind_info=unwind_info,
                raw_begin=raw_begin,
                raw_end=raw_end,
                byte_length=raw_end - raw_begin,
            )
        )
    if any(functions[i].begin > functions[i + 1].begin for i in range(len(functions) - 1)):
        raise BuildError("exception directory is not sorted by BeginAddress")
    return functions, [function.begin for function in functions]


def find_function(
    functions: Sequence[RuntimeFunction], begins: Sequence[int], rva: int
) -> RuntimeFunction | None:
    position = bisect.bisect_right(begins, rva) - 1
    if position < 0:
        return None
    function = functions[position]
    return function if function.begin <= rva < function.end else None


def collect_code_pointer_slots(
    pe: pefile.PE, payload: bytes
) -> tuple[tuple[CodePointerSlot, ...], int, Counter[str]]:
    """Find data-section 8-byte slots holding ImageBase + executable RVA.

    Read-only sections classify as ``vtable`` candidates, writable sections as
    ``global_fnptr`` candidates. The only structural vtable signal available
    without type information is the length and position of the maximal run of
    consecutive slots a slot belongs to, so both are recorded per slot.
    """
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)
    executable = [
        (section.virtual_address, section.virtual_end)
        for section in common.sections(pe)
        if section.characteristics & EXECUTABLE_CHARACTERISTIC
    ]
    writable = {
        section.name
        for section in common.sections(pe)
        if section.characteristics & WRITABLE_CHARACTERISTIC
    }

    inspected = 0
    per_section: Counter[str] = Counter()
    found: dict[int, tuple[str, str, int]] = {}
    for section in common.sections(pe):
        if section.name in CODE_POINTER_EXCLUDED_SECTIONS:
            continue
        span = min(section.raw_size, section.virtual_size) if section.virtual_size else section.raw_size
        first = common.align_up(section.virtual_address, CODE_POINTER_STRIDE)
        limit = first + (span // CODE_POINTER_STRIDE) * CODE_POINTER_STRIDE
        category = "global_fnptr" if section.name in writable else "vtable"
        for rva in range(first, limit, CODE_POINTER_STRIDE):
            inspected += 1
            raw = common.rva_to_raw(pe, rva)
            if raw is None:
                continue
            value = struct.unpack_from("<Q", payload, raw)[0]
            if not image_base <= value < image_base + size_of_image:
                continue
            code_rva = value - image_base
            if not any(start <= code_rva < stop for start, stop in executable):
                continue
            per_section[section.name] += 1
            found[rva] = (section.name, category, code_rva)

    by_section: dict[str, list[int]] = {}
    for rva, entry in found.items():
        by_section.setdefault(entry[0], []).append(rva)

    slots: list[CodePointerSlot] = []
    for name in sorted(by_section):
        run_rvas = sorted(by_section[name])
        position = 0
        while position < len(run_rvas):
            stop = position
            while stop + 1 < len(run_rvas) and run_rvas[stop + 1] == run_rvas[stop] + CODE_POINTER_STRIDE:
                stop += 1
            for offset in range(position, stop + 1):
                rva = run_rvas[offset]
                _name, category, code_rva = found[rva]
                slots.append(
                    CodePointerSlot(
                        rva=rva,
                        raw=common.rva_to_raw(pe, rva) or 0,
                        section=name,
                        category=category,
                        code_rva=code_rva,
                        run_length=stop - position + 1,
                        run_index=offset - position,
                    )
                )
            position = stop + 1
    slots.sort(key=lambda slot: slot.rva)
    return tuple(slots), inspected, per_section


def branch_annotation(
    form: str, target_kind: str, slot: CodePointerSlot | None, iat_slot: IatSlot | None
) -> str:
    if target_kind == "iat_slot" and iat_slot is not None:
        return f"rip_indirect_{form}_into_iat_slot+{iat_slot.evidence_suffix()}"
    if target_kind == "vtable_slot" and slot is not None:
        return (
            f"rip_indirect_{form}_into_readonly_code_pointer_slot"
            f"+run_length={slot.run_length}+run_index={slot.run_index}"
        )
    if target_kind == "global_fnptr_slot" and slot is not None:
        return (
            f"rip_indirect_{form}_into_writable_code_pointer_slot"
            f"+run_length={slot.run_length}+run_index={slot.run_index}"
        )
    if target_kind == "data":
        return f"rip_indirect_{form}_into_data_address_without_static_code_pointer"
    if target_kind == VIRTUAL_TAIL:
        return f"rip_indirect_{form}_into_loader_zero_fill_virtual_tail"
    return f"rip_indirect_{form}_target_outside_every_section_of_the_image"


def _branch(
    form: str,
    rva: int,
    raw: int,
    function: RuntimeFunction,
    target_rva: int,
    mnemonic: str,
    op_str: str,
    raw_bytes: str,
) -> Branch:
    return Branch(
        form=form,
        rva=rva,
        raw=raw,
        function_index=function.index,
        function_begin=function.begin,
        function_end=function.end,
        target_rva=target_rva,
        mnemonic=mnemonic,
        op_str=op_str,
        raw_bytes=raw_bytes,
    )


def decode_functions(
    pe: pefile.PE,
    payload: bytes,
    functions: list[RuntimeFunction],
    raw_call_iat: Mapping[int, int],
    thunk_iat: Mapping[int, int],
    fnptr_code_rvas: frozenset[int],
    slot_by_rva: Mapping[int, CodePointerSlot],
    iat_by_rva: Mapping[int, IatSlot],
    image_map: ImageMap,
) -> DecodeResult:
    """Linearly decode every runtime-function range and harvest xrefs and indirect sites.

    A raw ``FF 15`` candidate becomes an accepted direct xref only when the same RVA
    is reached here as a six-byte ``call`` at a linear instruction boundary. The same
    boundary test is applied to every raw ``FF 25`` import-thunk stub RVA, so a stub
    that is an interior byte of a longer instruction is recorded as such instead of
    being reported as a stub instruction of its own.
    """
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = False
    disasm = md.disasm
    reg_name = md.reg_name
    to_raw = common.rva_to_raw
    label_of = image_map.label

    direct_iat: list[Branch] = []
    direct_iat_slot: dict[int, int] = {}
    to_thunk: list[Branch] = []
    to_fnptr: list[Branch] = []
    sites: list[IndirectSite] = []
    decoded_rip_indirect: set[int] = set()
    uncatalogued_direct_calls = 0
    overlap_targets: set[int] = set()
    rex_w_iat_jmps = 0
    zero_instruction: list[RuntimeFunction] = []
    excluded_stores = 0
    excluded_mnemonics: Counter[str] = Counter()
    instruction_total = 0
    decoded_bytes = 0
    text = text_section(pe)
    text_begin = text.virtual_address
    text_end = text.virtual_end

    pending_stubs = sorted(thunk_iat)
    next_stub = 0
    placements: dict[int, ThunkStubPlacement] = {}

    for function in functions:
        blob = payload[function.raw_begin : function.raw_end]
        base = image_base + function.begin
        decoded_bytes += len(blob)
        count = 0
        for insn in disasm(blob, base):
            count += 1
            rva = insn.address - image_base
            mnemonic = insn.mnemonic
            operands = insn.operands
            is_call = insn.id == X86_INS_CALL
            is_jmp = insn.id == X86_INS_JMP
            raw = to_raw(pe, rva)
            raw = 0 if raw is None else raw
            raw_bytes = hex_bytes(insn.bytes)

            if next_stub < len(pending_stubs):
                stop = rva + insn.size
                while next_stub < len(pending_stubs) and pending_stubs[next_stub] < stop:
                    stub_rva = pending_stubs[next_stub]
                    if stub_rva >= rva:
                        placements[stub_rva] = ThunkStubPlacement(
                            rva=stub_rva,
                            at_instruction_boundary=stub_rva == rva,
                            covering_rva=rva,
                            covering_size=insn.size,
                            covering_mnemonic=mnemonic,
                            covering_first_byte=insn.bytes[0],
                            function_index=function.index,
                            function_begin=function.begin,
                            function_end=function.end,
                        )
                    next_stub += 1

            if is_call and insn.size == RIP_INDIRECT_SIZE and rva in raw_call_iat:
                target = raw_call_iat[rva]
                direct_iat_slot[rva] = target
                direct_iat.append(
                    _branch("call", rva, raw, function, target, mnemonic, insn.op_str, raw_bytes)
                )

            if operands and operands[0].type == X86_OP_IMM:
                if is_call or is_jmp:
                    form = "call" if is_call else "jmp"
                    target = operands[0].imm - image_base
                    # Capstone prints an immediate operand as a preferred-base VA; every address
                    # in this evidence set is an RVA, so the operand is rendered as an RVA.
                    # src_mnemonic already carries the verb, so src_op_str holds the operand only.
                    branch = _branch(
                        form, rva, raw, function, target, mnemonic, f"0x{target:x}", raw_bytes
                    )
                    if target in thunk_iat:
                        to_thunk.append(branch)
                        if target in fnptr_code_rvas:
                            overlap_targets.add(target)
                    elif target in fnptr_code_rvas:
                        to_fnptr.append(branch)
                    elif form == "call" and text_begin <= target < text_end:
                        uncatalogued_direct_calls += 1
                continue

            if (is_call or is_jmp) and operands:
                form = "call" if is_call else "jmp"
                site = decode_branch_site(
                    pe=pe,
                    insn=insn,
                    rva=rva,
                    raw=raw,
                    raw_bytes=raw_bytes,
                    function=function,
                    form=form,
                    slot_by_rva=slot_by_rva,
                    iat_by_rva=iat_by_rva,
                    image_map=image_map,
                    reg_name=reg_name,
                )
                if site is not None:
                    sites.append(site)
                    if site.operand_kind == "mem_rip":
                        decoded_rip_indirect.add(rva)
                        if (
                            site.target_kind == "iat_slot"
                            and insn.size == REX_W_INDIRECT_SIZE
                            and insn.bytes[0] == REX_W_PREFIX
                        ):
                            rex_w_iat_jmps += 1
                continue

            implicit_write = mnemonic.split(" ", 1)[-1] in IMPLICIT_WRITE_MNEMONICS
            for operand in operands:
                if operand.type != X86_OP_MEM:
                    continue
                if not (operand.access & CS_AC_WRITE or implicit_write):
                    continue
                memory = operand.mem
                if memory.base != X86_REG_RIP:
                    excluded_stores += 1
                    excluded_mnemonics[mnemonic] += 1
                    continue
                target = rva + insn.size + memory.disp
                target_kind, target_section, code_rva, iat_rva, module, symbol = classify_rip_target(
                    image_map, target, slot_by_rva, iat_by_rva
                )
                sites.append(
                    IndirectSite(
                        kind="write_rip",
                        source="pdata_decode",
                        insn_rva=rva,
                        insn_raw=raw,
                        code_instruction_function_index=function.index,
                        code_instruction_function_begin=function.begin,
                        code_instruction_function_end=function.end,
                        mnemonic=mnemonic,
                        op_str=insn.op_str,
                        raw_bytes=raw_bytes,
                        operand_kind="mem_rip",
                        operand_reg="",
                        mem_base="rip",
                        mem_index=reg_name(memory.index) or "",
                        mem_scale=str(memory.scale),
                        mem_disp=memory.disp,
                        target_kind=target_kind,
                        target_rva=target,
                        target_section=target_section,
                        target_code_rva=code_rva,
                        target_thunk_function_index=None,
                        target_thunk_function_begin=None,
                        target_thunk_function_end=None,
                        iat_rva=iat_rva,
                        module=module,
                        symbol=symbol,
                        annotation=WRITE_ANNOTATION.get(target_kind, WRITE_ANNOTATION["data"]),
                    )
                )

        if count == 0:
            zero_instruction.append(function)
        instruction_total += count

    return DecodeResult(
        functions=functions,
        direct_iat=direct_iat,
        direct_iat_slot=direct_iat_slot,
        to_thunk=to_thunk,
        to_fnptr=to_fnptr,
        sites=sites,
        decoded_rip_indirect=decoded_rip_indirect,
        thunk_stub_placements=placements,
        uncatalogued_direct_calls=uncatalogued_direct_calls,
        thunk_fnptr_overlap_targets=overlap_targets,
        rex_w_iat_jmps=rex_w_iat_jmps,
        zero_instruction_functions=tuple(zero_instruction),
        excluded_store_count=excluded_stores,
        excluded_store_mnemonics=excluded_mnemonics,
        instruction_total=instruction_total,
        decoded_bytes=decoded_bytes,
    )


def decode_branch_site(
    pe: pefile.PE,
    insn: Any,
    rva: int,
    raw: int,
    raw_bytes: str,
    function: RuntimeFunction,
    form: str,
    slot_by_rva: Mapping[int, CodePointerSlot],
    iat_by_rva: Mapping[int, IatSlot],
    image_map: ImageMap,
    reg_name: Any,
) -> IndirectSite | None:
    """Turn a decoded indirect call/jmp operand into an annotated site record."""
    operand = insn.operands[0]
    shared: dict[str, Any] = {
        "source": "pdata_decode",
        "insn_rva": rva,
        "insn_raw": raw,
        "code_instruction_function_index": function.index,
        "code_instruction_function_begin": function.begin,
        "code_instruction_function_end": function.end,
        "mnemonic": insn.mnemonic,
        "op_str": insn.op_str,
        "raw_bytes": raw_bytes,
    }
    unlabelled: dict[str, Any] = {
        "iat_rva": None,
        "module": "",
        "symbol": "",
        "target_code_rva": None,
    }

    if operand.type == X86_OP_REG:
        return IndirectSite(
            kind=f"{form}_reg",
            operand_kind="reg",
            operand_reg=reg_name(operand.reg) or "",
            mem_base="",
            mem_index="",
            mem_scale="",
            mem_disp=None,
            target_kind="reg",
            target_rva=None,
            target_section="",
            target_thunk_function_index=None,
            target_thunk_function_begin=None,
            target_thunk_function_end=None,
            annotation=f"register_indirect_{form}_target_not_statically_resolved",
            **unlabelled,
            **shared,
        )
    if operand.type != X86_OP_MEM:
        return None

    memory = operand.mem
    base_name = reg_name(memory.base) or ""
    index_name = reg_name(memory.index) or ""
    if memory.base == X86_REG_RIP:
        operand_kind = "mem_rip"
    elif memory.base == 0 and memory.index == 0:
        operand_kind = "mem_abs"
    else:
        operand_kind = "mem_base"

    if operand_kind != "mem_rip":
        shape = (
            f"+disp_multiple_of_{CODE_POINTER_STRIDE}=vtable_style_dispatch_shape"
            if memory.disp and memory.disp % CODE_POINTER_STRIDE == 0
            else ""
        )
        return IndirectSite(
            kind=f"{form}_{operand_kind}",
            operand_kind=operand_kind,
            operand_reg="",
            mem_base=base_name,
            mem_index=index_name,
            mem_scale=str(memory.scale),
            mem_disp=memory.disp,
            target_kind="unresolved",
            target_rva=None,
            target_section="",
            target_thunk_function_index=None,
            target_thunk_function_begin=None,
            target_thunk_function_end=None,
            annotation=f"memory_indirect_{form}_target_not_statically_resolved{shape}",
            **unlabelled,
            **shared,
        )

    target = rva + insn.size + memory.disp
    target_kind, target_section, code_rva, iat_rva, module, symbol = classify_rip_target(
        image_map, target, slot_by_rva, iat_by_rva
    )
    # A jmp that lands on an IAT slot is the import thunk itself, so the runtime
    # function that contains the instruction is also the function that contains
    # the target thunk; a call into the same slot is a direct CALL, not a thunk hop.
    is_thunk = form == "jmp" and target_kind == "iat_slot"
    return IndirectSite(
        kind=f"{form}_mem_rip",
        operand_kind="mem_rip",
        operand_reg="",
        mem_base="rip",
        mem_index=index_name,
        mem_scale=str(memory.scale),
        mem_disp=memory.disp,
        target_kind=target_kind,
        target_rva=target,
        target_section=target_section,
        target_code_rva=code_rva,
        target_thunk_function_index=function.index if is_thunk else None,
        target_thunk_function_begin=function.begin if is_thunk else None,
        target_thunk_function_end=function.end if is_thunk else None,
        iat_rva=iat_rva,
        module=module,
        symbol=symbol,
        annotation=branch_annotation(form, target_kind, slot_by_rva.get(target), iat_by_rva.get(target)),
        **shared,
    )


def build_raw_thunk_sites(
    pe: pefile.PE,
    payload: bytes,
    thunk_iat: Mapping[int, int],
    decoded: set[int],
    functions: Sequence[RuntimeFunction],
    begins: Sequence[int],
    iat_by_rva: Mapping[int, IatSlot],
    image_map: ImageMap,
    placements: Mapping[int, ThunkStubPlacement],
) -> list[IndirectSite]:
    """Sites for import-thunk stubs that no runtime-function range decodes.

    Doc 03 finds thunks with a raw scan, so a stub outside every .pdata range is
    still a real `jmp qword ptr [rip+disp]` instruction and is annotated as
    unanchored. A stub RVA that a runtime function does contain is a different
    case: the six-byte marker matched an interior byte of a longer instruction, so
    the row carries no code instruction of its own, names the covering instruction
    in its annotation, and reports the containing function in the target-thunk
    columns alone.
    """
    sites: list[IndirectSite] = []
    for stub_rva in sorted(thunk_iat):
        raw = common.rva_to_raw(pe, stub_rva)
        if raw is None:
            raise BuildError(f"import thunk RVA {common.hexs(stub_rva)} has no file backing")
        if stub_rva in decoded:
            continue
        placement = placements.get(stub_rva)
        owner = find_function(functions, begins, stub_rva)
        if placement is not None:
            if placement.at_instruction_boundary or owner is None or owner.index != placement.function_index:
                raise BuildError(
                    f"import thunk RVA {common.hexs(stub_rva)} placement disagrees with the runtime "
                    f"function that covers it"
                )
            annotation = f"{RAW_THUNK_INTERIOR_ANNOTATION}+{placement.evidence_suffix()}"
        else:
            if owner is not None:
                raise BuildError(
                    f"import thunk RVA {common.hexs(stub_rva)} lies inside runtime function {owner.index} "
                    "but no decoded instruction covers it"
                )
            annotation = RAW_THUNK_ANNOTATION
        slot = iat_by_rva[thunk_iat[stub_rva]]
        sites.append(
            IndirectSite(
                kind="jmp_mem_rip",
                source="raw_scan",
                insn_rva=stub_rva,
                insn_raw=raw,
                code_instruction_function_index=None,
                code_instruction_function_begin=None,
                code_instruction_function_end=None,
                mnemonic="jmp",
                op_str=f"qword ptr [rip + 0x{slot.rva - stub_rva - RIP_INDIRECT_SIZE:x}]",
                raw_bytes=hex_bytes(payload[raw : raw + RIP_INDIRECT_SIZE]),
                operand_kind="mem_rip",
                operand_reg="",
                mem_base="rip",
                mem_index="",
                mem_scale="1",
                mem_disp=slot.rva - stub_rva - RIP_INDIRECT_SIZE,
                target_kind="iat_slot",
                target_rva=slot.rva,
                target_section=image_map.raw_section(slot.rva) or UNMAPPED,
                target_code_rva=None,
                target_thunk_function_index=placement.function_index if placement else None,
                target_thunk_function_begin=placement.function_begin if placement else None,
                target_thunk_function_end=placement.function_end if placement else None,
                iat_rva=slot.rva,
                module=slot.module,
                symbol=slot.symbol,
                annotation=f"{annotation}+{slot.evidence_suffix()}",
            )
        )
    return sites


def build_rejected_sites(
    pe: pefile.PE,
    payload: bytes,
    rejected: Mapping[int, int],
    iat_by_rva: Mapping[int, IatSlot],
    image_map: ImageMap,
) -> tuple[list[IndirectSite], tuple[tuple[int, int, int, str], ...]]:
    """Sites for raw FF 15 candidates the .pdata plus boundary filter rejects.

    Doc 03 drops these candidates. They are emitted with an explicit rejection kind
    so the exclusion is auditable in the evidence set rather than only in prose.
    A rejected candidate is by definition not a decoded instruction, so no
    code-instruction function is named for it.
    """
    sites: list[IndirectSite] = []
    details: list[tuple[int, int, int, str]] = []
    for site_rva in sorted(rejected):
        raw = common.rva_to_raw(pe, site_rva)
        if raw is None:
            raise BuildError(f"rejected candidate RVA {common.hexs(site_rva)} has no file backing")
        target = rejected[site_rva]
        slot = iat_by_rva[target]
        details.append((site_rva, raw, target, f"{slot.module}!{slot.symbol}"))
        sites.append(
            IndirectSite(
                kind="raw_ff15_rejected",
                source="raw_scan",
                insn_rva=site_rva,
                insn_raw=raw,
                code_instruction_function_index=None,
                code_instruction_function_begin=None,
                code_instruction_function_end=None,
                mnemonic="",
                op_str="",
                raw_bytes=hex_bytes(payload[raw : raw + RIP_INDIRECT_SIZE]),
                operand_kind="mem_rip",
                operand_reg="",
                mem_base="rip",
                mem_index="",
                mem_scale="1",
                mem_disp=target - site_rva - RIP_INDIRECT_SIZE,
                target_kind="rejected",
                target_rva=target,
                target_section=image_map.raw_section(target) or UNMAPPED,
                target_code_rva=None,
                target_thunk_function_index=None,
                target_thunk_function_begin=None,
                target_thunk_function_end=None,
                iat_rva=target,
                module=slot.module,
                symbol=slot.symbol,
                annotation=f"{REJECTED_ANNOTATION}+{slot.evidence_suffix()}",
            )
        )
    return sites, tuple(details)


def build_edges(
    pe: pefile.PE,
    payload: bytes,
    slots: Sequence[IatSlot],
    iat_by_rva: Mapping[int, IatSlot],
    thunk_iat: Mapping[int, int],
    code_slots: Sequence[CodePointerSlot],
    sites: Sequence[IndirectSite],
    decode: DecodeResult,
    direct_slots: frozenset[int],
    thunk_slots: frozenset[int],
    functions: Sequence[RuntimeFunction],
    begins: Sequence[int],
) -> list[Edge]:
    """Assemble the stable src -> target edge set over catalogued nodes.

    A thunk target is resolved to its owning runtime function through
    ``.pdata`` containment, which is independent of whether the source instruction
    was decoded: a rel32 edge always has a decoded source, and a thunk stub edge
    never does, because a stub RVA that a runtime function contains is an interior
    byte of a longer instruction rather than a jump of its own.
    """
    edges: list[Edge] = []
    slot_by_rva = {slot.rva: slot for slot in code_slots}
    thunk_owner = {
        rva: find_function(functions, begins, rva) for rva in sorted(thunk_iat)
    }

    for branch in decode.direct_iat:
        slot = iat_by_rva[branch.target_rva]
        edges.append(
            Edge(
                category="iat",
                relation="call_indirect_iat",
                evidence=f"pdata_boundary+raw_ff15+iat_slot_target+{slot.evidence_suffix()}",
                src_rva=branch.rva,
                src_raw=branch.raw,
                code_instruction_function_index=branch.function_index,
                code_instruction_function_begin=branch.function_begin,
                code_instruction_function_end=branch.function_end,
                src_mnemonic=branch.mnemonic,
                src_op_str=branch.op_str,
                src_bytes=branch.raw_bytes,
                via_rva=None,
                target_thunk_function_index=None,
                target_thunk_function_begin=None,
                target_thunk_function_end=None,
                dst_kind="iat_slot",
                dst_rva=slot.rva,
                dst_raw=slot.raw,
                dst_module=slot.module,
                dst_symbol=slot.symbol,
                iat_rva=slot.rva,
            )
        )

    for slot in slots:
        evidence = (
            f"iat_directory_binding+{slot.reach_evidence(slot.rva in direct_slots, slot.rva in thunk_slots)}"
            f"+{slot.evidence_suffix()}"
        )
        edges.append(
            Edge(
                category="iat",
                relation="iat_slot_symbol_binding",
                evidence=evidence,
                src_rva=slot.rva,
                src_raw=slot.raw,
                code_instruction_function_index=None,
                code_instruction_function_begin=None,
                code_instruction_function_end=None,
                src_mnemonic="",
                src_op_str="",
                src_bytes="",
                via_rva=None,
                target_thunk_function_index=None,
                target_thunk_function_begin=None,
                target_thunk_function_end=None,
                dst_kind="external",
                dst_rva=None,
                dst_raw=None,
                dst_module=slot.module,
                dst_symbol=slot.symbol,
                iat_rva=slot.rva,
            )
        )

    for branch in decode.to_thunk:
        slot_rva = thunk_iat[branch.target_rva]
        slot = iat_by_rva[slot_rva]
        owner = thunk_owner[branch.target_rva]
        edges.append(
            Edge(
                category="thunk",
                relation=THUNK_RELATION[branch.form],
                evidence=f"pdata_boundary+{branch.form}_rel+import_thunk_target+{slot.evidence_suffix()}",
                src_rva=branch.rva,
                src_raw=branch.raw,
                code_instruction_function_index=branch.function_index,
                code_instruction_function_begin=branch.function_begin,
                code_instruction_function_end=branch.function_end,
                src_mnemonic=branch.mnemonic,
                src_op_str=branch.op_str,
                src_bytes=branch.raw_bytes,
                via_rva=branch.target_rva,
                target_thunk_function_index=owner.index if owner is not None else None,
                target_thunk_function_begin=owner.begin if owner is not None else None,
                target_thunk_function_end=owner.end if owner is not None else None,
                dst_kind="code",
                dst_rva=branch.target_rva,
                dst_raw=common.rva_to_raw(pe, branch.target_rva),
                dst_module=slot.module,
                dst_symbol=slot.symbol,
                iat_rva=slot_rva,
            )
        )

    for stub_rva in sorted(thunk_iat):
        slot = iat_by_rva[thunk_iat[stub_rva]]
        raw = common.rva_to_raw(pe, stub_rva) or 0
        owner = thunk_owner[stub_rva]
        edges.append(
            Edge(
                category="thunk",
                relation="iat_jmp_thunk_stub",
                evidence=f"raw_ff25_scan+iat_slot_target+{slot.evidence_suffix()}",
                src_rva=stub_rva,
                src_raw=raw,
                code_instruction_function_index=None,
                code_instruction_function_begin=None,
                code_instruction_function_end=None,
                src_mnemonic="jmp",
                src_op_str=f"qword ptr [rip + 0x{slot.rva - stub_rva - RIP_INDIRECT_SIZE:x}]",
                src_bytes=hex_bytes(payload[raw : raw + RIP_INDIRECT_SIZE]),
                via_rva=None,
                target_thunk_function_index=owner.index if owner is not None else None,
                target_thunk_function_begin=owner.begin if owner is not None else None,
                target_thunk_function_end=owner.end if owner is not None else None,
                dst_kind="iat_slot",
                dst_rva=slot.rva,
                dst_raw=slot.raw,
                dst_module=slot.module,
                dst_symbol=slot.symbol,
                iat_rva=slot.rva,
            )
        )

    for branch in decode.to_fnptr:
        edges.append(
            Edge(
                category="direct_call" if branch.form == "call" else "direct_jmp",
                relation=DIRECT_RELATION[branch.form],
                evidence=f"pdata_boundary+{branch.form}_rel+code_pointer_slot_target",
                src_rva=branch.rva,
                src_raw=branch.raw,
                code_instruction_function_index=branch.function_index,
                code_instruction_function_begin=branch.function_begin,
                code_instruction_function_end=branch.function_end,
                src_mnemonic=branch.mnemonic,
                src_op_str=branch.op_str,
                src_bytes=branch.raw_bytes,
                via_rva=None,
                target_thunk_function_index=None,
                target_thunk_function_begin=None,
                target_thunk_function_end=None,
                dst_kind="code",
                dst_rva=branch.target_rva,
                dst_raw=common.rva_to_raw(pe, branch.target_rva),
                dst_module="",
                dst_symbol="",
                iat_rva=None,
            )
        )

    for slot in code_slots:
        edges.append(
            Edge(
                category=slot.category,
                relation="fnptr_slot_code_target",
                evidence=(
                    f"data_section_code_pointer_slot+section={slot.section}"
                    f"+run_length={slot.run_length}+run_index={slot.run_index}"
                ),
                src_rva=slot.rva,
                src_raw=slot.raw,
                code_instruction_function_index=None,
                code_instruction_function_begin=None,
                code_instruction_function_end=None,
                src_mnemonic="",
                src_op_str="",
                src_bytes=hex_bytes(payload[slot.raw : slot.raw + CODE_POINTER_STRIDE]),
                via_rva=None,
                target_thunk_function_index=None,
                target_thunk_function_begin=None,
                target_thunk_function_end=None,
                dst_kind="code",
                dst_rva=slot.code_rva,
                dst_raw=common.rva_to_raw(pe, slot.code_rva),
                dst_module="",
                dst_symbol="",
                iat_rva=None,
            )
        )

    for site in sites:
        if site.target_kind not in ("vtable_slot", "global_fnptr_slot") or site.target_rva is None:
            continue
        if site.kind.startswith("write"):
            continue
        slot = slot_by_rva[site.target_rva]
        form = "call" if site.kind.startswith("call") else "jmp"
        edges.append(
            Edge(
                category=slot.category,
                relation=f"{form}_indirect_fnptr",
                evidence=site.annotation,
                src_rva=site.insn_rva,
                src_raw=site.insn_raw,
                code_instruction_function_index=site.code_instruction_function_index,
                code_instruction_function_begin=site.code_instruction_function_begin,
                code_instruction_function_end=site.code_instruction_function_end,
                src_mnemonic=site.mnemonic,
                src_op_str=site.op_str,
                src_bytes=site.raw_bytes,
                via_rva=slot.rva,
                target_thunk_function_index=None,
                target_thunk_function_begin=None,
                target_thunk_function_end=None,
                dst_kind="fnptr_slot",
                dst_rva=slot.rva,
                dst_raw=slot.raw,
                dst_module="",
                dst_symbol="",
                iat_rva=site.iat_rva,
            )
        )

    edges.sort(key=Edge.sort_key)
    return edges


def zero_instruction_detail(pe: pefile.PE, functions: Sequence[RuntimeFunction]) -> tuple[int, int, str, str]:
    """Characterise runtime-function ranges whose linear decode yields no instruction.

    The leading byte decides the outcome, so it is reported together with the
    ModRM byte that follows it: in 64-bit mode ``C7`` has exactly one defined form,
    ``C7 /0``, so a non-zero ModRM.reg field makes the first byte undecodable and
    the linear decode stops there. The bytes after it are then not decoded at all,
    which is a statement about the decode, not about the data, so the structural
    shape of the range is reported separately instead of being classified.
    """
    if not functions:
        return 0, 0, "none", "none"
    function = functions[0]
    blob = pe.__data__[function.raw_begin : function.raw_end]
    has_marker = any(marker in blob for marker in INDIRECT_MARKER_BYTES)
    leading = blob[0]
    modrm = blob[1] if len(blob) > 1 else 0
    detail = (
        f"index={function.index} rva={common.hexs(function.begin)}-{common.hexs(function.end)} "
        f"bytes={function.byte_length} first8={hex_bytes(blob[:8])} "
        f"has_ff15_or_ff25={has_marker} e8_byte_count={blob.count(bytes([CALL_REL32_OPCODE]))} "
        f"leading_opcode=0x{leading:02x} modrm=0x{modrm:02x} modrm_reg={(modrm >> 3) & 7} "
        f"undecoded_tail_bytes={max(len(blob) - 1, 0)}"
    )
    return (
        len(functions),
        sum(item.byte_length for item in functions),
        detail,
        zero_instruction_shape(blob),
    )


def zero_instruction_shape(blob: bytes) -> str:
    """Report the observable byte shape of a range that decodes to no instruction.

    Nothing here interprets the bytes. It records only what is measurable: how many
    leading 32-bit words share their upper halfword, and the value set of the bytes
    behind them, so a reader can see the structure a data table would produce
    without the tool asserting what the table encodes.
    """
    if not blob:
        return "empty"
    counted = min(len(blob), U32_ANNOTATION_WORDS * U32_ANNOTATION_STRIDE)
    words = [
        struct.unpack_from("<I", blob, offset)[0]
        for offset in range(0, counted - U32_ANNOTATION_STRIDE + 1, U32_ANNOTATION_STRIDE)
    ]
    tail = blob[counted:]
    parts = [f"leading_u32_words={len(words)}"]
    if words:
        parts.append(f"leading_u32_upper_halfwords={len({word >> 16 for word in words})}")
        parts.append(
            f"leading_u32_lower_halfword_range=0x{min(word & 0xFFFF for word in words):04x}"
            f"..0x{max(word & 0xFFFF for word in words):04x}"
        )
    parts.append(f"trailing_bytes={len(tail)}")
    if tail:
        parts.append(f"trailing_byte_values={min(tail)}..{max(tail)}")
        parts.append(f"trailing_distinct_values={len(set(tail))}")
    return "+".join(parts)


def build(pe: pefile.PE) -> BuildResult:
    """Run the whole static xref pass and return the deterministic build output."""
    payload = pe.__data__
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)

    slots, int_equal, name_check = load_iat_slots(pe)
    iat_by_rva = {slot.rva: slot for slot in slots}
    iat_rvas = frozenset(iat_by_rva)
    raw_call_iat, thunk_iat = scan_text_markers(pe, iat_rvas)

    code_slots, slots_inspected, slots_per_section = collect_code_pointer_slots(pe, payload)
    slot_by_rva = {slot.rva: slot for slot in code_slots}
    fnptr_code_rvas = frozenset(slot.code_rva for slot in code_slots)
    image_map = ImageMap.from_pe(pe)

    records = read_runtime_functions(pe)
    functions, begins = build_function_index(pe, records)
    decode = decode_functions(
        pe=pe,
        payload=payload,
        functions=functions,
        raw_call_iat=raw_call_iat,
        thunk_iat=thunk_iat,
        fnptr_code_rvas=fnptr_code_rvas,
        slot_by_rva=slot_by_rva,
        iat_by_rva=iat_by_rva,
        image_map=image_map,
    )

    raw_thunk_sites = build_raw_thunk_sites(
        pe,
        payload,
        thunk_iat,
        decode.decoded_rip_indirect,
        functions,
        begins,
        iat_by_rva,
        image_map,
        decode.thunk_stub_placements,
    )
    rejected = {rva: raw_call_iat[rva] for rva in sorted(set(raw_call_iat) - set(decode.direct_iat_slot))}
    rejected_sites, rejected_details = build_rejected_sites(pe, payload, rejected, iat_by_rva, image_map)
    sites = sorted(decode.sites + raw_thunk_sites + rejected_sites, key=IndirectSite.sort_key)

    thunk_calls = [branch for branch in decode.to_thunk if branch.form == "call"]
    thunk_jmps = [branch for branch in decode.to_thunk if branch.form == "jmp"]
    direct_slots = frozenset(decode.direct_iat_slot.values())
    thunk_slots = frozenset(thunk_iat[branch.target_rva] for branch in thunk_calls)
    touched = direct_slots | thunk_slots
    thunks_reached = frozenset(branch.target_rva for branch in thunk_calls)
    xref_functions = {branch.function_index for branch in decode.direct_iat} | {
        branch.function_index for branch in thunk_calls
    }
    xref_bytes = sum(functions[index].byte_length for index in xref_functions)
    delay_slots = [rva for rva in direct_slots if iat_by_rva[rva].is_delay]
    delay_call_rva = min(
        (branch.rva for branch in decode.direct_iat if iat_by_rva[branch.target_rva].is_delay),
        default=-1,
    )
    empty_count, empty_bytes, empty_detail, empty_shape = zero_instruction_detail(
        pe, decode.zero_instruction_functions
    )

    placements = decode.thunk_stub_placements
    stub_at_boundary = sum(1 for item in placements.values() if item.at_instruction_boundary)
    stub_inside = sum(1 for rva in thunk_iat if find_function(functions, begins, rva) is not None)
    stub_outside = len(thunk_iat) - stub_inside
    stub_interior = sum(1 for rva in thunk_iat if rva in placements and not placements[rva].at_instruction_boundary)
    stub_shapes = Counter(
        (
            item.rva - item.covering_rva,
            item.covering_size,
            item.covering_mnemonic,
            item.covering_first_byte,
        )
        for item in placements.values()
    )
    stub_shape_text = (
        ";".join(
            f"byte_offset={offset},size={size},mnemonic={mnemonic},first_byte=0x{first:02x},count={count}"
            for (offset, size, mnemonic, first), count in sorted(stub_shapes.items())
        )
        or "none"
    )
    interior_targets = {
        branch.target_rva
        for branch in decode.to_thunk
        if branch.target_rva in placements and not placements[branch.target_rva].at_instruction_boundary
    }

    site_counter: Counter[tuple[str, str]] = Counter((site.kind, site.target_kind) for site in sites)
    branch_sites = sum(count for (kind, _), count in site_counter.items() if not kind.startswith("write"))
    write_sites = sum(count for (kind, _), count in site_counter.items() if kind.startswith("write"))
    fnptr_sites = sum(
        count for (kind, target), count in site_counter.items() if target in ("vtable_slot", "global_fnptr_slot")
    )
    iat_indirect_sites = sum(count for (_k, target), count in site_counter.items() if target == "iat_slot")
    stats_iat_jmps = sum(
        count for (kind, target), count in site_counter.items() if kind.startswith("jmp") and target == "iat_slot"
    )

    stats: dict[str, Any] = {
        "image_base": image_base,
        "runtime_function_count": len(functions),
        "runtime_function_record_size": RUNTIME_FUNCTION_SIZE,
        "runtime_function_decoded_bytes": decode.decoded_bytes,
        "runtime_function_instruction_total": decode.instruction_total,
        "runtime_functions_without_instructions": empty_count,
        "runtime_functions_without_instructions_bytes": empty_bytes,
        "runtime_functions_without_instructions_detail": empty_detail or "none",
        "runtime_functions_without_instructions_shape": empty_shape,
        "iat_slot_count_total": len(slots),
        "iat_slot_count_regular": sum(1 for slot in slots if not slot.is_delay),
        "iat_slot_count_delay": sum(1 for slot in slots if slot.is_delay),
        "iat_slots_ordinal_only": sum(1 for slot in slots if slot.ordinal is not None),
        "iat_slots_with_secondary_ordlookup_name": sum(1 for slot in slots if slot.secondary_name),
        "import_name_max_bytes": name_check.longest_file_bytes,
        "import_name_library_mismatch_count": name_check.mismatches,
        "import_name_library_mismatch_iat_rvas": [
            common.hexs(rva) for rva in name_check.mismatch_iat_rvas
        ],
        "int_equals_iat_qword": int_equal,
        "raw_direct_call_iat_candidates": len(raw_call_iat),
        "raw_direct_call_iat_rejected": len(rejected),
        "direct_call_iat_xrefs": len(decode.direct_iat),
        "direct_call_iat_xrefs_regular": len(decode.direct_iat) - len(delay_slots),
        "direct_call_iat_xrefs_delay": len(delay_slots),
        "import_thunk_count": len(thunk_iat),
        "thunk_mediated_call_xrefs": len(thunk_calls),
        "thunks_reached_by_call": len(thunks_reached),
        "total_statistical_call_xrefs": len(decode.direct_iat) + len(thunk_calls),
        "iat_slots_reached_direct": len(direct_slots),
        "iat_slots_reached_via_thunk": len(thunk_slots),
        "iat_slots_touched": len(touched),
        "iat_slots_untouched": len(slots) - len(touched),
        "xref_runtime_functions": len(xref_functions),
        "xref_runtime_function_bytes": xref_bytes,
        "delay_xref_call_rva": delay_call_rva,
        "delay_xref_iat_rva": sorted(delay_slots)[0] if delay_slots else -1,
        "thunk_jmp_rel_edges": len(thunk_jmps),
        "thunk_stub_rvas_at_a_decoded_instruction_boundary": stub_at_boundary,
        "thunk_stub_rvas_inside_a_pdata_function": stub_inside,
        "thunk_stub_rvas_outside_every_pdata_function": stub_outside,
        "thunk_stub_rvas_inside_a_pdata_function_without_a_decoded_boundary": stub_interior,
        "thunk_stub_covering_instruction_shapes": stub_shape_text,
        "thunk_edges_targeting_a_stub_without_a_decoded_boundary": sum(
            1 for branch in decode.to_thunk if branch.target_rva in interior_targets
        ),
        "rex_w_prefixed_iat_jmps": decode.rex_w_iat_jmps,
        "iat_jmp_sites_total": stats_iat_jmps,
        "thunk_rvas_also_fnptr_slot_targets": len(decode.thunk_fnptr_overlap_targets),
        "thunk_target_iat_slots": len({thunk_iat[rva] for rva in thunk_iat}),
        "iat_slots_with_multiple_thunks": sum(
            1 for slot in slots if len({rva for rva, target in thunk_iat.items() if target == slot.rva}) > 1
        ),
        "code_pointer_slots_inspected": slots_inspected,
        "code_pointer_slots_total": len(code_slots),
        "code_pointer_slots_vtable": sum(1 for slot in code_slots if slot.category == "vtable"),
        "code_pointer_slots_global_fnptr": sum(1 for slot in code_slots if slot.category == "global_fnptr"),
        "code_pointer_slots_isolated": sum(1 for slot in code_slots if slot.run_length == 1),
        "code_pointer_slot_runs_of_two_or_more": len(
            {slot.rva - slot.run_index * CODE_POINTER_STRIDE for slot in code_slots if slot.run_length > 1}
        ),
        "code_pointer_slot_targets": len(fnptr_code_rvas),
        "direct_call_fnptr_edges": sum(1 for branch in decode.to_fnptr if branch.form == "call"),
        "direct_jmp_fnptr_edges": sum(1 for branch in decode.to_fnptr if branch.form == "jmp"),
        "fnptr_slot_code_edges": len(code_slots),
        "indirect_branch_sites": branch_sites,
        "indirect_branch_sites_iat_slot": iat_indirect_sites,
        "indirect_branch_sites_fnptr_slot": fnptr_sites,
        "write_sites_rip": write_sites,
        "write_sites_unresolvable": decode.excluded_store_count,
        "rejected_candidate_targets": sorted({detail[3] for detail in rejected_details}),
        "rejected_candidate_inside_pdata": sum(
            1 for rva in rejected if find_function(functions, begins, rva) is not None
        ),
    }
    for name, count in sorted(slots_per_section.items()):
        stats[f"code_pointer_slots_in_{name}"] = count
    for kind, target in sorted(site_counter):
        stats[f"site_count_{kind}_to_{target}"] = site_counter[(kind, target)]

    edges = build_edges(
        pe=pe,
        payload=payload,
        slots=slots,
        iat_by_rva=iat_by_rva,
        thunk_iat=thunk_iat,
        code_slots=code_slots,
        sites=sites,
        decode=decode,
        direct_slots=direct_slots,
        thunk_slots=thunk_slots,
        functions=functions,
        begins=begins,
    )
    edge_counter_final: Counter[tuple[str, str]] = Counter(
        (edge.category, edge.relation) for edge in edges
    )
    stats["edge_count_total"] = len(edges)
    for (category, relation), count in sorted(edge_counter_final.items()):
        stats[f"edge_count_{category}_{relation}"] = count
    stats["direct_call_rel32_to_uncatalogued_code"] = decode.uncatalogued_direct_calls

    return BuildResult(edges=edges, sites=sites, stats=stats, rejected=rejected_details)


def build_divergences(stats: Mapping[str, Any]) -> tuple[Divergence, ...]:
    """Record every difference from, extension of, and boundary around doc 03.

    Nothing here is applied to the counts: each entry states the doc 03 claim, what
    this run observed, the impact on the published figures and how the item is
    handled.
    """
    zero_detail = str(stats["runtime_functions_without_instructions_detail"])
    if len(zero_detail) > MAX_DETAIL_CHARS:
        zero_detail = zero_detail[: MAX_DETAIL_CHARS - 3] + "..."
    empty = stats["runtime_functions_without_instructions"]
    return (
        Divergence(
            identifier="D01",
            kind="reproduced",
            doc03_ref=f"{DOC03_METHOD} exclusion note",
            doc03_claim=(
                "pure jmp [IAT] jumps, MOV/LEA reads of an IAT address, function-pointer data transfer "
                "and unproven register-indirect CALLs are outside the doc 03 lists"
            ),
            observed=(
                f"{stats['raw_direct_call_iat_candidates']} raw FF 15 candidates resolve onto an IAT slot, "
                f"{stats['raw_direct_call_iat_rejected']} are rejected by the .pdata plus linear-boundary "
                f"filter, {stats['direct_call_iat_xrefs']} are accepted; the rejected set targets only "
                f"{', '.join(stats['rejected_candidate_targets'])} and "
                f"{stats['rejected_candidate_inside_pdata']} of {stats['raw_direct_call_iat_rejected']} lie "
                "inside a runtime function range"
            ),
            impact=(
                "none; the doc 03 accepted set is reproduced exactly and is not widened by this step"
            ),
            disposition=(
                "rejected candidates are emitted to indirect_sites.csv with kind=raw_ff15_rejected so the "
                "exclusion is auditable in the evidence set instead of only in prose"
            ),
        ),
        Divergence(
            identifier="D02",
            kind="divergence",
            doc03_ref=f"{DOC03_METHOD} decode sentence",
            doc03_claim=(
                f"all {stats['runtime_function_count']} .pdata runtime-function ranges were linearly decoded "
                "from BeginAddress to EndAddress with Capstone"
            ),
            observed=(
                f"{stats['runtime_function_count'] - empty} of {stats['runtime_function_count']} ranges yield "
                f"at least one instruction and {empty} yields none: {zero_detail}"
            ),
            impact=(
                f"{stats['runtime_functions_without_instructions_bytes']} byte(s) are covered by no decoded "
                "instruction; the range holds no FF 15, FF 25 or usable E8 rel32 marker, so no published xref "
                f"figure changes; the byte shape is {stats['runtime_functions_without_instructions_shape']}"
            ),
            disposition=(
                "not repaired and not skipped; the range is still decoded and the zero-instruction outcome is "
                "asserted in the report. The decode stops on the first byte, not on the whole range: that byte is "
                "C7, whose only defined 64-bit form is C7 /0, and the ModRM.reg field of the following byte is "
                "non-zero, so the first byte alone is undecodable. The bytes behind it are therefore left "
                "undecoded rather than classified, and the shape reported above is a measurement of those bytes, "
                "not a claim about what they encode"
            ),
        ),
        Divergence(
            identifier="D03",
            kind="observation",
            doc03_ref=f"{DOC03_SUMMARY} import-thunk row",
            doc03_claim=(
                f"{stats['import_thunk_count']} FF 25 import thunks, of which "
                f"{stats['thunks_reached_by_call']} are reached by at least one statistical CALL xref"
            ),
            observed=(
                f"{stats['import_thunk_count']} thunks and {stats['thunks_reached_by_call']} CALL-reached thunks "
                f"reproduce exactly, but the stubs resolve onto only {stats['thunk_target_iat_slots']} distinct "
                f"IAT slots, so {stats['iat_slots_with_multiple_thunks']} slot(s) carry more than one stub"
            ),
            impact="none; 355, 193 and 193 all reproduce exactly",
            disposition="recorded only; no doc 03 figure is revised",
        ),
        Divergence(
            identifier="D04",
            kind="observation",
            doc03_ref=f"{DOC03_METHOD} importthunk-marker sentence",
            doc03_claim=(
                f"the {stats['import_thunk_count']} six-byte FF 25 sequences are found by a raw scan, without a "
                ".pdata anchor"
            ),
            observed=(
                f"{stats['thunk_stub_rvas_at_a_decoded_instruction_boundary']} of the "
                f"{stats['import_thunk_count']} stub RVAs is the first byte of a decoded instruction; "
                f"{stats['thunk_stub_rvas_inside_a_pdata_function']} lie inside a .pdata runtime-function range "
                f"and {stats['thunk_stub_rvas_outside_every_pdata_function']} lie outside every range, and all "
                f"{stats['thunk_stub_rvas_inside_a_pdata_function_without_a_decoded_boundary']} of the inside "
                f"ones sit at an interior byte of a longer instruction "
                f"({stats['thunk_stub_covering_instruction_shapes']}), the REX.W jmp-through-IAT form of D09"
            ),
            impact=(
                f"none on any published figure; the {stats['import_thunk_count']} stub count is defined over the "
                f"raw six-byte marker with no alignment rule, so the {stats['thunk_mediated_call_xrefs']} "
                f"thunk-mediated CALL xrefs and the {stats['thunks_reached_by_call']} CALL-reached thunks are "
                f"unchanged, and {stats['thunk_edges_targeting_a_stub_without_a_decoded_boundary']} rel32 edge(s) "
                "target such a stub RVA. What is corrected is the provenance record: such a stub is not a jump "
                "instruction of its own, so it is no longer described as one"
            ),
            disposition=(
                "recorded only; a stub that no runtime function covers keeps the unanchored annotation, and a "
                "stub whose RVA a runtime function covers is annotated as an interior byte of the decoded "
                "instruction that covers it, with the code-instruction function columns left empty and the "
                "target-thunk function columns naming the containing record, so no row's annotation contradicts "
                "its own columns"
            ),
        ),
        Divergence(
            identifier="D05",
            kind="extension",
            doc03_ref=f"{DOC03_METHOD} exclusion note and {DOC03_TABLES}",
            doc03_claim=(
                f"the doc 03 CALL lists are closed over call [IAT] and call rel32 through an import thunk, so "
                f"the {stats['thunk_mediated_call_xrefs']} figure is CALL-only"
            ),
            observed=(
                f"this step additionally emits {stats['thunk_jmp_rel_edges']} direct jmp rel edges into import "
                f"thunks, {stats['direct_call_fnptr_edges']} direct call and {stats['direct_jmp_fnptr_edges']} "
                f"direct jmp edges into code-pointer-slot targets, {stats['fnptr_slot_code_edges']} "
                f"slot-to-code edges and {stats['indirect_branch_sites']} indirect branch sites"
            ),
            impact=(
                "none on the doc 03 figures; the doc 03 counts stay CALL-only and are reported unchanged "
                "alongside the extra edge categories"
            ),
            disposition="extension recorded; the doc 03 numbers are not restated or merged",
        ),
        Divergence(
            identifier="D06",
            kind="scope-boundary",
            doc03_ref=f"{DOC03_TABLES} publishes only the import-mediated CALL xrefs",
            doc03_claim="the unrestricted intra-image direct call graph is not published",
            observed=(
                f"{stats['direct_call_rel32_to_uncatalogued_code']} decoded call rel32 sites target in-image code "
                "that is neither an import thunk nor a code-pointer-slot target"
            ),
            impact=(
                "direct_call and direct_jmp edges are closed over catalogued nodes only, so those call sites "
                "have no src -> target edge in xref_edges.csv"
            ),
            disposition="counted as a bounded negative rather than silently dropped",
        ),
        Divergence(
            identifier="D07",
            kind="scope-boundary",
            doc03_ref=f"{DOC03_METHOD} exclusion note",
            doc03_claim="function-pointer data transfer and writable-slot mutation are outside the doc 03 lists",
            observed=(
                f"{stats['write_sites_rip']} RIP-relative write sites are enumerated; "
                f"{stats['write_sites_unresolvable']} stores through a base register are counted only"
            ),
            impact=(
                "a base-register store has no statically resolvable destination, so it cannot yield a stable "
                "src -> target edge or a slot annotation; a resolved write site is recorded in "
                "indirect_sites.csv and deliberately produces no control-flow edge in xref_edges.csv"
            ),
            disposition="counted as a bounded negative rather than silently dropped",
        ),
        Divergence(
            identifier="D08",
            kind="reproduced",
            doc03_ref=f"{DOC03_CHECKS} INT=IAT row",
            doc03_claim=(
                f"INT=IAT qword pairs: expected {stats['iat_slot_count_regular']}, actual "
                f"{stats['iat_slot_count_regular']}"
            ),
            observed=(
                f"{stats['int_equals_iat_qword']} of {stats['iat_slot_count_regular']} regular INT/IAT qword pairs "
                "compare byte-equal"
            ),
            impact=(
                "none; this is the input precondition for the IAT slot table the whole xref pass consumes"
            ),
            disposition="reproduced and asserted before any xref is emitted",
        ),
        Divergence(
            identifier="D09",
            kind="divergence",
            doc03_ref=f"{DOC03_METHOD} importthunk-marker sentence and {DOC03_DELAY}",
            doc03_claim=(
                f"an importthunk marker is a six-byte FF 25 disp32 sequence, giving "
                f"{stats['import_thunk_count']} thunks"
            ),
            observed=(
                f"the six-byte definition misses {stats['rex_w_prefixed_iat_jmps']} REX.W-prefixed "
                f"48 FF 25 disp32 jmp qword ptr [rip+disp] instructions that Capstone decodes inside "
                f".pdata ranges and that land on an IAT slot; the complete set of jmp-through-IAT sites is "
                f"therefore {stats['iat_jmp_sites_total']} = {stats['import_thunk_count']} six-byte stubs + "
                f"{stats['rex_w_prefixed_iat_jmps']} REX.W sites"
            ),
            impact=(
                f"none on the published figures: the {stats['import_thunk_count']} thunk and "
                f"{stats['thunk_mediated_call_xrefs']} thunk-mediated CALL counts are defined over the "
                "six-byte marker and reproduce exactly, and none of the REX.W sites is a CALL"
            ),
            disposition=(
                "not folded into the import_thunk_count and not silently dropped: the six-byte definition is "
                "kept verbatim, the REX.W sites are emitted to indirect_sites.csv as jmp_mem_rip rows with "
                "target_kind=iat_slot, and the split is reported by rex_w_prefixed_iat_jmps and "
                "iat_jmp_sites_total"
            ),
        ),
        Divergence(
            identifier="D10",
            kind="observation",
            doc03_ref=f"{DOC03_TABLES} thunk and slot coverage",
            doc03_claim="doc 03 does not state how import thunks and code-pointer slots can overlap",
            observed=(
                f"{stats['thunk_rvas_also_fnptr_slot_targets']} thunk RVAs are also the static code target of a "
                "read-only or writable code-pointer slot, so those direct branches satisfy both catalogs"
            ),
            impact=(
                "direct_call and direct_jmp edges would double count these branches if both catalogs claimed "
                "them, because the doc 03 thunk counts must stay exact"
            ),
            disposition=(
                "the thunk category takes precedence by construction; such a branch is emitted once, as a "
                "thunk edge, and the overlap is counted by thunk_rvas_also_fnptr_slot_targets"
            ),
        ),
        Divergence(
            identifier="D11",
            kind="tool-boundary",
            doc03_ref=f"{DOC03_TABLES} import symbol column",
            doc03_claim="every import name in the two doc 03 xref tables is the name the file holds",
            observed=(
                f"the longest import name in the specimen is {stats['import_name_max_bytes']} bytes, and "
                f"pefile's import-name field differs from the file for exactly "
                f"{stats['import_name_library_mismatch_count']} of {stats['iat_slot_count_regular']} regular "
                f"entries ({', '.join(stats['import_name_library_mismatch_iat_rvas'])}), because that field is "
                "capped and truncates the one name above the cap; the doc 03 cell for the same entry is "
                f"{stats['import_name_max_bytes']} bytes and byte-identical to the file"
            ),
            impact=(
                "symbol identity for that one slot would be silently wrong in xref_edges.csv and in the "
                "dll/symbol columns of indirect_sites.csv if the library field were used directly"
            ),
            disposition=(
                "doc 03 is confirmed correct and is not modified; this step reads the IMAGE_IMPORT_BY_NAME "
                "record straight from the file for every regular slot, so the published symbol identity is "
                "file-backed, and the divergence from the library field is measured on each run"
            ),
        ),
        Divergence(
            identifier="D12",
            kind="observation",
            doc03_ref=f"{DOC03_TABLES} import symbol column",
            doc03_claim="doc 03 renders an ordinal-only import as #<ordinal> (ordinal)",
            observed=(
                f"{stats['iat_slots_ordinal_only']} regular slots are ordinal-only, all in WS2_32.dll, and "
                f"pefile supplies a name for {stats['iat_slots_with_secondary_ordlookup_name']} of them from its "
                "own ordinal table"
            ),
            impact=(
                "the two renderings are the same import; reporting only the resolved name would make an "
                "ordinal-only entry indistinguishable from a name-imported one and would contradict the "
                "doc 03 name-versus-ordinal split"
            ),
            disposition=(
                "dst_symbol follows doc 03 as #<ordinal> (ordinal); the pefile-derived name is preserved in the "
                "evidence field as ordlookup_name=<name> and the ordinal as int_ordinal=<n>"
            ),
        ),
    )


def doc03_checks(stats: Mapping[str, Any]) -> list[common.Check]:
    checks: list[common.Check] = []
    for name in sorted(DOC03_EXPECTATIONS):
        expected = DOC03_EXPECTATIONS[name]
        actual = stats.get(name, "<missing>")
        checks.append(
            common.Check(
                name=DOC03_EXPECTATION_LABELS.get(name, name),
                expected=expected,
                actual=actual,
                ok=expected == actual,
            )
        )
    return checks


def compare_csv(path: Path, fieldnames: Sequence[str], rows: Sequence[Mapping[str, Any]]) -> bool:
    """Compare a stored evidence CSV against a freshly built row list, field by field."""
    if not path.exists():
        print(f"FAIL {path.name} does not exist")
        return False
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        header = tuple(reader.fieldnames or ())
        stored = list(reader)
    if header != tuple(fieldnames):
        print(f"FAIL {path.name} header stored={header} fresh={tuple(fieldnames)}")
        return False
    if len(stored) != len(rows):
        print(f"FAIL {path.name} row count stored={len(stored)} fresh={len(rows)}")
        return False
    for line, (old, new) in enumerate(zip(stored, rows), start=2):
        for name in fieldnames:
            fresh = common.scalar_text(new.get(name))
            if old.get(name) != fresh:
                print(f"FAIL {path.name} line {line} field {name}: stored={old.get(name)!r} fresh={fresh!r}")
                return False
    return True


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    parser = argparse.ArgumentParser(
        description=(
            "Rebuild the adhesive.dll import xref graph and indirect-site inventory statically. "
            f"Methodology: {DOC03_METHOD}. Never loads or executes the specimen."
        )
    )
    parser.add_argument("--specimen", type=Path, default=DEFAULT_SPECIMEN)
    parser.add_argument("--edges-csv", type=Path, default=DEFAULT_EDGES)
    parser.add_argument("--sites-csv", type=Path, default=DEFAULT_SITES)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="recompute and compare against the stored CSVs without rewriting them",
    )
    parser.add_argument("--max-report", type=int, default=40)
    args = parser.parse_args(argv)

    started = time.monotonic()
    specimen: Path = args.specimen.resolve()
    relative_specimen = specimen.relative_to(ROOT).as_posix()
    print(f"script    {script.relative_to(ROOT).as_posix()}")
    print(f"sha256    {common.sha256_file(script)}")
    print(f"specimen  {relative_specimen} size={specimen.stat().st_size} sha256={common.sha256_file(specimen)}")
    print(f"method    {DOC03_METHOD}")

    pe = common.load_pe(specimen)
    try:
        result = build(pe)
    finally:
        pe.close()
    stats = result.stats

    print()
    print("== doc 03 expectations ==")
    checks = doc03_checks(stats)
    failed = common.report_checks(checks, args.max_report)
    print(f"checks    {len(checks) - failed}/{len(checks)} matched")

    print()
    print("== published doc 03 figures ==")
    for name in sorted(DOC03_EXPECTATIONS):
        print(f"  {name:44s} {common.scalar_text(stats.get(name))}")

    print()
    print("== additional observed counters ==")
    for name in sorted(stats):
        if name in DOC03_EXPECTATIONS or name == "image_base":
            continue
        value = stats[name]
        if isinstance(value, (str, int, list)):
            print(f"  {name:44s} {common.scalar_text(value)}")

    print()
    print("== edges by category and relation ==")
    edge_counter: Counter[tuple[str, str]] = Counter((edge.category, edge.relation) for edge in result.edges)
    for category, relation in sorted(edge_counter, key=lambda item: (CATEGORY_RANK[item[0]], item[1])):
        print(f"  {category:14s} {relation:24s} {edge_counter[(category, relation)]:7d}")
    print(f"  {'TOTAL':14s} {'':24s} {len(result.edges):7d}")

    print()
    print("== indirect sites by kind and target ==")
    site_counter: Counter[tuple[str, str]] = Counter((site.kind, site.target_kind) for site in result.sites)
    for kind, target in sorted(site_counter):
        print(f"  {kind:24s} {target:22s} {site_counter[(kind, target)]:7d}")
    print(f"  {'TOTAL':24s} {'':22s} {len(result.sites):7d}")

    print()
    print("== divergences, extensions and scope boundaries (recorded, not silently applied) ==")
    for record in build_divergences(stats):
        for line in record.as_lines():
            print(line)
        print()

    edge_rows = [edge.as_row(index + 1) for index, edge in enumerate(result.edges)]
    site_rows = [site.as_row(index + 1) for index, site in enumerate(result.sites)]

    print("== outputs ==")
    exit_code = 1 if failed else 0
    if args.verify:
        ok_edges = compare_csv(args.edges_csv, EDGE_FIELDS, edge_rows)
        ok_sites = compare_csv(args.sites_csv, SITE_FIELDS, site_rows)
        print(f"verify    {args.edges_csv.name} {'match' if ok_edges else 'MISMATCH'}")
        print(f"verify    {args.sites_csv.name} {'match' if ok_sites else 'MISMATCH'}")
        if not (ok_edges and ok_sites):
            exit_code = 1
    else:
        common.write_csv(args.edges_csv, edge_rows, EDGE_FIELDS)
        common.write_csv(args.sites_csv, site_rows, SITE_FIELDS)
        for path, rows in ((args.edges_csv, edge_rows), (args.sites_csv, site_rows)):
            print(
                f"write     {path.relative_to(ROOT).as_posix()} rows={len(rows)} "
                f"sha256={common.sha256_file(path)}"
            )

    print()
    print(f"elapsed   {time.monotonic() - started:.1f}s")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
