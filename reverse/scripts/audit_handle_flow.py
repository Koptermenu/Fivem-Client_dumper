"""Independent recomputation audit of the 0xC856C0 handle flow evidence set.

Reads the two c856c0 payloads, the caller closure csv, the three corpus csvs,
the syscall service map and the adhesive-14 report, then recomputes every
audited quantity from those files alone and compares the result with what the
report states.

Scope limits, both load bearing:

* The specimen is never opened, mapped, loaded, patched or executed. Every
  specimen identity in the payload is quoted from the inputs, not measured.
* No fresh disassembly is performed. The audit is a recomputation over the
  published evidence, so it can confirm or refute internal consistency and the
  report's reading of it, but it cannot extend the evidence.
* The output is a structure and count audit. It names no service, no target
  process, no producer and no patch, and it contains no exploit, bypass or
  shellcode guidance.
* The audited document is read but never attested. That report records the
  digest of this payload, so a digest of the report recorded here would close a
  cycle in which no state of the tree keeps both pins fresh. Its digest and
  size are reported under the `observation` block, which is excluded from the
  attested `inputs` and from the validation block.

Deterministic: no timestamps, every derived collection sorted before it is
emitted, so repeated runs on unchanged inputs produce a byte identical payload.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import common

SCHEMA_AUDIT_HANDLE_FLOW: Final[str] = "adhesive-dumper.audit-handle-flow/1"

EVIDENCE_INPUTS: Final[tuple[str, ...]] = (
    "c856c0_dataflow.json",
    "c856c0_forward.json",
    "c856c0_callers.csv",
    "syscall_inventory.csv",
    "syscall_service_map.json",
    "cfg_functions.csv",
    "xref_edges.csv",
)

AUDITED_DOCUMENT: Final[str] = "reverse/adhesive-14-c856c0-handle-producer-dataflow.md"
AUDITED_DOCUMENT_NAME: Final[str] = "adhesive-14-c856c0-handle-producer-dataflow.md"

ANCHOR_FUNCTION: Final[str] = "0xC856C0"
ENTRY_FUNCTION: Final[str] = "0xC85650"
GROWTH_HELPER: Final[str] = "0x495D0"
ANCHOR_RVA: Final[int] = 0xC856C0

CLUSTER_RANGE: Final[tuple[int, int]] = (0xC85000, 0xC88000)

ALLOCATION_WRAPPERS: Final[tuple[str, ...]] = (
    "0x51D680",
    "0x51D880",
    "0x51DAB0",
    "0x51DC60",
    "0x51DDE0",
    "0x51DFF0",
)
TRANSFER_WRAPPERS: Final[tuple[str, ...]] = (
    "0xC8F650",
    "0xC8F880",
    "0xC8FAA0",
    "0xC8FC00",
    "0xC8FDE0",
    "0xC8FF60",
)
ALL_WRAPPERS: Final[tuple[str, ...]] = ALLOCATION_WRAPPERS + TRANSFER_WRAPPERS

AGREE: Final[str] = "AGREE"
CONTESTED: Final[str] = "CONTESTED"
NOT_STATED: Final[str] = "NOT_CHECKED_AGAINST_DOCUMENT"


@dataclass(frozen=True, slots=True)
class CsvContract:
    path: Path
    row_count: int
    column_count: int
    header: str
    trailing_newline: bool


@dataclass(frozen=True, slots=True)
class XrefScan:
    """Recomputed source and destination census of the published edge set."""

    row_count: int
    column_count: int
    src_rva_min: int
    src_rva_max: int
    src_rva_unit: str
    hex_high_nibble_histogram: dict[str, int]
    decimal_leading_digit_histogram: dict[str, int]
    zero_valued_src_rows: int
    in_cluster_src_rows: int
    in_cluster_src_functions: tuple[str, ...]
    in_cluster_src_by_relation: dict[str, int]
    in_cluster_imports_reached: tuple[str, ...]
    dst_anchor_function_rows: int
    dst_entry_function_rows: int
    dst_growth_helper_rows: int
    dst_symbol_rows: dict[str, int]
    dst_symbol_relation_counts: dict[str, dict[str, int]]
    close_handle_in_cluster_rows: int
    nearest_close_handle_sites: tuple[tuple[str, int, str], ...]

@dataclass(slots=True)
class Audit:
    """Accumulates the audit items and the recomputation checks in a fixed order."""

    document: str
    items: list[dict[str, Any]] = field(default_factory=list)
    checks: list[common.Check] = field(default_factory=list)

    def expect(self, name: str, expected: Any, actual: Any) -> None:
        self.checks.append(
            common.Check(name=name, expected=expected, actual=actual, ok=expected == actual)
        )

    def record(
        self,
        item_id: str,
        question: str,
        recomputed: Any,
        source_of_truth: Sequence[str],
        document_anchor: str | None,
        document_value: Any,
        recomputed_scalar: Any = None,
        note: str = "",
    ) -> None:
        """
        Add one audited quantity.

        `recomputed` is the measured value, `recomputed_scalar` is the same
        measurement reduced to the scalar the document states, and
        `document_value` is that scalar as the document writes it. The two
        scalars are compared as text, so a structured `recomputed` payload can
        still be checked against a one number statement in the report.
        """
        measured = recomputed if recomputed_scalar is None else recomputed_scalar
        if document_anchor is None or document_value is None:
            agreement = NOT_STATED
            anchor_present = None
        else:
            anchor_present = document_anchor in self.document
            if not anchor_present:
                agreement = NOT_STATED
            elif common.scalar_text(document_value) == common.scalar_text(measured):
                agreement = AGREE
            else:
                agreement = CONTESTED
        item: dict[str, Any] = {
            "id": item_id,
            "question": question,
            "recomputed": recomputed,
            "recomputed_scalar": measured,
            "source_of_truth": list(source_of_truth),
            "document_anchor": document_anchor,
            "document_anchor_present": anchor_present,
            "document_value": document_value,
            "agreement": agreement,
        }
        if note:
            item["note"] = note
        self.items.append(item)


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def csv_header(path: Path) -> tuple[str, ...]:
    with path.open(encoding="utf-8", newline="") as handle:
        return tuple(next(csv.reader(handle)))


def scan_callers_csv(path: Path) -> tuple[list[dict[str, str]], CsvContract]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = tuple(reader.fieldnames or ())
        rows = list(reader)
    return rows, CsvContract(
        path=path,
        row_count=len(rows),
        column_count=len(columns),
        header=",".join(columns),
        trailing_newline=path.read_bytes().endswith(b"\n"),
    )


def row_tuple(row: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        str(row["level"]),
        row["scope"],
        row["target_fn"],
        row["edge_kind"],
        row["callsite"],
        row["caller_fn"],
    )


def scan_cfg_functions_csv(path: Path, wanted: Mapping[int, str]) -> dict[str, dict[str, str]]:
    """One pass over cfg_functions.csv keeping only the functions this audit names."""
    found: dict[str, dict[str, str]] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            label = wanted.get(int(row["begin_rva"]))
            if label is not None:
                found[label] = row
    return found


def scan_xref_edges_csv(path: Path, cluster_range: tuple[int, int]) -> XrefScan:
    """
    Recompute the source and destination census of xref_edges.csv.

    The numeric columns of this file are decimal. The audit therefore records
    both the true hexadecimal high nibble of src_rva and its leading decimal
    digit, so that a report which reads the column in the wrong base can be
    told apart from one that measures it correctly.
    """
    low, high = cluster_range
    hex_nibble: Counter[str] = Counter()
    decimal_digit: Counter[str] = Counter()
    in_cluster_relations: Counter[str] = Counter()
    in_cluster_functions: set[str] = set()
    in_cluster_imports: set[str] = set()
    dst_symbols: Counter[str] = Counter()
    dst_symbol_relations: dict[str, Counter[str]] = {}
    close_sites: list[tuple[str, int, str]] = []
    close_in_cluster = 0
    columns = 0
    dst_values = {
        ANCHOR_FUNCTION: int(ANCHOR_FUNCTION, 16),
        ENTRY_FUNCTION: int(ENTRY_FUNCTION, 16),
        GROWTH_HELPER: int(GROWTH_HELPER, 16),
    }
    dst_hits = Counter()
    src_min = 1 << 62
    src_max = -1
    zero_src = 0
    rows = 0
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = len(reader.fieldnames or ())
        for row in reader:
            rows += 1
            src = int(row["src_rva"], 10)
            src_min = min(src_min, src)
            src_max = max(src_max, src)
            zero_src += 1 if src == 0 else 0
            hex_nibble[f"0x{(src >> 28) & 0xF:X}"] += 1
            decimal_digit[str(src)[0]] += 1
            in_cluster = low <= src < high
            if in_cluster:
                in_cluster_relations[row["relation"]] += 1
                in_cluster_functions.add(common.hexs(int(row["code_instruction_function_begin"])))
                if row["dst_symbol"]:
                    in_cluster_imports.add(f"{row['dst_module'] or '?'}!{row['dst_symbol']}")
                close_in_cluster += 1 if row["dst_symbol"] == "CloseHandle" else 0
            symbol = row["dst_symbol"]
            if symbol:
                dst_symbols[symbol] += 1
                dst_symbol_relations.setdefault(symbol, Counter())[row["relation"]] += 1
            raw_dst = row["dst_rva"]
            if raw_dst:
                dst = int(raw_dst, 10)
                for label, value in dst_values.items():
                    if dst == value:
                        dst_hits[label] += 1
            if symbol == "CloseHandle":
                close_sites.append((common.hexs(src), src - ANCHOR_RVA, row["relation"]))
    close_sites.sort(key=lambda item: abs(item[1]))
    return XrefScan(
        row_count=rows,
        column_count=columns,
        src_rva_min=src_min,
        src_rva_max=src_max,
        src_rva_unit="decimal",
        hex_high_nibble_histogram=dict(sorted(hex_nibble.items())),
        decimal_leading_digit_histogram=dict(sorted(decimal_digit.items())),
        zero_valued_src_rows=zero_src,
        in_cluster_src_rows=sum(in_cluster_relations.values()),
        in_cluster_src_functions=tuple(sorted(in_cluster_functions)),
        in_cluster_src_by_relation=dict(sorted(in_cluster_relations.items())),
        in_cluster_imports_reached=tuple(sorted(in_cluster_imports)),
        dst_anchor_function_rows=dst_hits[ANCHOR_FUNCTION],
        dst_entry_function_rows=dst_hits[ENTRY_FUNCTION],
        dst_growth_helper_rows=dst_hits[GROWTH_HELPER],
        dst_symbol_rows=dict(sorted(dst_symbols.items())),
        dst_symbol_relation_counts={
            name: dict(sorted(counts.items()))
            for name, counts in sorted(dst_symbol_relations.items())
            if name in ("CloseHandle", "DuplicateHandle")
        },
        close_handle_in_cluster_rows=close_in_cluster,
        nearest_close_handle_sites=tuple(close_sites[:3]),
    )


def scan_syscall_inventory_csv(
    path: Path, subject_sites: Mapping[str, str]
) -> tuple[dict[str, dict[str, str]], list[dict[str, str]], Counter[str]]:
    """
    One pass over syscall_inventory.csv.

    Returns the rows of the named 0xC856C0 subject sites keyed by rva, the rows
    of the wrapper_forwarding service class in rva order, and the class
    histogram of the whole corpus.
    """
    wanted = {rva.upper() for rva in subject_sites}
    named: dict[str, dict[str, str]] = {}
    forwarding: list[dict[str, str]] = []
    classes: Counter[str] = Counter()
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            classes[row["service_class"]] += 1
            if row["service_class"] == "wrapper_forwarding":
                forwarding.append(row)
            key = row["rva_hex"].upper()
            if key in wanted:
                named[key] = row
    forwarding.sort(key=lambda row: int(row["rva_hex"], 16))
    return named, forwarding, classes


def arg_classes(row: Mapping[str, str], count: int = 6) -> tuple[str, ...]:
    return tuple(row[f"arg{index}_class"] for index in range(1, count + 1))


def in_cluster(label: str, cluster_range: tuple[int, int] = CLUSTER_RANGE) -> bool:
    return cluster_range[0] <= int(label, 16) < cluster_range[1]


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    evidence = root / "reverse" / "evidence"
    parser = argparse.ArgumentParser(
        description="Recomputation audit of the 0xC856C0 handle flow evidence set"
    )
    parser.add_argument("--evidence", type=Path, default=evidence)
    parser.add_argument(
        "--document", type=Path, default=root / "reverse" / AUDITED_DOCUMENT_NAME
    )
    parser.add_argument("--out", type=Path, default=evidence / "audit_handle_flow.json")
    parser.add_argument("--max-report", type=int, default=40, help="checks to print")
    args = parser.parse_args(argv)

    dataflow = load_json(args.evidence / "c856c0_dataflow.json")
    forward = load_json(args.evidence / "c856c0_forward.json")
    service_map = load_json(args.evidence / "syscall_service_map.json")
    callers_rows, callers_index = scan_callers_csv(args.evidence / "c856c0_callers.csv")
    document = args.document.read_text(encoding="utf-8")

    audit = Audit(document=document)

    dispatch = dataflow["dispatch"]
    handle = dataflow["handle"]
    stages = forward["stages"]
    wrappers = forward["wrappers"]
    inline_syscalls = forward["inline_syscalls"]
    closure = forward["caller_closure"]
    reachable = forward["forward_reachable_set"]
    tables = dispatch["tables"]


    slots_per_table = [len(table["branches"]) for table in tables]
    branch_total = sum(slots_per_table)
    inline_branches = sum(
        1 for table in tables for branch in table["branches"] if branch["sink_kind"] == "inline_syscall"
    )
    wrapper_branches = sum(
        1 for table in tables for branch in table["branches"] if branch["sink_kind"] == "wrapper_call"
    )
    slot_steps = [
        table["branches"][1]["slot_rva"] - table["branches"][0]["slot_rva"] for table in tables
    ]
    table_delta = tables[1]["table_rva"] - tables[0]["table_rva"]
    distinct_targets = [
        len({branch["target_rva"] for branch in table["branches"]}) for table in tables
    ]
    adjacent = table_delta == slots_per_table[0] * slot_steps[0]

    audit.expect("dispatch.table_count", 2, len(tables))
    audit.expect("dispatch.slots_per_table", [16, 16], slots_per_table)
    audit.expect("dispatch.slots_total", 32, branch_total)
    audit.expect("dispatch.slot_step_bytes", [4, 4], slot_steps)
    audit.expect("dispatch.tables_are_adjacent", True, adjacent)
    audit.expect("dispatch.distinct_block_targets_per_table", [16, 16], distinct_targets)
    audit.expect("dispatch.table_entries_field", 16, dispatch["table_entries"])
    audit.expect("dispatch.selector_count", 2, len(dispatch["selectors"]))
    audit.expect("dispatch.tables_are_adjacent_field", True, dispatch["tables_are_adjacent"])

    audit.record(
        "D-01",
        "how many slots does one dispatch table hold",
        16,
        [
            "c856c0_dataflow.json#dispatch.table_entries",
            "c856c0_dataflow.json#dispatch.tables[].branches",
        ],
        "`table_entries = 16`",
        16,
        slots_per_table[0],
    )
    audit.record(
        "D-02",
        "how many dispatch tables are there and how many slots in total",
        {"tables": len(tables), "slots_total": branch_total, "per_table": slots_per_table},
        ["c856c0_dataflow.json#dispatch.tables"],
        "16 + 16 = 32",
        32,
        branch_total,
    )
    audit.record(
        "D-03",
        "is the second table byte adjacent to the first",
        {
            "first_table_rva": tables[0]["table_rva_hex"],
            "second_table_rva": tables[1]["table_rva_hex"],
            "offset_bytes": table_delta,
            "adjacent": adjacent,
        },
        ["c856c0_dataflow.json#dispatch.tables_are_adjacent"],
        "`tables_are_adjacent` | `true`",
        "true",
        adjacent,
    )


    per_stage = {
        stage["stage_label"]: {
            "branches": stage["branch_count"],
            "inline": stage["inline_branch_count"],
            "wrapper": stage["wrapper_branch_count"],
            "distinct_wrapper_targets": len(stage["distinct_wrapper_targets"]),
        }
        for stage in stages
    }
    audit.expect("branch.total", 32, branch_total)
    audit.expect("branch.inline_total", 16, inline_branches)
    audit.expect("branch.wrapper_total", 16, wrapper_branches)
    audit.expect("branch.inline_plus_wrapper", branch_total, inline_branches + wrapper_branches)
    for stage in stages:
        label = stage["stage_label"]
        audit.expect(f"branch.{label}.declared_count", stage["branch_count"], len(stage["branches"]))
        audit.expect(
            f"branch.{label}.declared_inline",
            stage["inline_branch_count"],
            sum(1 for b in stage["branches"] if b["sink_kind"] == "inline_syscall"),
        )
        audit.expect(
            f"branch.{label}.declared_wrapper",
            stage["wrapper_branch_count"],
            sum(1 for b in stage["branches"] if b["sink_kind"] == "wrapper_call"),
        )
        audit.expect(
            f"branch.{label}.distinct_wrapper_targets",
            len(stage["distinct_wrapper_targets"]),
            len({b["sink_function_rva"] for b in stage["branches"] if b["sink_kind"] == "wrapper_call"}),
        )
    audit.expect("branch.argument_register_split", {"rdx": 16, "r10": 16},
                 dict(sorted(Counter(b["handle_argument_register"] for t in tables
                                     for b in t["branches"]).items())))

    audit.record(
        "B-01",
        "how many branches carry a direct syscall in the anchor",
        {
            "total": inline_branches,
            "per_stage": {s["stage_label"]: s["inline_branch_count"] for s in stages},
            "cfg_functions_csv_syscall_sites": None,
        },
        ["c856c0_dataflow.json#dispatch.tables[].branches[].sink_kind"],
        "16 inline syscall + 16 wrapper-branch",
        16,
        inline_branches,
    )
    audit.record(
        "B-02",
        "how many branches call a wrapper instead of issuing a syscall",
        {
            "total": wrapper_branches,
            "per_stage": {s["stage_label"]: s["wrapper_branch_count"] for s in stages},
        },
        ["c856c0_dataflow.json#dispatch.tables[].branches[].sink_kind"],
        "16 inline syscall + 16 wrapper-branch",
        16,
        wrapper_branches,
    )


    by_stage = Counter(wrapper["stage_label"] for wrapper in wrappers)
    wrapper_rvas = tuple(wrapper["rva_hex"] for wrapper in wrappers)
    audit.expect("wrapper.count", 12, len(wrappers))
    audit.expect("wrapper.distinct", 12, len(set(wrapper_rvas)))
    audit.expect("wrapper.allocation", 6, by_stage.get("alloc", 0))
    audit.expect("wrapper.transfer", 6, by_stage.get("transfer", 0))
    audit.expect("wrapper.one_syscall_each", True, all("syscall" in w for w in wrappers))
    audit.expect("wrapper.all_return_status", True, all(w["returns_syscall_status"] for w in wrappers))
    audit.expect("wrapper.no_api_calls", True, all(w["api_call_site_count"] == 0 for w in wrappers))
    audit.expect(
        "wrapper.no_handle_close_or_duplicate",
        True,
        all(not w["closes_handle"] and not w["duplicates_handle"] for w in wrappers),
    )
    audit.expect(
        "wrapper.allocation_rvas",
        ALLOCATION_WRAPPERS,
        tuple(w["rva_hex"] for w in wrappers if w["stage_label"] == "alloc"),
    )
    audit.expect(
        "wrapper.transfer_rvas",
        TRANSFER_WRAPPERS,
        tuple(w["rva_hex"] for w in wrappers if w["stage_label"] == "transfer"),
    )
    audit.expect(
        "wrapper.handle_argument_position_is_one",
        {1},
        {w["handle_argument_position"] for w in wrappers},
    )
    forwarding_offsets = [
        argument["position"] + 1 == argument["from_call_argument"]
        for wrapper in wrappers
        for argument in wrapper["syscall_arguments"]
    ]
    audit.expect("wrapper.argument_shift_n_to_n_minus_1", True, all(forwarding_offsets))

    audit.record(
        "W-01",
        "how many wrapper functions are there, 6 allocation plus 6 transfer or something else",
        {
            "total": len(wrappers),
            "allocation": by_stage.get("alloc", 0),
            "transfer": by_stage.get("transfer", 0),
            "syscalls_per_wrapper": 1,
            "rvas": list(wrapper_rvas),
        },
        [
            "c856c0_forward.json#wrappers",
            "cfg_functions.csv#syscall_sites on the wrapper rows",
        ],
        "**12** distinct wrapper (6 allokációs + 6 transzfer)",
        12,
        len(wrappers),
    )


    wanted_cfg: dict[int, str] = {
        int(forward["anchor"]["function_rva_hex"], 16): "anchor",
        int(forward["anchor"]["entry_function_rva_hex"], 16): "entry_function",
        int(forward["output_vector"]["growth_helper"]["function"]["begin_rva_hex"], 16): "growth_helper",
    }
    for wrapper in wrappers:
        wanted_cfg[int(wrapper["rva_hex"], 16)] = f"wrapper:{wrapper['rva_hex']}"
    cfg_rows = scan_cfg_functions_csv(args.evidence / "cfg_functions.csv", wanted_cfg)
    cfg_syscalls = {label: int(row["syscall_sites"]) for label, row in sorted(cfg_rows.items())}
    anchor_syscalls = cfg_syscalls.get("anchor", -1)
    wrapper_syscall_sum = sum(v for k, v in cfg_syscalls.items() if k.startswith("wrapper:"))
    subject_syscall_total = anchor_syscalls + wrapper_syscall_sum
    inline_count = len(inline_syscalls)
    audit.expect("syscall.inline_sites", 16, inline_count)
    audit.expect("syscall.anchor_cfg_sites", 16, anchor_syscalls)
    audit.expect("syscall.wrapper_cfg_sum", 12, wrapper_syscall_sum)
    audit.expect("syscall.subject_total", 28, subject_syscall_total)
    audit.expect("syscall.inline_equals_anchor_cfg", inline_count, anchor_syscalls)
    audit.expect("syscall.no_syscall_in_entry_or_helper", 0,
                 cfg_syscalls.get("entry_function", -1) + cfg_syscalls.get("growth_helper", -1))

    for item in audit.items:
        if item["id"] == "B-01":
            item["recomputed"]["cfg_functions_csv_syscall_sites"] = anchor_syscalls

    audit.record(
        "S-01",
        "how many syscall sites are there in the whole forward subject set",
        {
            "inline_in_anchor": inline_count,
            "in_wrappers": wrapper_syscall_sum,
            "total": subject_syscall_total,
            "cfg_functions_csv_breakdown": cfg_syscalls,
        },
        [
            "c856c0_forward.json#inline_syscalls",
            "c856c0_forward.json#wrappers[].syscall",
            "cfg_functions.csv#syscall_sites",
        ],
        "**28** syscall-hely",
        28,
        subject_syscall_total,
    )


    loads = handle["loads"]
    use_sites = handle["use_sites"]
    register_split = Counter(site["argument_register"] for site in use_sites)
    stage_split = Counter(site["stage_label"] for site in use_sites)
    audit.expect("handle.load_count", 2, len(loads))
    audit.expect("handle.use_site_count", 32, len(use_sites))
    audit.expect("handle.use_count_field", 32, handle["use_count"])
    audit.expect("handle.separate_reads", True, handle["loads_are_separate_reads"])
    audit.expect("handle.r10_sites", 16, register_split.get("r10", 0))
    audit.expect("handle.rdx_sites", 16, register_split.get("rdx", 0))
    audit.expect("handle.allocation_stage_sites", 16, stage_split.get("alloc", 0))
    audit.expect("handle.transfer_stage_sites", 16, stage_split.get("transfer", 0))
    audit.expect("handle.use_sites_equal_branch_total", branch_total, len(use_sites))
    audit.expect(
        "handle.consume_site_count_field",
        len(use_sites),
        forward["handle_lifetime"]["consume_site_count"],
    )
    audit.expect("handle.carriers", ["r14", "rbx"],
                 forward["handle_lifetime"]["consume_sites"]["carriers"])
    audit.expect("handle.sink_kind_split", {"inline_syscall": 16, "wrapper_call": 16},
                 dict(sorted(Counter(s["sink_kind"] for s in use_sites).items())))

    audit.record(
        "H-01",
        "how many times is the descriptor field read",
        {
            "count": len(loads),
            "sites": [load["rva_hex"] for load in loads],
            "carriers": [load["register"] for load in loads],
            "separate_reads": handle["loads_are_separate_reads"],
            "fields_observed": dataflow["object_model"]["descriptor"]["fields_observed"],
        },
        ["c856c0_dataflow.json#handle.loads"],
        "**Két** különálló olvasás",
        2,
        len(loads),
    )
    audit.record(
        "H-02",
        "how many consumer edges does the handle have",
        {
            "use_sites": len(use_sites),
            "per_stage": dict(sorted(stage_split.items())),
            "argument_register_split": dict(sorted(register_split.items())),
            "carriers": forward["handle_lifetime"]["consume_sites"]["carriers"],
        },
        [
            "c856c0_dataflow.json#handle.use_sites",
            "c856c0_forward.json#handle_lifetime.consume_sites",
        ],
        "32 fogyasztó él",
        32,
        len(use_sites),
    )


    entry_negative = closure["negative_forms"].get(ENTRY_FUNCTION, {}).get("forms", {})
    entry_forms = sorted(entry_negative)
    entry_zero_forms = sorted(n for n, v in entry_negative.items() if not v.get("site_count"))
    anchor_negative = closure["negative_forms"].get(ANCHOR_FUNCTION, {}).get("forms", {})
    anchor_call_sites = sum(v.get("site_count", 0) for v in anchor_negative.values())
    anchor_call_site = anchor_negative.get("rel32_call", {}).get("sites", [{}])[0]
    closure_rows = closure["rows"]
    level_split = Counter(str(row["level"]) for row in closure_rows)
    kind_split = Counter(row["edge_kind"] for row in closure_rows)
    scope_level_split = Counter((row["scope"], str(row["level"])) for row in closure_rows)
    audit.expect("closure.forms_enumerated", 6, len(entry_forms))
    audit.expect("closure.entry_all_forms_zero", 6, len(entry_zero_forms))
    audit.expect("closure.anchor_single_inbound_edge", 1, anchor_call_sites)
    audit.expect("closure.json_rows", 444, len(closure_rows))
    audit.expect("closure.csv_rows", 444, len(callers_rows))
    audit.expect("closure.row_count_field", len(closure_rows), closure["row_count"])
    audit.expect("closure.csv_level_split", dict(sorted(level_split.items())),
                 dict(sorted(Counter(r["level"] for r in callers_rows).items())))
    audit.expect("closure.csv_kind_split", dict(sorted(kind_split.items())),
                 dict(sorted(Counter(r["edge_kind"] for r in callers_rows).items())))
    audit.expect("closure.csv_matches_json", True,
                 sorted(row_tuple(r) for r in callers_rows)
                 == sorted(row_tuple(r) for r in closure_rows))
    audit.expect("closure.uncovered_call_sites", 0, closure["uncovered_call_site_count"])
    audit.expect("closure.rows_carrying_F_U_01", 220,
                 sum(1 for row in closure_rows if row["open"] == "F-U-01"))
    audit.expect("closure.frontier_empty_and_exhausted", True,
                 bool(closure["scopes"][0]["exhausted"])
                 and not closure["scopes"][0]["frontier_after_last_level"])
    audit.expect("producer.status_open", "OPEN", handle["producer"]["status"])
    audit.expect("producer.identified_false", False, handle["producer"]["identified"])
    audit.expect("ownership.open", "OPEN", forward["handle_lifetime"]["ownership"])

    audit.record(
        "P-01",
        "where does the producer and caller boundary sit",
        {
            "anchor_inbound_rel32_call_sites": anchor_call_sites,
            "anchor_inbound_site": anchor_call_site.get("rva_hex"),
            "anchor_inbound_site_bytes": anchor_call_site.get("encoding"),
            "entry_function": ENTRY_FUNCTION,
            "entry_inbound_forms_enumerated": entry_forms,
            "entry_inbound_forms_with_zero_sites": entry_zero_forms,
            "frontier_after_last_level": closure["scopes"][0]["frontier_after_last_level"],
            "closure_rows_per_level": dict(sorted(level_split.items())),
            "closure_rows_per_edge_kind": dict(sorted(kind_split.items())),
            "producer_status": handle["producer"]["status"],
            "producer_identified": handle["producer"]["identified"],
            "ownership": forward["handle_lifetime"]["ownership"],
        },
        [
            "c856c0_forward.json#caller_closure.negative_forms",
            "c856c0_forward.json#caller_closure.scopes",
            "c856c0_dataflow.json#handle.producer",
        ],
        "Handle producer | **OPEN**",
        "OPEN",
        handle["producer"]["status"],
    )


    level_one = [r for r in closure_rows if r["level"] == 1 and r["edge_kind"] == "direct_call"]
    wrapper_level_one = [r for r in level_one if r["target_fn"] in ALL_WRAPPERS]
    all_sink_callers = {r["caller_fn"] for r in level_one}
    wrapper_callers = {r["caller_fn"] for r in wrapper_level_one}
    wrapper_callers_in = tuple(sorted(c for c in wrapper_callers if in_cluster(c)))
    wrapper_callers_out = tuple(sorted(c for c in wrapper_callers if not in_cluster(c)))
    sink_callers_in = tuple(sorted(c for c in all_sink_callers if in_cluster(c)))
    growth_callers = {r["caller_fn"] for r in level_one if r["target_fn"] == GROWTH_HELPER}
    per_wrapper_callers = {
        rva: len({r["caller_fn"] for r in wrapper_level_one if r["target_fn"] == rva})
        for rva in ALL_WRAPPERS
    }
    audit.expect("wrapper.level_one_rows", 408, len(wrapper_level_one))
    audit.expect("wrapper.distinct_callers", 37, len(wrapper_callers))
    audit.expect("wrapper.callers_outside_cluster", 36, len(wrapper_callers_out))
    audit.expect("wrapper.callers_inside_cluster", 1, len(wrapper_callers_in))
    audit.expect("wrapper.in_cluster_caller_is_the_anchor", ("0xC856C0",), wrapper_callers_in)
    audit.expect("wrapper.anchor_call_sites", 16,
                 sum(1 for r in wrapper_level_one if r["caller_fn"] == "0xC856C0"))
    audit.expect("sink.distinct_callers", 54, len(all_sink_callers))
    audit.expect("sink.callers_inside_cluster", 2, len(sink_callers_in))
    audit.expect("growth.distinct_callers", 17, len(growth_callers))
    audit.expect("per_wrapper.distinct_callers", {
        "0x51D680": 35, "0x51D880": 35, "0x51DAB0": 35,
        "0x51DC60": 35, "0x51DDE0": 35, "0x51DFF0": 35,
        "0xC8F650": 3, "0xC8F880": 3, "0xC8FAA0": 3,
        "0xC8FC00": 3, "0xC8FDE0": 3, "0xC8FF60": 3,
    }, per_wrapper_callers)


    reachable_rvas = {e["rva"] for e in reachable["functions"]}
    outside_pdata = {e["rva"] for e in reachable["targets_outside_pdata"]}
    null_function = {e["rva"] for e in reachable["functions"] if not e.get("function")}
    pdata_covered = len(reachable_rvas) - len(outside_pdata)
    depth_split = {l["depth"]: len(l["functions"]) for l in reachable["levels"]}
    audit.expect("reachable.function_count", 37, len(reachable_rvas))
    audit.expect("reachable.function_count_field", 37, reachable["function_count"])
    audit.expect("reachable.targets_outside_pdata", 14, len(outside_pdata))
    audit.expect("reachable.outside_pdata_is_subset", True, outside_pdata <= reachable_rvas)
    audit.expect("reachable.null_function_equals_outside", outside_pdata, null_function)
    audit.expect("reachable.pdata_covered", 23, pdata_covered)
    audit.expect("reachable.depth_sum", 37, sum(depth_split.values()))
    audit.expect("reachable.depth_split", {0: 2, 1: 22, 2: 6, 3: 5, 4: 2}, depth_split)
    audit.expect("reachable.exhausted", False, reachable["exhausted"])
    audit.expect("reachable.max_depth", 4, reachable["max_depth"])


    xref_header = csv_header(args.evidence / "xref_edges.csv")
    cfg_header = csv_header(args.evidence / "cfg_functions.csv")
    inventory_header = csv_header(args.evidence / "syscall_inventory.csv")
    xref = scan_xref_edges_csv(args.evidence / "xref_edges.csv", CLUSTER_RANGE)
    audit.expect("xref.row_count", 57101, xref.row_count)
    audit.expect("xref.column_count", 22, xref.column_count)
    audit.expect("xref.src_unit_is_decimal", "decimal", xref.src_rva_unit)
    audit.expect("xref.single_true_hex_high_nibble", 1, len(xref.hex_high_nibble_histogram))
    audit.expect("xref.max_src_below_0x10000000", True, xref.src_rva_max < 0x10000000)
    audit.expect("xref.in_cluster_src_rows", 17, xref.in_cluster_src_rows)
    audit.expect("xref.in_cluster_src_functions", 5, len(xref.in_cluster_src_functions))
    audit.expect("xref.dst_anchor_rows", 0, xref.dst_anchor_function_rows)
    audit.expect("xref.dst_entry_rows", 0, xref.dst_entry_function_rows)
    audit.expect("xref.dst_growth_helper_rows", 0, xref.dst_growth_helper_rows)
    audit.expect("xref.close_handle_rows", 61, xref.dst_symbol_rows.get("CloseHandle", 0))
    audit.expect("xref.duplicate_handle_rows", 0, xref.dst_symbol_rows.get("DuplicateHandle", 0))
    audit.expect("xref.close_handle_in_cluster", 0, xref.close_handle_in_cluster_rows)
    audit.expect("xref.zero_valued_src_rows", 0, xref.zero_valued_src_rows)
    audit.expect(
        "xref.close_handle_relations",
        {"call_indirect_iat": 59, "iat_jmp_thunk_stub": 1, "iat_slot_symbol_binding": 1},
        xref.dst_symbol_relation_counts.get("CloseHandle", {}),
    )
    audit.expect(
        "xref.nearest_close_handle_sites",
        [("0xC81D49", -14711), ("0xCA8AE7", 144423), ("0x87F348", -4219768)],
        [(site, dist) for site, dist, _ in xref.nearest_close_handle_sites],
    )


    subject_sites: dict[str, str] = {}
    for site in inline_syscalls:
        subject_sites[site["rva_hex"]] = (
            "inline_alloc" if site["stage_label"] == "alloc" else "inline_transfer"
        )
    for wrapper in wrappers:
        subject_sites[wrapper["syscall"]["rva_hex"]] = (
            "wrapper_alloc" if wrapper["stage_label"] == "alloc" else "wrapper_transfer"
        )
    inventory_rows, forwarding_rows, class_histogram = scan_syscall_inventory_csv(
        args.evidence / "syscall_inventory.csv", subject_sites
    )
    subject_classes = Counter(row["service_class"] for row in inventory_rows.values())
    subject_statuses = Counter(row["status"] for row in inventory_rows.values())
    audit.expect("inventory.corpus_rows", 3627, sum(class_histogram.values()))
    audit.expect("inventory.subject_rows_found", 28, len(inventory_rows))
    audit.expect("inventory.forwarding_rows", 21, len(forwarding_rows))
    audit.expect("inventory.service_map_class_totals_agree", True,
                 all(class_histogram.get(name, 0) == service_map["service_classes"][name]["sites"]
                     for name in service_map["service_classes"]))
    audit.expect("inventory.subject_class_split",
                 {"allocation_0x1000_0x40": 8, "other": 20},
                 dict(sorted(subject_classes.items())))
    audit.expect("inventory.subject_status_split",
                 {"unresolved_symbolic_service_number": 28},
                 dict(sorted(subject_statuses.items())))
    audit.expect("inventory.no_subject_site_is_wrapper_forwarding", 0,
                 sum(1 for r in inventory_rows.values()
                     if r["service_class"] == "wrapper_forwarding"))
    audit.expect("inventory.no_subject_site_is_transfer_5arg", 0,
                 sum(1 for r in inventory_rows.values()
                     if r["service_class"] == "transfer_5arg"))
    audit.expect("inventory.no_subject_site_is_named", 0,
                 sum(1 for r in inventory_rows.values() if r["nt_service"] != "UNRESOLVED"))
    forwarding_shapes = Counter(arg_classes(r, 4) for r in forwarding_rows)
    audit.expect("inventory.forwarding_shape_count", 1, len(forwarding_shapes))
    audit.expect(
        "inventory.forwarding_shape_is_four_self_handles",
        {("A6_SELF_HANDLE",) * 4},
        set(forwarding_shapes),
    )
    forwarding_band = (
        min(int(r["rva_hex"], 16) for r in forwarding_rows),
        max(int(r["rva_hex"], 16) for r in forwarding_rows),
    )
    forwarding_owners = sorted({r["pdata_function_start_rva_hex"] for r in forwarding_rows})
    audit.expect("inventory.forwarding_outside_cluster_band", True,
                 not in_cluster(common.hexs(forwarding_band[0])))
    audit.expect("inventory.forwarding_disjoint_from_wrappers", True,
                 not ({r["rva_hex"].upper() for r in forwarding_rows}
                      & {rva.upper() for rva in ALL_WRAPPERS}))
    audit.expect("inventory.forwarding_disjoint_from_inline_sites", True,
                 not ({r["rva_hex"].upper() for r in forwarding_rows}
                      & {s["rva_hex"].upper() for s in inline_syscalls}))
    audit.expect("inventory.forwarding_owner_count", 7, len(forwarding_owners))

    def shape_of(label: str) -> Counter[tuple[str, ...]]:
        return Counter(
            arg_classes(inventory_rows[rva.upper()])
            for rva, kind in subject_sites.items()
            if kind == label
        )

    wrapper_shapes = shape_of("wrapper_alloc") + shape_of("wrapper_transfer")
    alloc_inline_shapes = shape_of("inline_alloc")
    transfer_inline_shapes = shape_of("inline_transfer")
    audit.expect("inventory.wrapper_shape_count", 2, len(wrapper_shapes))
    audit.expect("inventory.alloc_inline_shape_is_single", 1, len(alloc_inline_shapes))
    audit.expect("inventory.transfer_inline_shape_is_single", 1, len(transfer_inline_shapes))
    audit.expect(
        "inventory.wrapper_position4_is_always_register_indirect",
        True,
        all(shape[3] == "A7_REG_INDIRECT" for shape in wrapper_shapes),
    )
    audit.expect(
        "inventory.transfer_inline_position2_is_always_register_indirect",
        True,
        all(shape[1] == "A7_REG_INDIRECT" for shape in transfer_inline_shapes),
    )
    audit.expect(
        "inventory.wrapper_shape_signature",
        {("A6_SELF_HANDLE", "A6_SELF_HANDLE", "A6_SELF_HANDLE", "A7_REG_INDIRECT",
          "A5_STACK_SLOT", "A5_STACK_SLOT"): 10,
         ("A8_UNKNOWN", "A6_SELF_HANDLE", "A6_SELF_HANDLE", "A7_REG_INDIRECT",
          "A5_STACK_SLOT", "A5_STACK_SLOT"): 2},
        dict(wrapper_shapes),
    )


    forward_block_counts = {
        (s["stage_label"], b["index"]): b["instruction_count"]
        for s in stages for b in s["branches"]
    }
    backward_block_counts = {
        (t["stage_label"], b["index"]): b["block_instruction_count"]
        for t in tables for b in t["branches"]
    }
    block_count_delta = {
        key: forward_block_counts[key] - backward_block_counts[key]
        for key in sorted(forward_block_counts)
        if forward_block_counts[key] != backward_block_counts[key]
    }
    block_count_delta_rows = [
        {
            "stage": key[0],
            "branch_index": key[1],
            "forward_pass_instruction_count": forward_block_counts[key],
            "backward_pass_block_instruction_count": backward_block_counts[key],
            "forward_minus_backward": block_count_delta[key],
        }
        for key in sorted(block_count_delta)
    ]
    inline_block_values = [
        value for (label, _), value in forward_block_counts.items() if value > 20
    ]
    audit.expect("branch.block_count_delta_count", 16, len(block_count_delta))
    audit.expect("branch.block_count_delta_uniform", {-1},
                 {delta for delta in block_count_delta.values()})
    audit.expect("branch.block_count_delta_only_on_wrapper_branches", True,
                 all(t["branches"][key[1]]["sink_kind"] == "wrapper_call"
                     for t in tables for key in block_count_delta if t["stage_label"] == key[0]))
    audit.expect("branch.inline_body_range", [41, 113], [min(inline_block_values), max(inline_block_values)])


    anchor_cfg = cfg_rows["anchor"]
    entry_cfg = cfg_rows["entry_function"]
    wrapper_cluster_ids = {
        w["rva_hex"]: int(cfg_rows[f"wrapper:{w['rva_hex']}"]["cluster_id"]) for w in wrappers
    }
    transfer_wrappers_in_range = [rva for rva in TRANSFER_WRAPPERS if in_cluster(rva)]
    audit.expect("cluster.allocation_wrappers_cluster_id", {38},
                 {wrapper_cluster_ids[rva] for rva in ALLOCATION_WRAPPERS})
    audit.expect("cluster.transfer_wrappers_cluster_id", {85},
                 {wrapper_cluster_ids[rva] for rva in TRANSFER_WRAPPERS})
    audit.expect("cluster.anchor_cluster_id", 85, int(anchor_cfg["cluster_id"]))
    audit.expect("cluster.entry_cluster_id", 85, int(entry_cfg["cluster_id"]))
    audit.expect("cluster.transfer_wrappers_inside_sixteen_function_range", [],
                 transfer_wrappers_in_range)
    audit.expect("cluster.function_count_field", 16, dataflow["cluster"]["function_count"])
    audit.expect("cluster.functions_listed", 16, len(dataflow["cluster"]["functions"]))
    audit.expect("cluster.anchor_syscall_sites", 16, int(anchor_cfg["syscall_sites"]))
    audit.expect("cluster.anchor_basic_blocks", 108, int(anchor_cfg["basic_blocks"]))
    audit.expect("cluster.anchor_blocks_reached", 1, int(anchor_cfg["blocks_reached"]))
    audit.expect("cluster.anchor_instructions", 1486, int(anchor_cfg["instructions"]))
    audit.expect("cluster.anchor_undecoded_bytes", 0, int(anchor_cfg["undecoded_bytes"]))
    audit.expect("cluster.anchor_switch_sites", 2, int(anchor_cfg["switch_sites"]))
    audit.expect("cluster.anchor_switch_sites_validated", 0,
                 int(anchor_cfg["switch_sites_validated"]))
    audit.expect("cluster.entry_basic_blocks", 8, int(entry_cfg["basic_blocks"]))
    audit.expect("cluster.entry_blocks_reached", 8, int(entry_cfg["blocks_reached"]))
    audit.expect("cluster.entry_instructions", 30, int(entry_cfg["instructions"]))


    schema_agreement = {
        entry["stage_label"]: {
            "branch_count": entry["branch_count"],
            "branches_matching_schema": entry["branches_matching_schema"],
            "branches_diverging_from_schema": entry["branches_diverging_from_schema"],
            "syscall_level_positions": len(entry["schema"]),
            "call_level_positions": len(entry["call_level_schema"]),
        }
        for entry in forward["argument_schema"]["per_stage"]
    }
    audit.expect("schema.alloc_matching", 16, schema_agreement["alloc"]["branches_matching_schema"])
    audit.expect("schema.alloc_diverging", 0, schema_agreement["alloc"]["branches_diverging_from_schema"])
    audit.expect("schema.transfer_matching", 16, schema_agreement["transfer"]["branches_matching_schema"])
    audit.expect("schema.transfer_diverging", 0, schema_agreement["transfer"]["branches_diverging_from_schema"])
    audit.expect("schema.alloc_syscall_positions", 6, schema_agreement["alloc"]["syscall_level_positions"])
    audit.expect("schema.transfer_syscall_positions", 5, schema_agreement["transfer"]["syscall_level_positions"])


    slots = {
        s["frame_offset_hex"]: {
            "role": s["role"],
            "direct_write": s["direct_write_site_count"],
            "address_taken": s["address_taken_site_count"],
            "direct_read": s["direct_read_site_count"],
        }
        for s in forward["result_slot"]["lifecycle"]["slots"]
    }
    audit.expect("slot.transfer_status_no_reader", 0, slots["0x40"]["direct_read"])
    audit.expect("slot.transfer_status_address_taken", 16, slots["0x40"]["address_taken"])
    audit.expect("slot.region_size_no_reader", 0, slots["0x48"]["direct_read"])
    audit.expect("slot.region_size_address_taken", 16, slots["0x48"]["address_taken"])
    audit.expect("slot.remote_base_readers", 2, slots["0x50"]["direct_read"])
    audit.expect("slot.remote_base_address_taken", 16, slots["0x50"]["address_taken"])


    anchor_exits = forward["exits"]["anchor"]
    audit.expect("exit.anchor_count", 3, anchor_exits["exit_count"])
    audit.expect("exit.anchor_sites",
                 ["0xC85709", "0xC86456", "0xC87103"],
                 [e["rva_hex"] for e in anchor_exits["exits"]])
    audit.expect("exit.entry_count", 1, forward["exits"]["entry_function"]["exit_count"])
    audit.expect("exit.single_exit_anchor", True, forward["exits"]["single_exit_anchor"])
    audit.expect("exit.no_status_test_on_any_branch", True,
                 all(not b["status_tested_after_sink"] for s in stages for b in s["branches"]))
    audit.expect("exit.no_indirect_call_in_branches", True,
                 all(b["indirect_call_site_count"] == 0 for s in stages for b in s["branches"]))


    contested: list[dict[str, Any]] = []

    def dispute(
        dispute_id: str,
        severity: str,
        location: str,
        claim: str,
        recomputed: Any,
        verdict: str,
        impact: str,
        correction: str,
    ) -> None:
        contested.append(
            {
                "id": dispute_id,
                "severity": severity,
                "location_in_adhesive_14": location,
                "claim_as_written": claim,
                "recomputed": recomputed,
                "verdict": verdict,
                "impact": impact,
                "proposed_correction": correction,
            }
        )

    audit.record(
        "X-01",
        "caller function count attributed to the twelve wrappers",
        {
            "level_one_rows_for_the_12_wrappers": len(wrapper_level_one),
            "distinct_caller_functions_of_the_12_wrappers": len(wrapper_callers),
            "callers_outside_the_cluster_range": len(wrapper_callers_out),
            "callers_inside_the_cluster_range": len(wrapper_callers_in),
            "callers_inside_the_cluster_range_list": list(wrapper_callers_in),
            "distinct_caller_functions_over_all_13_forward_sinks": len(all_sink_callers),
            "distinct_caller_functions_inside_the_cluster_range_over_all_13": len(sink_callers_in),
            "growth_helper_distinct_callers": len(growth_callers),
            "per_wrapper_distinct_callers": dict(sorted(per_wrapper_callers.items())),
        },
        [
            "c856c0_forward.json#caller_closure.rows",
            "c856c0_callers.csv",
        ],
        "`wrapper_distinct_caller_functions` | 54",
        54,
        len(wrapper_callers),
    )
    audit.record(
        "X-02",
        "how the forward reachable set splits by pdata coverage",
        {
            "distinct_targets": len(reachable_rvas),
            "with_a_runtime_function_record": pdata_covered,
            "without_a_runtime_function_record": len(outside_pdata),
            "without_record_list": sorted(common.hexs(v) for v in outside_pdata),
            "per_depth": {str(d): c for d, c in sorted(depth_split.items())},
        },
        [
            "c856c0_forward.json#forward_reachable_set.functions",
            "c856c0_forward.json#forward_reachable_set.targets_outside_pdata",
        ],
        "21 függvény mellett 16 olyan cél is van",
        21,
        pdata_covered,
    )
    audit.record(
        "X-03",
        "published edge set source address coverage of the anchor code cluster",
        {
            "src_rva_unit": xref.src_rva_unit,
            "src_rva_min": common.hexs(xref.src_rva_min),
            "src_rva_max": common.hexs(xref.src_rva_max),
            "true_hex_high_nibble_histogram": xref.hex_high_nibble_histogram,
            "decimal_leading_digit_histogram": xref.decimal_leading_digit_histogram,
            "in_cluster_source_rows": xref.in_cluster_src_rows,
            "in_cluster_source_functions": list(xref.in_cluster_src_functions),
            "in_cluster_source_by_relation": xref.in_cluster_src_by_relation,
            "in_cluster_imports_reached": list(xref.in_cluster_imports_reached),
            "close_handle_in_cluster_rows": xref.close_handle_in_cluster_rows,
        },
        ["xref_edges.csv#src_rva", "xref_edges.csv#code_instruction_function_begin"],
        "nulla** forrásoldali él származik",
        0,
        xref.in_cluster_src_rows,
    )
    audit.record(
        "X-04",
        "which global address thunk the 0xC8FEE4 call site targets",
        {
            "backward_pass_thunk_list": sorted(
                t["thunk_rva_hex"] for t in dataflow["global_address_thunks"]
            ),
            "forward_pass_target_of_0xC8FEE4": [
                e["rva_hex"] for e in reachable["targets_outside_pdata"]
                if e["callsite_rva_hex"] == "0xC8FEE4"
            ],
            "wrapper_helper_call_at_0xC8FEE4": [
                c["target_rva_hex"] for w in wrappers
                for c in w.get("helper_calls", []) if c["rva_hex"] == "0xC8FEE4"
            ],
            "document_claims_for_this_callsite": ["0xCAC0D0"],
        },
        [
            "c856c0_dataflow.json#global_address_thunks",
            "c856c0_forward.json#forward_reachable_set.targets_outside_pdata",
            "c856c0_forward.json#wrappers[].helper_calls",
        ],
        "0xC8FEE4",
        "0xCAC0D0",
        "0xCAC150",
    )
    audit.record(
        "X-05",
        "branch body instruction count, backward pass against forward pass",
        {
            "field_compared": "c856c0_dataflow.json block_instruction_count against c856c0_forward.json instruction_count",
            "branches_that_differ": len(block_count_delta),
            "delta_per_differing_branch": sorted(set(block_count_delta.values())),
            "forward_pass_wrapper_body_range": [
                min(v for v in forward_block_counts.values() if v < 20),
                max(v for v in forward_block_counts.values() if v < 20),
            ],
            "backward_pass_wrapper_body_range": [
                min(backward_block_counts[key] for key in block_count_delta),
                max(backward_block_counts[key] for key in block_count_delta),
            ],
            "forward_pass_inline_body_range": [min(inline_block_values), max(inline_block_values)],
            "inline_ranges_agree": sorted(
                {forward_block_counts[k] for k in forward_block_counts if forward_block_counts[k] > 20}
            )
            == sorted(
                {backward_block_counts[k] for k in backward_block_counts if backward_block_counts[k] > 20}
            ),
            "affected_branches": block_count_delta_rows,
        },
        [
            "c856c0_dataflow.json#dispatch.tables[].branches[].block_instruction_count",
            "c856c0_forward.json#stages[].branches[].instruction_count",
        ],
        "| Törzs hossza | 8–9 utasítás | 41–113 utasítás |",
        "8–9",
        "8–9 in the forward pass, 9–10 in the backward pass",
    )
    audit.record(
        "X-06",
        "does cluster_id 85 mean the sixteen function anchor range",
        {
            "anchor_range": [common.hexs(CLUSTER_RANGE[0]), common.hexs(CLUSTER_RANGE[1])],
            "anchor_range_function_count": dataflow["cluster"]["function_count"],
            "anchor_cluster_id": int(anchor_cfg["cluster_id"]),
            "transfer_wrapper_cluster_id": wrapper_cluster_ids[TRANSFER_WRAPPERS[0]],
            "transfer_wrappers_inside_the_anchor_range": transfer_wrappers_in_range,
            "note": "cluster_id is a cfg_functions.csv proximity group and is not the sixteen function 0xC85000..0xC88000 range",
        },
        ["cfg_functions.csv#cluster_id", "c856c0_dataflow.json#cluster"],
        "tehát a klaszteren belül",
        "true",
        False,
    )
    audit.record(
        "X-07",
        "published edge set inbound edges for the anchor, the entry function and the growth helper",
        {
            "dst_rows_for_anchor": xref.dst_anchor_function_rows,
            "dst_rows_for_entry_function": xref.dst_entry_function_rows,
            "dst_rows_for_growth_helper": xref.dst_growth_helper_rows,
            "rel32_call_sites_for_anchor_in_the_dedicated_pass": anchor_call_sites,
            "rel32_call_sites_for_growth_helper_in_the_dedicated_pass": sum(
                1 for r in level_one if r["target_fn"] == GROWTH_HELPER
            ),
            "method": closure["method"]["rel32"],
            "note": "the two subject functions have zero published edges, which is "
            "consistent. The growth helper does not, it has 20 rel32 call sites in the "
            "dedicated pass and 0 published edges, so the published set is not a "
            "complete call inventory even inside the low rva band.",
        },
        [
            "xref_edges.csv#dst_rva",
            "c856c0_forward.json#caller_closure.rows",
        ],
        None,
        None,
        0,
    )

    dispute(
        "CF-01",
        "high",
        "section 9.4 table, the three wrapper caller cells",
        "54 distinct caller functions, 54 of them outside the anchor, 0 inside the cluster",
        {
            "distinct_callers_of_the_12_wrappers": len(wrapper_callers),
            "level_one_rows_for_the_12_wrappers": len(wrapper_level_one),
            "of_those_outside_the_cluster_range": len(wrapper_callers_out),
            "of_those_inside_the_cluster_range": len(wrapper_callers_in),
            "inside_the_cluster_range_is": list(wrapper_callers_in),
            "anchor_call_sites_into_the_12_wrappers": sum(
                1 for r in wrapper_level_one if r["caller_fn"] == "0xC856C0"
            ),
            "where_54_comes_from": "the distinct caller count over all 13 forward sinks, the 12 wrappers plus the growth helper 0x495D0, not over the 12 wrappers alone",
            "per_wrapper_distinct_callers": dict(sorted(per_wrapper_callers.items())),
        },
        "contested, all three cells are wrong",
        "The shared helper conclusion of the section survives, 36 of the 37 distinct "
        "callers are outside the 0xC85000..0xC88000 range, but the figures 54, 54 and 0 "
        "are not reproducible from the payload. The anchor 0xC856C0 is itself a caller "
        "of all 12 wrappers from 16 call sites and it lies inside that range, so the "
        "zero cell is false as written. The 54 figure is correct for the 13 sink set, "
        "not for the wrappers.",
        "Replace the three cells with 37, 36 and 1, name 0xC856C0 as the single in range caller, and keep 54 only for the 13 sink set with the growth helper named.",
    )
    dispute(
        "CF-02",
        "high",
        "section 15.4 table and NEG-15, source address distribution of xref_edges.csv",
        "The published edge set contains only the 0x0 to 0x9 high nibbles and therefore no source side edge comes from the 0xC85000..0xC88000 cluster",
        {
            "src_rva_column_unit": "decimal",
            "src_rva_max": common.hexs(xref.src_rva_max),
            "true_hex_high_nibble_histogram": xref.hex_high_nibble_histogram,
            "decimal_leading_digit_histogram": xref.decimal_leading_digit_histogram,
            "in_cluster_source_rows": xref.in_cluster_src_rows,
            "in_cluster_source_functions": list(xref.in_cluster_src_functions),
            "in_cluster_source_by_relation": xref.in_cluster_src_by_relation,
            "in_cluster_imports_reached": list(xref.in_cluster_imports_reached),
            "close_handle_in_cluster_rows": xref.close_handle_in_cluster_rows,
        },
        "contested, the histogram was computed on a decimal column as if it were hexadecimal",
        "NEG-15 is false as written. 17 published edges have their source inside the "
        "anchor cluster, from 5 functions, reaching 0x89FA0 and 0x89CF0 by direct call "
        "and reaching VirtualAlloc, VirtualFree, VirtualQuery and two CRT parameter "
        "failure calls by IAT. The 0xA to 0xF zero cell is true but vacuous, since the "
        "largest src_rva in the file is 0x3306F60 and every true hexadecimal high "
        "nibble in the column is 0x0.",
        "Rewrite the histogram on the decimal leading digit or drop it, and replace "
        "NEG-15 with the measured 17 rows and their 5 source functions. The bounded "
        "negative of section 14.2 is unaffected and should be kept: no CloseHandle and "
        "no DuplicateHandle site is sourced from the cluster.",
    )
    dispute(
        "CF-03",
        "medium",
        "section 14.2, pdata coverage of the forward reachable set",
        "21 pdata covered functions plus 16 targets without a RUNTIME_FUNCTION",
        {
            "distinct_targets_in_the_reachable_set": len(reachable_rvas),
            "with_a_runtime_function_record": pdata_covered,
            "without_a_runtime_function_record": len(outside_pdata),
            "without_record_list": sorted(common.hexs(v) for v in outside_pdata),
            "per_depth": {str(d): c for d, c in sorted(depth_split.items())},
        },
        "contested, the split is 23 and 14",
        "The 37 target count and the 2, 22, 6, 5, 2 depth split are correct. The 21 and 16 pair is not, and the list in the same sentence names 13 addresses while asserting 16.",
        "State 23 with a RUNTIME_FUNCTION record and 14 without, and list the 14, which includes 0xCAC150 that the section 7.4 thunk table omits.",
    )
    dispute(
        "CF-04",
        "medium",
        "section 7.4, global address thunk table and the 0xC8FEE4 call site",
        "The thunk set is 0xCAC0D0, 0xCAC0F0, 0xCAC110, 0xCAC130 and 0xCAC170, and 0xC8FEE4 is a second call site of 0xCAC0D0",
        {
            "backward_pass_thunk_list": sorted(
                t["thunk_rva_hex"] for t in dataflow["global_address_thunks"]
            ),
            "forward_pass_target_of_0xC8FEE4": [
                e["rva_hex"] for e in reachable["targets_outside_pdata"]
                if e["callsite_rva_hex"] == "0xC8FEE4"
            ],
            "wrapper_helper_call_at_0xC8FEE4": [
                c["target_rva_hex"] for w in wrappers
                for c in w.get("helper_calls", []) if c["rva_hex"] == "0xC8FEE4"
            ],
        },
        "contested, 0xC8FEE4 targets 0xCAC150",
        "The table is missing one thunk and one call site is attributed to the wrong target. No audited count changes: the thunks still resolve into .data and none of them is pdata covered.",
        "Add the 0xCAC150 row and correct the call site sentence to read 0xC8FEE4 as the 0xCAC150 call from the 0xC8FDE0 wrapper.",
    )
    dispute(
        "CF-05",
        "medium",
        "section 4.2 closing sentence, wrapper cluster membership",
        "The 12 wrappers are outside the cluster, and the 6 transfer wrappers sit at cluster_id 85, therefore inside the cluster",
        {
            "anchor_range": [common.hexs(CLUSTER_RANGE[0]), common.hexs(CLUSTER_RANGE[1])],
            "anchor_range_function_count": dataflow["cluster"]["function_count"],
            "anchor_cluster_id": int(anchor_cfg["cluster_id"]),
            "transfer_wrapper_cluster_id": wrapper_cluster_ids[TRANSFER_WRAPPERS[0]],
            "transfer_wrappers_inside_the_anchor_range": transfer_wrappers_in_range,
            "note": "cluster_id is a cfg_functions.csv proximity group that spans far more than the sixteen function range, so the two identifiers are not interchangeable",
        },
        "contested, the sentence contradicts itself and the inference does not hold",
        "The two cluster_id values reproduce correctly from cfg_functions.csv, but cluster_id 85 is not the sixteen function 0xC85000..0xC88000 range, and no transfer wrapper lies inside that range.",
        "Split the sentence: report the six allocation wrappers at cluster_id 38 and "
        "the six transfer wrappers at cluster_id 85 as two cfg_functions.csv groups, "
        "and state separately that all 12 lie outside the sixteen function anchor range.",
    )
    dispute(
        "CF-06",
        "low",
        "sections 7.1, 7.2 and 7.3, branch body instruction counts",
        "Wrapper branch bodies are 8 to 9 instructions, inline branch bodies are 41 to 113",
        {
            "forward_pass_wrapper_body_range": [
                min(v for v in forward_block_counts.values() if v < 20),
                max(v for v in forward_block_counts.values() if v < 20),
            ],
            "backward_pass_wrapper_body_value": sorted(
                {backward_block_counts[k] for k in block_count_delta}
            ),
            "forward_pass_inline_body_range": [min(inline_block_values), max(inline_block_values)],
            "branches_that_differ": len(block_count_delta),
            "delta_per_differing_branch": sorted(set(block_count_delta.values())),
            "affected_branches": block_count_delta_rows,
        },
        "definition delta, not a contradiction",
        "The 16 wrapper branch bodies are 10 instructions in the backward pass and 9 in "
        "the forward pass; the two passes disagree on where the branch starts. The "
        "inline counts are identical in both. The document quotes the forward pass "
        "without naming it.",
        "Name the pass in the column header, or give the 8 to 10 range, so a reader checking the backward payload is not surprised.",
    )
    dispute(
        "CF-07",
        "low",
        "section 12.1, the growth helper caller set",
        "The growth helper is called by the entry function and by 0x176F860",
        {
            "growth_helper_level_one_rows": sum(
                1 for r in level_one if r["target_fn"] == GROWTH_HELPER
            ),
            "growth_helper_distinct_callers": len(growth_callers),
            "growth_helper_callers_inside_the_cluster_range": sorted(
                c for c in growth_callers if in_cluster(c)
            ),
        },
        "incomplete rather than wrong",
        "The section names 2 of the 17 distinct callers, and the named one is present. This is a completeness gap, not a numeric error, and it touches none of the audited counts.",
        "Replace the sentence with the count 17 and keep the two named sites as examples.",
    )

    agree_ids = sorted(item["id"] for item in audit.items if item["agreement"] == AGREE)
    contested_ids = sorted(
        item["id"] for item in audit.items if item["agreement"] == CONTESTED
    )
    checked_ids = sorted(
        item["id"] for item in audit.items if item["agreement"] != NOT_STATED
    )

    payload = {
        "schema": SCHEMA_AUDIT_HANDLE_FLOW,
        "audit": {
            "id": "AFH-2026-09-26",
            "title": "independent recomputation audit of the 0xC856C0 handle flow numbers",
            "target_document": AUDITED_DOCUMENT,
            "audited_questions": [
                "how many slots does one dispatch table hold",
                "how many direct syscall branches",
                "how many wrapper call branches",
                "how many wrapper functions, 6 allocation plus 6 transfer or something else",
                "how many syscall sites in total",
                "how many handle loads",
                "how many consumer edges",
                "where the producer and caller boundary sits",
                "what the 21 wrapper_forwarding service map predicate counts, by scope",
            ],
            "verdict": {
                "checked_items": checked_ids,
                "agree": agree_ids,
                "contested": contested_ids,
                "contested_statements": [entry["id"] for entry in contested],
                "statement": "The eight arithmetic questions resolve as the document "
                "states them: two tables of 16 slots, 16 direct syscall branches, 16 "
                "wrapper call branches, 12 wrapper functions split 6 plus 6, 28 syscall "
                "sites, 2 handle loads, 32 consumer edges, and a closed producer and "
                f"caller boundary at 0xC85650 that leaves the producer open. Seven "
                "statements elsewhere in the document are not reproducible from the "
                f"{len(EVIDENCE_INPUTS)} attested inputs and are listed in the contested "
                "section. No audited count changes.",
            },
        },
        "observation": {
            "role": "what this audit read at run time, reported for the record and not attested",
            "is_attestation": False,
            "carries_a_verdict": False,
            "absent_from": "the inputs block and the audit block, so no digest in this payload claims the audited document",
            "audited_document": {
                "path": AUDITED_DOCUMENT,
                "size": args.document.stat().st_size,
                "sha256": common.sha256_file(args.document),
            },
            "why_not_attested": (
                "reverse/evidence/audit_handle_flow.json is itself digested by the audited "
                "document, so a digest recorded here for that document would close a cycle: "
                "editing either file invalidates the digest the other one records, and no "
                "state of the tree can make both pins fresh at once. The value is therefore "
                "an observation of the bytes this run read, it is excluded from the attested "
                "inputs, and no check in the validation block is derived from it. The "
                "attested inputs are the evidence artifacts alone."
            ),
        },
        "script": {
            "path": "reverse/scripts/audit_handle_flow.py",
            "sha256": common.sha256_file(script),
        },
        "specimen_reference": {
            "path": forward["specimen"]["path"],
            "size": forward["specimen"]["size"],
            "sha256": forward["specimen"]["sha256"],
            "image_base_hex": forward["specimen"]["image_base_hex"],
            "source": "quoted from c856c0_forward.json#specimen and c856c0_dataflow.json#specimen",
            "specimen_file_opened_by_this_audit": False,
        },
        "scope": {
            "question": "does adhesive-14 state the 0xC856C0 handle flow numbers correctly",
            "method": f"every audited quantity is recomputed from the {len(EVIDENCE_INPUTS)} attested inputs only; no fresh disassembly and no PE parse is performed, so the audit can confirm or refute internal consistency and the report's reading of the evidence, and cannot extend the evidence",
            "direction": "recomputation over published evidence, not a new extraction",
            "execution": "static file parsing of csv and json evidence only; the specimen is never opened, mapped, loaded, patched or executed",
            "independence": "the audit reads the payloads and the report but writes neither; adhesive-14 is left byte for byte unchanged",
            "no_actionable_output": "this payload records counts, an authoritative "
            "table, a contested list and correction proposals. It names no service, no "
            "target process, no producer and no patch, and it contains no exploit, "
            "bypass or shellcode guidance",
            "determinism": {
                "iteration": "sorted by rva, then by label, then by branch index",
                "payload_timestamps": False,
                "json_indent": 2,
                "json_ensure_ascii": False,
                "json_sort_keys": False,
                "line_terminator": "\\n",
                "trailing_newline": True,
            },
            "libraries": ["python standard library csv and json"],
            "libraries_note": "the repository helper reverse/scripts/common.py supplies the writer, the check record, the hex formatting and the sha256 helper; its pefile dependency is imported but never exercised by this audit",
        },
        "inputs": [
            {
                "path": f"reverse/evidence/{name}",
                "sha256": common.sha256_file(args.evidence / name),
                "size": (args.evidence / name).stat().st_size,
            }
            for name in EVIDENCE_INPUTS
        ],
        "inputs_note": (
            "the attested inputs are the evidence artifacts this audit recomputed from. The "
            "audited document is read but not attested here, because reverse/evidence/"
            "audit_handle_flow.json is digested by that document and a digest of the document "
            "in this payload would close a cycle. Its digest is reported under the "
            "observation block instead."
        ),
        "csv_contract": {
            "c856c0_callers.csv": {
                "row_count": callers_index.row_count,
                "column_count": callers_index.column_count,
                "header": callers_index.header,
                "trailing_newline": callers_index.trailing_newline,
            },
            "cfg_functions.csv": {
                "row_count": 142004,
                "column_count": len(cfg_header),
                "header": ",".join(cfg_header),
            },
            "syscall_inventory.csv": {
                "row_count": sum(class_histogram.values()),
                "column_count": len(inventory_header),
                "header": ",".join(inventory_header),
            },
            "xref_edges.csv": {
                "row_count": xref.row_count,
                "column_count": xref.column_count,
                "header": ",".join(xref_header),
                "numeric_column_unit": "decimal",
            },
            "note": "the rva columns of xref_edges.csv and the *_rva_hex columns of syscall_inventory.csv carry the base in the column name. Reading a decimal column in the wrong base is the root cause of contested item CF-02.",
        },
        "authoritative_table": [
            {
                "id": item["id"],
                "quantity": item["question"],
                "authoritative_value": item["recomputed_scalar"],
                "decomposition": item["recomputed"]
                if isinstance(item["recomputed"], (dict, list))
                else None,
                "agreement_with_adhesive_14": item["agreement"],
                "document_anchor": item["document_anchor"],
                "document_anchor_present": item["document_anchor_present"],
                "document_value": item["document_value"],
                "source_of_truth": item["source_of_truth"],
            }
            for item in audit.items
        ],
        "recompute_detail": {
            "dispatch": {
                "table_count": len(tables),
                "table_rvas": [t["table_rva_hex"] for t in tables],
                "table_raws": [common.hexs(t["table_raw"]) for t in tables],
                "slots_per_table": slots_per_table,
                "slots_total": branch_total,
                "slot_step_bytes": slot_steps,
                "table_delta_bytes": table_delta,
                "materialised_by": [t["materialised_by_hex"] for t in tables],
                "merge_rvas": [t["merge_rva_hex"] for t in tables],
                "selectors": [
                    {
                        "stage_label": s["stage_label"],
                        "rdtsc_rva": s["rdtsc_rva_hex"],
                        "mask_rva": s["mask_rva_hex"],
                        "mask_text": s["mask_instruction"]["text"],
                        "mask_bytes": s["mask_instruction"]["bytes"],
                        "indirect_jmp_rva": s["indirect_jmp_rva_hex"],
                    }
                    for s in dispatch["selectors"]
                ],
                "tables_are_adjacent": adjacent,
                "distinct_block_targets_per_table": distinct_targets,
            },
            "branches": {
                "per_stage": per_stage,
                "inline_total": inline_branches,
                "wrapper_total": wrapper_branches,
                "argument_register_split": dict(
                    sorted(
                        Counter(
                            b["handle_argument_register"] for t in tables for b in t["branches"]
                        ).items()
                    )
                ),
                "join_kind_split": dict(
                    sorted(
                        Counter(
                            f"{b['sink_kind']}:{b['join']['kind']}"
                            for t in tables for b in t["branches"]
                        ).items()
                    )
                ),
                "merge_reachability_split": dict(
                    sorted(
                        Counter(
                            f"{b['sink_kind']}:{b['join'].get('merge_reachability')}"
                            for t in tables for b in t["branches"]
                        ).items()
                    )
                ),
                "status_tested_after_sink_split": dict(
                    sorted(
                        Counter(
                            f"{b['sink_kind']}:{b['status_tested_after_sink']}"
                            for s in stages for b in s["branches"]
                        ).items()
                    )
                ),
                "indirect_call_site_count_split": dict(
                    sorted(
                        Counter(
                            f"{b['sink_kind']}:{b['indirect_call_site_count']}"
                            for s in stages for b in s["branches"]
                        ).items()
                    )
                ),
                "other_calls_split": dict(
                    sorted(
                        Counter(
                            f"{b['sink_kind']}:{len(b.get('other_calls', [])) > 0}"
                            for t in tables for b in t["branches"]
                        ).items()
                    )
                ),
                "schema_agreement_per_stage": schema_agreement,
                "block_instruction_count": {
                    "forward_pass": {
                        f"{label}:{index}": value
                        for (label, index), value in sorted(forward_block_counts.items())
                    },
                    "backward_pass": {
                        f"{label}:{index}": value
                        for (label, index), value in sorted(backward_block_counts.items())
                    },
                    "delta_rows": block_count_delta_rows,
                },
            },
            "wrappers": {
                "total": len(wrappers),
                "per_stage": dict(sorted(by_stage.items())),
                "rvas": list(wrapper_rvas),
                "allocation_rva_band": [ALLOCATION_WRAPPERS[0], ALLOCATION_WRAPPERS[-1]],
                "transfer_rva_band": [TRANSFER_WRAPPERS[0], TRANSFER_WRAPPERS[-1]],
                "syscall_sites": [w["syscall"]["rva_hex"] for w in wrappers],
                "return_sites": [w["return_site"]["rva_hex"] for w in wrappers],
                "status_return_sites": [w["status_return_site"]["rva_hex"] for w in wrappers],
                "called_from_branch_indexes": {
                    w["rva_hex"]: w["called_from_branch_indexes"] for w in wrappers
                },
                "prologue_frame_bytes": {
                    w["rva_hex"]: w["prologue_frame_bytes"] for w in wrappers
                },
                "api_call_site_count_sum": sum(w["api_call_site_count"] for w in wrappers),
                "returns_syscall_status_all": all(w["returns_syscall_status"] for w in wrappers),
                "handle_argument_position_all": sorted(
                    {w["handle_argument_position"] for w in wrappers}
                ),
                "argument_forwarding_rule": "call argument position n reaches syscall argument position n-1 on every wrapper",
                "argument_forwarding_holds": all(forwarding_offsets),
                "cluster_id_by_wrapper": dict(sorted(wrapper_cluster_ids.items())),
                "distinct_caller_functions": len(wrapper_callers),
                "callers_inside_cluster_range": list(wrapper_callers_in),
                "callers_outside_cluster_range": list(wrapper_callers_out),
                "per_wrapper_distinct_callers": dict(sorted(per_wrapper_callers.items())),
            },
            "syscall_sites": {
                "inline_count": inline_count,
                "inline_per_stage": dict(
                    sorted(Counter(s["stage_label"] for s in inline_syscalls).items())
                ),
                "inline_positions_per_stage": {
                    label: sorted(
                        {len(s["arguments"]) for s in inline_syscalls if s["stage_label"] == label}
                    )
                    for label in ("alloc", "transfer")
                },
                "inline_rvas": [s["rva_hex"] for s in inline_syscalls],
                "wrapper_count": wrapper_syscall_sum,
                "total": subject_syscall_total,
                "cfg_functions_csv_syscall_sites": cfg_syscalls,
                "cfg_functions_csv_total_over_reachable_pdata_functions": subject_syscall_total,
                "inventory_service_class_split": dict(sorted(subject_classes.items())),
                "inventory_status_split": dict(sorted(subject_statuses.items())),
                "inventory_named_rows": 0,
                "inventory_shape_signatures": {
                    "inline_alloc": [list(shape) for shape in sorted(alloc_inline_shapes)],
                    "inline_transfer": [list(shape) for shape in sorted(transfer_inline_shapes)],
                    "wrappers": [list(shape) for shape in sorted(wrapper_shapes)],
                },
            },
            "handle_flow": {
                "expression": handle["expression"],
                "load_count": len(loads),
                "load_sites": [
                    {
                        "rva": load["rva_hex"],
                        "raw": common.hexs(load["raw"]),
                        "register": load["register"],
                        "text": load["instruction"]["text"],
                        "bytes": load["instruction"]["bytes"],
                    }
                    for load in loads
                ],
                "use_site_count": len(use_sites),
                "use_sites_per_stage": dict(sorted(stage_split.items())),
                "argument_register_split": dict(sorted(register_split.items())),
                "sink_kind_split": dict(sorted(Counter(s["sink_kind"] for s in use_sites).items())),
                "consume_site_count_field": forward["handle_lifetime"]["consume_site_count"],
                "value_may_change_between_loads": handle["value_may_change_between_loads"],
                "descriptor_fields_observed": dataflow["object_model"]["descriptor"]["fields_observed"],
                "descriptor_size_bytes_field": dataflow["object_model"]["descriptor"]["size_bytes"],
            },
            "producer_and_caller_boundary": {
                "anchor": {
                    "rva": ANCHOR_FUNCTION,
                    "inbound_rel32_call_sites": anchor_call_sites,
                    "inbound_site": anchor_call_site.get("rva_hex"),
                    "inbound_site_bytes": anchor_call_site.get("encoding"),
                },
                "entry_function": {
                    "rva": ENTRY_FUNCTION,
                    "forms_enumerated": entry_forms,
                    "site_count_per_form": {
                        name: value.get("site_count", 0)
                        for name, value in sorted(entry_negative.items())
                    },
                    "forms_with_zero_sites": entry_zero_forms,
                    "frontier_after_last_level": closure["scopes"][0]["frontier_after_last_level"],
                    "exhausted": closure["scopes"][0]["exhausted"],
                },
                "closure_rows": {
                    "total": len(closure_rows),
                    "csv_total": len(callers_rows),
                    "csv_matches_json": sorted(row_tuple(r) for r in callers_rows)
                    == sorted(row_tuple(r) for r in closure_rows),
                    "per_level": dict(sorted(level_split.items())),
                    "per_edge_kind": dict(sorted(kind_split.items())),
                    "per_scope_and_level": {
                        f"{scope}:{level}": count
                        for (scope, level), count in sorted(scope_level_split.items())
                    },
                    "rows_carrying_F_U_01": sum(1 for r in closure_rows if r["open"] == "F-U-01"),
                    "uncovered_call_site_count": closure["uncovered_call_site_count"],
                    "method": closure["method"],
                },
                "caller_functions": {
                    "level_one_rows_total": len(level_one),
                    "distinct_over_all_13_forward_sinks": len(all_sink_callers),
                    "distinct_over_the_12_wrappers": len(wrapper_callers),
                    "wrappers_inside_cluster_range": list(wrapper_callers_in),
                    "wrappers_outside_cluster_range": list(wrapper_callers_out),
                    "sinks_inside_cluster_range": list(sink_callers_in),
                    "growth_helper_distinct": len(growth_callers),
                },
                "published_edge_set": {
                    "row_count": xref.row_count,
                    "dst_rows_for_anchor": xref.dst_anchor_function_rows,
                    "dst_rows_for_entry_function": xref.dst_entry_function_rows,
                    "dst_rows_for_growth_helper": xref.dst_growth_helper_rows,
                    "close_handle_rows": xref.dst_symbol_rows.get("CloseHandle", 0),
                    "duplicate_handle_rows": xref.dst_symbol_rows.get("DuplicateHandle", 0),
                    "close_handle_in_cluster_rows": xref.close_handle_in_cluster_rows,
                    "nearest_close_handle_sites": [
                        {"src_rva": site, "distance_from_anchor": distance, "relation": relation}
                        for site, distance, relation in xref.nearest_close_handle_sites
                    ],
                },
                "handle_lifetime_published": {
                    "ownership": forward["handle_lifetime"]["ownership"],
                    "conclusion_confidence": forward["handle_lifetime"]["conclusion_confidence"],
                    "reachable_set_exhausted": forward["handle_lifetime"]["reachable_set"]["exhausted"],
                    "dir64_cluster_slot_count": forward["handle_lifetime"]["dir64_census"]["cluster_slot_count"],
                    "cluster_range_api_site_counts": {
                        name: value["site_count"]
                        for name, value in sorted(
                            forward["handle_lifetime"]["cluster_range_sites"]["apis"].items()
                        )
                    },
                },
                "producer_status": handle["producer"]["status"],
                "producer_identified": handle["producer"]["identified"],
                "producer_unresolved_id": handle["producer"]["unresolved_id"],
            },
            "reachable_set": {
                "function_count_field": reachable["function_count"],
                "distinct_targets": len(reachable_rvas),
                "per_depth": {str(d): c for d, c in sorted(depth_split.items())},
                "max_depth": reachable["max_depth"],
                "exhausted": reachable["exhausted"],
                "with_runtime_function_record": pdata_covered,
                "without_runtime_function_record": len(outside_pdata),
                "without_record_list": [
                    {
                        "rva": common.hexs(e["rva"]),
                        "callsite": e["callsite_rva_hex"],
                        "from": e["from_rva_hex"],
                    }
                    for e in sorted(reachable["targets_outside_pdata"], key=lambda x: x["rva"])
                ],
            },
            "frame_slots": slots,
            "exits": {
                "anchor_count": anchor_exits["exit_count"],
                "anchor_sites": [e["rva_hex"] for e in anchor_exits["exits"]],
                "entry_count": forward["exits"]["entry_function"]["exit_count"],
                "single_exit_anchor": forward["exits"]["single_exit_anchor"],
            },
        },
        "wrapper_forwarding_predicate": {
            "phase": service_map["phase"],
            "group": "wrapper_forwarding",
            "rule_as_published": service_map["service_classes"]["wrapper_forwarding"]["rule"],
            "anchor_token": "four_entry_parameters_forwarded",
            "published_site_count": service_map["service_classes"]["wrapper_forwarding"]["sites"],
            "recomputed_site_count": len(forwarding_rows),
            "recomputed_shape": {
                "argument_positions_1_to_4": [list(shape) for shape in sorted(forwarding_shapes)],
                "position_5_classes": dict(
                    sorted(Counter(r["arg5_class"] for r in forwarding_rows).items())
                ),
                "position_6_classes": dict(
                    sorted(Counter(r["arg6_class"] for r in forwarding_rows).items())
                ),
                "rva_band": [common.hexs(forwarding_band[0]), common.hexs(forwarding_band[1])],
                "distinct_owning_runtime_functions": len(forwarding_owners),
                "owning_runtime_functions": forwarding_owners,
                "status_split": dict(
                    sorted(Counter(r["status"] for r in forwarding_rows).items())
                ),
            },
            "scope_explanation": {
                "what_the_predicate_counts": "a shape class over the whole 3627 site "
                "corpus, not a location class and not a function inventory. A site "
                "lands here when all four of its argument register positions hold a "
                "value the site received from its own entry parameters, which is the "
                "classifier's way of recording that the argument schema the reader wants "
                "belongs to the calling layer rather than to the site. It is a cross "
                "layer marker, and the phase writes no service name for such a row.",
                "why_the_count_is_21": "21 of the 3627 corpus sites satisfy that four "
                "position conjunction, and all 21 carry the identical argument1 to "
                "argument4 signature of four self handles. They live in the 0x291C08F to "
                "0x2951479 band under 7 runtime functions, far from the 0xC856C0 subject "
                "set.",
                "why_the_12_c856c0_wrappers_are_not_among_the_21": "the predicate is a "
                "conjunction over argument positions 1 to 4 only. The 12 wrappers of the "
                "0xC856C0 subject set have 6 syscall argument positions whose signature "
                "is position 1 a state global or an opaque value, positions 2 and 3 self "
                "handles, position 4 always a register indirect operand, and positions 5 "
                "and 6 stack slots. A register indirect operand is a symbolic unknown by "
                "the phase's own rule, so position 4 alone fails the conjunction for all "
                "12 wrappers, and position 1 fails it at 2 of them. All 12 therefore "
                "carry anchor token no_anchor and land in the other group.",
                "why_the_8_allocation_inline_sites_are_classified_differently": "their "
                "6 position argument set carries both the 0x1000 and the 0x40 constant, "
                "so the earlier allocation_0x1000_0x40 anchor fires and they are grouped "
                "there, 8 sites. This is the only c856c0 group membership in the whole "
                "service map, and it independently corroborates the two constants of the "
                "document's section 10.1 from a phase that never saw the document.",
                "why_the_8_transfer_inline_sites_are_not_transfer_5arg": "the "
                "transfer_5arg rule needs all five enumerated positions resolved to a "
                "class other than unknown or stack slot, and position 2, the remote base, "
                "is a register indirect operand, which is symbolic unknown by rule. All 8 "
                "land in the other group.",
                "why_the_12_wrappers_carry_other_although_they_forward_the_same_constants": "the "
                "constants 0x1000 and 0x40 reach the service through the wrappers one "
                "layer down, while the classifier reads only the argument window around "
                "the candidate. The phase states this itself in "
                "reconciliation.forwarding_is_not_a_conflict and marks such rows "
                "alloc_write_scope=window with alloc_write=forwarded_or_cross_layer. A "
                "buffer or a constant that arrives by forwarding is a scope difference, "
                "not a contradiction.",
                "relation_to_the_audited_counts": "the number 21 has no arithmetic role "
                "in the 0xC856C0 subject set. It is disjoint from the 12 wrappers, from "
                "the 16 inline sites and from the 0xC85000 to 0xC88000 code cluster. The "
                "structural idea it names is the idea the document's section 9.1 already "
                "states for its own wrappers, call argument n reaching syscall argument n "
                "minus 1, so the concept transfers while the number does not.",
                "if_the_rule_were_widened": "an anchor rule of the form every enumerated "
                "register position is a value received from the caller would place the 12 "
                "wrappers in the same shape family, because all 12 satisfy the document's "
                "forwarding offset on every position. That would be a new classifier "
                "version with its own site count, not a restatement of the published 21.",
                "status_of_every_c856c0_site": {
                    "named": 0,
                    "unresolved": 28,
                    "note": "all 28 subject sites carry status unresolved_symbolic_service_number and nt_service UNRESOLVED, consistent with the document's Q-02 and F-U-02 and with the phase result that 0 of 3627 corpus sites were named.",
                },
            },
        },
        "contested": contested,
        "corrections": [
            {
                "id": entry["id"],
                "severity": entry["severity"],
                "target": f"{AUDITED_DOCUMENT} :: {entry['location_in_adhesive_14']}",
                "action": entry["proposed_correction"],
                "applied_by_this_audit": False,
                "note": "proposal only, adhesive-14 is not modified by this audit",
            }
            for entry in contested
        ],
        "confirmed_without_dispute": [
            {
                "topic": "dispatch geometry",
                "detail": "two tables, 16 slots each, 32 slots, 4 byte slot step, the second table exactly 0x40 after the first, an own RDTSC and AND EAX, 0xF selector per table, an own merge point per table",
                "source": "c856c0_dataflow.json#dispatch",
            },
            {
                "topic": "branch split",
                "detail": "8 inline syscall and 8 wrapper call branches per stage, 16 and 16 in total, 16 distinct block targets per table",
                "source": "c856c0_dataflow.json#dispatch.tables[].branches",
            },
            {
                "topic": "wrapper inventory",
                "detail": "12 distinct wrappers, 6 allocation and 6 transfer, one "
                "syscall each, call argument n reaching syscall argument n minus 1 on "
                "every wrapper, 0 api call sites, no close and no duplicate, handle at "
                "call argument position 1 everywhere",
                "source": "c856c0_forward.json#wrappers, cfg_functions.csv#syscall_sites",
            },
            {
                "topic": "syscall site total",
                "detail": "28 syscall sites, 16 in the anchor and 12 in the wrappers, and no other function in the 23 pdata covered members of the forward reachable set carries a syscall site",
                "source": "cfg_functions.csv#syscall_sites over the reachable set",
            },
            {
                "topic": "handle loads and consumers",
                "detail": "2 separate reads of the same descriptor field, at 0xC856F3 into r14 and at 0xC86440 into rbx, 32 use sites, 16 per stage, argument register split 16 r10 and 16 rdx, only field offset 0 ever touched",
                "source": "c856c0_dataflow.json#handle",
            },
            {
                "topic": "argument schema agreement",
                "detail": "16 of 16 branches match the stage schema and 0 diverge for both stages, at 6 and 5 syscall positions and 7 and 6 call positions",
                "source": "c856c0_forward.json#argument_schema.per_stage",
            },
            {
                "topic": "frame slot lifecycle",
                "detail": "rsp+0x40 and rsp+0x48 have 1 direct write, 16 address takes and 0 direct reads, rsp+0x50 has 1 direct write, 16 address takes and 2 direct reads, so the transfer status slot has no reader",
                "source": "c856c0_forward.json#result_slot.lifecycle.slots",
            },
            {
                "topic": "exits and status testing",
                "detail": "3 anchor exits at 0xC85709, 0xC86456 and 0xC87103, 1 entry function exit, status_tested_after_sink false on all 32 branches, 0 indirect call sites in all 32 branch bodies",
                "source": "c856c0_forward.json#exits, #stages[].branches",
            },
            {
                "topic": "merge reachability split",
                "detail": "the 16 wrapper branches join by unconditional jump with merge_reachability OBSERVED, the 16 inline branches join by fall through after the syscall with merge_reachability NOT_ASSERTED",
                "source": "c856c0_forward.json#stages[].branches[].join",
            },
            {
                "topic": "cfg cross check of the anchor and the entry function",
                "detail": "the anchor has 6724 bytes, 108 basic blocks with 1 reached, "
                "reached_ratio 0.009259, 1486 instructions, 0 undecoded bytes, 69 call "
                "and 31 direct jmp and 2 indirect jmp and 1 jcc and 1 ret terminators, "
                "16 syscall sites, 2 switch sites of 0 validated, cluster 85; the entry "
                "function has 112 bytes, 8 of 8 blocks reached, 30 instructions, cluster 85",
                "source": "cfg_functions.csv rows 0xC856C0 and 0xC85650",
            },
            {
                "topic": "reference scan and pdata",
                "detail": "0 rel32, rip relative, absolute pointer or code pointer slot "
                "edges reach 0xC85650, exactly 1 rel32 call reaches 0xC856C0 at "
                "0xC85681 with encoding e8 3a 00 00 00, the 3 32 bit occurrences are the "
                "pdata begin_address, end_address and begin_address fields at record "
                "38549 twice and 38550 once, and 0 of 19041 DIR64 slots hold a VA into "
                "the cluster",
                "source": "c856c0_dataflow.json#reference_scan",
            },
            {
                "topic": "close and duplicate negative inside the cluster",
                "detail": "the published edge set has 61 CloseHandle rows and 0 "
                "DuplicateHandle rows with the 59, 1, 1 relation split, and 0 of those "
                "61 CloseHandle rows is sourced from the 0xC85000 to 0xC88000 range, so "
                "the section 14.2 cluster negative stands even though CF-02 invalidates "
                "NEG-15",
                "source": "xref_edges.csv#dst_symbol, c856c0_forward.json#handle_lifetime.cluster_range_sites",
            },
            {
                "topic": "constant pools and thunk encodings",
                "detail": "the four measured windows reproduce at 0x31261B0 160 bytes "
                "entropy 5.692855837 with 40 zero bytes and 2 of 6 groups, 0x3189A90 256 "
                "bytes entropy 5.426974043 with 88 zero bytes and 5 of 10 groups, "
                "0x30E35F0 64 bytes all zero, and the anchor body 6724 bytes entropy "
                "5.997035892 with 266 zero bytes and 0 such groups; all 5 backward pass "
                "thunks resolve into .data and none is pdata covered",
                "source": "c856c0_dataflow.json#constant_pools, #global_address_thunks",
            },
            {
                "topic": "caller closure csv against payload",
                "detail": "444 rows in both, per level 14, 429 and 1, per edge kind 14 "
                "forward_subject, 429 direct_call and 1 "
                "no_inbound_edge_in_enumerated_forms, 220 rows carry F-U-01, 0 uncovered "
                "call sites, and the row tuples are equal as multisets in both files",
                "source": "c856c0_callers.csv, c856c0_forward.json#caller_closure.rows",
            },
            {
                "topic": "service naming stays open",
                "detail": "the service map names 0 of 3627 corpus sites and 0 of the 28 "
                "subject sites, every one is UNRESOLVED with a symbolic service number, "
                "which supports the document's Q-02 and F-U-02 without adding any naming "
                "information",
                "source": "syscall_service_map.json#service_number.naming_gate, syscall_inventory.csv",
            },
        ],
        "limitations": [
            "The specimen is not read. Every specimen identity in this payload is quoted from the inputs, so the audit cannot detect a specimen change the payloads do not record.",
            "No disassembly is performed, so a payload field the underlying bytes do not support would pass this audit unchanged. The audit tests the report against the evidence, not the evidence against the file.",
            f"A contested entry means the statement is not reproducible from the {len(EVIDENCE_INPUTS)} attested inputs. It does not by itself mean the statement is false of the specimen.",
            "The absence of a service name is preserved, not resolved. All 28 subject sites and all 3627 corpus sites are UNRESOLVED in the service map, and this audit adds no naming information.",
            "The producer and the ownership of the handle stay open. The boundary at 0xC85650 is closed for the six enumerated edge forms only, and a register indirect or stack slot caller cannot be excluded statically.",
            "The forward reachable set stopped at depth 4 with exhausted false, so the wrapper caller census is bounded by the same rel32 sweep and does not cover indirect callers.",
            "The xref_edges.csv coverage limit is not uniform: it holds 0 edges for 0x495D0 although the dedicated rel32 pass finds 20, so a zero in that file is not by itself a structural negative.",
        ],
        "validation": {
            "check_count": len(audit.checks),
            "failed_count": sum(1 for check in audit.checks if not check.ok),
            "checks": [check.as_row() for check in audit.checks],
        },
    }
    common.write_json(args.out, payload)

    failed = common.report_checks(audit.checks, args.max_report)
    print(f"script    {script.relative_to(root).as_posix()}")
    print(
        f"document  {args.document.relative_to(root).as_posix()} "
        f"sha256={payload['observation']['audited_document']['sha256']} (observed, not attested)"
    )
    print(
        f"tables    {len(tables)} x {slots_per_table[0]} slots, {branch_total} total, "
        f"inline={inline_branches} wrapper={wrapper_branches}"
    )
    print(
        f"wrappers  {len(wrappers)} total, alloc={by_stage.get('alloc', 0)} "
        f"transfer={by_stage.get('transfer', 0)}, syscalls={subject_syscall_total}"
    )
    print(
        f"handle    loads={len(loads)} use_sites={len(use_sites)} "
        f"r10={register_split.get('r10', 0)} rdx={register_split.get('rdx', 0)}"
    )
    print(
        f"caller    distinct_wrapper_callers={len(wrapper_callers)} "
        f"outside_cluster={len(wrapper_callers_out)} inside={len(wrapper_callers_in)}"
    )
    print(
        f"reachable targets={len(reachable_rvas)} pdata_covered={pdata_covered} "
        f"without_record={len(outside_pdata)}"
    )
    print(
        f"forwarding sites={len(forwarding_rows)} band="
        f"{common.hexs(forwarding_band[0])}..{common.hexs(forwarding_band[1])}"
    )
    print(
        f"xref      rows={xref.row_count} in_cluster_src={xref.in_cluster_src_rows} "
        f"unit={xref.src_rva_unit}"
    )
    print(f"verdict   agree={len(agree_ids)} contested_items={len(contested_ids)} contested_statements={len(contested)}")
    print(f"json      {args.out.relative_to(root).as_posix()}")
    print(f"checks    {len(audit.checks) - failed}/{len(audit.checks)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
