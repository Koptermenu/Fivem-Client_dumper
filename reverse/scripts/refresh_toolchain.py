"""Deterministic refresh of reverse/evidence/toolchain.json for the adhesive.dll evidence set.

The base payload is produced by common.build_toolchain, so the script inventory, the
host and interpreter records and the specimen digest keep coming from the one helper the
rest of the evidence set already depends on. This module adds the three things that record
was missing: the version axes behind every third-party package, a per-script import census,
and the digests of the artifacts the toolchain claims to describe.

Every package is versioned on independent axes and the axes are never collapsed into one
number. The installed distribution metadata, the attribute the imported module exposes and
the version the native engine reports are recorded side by side, so a disagreement stays
visible instead of being smoothed away. When the axes disagree the record also states which
producers import the package and which document prose names a version, which is what makes
the difference between the two values decidable instead of ambiguous.

Static file parsing only: nothing here loads or executes the specimen. The payload carries
no run timestamp and no filesystem modification time, so two refreshes of an unchanged tree
produce byte-identical output and --check can be used as a regression gate.

Reading the inventory costs nothing to reproduce: python reverse/scripts/refresh_toolchain.py
rewrites the file, python reverse/scripts/refresh_toolchain.py --check reports the difference
without writing. The digests block hashes the five decoded csv artifacts as well as pdata_stats.json,
baseline.json, common.py and unresolved_regions.json. The first eight reach every artifact
audit_infra.py audits except the payload itself: none of the five csv producers records an output
digest of its own the way pdata_map.py does, so the toolchain block is what attests them. The ninth,
unresolved_regions.json, is not an audited artifact but a derived payload nothing else attests, so
hashing it is what keeps it from drifting unnoticed. The refresh therefore has to run after
pdata_map.py, cfg_build.py, xref_build.py, syscall_scan.py and unresolved_regions.py, since it
hashes what they write. The block cannot attest the payload and none of the files it attests records
the payload digest, so the digests and the artifacts they cover form no cycle: the guard in
cycle_targets rejects a target equal to the payload before the write, and audit_infra.py re-derives
the second half of that claim on every run.
"""

from __future__ import annotations

import argparse
import ast
import importlib
import importlib.metadata
import json
import re
import sys
import sysconfig
from pathlib import Path
from typing import Any, Final, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import common

SPECIMEN_RELATIVE: Final[str] = "reverse/adhesive.dll"
SCRIPTS_RELATIVE: Final[str] = "reverse/scripts"
DEFAULT_OUTPUT: Final[str] = "reverse/evidence/toolchain.json"
PDATA_STATS_RELATIVE: Final[str] = "reverse/evidence/pdata_stats.json"
BASELINE_RELATIVE: Final[str] = "reverse/evidence/baseline.json"
COMMON_RELATIVE: Final[str] = "reverse/scripts/common.py"
CFG_FUNCTIONS_RELATIVE: Final[str] = "reverse/evidence/cfg_functions.csv"
CFG_CLUSTERS_RELATIVE: Final[str] = "reverse/evidence/cfg_clusters.csv"
XREF_EDGES_RELATIVE: Final[str] = "reverse/evidence/xref_edges.csv"
INDIRECT_SITES_RELATIVE: Final[str] = "reverse/evidence/indirect_sites.csv"
SYSCALL_CANDIDATES_RAW_RELATIVE: Final[str] = "reverse/evidence/syscall_candidates_raw.csv"
UNRESOLVED_REGIONS_RELATIVE: Final[str] = "reverse/evidence/unresolved_regions.json"
FOUNDATION_DIGEST_ENTRIES: Final[tuple[str, ...]] = (
    BASELINE_RELATIVE,
    COMMON_RELATIVE,
    PDATA_STATS_RELATIVE,
)
AUDITED_CSV_DIGEST_ENTRIES: Final[tuple[str, ...]] = (
    CFG_FUNCTIONS_RELATIVE,
    CFG_CLUSTERS_RELATIVE,
    XREF_EDGES_RELATIVE,
    INDIRECT_SITES_RELATIVE,
    SYSCALL_CANDIDATES_RAW_RELATIVE,
)
UNATTESTED_JSON_DIGEST_ENTRIES: Final[tuple[str, ...]] = (UNRESOLVED_REGIONS_RELATIVE,)
DIGEST_ENTRIES: Final[tuple[str, ...]] = (
    FOUNDATION_DIGEST_ENTRIES + AUDITED_CSV_DIGEST_ENTRIES + UNATTESTED_JSON_DIGEST_ENTRIES
)
DIGEST_COVERAGE: Final[str] = (
    "the two foundation files every other artifact in the set is built on, plus "
    "reverse/evidence/pdata_stats.json because the cross references below read their digests out of "
    "it, plus the five decoded csv artifacts whose producers record no output digest of their own. "
    "That is every artifact reverse/scripts/audit_infra.py audits except the payload itself, which "
    "is the one file the self block below excludes, plus "
    "reverse/evidence/unresolved_regions.json. That last one is not an audited artifact: it is a "
    "large derived payload that no surviving record in the set attests, its producer records no "
    "output digest of its own, and it records no digest of this payload, so hashing it here is "
    "what stops it from drifting unnoticed"
)
DIGEST_ORDERING_NOTE: Final[str] = (
    "every target is hashed rather than merely listed, so a producer run invalidates the digest this "
    "payload records for it: refresh_toolchain.py has to run after pdata_map.py, cfg_build.py, "
    "xref_build.py, syscall_scan.py and unresolved_regions.py, never before them"
)

INVENTORY_FIELDS: Final[tuple[str, ...]] = (
    "path",
    "name",
    "size",
    "sha256",
    "utf8_bom",
    "crlf_line_count",
    "lf_line_count",
    "third_party_imports",
)
INVENTORY_OMITTED: Final[tuple[str, ...]] = ("atime", "ctime", "mtime")
INVENTORY_OMITTED_REASON: Final[str] = (
    "filesystem timestamps are host state rather than evidence, recording them would make the "
    "payload change on a touch, so the inventory attests content identity only"
)
AXES: Final[tuple[str, ...]] = ("package_metadata", "imported_module", "native_engine")
COMPARABLE_AXES: Final[tuple[str, ...]] = ("package_metadata", "imported_module")
ENGINE_AXIS_NOTE: Final[str] = (
    "the native engine reports a core API number as (major, minor, major << 8 | minor), not a "
    "release version, so it is recorded in full but never compared against a release string"
)
LIBRARY_BLOCK_FIELDS: Final[Mapping[str, str]] = {
    "package_metadata.version": "distribution_version",
    "imported_module.version": "module_version",
    "native_engine.version": "engine_version",
}
IMPORT_VERSION_ATTRIBUTES: Final[tuple[str, ...]] = (
    "__version__",
    "__commit__",
    "__tag__",
    "__is_tagged__",
    "__extended__",
    "__free_threaded__",
)
BINDING_CONSTANTS: Final[tuple[str, ...]] = (
    "CS_API_MAJOR",
    "CS_API_MINOR",
    "CS_VERSION_MAJOR",
    "CS_VERSION_MINOR",
    "CS_VERSION_EXTRA",
)
DOCUMENTS: Final[tuple[str, ...]] = (
    "reverse/adhesive-03-imports-exports.md",
    "reverse/adhesive-12-risk-methodology-open-questions.md",
)
DOCUMENT_LABELS: Final[Mapping[str, str]] = {
    "capstone": "Capstone",
    "lief": "LIEF",
    "pefile": "pefile",
}
CROSS_REFERENCES: Final[tuple[tuple[str, str, str], ...]] = (
    (PDATA_STATS_RELATIVE, "producer.baseline_sha256", BASELINE_RELATIVE),
    (PDATA_STATS_RELATIVE, "producer.helper_sha256", COMMON_RELATIVE),
)
ASSESSMENTS: Final[Mapping[tuple[str, str], str]] = {
    ("capstone", "imported_module"): (
        "the installed wheel declares 5.0.9 in its distribution metadata while the imported "
        "capstone package reports 5.0.7, because the binding composes __version__ from "
        "CS_API_MAJOR, CS_API_MINOR and the literal CS_VERSION_EXTRA in capstone/__init__.py and "
        "never reads the wheel version, so the imported string lags the wheel that carries it"
    ),
    ("lief", "imported_module"): (
        "the installed wheel declares 1.0.0 in its distribution metadata while the imported lief "
        "package reports 1.0.0-d05b3499b, because lief/__init__.py re-exports __version__ from the "
        "compiled extension and that string is the build stamp baked in by scikit-build-core, here "
        "an untagged commit build rather than a release build"
    ),
}
TIMESTAMP_KEYS: Final[frozenset[str]] = frozenset(
    {
        "asctime",
        "atime",
        "created",
        "created_at",
        "ctime",
        "date",
        "datetime",
        "generated",
        "generated_at",
        "mtime",
        "now",
        "run_at",
        "time",
        "timestamp",
        "updated_at",
    }
)
ISO_DATE: Final[Any] = re.compile(r"\d{4}-\d{2}-\d{2}")


def relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def headers(text: str | None) -> dict[str, str]:
    if text is None:
        return {}
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            break
        name, separator, value = line.partition(":")
        if separator:
            fields.setdefault(name.strip(), value.strip())
    return fields


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def scalar(value: Any) -> Any:
    if isinstance(value, (str, bool, int, float)) or value is None:
        return value
    return str(value)


def third_party_imports(data: bytes, siblings: frozenset[str]) -> list[str]:
    """Top-level module names a script imports that are neither stdlib nor a sibling script."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(data.decode("utf-8-sig"))):
        if isinstance(node, ast.Import):
            names.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.partition(".")[0])
    return sorted(
        name
        for name in names
        if name != "__future__" and name not in siblings and name not in sys.stdlib_module_names
    )


def import_census(
    root: Path, scripts: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Per-script third-party imports plus the reverse map, both in file name order."""
    siblings = frozenset(path.stem for path in (root / SCRIPTS_RELATIVE).glob("*.py"))
    census = {
        entry["name"]: third_party_imports((root / entry["path"]).read_bytes(), siblings)
        for entry in scripts
    }
    reverse: dict[str, set[str]] = {}
    for script, names in census.items():
        for name in names:
            reverse.setdefault(name, set()).add(script)
    return census, {name: sorted(scripts) for name, scripts in sorted(reverse.items())}


def dist_info(distribution: str) -> str | None:
    """Name of the .dist-info directory pip installed, without the host path it sits in."""
    for key in ("purelib", "platlib"):
        site = Path(sysconfig.get_paths()[key])
        if not site.is_dir():
            continue
        for candidate in sorted(site.glob(f"{canonical(distribution)}-*.dist-info")):
            metadata = candidate / "METADATA"
            if not metadata.is_file():
                continue
            name = headers(metadata.read_text(encoding="utf-8", errors="replace")).get("Name", "")
            if canonical(name) == canonical(distribution):
                return candidate.name
    return None


def package_axis(distribution: str) -> dict[str, Any]:
    axis: dict[str, Any] = {"distribution": distribution}
    try:
        found = importlib.metadata.distribution(distribution)
    except importlib.metadata.PackageNotFoundError:
        axis["installed"] = False
        return axis
    wheel = headers(found.read_text("WHEEL"))
    installer = (found.read_text("INSTALLER") or "").strip()
    axis["installed"] = True
    axis["version"] = found.version
    axis["metadata_name"] = found.metadata["Name"]
    axis["metadata_version"] = found.metadata["Version"]
    axis["dist_info"] = dist_info(distribution)
    axis["metadata_version_matches_version_field"] = found.metadata["Version"] == found.version
    axis["wheel_generator"] = wheel.get("Generator")
    axis["wheel_tag"] = wheel.get("Tag")
    axis["wheel_root_is_purelib"] = wheel.get("Root-Is-Purelib")
    axis["installer"] = installer or None
    axis["recorded_file_count"] = len(found.files or ())
    return axis


def import_axis(distribution: str, module: Any) -> dict[str, Any]:
    axis: dict[str, Any] = {"module": module.__name__, "imported": True}
    for attribute in IMPORT_VERSION_ATTRIBUTES:
        if hasattr(module, attribute):
            axis[attribute] = scalar(getattr(module, attribute))
    axis["version"] = axis.get("__version__")
    for name, member in sorted(vars(module).items()):
        if not isinstance(member, type(sys)):
            continue
        origin = getattr(member, "__file__", "") or ""
        if origin.endswith((".pyd", ".so", ".dylib")) and hasattr(member, "__version__"):
            axis["version_re_exported_from"] = name
            axis["version_re_exported_from_kind"] = "compiled extension"
            break
    constants = {
        name: scalar(getattr(module, name))
        for name in BINDING_CONSTANTS
        if hasattr(module, name)
    }
    if constants:
        axis["binding_constants"] = constants
        major = constants.get("CS_VERSION_MAJOR")
        minor = constants.get("CS_VERSION_MINOR")
        extra = constants.get("CS_VERSION_EXTRA")
        if None not in (major, minor, extra):
            composed = f"{major}.{minor}.{extra}"
            axis["version_composed_from_binding_constants"] = composed
            axis["version_equals_composition"] = composed == axis.get("__version__")
    return axis


def engine_axis(distribution: str, module: Any) -> dict[str, Any]:
    axis: dict[str, Any] = {}
    probe = getattr(module, "cs_version", None)
    if callable(probe):
        major, minor, combined = probe()
        axis["version"] = [int(major), int(minor), int(combined)]
        axis["reported_by"] = f"{module.__name__}.cs_version()"
        bind = getattr(module, "version_bind", None)
        if callable(bind):
            bound = [int(part) for part in bind()]
            axis["binding_version"] = bound
            axis["reported_by_binding"] = f"{module.__name__}.version_bind()"
            axis["core_matches_binding"] = bound == axis["version"]
    extended = getattr(module, "extended_version", None)
    if callable(extended):
        axis["extended_version"] = scalar(extended())
        info = getattr(module, "extended_version_info", None)
        if callable(info):
            axis["extended_version_info"] = scalar(info())
    return axis


def document_claims(
    root: Path, distribution: str, imported: str | None, declared: str | None
) -> list[dict[str, Any]]:
    """Which write-ups name a version for this package, and which axis that version belongs to."""
    label = DOCUMENT_LABELS.get(distribution, distribution)
    claims: list[dict[str, Any]] = []
    for relative_path in DOCUMENTS:
        path = root / relative_path
        if not path.is_file() or imported is None:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if label not in text or imported not in text:
            continue
        claims.append(
            {
                "file": relative_path,
                "label": label,
                "version": imported,
                "axis": "imported_module",
                "agrees_with_package_metadata": imported == declared,
            }
        )
    return claims


def divergence(
    root: Path,
    distribution: str,
    axes: Mapping[str, Mapping[str, Any]],
    library: Mapping[str, Any],
    users: Sequence[str],
) -> dict[str, Any]:
    values = {axis: axes[axis].get("version") for axis in AXES}
    declared = values["package_metadata"]
    disagreeing = [
        axis
        for axis in COMPARABLE_AXES
        if values[axis] is not None and values[axis] != declared
    ]
    return {
        "axes": dict(values),
        "compared_axes": list(COMPARABLE_AXES),
        "axes_disagreeing_with_package_metadata": disagreeing,
        "axes_reconciled": False,
        "native_engine_comparable_to_release_versions": False,
        "native_engine_note": ENGINE_AXIS_NOTE if values["native_engine"] is not None else None,
        "library_block_values_match_axes": {
            field: library.get(key) == axes[field.split(".")[0]].get("version")
            for field, key in LIBRARY_BLOCK_FIELDS.items()
        },
        "assessments": {
            axis: ASSESSMENTS[(distribution, axis)]
            for axis in disagreeing
            if (distribution, axis) in ASSESSMENTS
        },
        "documented_claims": document_claims(
            root, distribution, values["imported_module"], values["package_metadata"]
        ),
        "effect_on_evidence": (
            f"the decoded evidence depends on this package through {', '.join(users)}, so the axis "
            f"that names the build actually loaded is the one a reader has to take as authoritative"
            if users
            else f"no reverse/scripts producer imports {distribution}, so the divergence is confined "
            f"to this record and cannot have changed any decoded artifact"
        ),
    }


def package_record(
    root: Path, distribution: str, library: Mapping[str, Any], users: Sequence[str]
) -> dict[str, Any]:
    metadata = package_axis(distribution)
    try:
        module: Any = importlib.import_module(distribution)
    except ImportError:
        module = None
    imported: dict[str, Any] = (
        {"module": distribution, "imported": False} if module is None else import_axis(distribution, module)
    )
    engines = {"installed": False} if module is None else engine_axis(distribution, module)
    axes = {
        "package_metadata": metadata,
        "imported_module": imported,
        "native_engine": engines,
    }
    return {
        "declared_in_libraries": True,
        "axes": axes,
        "imported_by": list(users),
        "divergence": divergence(root, distribution, axes, library, users),
    }


def undeclared_record(distribution: str, users: Sequence[str]) -> dict[str, Any]:
    try:
        module: Any = importlib.import_module(distribution)
    except ImportError:
        module = None
    imported: dict[str, Any] = (
        {"module": distribution, "imported": False} if module is None else import_axis(distribution, module)
    )
    return {
        "declared_in_libraries": False,
        "imported_by": list(users),
        "package_metadata": package_axis(distribution),
        "imported_module": imported,
        "note": (
            f"{distribution} is imported by {', '.join(users)} but is not one of the packages the "
            f"libraries block declares, so the libraries block is not a complete inventory of what "
            f"the producers import"
        ),
    }


def inventory_block(scripts: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "root": SCRIPTS_RELATIVE,
        "glob": "*.py",
        "entry_count": len(scripts),
        "order": "file name ascending, code point order",
        "producer": (
            "reverse/scripts/common.py script_records, extended by "
            "reverse/scripts/refresh_toolchain.py with third_party_imports"
        ),
        "fields": list(INVENTORY_FIELDS),
        "omitted": list(INVENTORY_OMITTED),
        "omitted_reason": INVENTORY_OMITTED_REASON,
    }


def digest_block(root: Path) -> dict[str, Any]:
    entries: dict[str, Any] = {}
    for target in DIGEST_ENTRIES:
        path = root / target
        entries[target] = {
            "size": path.stat().st_size,
            "sha256": common.sha256_file(path),
        }
    references: list[dict[str, Any]] = []
    for source, field, target in CROSS_REFERENCES:
        path = root / source
        if not path.is_file():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        recorded: Any = payload
        for part in field.split("."):
            recorded = recorded.get(part) if isinstance(recorded, Mapping) else None
        references.append(
            {
                "file": source,
                "field": field,
                "target": target,
                "recorded_sha256": recorded,
                "matches_recomputed": recorded == entries[target]["sha256"],
            }
        )
    return {
        "algorithm": "sha256 over the file bytes, recomputed on every refresh",
        "entries": entries,
        "entries_cover": f"{DIGEST_COVERAGE}. {DIGEST_ORDERING_NOTE}",
        "cross_references": references,
        "self": {
            "path": DEFAULT_OUTPUT,
            "sha256": None,
            "reason": (
                "a payload cannot contain its own digest, so reverse/scripts/refresh_toolchain.py "
                "prints it after writing and the file has to be attested from outside"
            ),
        },
    }


def cycle_targets(
    entries: Mapping[str, Any], references: Sequence[Mapping[str, Any]]
) -> list[str]:
    """Attestation targets whose digest this payload would be recording inside its own bytes.

    A target equal to the payload itself makes the digest block unsatisfiable: the value written is
    the digest of the bytes it is written into, so no two refreshes could ever agree and --check
    could never pass. The guard runs before the write, so the impossible payload is never produced.
    """
    offenders = [target for target in entries if target == DEFAULT_OUTPUT]
    offenders.extend(
        str(reference.get("target"))
        for reference in references
        if reference.get("target") == DEFAULT_OUTPUT
    )
    return sorted(set(offenders))


def package_block(
    root: Path,
    libraries: Mapping[str, Any],
    census: Mapping[str, Sequence[str]],
    reverse_census: Mapping[str, Sequence[str]],
) -> dict[str, Any]:
    declared = sorted(libraries)
    return {
        "method": (
            "each third-party package is versioned on independent axes: the installed distribution "
            "metadata, the attribute the imported module exposes and the version the native engine "
            "reports. The axes are recorded side by side and are never reconciled into one value, so "
            "a disagreement between them stays visible in the evidence set"
        ),
        "axes": list(AXES),
        "library_block_fields": dict(LIBRARY_BLOCK_FIELDS),
        "declared": declared,
        "packages": {
            name: package_record(root, name, libraries[name], reverse_census.get(name, ()))
            for name in declared
        },
        "undeclared_imports": {
            name: undeclared_record(name, users)
            for name, users in reverse_census.items()
            if name not in libraries
        },
        "imported_by": {
            name: list(reverse_census[name]) for name in sorted(reverse_census) if name in libraries
        },
        "import_census": {name: list(names) for name, names in sorted(census.items())},
    }


def timestamp_leaks(payload: Any, prefix: str = "") -> list[str]:
    leaks: list[str] = []
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if str(key).lower() in TIMESTAMP_KEYS:
                leaks.append(path)
            leaks.extend(timestamp_leaks(value, path))
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            leaks.extend(timestamp_leaks(value, f"{prefix}[{index}]"))
    elif isinstance(payload, str) and ISO_DATE.search(payload):
        leaks.append(prefix)
    return leaks


def build_payload(root: Path, specimen: Path) -> dict[str, Any]:
    relative_specimen = relative(root, specimen)
    base = common.build_toolchain(root, specimen, relative_specimen)
    scripts = base["scripts"]
    census, reverse_census = import_census(root, scripts)
    for entry in scripts:
        entry["third_party_imports"] = census[entry["name"]]
    return {
        "schema": base["schema"],
        "determinism": base["determinism"],
        "host": base["host"],
        "python": base["python"],
        "libraries": base["libraries"],
        "binutils": base["binutils"],
        "specimen": base["specimen"],
        "script_inventory": inventory_block(scripts),
        "package_versions": package_block(root, base["libraries"], census, reverse_census),
        "digests": digest_block(root),
        "scripts": scripts,
    }


def serialize(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False, allow_nan=False) + "\n"


def compare(stored: Mapping[str, Any], fresh: Mapping[str, Any]) -> list[common.Check]:
    before = dict(common.iter_scalar_paths(stored))
    after = dict(common.iter_scalar_paths(fresh))
    return [
        common.Check(
            name=key,
            expected=before.get(key, "<missing>"),
            actual=after.get(key, "<missing>"),
            ok=before.get(key, "<missing>") == after.get(key, "<missing>"),
        )
        for key in sorted(set(before) | set(after))
    ]


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description="Deterministic refresh of the toolchain json for the adhesive.dll evidence set"
    )
    parser.add_argument("--specimen", type=Path, default=root / SPECIMEN_RELATIVE)
    parser.add_argument("--output", type=Path, default=root / DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report the difference against the stored file without writing",
    )
    parser.add_argument("--max-report", type=int, default=40, help="mismatches to print")
    args = parser.parse_args(argv)

    specimen = args.specimen.resolve()
    output = args.output.resolve()
    payload = build_payload(root, specimen)

    cycles = cycle_targets(
        payload["digests"]["entries"], payload["digests"]["cross_references"]
    )
    if cycles:
        for target in cycles:
            print(f"CYCLE {target} is attested by the payload that records its digest")
        return 1

    leaks = timestamp_leaks(payload)
    if leaks:
        for path in leaks[: args.max_report]:
            print(f"LEAK {path} carries a timestamp")
        print(f"LEAK ... {len(leaks) - args.max_report} further timestamp fields")
        return 1

    text = serialize(payload)
    stored = output.read_text(encoding="utf-8") if output.is_file() else None
    print(f"script    {relative(root, script)}")
    print(f"sha256    {common.sha256_file(script)}")
    print(
        f"specimen  {payload['specimen']['path']} size={payload['specimen']['size']} "
        f"sha256={payload['specimen']['sha256']}"
    )
    inventory = payload["script_inventory"]
    print(
        f"inventory {inventory['root']}/{inventory['glob']} entries={inventory['entry_count']} "
        f"omitted={','.join(inventory['omitted'])}"
    )
    for name, record in payload["package_versions"]["packages"].items():
        values = record["divergence"]["axes"]
        disagreeing = record["divergence"]["axes_disagreeing_with_package_metadata"]
        print(
            f"package   {name} metadata={values['package_metadata']} "
            f"imported={values['imported_module']} engine={values['native_engine']} "
            f"imported_by={len(record['imported_by'])} "
            f"divergent={','.join(disagreeing) if disagreeing else '-'}"
        )
    for name, record in payload["package_versions"]["undeclared_imports"].items():
        print(
            f"undeclar. {name} imported={record['imported_module'].get('__version__')} "
            f"imported_by={','.join(record['imported_by'])}"
        )
    for target, entry in payload["digests"]["entries"].items():
        print(f"digest    {target} {entry['sha256']}")
    for reference in payload["digests"]["cross_references"]:
        print(
            f"xref      {reference['file']}#{reference['field']} "
            f"agrees={reference['matches_recomputed']}"
        )

    if args.check:
        if stored is None:
            print(f"MISSING   {relative(root, output)}")
            return 1
        checks = compare(json.loads(stored), payload)
        failed = common.report_checks(checks, args.max_report)
        if stored == text:
            print(f"toolchain {relative(root, output)} byte identical")
            return 0
        print(f"toolchain {relative(root, output)} differs on {failed}/{len(checks)} values")
        return 1

    common.write_json(output, payload)
    print(f"toolchain {relative(root, output)} sha256={common.sha256_file(output)}")
    if stored is not None and stored == text:
        print("unchanged the stored payload was already byte identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
