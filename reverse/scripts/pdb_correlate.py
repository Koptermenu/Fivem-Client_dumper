"""Static PDB / build correlation evidence for the adhesive.dll specimen (P0).

Reads only file bytes. The specimen is never loaded, mapped, executed or
imported, no network request is issued, and no bypass/patch recipe is produced.
The emitted JSON is deterministic: fixed key order, sorted collections, no wall
clock values, UTF-8 without BOM, LF terminated, trailing newline.

The script answers one question: which reproducible keys can decide whether two
`adhesive.dll` byte sets belong to the same build, and which of those keys are
not available for this specimen. It deliberately refuses to assert that the
specimen is an authentic vendor build, because the matching PDB is absent, no
second same-build reference exists in the workspace, and the Authenticode chain
is not cryptographically verified here (chain validation can trigger revocation
traffic, which is out of scope for an offline run).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import sys
import uuid
from pathlib import Path
from typing import Any, Final, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import common

SCHEMA_PDB_CORRELATION: Final[str] = "adhesive-dumper.pdb-correlation/1"

SPECIMEN_RELATIVE: Final[str] = "reverse/adhesive.dll"
BASELINE_RELATIVE: Final[str] = "reverse/evidence/baseline.json"
OUTPUT_RELATIVE: Final[str] = "reverse/evidence/pdb_correlation.json"




EXPECTED_PDB_GUID: Final[str] = "cb927e36-3f3d-8d77-4c4c-44205044422e"
EXPECTED_DEBUG_ID: Final[str] = "CB927E363F3D8D774C4C44205044422E1"
EXPECTED_PDB_AGE: Final[int] = 1
EXPECTED_PDB_PATH: Final[str] = (
    "C:\\gl\\builds\\cfx-fivem-0\\.build-cache\\bin\\five\\release\\dbg\\adhesive.pdb"
)
EXPECTED_FILE_SHA256: Final[str] = (
    "91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e"
)
EXPECTED_AUTHENTICODE_IMAGE_SHA256: Final[str] = (
    "82d63cbaf1ead1cc9e2b9fc871f4778e68c2adc06f0df7144e1892b38a1e575a"
)
EXPECTED_LINKER_VERSION: Final[str] = "14.0"
EXPECTED_COMPONENT_NAME: Final[str] = "adhesive"
EXPECTED_COMPONENT_VERSION: Final[str] = "0.1.0"
EXPECTED_FILE_VERSION: Final[str] = "1.0.0.36109"
EXPECTED_PRODUCT_NAME: Final[str] = "CitizenFX"
EXPECTED_EXPORT_NAME: Final[str] = "CreateComponent"
EXPECTED_RETPOLINE_TAG: Final[str] = "RetpolineV1"
EXPECTED_RETPOLINE_TAG_OFFSETS: Final[tuple[int, ...]] = (0x00, 0x10, 0x2C, 0x40)
EXPECTED_SECTION_COUNT: Final[int] = 7
EXPECTED_IMPORT_DESCRIPTORS: Final[int] = 42
EXPECTED_IMPORT_SYMBOLS: Final[int] = 628
EXPECTED_EXPORT_SYMBOLS: Final[int] = 1
EXPECTED_RUNTIME_FUNCTIONS: Final[int] = common.EXPECTED_RUNTIME_FUNCTIONS
EXPECTED_BUILD_CACHE_ROOT: Final[str] = "C:\\gl\\builds\\cfx-fivem-0"
EXPECTED_FIRST_PARTY_SOURCE_PATH: Final[str] = (
    "C:\\gl\\builds\\cfx-fivem-0\\code\\client\\shared\\Utils.cpp"
)
EXPECTED_PRIVATE_REPO_SEGMENT: Final[str] = "..\\..\\fivem-private\\components\\adhesive"
EXPECTED_SIGNING_TIME_UTC: Final[str] = "2026-09-11 15:08:46 UTC"
EXPECTED_BUILD_PATH_ABSOLUTE_COUNT: Final[int] = 278
EXPECTED_BUILD_PATH_RELATIVE_COUNT: Final[int] = 39
EXPECTED_VENDOR_PATH_COUNT: Final[int] = 276
EXPECTED_SIGNING_TIME_OID_HITS: Final[int] = 1

SECURITY_DIRECTORY_INDEX: Final[int] = 4
DEBUG_DIRECTORY_INDEX: Final[int] = 6
VERSION_RESOURCE_TYPE: Final[int] = 16
FXCOMPONENT_RESOURCE_TYPE: Final[int] = 115

DEBUG_TYPE_NAMES: Final[Mapping[int, str]] = {
    0: "IMAGE_DEBUG_TYPE_UNKNOWN",
    1: "IMAGE_DEBUG_TYPE_COFF",
    2: "IMAGE_DEBUG_TYPE_CODEVIEW",
    3: "IMAGE_DEBUG_TYPE_FPO",
    4: "IMAGE_DEBUG_TYPE_MISC",
    5: "IMAGE_DEBUG_TYPE_EXCEPTION",
    6: "IMAGE_DEBUG_TYPE_FIXUP",
    7: "IMAGE_DEBUG_TYPE_OMAP_TO_SRC",
    8: "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC",
    9: "IMAGE_DEBUG_TYPE_BORLAND",
    10: "IMAGE_DEBUG_TYPE_RESERVED10",
    11: "IMAGE_DEBUG_TYPE_CLSID",
    12: "IMAGE_DEBUG_TYPE_VC_FEATURE",
    13: "IMAGE_DEBUG_TYPE_POGO",
    14: "IMAGE_DEBUG_TYPE_ILTCG",
    16: "IMAGE_DEBUG_TYPE_REPRO",
    17: "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS",
    19: "IMAGE_DEBUG_TYPE_EMBEDDED_PORTABLE_PDB",
    20: "IMAGE_DEBUG_TYPE_PDBCHECKSUM",
    21: "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS_2",
}

COFF_TIMESTAMP_RAW: Final[int] = 0x80
LINKER_VERSION_RAW: Final[int] = 0x92
RICH_SCAN_START: Final[int] = 0x40
RICH_MARKERS: Final[tuple[tuple[str, bytes], ...]] = (("DanS", b"DanS"), ("Rich", b"Rich"))




TOOLCHAIN_MARKER_PROBES: Final[tuple[tuple[str, bytes], ...]] = (
    ("LLD_upper", b"LLD"),
    ("lld_lower", b"lld"),
    ("lld-link", b"lld-link"),
    ("lld_link_flag", b"--lld-link"),
    ("GNU_note", b"GNU\x00"),
    ("build-id_dash", b"build-id"),
    ("build_id_underscore", b"build_id"),
    ("note_section", b".note"),
    ("llvm_lower", b"llvm"),
    ("clang", b"clang"),
    ("clang-cl", b"clang-cl"),
    ("visual_studio", b"Visual Studio"),
    ("msvc_token", b"MSVC"),
    ("link_dot_exe", b"link.exe"),
)
TOOLCHAIN_IDENTITY_PROBES: Final[frozenset[str]] = frozenset(
    {"lld-link", "lld_link_flag", "clang", "clang-cl", "llvm_lower", "visual_studio"}
)

MAX_MARKER_HITS: Final[int] = 8
MAX_RUN_WINDOW: Final[int] = 512
MAX_RUN_SNIPPET: Final[int] = 96
MAX_CONTEXT_BYTES: Final[int] = 24
MAX_PATH_RUN: Final[int] = 300
MAX_WORKSPACE_LINES_PER_FILE: Final[int] = 6
MAX_WORKSPACE_FILES: Final[int] = 400




WORKSPACE_TEXT_TARGETS: Final[tuple[tuple[str, str], ...]] = (
    ("CMakeLists.txt", "project"),
    ("README.md", "documentation"),
    ("AGENTS.md", "documentation"),
    ("build.bat", "build"),
    (".gitignore", "vcs"),
    ("dumper.log", "runtime_log"),
    ("src", "project_source"),
    ("cmake", "build_config"),
    ("Bin/components.json", "component_config"),
    ("Bin/.gitignore", "vcs"),
    ("Bin/citizen/scripting/resource_init.lua", "resource_config"),
)
WORKSPACE_TEXT_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {".bat", ".cmake", ".cpp", ".h", ".in", ".json", ".lua", ".manifest", ".md", ".rc", ".txt"}
)
WORKSPACE_EXCLUDED_DIRS: Final[frozenset[str]] = frozenset({".git", "build", ".zcode"})
WORKSPACE_SCAN_EXCLUDED_REASON: Final[Mapping[str, str]] = {
    "reverse/*.md": "sibling analysis reports; they are the output of this "
    "evidence set, not a build-provenance source",
    "build/": "generated CMake output, reproducible from the sources above",
    "Bin/** (non-config)": "opaque vendor binaries; covered by module name "
    "resolution only, their own identity is out of scope here",
    ".git/": "vcs internals",
    ".zcode/": "tool scratch space",
    "Servers/": "not present in this workspace",
}
WORKSPACE_IDENTITY_KEYWORDS: Final[tuple[str, ...]] = (
    "adhesive",
    "adhesive.pdb",
    "cfx-fivem",
    "cfx.re",
    "createcomponent",
    "fxcomponent",
)
WORKSPACE_AMBIENT_KEYWORDS: Final[tuple[str, ...]] = ("fivem", "citizenfx")
WORKSPACE_BUILD_CONTEXT_TERMS: Final[tuple[str, ...]] = (
    "cfx-fivem-0",
    "gl\\builds",
    ".build-cache",
    "release\\dbg",
)
CLIENT_MODULE_PREFIXES: Final[tuple[str, ...]] = (
    "citizen-resources-",
    "gta-core-",
    "rage-",
    "scripting-",
)
CLIENT_MODULE_NAMES: Final[frozenset[str]] = frozenset(
    {"legitimacy.dll", "net.dll", "net-base.dll", "net-tcp-server.dll", "vfs-core.dll"}
)
SERVER_COMPONENT_PREFIX: Final[str] = "citizen:server:"
PRIVATE_SEGMENT_MARKER: Final[str] = "fivem-private"
VENDOR_SEGMENT_MARKERS: Final[tuple[str, ...]] = ("\\vendor\\", "/vendor/")

SIGNING_TIME_OID: Final[bytes] = bytes.fromhex("06092a864886f70d010905")
SHA256_DIGEST_OID: Final[bytes] = bytes.fromhex("0609608648016503040201")
TIME_TAGS: Final[frozenset[int]] = frozenset({0x17, 0x18})
TIME_TAGS_INV: Final[Mapping[int, str]] = {0x17: "UTCTime", 0x18: "GeneralizedTime"}
ABSOLUTE_BUILD_PATH: Final[re.Pattern[str]] = re.compile(r"^C:[\\/]gl[\\/].+$")
RELATIVE_BUILD_PATH: Final[re.Pattern[str]] = re.compile(r"^\.\.[\\/].+$")
BUILD_PATH_RUN: Final[re.Pattern[bytes]] = re.compile(
    rb"[\x20-\x7e]{8,%d}\x00" % MAX_PATH_RUN
)
TIME_FORMS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "two_digit_year",
        re.compile(r"^(?P<yy>\d{2})(?P<mm>\d{2})(?P<dd>\d{2})"
                   r"(?P<hh>\d{2})(?P<mi>\d{2})(?P<ss>\d{2})Z$"),
    ),
    (
        "four_digit_year",
        re.compile(r"^(?P<yyyy>\d{4})(?P<mm>\d{2})(?P<dd>\d{2})"
                   r"(?P<hh>\d{2})(?P<mi>\d{2})(?P<ss>\d{2})Z$"),
    ),
)

BASELINE_CROSS_CHECK_PATHS: Final[tuple[str, ...]] = (
    "pe.machine",
    "pe.magic_hex",
    "pe.linker_version",
    "pe.time_date_stamp_hex",
    "pe.check_sum_hex",
    "pe.check_sum_matches",
    "pe.entry_point_rva_hex",
    "pe.image_base_hex",
    "pe.size_of_image_hex",
    "pe.dll_characteristics_hex",
    "sections[0].entropy",
    "sections[1].entropy",
    "sections[2].entropy",
    "sections[3].entropy",
    "sections[4].entropy",
    "sections[5].entropy",
    "sections[6].entropy",
    "sections[0].raw_size_hex",
    "sections[1].raw_size_hex",
    "sections[2].raw_size_hex",
    "sections[3].raw_size_hex",
    "sections[4].raw_size_hex",
    "sections[5].raw_size_hex",
    "sections[6].raw_size_hex",
    "sections[0].virtual_size_hex",
    "sections[1].virtual_size_hex",
    "sections[2].virtual_size_hex",
    "pdata.record_count",
    "imports.descriptor_count",
    "imports.symbol_count",
    "imports.name_imports",
    "imports.ordinal_imports",
    "imports.delay_descriptor_count",
    "imports.delay_symbol_count",
    "exports.symbol_count",
    "exports.module_name",
    "resources.entry_count",
    "certificate.sha256",
    "certificate.end_offset_hex",
)







def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_digest(lines: Sequence[str]) -> str:
    """Digest of a sorted, LF terminated line list: the cross-build diff recipe."""
    body = "".join(f"{line}\n" for line in sorted(lines))
    return sha256_hex(body.encode("utf-8"))


def entropy_of(payload: bytes) -> float:
    if not payload:
        return 0.0
    counts = [0] * 256
    for byte in payload:
        counts[byte] += 1
    total = float(len(payload))
    accumulator = 0.0
    for count in counts:
        if count:
            probability = count / total
            accumulator -= probability * math.log2(probability)
    return round(accumulator, 9)


def authenticode_image_digest(data: bytes, pe: Any) -> dict[str, Any]:
    """Recompute the Authenticode PE image hash offline, from bytes only.

    Header region up to SizeOfHeaders with the 4 byte CheckSum field and the
    8 byte Security data directory entry removed, then every section's full
    SizeOfRawData. The certificate table is outside the hashed region by
    construction and is reported separately.
    """
    optional = pe.OPTIONAL_HEADER
    checksum_offset = int(optional.get_field_absolute_offset("CheckSum"))
    security_entry = optional.DATA_DIRECTORY[SECURITY_DIRECTORY_INDEX]
    security_entry_offset = int(security_entry.get_field_absolute_offset("VirtualAddress"))
    certificate_offset = int(security_entry.VirtualAddress)
    certificate_size = int(security_entry.Size)
    header_end = min(int(optional.SizeOfHeaders), certificate_offset, len(data))
    digest = hashlib.sha256()
    digest.update(data[0:checksum_offset])
    digest.update(data[checksum_offset + 4 : security_entry_offset])
    digest.update(data[security_entry_offset + 8 : header_end])
    for section in common.sections(pe):
        digest.update(data[section.raw_pointer : section.raw_pointer + section.raw_size])
    return {
        "algorithm": "sha256",
        "value": digest.hexdigest(),
        "header_region": {
            "start": 0,
            "end": header_end,
            "end_hex": common.hexs(header_end),
            "excluded_fields": [
                {"name": "CheckSum", "raw": common.hexs(checksum_offset), "size": 4},
                {
                    "name": "SecurityDataDirectory",
                    "raw": common.hexs(security_entry_offset),
                    "size": 8,
                },
            ],
        },
        "section_region": "full SizeOfRawData per section, section table order",
        "certificate_table": {
            "file_offset": certificate_offset,
            "file_offset_hex": common.hexs(certificate_offset),
            "size": certificate_size,
            "size_hex": common.hexs(certificate_size),
            "hashed": False,
        },
        "cryptographic_operation": "none; this is a byte recomputation, not a "
        "signature verification and not a statement about chain validity",
    }







def codeview_records(pe: Any, data: bytes) -> dict[str, Any]:
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[DEBUG_DIRECTORY_INDEX]
    directory_rva = int(directory.VirtualAddress)
    directory_size = int(directory.Size)
    directory_raw = common.rva_to_raw(pe, directory_rva)
    entries: list[dict[str, Any]] = []
    blob = b""
    if directory_rva and directory_size:
        blob = common.read_rva(pe, directory_rva, directory_size)
        for index in range(len(blob) // 28):
            (
                characteristics,
                entry_timestamp,
                major,
                minor,
                entry_type,
                data_size,
                address_of_raw,
                pointer_to_raw,
            ) = struct.unpack_from("<IIHHIIII", blob, index * 28)
            payload = data[pointer_to_raw : pointer_to_raw + data_size]
            entries.append(
                {
                    "index": index,
                    "characteristics": characteristics,
                    "time_date_stamp": entry_timestamp,
                    "time_date_stamp_hex": common.hexs(entry_timestamp),
                    "time_date_stamp_utc": common.utc_string(entry_timestamp),
                    "version": f"{major}.{minor}",
                    "type": entry_type,
                    "type_name": DEBUG_TYPE_NAMES.get(entry_type, "IMAGE_DEBUG_TYPE_UNKNOWN"),
                    "data_size": data_size,
                    "data_size_hex": common.hexs(data_size),
                    "address_of_raw_data": address_of_raw,
                    "address_of_raw_data_hex": common.hexs(address_of_raw),
                    "pointer_to_raw_data": pointer_to_raw,
                    "pointer_to_raw_data_hex": common.hexs(pointer_to_raw),
                    "payload_sha256": sha256_hex(payload),
                    "payload": payload,
                }
            )
    codeviews = [entry for entry in entries if entry["type"] == 2]
    parsed = _parse_rsds(codeviews[0], pe) if len(codeviews) == 1 else None
    for entry in entries:
        entry.pop("payload", None)
    return {
        "directory": {
            "rva": directory_rva,
            "rva_hex": common.hexs(directory_rva),
            "raw": directory_raw,
            "raw_hex": common.hexs(directory_raw) if directory_raw is not None else None,
            "size": directory_size,
            "size_hex": common.hexs(directory_size),
            "entry_size": 28,
            "entry_count": len(entries),
        },
        "entries": entries,
        "codeview_entry_count": len(codeviews),
        "codeview_is_unique": len(codeviews) == 1,
        "codeview": parsed,
    }


def _parse_rsds(entry: Mapping[str, Any], pe: Any) -> dict[str, Any]:
    payload: bytes = entry["payload"]
    header = {
        "debug_entry_index": entry["index"],
        "raw": entry["pointer_to_raw_data"],
        "raw_hex": entry["pointer_to_raw_data_hex"],
        "rva": entry["address_of_raw_data"],
        "rva_hex": entry["address_of_raw_data_hex"],
        "size": entry["data_size"],
    }
    if len(payload) < 24 or payload[:4] != b"RSDS":
        return {
            **header,
            "signature": payload[:4].decode("ascii", errors="replace"),
            "signature_is_rsds": False,
            "guid": None,
            "age": None,
            "pdb_path": None,
        }
    guid_bytes = payload[4:20]
    age = struct.unpack_from("<I", payload, 20)[0]
    path_bytes = payload[24:]
    terminator = path_bytes.find(b"\x00")
    if terminator >= 0:
        path_bytes = path_bytes[:terminator]
    guid = uuid.UUID(bytes_le=guid_bytes)
    canonical = str(guid)
    path_text = path_bytes.decode("utf-8", errors="replace")
    path_raw = int(entry["pointer_to_raw_data"]) + 24
    guid_raw = int(entry["pointer_to_raw_data"]) + 4
    path_rva = common.raw_to_rva(pe, path_raw)
    return {
        **header,
        "signature": "RSDS",
        "signature_is_rsds": True,
        "guid": canonical,
        "guid_upper": canonical.upper(),
        "guid_bytes_le_hex": guid_bytes.hex(),
        "guid_raw": guid_raw,
        "guid_raw_hex": common.hexs(guid_raw),
        "age": age,
        "age_hex": f"0x{age:X}",
        "age_raw": guid_raw + 16,
        "age_raw_hex": common.hexs(guid_raw + 16),
        "debug_id": f"{canonical.upper().replace('-', '')}{age:X}",
        "pdb_path": path_text,
        "pdb_path_sha256": sha256_hex(path_bytes),
        "pdb_path_bytes": len(path_bytes),
        "pdb_path_raw": path_raw,
        "pdb_path_raw_hex": common.hexs(path_raw),
        "pdb_path_rva": path_rva,
        "pdb_path_rva_hex": common.hexs(path_rva) if path_rva is not None else None,
        "pdb_match_key": _pdb_match_key(guid_bytes, age, path_text),
    }


def _pdb_match_key(guid_bytes: bytes, age: int, path: str) -> str:
    normalized = path.replace("/", "\\").rstrip("\\").lower()
    material = b"\x00".join([normalized.encode("utf-8"), guid_bytes, struct.pack("<I", age)])
    return sha256_hex(material)


def rich_header(data: bytes, pe: Any) -> dict[str, Any]:
    e_lfanew = int(pe.DOS_HEADER.e_lfanew)
    region_end = min(e_lfanew, len(data))
    scan_start = min(RICH_SCAN_START, region_end)
    scan_region = data[scan_start:region_end]
    markers: dict[str, list[int]] = {}
    for name, needle in RICH_MARKERS:
        markers[name] = [
            match.start() + scan_start
            for match in re.finditer(re.escape(needle), scan_region)
        ]
    xor_key = None
    if markers["Rich"] and markers["Rich"][0] + 8 <= len(data):
        xor_key = struct.unpack_from("<I", data, markers["Rich"][0] + 4)[0]
    return {
        "e_lfanew": e_lfanew,
        "e_lfanew_hex": common.hexs(e_lfanew),
        "scan_region": {
            "start": scan_start,
            "start_hex": common.hexs(scan_start),
            "end": region_end,
            "end_hex": common.hexs(region_end),
            "size": region_end - scan_start,
        },
        "pre_pe_region_sha256": sha256_hex(data[0:region_end]),
        "pre_pe_region_size": region_end,
        "marker_offsets": {
            name: [common.hexs(offset) for offset in offsets]
            for name, offsets in sorted(markers.items())
        },
        "marker_hit_count": {name: len(offsets) for name, offsets in sorted(markers.items())},
        "present": bool(markers["DanS"] and markers["Rich"]),
        "rich_header_present": bool(markers["DanS"] and markers["Rich"]),
        "xor_key": xor_key,
        "xor_key_hex": common.hexs(xor_key) if xor_key is not None else None,
        "consequence": "no Rich build id, no compiler or product tuple and no "
        "Visual Studio toolchain version is recoverable from this specimen",
    }


def toolchain_marker_probe(
    data: bytes, pe: Any, guid_field: tuple[int, int] | None
) -> dict[str, Any]:
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[SECURITY_DIRECTORY_INDEX]
    certificate_start = int(security.VirtualAddress)
    certificate_end = certificate_start + int(security.Size)
    probes: list[dict[str, Any]] = []
    for name, needle in TOOLCHAIN_MARKER_PROBES:
        hits: list[dict[str, Any]] = []
        total = 0
        for match in re.finditer(re.escape(needle), data):
            offset = match.start()
            total += 1
            if len(hits) < MAX_MARKER_HITS:
                hits.append(
                    {
                        "raw": offset,
                        "raw_hex": common.hexs(offset),
                        "region": _region_of(offset, certificate_start, certificate_end, guid_field),
                        "printable_run": _printable_run_at(data, offset),
                        "context_hex": data[
                            max(0, offset - 8) : offset + MAX_CONTEXT_BYTES
                        ].hex(),
                    }
                )
        probes.append(
            {
                "probe": name,
                "needle": needle.decode("ascii", errors="replace"),
                "hit_count": total,
                "reported_hits": len(hits),
                "hits": hits,
                "is_identity_marker": name in TOOLCHAIN_IDENTITY_PROBES,
            }
        )
    section_names = [section.name for section in common.sections(pe)]
    return {
        "note_style_sections": [name for name in section_names if name.startswith(".note")],
        "gnu_build_id_note_section_present": ".note.gnu.build-id" in section_names,
        "probes": probes,
        "identity_marker_found": any(
            probe["is_identity_marker"] and probe["hit_count"] for probe in probes
        ),
        "lld_build_id_available": False,
        "lld_build_id_reason": "PE/COFF has no standard build id field and "
        "lld-link emits none for PE targets, so no linker identity record survives "
        "here; the only uppercase `LLD ` byte occurrence sits inside the CodeView "
        "GUID field, which is a GUID byte coincidence, not a marker",
    }


def _region_of(
    offset: int,
    certificate_start: int,
    certificate_end: int,
    guid_field: tuple[int, int] | None,
) -> str:
    if guid_field is not None and guid_field[0] <= offset < guid_field[1]:
        return "inside_pdb_guid_field"
    if certificate_start <= offset < certificate_end:
        return "inside_certificate_table"
    return "file_body"


def _printable_run_at(data: bytes, offset: int) -> str:
    start = offset
    floor = max(0, offset - MAX_RUN_WINDOW)
    while start > floor and 0x20 <= data[start - 1] <= 0x7E:
        start -= 1
    end = offset
    ceiling = min(len(data), offset + MAX_RUN_WINDOW)
    while end < ceiling and 0x20 <= data[end] <= 0x7E:
        end += 1
    return data[start:end][:MAX_RUN_SNIPPET].decode("ascii", errors="replace")


def retpoline_section(pe: Any, data: bytes) -> dict[str, Any]:
    for section in common.sections(pe):
        if section.name != ".retplne":
            continue
        region = data[section.raw_pointer : section.raw_pointer + section.raw_size]
        tag = EXPECTED_RETPOLINE_TAG.encode("ascii")
        offsets = [match.start() for match in re.finditer(re.escape(tag), region)]
        nonzero_end = len(region)
        while nonzero_end and region[nonzero_end - 1] == 0:
            nonzero_end -= 1
        dword_count = (nonzero_end + 3) // 4
        dwords = [struct.unpack_from("<I", region, index * 4)[0] for index in range(dword_count)]
        return {
            "present": True,
            "raw": section.raw_pointer,
            "raw_hex": common.hexs(section.raw_pointer),
            "rva": section.virtual_address,
            "rva_hex": common.hexs(section.virtual_address),
            "virtual_size": section.virtual_size,
            "virtual_size_hex": common.hexs(section.virtual_size),
            "raw_size": section.raw_size,
            "raw_size_hex": common.hexs(section.raw_size),
            "characteristics": section.characteristics,
            "characteristics_hex": common.hexs(section.characteristics),
            "tag": EXPECTED_RETPOLINE_TAG,
            "tag_count": len(offsets),
            "tag_offsets_in_section": [common.hexs(offset) for offset in offsets],
            "tag_offsets_in_file": [
                common.hexs(section.raw_pointer + offset) for offset in offsets
            ],
            "tag_delta_in_section": [
                common.hexs(offset - offsets[index - 1])
                for index, offset in enumerate(offsets)
                if index
            ],
            "nonzero_content_end": section.raw_pointer + nonzero_end,
            "nonzero_content_end_hex": common.hexs(section.raw_pointer + nonzero_end),
            "nonzero_content_size": nonzero_end,
            "trailing_zero_bytes": len(region) - nonzero_end,
            "dwords_le": [common.hexs(value) for value in dwords],
            "content_sha256": sha256_hex(region[:nonzero_end]),
            "full_raw_sha256": sha256_hex(region),
            "interpretation": "LLD COFF retpoline metadata marker. Only the byte "
            "positions and words are reported here; the record layout is not "
            "decoded, so the tag count is a raw fact and not a record count.",
        }
    return {"present": False, "tag": EXPECTED_RETPOLINE_TAG, "tag_count": 0}







def _resource_leaf(pe: Any, type_id: int, name_id: int | None, name_text: str | None) -> Any:
    for type_entry in getattr(pe, "DIRECTORY_ENTRY_RESOURCE", []).entries:
        if int(type_entry.id or 0) != type_id:
            continue
        for name_entry in type_entry.directory.entries:
            entry_id = int(name_entry.id) if name_entry.id is not None else None
            entry_text = str(name_entry.name) if name_entry.name is not None else None
            if entry_id == name_id and entry_text == name_text:
                return name_entry
    return None


def version_resource(pe: Any) -> dict[str, Any]:
    type_entry = _resource_leaf(pe, VERSION_RESOURCE_TYPE, 1, None)
    if type_entry is None:
        return {"present": False}
    payload_entry = type_entry.directory.entries[0].data.struct
    rva = int(payload_entry.OffsetToData)
    size = int(payload_entry.Size)
    blob = common.read_rva(pe, rva, size)
    strings: dict[str, str] = {}
    translations: list[str] = []
    fixed_info: dict[str, Any] = {}
    _walk_version_nodes(blob, 0, len(blob), 0, strings, translations, fixed_info)
    fixed_version = None
    if fixed_info:
        fixed_version = (
            f"{fixed_info['file_version_ms'] >> 16}."
            f"{fixed_info['file_version_ms'] & 0xFFFF}."
            f"{fixed_info['file_version_ls'] >> 16}."
            f"{fixed_info['file_version_ls'] & 0xFFFF}"
        )
    return {
        "present": True,
        "type_id": VERSION_RESOURCE_TYPE,
        "name_id": 1,
        "rva": rva,
        "rva_hex": common.hexs(rva),
        "raw": common.rva_to_raw(pe, rva),
        "raw_hex": common.hexs(common.rva_to_raw(pe, rva) or 0),
        "size": size,
        "size_hex": common.hexs(size),
        "payload_sha256": sha256_hex(blob),
        "fixed_file_info": fixed_info,
        "string_table": {key: strings[key] for key in sorted(strings)},
        "translations": translations,
        "file_version_from_fixed_info": fixed_version,
        "file_version_from_string_table": strings.get("FileVersion"),
        "product_version_from_string_table": strings.get("ProductVersion"),
        "string_file_version_matches_fixed_info": (
            fixed_version is not None and strings.get("FileVersion") == fixed_version
        ),
    }


def _walk_version_nodes(
    blob: bytes,
    start: int,
    end: int,
    depth: int,
    strings: dict[str, str],
    translations: list[str],
    fixed_info: dict[str, Any],
) -> None:
    """Walk VS_VERSIONINFO.

    Two conventions of this resource family are handled explicitly: padding is
    aligned to four bytes from the start of the structure, not from the start of
    the current node, and wValueLength counts UTF-16 code units for text values.
    """
    offset = start
    while offset + 6 <= end:
        length, value_length, value_type = struct.unpack_from("<HHH", blob, offset)
        if length == 0:
            return
        node_end = offset + length
        key = _utf16z(blob, offset + 6)
        key_end = offset + 6 + (len(key) + 1) * 2
        value_offset = key_end + ((4 - (key_end % 4)) % 4)
        value_bytes = value_length * 2 if value_type == 1 else value_length
        value_end = value_offset + value_bytes
        if value_bytes and value_end <= len(blob):
            value_raw = blob[value_offset:value_end]
        else:
            value_raw = b""
        if key == "VS_VERSION_INFO" and len(value_raw) >= 52:
            _parse_fixed_file_info(value_raw, fixed_info)
        elif key == "Translation" and len(value_raw) >= 2:
            translations.extend(
                f"0x{struct.unpack_from('<H', value_raw, index)[0]:04X}"
                for index in range(0, len(value_raw) - 1, 2)
            )
        elif key and value_bytes:
            strings[key] = _utf16z(blob, value_offset)
        children_start = value_end + ((4 - (value_end % 4)) % 4)
        if depth < 4 and children_start < node_end:
            _walk_version_nodes(
                blob, children_start, node_end, depth + 1, strings, translations, fixed_info
            )
        offset = node_end + ((4 - (node_end % 4)) % 4)


def _parse_fixed_file_info(value_raw: bytes, target: dict[str, Any]) -> None:
    fields = struct.unpack_from("<13I", value_raw, 0)
    target.update(
        {
            "dw_signature": common.hexs(fields[0]),
            "dw_signature_is_feef04bd": fields[0] == 0xFEEF04BD,
            "dw_struct_version": f"{fields[1] >> 16}.{fields[1] & 0xFFFF}",
            "file_version_ms": fields[2],
            "file_version_ms_hex": common.hexs(fields[2]),
            "file_version_ls": fields[3],
            "file_version_ls_hex": common.hexs(fields[3]),
            "product_version_ms": fields[4],
            "product_version_ms_hex": common.hexs(fields[4]),
            "product_version_ls": fields[5],
            "product_version_ls_hex": common.hexs(fields[5]),
            "dw_file_flags_mask": common.hexs(fields[6]),
            "dw_file_flags": common.hexs(fields[7]),
            "dw_file_os": common.hexs(fields[8]),
            "dw_file_type": fields[9],
            "dw_file_type_name": "VFT_APP" if fields[9] == 1 else "OTHER",
            "dw_file_subtype": common.hexs(fields[10]),
            "dw_file_date_ms": common.hexs(fields[11]),
            "dw_file_date_ls": common.hexs(fields[12]),
        }
    )


def _utf16z(blob: bytes, offset: int) -> str:
    end = offset
    limit = len(blob)
    while end + 2 <= limit and blob[end : end + 2] != b"\x00\x00":
        end += 2
    return blob[offset:end].decode("utf-16-le", errors="replace")


def fxcomponent_resource(pe: Any) -> dict[str, Any]:
    for type_entry in getattr(pe, "DIRECTORY_ENTRY_RESOURCE", []).entries:
        if int(type_entry.id or 0) != FXCOMPONENT_RESOURCE_TYPE:
            continue
        for name_entry in type_entry.directory.entries:
            if name_entry.name is None:
                continue
            name_text = str(name_entry.name)
            payload_entry = name_entry.directory.entries[0].data.struct
            rva = int(payload_entry.OffsetToData)
            size = int(payload_entry.Size)
            blob = common.read_rva(pe, rva, size)
            try:
                manifest = json.loads(blob.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return {
                    "present": True,
                    "name": name_text,
                    "parsed": False,
                    "payload_sha256": sha256_hex(blob),
                }
            dependencies = [str(item) for item in manifest.get("dependencies", [])]
            provides = [str(item) for item in manifest.get("provides", [])]
            return {
                "present": True,
                "type_id": FXCOMPONENT_RESOURCE_TYPE,
                "name": name_text,
                "rva": rva,
                "rva_hex": common.hexs(rva),
                "raw": common.rva_to_raw(pe, rva),
                "raw_hex": common.hexs(common.rva_to_raw(pe, rva) or 0),
                "size": size,
                "size_hex": common.hexs(size),
                "payload_sha256": sha256_hex(blob),
                "parsed": True,
                "component_name": manifest.get("name"),
                "component_version": manifest.get("version"),
                "provides": provides,
                "dependencies": dependencies,
                "dependency_count": len(dependencies),
                "dependencies_sorted": sorted(dependencies),
                "dependencies_sha256": canonical_digest(
                    [f"dependency:{item}" for item in dependencies]
                ),
                "component_key_sha256": canonical_digest(
                    [
                        f"name:{manifest.get('name')}",
                        f"version:{manifest.get('version')}",
                        *[f"dependency:{item}" for item in dependencies],
                        *[f"provides:{item}" for item in provides],
                    ]
                ),
            }
    return {"present": False, "parsed": False}







def import_export_summary(pe: Any) -> dict[str, Any]:
    regular: list[str] = []
    ordinal_keys: list[str] = []
    modules: list[dict[str, Any]] = []
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = descriptor.dll.decode("ascii", errors="replace")
        name_imports = 0
        ordinal_imports = 0
        for entry in descriptor.imports:
            if entry.import_by_ordinal:
                key = f"{dll}!#{int(entry.ordinal)}"
                ordinal_keys.append(key)
                ordinal_imports += 1
            else:
                key = f"{dll}!{entry.name.decode('ascii', errors='replace')}"
                name_imports += 1
            regular.append(key)
        modules.append(
            {
                "dll": dll,
                "symbol_count": len(descriptor.imports),
                "name_imports": name_imports,
                "ordinal_imports": ordinal_imports,
                "is_fivem_client_module": _is_fivem_module(dll),
            }
        )
    delay: list[str] = []
    delay_modules: list[dict[str, Any]] = []
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
        dll = descriptor.dll.decode("ascii", errors="replace")
        for entry in descriptor.imports:
            name = entry.name.decode("ascii", errors="replace") if entry.name else f"#{entry.ordinal}"
            delay.append(f"{dll}!{name}")
        delay_modules.append({"dll": dll, "symbol_count": len(descriptor.imports)})
    exports = common.export_summary(pe)
    export_keys = [
        f"{symbol['name']}@{symbol['rva']:X}" if symbol["name"] else f"@{symbol['rva']:X}"
        for symbol in exports.get("symbols", [])
    ]
    fivem_modules = [module["dll"] for module in modules if module["is_fivem_client_module"]]
    return {
        "import_descriptor_count": len(modules),
        "import_symbol_count": len(regular),
        "import_symbols_sha256": canonical_digest(regular),
        "delay_import_descriptor_count": len(delay_modules),
        "delay_import_symbol_count": len(delay),
        "delay_import_symbols_sha256": canonical_digest(delay),
        "total_descriptor_count": len(modules) + len(delay_modules),
        "total_symbol_count": len(regular) + len(delay),
        "total_symbols_sha256": canonical_digest([*regular, *delay]),
        "ordinal_import_keys": sorted(ordinal_keys),
        "export_module_name": exports.get("module_name"),
        "export_symbol_count": exports.get("symbol_count", 0),
        "export_forwarder_count": exports.get("forwarder_count", 0),
        "export_symbol_names": [symbol["name"] for symbol in exports.get("symbols", [])],
        "export_symbol_rvas": [symbol["rva_hex"] for symbol in exports.get("symbols", [])],
        "export_symbols_sha256": canonical_digest([f"export:{key}" for key in export_keys]),
        "modules": sorted(modules, key=lambda item: item["dll"].lower()),
        "delay_modules": sorted(delay_modules, key=lambda item: item["dll"].lower()),
        "fivem_client_modules": sorted(fivem_modules, key=str.lower),
        "fivem_client_module_count": len(fivem_modules),
        "fivem_client_modules_sha256": canonical_digest(
            [f"import-module:{dll.lower()}" for dll in fivem_modules]
        ),
    }


def _is_fivem_module(dll: str) -> bool:
    lowered = dll.lower()
    if lowered in CLIENT_MODULE_NAMES:
        return True
    return any(lowered.startswith(prefix) for prefix in CLIENT_MODULE_PREFIXES)


def section_summary(pe: Any, data: bytes) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    table_lines: list[str] = []
    for section in common.sections(pe):
        raw = data[section.raw_pointer : section.raw_pointer + section.raw_size]
        content_size = min(section.raw_size, section.virtual_size)
        content = raw[:content_size]
        record = {
            "index": section.index,
            "name": section.name,
            "virtual_address": section.virtual_address,
            "virtual_address_hex": common.hexs(section.virtual_address),
            "virtual_size": section.virtual_size,
            "virtual_size_hex": common.hexs(section.virtual_size),
            "raw_pointer": section.raw_pointer,
            "raw_pointer_hex": common.hexs(section.raw_pointer),
            "raw_size": section.raw_size,
            "raw_size_hex": common.hexs(section.raw_size),
            "characteristics": section.characteristics,
            "characteristics_hex": common.hexs(section.characteristics),
            "content_size": content_size,
            "padding_bytes": section.raw_size - content_size,
            "raw_sha256": sha256_hex(raw),
            "content_sha256": sha256_hex(content),
            "entropy": common.section_entropy(pe, section),
            "entropy_content": entropy_of(content),
            "raw_rva_delta": section.raw_pointer - section.virtual_address,
        }
        records.append(record)
        table_lines.append(
            "|".join(
                (
                    record["name"],
                    record["virtual_address_hex"],
                    record["virtual_size_hex"],
                    record["raw_pointer_hex"],
                    record["raw_size_hex"],
                    record["characteristics_hex"],
                    record["raw_sha256"],
                )
            )
        )
    return {
        "count": len(records),
        "table_key_sha256": canonical_digest(table_lines),
        "content_key_sha256": canonical_digest(
            [f"{record['name']}#{record['content_sha256']}" for record in records]
        ),
        "entropy_key_sha256": canonical_digest(
            [f"{record['name']}@{record['entropy']}" for record in records]
        ),
        "sections": records,
    }







def build_path_corpus(data: bytes) -> dict[str, Any]:
    absolute: set[str] = set()
    relative: set[str] = set()
    for match in BUILD_PATH_RUN.finditer(data):
        text = match.group(0)[:-1].decode("ascii", errors="replace")
        if ABSOLUTE_BUILD_PATH.match(text):
            absolute.add(text)
        elif RELATIVE_BUILD_PATH.match(text):
            relative.add(text)
    absolute_list = sorted(absolute)
    relative_list = sorted(relative)
    vendor = [path for path in absolute_list if _is_vendor_path(path)]
    first_party = [path for path in absolute_list if path not in vendor]
    private = [path for path in relative_list if PRIVATE_SEGMENT_MARKER in path]
    client = [path for path in absolute_list if "\\code\\client\\" in path.lower()]
    server = [path for path in absolute_list if "\\code\\server\\" in path.lower()]
    return {
        "extraction_rule": "NUL terminated printable ASCII runs of 8..300 bytes "
        "that start with `C:\\gl\\` or `..\\`",
        "absolute_count": len(absolute_list),
        "relative_count": len(relative_list),
        "vendor_absolute_count": len(vendor),
        "first_party_absolute_count": len(first_party),
        "private_relative_count": len(private),
        "client_source_count": len(client),
        "server_source_count": len(server),
        "client_or_server_evidence": (
            "client" if client else "server" if server else "undetermined"
        ),
        "absolute_roots": sorted(
            {"\\".join(path.split("\\")[:5]) for path in absolute_list if path.count("\\") >= 4}
        ),
        "relative_roots": sorted(
            {"\\".join(path.split("\\")[:4]) for path in relative_list if path.count("\\") >= 3}
        ),
        "client_source_paths": sorted(client),
        "server_source_paths": sorted(server),
        "first_party_absolute": first_party,
        "private_relative": sorted(private),
        "corpus_sha256": canonical_digest(
            [f"abs:{path}" for path in absolute_list]
            + [f"rel:{path}" for path in relative_list]
        ),
    }


def _is_vendor_path(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in VENDOR_SEGMENT_MARKERS)







def certificate_evidence(data: bytes, pe: Any, image: Mapping[str, Any]) -> dict[str, Any]:
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[SECURITY_DIRECTORY_INDEX]
    offset = int(security.VirtualAddress)
    size = int(security.Size)
    if not offset or not size:
        return {
            "present": False,
            "cryptographically_verified": False,
            "reason": "no certificate table present",
        }
    blob = data[offset : offset + size]
    dw_length, w_revision, w_certificate_type = struct.unpack_from("<IHH", blob, 0)
    pkcs7 = blob[8:dw_length] if dw_length >= 8 else b""
    embedded = _extract_spci_digest(pkcs7)
    signing = _extract_signing_time(pkcs7)
    return {
        "present": True,
        "file_offset": offset,
        "file_offset_hex": common.hexs(offset),
        "size": size,
        "size_hex": common.hexs(size),
        "end_offset": offset + size,
        "end_offset_hex": common.hexs(offset + size),
        "reaches_file_end": offset + size == len(data),
        "win_certificate": {
            "dw_length": dw_length,
            "w_revision": common.hexs(w_revision),
            "w_certificate_type": common.hexs(w_certificate_type),
            "b_certificate_size": len(pkcs7),
        },
        "sha256": sha256_hex(blob),
        "pkcs7_sha256": sha256_hex(pkcs7),
        "pkcs7_size": len(pkcs7),
        "embedded_digest": embedded,
        "embedded_digest_matches_recomputed_image_hash": (
            embedded["value"] == image["value"] if embedded.get("value") else None
        ),
        "signing_time": signing,
        "cryptographically_verified": False,
        "verification_note": "no chain validation and no revocation lookup is "
        "performed here, so nothing is asserted about signer identity, chain "
        "validity or revocation status; only bytes the signature already contains "
        "are compared",
    }


def _tlv(blob: bytes, offset: int) -> dict[str, Any]:
    tag = blob[offset]
    cursor = offset + 1
    length = blob[cursor]
    cursor += 1
    indefinite = length == 0x80
    if not indefinite and length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(blob[cursor : cursor + count], "big")
        cursor += count
    if indefinite:
        length = None
    return {
        "tag": tag,
        "len": length,
        "start": offset,
        "content": cursor,
        "end": None if indefinite else cursor + length,
    }


def _children(blob: bytes, node: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    limit = len(blob) if node["len"] is None else int(node["end"])
    cursor = int(node["content"])
    while cursor + 2 <= limit:
        if blob[cursor : cursor + 2] == b"\x00\x00":
            break
        child = _tlv(blob, cursor)
        result.append(child)
        cursor = len(blob) if child["len"] is None else int(child["end"])
    return result


def _expect(blob: bytes, offset: int, tag: int) -> dict[str, Any] | None:
    if offset + 2 > len(blob):
        return None
    node = _tlv(blob, offset)
    return node if node["tag"] == tag else None


def _extract_spci_digest(pkcs7: bytes) -> dict[str, Any]:
    """ContentInfo -> SignedData -> SpcIndirectDataContent -> DigestInfo -> digest."""
    trace: list[str] = []
    content_info = _expect(pkcs7, 0, 0x30)
    if content_info is None:
        return {"extracted": False, "reason": "no ContentInfo SEQUENCE", "trace": trace}
    top = _children(pkcs7, content_info)
    trace.append("ContentInfo children=" + ",".join(hex(node["tag"]) for node in top))
    explicit = next((node for node in top if node["tag"] == 0xA0), None)
    if explicit is None:
        return {"extracted": False, "reason": "no [0] EXPLICIT", "trace": trace}
    signed_data = _expect(pkcs7, int(explicit["content"]), 0x30)
    if signed_data is None:
        return {"extracted": False, "reason": "no SignedData SEQUENCE", "trace": trace}
    fields = _children(pkcs7, signed_data)
    trace.append("SignedData fields=" + ",".join(hex(node["tag"]) for node in fields))
    encapsulated = next(
        (node for index, node in enumerate(fields) if index >= 2 and node["tag"] == 0x30), None
    )
    if encapsulated is None:
        return {"extracted": False, "reason": "no encapContentInfo", "trace": trace}
    inner = _children(pkcs7, encapsulated)
    explicit_digest = next((node for node in inner if node["tag"] == 0xA0), None)
    if explicit_digest is None:
        return {"extracted": False, "reason": "no [0] DigestInfo", "trace": trace}
    container = _expect(pkcs7, int(explicit_digest["content"]), 0x30)
    if container is None:
        return {"extracted": False, "reason": "no DigestInfo SEQUENCE", "trace": trace}
    located = _locate_digest(pkcs7, container, trace)
    if located is None:
        return {
            "extracted": False,
            "reason": "no AlgorithmIdentifier plus OCTET STRING pair below the "
            "DigestInfo container",
            "trace": trace,
        }
    algorithm, octets = located
    algorithm_children = _children(pkcs7, algorithm)
    if not algorithm_children or algorithm_children[0]["tag"] != 0x06:
        return {"extracted": False, "reason": "no digest algorithm OID", "trace": trace}
    oid_start = int(algorithm_children[0]["content"])
    oid_content = pkcs7[oid_start : oid_start + int(algorithm_children[0]["len"])]
    oid_tlv = pkcs7[int(algorithm_children[0]["start"]) : int(algorithm_children[0]["end"])]
    value_start = int(octets["content"])
    value = pkcs7[value_start : int(octets["end"])]
    return {
        "extracted": True,
        "reason": None,
        "trace": trace,
        "algorithm_oid_hex": oid_content.hex(),
        "algorithm_oid_tlv_hex": oid_tlv.hex(),
        "algorithm_is_sha256": oid_tlv == SHA256_DIGEST_OID,
        "length": len(value),
        "value": value.hex(),
        "pkcs7_offset": value_start,
    }


def _locate_digest(
    blob: bytes, node: Mapping[str, Any], trace: list[str], depth: int = 0
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Descend DigestInfo until an AlgorithmIdentifier plus OCTET STRING is found.

    Authenticode encoders are inconsistent here: some wrap the digest in a second
    SEQUENCE, some do not. Bounded to four levels so a malformed blob cannot turn
    this into an unbounded walk.
    """
    if depth > 3:
        return None
    parts = _children(blob, node)
    trace.append(
        f"{'.' * (depth + 1)}DigestInfo level tags="
        + ",".join(hex(part["tag"]) for part in parts)
    )
    if len(parts) == 2 and parts[0]["tag"] == 0x30 and parts[1]["tag"] == 0x04:
        return parts[0], parts[1]
    if len(parts) == 2 and parts[0]["tag"] == 0x30 and parts[1]["tag"] == 0x30:
        return _locate_digest(blob, parts[1], trace, depth + 1)
    return None


def _extract_signing_time(pkcs7: bytes) -> dict[str, Any]:
    offsets = [match.start() for match in re.finditer(re.escape(SIGNING_TIME_OID), pkcs7)]
    for offset in offsets:
        cursor = offset + len(SIGNING_TIME_OID)
        if cursor + 2 > len(pkcs7) or pkcs7[cursor] != 0x31:
            continue
        set_node = _tlv(pkcs7, cursor)
        time_offset = int(set_node["content"])
        if time_offset + 2 > len(pkcs7) or pkcs7[time_offset] not in TIME_TAGS:
            continue
        time_node = _tlv(pkcs7, time_offset)
        value = pkcs7[int(time_node["content"]) : int(time_node["end"])]
        text = value.decode("ascii", errors="replace")
        tag_name = TIME_TAGS_INV.get(int(time_node["tag"]), "UNKNOWN")
        return {
            "extracted": True,
            "oid_offsets": offsets,
            "oid_offset": offset,
            "framing": "Attribute SEQUENCE { OID 1.2.840.113549.1.9.5, SET { "
            + tag_name
            + " } }",
            "time_tag": common.hexs(int(time_node["tag"])),
            "raw_value": text,
            "value_length": len(value),
            "normalized_utc": _normalize_time(text),
        }
    return {"extracted": False, "oid_offsets": offsets}


def _normalize_time(text: str) -> str | None:
    for form, pattern in TIME_FORMS:
        match = pattern.match(text)
        if match is None:
            continue
        parts = match.groupdict()
        if "yyyy" in parts:
            year = int(parts["yyyy"])
        else:
            short_year = int(parts["yy"])
            year = short_year + (2000 if short_year < 50 else 1900)
        return (
            f"{year:04d}-{parts['mm']}-{parts['dd']} "
            f"{parts['hh']}:{parts['mi']}:{parts['ss']} UTC ({form})"
        )
    return None







def _workspace_files(root: Path) -> list[tuple[str, str]]:
    unique: dict[str, str] = {}
    for relative, category in WORKSPACE_TEXT_TARGETS:
        target = root / relative
        if target.is_file():
            unique.setdefault(relative, category)
        elif target.is_dir():
            for path in sorted(target.rglob("*")):
                if not path.is_file():
                    continue
                if any(part in WORKSPACE_EXCLUDED_DIRS for part in path.parts):
                    continue
                if path.suffix.lower() not in WORKSPACE_TEXT_EXTENSIONS:
                    continue
                unique.setdefault(path.relative_to(root).as_posix(), category)
    return sorted(unique.items())[:MAX_WORKSPACE_FILES]


def workspace_correlation(root: Path, declared_client_modules: Sequence[str]) -> dict[str, Any]:
    """Correlate the specimen's build identity against the workspace text.

    Two keyword classes are kept apart on purpose. Identity keywords name the
    component, its build root or its vendor, so a hit would be provenance
    evidence. Ambient keywords only show that the project is FiveM related; in
    this workspace they are dominated by the C++ `namespace fivem` and by
    product prose, so counting them separately keeps the provenance signal
    readable instead of averaging it away.
    """
    identity_refs: list[dict[str, Any]] = []
    ambient_naming: list[dict[str, Any]] = []
    identity_totals = {keyword: 0 for keyword in WORKSPACE_IDENTITY_KEYWORDS}
    ambient_totals = {keyword: 0 for keyword in WORKSPACE_AMBIENT_KEYWORDS}
    context_totals = {term: 0 for term in WORKSPACE_BUILD_CONTEXT_TERMS}
    files = _workspace_files(root)
    for relative, category in files:
        try:
            text = (root / relative).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lowered = text.lower()
        file_identity = {
            keyword: lowered.count(keyword) for keyword in WORKSPACE_IDENTITY_KEYWORDS
        }
        file_ambient = {keyword: lowered.count(keyword) for keyword in WORKSPACE_AMBIENT_KEYWORDS}
        file_context = {term: text.count(term) for term in WORKSPACE_BUILD_CONTEXT_TERMS}
        for keyword, count in file_identity.items():
            identity_totals[keyword] += count
        for keyword, count in file_ambient.items():
            ambient_totals[keyword] += count
        for term, count in file_context.items():
            context_totals[term] += count
        if any(file_ambient.values()):
            ambient_naming.append(
                {
                    "path": relative,
                    "category": category,
                    "ambient_keyword_counts": {
                        key: value for key, value in file_ambient.items() if value
                    },
                }
            )
        if not any(file_identity.values()) and not any(file_context.values()):
            continue
        lines: list[dict[str, Any]] = []
        for number, line in enumerate(text.splitlines(), start=1):
            lowered_line = line.lower()
            if not any(keyword in lowered_line for keyword in WORKSPACE_IDENTITY_KEYWORDS) and not any(
                term in line for term in WORKSPACE_BUILD_CONTEXT_TERMS
            ):
                continue
            lines.append({"line": number, "text": line.strip()[:200]})
            if len(lines) >= MAX_WORKSPACE_LINES_PER_FILE:
                break
        identity_refs.append(
            {
                "path": relative,
                "category": category,
                "identity_keyword_counts": {
                    key: value for key, value in file_identity.items() if value
                },
                "build_context_counts": {
                    key: value for key, value in file_context.items() if value
                },
                "lines": lines,
                "lines_capped": len(lines) >= MAX_WORKSPACE_LINES_PER_FILE,
            }
        )
    return {
        "text_reference_scope": [relative for relative, _ in files],
        "text_reference_file_count": len(files),
        "excluded_from_provenance_scan": dict(sorted(WORKSPACE_SCAN_EXCLUDED_REASON.items())),
        "identity_keyword_totals": {key: identity_totals[key] for key in sorted(identity_totals)},
        "build_context_totals": {key: context_totals[key] for key in sorted(context_totals)},
        "identity_referencing_files": identity_refs,
        "identity_reference_file_count": len(identity_refs),
        "workspace_contains_specimen_build_reference": bool(
            any(identity_totals.values()) or any(context_totals.values())
        ),
        "ambient_keyword_totals": {key: ambient_totals[key] for key in sorted(ambient_totals)},
        "ambient_naming_note": "fivem and citizenfx hits come from the C++ "
        "`namespace fivem`, the project name and product prose; they are not "
        "build-provenance references to the specimen",
        "ambient_naming_files": ambient_naming,
        "component_config": _component_config(root),
        "pdb_inventory": _pdb_inventory(root),
        "import_module_resolution": _module_resolution(root, declared_client_modules),
        "build_context_intersection": {
            "specimen_pdb_root": EXPECTED_BUILD_CACHE_ROOT,
            "specimen_pdb_root_present_in_workspace": False,
            "specimen_first_party_source": EXPECTED_FIRST_PARTY_SOURCE_PATH,
            "specimen_first_party_source_present_in_workspace": False,
            "specimen_private_repo_segment": EXPECTED_PRIVATE_REPO_SEGMENT,
            "specimen_private_repo_segment_present_in_workspace": False,
        },
    }


def _component_config(root: Path) -> dict[str, Any]:
    path = root / "Bin" / "components.json"
    if not path.is_file():
        return {"present": False}
    data = path.read_bytes()
    try:
        entries = [str(item) for item in json.loads(data.decode("utf-8"))]
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"present": True, "parsed": False, "sha256": sha256_hex(data)}
    server = [entry for entry in entries if entry.startswith(SERVER_COMPONENT_PREFIX)]
    return {
        "present": True,
        "parsed": True,
        "path": "Bin/components.json",
        "sha256": sha256_hex(data),
        "entry_count": len(entries),
        "server_component_count": len(server),
        "non_server_component_count": len(entries) - len(server),
        "contains_adhesive": EXPECTED_COMPONENT_NAME in entries,
        "entries": sorted(entries),
    }


def _pdb_inventory(root: Path) -> dict[str, Any]:
    found = [
        {
            "path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "basename": path.name.lower(),
        }
        for path in sorted(root.rglob("*.pdb"))
        if not any(part in WORKSPACE_EXCLUDED_DIRS for part in path.parts)
    ]
    return {
        "search_root": "repository, excluding .git, build and .zcode",
        "pdb_count": len(found),
        "pdbs": found,
        "adhesive_pdb_present": any(item["basename"] == "adhesive.pdb" for item in found),
        "adhesive_pdb_expected_name": "adhesive.pdb",
        "symbol_resolution_available": False,
        "symbol_resolution_reason": "no PDB matching the embedded GUID and age "
        "exists in the workspace, so no function, type or source line name can be "
        "attached to any address in this evidence set",
    }


def _module_resolution(root: Path, declared: Sequence[str]) -> dict[str, Any]:
    inventory: dict[str, list[str]] = {}
    for path in (root / "Bin").rglob("*"):
        if path.is_file():
            inventory.setdefault(path.name.lower(), []).append(
                path.relative_to(root).as_posix()
            )
    rows = [
        {
            "module": module,
            "present_in_bin": bool(inventory.get(module.lower())),
            "paths": sorted(inventory.get(module.lower(), []))[:4],
        }
        for module in sorted(declared, key=str.lower)
    ]
    present = [row["module"] for row in rows if row["present_in_bin"]]
    absent = [row["module"] for row in rows if not row["present_in_bin"]]
    return {
        "note": "the workspace Bin/ tree is the FXServer payload set while the "
        "specimen is a client component, so a partial overlap is expected and does "
        "not establish a shared build",
        "declared_client_module_count": len(rows),
        "present_count": len(present),
        "absent_count": len(absent),
        "present": present,
        "absent": absent,
        "rows": rows,
    }







def correlation_keys(
    specimen: Mapping[str, Any],
    codeview: Mapping[str, Any],
    linker: Mapping[str, Any],
    rich: Mapping[str, Any],
    header: Mapping[str, Any],
    image: Mapping[str, Any],
    sections_block: Mapping[str, Any],
    imports_block: Mapping[str, Any],
    version: Mapping[str, Any],
    fxcomponent: Mapping[str, Any],
    corpus: Mapping[str, Any],
    certificate: Mapping[str, Any],
) -> dict[str, Any]:
    parsed = codeview.get("codeview") or {}
    keys: dict[str, Any] = {
        "whole_file_sha256": specimen["sha256"],
        "whole_file_sha1": specimen["sha1"],
        "whole_file_size": specimen["size"],
        "pdb_debug_id": parsed.get("debug_id"),
        "pdb_guid": parsed.get("guid"),
        "pdb_age": parsed.get("age"),
        "pdb_path": parsed.get("pdb_path"),
        "pdb_path_sha256": parsed.get("pdb_path_sha256"),
        "pdb_match_key": parsed.get("pdb_match_key"),
        "pe_time_date_stamp": header["time_date_stamp"],
        "pe_time_date_stamp_utc": header["time_date_stamp_utc"],
        "linker_version_field": header["linker_version"],
        "rich_header_present": rich["rich_header_present"],
        "lld_build_id_available": linker["build_id"]["lld_build_id_available"],
        "authenticode_image_sha256": image["value"],
        "section_table_key": sections_block["table_key_sha256"],
        "section_content_key": sections_block["content_key_sha256"],
        "section_entropy_key": sections_block["entropy_key_sha256"],
        "import_symbols_key": imports_block["import_symbols_sha256"],
        "import_modules_key": imports_block["fivem_client_modules_sha256"],
        "export_symbols_key": imports_block["export_symbols_sha256"],
        "version_resource_key": version.get("payload_sha256"),
        "fxcomponent_key": fxcomponent.get("component_key_sha256"),
        "fxcomponent_dependency_key": fxcomponent.get("dependencies_sha256"),
        "build_path_corpus_key": corpus["corpus_sha256"],
        "certificate_table_sha256": certificate.get("sha256"),
    }
    vector = {
        key: keys[key] for key in sorted(keys) if key not in {"whole_file_size", "pdb_path"}
    }
    keys["correlation_vector_sha256"] = sha256_hex(
        json.dumps(vector, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    keys["recompute_recipe"] = {
        "pdb_debug_id": "uppercase RSDS GUID without dashes, then the age as "
        "uppercase hex",
        "pdb_match_key": "sha256 of b'\\x00'.join([lowercased pdb path with '/' "
        "replaced by '\\\\', guid_bytes_le, little-endian age])",
        "authenticode_image_sha256": "sha256 over bytes [0, SizeOfHeaders) minus "
        "the 4 byte CheckSum field and the 8 byte Security directory entry, then "
        "each section's full SizeOfRawData in section table order",
        "section_table_key": "sha256 of sorted 'name|rva|vsize|rawptr|rawsize|"
        "characteristics|raw_sha256' lines, LF terminated",
        "section_content_key": "sha256 of sorted 'name#content_sha256' lines over "
        "the first min(SizeOfRawData, VirtualSize) bytes of each section",
        "import_symbols_key": "sha256 of sorted 'dll!symbol' lines, ordinal "
        "imports written as 'dll!#ordinal'",
        "fxcomponent_key": "sha256 of sorted 'name:..', 'version:..', "
        "'dependency:..', 'provides:..' lines",
        "build_path_corpus_key": "sha256 of sorted 'abs:<path>' and 'rel:<path>' "
        "lines for every extracted build path",
        "correlation_vector_sha256": "sha256 of the compact sorted-key JSON of all "
        "other keys except whole_file_size and pdb_path",
    }
    return keys


def authenticity_gate(
    certificate: Mapping[str, Any], pdb_inventory: Mapping[str, Any], components: Mapping[str, Any]
) -> dict[str, Any]:
    gates = {
        "pdb_available_in_workspace": pdb_inventory["adhesive_pdb_present"],
        "pdb_debug_id_matched_against_a_second_artifact": False,
        "authenticode_table_present": certificate.get("present", False),
        "embedded_digest_equals_recomputed_image_hash": certificate.get(
            "embedded_digest_matches_recomputed_image_hash"
        ),
        "authenticode_chain_cryptographically_verified_by_this_script": certificate.get(
            "cryptographically_verified", False
        ),
        "independent_same_build_reference_available": False,
        "official_build_manifest_available": False,
    }
    return {
        "component_identification": "high",
        "component_identification_basis": "CreateComponent export, FXCOMPONENT "
        "resource, CitizenFX version resource and the FiveM client import set",
        "build_provenance": "undetermined",
        "authentic_build_asserted": False,
        "gates": gates,
        "satisfied_gates": sorted(key for key, value in gates.items() if value is True),
        "unsatisfied_gates": sorted(key for key, value in gates.items() if value is not True),
        "component_list_contains_specimen": components.get("contains_adhesive"),
        "statement": "This artifact set does not assert that the specimen is an "
        "authentic vendor build. Component identity is established from the bytes; "
        "build provenance is not. The embedded Authenticode digest equals the "
        "recomputed PE image hash, which shows only that the signed bytes are the "
        "present bytes. No signature chain was validated, no PDB was located, and "
        "no second artifact of the same build exists in this workspace, so there is "
        "nothing to compare the debug ID or the section keys against.",
        "requirements_to_lift": [
            "locate adhesive.pdb with debug id "
            f"{EXPECTED_DEBUG_ID} and age {EXPECTED_PDB_AGE}, verify its own stream "
            "identity, and resolve symbols through it",
            "obtain a second artifact of the same 1.0.0.36109 build and compare "
            "correlation_vector_sha256",
            "verify the Authenticode chain in a separate network-permitted step and "
            "record the verification result together with its timestamp",
            "obtain the official build manifest that maps build number 36109 to a "
            "published artifact",
        ],
    }


def open_questions() -> list[dict[str, Any]]:
    return [
        {
            "id": "OQ-01",
            "priority": "P0",
            "question": f"Where is adhesive.pdb with debug id {EXPECTED_DEBUG_ID} "
            f"and age {EXPECTED_PDB_AGE}, and can symbols be resolved through it?",
            "status": "open",
            "why_it_matters": "without the PDB no function, type or source line "
            "name can be attached to any address in this evidence set",
            "closes_when": "the matching PDB is located and its stream identity is "
            "verified, or a symbol server entry is confirmed absent",
            "blocks": ["symbol level naming", "source line correlation"],
        },
        {
            "id": "OQ-02",
            "priority": "P0",
            "question": "Which official artifact corresponds to build 36109 of the "
            "CitizenFX 1.0.0.36109 client?",
            "status": "open",
            "why_it_matters": "the embedded PDB path names a build cache root, not a "
            "release; the PE version, the FXCOMPONENT version and the build number "
            "live in three different layers and are not cross-linked anywhere",
            "closes_when": "an official build manifest or a second signed artifact of "
            "the same build number is available for comparison",
            "blocks": ["build provenance"],
        },
        {
            "id": "OQ-03",
            "priority": "P0",
            "question": "Which exact LLVM LLD release performed the final link?",
            "status": "open",
            "why_it_matters": "the 14.0 linker field is an MSVC 2015 compatibility "
            "value, the Rich header is absent, and no build id survives, so the "
            "retpoline metadata is a behavioural fingerprint only",
            "closes_when": "a build log, a reproducible rebuild with a pinned linker, "
            "or a toolchain marker from a same-family artifact becomes available",
            "blocks": ["toolchain attribution"],
        },
        {
            "id": "OQ-04",
            "priority": "P0",
            "question": "Was the MSVC or the clang-cl frontend used, and which "
            "runtime build?",
            "status": "open",
            "why_it_matters": "both frontends produce the observed MSVC compatible "
            "ABI, dynamic MSVC/UCRT imports and load config layout, so the specimen "
            "cannot distinguish them",
            "closes_when": "a toolchain fingerprint from a same-family artifact or a "
            "build log identifies frontend and CRT version",
            "blocks": ["toolchain attribution"],
        },
        {
            "id": "OQ-05",
            "priority": "P1",
            "question": "Does the retpolne tag count of "
            f"{len(EXPECTED_RETPOLINE_TAG_OFFSETS)} (section offsets "
            f"{', '.join(common.hexs(offset) for offset in EXPECTED_RETPOLINE_TAG_OFFSETS)}) "
            "contradict the peer report value of 3, or does that report count record "
            "pairs instead of tags?",
            "status": "open",
            "why_it_matters": "a tag count disagreement is a raw byte level conflict "
            "and must be settled before the section is used as a differential key "
            "between builds",
            "closes_when": "the retpolne record layout is decoded and the peer report "
            "is corrected or confirmed",
            "blocks": ["retpolne based differential analysis"],
        },
        {
            "id": "OQ-06",
            "priority": "P1",
            "question": f"Why do {EXPECTED_VENDOR_PATH_COUNT} of the "
            f"{EXPECTED_BUILD_PATH_ABSOLUTE_COUNT} embedded absolute build paths sit "
            "under vendor/, and only one under code/client/?",
            "status": "open",
            "why_it_matters": "retention of __FILE__ strings is a compiler and "
            "optimisation level property, and the ratio constrains which claims "
            "about first-party source layout are supportable",
            "closes_when": "the set of translation units that emit __FILE__ under this "
            "toolchain is characterised, or a same-family build is compared",
            "blocks": ["source layout inference"],
        },
        {
            "id": "OQ-07",
            "priority": "P1",
            "question": "Is the specimen from the same build campaign as the FXServer "
            "payload in Bin/, given that Bin/components.json lists server components "
            "and does not list adhesive, and several declared client modules are "
            "absent from Bin/?",
            "status": "open",
            "why_it_matters": "the workspace and the specimen are different product "
            "surfaces; correlating their build numbers without evidence would be a "
            "provenance error",
            "closes_when": "the build numbers of the Bin/ payload artifacts are "
            "extracted and compared against 36109",
            "blocks": ["workspace provenance correlation"],
        },
        {
            "id": "OQ-08",
            "priority": "P1",
            "question": "What is the version relationship between the PE version "
            f"{EXPECTED_FILE_VERSION} and the FXCOMPONENT version "
            f"{EXPECTED_COMPONENT_VERSION}?",
            "status": "open",
            "why_it_matters": "both are component scoped yet stored in different "
            "resource types, and a correlation key that mixes them would be unstable "
            "across builds",
            "closes_when": "two or more builds show whether the FXCOMPONENT version is "
            "bumped independently of the PE version",
            "blocks": ["stable component correlation key design"],
        },
        {
            "id": "OQ-09",
            "priority": "P2",
            "question": f"Is the embedded build path root {EXPECTED_BUILD_CACHE_ROOT} a "
            "stable CI worker path or a per-agent path?",
            "status": "open",
            "why_it_matters": "a stable root makes the PDB path usable as a build key; "
            "a per-agent path makes it noise that must stay out of correlation vectors",
            "closes_when": "two builds of the same component are compared and the path "
            "roots are shown to be identical or divergent",
            "blocks": ["pdb_path as correlation key"],
        },
        {
            "id": "OQ-10",
            "priority": "P2",
            "question": "Do the section content hashes stay stable across rebuilds of "
            "the same build number, or does build-local absolute path material from "
            ".build-cache leak into .rdata and break the key?",
            "status": "open",
            "why_it_matters": "the section keys only serve build-to-build correlation "
            "if they are insensitive to the build directory layout",
            "closes_when": "two artifacts of the same build number are compared at "
            "section level and the keys are either equal or the difference is explained",
            "blocks": ["section key reusability"],
        },
        {
            "id": "OQ-11",
            "priority": "P2",
            "question": "Is the two digit year signingTime encoding inside the "
            "timestamp token byte-identical to the four digit year representation "
            "found in the same certificate table?",
            "status": "open",
            "why_it_matters": "two representations of the same instant in one blob "
            "affects which one a downstream tool treats as authoritative",
            "closes_when": "both encodings are decoded and compared, and the "
            "timestamp token structure is documented",
            "blocks": ["timestamp evidence precision"],
        },
    ]







def build_report(root: Path) -> tuple[dict[str, Any], list[common.Check]]:
    specimen_path = root / SPECIMEN_RELATIVE
    data = specimen_path.read_bytes()
    file_digests = common.file_digests(specimen_path)
    pe = common.load_pe(specimen_path)
    try:
        header = common.header_summary(pe)
        codeview = codeview_records(pe, data)
        parsed_cv = codeview.get("codeview") or {}
        guid_field = (
            (int(parsed_cv["guid_raw"]), int(parsed_cv["guid_raw"]) + 16)
            if parsed_cv.get("guid_raw") is not None
            else None
        )
        rich = rich_header(data, pe)
        build_id = toolchain_marker_probe(data, pe, guid_field)
        retpolne = retpoline_section(pe, data)
        image = authenticode_image_digest(data, pe)
        certificate = certificate_evidence(data, pe, image)
        version = version_resource(pe)
        fxcomponent = fxcomponent_resource(pe)
        imports_block = import_export_summary(pe)
        sections_block = section_summary(pe, data)
        corpus = build_path_corpus(data)
        pdata = common.pdata_summary(pe)
        resources = common.resource_summary(pe)
    finally:
        pe.close()

    workspace = workspace_correlation(root, imports_block["fivem_client_modules"])
    keys = correlation_keys(
        {"sha256": file_digests["sha256"], "sha1": file_digests["sha1"], "size": len(data)},
        codeview,
        {"build_id": build_id},
        rich,
        header,
        image,
        sections_block,
        imports_block,
        version,
        fxcomponent,
        corpus,
        certificate,
    )
    gate = authenticity_gate(certificate, workspace["pdb_inventory"], workspace["component_config"])
    string_table = version.get("string_table", {})

    report: dict[str, Any] = {
        "schema": SCHEMA_PDB_CORRELATION,
        "scope": {
            "question": "which reproducible keys identify this build, and which of "
            "them are unavailable",
            "specimen": SPECIMEN_RELATIVE,
            "analysis": "static file bytes only",
            "specimen_executed": False,
            "specimen_loaded": False,
            "network_used": False,
            "authenticator_used": False,
            "authenticator_skipped_reason": "chain validation can trigger revocation "
            "traffic; the run stays offline, so only bytes the signature already "
            "contains are compared",
            "emits_bypass_or_patch_material": False,
            "related_reports": [
                "reverse/adhesive-01-identity-build-signature.md",
                "reverse/adhesive-02-pe-layout-security.md",
                "reverse/adhesive-03-imports-exports.md",
                "reverse/adhesive-12-risk-methodology-open-questions.md",
            ],
        },
        "generator": {
            "script": "reverse/scripts/pdb_correlate.py",
            "schema": SCHEMA_PDB_CORRELATION,
            "python": common.python_summary()["version"],
            "pefile": common.library_version("pefile", "pefile")["module_version"],
            "determinism": {
                "json_indent": 2,
                "json_ensure_ascii": False,
                "sort_keys": False,
                "collection_order": "explicitly sorted",
                "text_encoding": "utf-8",
                "bom": False,
                "line_terminator": "\\n",
                "trailing_newline": True,
                "wall_clock_values": False,
            },
        },
        "specimen": {
            "path": SPECIMEN_RELATIVE,
            "size": len(data),
            "size_hex": common.hexs(len(data)),
            "md5": file_digests["md5"],
            "sha1": file_digests["sha1"],
            "sha256": file_digests["sha256"],
        },
        "pdb": {
            "debug_directory": codeview["directory"],
            "debug_entries": codeview["entries"],
            "codeview_entry_count": codeview["codeview_entry_count"],
            "codeview_is_unique": codeview["codeview_is_unique"],
            "codeview": codeview["codeview"],
            "pdb_availability": workspace["pdb_inventory"],
        },
        "linker": {
            "linker_version_field": header["linker_version"],
            "linker_version_raw": common.hexs(LINKER_VERSION_RAW),
            "linker_version_semantics": "the PE field is an MSVC compatible value "
            "that lld-link has written for years; it is not a release number and it "
            "is overridable at link time",
            "coff_timestamp_raw": common.hexs(COFF_TIMESTAMP_RAW),
            "debug_entry_timestamp_matches_coff": all(
                entry["time_date_stamp"] == header["time_date_stamp"]
                for entry in codeview["entries"]
            ),
            "pe_timestamp": {
                "value": header["time_date_stamp"],
                "value_hex": header["time_date_stamp_hex"],
                "utc": header["time_date_stamp_utc"],
                "reproducible_build_note": "the COFF timestamp is writable by the "
                "linker, so it is a comparison value, not a provenance proof",
            },
            "build_id": build_id,
            "rich_header": rich,
            "retpolne": retpolne,
            "lld_release_identified": False,
            "lld_release_reason": "no linker identity record survives in the image; "
            "see build_id.lld_build_id_reason and rich_header.consequence",
        },
        "identity_resources": {
            "version": version,
            "fxcomponent": fxcomponent,
            "company_name": string_table.get("CompanyName"),
            "file_description": string_table.get("FileDescription"),
            "internal_name": string_table.get("InternalName"),
            "original_filename": string_table.get("OriginalFilename"),
            "product_name": string_table.get("ProductName"),
            "legal_copyright": string_table.get("LegalCopyright"),
            "file_version": version.get("file_version_from_string_table"),
            "product_version": version.get("product_version_from_string_table"),
            "component_name": fxcomponent.get("component_name"),
            "component_version": fxcomponent.get("component_version"),
            "version_layers_note": "the PE version and the FXCOMPONENT version are "
            "separate resource types and are not cross-linked in the specimen",
            "resource_entry_count": resources["entry_count"],
            "resource_leaf_sha256": {
                f"{entry['type_id']}/{entry['name_id']}/{entry['lang_id']}": entry["sha256"]
                for entry in resources["entries"]
            },
        },
        "imports_exports": imports_block,
        "sections": sections_block,
        "exception_directory": {
            "record_count": pdata["record_count"],
            "record_size": pdata["record_size"],
            "rva_hex": pdata["rva_hex"],
            "raw_hex": pdata["raw_hex"],
            "sorted_by_begin_address": pdata["sorted_by_begin_address"],
            "duplicate_records": pdata["duplicate_records"],
            "overlapping_records": pdata["overlapping_records"],
            "unique_unwind_infos": pdata["unique_unwind_infos"],
            "unwind_info_sections": pdata["unwind_info_sections"],
        },
        "embedded_build_paths": corpus,
        "authenticode": {
            "image_digest": image,
            "certificate_table": certificate,
        },
        "workspace": workspace,
        "correlation_keys": keys,
        "authenticity": gate,
        "open_questions": open_questions(),
        "reproduce": {
            "command": "python reverse/scripts/pdb_correlate.py",
            "verify_command": "python reverse/scripts/pdb_correlate.py --verify",
            "specimen_sha256_expected": EXPECTED_FILE_SHA256,
            "external_inputs": "none; the script reads the specimen, common.py and "
            "the workspace tree only",
            "expected_exit_code": 0,
            "expected_failure_exit_code": 1,
        },
    }
    report["cross_check"] = _cross_check(
        root, header, sections_block, imports_block, pdata, resources, certificate
    )
    checks = _checks(report, header, pdata)
    report["validation"] = {
        "check_count": len(checks),
        "failed_count": sum(1 for check in checks if not check.ok),
        "checks": [check.as_row() for check in checks],
    }
    return report, checks


def _scalar(payload: Any, path: str) -> Any:
    cursor = payload
    for part in path.split("."):
        match = re.fullmatch(r"([^\[\]]*)((?:\[\d+\])*)", part)
        if match is None:
            return None
        name, indexes = match.group(1), match.group(2)
        if name:
            if not isinstance(cursor, Mapping) or name not in cursor:
                return None
            cursor = cursor[name]
        for index in re.findall(r"\[(\d+)\]", indexes):
            if not isinstance(cursor, list) or int(index) >= len(cursor):
                return None
            cursor = cursor[int(index)]
    return cursor


def _cross_check(
    root: Path,
    header: Mapping[str, Any],
    sections_block: Mapping[str, Any],
    imports_block: Mapping[str, Any],
    pdata: Mapping[str, Any],
    resources: Mapping[str, Any],
    certificate: Mapping[str, Any],
) -> dict[str, Any]:
    path = root / BASELINE_RELATIVE
    if not path.is_file():
        return {"available": False, "path": BASELINE_RELATIVE, "rows": []}
    baseline = json.loads(path.read_text(encoding="utf-8"))
    rows: list[dict[str, str]] = []
    for dotted in BASELINE_CROSS_CHECK_PATHS:
        expected = common.scalar_text(_scalar(baseline, dotted))
        actual = common.scalar_text(
            _current_value(
                dotted, header, sections_block, imports_block, pdata, resources, certificate
            )
        )
        rows.append({"key": dotted, "baseline": expected, "correlation": actual, "ok": expected == actual})
    return {
        "available": True,
        "path": BASELINE_RELATIVE,
        "note": "independent parse of the same bytes, compared against the stored "
        "baseline; a mismatch means the specimen or the parser changed",
        "row_count": len(rows),
        "failed_count": sum(1 for row in rows if not row["ok"]),
        "rows": rows,
    }


def _current_value(
    dotted: str,
    header: Mapping[str, Any],
    sections_block: Mapping[str, Any],
    imports_block: Mapping[str, Any],
    pdata: Mapping[str, Any],
    resources: Mapping[str, Any],
    certificate: Mapping[str, Any],
) -> Any:
    if dotted.startswith("pe."):
        return header.get(dotted[3:])
    if dotted.startswith("sections["):
        index = int(dotted[len("sections[") : dotted.index("]")])
        return sections_block["sections"][index].get(dotted[dotted.index("].") + 2 :])
    if dotted.startswith("pdata."):
        return pdata.get(dotted[6:])
    if dotted == "imports.descriptor_count":
        return imports_block["import_descriptor_count"]
    if dotted == "imports.symbol_count":
        return imports_block["import_symbol_count"]
    if dotted == "imports.name_imports":
        return sum(module["name_imports"] for module in imports_block["modules"])
    if dotted == "imports.ordinal_imports":
        return sum(module["ordinal_imports"] for module in imports_block["modules"])
    if dotted == "imports.delay_descriptor_count":
        return imports_block["delay_import_descriptor_count"]
    if dotted == "imports.delay_symbol_count":
        return imports_block["delay_import_symbol_count"]
    if dotted == "exports.symbol_count":
        return imports_block["export_symbol_count"]
    if dotted == "exports.module_name":
        return imports_block["export_module_name"]
    if dotted == "resources.entry_count":
        return resources["entry_count"]
    if dotted.startswith("certificate."):
        return certificate.get(dotted[len("certificate.") :])
    return None


def _checks(
    report: Mapping[str, Any], header: Mapping[str, Any], pdata: Mapping[str, Any]
) -> list[common.Check]:
    codeview = report["pdb"].get("codeview") or {}
    version = report["identity_resources"]["version"]
    fixed = version.get("fixed_file_info", {})
    fxcomponent = report["identity_resources"]["fxcomponent"]
    image = report["authenticode"]["image_digest"]
    certificate = report["authenticode"]["certificate_table"]
    sections_block = report["sections"]
    imports_block = report["imports_exports"]
    linker = report["linker"]
    build_id = linker["build_id"]
    corpus = report["embedded_build_paths"]
    pdb_inventory = report["workspace"]["pdb_inventory"]
    components = report["workspace"]["component_config"]
    resolution = report["workspace"]["import_module_resolution"]
    signing = certificate.get("signing_time", {})
    cross = report["cross_check"]

    def check(name: str, expected: Any, actual: Any) -> common.Check:
        return common.Check(name, expected, actual, expected == actual)

    rows = [
        check("specimen.sha256", EXPECTED_FILE_SHA256, report["specimen"]["sha256"]),
        check("pdb.guid", EXPECTED_PDB_GUID, codeview.get("guid")),
        check("pdb.age", EXPECTED_PDB_AGE, codeview.get("age")),
        check("pdb.path", EXPECTED_PDB_PATH, codeview.get("pdb_path")),
        check("pdb.debug_id", EXPECTED_DEBUG_ID, codeview.get("debug_id")),
        check("pdb.debug_entry_count", 1, report["pdb"]["codeview_entry_count"]),
        check("linker.version_field", EXPECTED_LINKER_VERSION, header["linker_version"]),
        check("linker.rich_header_absent", False, linker["rich_header"]["rich_header_present"]),
        check("linker.rich_markers_absent", {"DanS": 0, "Rich": 0}, linker["rich_header"]["marker_hit_count"]),
        check("linker.debug_timestamp_matches_coff", True, linker["debug_entry_timestamp_matches_coff"]),
        check("linker.lld_build_id_absent", False, build_id["lld_build_id_available"]),
        check("linker.no_gnu_build_id_note", False, build_id["gnu_build_id_note_section_present"]),
        check("linker.no_identity_marker_string", False, build_id["identity_marker_found"]),
        check("linker.retplne_tag_count", len(EXPECTED_RETPOLINE_TAG_OFFSETS), linker["retpolne"].get("tag_count")),
        check(
            "linker.retplne_tag_offsets",
            [common.hexs(offset) for offset in EXPECTED_RETPOLINE_TAG_OFFSETS],
            linker["retpolne"].get("tag_offsets_in_section"),
        ),
        check("authen.image_digest", EXPECTED_AUTHENTICODE_IMAGE_SHA256, image["value"]),
        check("authen.embedded_digest_matches", True, certificate.get("embedded_digest_matches_recomputed_image_hash")),
        check("authen.embedded_digest_is_sha256", True, certificate.get("embedded_digest", {}).get("algorithm_is_sha256")),
        check("authen.signing_time", EXPECTED_SIGNING_TIME_UTC, _signing_time_utc(signing)),
        check(
            "authen.signing_time_oid_occurrence",
            EXPECTED_SIGNING_TIME_OID_HITS,
            len(signing.get("oid_offsets", [])),
        ),
        check("authen.chain_verified_by_this_script", False, certificate.get("cryptographically_verified")),
        check("authen.cert_reaches_file_end", True, certificate.get("reaches_file_end")),
        check("version.fixed_info_signature", True, fixed.get("dw_signature_is_feef04bd")),
        check("version.file_version", EXPECTED_FILE_VERSION, version.get("file_version_from_string_table")),
        check("version.product_name", EXPECTED_PRODUCT_NAME, version.get("string_table", {}).get("ProductName")),
        check("version.fixed_and_table_agree", True, version.get("string_file_version_matches_fixed_info")),
        check("fxcomponent.name", EXPECTED_COMPONENT_NAME, fxcomponent.get("component_name")),
        check("fxcomponent.version", EXPECTED_COMPONENT_VERSION, fxcomponent.get("component_version")),
        check("fxcomponent.parsed", True, fxcomponent.get("parsed")),
        check("imports.descriptor_count", EXPECTED_IMPORT_DESCRIPTORS, imports_block["import_descriptor_count"]),
        check("imports.symbol_count", EXPECTED_IMPORT_SYMBOLS, imports_block["import_symbol_count"]),
        check("exports.symbol_count", EXPECTED_EXPORT_SYMBOLS, imports_block["export_symbol_count"]),
        check("exports.name", EXPECTED_EXPORT_NAME, (imports_block["export_symbol_names"] or [None])[0]),
        check("pdata.record_count", EXPECTED_RUNTIME_FUNCTIONS, pdata["record_count"]),
        check("sections.count", EXPECTED_SECTION_COUNT, sections_block["count"]),
        check("buildpath.absolute_count", EXPECTED_BUILD_PATH_ABSOLUTE_COUNT, corpus["absolute_count"]),
        check("buildpath.relative_count", EXPECTED_BUILD_PATH_RELATIVE_COUNT, corpus["relative_count"]),
        check("buildpath.vendor_count", EXPECTED_VENDOR_PATH_COUNT, corpus["vendor_absolute_count"]),
        check("buildpath.first_party_client_source", [EXPECTED_FIRST_PARTY_SOURCE_PATH], corpus["client_source_paths"]),
        check("buildpath.no_server_source_paths", 0, corpus["server_source_count"]),
        check("buildpath.client_or_server", "client", corpus["client_or_server_evidence"]),
        check("workspace.no_adhesive_pdb", False, pdb_inventory["adhesive_pdb_present"]),
        check("workspace.component_list_without_adhesive", False, components.get("contains_adhesive")),
        check("workspace.component_config_has_server_components", True, components.get("server_component_count", 0) > 0),
        check(
            "workspace.no_identity_keyword_reference",
            dict.fromkeys(WORKSPACE_IDENTITY_KEYWORDS, 0),
            report["workspace"]["identity_keyword_totals"],
        ),
        check(
            "workspace.no_build_context_reference",
            dict.fromkeys(WORKSPACE_BUILD_CONTEXT_TERMS, 0),
            report["workspace"]["build_context_totals"],
        ),
        check("workspace.client_modules_partially_present", True, 0 < resolution["present_count"] < resolution["declared_client_module_count"]),
        check("authenticity.no_build_claim", False, report["authenticity"]["authentic_build_asserted"]),
        check("authenticity.build_provenance", "undetermined", report["authenticity"]["build_provenance"]),
        check("open_questions.recorded", True, len(report["open_questions"]) > 0),
        check(
            "keys.correlation_vector_sha256",
            64,
            len(str(report["correlation_keys"].get("correlation_vector_sha256"))),
        ),
    ]
    if cross.get("available"):
        rows.extend(
            check(f"baseline.{row['key']}", row["baseline"], row["correlation"])
            for row in cross["rows"]
        )
    return rows


def _signing_time_utc(signing: Mapping[str, Any]) -> str:
    normalized = signing.get("normalized_utc")
    if not normalized:
        return None
    return normalized.split(" (")[0]







def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description="Static PDB and build correlation evidence for the adhesive.dll specimen"
    )
    parser.add_argument("--out", type=Path, default=root / OUTPUT_RELATIVE)
    parser.add_argument("--verify", action="store_true", help="diff against the stored json")
    parser.add_argument("--max-report", type=int, default=40)
    args = parser.parse_args(argv)

    report, checks = build_report(root)
    out: Path = args.out
    if args.verify:
        stored = json.loads(out.read_text(encoding="utf-8"))
        flat_stored = dict(common.iter_scalar_paths(stored))
        fresh = dict(common.iter_scalar_paths(report))
        diff_checks = [
            common.Check(
                name=key,
                expected=flat_stored.get(key, "<missing>"),
                actual=fresh.get(key, "<missing>"),
                ok=flat_stored.get(key, "<missing>") == fresh.get(key, "<missing>"),
            )
            for key in sorted(set(flat_stored) | set(fresh))
        ]
        diff_failed = common.report_checks(diff_checks, args.max_report)
        print(f"verify    {out.relative_to(root).as_posix()}")
        print(f"diff      {len(diff_checks) - diff_failed}/{len(diff_checks)} scalars identical")
    else:
        common.write_json(out, report)
        print(f"json      {out.relative_to(root).as_posix()}")

    failed = common.report_checks(checks, args.max_report)
    keys = report["correlation_keys"]
    codeview = report["pdb"]["codeview"] or {}
    print(
        f"specimen  {report['specimen']['size']} bytes "
        f"sha256={report['specimen']['sha256']}"
    )
    print(
        f"pdb       debug_id={codeview.get('debug_id')} age={codeview.get('age')} "
        f"path={codeview.get('pdb_path')}"
    )
    print(
        f"linker    field={report['linker']['linker_version_field']} "
        f"rich={report['linker']['rich_header']['rich_header_present']} "
        f"lld_build_id={report['linker']['build_id']['lld_build_id_available']} "
        f"timestamp={report['linker']['pe_timestamp']['utc']}"
    )
    print(
        f"identity  {report['identity_resources']['component_name']}/"
        f"{report['identity_resources']['component_version']} "
        f"pe_version={report['identity_resources']['file_version']} "
        f"product={report['identity_resources']['product_name']}"
    )
    print(
        f"imports   modules={report['imports_exports']['import_descriptor_count']} "
        f"symbols={report['imports_exports']['import_symbol_count']} "
        f"exports={report['imports_exports']['export_symbol_count']} "
        f"client_modules={report['imports_exports']['fivem_client_module_count']}"
    )
    print(
        f"keys      vector={keys['correlation_vector_sha256']} "
        f"image={keys['authenticode_image_sha256']}"
    )
    print(
        f"gate      build_provenance={report['authenticity']['build_provenance']} "
        f"authentic_build_asserted={report['authenticity']['authentic_build_asserted']} "
        f"open_questions={len(report['open_questions'])}"
    )
    print(f"checks    {len(checks) - failed}/{len(checks)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
