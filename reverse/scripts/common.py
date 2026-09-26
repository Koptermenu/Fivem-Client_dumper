"""Deterministic static-PE helper for the adhesive.dll evidence set.

Static file parsing only: nothing in this module loads or executes the specimen.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import importlib.metadata
import json
import platform
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, Iterator, Mapping, Sequence

import pefile

SCHEMA_BASELINE: Final[str] = "adhesive-dumper.baseline/1"
SCHEMA_TOOLCHAIN: Final[str] = "adhesive-dumper.toolchain/1"

HASH_CHUNK_SIZE: Final[int] = 1 << 20
RUNTIME_FUNCTION_SIZE: Final[int] = 12
EXPECTED_RUNTIME_FUNCTIONS: Final[int] = 142_004
EXPECTED_RUNTIME_FUNCTION_SOURCE: Final[str] = "reverse/adhesive-02-pe-layout-security.md#15"

SECURITY_DIRECTORY_INDEX: Final[int] = 4
IAT_DIRECTORY_INDEX: Final[int] = 12
BOUND_IMPORT_DIRECTORY_INDEX: Final[int] = 11
EXCEPTION_DIRECTORY_INDEX: Final[int] = 3
RESOURCE_DIRECTORY_INDEX: Final[int] = 2
RELOC_DIRECTORY_INDEX: Final[int] = 5

PE_MAGICS: Final[Mapping[int, str]] = {0x010B: "PE32", 0x020B: "PE32+"}

DATA_DIRECTORY_NAMES: Final[tuple[str, ...]] = (
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "SECURITY",
    "BASERELOC",
    "DEBUG",
    "COPYRIGHT",
    "GLOBALPTR",
    "TLS",
    "LOAD_CONFIG",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT",
    "COM_DESCRIPTOR",
    "RESERVED",
)

_FILE_CHARACTERISTICS: Final[tuple[tuple[int, str], ...]] = (
    (0x0001, "RELOCS_STRIPPED"),
    (0x0002, "EXECUTABLE_IMAGE"),
    (0x0004, "LINE_NUMS_STRIPPED"),
    (0x0008, "LOCAL_SYMS_STRIPPED"),
    (0x0020, "LARGE_ADDRESS_AWARE"),
    (0x0100, "32BIT_MACHINE"),
    (0x0200, "DEBUG_STRIPPED"),
    (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "NET_RUN_FROM_SWAP"),
    (0x1000, "SYSTEM"),
    (0x2000, "DLL"),
    (0x4000, "UP_SYSTEM_ONLY"),
    (0x8000, "BYTES_REVERSED_LO"),
)

_DLL_CHARACTERISTICS: Final[tuple[tuple[int, str], ...]] = (
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
)

_SECTION_FLAGS: Final[tuple[tuple[int, str], ...]] = (
    (0x00000020, "CNT_CODE"),
    (0x00000040, "CNT_INITIALIZED_DATA"),
    (0x00000080, "CNT_UNINITIALIZED_DATA"),
    (0x00000200, "LNK_INFO"),
    (0x00000800, "LNK_REMOVE"),
    (0x00001000, "LNK_COMDAT"),
    (0x00004000, "NO_DEFER_SPEC_EXC"),
    (0x00008000, "GPREL"),
    (0x01000000, "LNK_NRELOC_OVFL"),
    (0x02000000, "MEM_DISCARDABLE"),
    (0x04000000, "MEM_NOT_CACHED"),
    (0x08000000, "MEM_NOT_PAGED"),
    (0x10000000, "MEM_SHARED"),
    (0x20000000, "MEM_EXECUTE"),
    (0x40000000, "MEM_READ"),
    (0x80000000, "MEM_WRITE"),
)

_UNWIND_FLAGS: Final[tuple[tuple[int, str], ...]] = (
    (0x01, "EHANDLER"),
    (0x02, "UHANDLER"),
    (0x04, "CHAININFO"),
)

_MACHINE_NAMES: Final[Mapping[int, str]] = {
    0x014C: "IMAGE_FILE_MACHINE_I386",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0xAA64: "IMAGE_FILE_MACHINE_ARM64",
}

_SUBSYSTEM_NAMES: Final[Mapping[int, str]] = {
    1: "IMAGE_SUBSYSTEM_NATIVE",
    2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    3: "IMAGE_SUBSYSTEM_WINDOWS_CUI",
    9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
    10: "IMAGE_SUBSYSTEM_EFI_APPLICATION",
    14: "IMAGE_SUBSYSTEM_XBOX",
}

_WIN_CERT_REVISION_NAMES: Final[Mapping[int, str]] = {
    0x0100: "WIN_CERT_REVISION_1_0",
    0x0200: "WIN_CERT_REVISION_2_0",
}

_WIN_CERT_TYPE_NAMES: Final[Mapping[int, str]] = {
    0x0001: "WIN_CERT_TYPE_X509",
    0x0002: "WIN_CERT_TYPE_PKCS_SIGNED_DATA",
    0x0003: "WIN_CERT_TYPE_RESERVED_1",
    0x0004: "WIN_CERT_TYPE_TS_STACK_SIGNED",
}

_RESOURCE_TYPE_NAMES: Final[Mapping[int, str]] = {
    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    17: "RT_DLGINCLUDE",
    19: "RT_PLUGPLAY",
    20: "RT_VXD",
    21: "RT_ANICURSOR",
    22: "RT_ANIICON",
    23: "RT_HTML",
    24: "RT_MANIFEST",
}

_RELOCATION_TYPE_NAMES: Final[Mapping[int, str]] = {
    0: "IMAGE_REL_BASED_ABSOLUTE",
    1: "IMAGE_REL_BASED_HIGH",
    2: "IMAGE_REL_BASED_LOW",
    3: "IMAGE_REL_BASED_HIGHLOW",
    4: "IMAGE_REL_BASED_HIGHADJ",
    10: "IMAGE_REL_BASED_DIR64",
}


def _resource_type_name(type_id: int | None) -> str | None:
    if type_id is None:
        return None
    return _RESOURCE_TYPE_NAMES.get(type_id, "CUSTOM")


@dataclass(frozen=True, slots=True)
class Section:
    """A single PE section as stored in the section table."""

    index: int
    name: str
    virtual_address: int
    virtual_size: int
    raw_pointer: int
    raw_size: int
    characteristics: int

    @property
    def raw_end(self) -> int:
        return self.raw_pointer + self.raw_size

    @property
    def virtual_end(self) -> int:
        return self.virtual_address + self.virtual_size

    def contains_rva_in_raw(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_address + self.raw_size

    def contains_raw(self, raw: int) -> bool:
        return self.raw_pointer <= raw < self.raw_end


@dataclass(frozen=True, slots=True)
class Check:
    """A single baseline verification outcome."""

    name: str
    expected: Any
    actual: Any
    ok: bool

    def as_row(self) -> dict[str, str]:
        return {
            "check": self.name,
            "expected": scalar_text(self.expected),
            "actual": scalar_text(self.actual),
            "ok": "true" if self.ok else "false",
        }


def hexs(value: int) -> str:
    """Uppercase 0x-prefixed hex, matching the format used in the reverse docs."""
    return f"0x{value:X}"


def scalar_text(value: Any) -> str:
    if value is None:
        return "None"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def decode_flags(value: int, table: Sequence[tuple[int, str]]) -> list[str]:
    return [name for mask, name in table if value & mask]


def utc_string(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def file_digests(path: Path) -> dict[str, str]:
    digests = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK_SIZE), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_pe(path: Path) -> pefile.PE:
    """Parse a PE file from disk. The caller owns the result and must close it."""
    return pefile.PE(str(path), fast_load=False)


def sections(pe: pefile.PE) -> tuple[Section, ...]:
    parsed = []
    for index, section in enumerate(pe.sections):
        parsed.append(
            Section(
                index=index,
                name=section.Name.decode("ascii", errors="replace").rstrip("\x00"),
                virtual_address=int(section.VirtualAddress),
                virtual_size=int(section.Misc_VirtualSize),
                raw_pointer=int(section.PointerToRawData),
                raw_size=int(section.SizeOfRawData),
                characteristics=int(section.Characteristics),
            )
        )
    return tuple(parsed)


def section_entropy(pe: pefile.PE, section: Section) -> float:
    """Shannon entropy over SizeOfRawData, including file alignment padding."""
    for candidate in pe.sections:
        if int(candidate.VirtualAddress) == section.virtual_address:
            return round(float(candidate.get_entropy()), 9)
    raise KeyError(section.name)


def section_for_rva(pe: pefile.PE, rva: int) -> Section | None:
    for section in sections(pe):
        if section.contains_rva_in_raw(rva):
            return section
    return None


def section_for_raw(pe: pefile.PE, raw: int) -> Section | None:
    for section in sections(pe):
        if section.contains_raw(raw):
            return section
    return None


def rva_to_raw(pe: pefile.PE, rva: int) -> int | None:
    """Map an RVA to a file offset, or None when the RVA has no bytes in the file.

    Only the SizeOfRawData backed part of a section is addressable in the file; the
    virtual tail behind it is loader supplied zero-fill and maps to nothing.
    """
    if rva < 0:
        return None
    size_of_headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
    if rva < size_of_headers:
        return rva
    for section in sections(pe):
        if section.contains_rva_in_raw(rva):
            return rva - section.virtual_address + section.raw_pointer
    return None


def raw_to_rva(pe: pefile.PE, raw: int) -> int | None:
    """Map a file offset to an RVA, or None when the offset is outside every raw range."""
    if raw < 0:
        return None
    if raw < int(pe.OPTIONAL_HEADER.SizeOfHeaders):
        return raw
    for section in sections(pe):
        if section.contains_raw(raw):
            return raw - section.raw_pointer + section.virtual_address
    return None


def rva_to_va(pe: pefile.PE, rva: int) -> int:
    return int(pe.OPTIONAL_HEADER.ImageBase) + rva


def va_to_rva(pe: pefile.PE, va: int) -> int:
    return va - int(pe.OPTIONAL_HEADER.ImageBase)


def read_rva(pe: pefile.PE, rva: int, length: int) -> bytes:
    return pe.get_data(rva, length)


def data_directories(pe: pefile.PE) -> list[dict[str, Any]]:
    entries = []
    for index, directory in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
        is_file_offset = index == SECURITY_DIRECTORY_INDEX
        address = int(directory.VirtualAddress)
        entries.append(
            {
                "index": index,
                "name": DATA_DIRECTORY_NAMES[index],
                "address_kind": "file_offset" if is_file_offset else "rva",
                "address": address,
                "address_hex": hexs(address),
                "size": int(directory.Size),
                "size_hex": hexs(int(directory.Size)),
                "mapped_raw": None if is_file_offset else rva_to_raw(pe, address),
            }
        )
    return entries


def header_summary(pe: pefile.PE) -> dict[str, Any]:
    file_header = pe.FILE_HEADER
    optional = pe.OPTIONAL_HEADER
    timestamp = int(file_header.TimeDateStamp)
    characteristics = int(file_header.Characteristics)
    dll_characteristics = int(optional.DllCharacteristics)
    entry_rva = int(optional.AddressOfEntryPoint)
    image_base = int(optional.ImageBase)
    checksum = int(optional.CheckSum)
    recomputed = int(pe.generate_checksum())
    coff_raw = int(pe.DOS_HEADER.e_lfanew) + 4
    entry_raw = rva_to_raw(pe, entry_rva)
    return {
        "machine": int(file_header.Machine),
        "machine_name": _MACHINE_NAMES.get(int(file_header.Machine), "UNKNOWN"),
        "number_of_sections": int(file_header.NumberOfSections),
        "size_of_optional_header": int(file_header.SizeOfOptionalHeader),
        "characteristics": characteristics,
        "characteristics_hex": hexs(characteristics),
        "characteristics_flags": decode_flags(characteristics, _FILE_CHARACTERISTICS),
        "is_dll": bool(characteristics & 0x2000),
        "magic": int(optional.Magic),
        "magic_hex": hexs(int(optional.Magic)),
        "magic_name": PE_MAGICS.get(int(optional.Magic), "UNKNOWN"),
        "linker_version": f"{int(optional.MajorLinkerVersion)}.{int(optional.MinorLinkerVersion)}",
        "subsystem": int(optional.Subsystem),
        "subsystem_name": _SUBSYSTEM_NAMES.get(int(optional.Subsystem), "UNKNOWN"),
        "time_date_stamp": timestamp,
        "time_date_stamp_hex": hexs(timestamp),
        "time_date_stamp_utc": utc_string(timestamp),
        "check_sum": checksum,
        "check_sum_hex": hexs(checksum),
        "check_sum_recomputed": recomputed,
        "check_sum_hex_recomputed": hexs(recomputed),
        "check_sum_matches": checksum == recomputed,
        "size_of_code": int(optional.SizeOfCode),
        "size_of_initialized_data": int(optional.SizeOfInitializedData),
        "size_of_uninitialized_data": int(optional.SizeOfUninitializedData),
        "base_of_code": int(optional.BaseOfCode),
        "entry_point_rva": entry_rva,
        "entry_point_rva_hex": hexs(entry_rva),
        "entry_point_va": rva_to_va(pe, entry_rva),
        "entry_point_va_hex": hexs(rva_to_va(pe, entry_rva)),
        "entry_point_raw": entry_raw,
        "entry_point_raw_hex": hexs(entry_raw) if entry_raw is not None else None,
        "image_base": image_base,
        "image_base_hex": hexs(image_base),
        "section_alignment": int(optional.SectionAlignment),
        "file_alignment": int(optional.FileAlignment),
        "size_of_image": int(optional.SizeOfImage),
        "size_of_image_hex": hexs(int(optional.SizeOfImage)),
        "size_of_headers": int(optional.SizeOfHeaders),
        "dll_characteristics": dll_characteristics,
        "dll_characteristics_hex": hexs(dll_characteristics),
        "dll_characteristics_flags": decode_flags(dll_characteristics, _DLL_CHARACTERISTICS),
        "number_of_rva_and_sizes": int(optional.NumberOfRvaAndSizes),
        "pe_signature_raw": hexs(int(pe.DOS_HEADER.e_lfanew)),
        "coff_header_raw": hexs(coff_raw),
        "optional_header_raw": hexs(coff_raw + 20),
        "section_table_raw": hexs(coff_raw + 20 + int(file_header.SizeOfOptionalHeader)),
    }


def section_records(pe: pefile.PE) -> list[dict[str, Any]]:
    section_alignment = int(pe.OPTIONAL_HEADER.SectionAlignment)
    records = []
    for section in sections(pe):
        next_aligned = align_up(section.virtual_end, section_alignment)
        rwx = section.characteristics & 0xE0000000
        records.append(
            {
                "index": section.index,
                "name": section.name,
                "virtual_address": section.virtual_address,
                "virtual_address_hex": hexs(section.virtual_address),
                "virtual_size": section.virtual_size,
                "virtual_size_hex": hexs(section.virtual_size),
                "raw_pointer": section.raw_pointer,
                "raw_pointer_hex": hexs(section.raw_pointer),
                "raw_size": section.raw_size,
                "raw_size_hex": hexs(section.raw_size),
                "raw_end": section.raw_end,
                "raw_end_hex": hexs(section.raw_end),
                "raw_rva_delta": section.raw_pointer - section.virtual_address,
                "virtual_end": section.virtual_end,
                "virtual_end_hex": hexs(section.virtual_end),
                "next_aligned_rva": next_aligned,
                "next_aligned_rva_hex": hexs(next_aligned),
                "virtual_tail": next_aligned - section.virtual_end,
                "characteristics": section.characteristics,
                "characteristics_hex": hexs(section.characteristics),
                "characteristics_flags": decode_flags(section.characteristics, _SECTION_FLAGS),
                "is_executable": bool(section.characteristics & 0x20000000),
                "is_readable": bool(section.characteristics & 0x40000000),
                "is_writable": bool(section.characteristics & 0x80000000),
                "is_rwx": rwx == 0xE0000000,
                "entropy": section_entropy(pe, section),
            }
        )
    return records


def pdata_summary(pe: pefile.PE) -> dict[str, Any]:
    """Parse the x64 exception directory into IMAGE_RUNTIME_FUNCTION records."""
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[EXCEPTION_DIRECTORY_INDEX]
    rva = int(directory.VirtualAddress)
    size = int(directory.Size)
    raw = rva_to_raw(pe, rva)
    blob = read_rva(pe, rva, size) if rva and size else b""
    count, remainder = divmod(size, RUNTIME_FUNCTION_SIZE)
    records = list(struct.iter_unpack("<III", blob))
    begins = [record[0] for record in records]
    ends = [record[1] for record in records]
    unwinds = [record[2] for record in records]
    sorted_by_begin = all(begins[index] <= begins[index + 1] for index in range(len(begins) - 1))
    duplicates = len(begins) - len(set(begins))
    overlaps = sum(1 for index in range(len(records) - 1) if ends[index] > begins[index + 1])
    unwind_stats = _unwind_stats(pe, unwinds)
    return {
        "rva": rva,
        "rva_hex": hexs(rva),
        "raw": raw,
        "raw_hex": hexs(raw) if raw is not None else None,
        "size": size,
        "size_hex": hexs(size),
        "record_size": RUNTIME_FUNCTION_SIZE,
        "record_count": count,
        "record_count_hex": hexs(count),
        "record_remainder": remainder,
        "expected_record_count": EXPECTED_RUNTIME_FUNCTIONS,
        "record_count_matches_expected": count == EXPECTED_RUNTIME_FUNCTIONS,
        "sorted_by_begin_address": sorted_by_begin,
        "duplicate_records": duplicates,
        "overlapping_records": overlaps,
        "begin_address_min": min(begins) if begins else None,
        "begin_address_min_hex": hexs(min(begins)) if begins else None,
        "end_address_max": max(ends) if ends else None,
        "end_address_max_hex": hexs(max(ends)) if ends else None,
        "unwind_info_address_null": sum(1 for unwind in unwinds if unwind == 0),
        "unique_unwind_infos": unwind_stats["unique_count"],
        "unwind_info_rva_min": unwind_stats["rva_min"],
        "unwind_info_rva_min_hex": hexs(unwind_stats["rva_min"]) if unwind_stats["rva_min"] else None,
        "unwind_info_rva_max": unwind_stats["rva_max"],
        "unwind_info_rva_max_hex": hexs(unwind_stats["rva_max"]) if unwind_stats["rva_max"] else None,
        "unwind_info_sections": unwind_stats["sections"],
        "unwind_flag_value_distribution": unwind_stats["flags_per_record"],
        "unwind_flag_distribution_per_unique_info": unwind_stats["flags_per_unique"],
        "unwind_version_invalid_records": unwind_stats["version_invalid"],
        "unwind_records_out_of_image": unwind_stats["unmapped"],
        "first_records": [
            _runtime_function_record(index, records[index]) for index in range(min(3, len(records)))
        ],
        "last_records": [
            _runtime_function_record(len(records) - 1 - offset, records[len(records) - 1 - offset])
            for offset in range(min(3, len(records)))
        ],
    }


def _runtime_function_record(index: int, record: tuple[int, int, int]) -> dict[str, Any]:
    return {
        "index": index,
        "begin_address": record[0],
        "begin_address_hex": hexs(record[0]),
        "end_address": record[1],
        "end_address_hex": hexs(record[1]),
        "unwind_info_address": record[2],
        "unwind_info_address_hex": hexs(record[2]),
    }


def _unwind_stats(pe: pefile.PE, unwind_rvas: Sequence[int]) -> dict[str, Any]:
    unique = sorted({rva for rva in unwind_rvas if rva})
    flags_per_unique: dict[str, int] = {name: 0 for _, name in _UNWIND_FLAGS}
    sections_seen: dict[str, int] = {}
    flags_per_record: dict[int, int] = {}
    flag_value_per_rva: dict[int, int] = {}
    version_invalid_per_rva: dict[int, int] = {}
    unmapped = 0
    for rva in unique:
        section = section_for_rva(pe, rva)
        if section is None:
            unmapped += 1
            continue
        sections_seen[section.name] = sections_seen.get(section.name, 0) + 1
        header = read_rva(pe, rva, 1)[0]
        version = header & 0x07
        flags = (header & 0xF8) >> 3
        flag_value_per_rva[rva] = flags
        version_invalid_per_rva[rva] = 0 if version == 1 else 1
        for name in decode_flags(flags, _UNWIND_FLAGS):
            flags_per_unique[name] += 1
    version_invalid = 0
    for rva in unwind_rvas:
        flags = flag_value_per_rva.get(rva, 0) if rva else 0
        flags_per_record[flags] = flags_per_record.get(flags, 0) + 1
        version_invalid += version_invalid_per_rva.get(rva, 0) if rva else 0
    return {
        "unique_count": len(unique),
        "rva_min": unique[0] if unique else None,
        "rva_max": unique[-1] if unique else None,
        "sections": {name: sections_seen[name] for name in sorted(sections_seen)},
        "flags_per_unique": flags_per_unique,
        "flags_per_record": {str(value): flags_per_record[value] for value in sorted(flags_per_record)},
        "version_invalid": version_invalid,
        "unmapped": unmapped,
    }


def overlay_summary(pe: pefile.PE, file_size: int) -> dict[str, Any]:
    section_ends = [section.raw_end for section in sections(pe) if section.raw_size]
    last_section_end = max(section_ends) if section_ends else int(pe.OPTIONAL_HEADER.SizeOfHeaders)
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[SECURITY_DIRECTORY_INDEX]
    security_offset = int(security.VirtualAddress)
    security_size = int(security.Size)
    detected = pe.get_overlay_data_start_offset()
    overlay_offset = last_section_end if detected is None else int(detected)
    overlay_size = max(0, file_size - overlay_offset)
    return {
        "file_size": file_size,
        "file_size_hex": hexs(file_size),
        "size_of_headers": int(pe.OPTIONAL_HEADER.SizeOfHeaders),
        "last_section_raw_end": last_section_end,
        "last_section_raw_end_hex": hexs(last_section_end),
        "overlay_offset": overlay_offset,
        "overlay_offset_hex": hexs(overlay_offset),
        "overlay_size": overlay_size,
        "overlay_size_hex": hexs(overlay_size),
        "overlay_end": overlay_offset + overlay_size,
        "overlay_end_hex": hexs(overlay_offset + overlay_size),
        "security_directory_file_offset": security_offset,
        "security_directory_file_offset_hex": hexs(security_offset),
        "security_directory_size": security_size,
        "security_directory_size_hex": hexs(security_size),
        "overlay_equals_security_directory": overlay_offset == security_offset
        and overlay_size == security_size,
        "unclaimed_trailing_bytes": max(0, file_size - max(overlay_offset, security_offset + security_size)),
    }


def certificate_summary(path: Path, file_size: int) -> dict[str, Any]:
    pe = load_pe(path)
    try:
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[SECURITY_DIRECTORY_INDEX]
        offset = int(directory.VirtualAddress)
        size = int(directory.Size)
        if offset == 0 or size == 0:
            return {
                "present": False,
                "file_offset": offset,
                "file_offset_hex": hexs(offset),
                "size": size,
                "sha256": None,
            }
        with path.open("rb") as handle:
            handle.seek(offset)
            blob = handle.read(size)
    finally:
        pe.close()
    dw_length, w_revision, w_certificate_type = struct.unpack_from("<IHH", blob, 0)
    payload = blob[8:dw_length] if dw_length >= 8 else b""
    return {
        "present": True,
        "file_offset": offset,
        "file_offset_hex": hexs(offset),
        "size": size,
        "size_hex": hexs(size),
        "end_offset": offset + size,
        "end_offset_hex": hexs(offset + size),
        "reaches_file_end": offset + size == file_size,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "sha1": hashlib.sha1(blob).hexdigest(),
        "md5": hashlib.md5(blob).hexdigest(),
        "win_certificate": {
            "dw_length": dw_length,
            "dw_length_hex": hexs(dw_length),
            "w_revision": w_revision,
            "w_revision_hex": hexs(w_revision),
            "w_revision_name": _WIN_CERT_REVISION_NAMES.get(w_revision, "UNKNOWN"),
            "w_certificate_type": w_certificate_type,
            "w_certificate_type_hex": hexs(w_certificate_type),
            "w_certificate_type_name": _WIN_CERT_TYPE_NAMES.get(w_certificate_type, "UNKNOWN"),
            "b_certificate_size": len(payload),
        },
        "pkcs7_sha256": hashlib.sha256(payload).hexdigest(),
    }


def import_summary(pe: pefile.PE) -> dict[str, Any]:
    modules = []
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        ordinals = [entry for entry in descriptor.imports if entry.import_by_ordinal]
        names = [entry for entry in descriptor.imports if not entry.import_by_ordinal]
        modules.append(
            {
                "dll": descriptor.dll.decode("ascii", errors="replace"),
                "symbol_count": len(descriptor.imports),
                "name_imports": len(names),
                "ordinal_imports": len(ordinals),
                "ordinals": sorted(int(entry.ordinal) for entry in ordinals),
                "ordinal_names": sorted(
                    entry.name.decode("ascii", errors="replace") if entry.name else None
                    for entry in ordinals
                ),
                "original_first_thunk_rva": int(descriptor.struct.OriginalFirstThunk),
                "first_thunk_rva": int(descriptor.struct.FirstThunk),
                "name_rva": int(descriptor.struct.Name),
                "time_date_stamp": int(descriptor.struct.TimeDateStamp),
                "forwarder_chain": int(descriptor.struct.ForwarderChain),
            }
        )
    delay_modules = []
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
        symbols = sorted(
            entry.name.decode("ascii", errors="replace") if entry.name else f"ordinal_{entry.ordinal}"
            for entry in descriptor.imports
        )
        delay_modules.append(
            {
                "dll": descriptor.dll.decode("ascii", errors="replace"),
                "symbol_count": len(descriptor.imports),
                "name_rva": int(descriptor.struct.szName),
                "module_handle_rva": int(descriptor.struct.phmod),
                "iat_rva": int(descriptor.struct.pIAT),
                "int_rva": int(descriptor.struct.pINT),
                "bound_iat_rva": int(descriptor.struct.pBoundIAT),
                "unload_iat_rva": int(descriptor.struct.pUnloadIAT),
                "attributes": int(descriptor.struct.grAttrs),
                "time_date_stamp": int(descriptor.struct.dwTimeStamp),
                "symbols": symbols,
            }
        )
    iat_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[IAT_DIRECTORY_INDEX]
    delay_symbols = sum(module["symbol_count"] for module in delay_modules)
    return {
        "descriptor_count": len(modules),
        "symbol_count": sum(module["symbol_count"] for module in modules),
        "name_imports": sum(module["name_imports"] for module in modules),
        "ordinal_imports": sum(module["ordinal_imports"] for module in modules),
        "iat_rva": int(iat_directory.VirtualAddress),
        "iat_rva_hex": hexs(int(iat_directory.VirtualAddress)),
        "iat_size": int(iat_directory.Size),
        "iat_raw": rva_to_raw(pe, int(iat_directory.VirtualAddress)),
        "bound_import_size": int(
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[BOUND_IMPORT_DIRECTORY_INDEX].Size
        ),
        "delay_descriptor_count": len(delay_modules),
        "delay_symbol_count": delay_symbols,
        "total_module_count": len(modules) + len(delay_modules),
        "total_symbol_count": sum(module["symbol_count"] for module in modules) + delay_symbols,
        "modules": modules,
        "delay_modules": delay_modules,
    }


def export_summary(pe: pefile.PE) -> dict[str, Any]:
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if directory is None:
        return {"present": False, "symbol_count": 0, "forwarder_count": 0, "symbols": []}
    symbols = []
    for entry in directory.symbols:
        address = int(entry.address)
        symbols.append(
            {
                "ordinal": int(entry.ordinal),
                "name": entry.name.decode("ascii", errors="replace") if entry.name else None,
                "rva": address,
                "rva_hex": hexs(address),
                "va": rva_to_va(pe, address),
                "raw": rva_to_raw(pe, address),
                "forwarder": entry.forwarder.decode("ascii", errors="replace")
                if entry.forwarder
                else None,
            }
        )
    export_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
    return {
        "present": True,
        "rva": int(export_directory.VirtualAddress),
        "rva_hex": hexs(int(export_directory.VirtualAddress)),
        "size": int(export_directory.Size),
        "raw": rva_to_raw(pe, int(export_directory.VirtualAddress)),
        "module_name": directory.name.decode("ascii", errors="replace") if directory.name else None,
        "characteristics": int(directory.struct.Characteristics),
        "time_date_stamp": int(directory.struct.TimeDateStamp),
        "base": int(directory.struct.Base),
        "number_of_functions": int(directory.struct.NumberOfFunctions),
        "number_of_names": int(directory.struct.NumberOfNames),
        "symbol_count": len(symbols),
        "forwarder_count": sum(1 for symbol in symbols if symbol["forwarder"]),
        "symbols": symbols,
    }


def resource_summary(pe: pefile.PE) -> dict[str, Any]:
    leaves = []
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is not None:
        for type_entry in root.entries:
            type_id = int(type_entry.id) if type_entry.id is not None else None
            type_name = str(type_entry.name) if type_entry.name is not None else None
            for name_entry in type_entry.directory.entries:
                name_id = int(name_entry.id) if name_entry.id is not None else None
                name_label = str(name_entry.name) if name_entry.name is not None else None
                for lang_entry in name_entry.directory.entries:
                    payload_entry = lang_entry.data.struct
                    rva = int(payload_entry.OffsetToData)
                    size = int(payload_entry.Size)
                    leaves.append(
                        {
                            "type_id": type_id,
                            "type_name": _resource_type_name(type_id),
                            "type_identifier": type_name,
                            "name_id": name_id,
                            "name": name_label,
                            "lang_id": int(lang_entry.id) if lang_entry.id is not None else None,
                            "rva": rva,
                            "rva_hex": hexs(rva),
                            "raw": rva_to_raw(pe, rva),
                            "size": size,
                            "code_page": int(payload_entry.CodePage),
                            "reserved": int(payload_entry.Reserved),
                            "sha256": hashlib.sha256(read_rva(pe, rva, size)).hexdigest(),
                        }
                    )
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[RESOURCE_DIRECTORY_INDEX]
    return {
        "present": root is not None,
        "rva": int(directory.VirtualAddress),
        "rva_hex": hexs(int(directory.VirtualAddress)),
        "raw": rva_to_raw(pe, int(directory.VirtualAddress)),
        "size": int(directory.Size),
        "entry_count": len(leaves),
        "total_payload_bytes": sum(leaf["size"] for leaf in leaves),
        "language_ids": sorted(
            {leaf["lang_id"] for leaf in leaves if leaf["lang_id"] is not None}
        ),
        "entries": leaves,
    }


def relocation_summary(pe: pefile.PE) -> dict[str, Any]:
    blocks = list(getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []))
    all_sections = sections(pe)
    size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)
    by_type: dict[int, int] = {}
    by_section: dict[str, int] = {}
    total = 0
    out_of_image = 0
    block_sizes: list[int] = []
    for block in blocks:
        block_sizes.append(int(block.struct.SizeOfBlock))
        for entry in block.entries:
            total += 1
            relocation_type = int(entry.type)
            by_type[relocation_type] = by_type.get(relocation_type, 0) + 1
            target = int(entry.rva)
            if target >= size_of_image:
                out_of_image += 1
                continue
            owner = next(
                (
                    section.name
                    for section in all_sections
                    if section.virtual_address <= target < section.virtual_end
                ),
                None,
            )
            label = owner if owner is not None else "UNMAPPED"
            by_section[label] = by_section.get(label, 0) + 1
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[RELOC_DIRECTORY_INDEX]
    sorted_types = sorted(by_type.items())
    return {
        "rva": int(directory.VirtualAddress),
        "rva_hex": hexs(int(directory.VirtualAddress)),
        "raw": rva_to_raw(pe, int(directory.VirtualAddress)),
        "size": int(directory.Size),
        "block_count": len(blocks),
        "entry_count": total,
        "types": {str(mask): count for mask, count in sorted_types},
        "types_named": {
            _RELOCATION_TYPE_NAMES.get(mask, f"IMAGE_REL_BASED_UNKNOWN_{mask}"): count
            for mask, count in sorted_types
        },
        "targets_by_section": {name: by_section[name] for name in sorted(by_section)},
        "targets_outside_size_of_image": out_of_image,
        "block_size_min": min(block_sizes) if block_sizes else None,
        "block_size_max": max(block_sizes) if block_sizes else None,
        "first_block": _relocation_block(blocks[0]) if blocks else None,
        "last_block": _relocation_block(blocks[-1]) if blocks else None,
    }


def _relocation_block(block: Any) -> dict[str, Any]:
    page_rva = int(block.struct.VirtualAddress)
    return {
        "page_rva": page_rva,
        "page_rva_hex": hexs(page_rva),
        "size_of_block": int(block.struct.SizeOfBlock),
        "entry_count": len(block.entries),
    }


def build_baseline(specimen: Path, relative_path: str) -> dict[str, Any]:
    file_size = specimen.stat().st_size
    digests = file_digests(specimen)
    pe = load_pe(specimen)
    try:
        return {
            "schema": SCHEMA_BASELINE,
            "specimen": {
                "path": relative_path,
                "name": specimen.name,
                "size": file_size,
                "size_hex": hexs(file_size),
                "sha256": digests["sha256"],
                "sha1": digests["sha1"],
                "md5": digests["md5"],
                "dll": {"name": specimen.name, "sha256": digests["sha256"], "size": file_size},
            },
            "pe": header_summary(pe),
            "sections": section_records(pe),
            "data_directories": data_directories(pe),
            "pdata": pdata_summary(pe),
            "overlay": overlay_summary(pe, file_size),
            "certificate": certificate_summary(specimen, file_size),
            "imports": import_summary(pe),
            "exports": export_summary(pe),
            "resources": resource_summary(pe),
            "relocations": relocation_summary(pe),
            "expected": {
                "runtime_function_count": EXPECTED_RUNTIME_FUNCTIONS,
                "runtime_function_record_size": RUNTIME_FUNCTION_SIZE,
                "source": EXPECTED_RUNTIME_FUNCTION_SOURCE,
            },
        }
    finally:
        pe.close()


def library_version(distribution: str, module_name: str) -> dict[str, Any]:
    try:
        distribution_version: str | None = importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        distribution_version = None
    module_version: str | None = None
    module_path: str | None = None
    engine_version: list[int] | None = None
    try:
        module = importlib.import_module(module_name)
    except ImportError:
        module = None
    if module is not None:
        module_version = getattr(module, "__version__", None)
        module_path = getattr(module, "__file__", None)
        if distribution == "capstone" and hasattr(module, "cs_version"):
            engine_version = [int(part) for part in module.cs_version()]
    return {
        "distribution": distribution,
        "distribution_version": distribution_version,
        "module_version": module_version,
        "module_path": module_path,
        "engine_version": engine_version,
    }


def objdump_version() -> dict[str, Any]:
    executable = shutil.which("objdump")
    if executable is None:
        return {"available": False, "path": None, "banner": None, "version": None}
    completed = subprocess.run(
        [executable, "--version"],
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
        errors="replace",
    )
    banner = (completed.stdout or "").splitlines()[0].strip() if completed.stdout else ""
    return {
        "available": True,
        "path": executable,
        "banner": banner,
        "version": banner.rsplit(" ", 1)[-1] if banner else None,
    }


def host_summary() -> dict[str, Any]:
    windows = None
    getter = getattr(sys, "getwindowsversion", None)
    if getter is not None:
        version = getter()
        windows = {
            "major": version.major,
            "minor": version.minor,
            "build": version.build,
            "platform": version.platform,
            "service_pack": version.service_pack,
            "version": f"{version.major}.{version.minor}.{version.build}",
        }
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "platform": platform.platform(),
        "windows": windows,
    }


def python_summary() -> dict[str, Any]:
    return {
        "version": platform.python_version(),
        "version_full": sys.version.replace("\n", " "),
        "implementation": platform.python_implementation(),
        "compiler": platform.python_compiler(),
        "api_version": sys.api_version,
        "default_encoding": sys.getdefaultencoding(),
        "utf8_mode": bool(sys.flags.utf8_mode),
    }


def script_records(scripts_dir: Path, root: Path) -> list[dict[str, Any]]:
    records = []
    for script in sorted(scripts_dir.glob("*.py"), key=lambda item: item.name):
        data = script.read_bytes()
        records.append(
            {
                "path": script.relative_to(root).as_posix(),
                "name": script.name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "utf8_bom": data.startswith(b"\xef\xbb\xbf"),
                "crlf_line_count": data.count(b"\r\n"),
                "lf_line_count": data.count(b"\n"),
            }
        )
    return records


def build_toolchain(root: Path, specimen: Path, relative_specimen: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA_TOOLCHAIN,
        "determinism": {
            "json_indent": 2,
            "json_ensure_ascii": False,
            "json_sort_keys": False,
            "text_encoding": "utf-8",
            "bom": False,
            "line_terminator": "\\n",
            "trailing_newline": True,
            "payload_timestamps": False,
        },
        "host": host_summary(),
        "python": python_summary(),
        "libraries": {
            "pefile": library_version("pefile", "pefile"),
            "lief": library_version("lief", "lief"),
            "capstone": library_version("capstone", "capstone"),
        },
        "binutils": {"objdump": objdump_version()},
        "specimen": {
            "path": relative_specimen,
            "sha256": sha256_file(specimen),
            "size": specimen.stat().st_size,
        },
        "scripts": script_records(root / "reverse" / "scripts", root),
    }


def write_json(path: Path, payload: Mapping[str, Any]) -> Path:
    """Write UTF-8 JSON without BOM, LF terminated, with a trailing newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False, allow_nan=False) + "\n"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str]) -> Path:
    """Write UTF-8 CSV without BOM, LF terminated, with a fixed column order."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(fieldnames),
            lineterminator="\n",
            extrasaction="raise",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({name: scalar_text(row.get(name)) for name in fieldnames})
    return path


def iter_scalar_paths(payload: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(payload, Mapping):
        for key in payload:
            yield from iter_scalar_paths(payload[key], f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            yield from iter_scalar_paths(item, f"{prefix}[{index}]")
    else:
        yield prefix, payload


def verify_baseline(specimen: Path, baseline: Mapping[str, Any], relative_path: str) -> list[Check]:
    """Recompute the baseline from the specimen and diff it against the stored payload."""
    stored = dict(iter_scalar_paths(baseline))
    fresh = dict(iter_scalar_paths(build_baseline(specimen, relative_path)))
    checks = [
        Check(
            name=key,
            expected=stored.get(key, "<missing>"),
            actual=fresh.get(key, "<missing>"),
            ok=stored.get(key, "<missing>") == fresh.get(key, "<missing>"),
        )
        for key in sorted(set(stored) | set(fresh))
    ]
    pdata = baseline.get("pdata", {})
    overlay = baseline.get("overlay", {})
    certificate = baseline.get("certificate", {})
    expected = baseline.get("expected", {})
    invariants: tuple[tuple[str, Any, Any], ...] = (
        (
            "invariant.runtime_function_count_equals_expected",
            EXPECTED_RUNTIME_FUNCTIONS,
            pdata.get("record_count"),
        ),
        (
            "invariant.expected_block_matches_observed_count",
            expected.get("runtime_function_count"),
            pdata.get("record_count"),
        ),
        (
            "invariant.overlay_equals_security_directory",
            True,
            overlay.get("overlay_equals_security_directory"),
        ),
        ("invariant.no_unclaimed_trailing_bytes", 0, overlay.get("unclaimed_trailing_bytes")),
        ("invariant.certificate_reaches_file_end", True, certificate.get("reaches_file_end")),
    )
    checks.extend(
        Check(name=name, expected=want, actual=got, ok=want == got) for name, want, got in invariants
    )
    return checks


def report_checks(checks: Sequence[Check], limit: int) -> int:
    failed = [check for check in checks if not check.ok]
    for check in failed[:limit]:
        print(
            f"FAIL {check.name}: expected={scalar_text(check.expected)} "
            f"actual={scalar_text(check.actual)}"
        )
    if len(failed) > limit:
        print(f"FAIL ... {len(failed) - limit} further mismatches")
    return len(failed)


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve()
    root = script.parent.parent.parent
    parser = argparse.ArgumentParser(
        description="Static PE helper and baseline verifier for the adhesive.dll specimen"
    )
    parser.add_argument("--specimen", type=Path, default=root / "reverse" / "adhesive.dll")
    parser.add_argument(
        "--baseline", type=Path, default=root / "reverse" / "evidence" / "baseline.json"
    )
    parser.add_argument(
        "--toolchain", type=Path, default=root / "reverse" / "evidence" / "toolchain.json"
    )
    parser.add_argument("--emit-baseline", action="store_true", help="write the baseline json")
    parser.add_argument("--emit-toolchain", action="store_true", help="write the toolchain json")
    parser.add_argument(
        "--checks-csv", type=Path, default=None, help="write the verification rows as csv"
    )
    parser.add_argument("--max-report", type=int, default=40, help="mismatches to print")
    args = parser.parse_args(argv)

    specimen = args.specimen.resolve()
    relative_specimen = specimen.relative_to(root).as_posix()
    print(f"script    {script.relative_to(root).as_posix()}")
    print(f"sha256    {sha256_file(script)}")
    print(f"specimen  {relative_specimen} size={specimen.stat().st_size} sha256={sha256_file(specimen)}")

    if args.emit_baseline:
        write_json(args.baseline, build_baseline(specimen, relative_specimen))
        print(f"baseline  {args.baseline.relative_to(root).as_posix()}")

    if args.emit_toolchain:
        write_json(args.toolchain, build_toolchain(root, specimen, relative_specimen))
        print(f"toolchain {args.toolchain.relative_to(root).as_posix()}")

    if args.emit_baseline or args.emit_toolchain:
        return 0

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    checks = verify_baseline(specimen, baseline, relative_specimen)
    if args.checks_csv is not None:
        write_csv(args.checks_csv, [check.as_row() for check in checks], ("check", "expected", "actual", "ok"))
        print(f"checks    {args.checks_csv}")
    failed = report_checks(checks, args.max_report)
    pdata = baseline.get("pdata", {})
    print(f"checks    {len(checks) - failed}/{len(checks)} matched")
    print(
        f"pdata     rva={pdata.get('rva_hex')} size={pdata.get('size_hex')} "
        f"records={pdata.get('record_count')}"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
