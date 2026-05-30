"""PE binary parser with Shannon entropy analysis and security mitigations detection."""

import hashlib
import math
import re
from pathlib import Path

import numpy as np
import pefile

from .config import ENTROPY_THRESHOLD, MIN_BLOB_SIZE
from .models import SectionInfo


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence using numpy for speed.

    Returns a value between 0.0 (completely uniform) and 8.0 (maximally random).
    """
    if not data:
        return 0.0

    byte_array = np.frombuffer(data, dtype=np.uint8)
    byte_counts = np.bincount(byte_array, minlength=256)
    total = len(data)

    probabilities = byte_counts[byte_counts > 0] / total
    entropy = float(-np.sum(probabilities * np.log2(probabilities)))
    return max(entropy, 0.0)


def extract_raw_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Extract raw ASCII and UTF-16LE strings from byte data."""
    if not data:
        return []

    strings = []
    # ASCII strings
    ascii_re = re.compile(b'[ -~]{' + str(min_len).encode() + b',}')
    for match in ascii_re.finditer(data):
        strings.append(match.group().decode('ascii', errors='ignore'))

    # UTF-16LE strings
    utf16_re = re.compile(b'(?:[ -~]\\x00){' + str(min_len).encode() + b',}')
    for match in utf16_re.finditer(data):
        try:
            strings.append(match.group().decode('utf-16le', errors='ignore'))
        except Exception:
            pass

    return list(set(strings))


def parse_pe_binary(file_path: str | Path) -> dict:
    """Parse a PE binary and return structured analysis results.

    Returns a dict with metadata, sections, security mitigations, and raw strings.
    """
    file_path = Path(file_path)

    result = {
        "filename": file_path.name,
        "file_hash_md5": "",
        "file_hash_sha256": "",
        "file_size": 0,
        "sections": [],
        "suspicious_sections": [],
        "aslr": False,
        "dep": False,
        "cfg": False,
        "safeseh": False,
        "authenticode": False,
        "embedded_pes": [],
        "raw_strings": [],
        "imports": [],
        "dangerous_imports": [],
        "error": None,
    }

    if not file_path.exists():
        result["error"] = f"File not found: {file_path}"
        return result

    try:
        raw_file = file_path.read_bytes()
    except OSError as exc:
        result["error"] = f"Cannot read file: {exc}"
        return result

    if not raw_file:
        result["error"] = "File is empty (0 bytes)"
        return result

    result["file_size"] = len(raw_file)
    result["file_hash_md5"] = hashlib.md5(raw_file).hexdigest()
    result["file_hash_sha256"] = hashlib.sha256(raw_file).hexdigest()

    # Extract raw strings from file data
    result["raw_strings"] = extract_raw_strings(raw_file)

    try:
        pe = pefile.PE(data=raw_file, fast_load=False)
    except pefile.PEFormatError as exc:
        result["error"] = f"Invalid PE format: {exc}"
        return result
    except Exception as exc:
        result["error"] = f"PE parsing failed: {exc}"
        return result

    try:
        # Check standard security characteristics
        dll_char = getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0)
        result["aslr"] = bool(dll_char & 0x0040)       # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        result["dep"] = bool(dll_char & 0x0100)        # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        result["cfg"] = bool(dll_char & 0x4000)        # IMAGE_DLLCHARACTERISTICS_GUARD_CF
        
        # Check SafeSEH
        no_seh = bool(dll_char & 0x0400)               # IMAGE_DLLCHARACTERISTICS_NO_SEH
        has_safeseh = False
        if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
            try:
                load_config = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
                if pe.PE_TYPE == pefile.OPT_HEADER_MAGIC_PE32PLUS:
                    has_safeseh = True  # x64 natively handles exceptions safely
                else:
                    has_safeseh = getattr(load_config, 'SEHandlerCount', 0) > 0
            except Exception:
                pass
        result["safeseh"] = no_seh or has_safeseh

        # Check Authenticode (Digital Signature Presence)
        has_signature = False
        try:
            sec_dir_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
            if security_dir.VirtualAddress > 0 and security_dir.Size > 0:
                has_signature = True
        except Exception:
            pass
        result["authenticode"] = has_signature

        # Extract Imports & Flag Dangerous ones
        dangerous_apis = {
            "CreateRemoteThread", "NtCreateThreadEx", "VirtualAllocEx", 
            "NtAllocateVirtualMemory", "WriteProcessMemory", "URLDownloadToFile", 
            "WinHttpOpen", "InternetOpenUrl", "ShellExecute", "WinExec", 
            "CreateProcess", "GetProcAddress", "LoadLibrary", "NtUnmapViewOfSection", 
            "ZwUnmapViewOfSection", "AdjustTokenPrivileges", "LookupPrivilegeValue"
        }
        
        imports = []
        dangerous_imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='replace')
                        imports.append(func_name)
                        if func_name in dangerous_apis:
                            dangerous_imports.append(func_name)
        result["imports"] = imports
        result["dangerous_imports"] = list(set(dangerous_imports))

        # Parse Sections, Entropy, & Search for Embedded PE
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            raw_data = section.get_data()
            entropy = calculate_shannon_entropy(raw_data)
            is_suspicious = entropy > ENTROPY_THRESHOLD

            sec_info = SectionInfo(
                name=name,
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                entropy=round(entropy, 4),
                is_suspicious=is_suspicious,
                raw_data=raw_data,
            )

            result["sections"].append(sec_info)
            if is_suspicious:
                result["suspicious_sections"].append(sec_info)

            # Embedded PE Signature Detection in sections
            idx = 0
            while True:
                idx = raw_data.find(b"MZ", idx)
                if idx == -1:
                    break
                if idx + 0x3C + 4 <= len(raw_data):
                    pe_offset = int.from_bytes(raw_data[idx+0x3c : idx+0x40], 'little')
                    if idx + pe_offset + 4 <= len(raw_data):
                        if raw_data[idx+pe_offset : idx+pe_offset+4] == b"PE\x00\x00":
                            result["embedded_pes"].append({
                                "section": name,
                                "offset": idx,
                                "size": len(raw_data) - idx
                            })
                idx += 2

    except Exception as exc:
        result["error"] = f"Section parsing failed: {exc}"
    finally:
        pe.close()

    return result


def extract_high_entropy_blobs(
    section_data: bytes,
    block_size: int = 256,
) -> list[tuple[int, bytes, float]]:
    """Slide a window over section data to find high-entropy sub-regions."""
    if not section_data or len(section_data) < MIN_BLOB_SIZE:
        return []

    effective_block = min(block_size, len(section_data))
    step = max(1, effective_block // 2)

    high_offsets: list[tuple[int, int, float]] = []

    for start in range(0, len(section_data) - effective_block + 1, step):
        block = section_data[start : start + effective_block]
        entropy = calculate_shannon_entropy(block)

        if entropy > ENTROPY_THRESHOLD:
            high_offsets.append((start, start + effective_block, entropy))

    if not high_offsets:
        return []

    merged: list[tuple[int, int, float]] = []
    cur_start, cur_end, cur_max_ent = high_offsets[0]

    for start, end, ent in high_offsets[1:]:
        if start <= cur_end:
            cur_end = max(cur_end, end)
            cur_max_ent = max(cur_max_ent, ent)
        else:
            merged.append((cur_start, cur_end, cur_max_ent))
            cur_start, cur_end, cur_max_ent = start, end, ent

    merged.append((cur_start, cur_end, cur_max_ent))

    blobs: list[tuple[int, bytes, float]] = []
    for start, end, _ in merged:
        blob_data = section_data[start:end]
        if len(blob_data) < MIN_BLOB_SIZE:
            continue
        blob_entropy = calculate_shannon_entropy(blob_data)
        if blob_entropy > ENTROPY_THRESHOLD:
            blobs.append((start, blob_data, round(blob_entropy, 4)))

    return blobs
