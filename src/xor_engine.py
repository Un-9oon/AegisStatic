"""XOR brute-force decryption engine for high-entropy PE blobs."""

import string
from concurrent.futures import ThreadPoolExecutor

import numpy as np

from .config import HIGH_VALUE_KEYWORDS, PRINTABLE_THRESHOLD, TWO_BYTE_KEYS

PRINTABLE_BYTES = set(string.printable.encode("ascii"))


def xor_decrypt(data: bytes, key: int) -> bytes:
    """XOR each byte of data with a single or double-byte key using numpy."""
    if not data:
        return b""
    arr = np.frombuffer(data, dtype=np.uint8)
    if key <= 0xFF:
        decrypted = np.bitwise_xor(arr, np.uint8(key))
    else:
        k1 = (key >> 8) & 0xFF
        k2 = key & 0xFF
        key_bytes = np.array([k1, k2], dtype=np.uint8)
        tiled_key = np.tile(key_bytes, (len(arr) + 1) // 2)[:len(arr)]
        decrypted = np.bitwise_xor(arr, tiled_key)
    return decrypted.tobytes()


def score_decryption(decrypted: bytes) -> tuple[float, float, list[str]]:
    """Score decrypted output for likelihood of meaningful content.

    Returns:
        (confidence_score, printable_ratio, keyword_hits)
        - printable_ratio: fraction of bytes that are printable ASCII
        - keyword_hits: HIGH_VALUE_KEYWORDS found (case-insensitive match)
        - confidence_score: 40% printable ratio + 60% keyword density
    """
    if not decrypted:
        return 0.0, 0.0, []

    printable_count = sum(1 for b in decrypted if b in PRINTABLE_BYTES)
    printable_ratio = printable_count / len(decrypted)

    lowered = decrypted.lower()
    keyword_hits = [
        kw.decode("ascii", errors="replace")
        for kw in HIGH_VALUE_KEYWORDS
        if kw.lower() in lowered
    ]

    keyword_density = min(len(keyword_hits) / max(len(HIGH_VALUE_KEYWORDS), 1), 1.0)
    confidence_score = 0.4 * printable_ratio + 0.6 * keyword_density

    return round(confidence_score, 4), round(printable_ratio, 4), keyword_hits


def _try_key(blob: bytes, key: int, section_name: str, offset: int) -> dict | None:
    """Attempt a single XOR key and return result dict if above threshold."""
    if key == 0:
        return None

    decrypted = xor_decrypt(blob, key)
    confidence, printable_ratio, keyword_hits = score_decryption(decrypted)

    if printable_ratio < PRINTABLE_THRESHOLD:
        return None

    printable_text = "".join(
        chr(b) if b in PRINTABLE_BYTES else "." for b in decrypted
    )[:500]

    key_hex = f"0x{key:04X}" if key > 0xFF else f"0x{key:02X}"

    return {
        "xor_key": key,
        "xor_key_hex": key_hex,
        "decrypted_text": printable_text,
        "confidence_score": confidence,
        "printable_ratio": printable_ratio,
        "keyword_hits": keyword_hits,
        "source_section": section_name,
        "offset": offset,
        "length": len(blob),
    }


def brute_force_xor(
    blob: bytes,
    section_name: str,
    offset: int,
    top_n: int = 5,
) -> list[dict]:
    """Try all 256 single-byte XOR keys and 35 common 2-byte keys on the blob.

    Args:
        blob: Encrypted byte sequence to decrypt.
        section_name: PE section this blob came from.
        offset: Byte offset within the section.
        top_n: Number of top results to return.

    Returns:
        Top-N results sorted by confidence score descending.
    """
    if not blob:
        return []

    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = []
        for key in range(1, 256):
            futures.append(executor.submit(_try_key, blob, key, section_name, offset))
        for key in TWO_BYTE_KEYS:
            futures.append(executor.submit(_try_key, blob, key, section_name, offset))

        for future in futures:
            result = future.result()
            if result is not None:
                results.append(result)

    results.sort(key=lambda r: r["confidence_score"], reverse=True)
    return results[:top_n]


def analyze_blobs(
    blobs: list[tuple[int, bytes, float]],
    section_name: str,
) -> list[dict]:
    """Process multiple high-entropy blobs from a single PE section.

    Args:
        blobs: List of (offset, blob_bytes, entropy) tuples.
        section_name: Name of the PE section these blobs came from.

    Returns:
        Flat list of all viable decryption results.
    """
    if not blobs:
        return []

    all_results: list[dict] = []

    for offset, blob_data, entropy in blobs:
        blob_results = brute_force_xor(
            blob=blob_data,
            section_name=section_name,
            offset=offset,
        )
        for res in blob_results:
            res["blob_entropy"] = entropy
        all_results.extend(blob_results)

    all_results.sort(key=lambda r: r["confidence_score"], reverse=True)
    return all_results
