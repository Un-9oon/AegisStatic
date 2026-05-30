import json
import re
import urllib.request
import urllib.parse
from pathlib import Path
from functools import lru_cache
import base64

THREAT_PATTERNS_PATH = Path(__file__).parent.parent / "data" / "threat_patterns.json"

SEVERITY_WEIGHTS = {
    "Critical": 25,
    "High": 15,
    "Medium": 8,
    "Low": 3,
    "Info": 1,
}

SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]


@lru_cache(maxsize=1)
def load_threat_patterns() -> dict:
    """Load and cache threat patterns from JSON file."""
    with open(THREAT_PATTERNS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def _get_context(text: str, start: int, end: int, window: int = 50) -> str:
    """Return ~window chars of context around a match."""
    ctx_start = max(0, start - window // 2)
    ctx_end = min(len(text), end + window // 2)
    snippet = text[ctx_start:ctx_end]
    prefix = "..." if ctx_start > 0 else ""
    suffix = "..." if ctx_end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def malwarebazaar_lookup(sha256_hash: str) -> dict:
    """Query MalwareBazaar for threat intelligence metadata using the SHA-256 hash."""
    url = "https://mb-api.abuse.ch/api/v1/"
    data = urllib.parse.urlencode({
        "query": "get_info",
        "hash": sha256_hash
    }).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": "AegisStatic-Static-Triage-Engine"
    })
    try:
        with urllib.request.urlopen(req, timeout=3.0) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            if res_data.get("query_status") == "ok":
                data_list = res_data.get("data", [])
                if data_list:
                    entry = data_list[0]
                    return {
                        "found": True,
                        "signature": entry.get("signature", "Unknown Family"),
                        "tags": entry.get("tags", []),
                        "reporter": entry.get("reporter", "Unknown"),
                        "first_seen": entry.get("first_seen", "Unknown"),
                        "file_type": entry.get("file_type", "Unknown")
                    }
    except Exception:
        pass
    return {"found": False}


def extract_iocs(text: str, source_section: str = "unknown") -> list[dict]:
    """Scan text against all threat patterns.

    Returns a deduplicated list of dicts.
    """
    if not text:
        return []

    data = load_threat_patterns()
    seen: set[tuple[str, str]] = set()
    iocs: list[dict] = []

    for category in data.get("patterns", []):
        category_name = category.get("category", "Unknown")
        for pattern_def in category.get("patterns", []):
            regex_str = pattern_def.get("regex", "")
            if not regex_str:
                continue

            try:
                compiled = re.compile(regex_str)
            except re.error:
                continue

            for match in compiled.finditer(text):
                value = match.group(0)
                technique_id = pattern_def.get("mitre_technique_id", "")
                dedup_key = (value, technique_id)

                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                iocs.append({
                    "ioc_type": pattern_def.get("description", category_name),
                    "value": value,
                    "severity": pattern_def.get("severity", "Info"),
                    "mitre_technique_id": technique_id,
                    "mitre_technique_name": pattern_def.get(
                        "mitre_technique_name", ""
                    ),
                    "mitre_tactic": pattern_def.get("mitre_tactic", ""),
                    "context": _get_context(text, match.start(), match.end()),
                    "source_section": source_section,
                })

    return iocs


def extract_base64_iocs(text: str, source_section: str = "unknown") -> list[dict]:
    """Detect and decode Base64 strings, scanning them for nested IOCs."""
    if not text:
        return []

    # Regex matching base64 strings of minimum 20 characters
    b64_regex = re.compile(r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    iocs = []

    for match in b64_regex.finditer(text):
        b64_str = match.group(0)
        try:
            decoded_bytes = base64.b64decode(b64_str)
            # Filter for printable ascii ratio >= 40%
            if len(decoded_bytes) > 0:
                printable_count = sum(1 for b in decoded_bytes if 32 <= b <= 126 or b in (9, 10, 13))
                ratio = printable_count / len(decoded_bytes)
                if ratio >= 0.4:
                    decoded_text = decoded_bytes.decode('ascii', errors='ignore')
                    nested_iocs = extract_iocs(decoded_text, source_section=f"{source_section} (Base64)")
                    iocs.extend(nested_iocs)
        except Exception:
            pass

    return iocs


def extract_rot13_iocs(text: str, source_section: str = "unknown") -> list[dict]:
    """Apply ROT13 decode on text and scan for nested IOCs."""
    if not text:
        return []

    # ROT13 translation tables
    rot13_trans = str.maketrans(
        "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
        "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"
    )
    rot13_text = text.translate(rot13_trans)
    
    if rot13_text == text:
        return []

    return extract_iocs(rot13_text, source_section=f"{source_section} (ROT13)")


def build_mitre_summary(iocs: list[dict]) -> dict:
    """Aggregate IOCs into a MITRE ATT&CK summary."""
    tactic_map: dict[str, dict[str, dict]] = {}

    for ioc in iocs:
        tactic = ioc.get("mitre_tactic", "Unknown")
        tech_id = ioc.get("mitre_technique_id", "")
        tech_name = ioc.get("mitre_technique_name", "")
        severity = ioc.get("severity", "Info")

        if not tactic:
            continue

        if tactic not in tactic_map:
            tactic_map[tactic] = {}

        if tech_id not in tactic_map[tactic]:
            tactic_map[tactic][tech_id] = {
                "id": tech_id,
                "name": tech_name,
                "severity": severity,
                "ioc_count": 0,
            }

        tactic_map[tactic][tech_id]["ioc_count"] += 1

        existing_sev = tactic_map[tactic][tech_id]["severity"]
        if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(existing_sev):
            tactic_map[tactic][tech_id]["severity"] = severity

    summary: dict = {}
    for tactic, techniques in tactic_map.items():
        tech_list = list(techniques.values())
        max_sev = "Info"
        for tech in tech_list:
            if SEVERITY_ORDER.index(tech["severity"]) > SEVERITY_ORDER.index(max_sev):
                max_sev = tech["severity"]

        summary[tactic] = {
            "technique_count": len(tech_list),
            "techniques": tech_list,
            "max_severity": max_sev,
        }

    return summary


def calculate_risk_score(iocs: list[dict]) -> float:
    """Calculate a 0-100 risk score based on IOC count and severity distribution."""
    if not iocs:
        return 0.0

    raw_score = 0.0
    for ioc in iocs:
        severity = ioc.get("severity", "Info")
        raw_score += SEVERITY_WEIGHTS.get(severity, 1)

    max_expected = 20 * SEVERITY_WEIGHTS["Critical"]
    normalized = (raw_score / max_expected) * 100.0

    return min(round(normalized, 2), 100.0)


def classify_behavior_profile(iocs: list[dict]) -> dict:
    """Determine the behavior profile of the binary based on MITRE tactics."""
    if not iocs:
        return {"class": "Clean Utility", "confidence": "Low"}

    tactics = {ioc.get("mitre_tactic") for ioc in iocs if ioc.get("mitre_tactic")}
    
    # Classification rules
    if "Credential Access" in tactics and "Collection" in tactics:
        behavior_class = "Infostealer / Spyware"
    elif "Execution" in tactics and "Command and Control" in tactics and "Defense Evasion" in tactics:
        behavior_class = "Trojan / RAT (Remote Access Trojan)"
    elif "Persistence" in tactics and "Privilege Escalation" in tactics:
        behavior_class = "Rootkit / Persistence Loader"
    elif "Persistence" in tactics and "Defense Evasion" in tactics:
        behavior_class = "Trojan / Loader"
    elif "Defense Evasion" in tactics or "Discovery" in tactics:
        behavior_class = "Adversary Discovery / Evasive Utility"
    else:
        behavior_class = "Suspicious Binary"

    # Confidence rating
    if len(tactics) >= 3:
        confidence = "High"
    elif len(tactics) >= 1:
        confidence = "Medium"
    else:
        confidence = "Low"

    return {"class": behavior_class, "confidence": confidence}


def process_decryption_results(
    results: list[dict],
    raw_strings: list[str] = None,
) -> tuple[list[dict], dict, float]:
    """Extract IOCs, decode strings (Base64/ROT13), compile MITRE summary, and score risk."""
    all_iocs: list[dict] = []
    global_seen: set[tuple[str, str]] = set()

    def add_ioc(ioc):
        dedup_key = (ioc["value"], ioc["mitre_technique_id"])
        if dedup_key not in global_seen:
            global_seen.add(dedup_key)
            all_iocs.append(ioc)

    # 1. Process XOR decryption text blocks
    for result in results:
        decrypted_text = result.get("decrypted_text", "")
        section = result.get("source_section", "unknown")
        
        # Standard extraction
        for ioc in extract_iocs(decrypted_text, source_section=f"XOR Decryption ({section})"):
            add_ioc(ioc)
        
        # Base64 nested extraction
        for ioc in extract_base64_iocs(decrypted_text, source_section=f"XOR Decryption ({section})"):
            add_ioc(ioc)

        # ROT13 nested extraction
        for ioc in extract_rot13_iocs(decrypted_text, source_section=f"XOR Decryption ({section})"):
            add_ioc(ioc)

    # 2. Process Raw Strings extracted from binary
    if raw_strings:
        for s in raw_strings:
            # Direct extraction on raw strings
            for ioc in extract_iocs(s, source_section="Raw Strings"):
                add_ioc(ioc)
            
            # Base64 extraction on raw strings
            for ioc in extract_base64_iocs(s, source_section="Raw Strings"):
                add_ioc(ioc)
            
            # ROT13 extraction on raw strings
            for ioc in extract_rot13_iocs(s, source_section="Raw Strings"):
                add_ioc(ioc)

    mitre_summary = build_mitre_summary(all_iocs)
    risk_score = calculate_risk_score(all_iocs)

    return all_iocs, mitre_summary, risk_score
