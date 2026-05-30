from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    is_suspicious: bool
    raw_data: bytes = field(repr=False)


@dataclass
class DecryptionResult:
    xor_key: int
    decrypted_text: str
    confidence_score: float
    printable_ratio: float
    keyword_hits: list[str]
    source_section: str
    offset: int
    length: int


@dataclass
class IOCEntry:
    ioc_type: str
    value: str
    severity: str
    mitre_technique_id: str
    mitre_technique_name: str
    context: str
    source_section: str


@dataclass
class AnalysisReport:
    filename: str
    file_hash_md5: str
    file_hash_sha256: str
    file_size: int
    sections: list[SectionInfo]
    suspicious_sections: list[SectionInfo]
    decryption_results: list[DecryptionResult]
    iocs: list[IOCEntry]
    mitre_summary: dict = field(default_factory=dict)
    risk_score: float = 0.0
