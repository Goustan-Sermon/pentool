"""
Modèles de données CVE — représentent une vulnérabilité NVD enrichie.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}


@dataclass
class CVEEntry:
    """Une vulnérabilité CVE complète telle que retournée par l'API NVD."""

    cve_id:       str
    description:  str
    published:    str
    modified:     str

    # CVSS v3 (prioritaire)
    cvss_v3_score:    Optional[float] = None
    cvss_v3_severity: str             = "UNKNOWN"
    cvss_v3_vector:   str             = ""

    # CVSS v2 (fallback)
    cvss_v2_score:    Optional[float] = None
    cvss_v2_severity: str             = ""

    # Méta
    references: list[str]   = field(default_factory=list)
    cpe_list:   list[str]   = field(default_factory=list)
    cwe_ids:    list[str]   = field(default_factory=list)

    # Contexte de détection (rempli par le correlateur)
    matched_service: str = ""
    matched_port:    int = 0

    @property
    def score(self) -> Optional[float]:
        return self.cvss_v3_score if self.cvss_v3_score is not None else self.cvss_v2_score

    @property
    def severity(self) -> str:
        if self.cvss_v3_severity and self.cvss_v3_severity != "UNKNOWN":
            return self.cvss_v3_severity
        if self.cvss_v2_severity:
            return self.cvss_v2_severity.upper()
        return "UNKNOWN"

    @property
    def severity_order(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 5)

    @property
    def nvd_url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"]        = self.score
        d["severity"]     = self.severity
        d["nvd_url"]      = self.nvd_url
        return d


@dataclass
class ServiceCVEMatch:
    """Résultat de la corrélation entre un service détecté et ses CVE."""
    service_name:    str
    service_version: str
    port:            int
    protocol:        str
    fingerprint:     str
    cves:            list[CVEEntry] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for c in self.cves if c.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for c in self.cves if c.severity == "HIGH")

    @property
    def max_score(self) -> Optional[float]:
        scores = [c.score for c in self.cves if c.score is not None]
        return max(scores) if scores else None

    def to_dict(self) -> dict:
        return {
            "service_name":    self.service_name,
            "service_version": self.service_version,
            "port":            self.port,
            "protocol":        self.protocol,
            "fingerprint":     self.fingerprint,
            "critical_count":  self.critical_count,
            "high_count":      self.high_count,
            "max_score":       self.max_score,
            "cves":            [c.to_dict() for c in self.cves],
        }