"""
Client pour l'API NVD (National Vulnerability Database) v2.0.

Doc officielle : https://nvd.nist.gov/developers/vulnerabilities
Endpoint       : GET https://services.nvd.nist.gov/rest/json/cves/2.0

Rate limit NVD :
  - Sans clé API : 5 req / 30 s
  - Avec clé API : 50 req / 30 s  (NIST_API_KEY dans l'env)
"""

from __future__ import annotations

import os
import time
import urllib.parse
from typing import Optional

import requests

from pentool.cve.models import CVEEntry
from pentool.utils import info, warning, error, console


NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_REQUEST_DELAY = 6.5   # secondes entre requêtes sans clé API (conservateur)


class NVDClient:
    """
    Client HTTP pour l'API NVD 2.0.

    Usage :
        client = NVDClient()
        cves   = client.search_by_keyword("Apache 2.4.49")
        cves  += client.search_by_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    """

    def __init__(
        self,
        api_key:  Optional[str] = None,
        timeout:  float         = 15.0,
        max_results: int        = 20,
    ) -> None:
        self._api_key    = api_key or os.environ.get("NVD_API_KEY", "")
        self._timeout    = timeout
        self._max_results = max_results
        self._last_call  = 0.0

        self._session = requests.Session()
        self._session.headers.update({
            "Accept": "application/json",
            "User-Agent": "Pentool/0.1 ISEN-SecProject",
        })
        if self._api_key:
            self._session.headers["apiKey"] = self._api_key

    # ──────────────────────────────────────────────────────────────────
    # Méthodes publiques
    # ──────────────────────────────────────────────────────────────────

    def search_by_keyword(self, keyword: str) -> list[CVEEntry]:
        """Recherche des CVE par mot-clé (nom produit + version)."""
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": self._max_results,
        }
        return self._query(params, context=keyword)

    def search_by_cpe(self, cpe: str) -> list[CVEEntry]:
        """Recherche des CVE liées à un CPE précis."""
        params = {
            "cpeName":        cpe,
            "resultsPerPage": self._max_results,
        }
        return self._query(params, context=cpe)

    def get_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """Récupère un CVE précis par son identifiant."""
        params = {"cveId": cve_id}
        results = self._query(params, context=cve_id)
        return results[0] if results else None

    # ──────────────────────────────────────────────────────────────────
    # Requête HTTP avec rate-limiting
    # ──────────────────────────────────────────────────────────────────

    def _query(self, params: dict, context: str = "") -> list[CVEEntry]:
        """Effectue la requête NVD avec respect du rate-limit."""
        self._rate_limit()

        url = f"{NVD_BASE_URL}?{urllib.parse.urlencode(params)}"
        try:
            resp = self._session.get(url, timeout=self._timeout)
            resp.raise_for_status()
            data = resp.json()
            return self._parse_response(data)

        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                return []
            if e.response is not None and e.response.status_code == 403:
                warning("NVD API : accès refusé (rate limit atteint). Attendez 30 s.")
                return []
            error(f"NVD HTTP {e.response.status_code if e.response else '?'} pour '{context}'")
            return []

        except requests.exceptions.Timeout:
            warning(f"NVD timeout pour '{context}' — skip")
            return []

        except Exception as exc:
            error(f"NVD erreur inattendue : {exc}")
            return []

    def _rate_limit(self) -> None:
        """Attend si nécessaire pour respecter le rate-limit NVD."""
        delay = 1.5 if self._api_key else _REQUEST_DELAY
        elapsed = time.time() - self._last_call
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_call = time.time()

    # ──────────────────────────────────────────────────────────────────
    # Parsing de la réponse JSON NVD 2.0
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_response(data: dict) -> list[CVEEntry]:
        """Transforme la réponse JSON NVD en liste de CVEEntry."""
        entries: list[CVEEntry] = []

        vulnerabilities = data.get("vulnerabilities", [])
        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            entry = NVDClient._parse_cve(cve_data)
            if entry:
                entries.append(entry)

        return entries

    @staticmethod
    def _parse_cve(cve: dict) -> Optional[CVEEntry]:
        """Parse un bloc CVE individuel du JSON NVD."""
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Description (priorité : anglais)
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        published = cve.get("published", "")[:10]
        modified  = cve.get("lastModified", "")[:10]

        # CVSS v3.1 puis v3.0
        cvss_v3_score = cvss_v3_severity = cvss_v3_vector = None
        metrics = cve.get("metrics", {})

        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                cvss_v3_score    = cvss_data.get("baseScore")
                cvss_v3_severity = cvss_data.get("baseSeverity", "UNKNOWN")
                cvss_v3_vector   = cvss_data.get("vectorString", "")
                break

        # CVSS v2 (fallback)
        cvss_v2_score = cvss_v2_severity = None
        if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            m2 = metrics["cvssMetricV2"][0]
            cvss_data2      = m2.get("cvssData", {})
            cvss_v2_score   = cvss_data2.get("baseScore")
            cvss_v2_severity = m2.get("baseSeverity", "")

        # Références
        references = [
            ref.get("url", "")
            for ref in cve.get("references", [])
            if ref.get("url")
        ][:5]

        # CPE (configurations affectées)
        cpe_list: list[str] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        cpe_list.append(cpe_match.get("criteria", ""))
        cpe_list = list(set(cpe_list))[:10]

        # CWE
        cwe_ids = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        return CVEEntry(
            cve_id=cve_id,
            description=description,
            published=published,
            modified=modified,
            cvss_v3_score=cvss_v3_score,
            cvss_v3_severity=cvss_v3_severity or "UNKNOWN",
            cvss_v3_vector=cvss_v3_vector or "",
            cvss_v2_score=cvss_v2_score,
            cvss_v2_severity=cvss_v2_severity or "",
            references=references,
            cpe_list=cpe_list,
            cwe_ids=cwe_ids,
        )