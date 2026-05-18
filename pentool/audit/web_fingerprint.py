"""
Web Application Fingerprinting — Phase 3.

Détecte la version des applications web exposées sur les vhosts découverts
(Cacti, WordPress, phpMyAdmin, etc.) et corrèle avec les CVE NVD.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field, asdict
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

from pentool.utils import info, warning, success, console


# ──────────────────────────────────────────────
# Signatures d'applications web
# Chaque entrée : (app_name, chemins à tester, regex de version, CPE template)
# ──────────────────────────────────────────────

APP_SIGNATURES: list[dict] = [
    {
        "name": "Cacti",
        "paths": ["/", "/index.php", "/cacti/"],
        "patterns": [
            r'Version\s+([0-9]+\.[0-9]+\.[0-9]+)',
            r'cacti_version\s*=\s*[\'"]([0-9.]+)[\'"]',
            r'<title>Login to Cacti[^<]*</title>',
        ],
        "version_patterns": [
            r'Version\s+([0-9]+\.[0-9]+\.[0-9]+)',
            r'cacti_version["\s=:]+([0-9]+\.[0-9]+\.[0-9]+)',
            r'var cactiVersion = "([0-9.]+)"',
        ],
        "cpe_template": "cpe:/a:cacti:cacti:{version}",
        "nvd_keyword": "Cacti {version}",
        "header_hints": ["Cacti"],
    },
    {
        "name": "WordPress",
        "paths": ["/", "/wp-login.php", "/wp-admin/"],
        "patterns": [
            r'wp-content', r'wp-includes',
            r'WordPress\s+([0-9]+\.[0-9]+)',
        ],
        "version_patterns": [
            r'<meta name="generator" content="WordPress ([0-9.]+)"',
            r'wp-includes/js/wp-emoji-release\.min\.js\?ver=([0-9.]+)',
            r'WordPress ([0-9]+\.[0-9]+\.[0-9]+)',
        ],
        "cpe_template": "cpe:/a:wordpress:wordpress:{version}",
        "nvd_keyword": "WordPress {version}",
        "header_hints": [],
    },
    {
        "name": "phpMyAdmin",
        "paths": ["/phpmyadmin/", "/pma/", "/phpMyAdmin/"],
        "patterns": [
            r'phpMyAdmin', r'PMA_VERSION',
        ],
        "version_patterns": [
            r'PMA_VERSION["\s=:]+([0-9]+\.[0-9]+\.[0-9]+)',
            r'phpMyAdmin ([0-9]+\.[0-9]+\.[0-9]+)',
            r'"version":"([0-9]+\.[0-9]+\.[0-9]+)"',
        ],
        "cpe_template": "cpe:/a:phpmyadmin:phpmyadmin:{version}",
        "nvd_keyword": "phpMyAdmin {version}",
        "header_hints": ["phpMyAdmin"],
    },
    {
        "name": "Joomla",
        "paths": ["/", "/administrator/"],
        "patterns": [r'Joomla!', r'/media/jui/'],
        "version_patterns": [
            r'<meta name="generator" content="Joomla! ([0-9.]+)"',
            r'Joomla! ([0-9]+\.[0-9]+\.[0-9]+)',
        ],
        "cpe_template": "cpe:/a:joomla:joomla:{version}",
        "nvd_keyword": "Joomla {version}",
        "header_hints": [],
    },
    {
        "name": "Drupal",
        "paths": ["/", "/user/login"],
        "patterns": [r'Drupal', r'/sites/default/', r'/misc/drupal.js'],
        "version_patterns": [
            r'Drupal ([0-9]+\.[0-9]+)',
            r'"drupalSettings".*"version":"([0-9.]+)"',
        ],
        "cpe_template": "cpe:/a:drupal:drupal:{version}",
        "nvd_keyword": "Drupal {version}",
        "header_hints": ["X-Generator: Drupal"],
    },
    {
        "name": "Apache Tomcat",
        "paths": ["/", "/manager/html"],
        "patterns": [r'Apache Tomcat', r'Tomcat/([0-9.]+)'],
        "version_patterns": [
            r'Apache Tomcat/([0-9]+\.[0-9]+\.[0-9]+)',
            r'Tomcat ([0-9]+\.[0-9]+\.[0-9]+)',
        ],
        "cpe_template": "cpe:/a:apache:tomcat:{version}",
        "nvd_keyword": "Apache Tomcat {version}",
        "header_hints": ["Apache-Coyote", "Tomcat"],
    },
    {
        "name": "Jenkins",
        "paths": ["/", "/login"],
        "patterns": [r'Jenkins', r'hudson'],
        "version_patterns": [
            r'Jenkins ver\. ([0-9.]+)',
            r'<title>Dashboard \[Jenkins ([0-9.]+)\]',
        ],
        "cpe_template": "cpe:/a:jenkins:jenkins:{version}",
        "nvd_keyword": "Jenkins {version}",
        "header_hints": ["X-Jenkins"],
    },
    {
        "name": "Grafana",
        "paths": ["/", "/login"],
        "patterns": [r'Grafana', r'"grafanaBootData"'],
        "version_patterns": [
            r'"version":"([0-9]+\.[0-9]+\.[0-9]+)"',
            r'Grafana v([0-9]+\.[0-9]+\.[0-9]+)',
        ],
        "cpe_template": "cpe:/a:grafana:grafana:{version}",
        "nvd_keyword": "Grafana {version}",
        "header_hints": ["Grafana"],
    },
    {
        "name": "Zabbix",
        "paths": ["/", "/zabbix/"],
        "patterns": [r'Zabbix SIA', r'zabbix\.js'],
        "version_patterns": [
            r'Zabbix ([0-9]+\.[0-9]+\.[0-9]+)',
            r'"zabbix_export".*"version":"([0-9.]+)"',
        ],
        "cpe_template": "cpe:/a:zabbix:zabbix:{version}",
        "nvd_keyword": "Zabbix {version}",
        "header_hints": [],
    },
]


# ──────────────────────────────────────────────
# Modèles de données
# ──────────────────────────────────────────────

@dataclass
class WebAppFingerprint:
    """Résultat du fingerprinting d'une application web."""
    url:         str
    app_name:    str
    version:     str         # "" si non détectée
    cpe:         str
    nvd_keyword: str
    confidence:  str         # "high" | "medium" | "low"
    evidence:    str         # ce qui a permis la détection
    cves:        list[dict] = field(default_factory=list)   # rempli par CVECorrelator

    def to_dict(self) -> dict:
        return asdict(self)


# ──────────────────────────────────────────────
# Fingerprinter principal
# ──────────────────────────────────────────────

class WebFingerprinter:
    """
    Identifie les applications web et leur version sur un ensemble d'URLs.

    Usage typique : appelé après VHostFuzzer pour analyser chaque vhost.
    """

    def __init__(self, timeout: float = 8.0) -> None:
        self._timeout = timeout
        self._session = requests.Session()
        adapter = HTTPAdapter(max_retries=1)
        self._session.mount("http://",  adapter)
        self._session.mount("https://", adapter)
        self._session.headers.update({
            "User-Agent": "Pentool/0.1 WebFingerprinter (ISEN)",
            "Accept":     "text/html,*/*",
        })

    def fingerprint_url(self, base_url: str, host_header: Optional[str] = None) -> list[WebAppFingerprint]:
        """
        Tente de détecter les applications sur base_url.

        Args:
            base_url:    ex: "http://10.129.60.43"
            host_header: ex: "cacti.monitorsfour.htb" (pour les vhosts)

        Returns:
            Liste des WebAppFingerprint détectés
        """
        results: list[WebAppFingerprint] = []
        headers = {}
        if host_header:
            headers["Host"] = host_header
            display_url = f"http://{host_header}"
        else:
            display_url = base_url

        info(f"  [cyan]Fingerprinting[/cyan] → {display_url}")

        for sig in APP_SIGNATURES:
            fp = self._try_signature(base_url, sig, headers, display_url)
            if fp:
                results.append(fp)
                break   # une app principale par URL suffit

        return results

    def _try_signature(
        self,
        base_url: str,
        sig:      dict,
        headers:  dict,
        display_url: str,
    ) -> Optional[WebAppFingerprint]:
        """Teste une signature sur les chemins définis."""

        for path in sig["paths"]:
            url = base_url.rstrip("/") + path
            try:
                resp = self._session.get(
                    url, headers=headers,
                    timeout=self._timeout,
                    allow_redirects=True,
                )
            except Exception:
                continue

            if resp.status_code not in (200, 401, 403):
                continue

            body = resp.text[:8000]
            all_headers_str = " ".join(
                f"{k}: {v}" for k, v in resp.headers.items()
            )
            full_text = body + all_headers_str

            # Vérification de présence de l'app
            app_present = any(
                re.search(p, full_text, re.IGNORECASE)
                for p in sig["patterns"]
            )
            if not app_present:
                # Vérifier les header hints
                app_present = any(
                    hint.lower() in all_headers_str.lower()
                    for hint in sig.get("header_hints", [])
                )

            if not app_present:
                continue

            # Extraction de version
            version = ""
            evidence = f"Détecté sur {url} (HTTP {resp.status_code})"
            for vpat in sig["version_patterns"]:
                m = re.search(vpat, full_text, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.lastindex else ""
                    evidence += f" — version pattern: {vpat[:50]}"
                    break

            confidence = "high" if version else "medium"
            cpe = sig["cpe_template"].format(version=version or "?")
            keyword = sig["nvd_keyword"].format(version=version) if version else sig["name"]

            fp = WebAppFingerprint(
                url=display_url,
                app_name=sig["name"],
                version=version,
                cpe=cpe,
                nvd_keyword=keyword,
                confidence=confidence,
                evidence=evidence,
            )

            level = "[success]" if version else "[warning]"
            ver_str = f"v{version}" if version else "version inconnue"
            info(f"    {level}✔[/{level[1:]}] {sig['name']} {ver_str} détecté sur {display_url}")
            return fp

        return None