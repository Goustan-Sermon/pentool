"""
Module de fuzzing de répertoires et fichiers cachés.

Envoie des requêtes HTTP concurrentes à partir d'une wordlist
et identifie les ressources accessibles (200, 301, 302, 403…).
"""

from __future__ import annotations

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from pentool.utils import info, warning, success, error, console


# ──────────────────────────────────────────────
# Wordlist intégrée (top chemins courants)
# ──────────────────────────────────────────────

WORDLIST_SMALL: list[str] = [
    # Admin & config
    "admin", "administrator", "admin/login", "admin/dashboard",
    "wp-admin", "wp-login.php", "phpmyadmin", "pma",
    "cpanel", "webmail", "panel", "dashboard", "user", "users",
    # Fichiers sensibles
    ".env", ".git", ".git/config", ".htaccess", ".htpasswd",
    "config.php", "config.yml", "config.json", "settings.py",
    "web.config", "Dockerfile", "docker-compose.yml",
    "backup.zip", "backup.tar.gz", "dump.sql", "db.sql",
    # API & dev
    "api", "api/v1", "api/v2", "graphql", "swagger",
    "swagger-ui", "swagger-ui.html", "api-docs", "redoc",
    "docs", "documentation", "dev", "test", "staging",
    # Auth
    "login", "logout", "register", "signup", "forgot-password",
    "reset-password", "oauth", "auth", "sso",
    # Uploads & media
    "upload", "uploads", "files", "static", "assets",
    "images", "img", "media", "public",
    # Monitoring & infra
    "health", "healthz", "status", "metrics", "actuator",
    "actuator/health", "actuator/env", "actuator/beans",
    "server-status", "server-info",
    # Frameworks courants
    "wp-content", "wp-includes", "wp-json",
    "administrator/index.php", "joomla",
    "vendor", "node_modules", "composer.json", "package.json",
    # Logs
    "logs", "log", "error.log", "access.log",
    "debug", "trace",
    # Robots & sitemap
    "robots.txt", "sitemap.xml", "sitemap.xml.gz",
    ".well-known", ".well-known/security.txt",
    # Misc
    "old", "bak", "backup", "archive", "temp", "tmp",
    "cgi-bin", "scripts", "bin",
]

# Extensions à tester en plus du chemin brut
EXTENSIONS: list[str] = [
    "", ".php", ".html", ".htm", ".asp", ".aspx",
    ".jsp", ".txt", ".bak", ".old", ".zip",
]


# ──────────────────────────────────────────────
# Codes HTTP intéressants (à reporter)
# ──────────────────────────────────────────────

INTERESTING_CODES: set[int] = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

# Codes qui indiquent une ressource "trouvée" (utile pour le rapport)
FOUND_CODES: set[int] = {200, 201, 204, 301, 302, 307, 308, 401, 403}


# ──────────────────────────────────────────────
# Modèles de données
# ──────────────────────────────────────────────

@dataclass
class FuzzResult:
    """Résultat pour un chemin donné."""
    url:           str
    path:          str
    status_code:   int
    content_length: int
    redirect_url:  str = ""
    content_type:  str = ""
    response_time: float = 0.0  # secondes

    @property
    def is_interesting(self) -> bool:
        return self.status_code in INTERESTING_CODES

    @property
    def severity(self) -> str:
        """Niveau de criticité pour le rapport."""
        if self.status_code == 200 and any(
            kw in self.path for kw in [".env", ".git", "config", "backup", "dump", "sql"]
        ):
            return "critical"
        if self.status_code in {200, 201} and any(
            kw in self.path for kw in ["admin", "phpmyadmin", "cpanel", "panel"]
        ):
            return "high"
        if self.status_code == 200:
            return "medium"
        if self.status_code in {301, 302, 403}:
            return "info"
        return "low"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity
        return d


@dataclass
class FuzzScanResult:
    """Résultat global du fuzzing sur une cible."""
    target_url:  str
    total_tested: int = 0
    results:     list[FuzzResult] = field(default_factory=list)
    scan_time:   float = 0.0

    @property
    def found(self) -> list[FuzzResult]:
        return [r for r in self.results if r.status_code in FOUND_CODES]

    @property
    def critical_findings(self) -> list[FuzzResult]:
        return [r for r in self.results if r.severity in {"critical", "high"}]

    def to_dict(self) -> dict:
        return {
            "target_url":   self.target_url,
            "total_tested": self.total_tested,
            "scan_time":    round(self.scan_time, 2),
            "found_count":  len(self.found),
            "results":      [r.to_dict() for r in self.results],
        }


# ──────────────────────────────────────────────
# Scanner principal
# ──────────────────────────────────────────────

class DirFuzzer:
    """
    Fuzzer de répertoires et fichiers HTTP.

    Utilise un ThreadPoolExecutor pour paralléliser les requêtes
    et respecte un délai configurable entre chaque batch.
    """

    def __init__(
        self,
        threads:     int   = 10,
        timeout:     float = 5.0,
        delay:       float = 0.0,
        user_agent:  str   = "Pentool/0.1 (ISEN Security Scanner)",
        follow_redirects: bool = False,
    ) -> None:
        self._threads          = threads
        self._timeout          = timeout
        self._delay            = delay
        self._follow_redirects = follow_redirects
        self._lock             = threading.Lock()

        # Session HTTP avec retry
        self._session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=threads, pool_maxsize=threads)
        self._session.mount("http://",  adapter)
        self._session.mount("https://", adapter)
        self._session.headers.update({
            "User-Agent": user_agent,
            "Accept":     "*/*",
        })

    # ------------------------------------------------------------------
    def fuzz(
        self,
        target_url:    str,
        wordlist:      Optional[list[str]] = None,
        extensions:    Optional[list[str]] = None,
        custom_codes:  Optional[set[int]]  = None,
    ) -> FuzzScanResult:
        """
        Lance le fuzzing sur target_url.

        Args:
            target_url:   URL de base (ex: http://192.168.1.1)
            wordlist:     liste de chemins (défaut: WORDLIST_SMALL)
            extensions:   extensions à tester (défaut: EXTENSIONS)
            custom_codes: codes HTTP à reporter (défaut: INTERESTING_CODES)

        Returns:
            FuzzScanResult avec tous les résultats
        """
        # Normalisation de l'URL
        target_url = self._normalize_url(target_url)
        words      = wordlist  or WORDLIST_SMALL
        exts       = extensions or [""]  # sans extensions par défaut (wordlist déjà précise)
        codes      = custom_codes or INTERESTING_CODES

        # Construction de la liste complète des chemins à tester
        paths: list[str] = []
        for word in words:
            for ext in exts:
                # N'ajoute l'extension que si le mot n'en a pas déjà une
                if ext and "." in word:
                    continue
                paths.append(f"{word}{ext}")

        total   = len(paths)
        result  = FuzzScanResult(target_url=target_url, total_tested=total)
        done    = 0
        start   = time.time()

        info(f"[bold]Dir Fuzzer[/bold] — {total} chemins × {self._threads} threads → [cyan]{target_url}[/cyan]")

        with console.status(
            f"[cyan]Fuzzing en cours… 0/{total}[/cyan]", spinner="dots"
        ) as status:
            with ThreadPoolExecutor(max_workers=self._threads) as pool:
                futures = {
                    pool.submit(self._probe, target_url, path): path
                    for path in paths
                }
                for future in as_completed(futures):
                    done += 1
                    if done % 20 == 0:
                        status.update(f"[cyan]Fuzzing en cours… {done}/{total}[/cyan]")

                    fuzz_res = future.result()
                    if fuzz_res and fuzz_res.status_code in codes:
                        with self._lock:
                            result.results.append(fuzz_res)

                    if self._delay:
                        time.sleep(self._delay)

        result.scan_time = time.time() - start
        # Tri par criticité puis code HTTP
        _order = {"critical": 0, "high": 1, "medium": 2, "info": 3, "low": 4}
        result.results.sort(key=lambda r: (_order.get(r.severity, 5), r.status_code))

        return result

    # ------------------------------------------------------------------
    def _probe(self, base_url: str, path: str) -> Optional[FuzzResult]:
        """Teste un chemin unique et retourne un FuzzResult ou None."""
        url = urljoin(base_url, path)
        try:
            t0 = time.time()
            resp = self._session.get(
                url,
                timeout=self._timeout,
                allow_redirects=self._follow_redirects,
                stream=False,
            )
            elapsed = time.time() - t0

            return FuzzResult(
                url=url,
                path=path,
                status_code=resp.status_code,
                content_length=int(resp.headers.get("Content-Length", len(resp.content))),
                redirect_url=resp.headers.get("Location", ""),
                content_type=resp.headers.get("Content-Type", "").split(";")[0].strip(),
                response_time=round(elapsed, 3),
            )
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_url(url: str) -> str:
        """Ajoute le schéma si absent, s'assure que l'URL se termine par /."""
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        if not url.endswith("/"):
            url += "/"
        return url