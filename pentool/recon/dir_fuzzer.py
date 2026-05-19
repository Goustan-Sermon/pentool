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
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from pentool.utils import info, warning, console


# ──────────────────────────────────────────────
# Wordlist intégrée (top chemins courants)
# ──────────────────────────────────────────────

WORDLIST_SMALL: list[str] = [
    # Admin & config
    "admin", "administrator", "admin/login", "admin/dashboard",
    "wp-admin", "wp-login.php", "phpmyadmin", "pma",
    "cpanel", "webmail", "panel", "dashboard",
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
        exts       = extensions or [""]
        codes      = custom_codes or INTERESTING_CODES

        paths: list[str] = []
        for word in words:
            for ext in exts:
                if ext and "." in word:
                    continue
                paths.append(f"{word}{ext}")

        total  = len(paths)
        result = FuzzScanResult(target_url=target_url, total_tested=total)
        done   = 0
        start  = time.time()

        info(f"[bold]Dir Fuzzer[/bold] -- {total} chemins x {self._threads} threads -> [cyan]{target_url}[/cyan]")

        # --- Reponse de reference anti-faux-positifs -------------------
        # Sonde un chemin improbable pour detecter les serveurs catchall
        ref_resp   = self._probe(target_url, "PENTOOL_NONEXISTENT_XYZ_12345")
        ref_size   = ref_resp.content_length if ref_resp else -1
        ref_status = ref_resp.status_code    if ref_resp else -1

        if ref_resp and ref_status in codes:
            warning(
                f"Serveur catchall detecte : repond {ref_status} ({ref_size} B) "
                f"pour tout chemin. Filtrage anti-faux-positifs actif."
            )

        def _is_false_positive(r: FuzzResult) -> bool:
            """Vrai si la reponse est identique a la reference catchall."""
            if ref_resp is None or ref_status == -1:
                return False
            same_status = r.status_code == ref_status
            same_size   = abs(r.content_length - ref_size) <= 10
            return same_status and same_size

        # --- Fuzzing parallele -----------------------------------------
        with console.status(
            f"[cyan]Fuzzing en cours... 0/{total}[/cyan]", spinner="dots"
        ) as status:
            with ThreadPoolExecutor(max_workers=self._threads) as pool:
                futures = {
                    pool.submit(self._probe, target_url, path): path
                    for path in paths
                }
                for future in as_completed(futures):
                    done += 1
                    if done % 20 == 0:
                        status.update(f"[cyan]Fuzzing en cours... {done}/{total}[/cyan]")

                    fuzz_res = future.result()
                    if fuzz_res and fuzz_res.status_code in codes:
                        if not _is_false_positive(fuzz_res):
                            with self._lock:
                                result.results.append(fuzz_res)

                    if self._delay:
                        time.sleep(self._delay)

        result.scan_time = time.time() - start
        _order = {"critical": 0, "high": 1, "medium": 2, "info": 3, "low": 4}
        result.results.sort(key=lambda r: (_order.get(r.severity, 5), r.status_code))
        return result

    # ------------------------------------------------------------------
    def fuzz_recursive(
        self,
        target_url:    str,
        depth:         int            = 2,
        wordlist:      Optional[list[str]] = None,
        custom_codes:  Optional[set[int]]  = None,
    ) -> FuzzScanResult:
        """
        Fuzzing récursif — relance un scan dans chaque répertoire découvert.

        Pour chaque chemin retournant 200/301, on relance le fuzzing
        dessus jusqu'à la profondeur demandée.

        Args:
            target_url: URL de base
            depth:      profondeur max (défaut: 2)
            wordlist:   wordlist à utiliser
            custom_codes: codes HTTP à considérer

        Returns:
            FuzzScanResult fusionné avec tous les chemins trouvés
        """
        from urllib.parse import urljoin

        visited:   set[str]        = set()
        all_found: list[FuzzResult] = []
        queue:     list[str]        = [target_url]
        current_depth = 0

        info(f"[bold]Dir Fuzzer récursif[/bold] — profondeur max {depth}")

        while queue and current_depth < depth:
            next_queue: list[str] = []
            for base in queue:
                if base in visited:
                    continue
                visited.add(base)

                # Fuzzing de ce niveau
                level_result = self.fuzz(
                    base,
                    wordlist=wordlist,
                    custom_codes=custom_codes,
                )
                all_found.extend(level_result.results)

                # Identifier les sous-répertoires à explorer
                for r in level_result.found:
                    if r.status_code in (200, 301, 302, 403):
                        # Un chemin qui ressemble à un répertoire
                        path = r.path.rstrip("/")
                        if "." not in path.split("/")[-1]:  # pas une extension de fichier
                            sub_url = urljoin(base, path + "/")
                            if sub_url not in visited:
                                next_queue.append(sub_url)

            queue = next_queue
            current_depth += 1

        # Construire le résultat fusionné
        merged = FuzzScanResult(
            target_url=target_url,
            total_tested=len(visited) * (len(wordlist or WORDLIST_SMALL)),
        )
        # Dédupliquer par URL
        seen_urls: set[str] = set()
        for r in all_found:
            if r.url not in seen_urls:
                merged.results.append(r)
                seen_urls.add(r.url)

        _order = {"critical": 0, "high": 1, "medium": 2, "info": 3, "low": 4}
        merged.results.sort(key=lambda r: (_order.get(r.severity, 5), r.status_code))

        if merged.results:
            # Affichage en arborescence
            _print_tree(target_url, merged.results)

        return merged

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

# ──────────────────────────────────────────────
# Affichage en arborescence des résultats
# ──────────────────────────────────────────────

def _print_tree(base_url: str, results: list) -> None:
    """
    Affiche les résultats de fuzzing sous forme d'arborescence.

    /
    ├── admin/           [200] HIGH
    │   ├── login        [200] MEDIUM
    │   └── dashboard    [403] INFO
    ├── .env             [200] CRITICAL
    └── api/
        └── v1/users     [200] MEDIUM
    """
    from rich.tree import Tree
    from rich      import box
    from pentool.utils import console

    _CODE_COLOR = {
        200: "green", 201: "green", 204: "green",
        301: "yellow", 302: "yellow",
        401: "red", 403: "yellow",
        500: "red",
    }
    _SEV_COLOR = {
        "critical": "bold red",
        "high":     "bold orange1",
        "medium":   "bold yellow",
        "info":     "dim",
        "low":      "dim green",
    }

    # Construire une arborescence depuis les chemins
    tree = Tree(f"[bold cyan]{base_url.rstrip('/')}[/bold cyan]")
    nodes: dict[str, object] = {"": tree}

    # Trier par chemin pour que l'arbre soit cohérent
    sorted_results = sorted(results, key=lambda r: r.path)

    for r in sorted_results:
        parts  = r.path.strip("/").split("/")
        parent = ""
        for i, part in enumerate(parts):
            current = "/".join(parts[: i + 1])
            if current not in nodes:
                is_last = i == len(parts) - 1
                code_col = _CODE_COLOR.get(r.status_code, "white")
                sev_col  = _SEV_COLOR.get(r.severity, "white")

                if is_last:
                    label = (
                        f"[{sev_col}]{part}[/{sev_col}]"
                        f"  [{code_col}]{r.status_code}[/{code_col}]"
                        f"  [dim]{r.content_length} B[/dim]"
                    )
                else:
                    label = f"[cyan]{part}/[/cyan]"

                nodes[current] = nodes[parent].add(label)
            parent = current

    console.print(tree)
