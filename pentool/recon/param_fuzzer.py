"""
Module de fuzzing de paramètres HTTP et détection d'endpoints API.

Deux fonctionnalités :
  1. ParamFuzzer   — teste des valeurs sur un paramètre connu
                     ex: /user?token=0, /user?token=1 … /user?token=9999
  2. EndpointProbe — sonde un endpoint JSON pour détecter les paramètres
                     acceptés (en analysant les messages d'erreur)
"""

from __future__ import annotations

import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from pentool.utils import info, warning, success, error, console


# ──────────────────────────────────────────────
# Paramètres courants à tester (découverte)
# ──────────────────────────────────────────────

COMMON_PARAMS: list[str] = [
    # Auth / session
    "token", "api_key", "apikey", "key", "secret", "auth",
    "access_token", "bearer", "jwt", "session", "sid",
    "authorization", "x-api-key",
    # Identification
    "id", "user_id", "uid", "userid", "user", "username",
    "account", "account_id", "profile", "member", "member_id",
    # Données
    "q", "query", "search", "keyword", "term", "filter",
    "page", "limit", "offset", "size", "count", "num",
    "sort", "order", "direction",
    # Debug / admin
    "debug", "verbose", "admin", "mode", "type", "action",
    "cmd", "command", "exec", "run", "code",
    # Fichiers / redirections
    "file", "path", "url", "redirect", "return", "next",
    "callback", "ref", "src", "dest", "target",
    # Injection classique
    "name", "email", "phone", "address", "data", "value",
    "input", "content", "text", "message", "body",
]

# Valeurs de test pour détecter les paramètres acceptés
PROBE_VALUES: list[str] = ["0", "1", "test", "true", "admin", "null", ""]


# ──────────────────────────────────────────────
# Patterns de détection dans les réponses
# ──────────────────────────────────────────────

# Indique qu'un paramètre est attendu mais la valeur est mauvaise
# (différent de "paramètre inexistant")
PARAM_ACCEPTED_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"invalid",
        r"unauthorized",
        r"forbidden",
        r"not found",
        r"missing",
        r"required",
        r"bad request",
        r"must be",
        r"expected",
        r"provide",
        r"token",
        r"permission",
        r"access denied",
        r'"error"',
        r'"message"',
        r'"status"',
        r'"code"',
    ]
]

# Indique que l'injection a produit quelque chose d'intéressant
INTERESTING_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r'"id"\s*:',
        r'"user(name)?"\s*:',
        r'"email"\s*:',
        r'"password"\s*:',
        r'"role"\s*:',
        r'"admin"\s*:',
        r'"token"\s*:',
        r'"key"\s*:',
        r'"secret"\s*:',
        r'\[\s*\{',           # début de liste JSON
        r'"data"\s*:\s*\[',
        r'"results"\s*:\s*\[',
    ]
]


# ──────────────────────────────────────────────
# Modèles de données
# ──────────────────────────────────────────────

@dataclass
class ParamHit:
    """Un hit lors du fuzzing de paramètre."""
    url:            str
    param:          str
    value:          str
    status_code:    int
    content_length: int
    content_type:   str
    response_body:  str     # extrait (512 premiers chars)
    is_interesting: bool    # contient des données sensibles ?
    note:           str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ParamFuzzResult:
    """Résultat global d'un fuzzing de paramètre."""
    target_url:   str
    param:        str
    total_tested: int = 0
    hits:         list[ParamHit] = field(default_factory=list)
    scan_time:    float = 0.0

    @property
    def interesting_hits(self) -> list[ParamHit]:
        return [h for h in self.hits if h.is_interesting]

    def to_dict(self) -> dict:
        return {
            "target_url":       self.target_url,
            "param":            self.param,
            "total_tested":     self.total_tested,
            "hits":             len(self.hits),
            "interesting_hits": len(self.interesting_hits),
            "scan_time":        round(self.scan_time, 2),
            "results":          [h.to_dict() for h in self.hits],
        }


@dataclass
class EndpointAnalysis:
    """Analyse d'un endpoint JSON (détection de paramètres)."""
    url:                str
    baseline_status:    int
    baseline_body:      str
    detected_params:    list[str] = field(default_factory=list)
    param_hints:        list[str] = field(default_factory=list)  # extraits du message d'erreur

    def to_dict(self) -> dict:
        return asdict(self)


# ──────────────────────────────────────────────
# Classe principale
# ──────────────────────────────────────────────

class ParamFuzzer:
    """
    Fuzzer de paramètres HTTP.

    Trois modes :
      - discover_params() : trouve quels paramètres un endpoint accepte
      - fuzz_param()      : teste des valeurs sur un paramètre connu
      - fuzz_range()      : teste une plage numérique (ex: id=0 à id=9999)
    """

    def __init__(
        self,
        threads:    int   = 10,
        timeout:    float = 5.0,
        user_agent: str   = "Pentool/0.1 ParamFuzzer (ISEN)",
        method:     str   = "GET",
    ) -> None:
        self._threads  = threads
        self._timeout  = timeout
        self._method   = method.upper()
        self._lock     = threading.Lock()

        self._session = requests.Session()
        retry = Retry(total=1, backoff_factor=0.2)
        adapter = HTTPAdapter(max_retries=retry,
                              pool_connections=threads,
                              pool_maxsize=threads)
        self._session.mount("http://",  adapter)
        self._session.mount("https://", adapter)
        self._session.headers.update({
            "User-Agent": user_agent,
            "Accept":     "application/json, text/html, */*",
            "Content-Type": "application/json",
        })

    # ------------------------------------------------------------------
    # 1. Découverte de paramètres
    # ------------------------------------------------------------------

    def discover_params(
        self,
        url:      str,
        wordlist: Optional[list[str]] = None,
    ) -> EndpointAnalysis:
        """
        Sonde un endpoint pour détecter les paramètres qu'il accepte.

        Stratégie : on envoie chaque paramètre avec une valeur de test
        et on regarde si la réponse change (taille, status, contenu).

        Args:
            url:      URL de l'endpoint (ex: http://monitorsfour.htb/user)
            wordlist: paramètres à tester (défaut: COMMON_PARAMS)

        Returns:
            EndpointAnalysis avec les paramètres détectés
        """
        params = wordlist or COMMON_PARAMS
        info(f"[bold]Param Discovery[/bold] — {len(params)} paramètres → [cyan]{url}[/cyan]")

        # Réponse de référence (sans paramètre)
        baseline = self._request(url, {})
        baseline_body   = (baseline.text[:512] if baseline else "")
        baseline_status = (baseline.status_code if baseline else 0)
        baseline_length = (len(baseline.content) if baseline else 0)

        info(f"Référence : HTTP {baseline_status}, {baseline_length} B  "
             f"→ [dim]{baseline_body[:80].strip()}[/dim]")

        # Extraction des hints depuis le message d'erreur de référence
        hints = self._extract_param_hints(baseline_body)
        if hints:
            info(f"Paramètres suggérés par le serveur : [yellow]{', '.join(hints)}[/yellow]")

        analysis = EndpointAnalysis(
            url=url,
            baseline_status=baseline_status,
            baseline_body=baseline_body,
            param_hints=hints,
        )

        detected: list[str] = list(hints)  # on inclut les hints directs

        with console.status(
            f"[cyan]Découverte de paramètres… 0/{len(params)}[/cyan]", spinner="dots"
        ) as status:
            done = 0
            for param in params:
                done += 1
                if done % 20 == 0:
                    status.update(f"[cyan]Découverte de paramètres… {done}/{len(params)}[/cyan]")

                for probe_val in PROBE_VALUES[:3]:  # test rapide, 3 valeurs
                    resp = self._request(url, {param: probe_val})
                    if resp is None:
                        continue

                    size_diff   = abs(len(resp.content) - baseline_length)
                    status_diff = resp.status_code != baseline_status
                    body_diff   = resp.text[:200] != baseline_body[:200]

                    if (size_diff > 20 or status_diff or body_diff) and param not in detected:
                        detected.append(param)
                        break  # un seul hit suffit pour marquer le param

        analysis.detected_params = detected
        if detected:
            success(f"{len(detected)} paramètre(s) détecté(s) : [yellow]{', '.join(detected)}[/yellow]")
        else:
            info("Aucun paramètre détecté automatiquement.")

        return analysis

    # ------------------------------------------------------------------
    # 2. Fuzzing d'un paramètre avec une wordlist
    # ------------------------------------------------------------------

    def fuzz_param(
        self,
        url:      str,
        param:    str,
        values:   list[str],
        filter_same_size: bool = True,
    ) -> ParamFuzzResult:
        """
        Teste une liste de valeurs sur un paramètre donné.

        Args:
            url:              URL de base
            param:            nom du paramètre (ex: "token")
            values:           valeurs à tester
            filter_same_size: filtre les réponses de même taille que la baseline
        """
        info(f"[bold]Param Fuzzer[/bold] — param=[yellow]{param}[/yellow], "
             f"{len(values)} valeurs → [cyan]{url}[/cyan]")

        result = ParamFuzzResult(target_url=url, param=param, total_tested=len(values))

        # Baseline
        baseline_resp = self._request(url, {param: "PENTOOL_BASELINE_XYZ"})
        baseline_size = len(baseline_resp.content) if baseline_resp else -1

        start = time.time()
        with console.status(
            f"[cyan]Fuzzing {param}… 0/{len(values)}[/cyan]", spinner="dots"
        ) as status:
            with ThreadPoolExecutor(max_workers=self._threads) as pool:
                futures = {
                    pool.submit(self._request, url, {param: v}): v
                    for v in values
                }
                done = 0
                for future in as_completed(futures):
                    done += 1
                    value = futures[future]
                    if done % 50 == 0:
                        status.update(f"[cyan]Fuzzing {param}… {done}/{len(values)}[/cyan]")

                    resp = future.result()
                    if resp is None:
                        continue

                    body    = resp.text[:512]
                    size    = len(resp.content)
                    is_int  = any(p.search(body) for p in INTERESTING_PATTERNS)
                    is_diff = abs(size - baseline_size) > 20

                    # Filtrer les réponses identiques à la baseline
                    if filter_same_size and not is_diff and not is_int:
                        continue

                    hit = ParamHit(
                        url=f"{url}?{param}={value}",
                        param=param,
                        value=value,
                        status_code=resp.status_code,
                        content_length=size,
                        content_type=resp.headers.get("Content-Type","").split(";")[0].strip(),
                        response_body=body,
                        is_interesting=is_int,
                        note="⭐ Données sensibles détectées" if is_int else "",
                    )
                    with self._lock:
                        result.hits.append(hit)

        result.scan_time = time.time() - start

        interesting = result.interesting_hits
        if interesting:
            success(f"[danger]{len(interesting)}[/danger] réponse(s) avec données sensibles !")
            for h in interesting[:5]:
                info(f"  ⭐ {h.url} → HTTP {h.status_code}")
                info(f"     [dim]{h.response_body[:120].strip()}[/dim]")
        elif result.hits:
            info(f"{len(result.hits)} réponse(s) différente(s) trouvée(s).")
        else:
            info("Aucune réponse différente de la baseline.")

        return result

    # ------------------------------------------------------------------
    # 3. Fuzzing par plage numérique (IDOR typique)
    # ------------------------------------------------------------------

    def fuzz_range(
        self,
        url:    str,
        param:  str,
        start:  int = 0,
        end:    int = 500,
        step:   int = 1,
    ) -> ParamFuzzResult:
        """
        Teste une plage de valeurs numériques sur un paramètre.
        Idéal pour détecter les IDOR (Insecure Direct Object Reference).

        Ex: /user?id=0 … /user?id=500

        Args:
            url:   URL de base
            param: nom du paramètre
            start: valeur de début
            end:   valeur de fin (incluse)
            step:  pas
        """
        values = [str(i) for i in range(start, end + 1, step)]
        info(f"[bold]Range Fuzzer[/bold] — {param}={start}…{end} ({len(values)} valeurs)")
        return self.fuzz_param(url, param, values)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _request(self, url: str, params: dict) -> Optional[requests.Response]:
        try:
            if self._method == "GET":
                return self._session.get(
                    url, params=params,
                    timeout=self._timeout, allow_redirects=True,
                )
            else:
                return self._session.post(
                    url, json=params,
                    timeout=self._timeout, allow_redirects=True,
                )
        except Exception:
            return None

    @staticmethod
    def _extract_param_hints(body: str) -> list[str]:
        """
        Extrait les noms de paramètres depuis un message d'erreur JSON.

        Ex: {"error": "Missing token parameter"} → ["token"]
        Ex: {"message": "field 'id' is required"} → ["id"]
        """
        if not body:
            return []
        hints = []
        # Pattern: "Missing X parameter" / "X is required" / "provide X"
        patterns = [
            r'"[^"]*[Mm]issing\s+(\w+)[^"]*"',
            r'"[^"]*(\w+)\s+(?:is\s+)?required[^"]*"',
            r'"[^"]*[Pp]rovide\s+(\w+)[^"]*"',
            r'"[^"]*[Ff]ield\s+[\'"]?(\w+)[\'"]?\s+[^"]*"',
            r'"[^"]*[Pp]arameter\s+[\'"]?(\w+)[\'"]?[^"]*"',
            r"[Mm]issing\s+(?:parameter\s+)?['\"]?(\w+)['\"]?",
            r"[Pp]arameter\s+['\"]?(\w+)['\"]?\s+(?:is\s+)?(?:required|missing)",
        ]
        for pat in patterns:
            for m in re.finditer(pat, body):
                word = m.group(1).lower()
                if len(word) > 1 and word not in hints:
                    hints.append(word)
        return hints[:5]