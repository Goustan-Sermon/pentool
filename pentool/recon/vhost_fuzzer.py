"""
Module de Virtual Host (vhost) fuzzing.

Contrairement au DNS bruteforce classique, cette technique envoie
des requêtes HTTP avec un en-tête Host: modifié pour découvrir des
virtual hosts qui ne sont pas dans le DNS public mais configurés
sur le serveur (typique en CTF / HackTheBox).

Exemple : Host: cacti.monitorsfour.htb → page différente de l'index

Stratégie anti-faux-positifs :
  1. On récupère la réponse de référence (Host: <IP>)
  2. On compare chaque réponse à cette référence
  3. Si taille différente OU status différent → vhost trouvé
"""

from __future__ import annotations

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from pentool.utils import info, warning, success, error, console


# ──────────────────────────────────────────────
# Wordlist vhosts intégrée
# ──────────────────────────────────────────────

VHOST_WORDLIST: list[str] = [
    # Monitoring / infra
    "cacti", "zabbix", "nagios", "grafana", "kibana", "prometheus",
    "netdata", "icinga", "observium", "monit", "uptimekuma",
    # Admin / gestion
    "admin", "administrator", "portal", "management", "console",
    "control", "panel", "controlpanel", "manager", "backend",
    # Dev / CI
    "dev", "development", "staging", "test", "testing", "beta",
    "preprod", "uat", "sandbox", "demo", "preview",
    "git", "gitlab", "github", "gitea", "gogs", "bitbucket",
    "jenkins", "ci", "build", "deploy", "drone", "travis",
    "sonar", "sonarqube", "nexus", "artifactory",
    # Réseau / sécurité
    "vpn", "remote", "rdp", "ssh", "fw", "firewall",
    "proxy", "gateway", "router", "ns", "ns1", "ns2",
    # Web / apps
    "www", "web", "app", "api", "rest", "graphql",
    "mobile", "m", "wap", "cdn", "static", "assets",
    # Mail
    "mail", "smtp", "pop", "imap", "mx", "mx1", "mx2",
    "webmail", "exchange", "owa", "autodiscover",
    # Base de données / stockage
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "elastic", "elasticsearch", "solr", "phpmyadmin", "pma",
    "adminer", "pgadmin",
    # Collaboration
    "wiki", "confluence", "jira", "redmine", "gitlab",
    "docs", "documentation", "kb", "helpdesk", "support",
    "forum", "community", "blog",
    # Cloud / infra
    "cloud", "storage", "backup", "files", "ftp", "sftp",
    "vault", "secret", "keycloak", "auth", "sso", "ldap",
    "internal", "intranet", "corp", "office", "private",
    # Spécifiques CTF / HTB
    "shop", "store", "payment", "cart", "crm", "erp",
    "hr", "helpdesk", "ticket", "chat", "status",
    "monitor", "dashboard", "report", "analytics",
]


# ──────────────────────────────────────────────
# Modèles de données
# ──────────────────────────────────────────────

@dataclass
class VHostResult:
    """Un virtual host découvert."""
    vhost:          str         # ex: cacti.monitorsfour.htb
    subdomain:      str         # ex: cacti
    base_domain:    str         # ex: monitorsfour.htb
    ip:             str
    status_code:    int
    content_length: int
    title:          str = ""    # <title> HTML si trouvé
    redirect_url:   str = ""
    content_type:   str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VHostScanResult:
    """Résultat global du vhost fuzzing."""
    target_ip:    str
    base_domain:  str
    total_tested: int = 0
    found:        list[VHostResult] = field(default_factory=list)
    scan_time:    float = 0.0

    def to_dict(self) -> dict:
        return {
            "target_ip":    self.target_ip,
            "base_domain":  self.base_domain,
            "total_tested": self.total_tested,
            "found_count":  len(self.found),
            "scan_time":    round(self.scan_time, 2),
            "found":        [v.to_dict() for v in self.found],
        }


# ──────────────────────────────────────────────
# Scanner principal
# ──────────────────────────────────────────────

class VHostFuzzer:
    """
    Fuzzer de virtual hosts HTTP.

    Envoie des requêtes avec Host: <subdomain>.<domain> et compare
    à la réponse de référence pour détecter les vhosts configurés.
    """

    def __init__(
        self,
        threads:  int   = 10,
        timeout:  float = 5.0,
        user_agent: str = "Pentool/0.1 VHost-Fuzzer (ISEN)",
    ) -> None:
        self._threads    = threads
        self._timeout    = timeout
        self._lock       = threading.Lock()

        self._session = requests.Session()
        retry = Retry(total=1, backoff_factor=0.2)
        adapter = HTTPAdapter(max_retries=retry,
                              pool_connections=threads,
                              pool_maxsize=threads)
        self._session.mount("http://",  adapter)
        self._session.mount("https://", adapter)
        self._session.headers.update({
            "User-Agent": user_agent,
            "Accept":     "text/html,application/json,*/*",
        })

    # ------------------------------------------------------------------
    def fuzz(
        self,
        target_ip:   str,
        base_domain: str,
        wordlist:    Optional[list[str]] = None,
        port:        int                 = 80,
        use_https:   bool                = False,
    ) -> VHostScanResult:
        """
        Lance le vhost fuzzing.

        Args:
            target_ip:   IP du serveur cible
            base_domain: domaine de base (ex: monitorsfour.htb)
            wordlist:    liste de sous-domaines à tester
            port:        port HTTP (défaut 80)
            use_https:   utiliser HTTPS

        Returns:
            VHostScanResult avec les vhosts découverts
        """
        scheme   = "https" if use_https else "http"
        words    = wordlist or VHOST_WORDLIST
        result   = VHostScanResult(target_ip=target_ip, base_domain=base_domain)
        base_url = f"{scheme}://{target_ip}"
        if port not in (80, 443):
            base_url += f":{port}"

        info(f"[bold]VHost Fuzzer[/bold] — base domain : [cyan]{base_domain}[/cyan]")
        info(f"IP cible : [cyan]{target_ip}[/cyan]  |  {len(words)} sous-domaines à tester")

        # 1. Réponses de référence — deux sondes pour détecter les catchalls
        # Sonde A : Host = IP brute (comportement par défaut du serveur)
        ref_a = self._get_reference(base_url, target_ip)
        if ref_a is None:
            error(f"Impossible de joindre {base_url} — vhost fuzzing abandonné.")
            return result

        # Sonde B : sous-domaine aléatoire improbable (détecte le wildcard DNS)
        ref_b = self._get_reference(base_url, f"pentool-nonexistent-xyz123.{base_domain}")

        ref_status_a = ref_a.get("status", 0)
        ref_size_a   = ref_a.get("length", -1)
        ref_status_b = ref_b.get("status", 0) if ref_b else ref_status_a
        ref_size_b   = ref_b.get("length", -1) if ref_b else ref_size_a

        info(f"Réponse de référence (IP)      : HTTP {ref_status_a}, {ref_size_a} B")
        info(f"Réponse de référence (wildcard): HTTP {ref_status_b}, {ref_size_b} B")

        def _is_vhost_false_positive(r: VHostResult) -> bool:
            """
            Filtre multi-niveau :
              1. Même status ET même taille que la référence IP → faux positif
              2. Même status ET même taille que le wildcard    → faux positif
              3. Code 404 avec taille identique à tous les autres 404 → faux positif (catchall)
            """
            # Tolérance taille : 10 B
            tol = 10

            # Comparer avec référence IP
            if (r.status_code == ref_status_a
                    and abs(r.content_length - ref_size_a) <= tol):
                return True

            # Comparer avec wildcard
            if (r.status_code == ref_status_b
                    and abs(r.content_length - ref_size_b) <= tol):
                return True

            return False

        # 2. Fuzzing parallèle
        start    = time.time()
        done     = 0
        total    = len(words)
        raw_results: list[VHostResult] = []

        with console.status(
            f"[cyan]VHost fuzzing… 0/{total}[/cyan]", spinner="dots"
        ) as status:
            with ThreadPoolExecutor(max_workers=self._threads) as pool:
                futures = {
                    pool.submit(self._probe, base_url, sub, base_domain): sub
                    for sub in words
                }
                for future in as_completed(futures):
                    done += 1
                    if done % 10 == 0:
                        status.update(f"[cyan]VHost fuzzing… {done}/{total}[/cyan]")
                    vhost_res = future.result()
                    if vhost_res:
                        raw_results.append(vhost_res)

        # 3. Anti-faux-positifs niveau 2 :
        #    Grouper par (status_code, content_length) et rejeter les groupes
        #    qui représentent >30% des résultats (comportement catchall)
        from collections import Counter
        size_groups = Counter(
            (r.status_code, r.content_length) for r in raw_results
        )
        catchall_threshold = max(3, total * 0.20)  # plus de 20% = catchall

        for r in raw_results:
            key = (r.status_code, r.content_length)
            if _is_vhost_false_positive(r):
                continue
            if size_groups[key] > catchall_threshold:
                continue
            # Codes non intéressants (404 inconnus non confirmés)
            if r.status_code == 404 and size_groups[key] > 2:
                continue
            with self._lock:
                result.found.append(r)

        result.total_tested = total
        result.scan_time    = time.time() - start

        if result.found:
            success(f"{len(result.found)} vhost(s) découvert(s) !")
            for v in result.found:
                info(f"  ✔ [cyan]{v.vhost}[/cyan] → HTTP {v.status_code} ({v.content_length} B)")
        else:
            info("Aucun vhost réel détecté (tous les résultats filtrés comme catchall).")

        return result

    # ------------------------------------------------------------------
    def _probe(self, base_url: str, subdomain: str, domain: str) -> Optional[VHostResult]:
        """Teste un vhost et retourne un VHostResult ou None."""
        vhost = f"{subdomain}.{domain}"
        try:
            resp = self._session.get(
                base_url,
                headers={"Host": vhost},
                timeout=self._timeout,
                allow_redirects=False,
            )
            length = int(resp.headers.get("Content-Length", len(resp.content)))
            title  = self._extract_title(resp.text)
            return VHostResult(
                vhost=vhost,
                subdomain=subdomain,
                base_domain=domain,
                ip=base_url.split("//")[-1].split(":")[0],
                status_code=resp.status_code,
                content_length=length,
                title=title,
                redirect_url=resp.headers.get("Location", ""),
                content_type=resp.headers.get("Content-Type", "").split(";")[0].strip(),
            )
        except Exception:
            return None

    def _get_reference(self, base_url: str, host: str) -> Optional[dict]:
        """Récupère la réponse de référence (Host = IP)."""
        try:
            resp = self._session.get(
                base_url,
                headers={"Host": host},
                timeout=self._timeout,
                allow_redirects=False,
            )
            return {
                "status": resp.status_code,
                "length": int(resp.headers.get("Content-Length", len(resp.content))),
            }
        except Exception:
            return None

    @staticmethod
    def _extract_title(html: str) -> str:
        """Extrait le <title> d'une page HTML."""
        import re
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip()[:80] if m else ""