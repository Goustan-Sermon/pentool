"""
Module d'énumération DNS et WHOIS.

Récupère :
  - Enregistrements A, AAAA, MX, NS, TXT, CNAME, SOA
  - Informations WHOIS (registrar, dates, contacts)
  - Sous-domaines communs (bruteforce passif)
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field, asdict
from typing import Optional

import dns.resolver
import dns.reversename
import whois

from pentool.utils import info, warning, error, console


# ──────────────────────────────────────────────
# Sous-domaines à tester (wordlist intégrée)
# ──────────────────────────────────────────────

COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "sftp",
    "ssh", "vpn", "remote", "rdp", "admin", "portal",
    "api", "dev", "staging", "test", "beta", "demo",
    "app", "cdn", "static", "assets", "media", "img",
    "blog", "shop", "store", "forum", "wiki", "docs",
    "git", "gitlab", "github", "jenkins", "ci", "build",
    "monitor", "status", "log", "logs", "backup",
    "db", "database", "mysql", "postgres", "redis",
    "internal", "intranet", "corp", "office", "support",
    "ns1", "ns2", "dns", "mx", "mx1", "mx2",
    "webmail", "autodiscover", "exchange", "owa", "cacti",
]


# ──────────────────────────────────────────────
# Modèles de données
# ──────────────────────────────────────────────

@dataclass
class DNSRecord:
    rtype:  str   # A, AAAA, MX, NS, TXT, CNAME, SOA …
    value:  str
    ttl:    int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SubdomainResult:
    subdomain: str
    ip:        str
    cname:     str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DNSEnumResult:
    target:     str
    records:    list[DNSRecord]       = field(default_factory=list)
    subdomains: list[SubdomainResult] = field(default_factory=list)
    whois_data: dict                  = field(default_factory=dict)
    reverse_ptr: str                  = ""

    def to_dict(self) -> dict:
        return {
            "target":      self.target,
            "reverse_ptr": self.reverse_ptr,
            "records":     [r.to_dict() for r in self.records],
            "subdomains":  [s.to_dict() for s in self.subdomains],
            "whois_data":  self.whois_data,
        }


# ──────────────────────────────────────────────
# Classe principale
# ──────────────────────────────────────────────

class DNSEnumerator:
    """Énumération DNS complète d'une cible."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]

    def __init__(self, timeout: float = 3.0) -> None:
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        self._resolver.timeout  = timeout

    # ------------------------------------------------------------------
    def enumerate(
        self,
        target: str,
        do_whois: bool = True,
        do_subdomains: bool = True,
        custom_wordlist: Optional[list[str]] = None,
    ) -> DNSEnumResult:
        """
        Lance l'énumération complète sur la cible.

        Args:
            target:          domaine ou IP
            do_whois:        activer la recherche WHOIS
            do_subdomains:   activer la recherche de sous-domaines
            custom_wordlist: liste custom (remplace COMMON_SUBDOMAINS)
        """
        result = DNSEnumResult(target=target)

        # 1. Enregistrements DNS standards
        info(f"[bold]DNS[/bold] — Résolution des enregistrements pour [cyan]{target}[/cyan]")
        result.records = self._fetch_all_records(target)

        # 2. PTR (reverse DNS si IP)
        if self._is_ip(target):
            result.reverse_ptr = self._reverse_lookup(target)

        # 3. WHOIS
        if do_whois and not self._is_ip(target):
            info("[bold]WHOIS[/bold] — Récupération des informations registrar…")
            result.whois_data = self._fetch_whois(target)

        # 4. Sous-domaines
        if do_subdomains and not self._is_ip(target):
            wordlist = custom_wordlist or COMMON_SUBDOMAINS
            info(f"[bold]Sous-domaines[/bold] — Test de {len(wordlist)} sous-domaines…")
            result.subdomains = self._bruteforce_subdomains(target, wordlist)

        return result

    # ------------------------------------------------------------------
    def _fetch_all_records(self, domain: str) -> list[DNSRecord]:
        records: list[DNSRecord] = []
        for rtype in self.RECORD_TYPES:
            try:
                answers = self._resolver.resolve(domain, rtype)
                for rdata in answers:
                    val = str(rdata)
                    records.append(DNSRecord(rtype=rtype, value=val, ttl=answers.ttl))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except dns.resolver.Timeout:
                warning(f"Timeout pour le type {rtype}")
            except Exception:
                pass
        return records

    # ------------------------------------------------------------------
    def _reverse_lookup(self, ip: str) -> str:
        try:
            rev = dns.reversename.from_address(ip)
            answers = self._resolver.resolve(rev, "PTR")
            return str(answers[0])
        except Exception:
            return ""

    # ------------------------------------------------------------------
    def _fetch_whois(self, domain: str) -> dict:
        try:
            w = whois.whois(domain)
            # Sérialisation manuelle pour éviter les types non-JSON
            data: dict = {}
            for key, val in w.items():
                if val is None:
                    continue
                if isinstance(val, list):
                    data[key] = [str(v) for v in val if v]
                else:
                    data[key] = str(val)
            return data
        except Exception as exc:
            warning(f"WHOIS indisponible : {exc}")
            return {}

    # ------------------------------------------------------------------
    def _bruteforce_subdomains(
        self, domain: str, wordlist: list[str]
    ) -> list[SubdomainResult]:
        found: list[SubdomainResult] = []
        with console.status("[cyan]Énumération des sous-domaines…[/cyan]", spinner="dots"):
            for sub in wordlist:
                fqdn = f"{sub}.{domain}"
                try:
                    answers = self._resolver.resolve(fqdn, "A")
                    ip = str(answers[0])
                    # Vérifier si c'est un CNAME
                    cname = ""
                    try:
                        cnames = self._resolver.resolve(fqdn, "CNAME")
                        cname = str(cnames[0])
                    except Exception:
                        pass
                    found.append(SubdomainResult(subdomain=fqdn, ip=ip, cname=cname))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    pass
                except Exception:
                    pass
        return found

    # ------------------------------------------------------------------
    @staticmethod
    def _is_ip(target: str) -> bool:
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, target)
                return True
            except socket.error:
                return False