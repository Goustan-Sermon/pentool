"""
Module de scan de ports et détection de services via python-nmap.

Utilisation :
    scanner = PortScanner()
    results = scanner.scan("192.168.1.1", profile="standard")
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Optional

import nmap

from pentool.utils import console, info, warning, error, success


# ──────────────────────────────────────────────
# Profils de scan (arguments nmap)
# ──────────────────────────────────────────────

SCAN_PROFILES: dict[str, dict] = {
    # Rapide : top 100 ports, détection de service
    "fast": {
        "args": "-sV -sC --top-ports 100 -T4 -O --osscan-limit",
        "label": "Fast (top 100 ports)",
    },
    # Standard : top 1000 ports (défaut nmap)
    "standard": {
        "args": "-sV -sC -T3 -O --osscan-limit",
        "label": "Standard (top 1000 ports)",
    },
    # Complet : tous les ports, plus lent
    "full": {
        "args": "-sV -sC -p- -T3 -O",
        "label": "Full (all 65535 ports)",
    },
    # Furtif : SYN scan sans scripts
    "stealth": {
        "args": "-sS -sV -T2 --top-ports 500",
        "label": "Stealth SYN scan",
    },
    # UDP (nécessite root)
    "udp": {
        "args": "-sU -sV --top-ports 50 -T3",
        "label": "UDP top 50 ports",
    },
}


# ──────────────────────────────────────────────
# Modèles de données
# ──────────────────────────────────────────────

@dataclass
class ServiceInfo:
    """Représente un service détecté sur un port."""
    port:      int
    protocol:  str                 # tcp / udp
    state:     str                 # open / closed / filtered
    service:   str                 # http, ssh, ftp …
    product:   str                 # Apache httpd, OpenSSH …
    version:   str                 # 2.4.49, 8.4p1 …
    extrainfo: str                 # infos additionnelles nmap
    cpe:       list[str] = field(default_factory=list)   # CPE strings

    @property
    def fingerprint(self) -> str:
        """Retourne une chaîne lisible pour la recherche CVE."""
        parts = [p for p in (self.product, self.version) if p]
        return " ".join(parts) if parts else self.service

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HostResult:
    """Résultat complet d'un scan sur un hôte."""
    target:    str
    ip:        str
    hostname:  str
    state:     str                 # up / down
    os_match:  list[dict]         = field(default_factory=list)
    services:  list[ServiceInfo]  = field(default_factory=list)
    scan_args: str                 = ""
    scan_time: str                 = ""

    # Raccourcis utiles
    @property
    def open_ports(self) -> list[ServiceInfo]:
        return [s for s in self.services if s.state == "open"]

    @property
    def os_name(self) -> str:
        if self.os_match:
            best = max(self.os_match, key=lambda x: x.get("accuracy", 0))
            return f"{best.get('name', '?')} ({best.get('accuracy', '?')}% accuracy)"
        return "Unknown"

    def to_dict(self) -> dict:
        return {
            "target":    self.target,
            "ip":        self.ip,
            "hostname":  self.hostname,
            "state":     self.state,
            "os_match":  self.os_match,
            "os_name":   self.os_name,
            "scan_args": self.scan_args,
            "scan_time": self.scan_time,
            "services":  [s.to_dict() for s in self.services],
        }


# ──────────────────────────────────────────────
# Scanner principal
# ──────────────────────────────────────────────

class PortScanner:
    """Wrapper autour de python-nmap avec gestion des profils."""

    def __init__(self) -> None:
        try:
            self._nm = nmap.PortScanner()
        except nmap.PortScannerError:
            error("nmap n'est pas installé ou n'est pas dans le PATH.")
            raise

    # ------------------------------------------------------------------
    def scan(
        self,
        target: str,
        profile: str = "standard",
        extra_args: str = "",
        ports: Optional[str] = None,
    ) -> HostResult:
        """
        Lance un scan nmap sur la cible.

        Args:
            target:     IP ou nom de domaine
            profile:    clé dans SCAN_PROFILES
            extra_args: arguments nmap additionnels
            ports:      ports spécifiques (ex: "22,80,443" ou "1-1024")

        Returns:
            HostResult peuplé
        """
        if profile not in SCAN_PROFILES:
            warning(f"Profil '{profile}' inconnu, utilisation de 'standard'.")
            profile = "standard"

        profile_cfg = SCAN_PROFILES[profile]
        args = profile_cfg["args"]
        if extra_args:
            args += f" {extra_args}"
        if ports:
            args += f" -p {ports}"

        info(f"Profil de scan : [bold]{profile_cfg['label']}[/bold]")
        info(f"Arguments nmap : [muted]{args}[/muted]")

        with console.status(
            f"[cyan]Scan de [bold]{target}[/bold] en cours…[/cyan]",
            spinner="dots",
        ):
            try:
                self._nm.scan(hosts=target, arguments=args)
            except nmap.PortScannerError as exc:
                error(f"Erreur nmap : {exc}")
                raise

        return self._parse_results(target)

    # ------------------------------------------------------------------
    def _parse_results(self, target: str) -> HostResult:
        """Transforme les données brutes nmap en HostResult."""
        all_hosts = self._nm.all_hosts()

        if not all_hosts:
            warning(f"Aucun hôte trouvé pour '{target}'. L'hôte est peut-être down ou filtré.")
            return HostResult(
                target=target, ip=target, hostname="", state="down"
            )

        # On prend le premier hôte (la cible principale)
        ip = all_hosts[0]
        nm_host = self._nm[ip]

        # Hostname
        hostnames = nm_host.get("hostnames", [])
        hostname = hostnames[0].get("name", "") if hostnames else ""

        # État de l'hôte
        state = nm_host.get("status", {}).get("state", "unknown")

        # OS detection
        os_matches = []
        if "osmatch" in nm_host:
            for match in nm_host["osmatch"][:3]:  # top 3
                os_matches.append({
                    "name":     match.get("name", ""),
                    "accuracy": match.get("accuracy", ""),
                    "osfamily": match.get("osclass", [{}])[0].get("osfamily", "") if match.get("osclass") else "",
                })

        # Services
        services: list[ServiceInfo] = []
        for proto in nm_host.all_protocols():
            ports = nm_host[proto].keys()
            for port in sorted(ports):
                pdata = nm_host[proto][port]
                cpe_list = []
                if "cpe" in pdata and pdata["cpe"]:
                    cpe_list = [pdata["cpe"]] if isinstance(pdata["cpe"], str) else list(pdata["cpe"])

                svc = ServiceInfo(
                    port=int(port),
                    protocol=proto,
                    state=pdata.get("state", ""),
                    service=pdata.get("name", ""),
                    product=pdata.get("product", ""),
                    version=pdata.get("version", ""),
                    extrainfo=pdata.get("extrainfo", ""),
                    cpe=cpe_list,
                )
                services.append(svc)

        # Infos générales du scan
        scan_info = self._nm.scaninfo()
        scan_stats = self._nm.scanstats()

        return HostResult(
            target=target,
            ip=ip,
            hostname=hostname,
            state=state,
            os_match=os_matches,
            services=services,
            scan_args=self._nm.command_line(),
            scan_time=scan_stats.get("elapsed", ""),
        )

    # ------------------------------------------------------------------
    def list_profiles(self) -> dict[str, str]:
        """Retourne les profils disponibles."""
        return {k: v["label"] for k, v in SCAN_PROFILES.items()}