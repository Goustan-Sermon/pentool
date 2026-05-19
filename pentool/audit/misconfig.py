"""
Détection de misconfigurations — Phase 3.

Checks passifs et semi-actifs :
  - Headers HTTP de sécurité manquants
  - Répertoires listés
  - Fichiers sensibles accessibles (.git, .env, backup…)
  - Accès anonyme FTP
  - MySQL sans authentification
  - SSL/TLS : protocoles et certificats
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

from pentool.utils import info, warning, success


# ──────────────────────────────────────────────
# Modèles de données
# ──────────────────────────────────────────────

@dataclass
class MisconfigFinding:
    """Une misconfiguration détectée."""
    check_name:  str
    severity:    str          # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    target:      str
    description: str
    evidence:    str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MisconfigReport:
    """Rapport complet des misconfigurations."""
    target:   str
    findings: list[MisconfigFinding] = field(default_factory=list)

    @property
    def critical(self) -> list[MisconfigFinding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]

    @property
    def high(self) -> list[MisconfigFinding]:
        return [f for f in self.findings if f.severity == "HIGH"]

    def to_dict(self) -> dict:
        return {
            "target":          self.target,
            "total":           len(self.findings),
            "critical_count":  len(self.critical),
            "high_count":      len(self.high),
            "findings":        [f.to_dict() for f in self.findings],
        }


# ──────────────────────────────────────────────
# Checker principal
# ──────────────────────────────────────────────

class MisconfigChecker:
    """Lance tous les checks de misconfiguration sur une cible."""

    def __init__(self, timeout: float = 6.0) -> None:
        self._timeout = timeout
        self._session = requests.Session()
        adapter = HTTPAdapter(max_retries=1)
        self._session.mount("http://",  adapter)
        self._session.mount("https://", adapter)
        self._session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    # ------------------------------------------------------------------
    def check_http(self, url: str, host_header: Optional[str] = None) -> MisconfigReport:
        """Lance tous les checks HTTP sur une URL."""
        target  = host_header or url
        report  = MisconfigReport(target=target)
        headers = {"Host": host_header} if host_header else {}

        info(f"  [cyan]Misconfig check HTTP[/cyan] → {target}")

        try:
            resp = self._session.get(
                url, headers=headers,
                timeout=self._timeout, allow_redirects=True,
            )
        except Exception as e:
            warning(f"  Impossible de joindre {url} : {e}")
            return report

        report.findings += self._check_security_headers(resp, target)
        report.findings += self._check_sensitive_files(url, headers, target)
        report.findings += self._check_directory_listing(url, headers, target)

        return report

    def check_ftp(self, ip: str, port: int = 21) -> MisconfigReport:
        """Vérifie l'accès anonyme FTP."""
        report = MisconfigReport(target=f"{ip}:{port}")
        info(f"  [cyan]FTP anonymous check[/cyan] → {ip}:{port}")

        try:
            s = socket.create_connection((ip, port), timeout=self._timeout)
            banner = s.recv(1024).decode("utf-8", errors="replace")

            s.sendall(b"USER anonymous\r\n")
            time.sleep(0.3)
            r1 = s.recv(1024).decode("utf-8", errors="replace")

            s.sendall(b"PASS anonymous@pentest.local\r\n")
            time.sleep(0.5)
            r2 = s.recv(1024).decode("utf-8", errors="replace")
            s.sendall(b"QUIT\r\n")
            s.close()

            if "230" in r2:
                report.findings.append(MisconfigFinding(
                    check_name  = "FTP Anonymous Login",
                    severity    = "HIGH",
                    target      = f"{ip}:{port}",
                    description = "Le serveur FTP autorise les connexions anonymes.",
                    evidence    = f"Banner: {banner.strip()[:80]}\nRéponse: {r2.strip()[:80]}",
                    remediation = "Désactiver l'accès anonyme dans la configuration FTP "
                                  "(anonymous_enable=NO pour vsftpd).",
                ))
                warning(f"  FTP anonymous login autorisé sur {ip}:{port}")
            else:
                info(f"  FTP : accès anonyme refusé — OK")

        except Exception as e:
            info(f"  FTP inaccessible : {e}")

        return report

    def check_mysql(self, ip: str, port: int = 3306) -> MisconfigReport:
        """Vérifie si MySQL est accessible sans authentification ou depuis l'extérieur."""
        report = MisconfigReport(target=f"{ip}:{port}")
        info(f"  [cyan]MySQL exposure check[/cyan] → {ip}:{port}")

        try:
            s = socket.create_connection((ip, port), timeout=self._timeout)
            handshake = s.recv(4096)
            s.close()

            if handshake and len(handshake) > 5:
                # Extraire la version
                try:
                    ver_end = handshake.index(b'\x00', 5)
                    version = handshake[5:ver_end].decode("ascii", errors="replace")
                except Exception:
                    version = "inconnue"

                report.findings.append(MisconfigFinding(
                    check_name  = "MySQL Port Exposed",
                    severity    = "MEDIUM",
                    target      = f"{ip}:{port}",
                    description = f"Le port MySQL ({port}) est accessible depuis l'extérieur.",
                    evidence    = f"Version MySQL : {version}",
                    remediation = "Restreindre l'accès MySQL aux seules connexions locales "
                                  "(bind-address = 127.0.0.1) ou via firewall.",
                ))
                info(f"  MySQL exposé : version {version}")

        except Exception:
            info(f"  MySQL inaccessible depuis l'extérieur — OK")

        return report

    def check_ssl(self, ip: str, port: int = 443,
                  host: Optional[str] = None) -> MisconfigReport:
        """Vérifie le certificat TLS et les protocoles."""
        report = MisconfigReport(target=f"{ip}:{port}")
        info(f"  [cyan]SSL/TLS check[/cyan] → {ip}:{port}")
        hostname = host or ip

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=self._timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                    cert    = tls.getpeercert()
                    version = tls.version()
                    cipher  = tls.cipher()

            # Vérification expiration
            if cert and "notAfter" in cert:
                expire_str = cert["notAfter"]
                try:
                    expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    if expire_dt < datetime.utcnow():
                        report.findings.append(MisconfigFinding(
                            check_name  = "TLS Certificate Expired",
                            severity    = "HIGH",
                            target      = f"{ip}:{port}",
                            description = "Le certificat TLS est expiré.",
                            evidence    = f"Expiré le : {expire_str}",
                            remediation = "Renouveler le certificat TLS (Let's Encrypt, certbot).",
                        ))
                except Exception:
                    pass

            # Vérification protocole faible
            if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                report.findings.append(MisconfigFinding(
                    check_name  = f"Weak TLS Protocol ({version})",
                    severity    = "HIGH",
                    target      = f"{ip}:{port}",
                    description = f"Protocole TLS obsolète utilisé : {version}",
                    evidence    = f"Protocole négocié : {version}, Cipher : {cipher}",
                    remediation = "Désactiver SSLv2, SSLv3, TLS 1.0 et TLS 1.1. "
                                  "Forcer TLS 1.2 minimum (TLS 1.3 recommandé).",
                ))

            if not report.findings:
                info(f"  TLS OK : {version}, cipher {cipher[0] if cipher else '?'}")

        except Exception as e:
            info(f"  SSL/TLS non disponible sur {ip}:{port} : {e}")

        return report

    # ------------------------------------------------------------------
    # Checks HTTP internes
    # ------------------------------------------------------------------

    def _check_security_headers(
        self, resp: requests.Response, target: str
    ) -> list[MisconfigFinding]:
        """Vérifie les headers de sécurité HTTP manquants."""
        findings = []
        h = {k.lower(): v for k, v in resp.headers.items()}

        checks = [
            (
                "Strict-Transport-Security",
                "strict-transport-security",
                "MEDIUM",
                "Header HSTS manquant — les connexions HTTP ne sont pas forcées en HTTPS.",
                "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains",
            ),
            (
                "X-Frame-Options",
                "x-frame-options",
                "MEDIUM",
                "Header X-Frame-Options manquant — risque de clickjacking.",
                "Ajouter : X-Frame-Options: DENY ou SAMEORIGIN",
            ),
            (
                "X-Content-Type-Options",
                "x-content-type-options",
                "LOW",
                "Header X-Content-Type-Options manquant — risque de MIME sniffing.",
                "Ajouter : X-Content-Type-Options: nosniff",
            ),
            (
                "Content-Security-Policy",
                "content-security-policy",
                "MEDIUM",
                "Header Content-Security-Policy manquant — risque XSS élevé.",
                "Définir une politique CSP adaptée à l'application.",
            ),
            (
                "Referrer-Policy",
                "referrer-policy",
                "LOW",
                "Header Referrer-Policy manquant.",
                "Ajouter : Referrer-Policy: strict-origin-when-cross-origin",
            ),
        ]

        # Vérifier aussi les headers qui révèlent trop d'infos
        if "server" in h and len(h["server"]) > 5:
            findings.append(MisconfigFinding(
                check_name  = "Server Header Information Disclosure",
                severity    = "LOW",
                target      = target,
                description = f"Le header Server révèle des informations de version.",
                evidence    = f"Server: {h['server']}",
                remediation = "Masquer ou minimaliser le header Server dans la config du serveur web.",
            ))

        if "x-powered-by" in h:
            findings.append(MisconfigFinding(
                check_name  = "X-Powered-By Information Disclosure",
                severity    = "LOW",
                target      = target,
                description = "Le header X-Powered-By révèle la stack applicative.",
                evidence    = f"X-Powered-By: {h['x-powered-by']}",
                remediation = "Supprimer le header X-Powered-By (header_remove X-Powered-By pour Apache).",
            ))

        # Headers manquants (seulement pour les pages HTML, pas les assets)
        ct = h.get("content-type", "")
        if "text/html" in ct:
            for name, key, sev, desc, remed in checks:
                if key not in h:
                    findings.append(MisconfigFinding(
                        check_name  = f"Missing {name}",
                        severity    = sev,
                        target      = target,
                        description = desc,
                        remediation = remed,
                    ))

        return findings

    def _check_sensitive_files(
        self, base_url: str, headers: dict, target: str
    ) -> list[MisconfigFinding]:
        """Vérifie l'accès à des fichiers sensibles courants."""
        findings = []

        sensitive = [
            ("/.git/config",        "CRITICAL", "Dépôt Git exposé",
             "Le fichier .git/config est accessible — le code source peut être téléchargé.",
             "Bloquer l'accès au répertoire .git via la config du serveur web."),
            ("/.env",               "CRITICAL", "Fichier .env exposé",
             "Le fichier .env contenant les secrets d'environnement est accessible.",
             "Bloquer l'accès aux fichiers .env et les exclure du document root."),
            ("/backup.zip",         "HIGH",     "Archive de backup exposée",
             "Une archive de backup est accessible publiquement.",
             "Supprimer les archives de backup du document root."),
            ("/dump.sql",           "CRITICAL", "Dump SQL exposé",
             "Un dump de base de données est accessible publiquement.",
             "Supprimer les dumps SQL du document root."),
            ("/config.php",         "HIGH",     "Fichier de configuration PHP exposé",
             "Un fichier de configuration PHP est accessible.",
             "Déplacer les fichiers de config hors du document root."),
            ("/phpinfo.php",        "MEDIUM",   "phpinfo() accessible",
             "Une page phpinfo() exposée révèle la configuration PHP complète.",
             "Supprimer ou restreindre l'accès aux pages phpinfo."),
            ("/server-status",      "MEDIUM",   "Apache server-status exposé",
             "La page de statut Apache est accessible et révèle les connexions actives.",
             "Restreindre /server-status aux seules IP autorisées."),
            ("/actuator/env",       "HIGH",     "Spring Actuator /env exposé",
             "L'endpoint Spring Actuator /env révèle les variables d'environnement.",
             "Sécuriser les endpoints Actuator avec authentification ou les désactiver."),
            ("/actuator/heapdump",  "CRITICAL", "Spring Actuator heapdump exposé",
             "Le heapdump JVM peut contenir des credentials en clair.",
             "Désactiver l'endpoint heapdump en production."),
        ]

        for path, sev, name, desc, remed in sensitive:
            url = base_url.rstrip("/") + path
            try:
                resp = self._session.get(
                    url, headers=headers,
                    timeout=self._timeout, allow_redirects=False,
                )
                if resp.status_code == 200 and len(resp.content) > 10:
                    findings.append(MisconfigFinding(
                        check_name  = name,
                        severity    = sev,
                        target      = target,
                        description = desc,
                        evidence    = f"HTTP 200 sur {path} ({len(resp.content)} B)\n"
                                      f"Extrait: {resp.text[:150].strip()}",
                        remediation = remed,
                    ))
                    warning(f"  [{sev}] {name} : {path} accessible !")
            except Exception:
                pass

        return findings

    def _check_directory_listing(
        self, base_url: str, headers: dict, target: str
    ) -> list[MisconfigFinding]:
        """Vérifie si des répertoires sont listés."""
        findings = []
        dirs_to_check = ["/uploads/", "/files/", "/backup/", "/logs/", "/images/", "/assets/"]

        for path in dirs_to_check:
            url = base_url.rstrip("/") + path
            try:
                resp = self._session.get(
                    url, headers=headers,
                    timeout=self._timeout, allow_redirects=False,
                )
                body = resp.text[:2000]
                # Signatures de directory listing (Apache, Nginx)
                if resp.status_code == 200 and any(
                    sig in body for sig in [
                        "Index of /", "Directory listing for",
                        "<title>Index of", "Parent Directory",
                    ]
                ):
                    findings.append(MisconfigFinding(
                        check_name  = "Directory Listing Enabled",
                        severity    = "MEDIUM",
                        target      = target,
                        description = f"Le répertoire {path} est listé.",
                        evidence    = f"HTTP 200 avec directory listing sur {path}",
                        remediation = "Désactiver l'indexation des répertoires "
                                      "(Options -Indexes pour Apache, autoindex off pour Nginx).",
                    ))
                    warning(f"  Directory listing sur {path}")
            except Exception:
                pass

        return findings