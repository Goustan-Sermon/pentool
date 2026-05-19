"""
Point d'entrée CLI — pentool

Commandes :
  pentool scan   <target>     Scan complet (ports + DNS + fuzz + CVE + PDF auto)
  pentool ports  <target>     Scan de ports uniquement
  pentool dns    <target>     Enumération DNS/WHOIS
  pentool fuzz   <target>     Fuzzing de répertoires HTTP
  pentool cve    <scan.json>  Corrélation CVE depuis un JSON de scan
  pentool report <scan.json>  Génère le rapport PDF depuis un JSON existant
  pentool info                Profils et version
"""

from __future__ import annotations

import json
from pathlib import Path
from typing  import Optional

import typer
from rich.table import Table
from rich       import box

from pentool            import __version__
from pentool.utils      import console, section, info, success, warning, error
from pentool.recon      import (
    PortScanner, DNSEnumerator, DirFuzzer, SCAN_PROFILES,
    print_port_scan, print_dns_enum, print_fuzz_results,
)
from pentool.cve        import CVECorrelator, print_cve_summary

app = typer.Typer(
    name="pentool",
    help="Pentool — Outil de test d'intrusion automatisé (ISEN)",
    add_completion=False,
    rich_markup_mode="rich",
)

BANNER = """\
[bold cyan]
 ██████╗ ███████╗███╗   ██╗████████╗ ██████╗  ██████╗ ██╗
 ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║
 ██████╔╝█████╗  ██╔██╗ ██║   ██║   ██║   ██║██║   ██║██║
 ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██║   ██║██║   ██║██║
 ██║     ███████╗██║ ╚████║   ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝[/bold cyan]
[dim] Projet ISEN — v{version}[/dim]
"""


def _banner() -> None:
    console.print(BANNER.format(version=__version__))


def _pdf_from_output(output: Optional[Path], combined: dict) -> None:
    """Génère automatiquement le PDF si --output est fourni."""
    if output is None:
        return
    try:
        from pentool.report import generate_pdf
        pdf_path = output.with_suffix(".pdf")
        with console.status("[cyan]Génération du rapport PDF…[/cyan]", spinner="dots"):
            generate_pdf(combined, pdf_path)
        success(f"Rapport PDF → [bold]{pdf_path}[/bold]")
    except Exception as exc:
        warning(f"Génération PDF échouée : {exc}")


# ─────────────────────────────────────────────
# info
# ─────────────────────────────────────────────

@app.command("info")
def cmd_info() -> None:
    """Affiche la version et les profils de scan disponibles."""
    _banner()
    t = Table(box=box.ROUNDED, header_style="bold cyan", border_style="dim")
    t.add_column("Profil",      style="bold yellow", width=12)
    t.add_column("Description", style="white",       width=28)
    t.add_column("Args nmap",   style="dim",         width=42)
    for key, cfg in SCAN_PROFILES.items():
        t.add_row(key, cfg["label"], cfg["args"])
    console.print(t)


# ─────────────────────────────────────────────
# ports
# ─────────────────────────────────────────────

@app.command("ports")
def cmd_ports(
    target:     str            = typer.Argument(..., help="IP ou domaine cible"),
    profile:    str            = typer.Option("standard", "--profile", "-p"),
    extra:      str            = typer.Option("", "--extra", "-e"),
    port_range: Optional[str]  = typer.Option(None, "--ports", "-P"),
    output:     Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Scan de ports et détection de services (Phase 1a)."""
    _banner()
    section(f"Scan de ports -> {target}")
    result = PortScanner().scan(target, profile=profile, extra_args=extra, ports=port_range)
    print_port_scan(result)
    if output:
        _save_json(result.to_dict(), output)


# ─────────────────────────────────────────────
# dns
# ─────────────────────────────────────────────

@app.command("dns")
def cmd_dns(
    target:        str            = typer.Argument(..., help="Domaine ou IP cible"),
    no_whois:      bool           = typer.Option(False, "--no-whois"),
    no_subdomains: bool           = typer.Option(False, "--no-subdomains"),
    output:        Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Enumération DNS, WHOIS et sous-domaines (Phase 1b)."""
    _banner()
    section(f"Enumération DNS -> {target}")
    result = DNSEnumerator().enumerate(
        target, do_whois=not no_whois, do_subdomains=not no_subdomains)
    print_dns_enum(result)
    if output:
        _save_json(result.to_dict(), output)


# ─────────────────────────────────────────────
# fuzz
# ─────────────────────────────────────────────

@app.command("fuzz")
def cmd_fuzz(
    target:   str            = typer.Argument(..., help="URL cible (ex: http://192.168.1.1)"),
    threads:  int            = typer.Option(10,  "--threads", "-t"),
    timeout:  float          = typer.Option(5.0, "--timeout"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", "-w"),
    output:   Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Fuzzing de répertoires et fichiers cachés (Phase 1c)."""
    _banner()
    section(f"Dir Fuzzer -> {target}")
    custom_words: Optional[list] = None
    if wordlist:
        if not wordlist.exists():
            error(f"Wordlist introuvable : {wordlist}")
            raise typer.Exit(1)
        custom_words = [l.strip() for l in wordlist.read_text().splitlines() if l.strip()]
    result = DirFuzzer(threads=threads, timeout=timeout).fuzz(target, wordlist=custom_words)
    print_fuzz_results(result)
    if output:
        _save_json(result.to_dict(), output)


# ─────────────────────────────────────────────
# cve
# ─────────────────────────────────────────────

@app.command("cve")
def cmd_cve(
    scan_json:  Path           = typer.Argument(..., help="JSON produit par 'pentool scan'"),
    api_key:    Optional[str]  = typer.Option(None,  "--api-key", envvar="NVD_API_KEY"),
    min_score:  float          = typer.Option(0.0,   "--min-score", "-s"),
    max_cves:   int            = typer.Option(10,    "--max-cves"),
    no_cache:   bool           = typer.Option(False, "--no-cache"),
    output:     Optional[Path] = typer.Option(None,  "--output", "-o"),
) -> None:
    """Corrélation CVE des services détectés via NVD (Phase 2)."""
    _banner()
    if not scan_json.exists():
        error(f"Fichier introuvable : {scan_json}")
        raise typer.Exit(1)

    data      = json.loads(scan_json.read_text(encoding="utf-8"))
    port_data = data.get("port_scan", data)

    from pentool.recon.port_scanner import HostResult, ServiceInfo
    services = [
        ServiceInfo(
            port=s["port"], protocol=s["protocol"], state=s["state"],
            service=s["service"], product=s["product"], version=s["version"],
            extrainfo=s.get("extrainfo", ""), cpe=s.get("cpe", []),
        )
        for s in port_data.get("services", [])
    ]
    host = HostResult(
        target=port_data.get("target", "?"), ip=port_data.get("ip", ""),
        hostname=port_data.get("hostname", ""), state="up", services=services,
    )

    correlator = CVECorrelator(api_key=api_key, max_cves=max_cves,
                               use_cache=not no_cache, min_score=min_score)
    matches = correlator.correlate(host)
    print_cve_summary(matches)

    if output:
        _save_json({"cve_matches": [m.to_dict() for m in matches]}, output)


# ─────────────────────────────────────────────
# report  (Phase 4 — génération PDF standalone)
# ─────────────────────────────────────────────

@app.command("report")
def cmd_report(
    scan_json: Path           = typer.Argument(..., help="JSON produit par 'pentool scan --output'"),
    output:    Optional[Path] = typer.Option(None, "--output", "-o",
                                              help="Chemin PDF (défaut : même nom que le JSON)"),
) -> None:
    """Génère le rapport PDF depuis un fichier JSON de scan existant (Phase 4)."""
    _banner()

    if not scan_json.exists():
        error(f"Fichier JSON introuvable : {scan_json}")
        raise typer.Exit(1)

    data = json.loads(scan_json.read_text(encoding="utf-8"))
    pdf_path = output or scan_json.with_suffix(".pdf")

    section(f"Génération du rapport PDF → {pdf_path}")
    try:
        from pentool.report import generate_pdf
        with console.status("[cyan]Compilation du PDF en cours…[/cyan]", spinner="dots"):
            result = generate_pdf(data, pdf_path)
        success(f"Rapport PDF généré → [bold]{result}[/bold]")
        info(f"Pages : voir le fichier pour le détail complet.")
    except Exception as exc:
        error(f"Erreur lors de la génération PDF : {exc}")
        raise typer.Exit(1)


# ─────────────────────────────────────────────
# scan  (commande principale — tout en un)
# ─────────────────────────────────────────────

@app.command("scan")
def cmd_scan(
    target:        str            = typer.Argument(..., help="IP ou domaine cible"),
    profile:       str            = typer.Option("standard", "--profile", "-p"),
    domain:        Optional[str]  = typer.Option(None,  "--domain", "-d",
                                                  help="Domaine base pour vhost fuzzing (ex: monitorsfour.htb)"),
    no_dns:        bool           = typer.Option(False, "--no-dns"),
    no_whois:      bool           = typer.Option(False, "--no-whois"),
    no_subdomains: bool           = typer.Option(False, "--no-subdomains"),
    no_fuzz:       bool           = typer.Option(False, "--no-fuzz"),
    no_vhost:      bool           = typer.Option(False, "--no-vhost",
                                                  help="Desactiver le vhost fuzzing"),
    no_param:      bool           = typer.Option(False, "--no-param",
                                                  help="Desactiver le param fuzzing automatique"),
    no_cve:        bool           = typer.Option(False, "--no-cve"),
    no_pdf:        bool           = typer.Option(False, "--no-pdf"),
    no_audit:      bool           = typer.Option(False, "--no-audit",
                                                  help="Desactiver Phase 3 (fingerprinting + misconfigs)"),
    fuzz_threads:  int            = typer.Option(10,   "--fuzz-threads"),
    api_key:       Optional[str]  = typer.Option(None, "--api-key", envvar="NVD_API_KEY"),
    output:        Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """
    Scan complet automatique :
      Phase 1a  — Scan de ports (nmap)
      Phase 1b  — Enumeration DNS + WHOIS + sous-domaines
      Phase 1c  — Fuzzing HTTP (anti-faux-positifs)
      Phase 1d  — VHost fuzzing (virtual hosts caches)
      Phase 1e  — Param fuzzing (endpoints API + IDOR)
      Phase 2   — Correlation CVE via NVD
      Phase 4   — Generation PDF automatique

    Exemple HTB :
      pentool scan 10.129.59.40 --domain monitorsfour.htb -o rapport.json
    """
    _banner()
    combined: dict = {"target": target}

    # ── Phase 1a : Scan de ports ──────────────────────────────────────
    section(f"Phase 1a — Scan de ports -> {target}")
    port_result = PortScanner().scan(target, profile=profile)
    print_port_scan(port_result)
    combined["port_scan"] = port_result.to_dict()

    # Detection des ports HTTP ouverts (utile pour les phases suivantes)
    # Stratégie : on prend le port HTTP principal (80 ou 8080) en priorité,
    # puis HTTPS seulement si pas de HTTP. Évite le double fuzzing 80+443.
    http_svcs = [s for s in port_result.open_ports
                 if s.service in ("http", "https", "http-alt", "http-proxy")
                 or s.port in (80, 443, 8080, 8443, 8000, 8888)]

    # Trier : HTTP avant HTTPS, ports standards avant non-standards
    _http_priority = {80: 0, 8080: 1, 8000: 2, 8888: 3, 443: 10, 8443: 11}
    http_svcs.sort(key=lambda s: _http_priority.get(s.port, 20))

    http_urls: list[str] = []
    seen_content_ports: set[str] = set()   # évite les doublons 80/443 même contenu
    for s in http_svcs:
        scheme   = "https" if s.service == "https" or s.port in (443, 8443) else "http"
        port_sfx = f":{s.port}" if s.port not in (80, 443) else ""
        url      = f"{scheme}://{target}{port_sfx}"
        # Dédupliquer : si on a déjà http://target, on n'ajoute pas https://target
        # (sauf si le port HTTPS est vraiment différent, ex: 8443)
        dedup_key = f"{target}:{s.port}"
        if dedup_key not in seen_content_ports:
            seen_content_ports.add(dedup_key)
            # Pour 443 : ne l'ajouter que s'il n'y a pas déjà un HTTP sur 80
            if s.port == 443 and any(u.startswith("http://") for u in http_urls):
                continue   # 80 déjà présent, on skip 443 (même contenu en général)
            http_urls.append(url)

    # ── Phase 1b : DNS ────────────────────────────────────────────────
    if not no_dns:
        section(f"Phase 1b — Enumeration DNS -> {target}")
        dns_result = DNSEnumerator().enumerate(
            target, do_whois=not no_whois, do_subdomains=not no_subdomains)
        print_dns_enum(dns_result)
        combined["dns_enum"] = dns_result.to_dict()

    # ── Phase 1c : Dir Fuzzing ────────────────────────────────────────
    if not no_fuzz and http_urls:
        section(f"Phase 1c — Dir Fuzzing HTTP")
        combined["fuzz"] = []
        for url in http_urls:
            info(f"Fuzzing -> [cyan]{url}[/cyan]")
            fuzz_result = DirFuzzer(threads=fuzz_threads).fuzz(url)
            print_fuzz_results(fuzz_result)
            combined["fuzz"].append(fuzz_result.to_dict())
    elif not http_urls:
        info("Phase 1c ignoree — aucun port HTTP detecte.")

    # ── Phase 1d : VHost Fuzzing ──────────────────────────────────────
    if not no_vhost and http_urls:
        # On a besoin d un domaine de base pour le vhost fuzzing
        # Si --domain n est pas fourni, on tente de le deduire
        vhost_domain = domain
        if not vhost_domain:
            # Tenter de deduire depuis le hostname nmap ou le DNS
            hostname = port_result.hostname or ""
            if hostname and "." in hostname:
                # ex: metasploitable.local -> local trop court, ignorer
                parts = hostname.split(".")
                if len(parts) >= 2 and len(parts[-1]) > 2:
                    vhost_domain = ".".join(parts[-2:])
            if not vhost_domain:
                # Pas de domaine deductible -> on skip avec un conseil
                info("Phase 1d (VHost) ignoree — aucun domaine connu.")
                info("Conseil : relancez avec [bold]--domain monitorsfour.htb[/bold] pour le vhost fuzzing.")
                vhost_domain = None

        if vhost_domain:
            section(f"Phase 1d — VHost Fuzzing -> {target} / {vhost_domain}")
            from pentool.recon.vhost_fuzzer import VHostFuzzer
            vhost_fuzzer = VHostFuzzer(threads=fuzz_threads)
            first_http = http_urls[0]
            port_num   = 80
            use_https  = first_http.startswith("https")
            import re as _re
            m = _re.search(r":(\d+)$", first_http.rstrip("/"))
            if m:
                port_num = int(m.group(1))
            elif use_https:
                port_num = 443

            vhost_result = vhost_fuzzer.fuzz(
                target_ip=target,
                base_domain=vhost_domain,
                port=port_num,
                use_https=use_https,
            )
            combined["vhost"] = vhost_result.to_dict()

            if vhost_result.found:
                # Afficher le tableau des vhosts trouves
                t = Table(box=box.ROUNDED, header_style="bold cyan", border_style="dim")
                t.add_column("VHost",   style="bold cyan", width=40)
                t.add_column("Code",    justify="center",  width=8)
                t.add_column("Taille",  justify="right",   width=10)
                t.add_column("Titre",   style="dim",       width=35)
                for v in vhost_result.found:
                    t.add_row(v.vhost, str(v.status_code), f"{v.content_length} B", v.title or "—")
                console.print(t)
                console.print()
                success(f"Ajoutez ces entrees dans /etc/hosts :")
                for v in vhost_result.found:
                    console.print(f"  [bold]{target}  {v.vhost}[/bold]")

    # ── Phase 1e : Param Fuzzing (endpoints JSON uniquement) ──────────
    if not no_param and http_urls:
        section("Phase 1e — Param Fuzzing (endpoints API JSON)")
        from pentool.recon.param_fuzzer import ParamFuzzer
        import requests as _req

        param_fuzzer   = ParamFuzzer(threads=fuzz_threads)
        param_findings = []

        json_endpoints = [
            "user", "users", "api/user", "api/users",
            "api/v1/user", "api/v1/users",
            "me", "account", "profile",
            "token", "auth/token",
        ]

        # Construire la liste des URLs à tester :
        # 1. URLs HTTP directes (IP ou domaine)
        # 2. VHosts découverts en Phase 1d (avec Host header)
        urls_to_param_fuzz: list[dict] = []
        for u in http_urls:
            urls_to_param_fuzz.append({"base": u, "host": None})

        # Ajouter les vhosts découverts — c'est ici qu'on trouve /user?token=0
        vhost_found = combined.get("vhost", {}).get("found", [])
        for v in vhost_found:
            if v.get("status_code") in (200, 302, 401, 403) and http_urls:
                urls_to_param_fuzz.append({
                    "base": http_urls[0],
                    "host": v["vhost"],
                })

        for entry in urls_to_param_fuzz:
            base_url = entry["base"]
            host_hdr = entry["host"]
            req_headers = {"Accept": "application/json"}
            if host_hdr:
                req_headers["Host"] = host_hdr

            for endpoint in json_endpoints:
                url = f"{base_url.rstrip('/')}/{endpoint}"
                label = f"http://{host_hdr}/{endpoint}" if host_hdr else url
                try:
                    probe = _req.get(
                        url, timeout=4, allow_redirects=True,
                        headers=req_headers,
                    )
                    ct   = probe.headers.get("Content-Type", "")
                    body = probe.text.strip()

                    # Ignorer les pages HTML (catchall de login)
                    if "text/html" in ct or body.startswith("<!"):
                        continue
                    if len(body) > 2000 and not body.startswith("{"):
                        continue

                    analysis = param_fuzzer.discover_params(url, wordlist=[
                        "token", "id", "user", "key", "auth",
                        "api_key", "username", "email", "name",
                        "access_token", "session", "debug",
                    ])

                    if analysis.detected_params or analysis.param_hints:
                        all_params = list(dict.fromkeys(
                            analysis.param_hints + analysis.detected_params
                        ))
                        finding = {
                            "url":    label,
                            "params": all_params,
                            "hints":  analysis.param_hints,
                            "body":   body[:200],
                            "host":   host_hdr,
                        }
                        param_findings.append(finding)
                        info(f"  [cyan]{label}[/cyan]")
                        info(f"  Parametre(s) : [yellow]{', '.join(all_params)}[/yellow]")

                        # IDOR automatique sur les parametres hints (plage 0-200)
                        for pname in all_params[:2]:
                            info(f"  -> IDOR {pname}=0..200 sur {label}...")
                            idor = param_fuzzer.fuzz_range(url, pname, 0, 200)
                            if idor.interesting_hits:
                                finding["idor_hits"] = idor.to_dict()
                                success(f"  {len(idor.interesting_hits)} reponse(s) avec donnees sensibles !")
                                for h in idor.interesting_hits[:3]:
                                    console.print(f"    [bold cyan]{h.url}[/bold cyan]")
                                    console.print(f"    [dim]{h.response_body[:120].strip()}[/dim]")

                except Exception:
                    continue

        if param_findings:
            combined["param_findings"] = param_findings
            success(f"{len(param_findings)} endpoint(s) API interactif(s) trouve(s).")
        else:
            info("Aucun endpoint API JSON detecte.")

        # ── Phase 3 : Audit (fingerprinting + misconfigurations) ─────────
    if not no_audit:
        section("Phase 3 — Audit : Fingerprinting & Misconfigurations")
        from pentool.audit import (
            WebFingerprinter, MisconfigChecker,
            print_fingerprints, print_misconfig_report,
        )
        fingerprinter  = WebFingerprinter()
        misconfig_chk  = MisconfigChecker()
        audit_results  = {"fingerprints": [], "misconfigs": []}

        # Construire la liste de toutes les URLs a auditer
        # IP directe + vhosts decouverts
        urls_to_audit = []
        for base_url in http_urls:
            urls_to_audit.append({"url": base_url, "host": None})

        for v in combined.get("vhost", {}).get("found", []):
            # N'auditer que les vhosts qui répondent vraiment (200 ou 401)
            if http_urls and v.get("status_code") in (200, 201, 401, 403):
                urls_to_audit.append({
                    "url":  http_urls[0],
                    "host": v["vhost"],
                })

        for entry in urls_to_audit:
            url  = entry["url"]
            host = entry["host"]
            label = host or url

            # 3a. Fingerprinting applicatif
            fps = fingerprinter.fingerprint_url(url, host_header=host)
            if fps:
                print_fingerprints(fps)
                # Correlation CVE sur les apps detectees
                if not no_cve and fps:
                    from pentool.cve import NVDClient, CVECache
                    client = NVDClient(api_key=api_key, max_results=5)
                    cache  = CVECache()
                    for fp in fps:
                        if not fp.nvd_keyword:
                            continue
                        cache_key = CVECache.make_key(fp.nvd_keyword)
                        cached = cache.get(cache_key)
                        if cached is not None:
                            fp.cves = [c.to_dict() for c in cached]
                        else:
                            cves = client.search_by_keyword(fp.nvd_keyword)
                            fp.cves = [c.to_dict() for c in cves[:5]]
                            if cves:
                                cache.set(cache_key, cves)
                        if fp.cves:
                            info(f"  [cyan]{fp.app_name} {fp.version}[/cyan] → [danger]{len(fp.cves)}[/danger] CVE")
                            for c in fp.cves[:3]:
                                sev   = c.get("cvss_v3_severity","?")
                                score = c.get("cvss_v3_score","?")
                                info(f"    [dim]{c['cve_id']}  {sev}  {score}  {c['description'][:60]}[/dim]")
                audit_results["fingerprints"].append(fp.to_dict() for fp in fps)

            # 3b. Misconfigurations HTTP
            mc = misconfig_chk.check_http(url, host_header=host)
            if mc.findings:
                print_misconfig_report(mc)
                audit_results["misconfigs"].append(mc.to_dict())

        # 3c. Checks services non-HTTP
        for svc in port_result.open_ports:
            if svc.service == "ftp" or svc.port == 21:
                mc = misconfig_chk.check_ftp(target, svc.port)
                if mc.findings:
                    print_misconfig_report(mc)
                    audit_results["misconfigs"].append(mc.to_dict())
            if svc.service in ("mysql", "mariadb") or svc.port == 3306:
                mc = misconfig_chk.check_mysql(target, svc.port)
                if mc.findings:
                    print_misconfig_report(mc)
                    audit_results["misconfigs"].append(mc.to_dict())
            if svc.service == "https" or svc.port == 443:
                mc = misconfig_chk.check_ssl(target, svc.port, host=domain)
                if mc.findings:
                    print_misconfig_report(mc)
                    audit_results["misconfigs"].append(mc.to_dict())

        combined["audit"] = audit_results

        # ── Phase 2 : CVE ────────────────────────────────────────────────
    if not no_cve:
        section("Phase 2 — Correlation CVE")
        matches = CVECorrelator(api_key=api_key).correlate(port_result)
        print_cve_summary(matches)
        combined["cve_matches"] = [m.to_dict() for m in matches]

    # ── Résumé terminal ──────────────────────────────────────────────
    section("Resume du scan complet")

    # Compter les resultats de fuzz (liste ou dict selon le nombre de ports)
    fuzz_data = combined.get("fuzz", [])
    if isinstance(fuzz_data, dict):
        fuzz_data = [fuzz_data]
    fuzz_200 = sum(
        len([r for r in fd.get("results", []) if r.get("status_code") == 200])
        for fd in fuzz_data
    )

    vhosts_found  = len(combined.get("vhost", {}).get("found", []))
    param_found   = len(combined.get("param_findings", []))
    total_cve     = sum(len(m.get("cves", [])) for m in combined.get("cve_matches", []))
    subs          = len(combined.get("dns_enum", {}).get("subdomains", []))

    console.print(f"  Ports ouverts        : [success]{len(port_result.open_ports)}[/success]")
    console.print(f"  Sous-domaines DNS    : [cyan]{subs}[/cyan]")
    console.print(f"  Repertoires HTTP 200 : [cyan]{fuzz_200}[/cyan]")
    console.print(f"  VHosts decouverts    : {'[danger]' + str(vhosts_found) + '[/danger]' if vhosts_found else '[dim]0[/dim]'}")
    console.print(f"  Endpoints API        : {'[warning]' + str(param_found) + '[/warning]' if param_found else '[dim]0[/dim]'}")
    console.print(f"  CVE trouvees         : [danger]{total_cve}[/danger]")

    # ── Sauvegarde JSON + PDF auto ───────────────────────────────────
    if output:
        _save_json(combined, output)
        success(f"JSON -> [bold]{output}[/bold]")

        if not no_pdf:
            pdf_path = output.with_suffix(".pdf")
            try:
                from pentool.report import generate_pdf
                with console.status("[cyan]Generation du rapport PDF...[/cyan]", spinner="dots"):
                    generate_pdf(combined, pdf_path)
                success(f"Rapport PDF -> [bold]{pdf_path}[/bold] ✅")
            except Exception as exc:
                warning(f"PDF non genere : {exc}")
        else:
            info(f"PDF: pentool report {output}")
    else:
        info("Ajoutez [bold]--output rapport.json[/bold] pour sauvegarder + generer le PDF.")

# ─────────────────────────────────────────────
# Helper JSON
# ─────────────────────────────────────────────

def _save_json(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, default=str)


if __name__ == "__main__":
    app()


# ─────────────────────────────────────────────
# vhost  (Virtual Host fuzzing)
# ─────────────────────────────────────────────

@app.command("vhost")
def cmd_vhost(
    target:     str            = typer.Argument(..., help="IP ou hostname cible (ex: 10.129.59.40)"),
    domain:     str            = typer.Option(...,  "--domain", "-d",
                                               help="Domaine de base (ex: monitorsfour.htb)"),
    threads:    int            = typer.Option(10,   "--threads", "-t"),
    port:       int            = typer.Option(80,   "--port",    "-p"),
    https:      bool           = typer.Option(False,"--https",   help="Utiliser HTTPS"),
    wordlist:   Optional[Path] = typer.Option(None, "--wordlist","-w"),
    output:     Optional[Path] = typer.Option(None, "--output",  "-o"),
) -> None:
    """
    Virtual Host fuzzing — découvre les sous-domaines cachés non présents en DNS.

    Exemple (HackTheBox style) :
      pentool vhost 10.129.59.40 --domain monitorsfour.htb
      → découvre cacti.monitorsfour.htb
    """
    _banner()
    from pentool.recon.vhost_fuzzer import VHostFuzzer
    section(f"VHost Fuzzing -> {target} (domaine: {domain})")

    custom_words: Optional[list] = None
    if wordlist:
        if not wordlist.exists():
            error(f"Wordlist introuvable : {wordlist}")
            raise typer.Exit(1)
        custom_words = [l.strip() for l in wordlist.read_text().splitlines() if l.strip()]
        info(f"Wordlist custom : {len(custom_words)} entrées")

    fuzzer = VHostFuzzer(threads=threads)
    result = fuzzer.fuzz(
        target_ip=target,
        base_domain=domain,
        wordlist=custom_words,
        port=port,
        use_https=https,
    )

    if result.found:
        t = Table(box=box.ROUNDED, header_style="bold cyan", border_style="dim")
        t.add_column("VHost",        style="bold cyan",  width=40)
        t.add_column("Code",         justify="center",   width=8)
        t.add_column("Taille",       justify="right",    width=10)
        t.add_column("Titre",        style="dim",        width=40)
        t.add_column("Redirect",     style="dim",        width=30)
        for v in result.found:
            t.add_row(v.vhost, str(v.status_code), f"{v.content_length} B",
                      v.title or "—", v.redirect_url or "—")
        console.print(t)
        console.print()
        success(f"Ajoutez ces vhosts a /etc/hosts :")
        for v in result.found:
            console.print(f"  [bold]{target}  {v.vhost}[/bold]")
    else:
        info("Aucun vhost découvert avec la wordlist intégrée.")
        info(f"Essayez avec une wordlist plus grande : --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")

    if output:
        _save_json(result.to_dict(), output)


# ─────────────────────────────────────────────
# param  (Parameter fuzzing / IDOR)
# ─────────────────────────────────────────────

@app.command("param")
def cmd_param(
    url:      str            = typer.Argument(..., help="URL de l'endpoint (ex: http://monitorsfour.htb/user)"),
    param:    Optional[str]  = typer.Option(None, "--param",   "-p",
                                             help="Paramètre à fuzzer (si absent: mode découverte)"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist","-w",
                                             help="Fichier de valeurs à tester (une par ligne)"),
    start:    Optional[int]  = typer.Option(None, "--start",   help="Début plage numérique (IDOR)"),
    end:      int            = typer.Option(500,  "--end",     help="Fin plage numérique"),
    threads:  int            = typer.Option(10,   "--threads", "-t"),
    method:   str            = typer.Option("GET","--method",  "-m", help="GET ou POST"),
    output:   Optional[Path] = typer.Option(None, "--output",  "-o"),
) -> None:
    """
    Parameter fuzzing et détection d'endpoints API.

    Mode 1 — Découverte de paramètres (aucun --param) :
      pentool param http://monitorsfour.htb/user
      → détecte que l'endpoint attend un paramètre 'token'

    Mode 2 — Fuzzing d'un paramètre connu avec wordlist :
      pentool param http://monitorsfour.htb/user --param token --wordlist tokens.txt

    Mode 3 — IDOR / plage numérique :
      pentool param http://monitorsfour.htb/user --param token --start 0 --end 9999
      → teste token=0, token=1 … token=9999
    """
    _banner()
    from pentool.recon.param_fuzzer import ParamFuzzer
    section(f"Param Fuzzer -> {url}")

    fuzzer = ParamFuzzer(threads=threads, method=method)

    if param is None:
        # Mode 1 : découverte de paramètres
        info("Mode : découverte automatique de paramètres")
        analysis = fuzzer.discover_params(url)
        console.print(f"\n  Paramètres détectés   : [yellow]{', '.join(analysis.detected_params) or 'aucun'}[/yellow]")
        console.print(f"  Hints serveur         : [cyan]{', '.join(analysis.param_hints) or 'aucun'}[/cyan]")
        if analysis.detected_params:
            console.print()
            info("Conseil : lancez maintenant :")
            for p in analysis.detected_params[:3]:
                console.print(f"  pentool param {url} --param {p} --start 0 --end 1000")
        if output:
            _save_json(analysis.to_dict(), output)

    elif start is not None:
        # Mode 3 : plage numérique (IDOR)
        info(f"Mode : IDOR / plage numérique — {param}={start}…{end}")
        result = fuzzer.fuzz_range(url, param, start=start, end=end)
        _print_param_results(result)
        if output:
            _save_json(result.to_dict(), output)

    else:
        # Mode 2 : wordlist custom ou valeurs par défaut
        values: list[str] = []
        if wordlist:
            if not wordlist.exists():
                error(f"Wordlist introuvable : {wordlist}")
                raise typer.Exit(1)
            values = [l.strip() for l in wordlist.read_text().splitlines() if l.strip()]
        else:
            # Pas de wordlist → on fait d'abord la découverte puis on propose
            warning("Aucune wordlist fournie. Lancement de la découverte de paramètres...")
            analysis = fuzzer.discover_params(url)
            if analysis.param_hints:
                info(f"Hint détecté : le paramètre '{param}' — test d'une plage 0-200")
                result = fuzzer.fuzz_range(url, param, start=0, end=200)
            else:
                from pentool.recon.param_fuzzer import PROBE_VALUES
                values = PROBE_VALUES * 10  # petit test
                result = fuzzer.fuzz_param(url, param, values)
            _print_param_results(result)
            if output:
                _save_json(result.to_dict(), output)
            return

        result = fuzzer.fuzz_param(url, param, values)
        _print_param_results(result)
        if output:
            _save_json(result.to_dict(), output)


def _print_param_results(result) -> None:
    """Affiche les résultats du param fuzzer."""
    hits = result.hits
    if not hits:
        info("Aucun résultat différent de la baseline.")
        return
    t = Table(box=box.ROUNDED, header_style="bold cyan", border_style="dim")
    t.add_column("Valeur",  style="bold yellow", width=14)
    t.add_column("Code",    justify="center",    width=8)
    t.add_column("Taille",  justify="right",     width=10)
    t.add_column("Note",    style="dim",         width=30)
    t.add_column("Extrait", style="dim",         width=60)
    for h in hits[:50]:
        note = "[danger]⭐ DONNÉES SENSIBLES[/danger]" if h.is_interesting else h.note
        t.add_row(
            str(h.value), str(h.status_code),
            f"{h.content_length} B", note,
            h.response_body[:60].replace("\n", " "),
        )
    console.print(t)
    interesting = result.interesting_hits
    if interesting:
        console.print()
        success(f"[danger]{len(interesting)}[/danger] réponse(s) avec données sensibles !")
        for h in interesting[:3]:
            console.print(f"  URL : [bold cyan]{h.url}[/bold cyan]")
            console.print(f"  Body: [dim]{h.response_body[:200]}[/dim]")