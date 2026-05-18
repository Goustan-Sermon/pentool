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
    no_dns:        bool           = typer.Option(False, "--no-dns"),
    no_whois:      bool           = typer.Option(False, "--no-whois"),
    no_subdomains: bool           = typer.Option(False, "--no-subdomains"),
    no_fuzz:       bool           = typer.Option(False, "--no-fuzz"),
    no_cve:        bool           = typer.Option(False, "--no-cve"),
    no_pdf:        bool           = typer.Option(False, "--no-pdf",
                                                  help="Ne pas générer le PDF automatiquement"),
    fuzz_threads:  int            = typer.Option(10,   "--fuzz-threads"),
    api_key:       Optional[str]  = typer.Option(None, "--api-key", envvar="NVD_API_KEY"),
    output:        Optional[Path] = typer.Option(None, "--output", "-o",
                                                  help="Sauvegarde JSON + génération PDF auto"),
) -> None:
    """
    Scan complet : ports + DNS + fuzzing + CVE + rapport PDF.

    Avec --output rapport.json :
      • Sauvegarde rapport.json
      • Génère automatiquement rapport.pdf
    """
    _banner()
    combined: dict = {"target": target}

    # ── Phase 1a : ports ──────────────────────
    section(f"Phase 1a — Scan de ports -> {target}")
    port_result = PortScanner().scan(target, profile=profile)
    print_port_scan(port_result)
    combined["port_scan"] = port_result.to_dict()

    # ── Phase 1b : DNS ────────────────────────
    if not no_dns:
        section(f"Phase 1b — DNS -> {target}")
        dns_result = DNSEnumerator().enumerate(
            target, do_whois=not no_whois, do_subdomains=not no_subdomains)
        print_dns_enum(dns_result)
        combined["dns_enum"] = dns_result.to_dict()

    # ── Phase 1c : Fuzzing ───────────────────
    if not no_fuzz:
        http_ports = [s for s in port_result.open_ports
                      if s.service in ("http", "https", "http-alt")]
        if http_ports:
            url = f"http://{target}" if not target.startswith("http") else target
            section(f"Phase 1c — Fuzzing HTTP -> {url}")
            fuzz_result = DirFuzzer(threads=fuzz_threads).fuzz(url)
            print_fuzz_results(fuzz_result)
            combined["fuzz"] = fuzz_result.to_dict()
        else:
            info("Aucun port HTTP détecté — fuzzing ignoré.")

    # ── Phase 2 : CVE ────────────────────────
    if not no_cve:
        section("Phase 2 — Corrélation CVE")
        matches = CVECorrelator(api_key=api_key).correlate(port_result)
        print_cve_summary(matches)
        combined["cve_matches"] = [m.to_dict() for m in matches]

    # ── Résumé terminal ──────────────────────
    section("Résumé")
    console.print(f"  Ports ouverts : [success]{len(port_result.open_ports)}[/success]")
    console.print(f"  Sous-domaines : [cyan]{len(combined.get('dns_enum', {}).get('subdomains', []))}[/cyan]")
    fuzz_200 = len([r for r in combined.get('fuzz', {}).get('results', [])
                    if r.get('status_code') == 200])
    console.print(f"  Répertoires   : [cyan]{fuzz_200}[/cyan] (HTTP 200)")
    total_cve = sum(len(m.get('cves', [])) for m in combined.get('cve_matches', []))
    console.print(f"  CVE trouvées  : [danger]{total_cve}[/danger]")

    # ── Sauvegarde JSON ──────────────────────
    if output:
        _save_json(combined, output)
        success(f"JSON -> [bold]{output}[/bold]")

        # ── Phase 4 : PDF auto ───────────────
        if not no_pdf:
            pdf_path = output.with_suffix(".pdf")
            try:
                from pentool.report import generate_pdf
                with console.status("[cyan]Génération du rapport PDF…[/cyan]", spinner="dots"):
                    generate_pdf(combined, pdf_path)
                success(f"Rapport PDF -> [bold]{pdf_path}[/bold] ✅")
            except Exception as exc:
                warning(f"PDF non généré : {exc}")
        else:
            info("PDF ignoré (--no-pdf). Générez-le plus tard avec : "
                 f"[bold]pentool report {output}[/bold]")
    else:
        info("Ajoutez [bold]--output rapport.json[/bold] pour sauvegarder et générer le PDF.")


# ─────────────────────────────────────────────
# Helper JSON
# ─────────────────────────────────────────────

def _save_json(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, default=str)


if __name__ == "__main__":
    app()