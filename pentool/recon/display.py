"""
Fonctions d'affichage Rich pour les résultats de reconnaissance.

Centralise tout le rendu terminal pour garder les modules de scan propres.
"""

from __future__ import annotations

from rich.table   import Table
from rich.panel   import Panel
from rich.columns import Columns
from rich         import box

from pentool.utils import console, section, success, warning, info
from pentool.recon.port_scanner import HostResult, ServiceInfo
from pentool.recon.dns_enum     import DNSEnumResult


# ──────────────────────────────────────────────────────────────────────
# Affichage des résultats de scan de ports
# ──────────────────────────────────────────────────────────────────────

def print_port_scan(result: HostResult) -> None:
    """Affiche les résultats du scan de ports sous forme de tableau Rich."""
    section("Résultats du scan de ports")

    # En-tête de l'hôte
    host_lines = [
        f"[bold]Cible      :[/bold] {result.target}",
        f"[bold]IP         :[/bold] {result.ip}",
        f"[bold]Hostname   :[/bold] {result.hostname or '—'}",
        f"[bold]État       :[/bold] {'[success]up[/success]' if result.state == 'up' else '[danger]down[/danger]'}",
        f"[bold]OS         :[/bold] {result.os_name}",
        f"[bold]Durée scan :[/bold] {result.scan_time}s",
    ]
    console.print(Panel("\n".join(host_lines), title="[cyan]Hôte[/cyan]", border_style="cyan", expand=False))

    if result.state != "up":
        warning("L'hôte semble injoignable. Vérifiez la cible et les droits réseau.")
        return

    open_svcs = result.open_ports
    if not open_svcs:
        warning("Aucun port ouvert détecté.")
        return

    success(f"{len(open_svcs)} port(s) ouvert(s) trouvé(s).")

    # Tableau principal
    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=box.ROUNDED,
        border_style="dim",
        row_styles=["", "dim"],
        expand=False,
    )
    table.add_column("Port",     style="bold white",  justify="right", width=8)
    table.add_column("Proto",    style="cyan",         justify="center", width=6)
    table.add_column("État",     justify="center",     width=10)
    table.add_column("Service",  style="green",        width=12)
    table.add_column("Produit",  style="yellow",       width=20)
    table.add_column("Version",  style="magenta",      width=14)
    table.add_column("Info",     style="dim white",    width=20)

    for svc in open_svcs:
        state_render = _state_badge(svc.state)
        table.add_row(
            str(svc.port),
            svc.protocol,
            state_render,
            svc.service,
            svc.product  or "—",
            svc.version  or "—",
            svc.extrainfo or "—",
        )

    console.print(table)

    # Empreintes pour CVE (Phase 2)
    console.print()
    console.print("[bold cyan]Empreintes services (Phase 2 → CVE)[/bold cyan]")
    fingerprints = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    fingerprints.add_column(style="bold white", justify="right")
    fingerprints.add_column(style="cyan")
    fingerprints.add_column(style="dim")
    for svc in open_svcs:
        if svc.product or svc.version:
            fingerprints.add_row(
                f":{svc.port}",
                svc.fingerprint,
                f"CPE: {svc.cpe[0]}" if svc.cpe else "",
            )
    console.print(fingerprints)


def _state_badge(state: str) -> str:
    mapping = {
        "open":     "[success]● open[/success]",
        "closed":   "[danger]● closed[/danger]",
        "filtered": "[warning]● filtered[/warning]",
    }
    return mapping.get(state, f"[muted]{state}[/muted]")


# ──────────────────────────────────────────────────────────────────────
# Affichage des résultats DNS/WHOIS
# ──────────────────────────────────────────────────────────────────────

def print_dns_enum(result: DNSEnumResult) -> None:
    """Affiche les résultats DNS, sous-domaines et WHOIS."""
    section("Résultats de l'énumération DNS")

    # ── Enregistrements DNS ──
    if result.records:
        dns_table = Table(
            title="[bold]Enregistrements DNS[/bold]",
            box=box.ROUNDED,
            border_style="dim",
            header_style="bold cyan",
            expand=False,
        )
        dns_table.add_column("Type",   style="bold yellow", width=8)
        dns_table.add_column("Valeur", style="white",       width=50)
        dns_table.add_column("TTL",    style="dim",         width=10)

        for rec in result.records:
            dns_table.add_row(rec.rtype, rec.value, str(rec.ttl))
        console.print(dns_table)
    else:
        warning("Aucun enregistrement DNS trouvé.")

    # ── PTR ──
    if result.reverse_ptr:
        info(f"PTR (reverse DNS) : [cyan]{result.reverse_ptr}[/cyan]")

    # ── Sous-domaines ──
    console.print()
    if result.subdomains:
        sub_table = Table(
            title=f"[bold]Sous-domaines découverts ({len(result.subdomains)})[/bold]",
            box=box.ROUNDED,
            border_style="dim",
            header_style="bold cyan",
            expand=False,
        )
        sub_table.add_column("Sous-domaine", style="green",  width=40)
        sub_table.add_column("IP",           style="yellow", width=20)
        sub_table.add_column("CNAME",        style="dim",    width=30)
        for sub in result.subdomains:
            sub_table.add_row(sub.subdomain, sub.ip, sub.cname or "—")
        console.print(sub_table)
        success(f"{len(result.subdomains)} sous-domaine(s) découvert(s).")
    else:
        info("Aucun sous-domaine commun trouvé.")

    # ── WHOIS ──
    console.print()
    if result.whois_data:
        whois_keys = [
            ("domain_name",       "Domaine"),
            ("registrar",         "Registrar"),
            ("creation_date",     "Créé le"),
            ("expiration_date",   "Expire le"),
            ("updated_date",      "Mis à jour"),
            ("name_servers",      "Name Servers"),
            ("registrant_name",   "Registrant"),
            ("registrant_country","Pays"),
            ("emails",            "E-mails"),
        ]
        whois_table = Table(
            title="[bold]WHOIS[/bold]",
            box=box.ROUNDED,
            border_style="dim",
            header_style="bold cyan",
            expand=False,
        )
        whois_table.add_column("Champ",  style="bold yellow", width=20)
        whois_table.add_column("Valeur", style="white",       width=50)
        for key, label in whois_keys:
            val = result.whois_data.get(key)
            if val:
                if isinstance(val, list):
                    val = ", ".join(val[:3])
                whois_table.add_row(label, str(val))
        console.print(whois_table)


# ──────────────────────────────────────────────────────────────────────
# Affichage des résultats de fuzzing
# ──────────────────────────────────────────────────────────────────────

_SEVERITY_STYLE: dict[str, str] = {
    "critical": "[critical] CRITICAL [/critical]",
    "high":     "[high] HIGH [/high]",
    "medium":   "[medium] MEDIUM [/medium]",
    "info":     "[info] INFO [/info]",
    "low":      "[muted] LOW [/muted]",
}

_CODE_STYLE: dict[int, str] = {
    200: "success", 201: "success", 204: "success",
    301: "warning", 302: "warning", 307: "warning", 308: "warning",
    401: "danger",  403: "warning",
    405: "muted",   500: "danger",
}


def print_fuzz_results(result) -> None:
    """Affiche les résultats du fuzzing de répertoires."""
    from pentool.recon.dir_fuzzer import FuzzScanResult
    section("Résultats du fuzzing de répertoires")

    found = result.found
    crits = result.critical_findings
    summary_lines = [
        f"[bold]Cible         :[/bold] {result.target_url}",
        f"[bold]Chemins testés:[/bold] {result.total_tested}",
        f"[bold]Trouvés       :[/bold] [success]{len(found)}[/success]",
        f"[bold]Critiques/High:[/bold] {'[danger]' + str(len(crits)) + '[/danger]' if crits else '[success]0[/success]'}",
        f"[bold]Durée         :[/bold] {result.scan_time:.1f}s",
    ]
    console.print(Panel("\n".join(summary_lines), title="[cyan]Fuzzing HTTP[/cyan]", border_style="cyan", expand=False))

    if not found:
        info("Aucune ressource intéressante découverte.")
        return

    if crits:
        console.print(f"\n[danger]⚠ {len(crits)} ressource(s) CRITIQUE(S) détectée(s) :[/danger]")
        for r in crits:
            console.print(f"  [danger]✘[/danger] [{r.status_code}] [bold]{r.url}[/bold]")

    table = Table(
        show_header=True, header_style="bold cyan",
        box=box.ROUNDED, border_style="dim",
        row_styles=["", "dim"], expand=False,
    )
    table.add_column("Sévérité",  justify="center", width=12)
    table.add_column("Code",      justify="center", width=6, style="bold")
    table.add_column("Chemin",    style="cyan",     width=36)
    table.add_column("Taille",    justify="right",  width=10, style="dim")
    table.add_column("Type MIME", style="dim",      width=22)

    for r in found:
        sev_badge  = _SEVERITY_STYLE.get(r.severity, r.severity)
        code_style = _CODE_STYLE.get(r.status_code, "muted")
        table.add_row(
            sev_badge,
            f"[{code_style}]{r.status_code}[/{code_style}]",
            r.path,
            _fmt_size(r.content_length),
            r.content_type or "—",
        )

    console.print(table)
    success(f"{len(found)} ressource(s) découverte(s) sur {result.total_tested} testée(s).")


def _fmt_size(n: int) -> str:
    if n < 1024:        return f"{n} B"
    if n < 1024 ** 2:   return f"{n / 1024:.1f} KB"
    return f"{n / 1024**2:.1f} MB"