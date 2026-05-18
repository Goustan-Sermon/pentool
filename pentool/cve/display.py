"""
Affichage Rich des résultats CVE.
"""

from __future__ import annotations

from rich.table  import Table
from rich.panel  import Panel
from rich        import box

from pentool.utils          import console, section, success, warning, info
from pentool.cve.models     import CVEEntry, ServiceCVEMatch


_SEV_STYLE: dict[str, str] = {
    "CRITICAL": "[critical] CRITICAL [/critical]",
    "HIGH":     "[high] HIGH [/high]",
    "MEDIUM":   "[medium] MEDIUM [/medium]",
    "LOW":      "[low] LOW [/low]",
    "NONE":     "[muted] NONE [/muted]",
    "UNKNOWN":  "[muted] UNKNOWN [/muted]",
}

_SCORE_COLOR: dict = {}   # calculé dynamiquement


def _score_style(score: float | None) -> str:
    if score is None:     return "[muted]—[/muted]"
    if score >= 9.0:      return f"[critical]{score:.1f}[/critical]"
    if score >= 7.0:      return f"[high]{score:.1f}[/high]"
    if score >= 4.0:      return f"[medium]{score:.1f}[/medium]"
    return f"[low]{score:.1f}[/low]"


def print_cve_summary(matches: list[ServiceCVEMatch]) -> None:
    """Vue d'ensemble : un tableau par service avec ses CVE critiques."""
    section("Phase 2 — Corrélation CVE")

    if not matches:
        warning("Aucun résultat CVE — vérifiez les versions détectées.")
        return

    total_cves = sum(len(m.cves) for m in matches)
    critical   = sum(m.critical_count for m in matches)
    high_      = sum(m.high_count     for m in matches)

    summary_lines = [
        f"[bold]Services analysés :[/bold] {len(matches)}",
        f"[bold]CVE trouvées      :[/bold] {total_cves}",
        f"[bold]CRITICAL          :[/bold] [danger]{critical}[/danger]",
        f"[bold]HIGH              :[/bold] [warning]{high_}[/warning]",
    ]
    console.print(Panel(
        "\n".join(summary_lines),
        title="[cyan]Résumé CVE[/cyan]",
        border_style="cyan",
        expand=False,
    ))

    for match in matches:
        _print_service_cves(match)


def _print_service_cves(match: ServiceCVEMatch) -> None:
    """Affiche les CVE d'un service dans un tableau compact."""
    if not match.cves:
        info(f"  :{match.port} {match.fingerprint} — aucune CVE trouvée")
        return

    sev_badge = _SEV_STYLE.get(
        max((c.severity for c in match.cves), key=lambda s: -_sev_order(s)),
        ""
    )

    console.print(
        f"\n[bold cyan]:{match.port}/{match.protocol}[/bold cyan]  "
        f"[yellow]{match.fingerprint}[/yellow]  "
        f"{sev_badge}  "
        f"[dim]{len(match.cves)} CVE[/dim]"
    )

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold dim",
        expand=False,
        padding=(0, 1),
    )
    table.add_column("CVE ID",      style="bold white",  width=18)
    table.add_column("Sév.",        justify="center",    width=12)
    table.add_column("Score",       justify="center",    width=7)
    table.add_column("Publié",      style="dim",         width=12)
    table.add_column("Description", style="dim",         width=52)

    for cve in match.cves:
        desc = cve.description[:80] + "…" if len(cve.description) > 80 else cve.description
        table.add_row(
            cve.cve_id,
            _SEV_STYLE.get(cve.severity, cve.severity),
            _score_style(cve.score),
            cve.published,
            desc,
        )

    console.print(table)


def print_cve_detail(cve: CVEEntry) -> None:
    """Affiche le détail complet d'un CVE individuel."""
    section(f"Détail — {cve.cve_id}")

    lines = [
        f"[bold]ID          :[/bold] {cve.cve_id}",
        f"[bold]Sévérité    :[/bold] {_SEV_STYLE.get(cve.severity, cve.severity)}",
        f"[bold]Score CVSS  :[/bold] {_score_style(cve.score)}",
        f"[bold]Vecteur     :[/bold] [dim]{cve.cvss_v3_vector or '—'}[/dim]",
        f"[bold]Publié      :[/bold] {cve.published}",
        f"[bold]Modifié     :[/bold] {cve.modified}",
        f"[bold]CWE         :[/bold] {', '.join(cve.cwe_ids) or '—'}",
        f"[bold]NVD URL     :[/bold] [link={cve.nvd_url}]{cve.nvd_url}[/link]",
        "",
        f"[bold]Description :[/bold]",
        cve.description,
    ]
    if cve.references:
        lines += ["", "[bold]Références  :[/bold]"]
        lines += [f"  • {r}" for r in cve.references[:3]]

    console.print(Panel("\n".join(lines), border_style="dim", expand=False))


def _sev_order(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}.get(sev, 5)