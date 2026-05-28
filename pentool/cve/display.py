"""
Affichage Rich des résultats CVE.
"""

from __future__ import annotations

from rich import box
from rich.panel import Panel
from rich.table import Table

from pentool.cve.models import ServiceCVEMatch
from pentool.utils import console, info, section, warning

_SEV_STYLE: dict[str, str] = {
    "CRITICAL": "[critical] CRITICAL [/critical]",
    "HIGH": "[high] HIGH [/high]",
    "MEDIUM": "[medium] MEDIUM [/medium]",
    "LOW": "[low] LOW [/low]",
    "NONE": "[muted] NONE [/muted]",
    "UNKNOWN": "[muted] UNKNOWN [/muted]",
}


def _score_style(score: float | None) -> str:
    if score is None:
        return "[muted]—[/muted]"
    if score >= 9.0:
        return f"[critical]{score:.1f}[/critical]"
    if score >= 7.0:
        return f"[high]{score:.1f}[/high]"
    if score >= 4.0:
        return f"[medium]{score:.1f}[/medium]"
    return f"[low]{score:.1f}[/low]"


def _sev_order(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}.get(sev, 5)


def print_cve_summary(matches: list[ServiceCVEMatch]) -> None:
    """Affiche un résumé CVE : panneau de synthèse puis tableau par service."""

    if not matches:
        warning("Aucun résultat CVE — vérifiez les versions détectées.")
        return

    total_cves = sum(len(m.cves) for m in matches)
    critical = sum(m.critical_count for m in matches)
    high_ = sum(m.high_count for m in matches)

    console.print(
        Panel(
            "\n".join(
                [
                    f"[bold]Services analysés :[/bold] {len(matches)}",
                    f"[bold]CVE trouvées      :[/bold] {total_cves}",
                    f"[bold]CRITICAL          :[/bold] [danger]{critical}[/danger]",
                    f"[bold]HIGH              :[/bold] [warning]{high_}[/warning]",
                ]
            ),
            title="[cyan]Résumé CVE[/cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    for match in matches:
        _print_service_cves(match)


def _print_service_cves(match: ServiceCVEMatch) -> None:
    """Tableau compact des CVE d'un service."""
    if not match.cves:
        info(f"  :{match.port} {match.fingerprint} — aucune CVE trouvée")
        return

    best_sev = max((c.severity for c in match.cves), key=lambda s: -_sev_order(s))
    sev_badge = _SEV_STYLE.get(best_sev, "")

    console.print(
        f"\n[bold cyan]:{match.port}/{match.protocol}[/bold cyan]  "
        f"[yellow]{match.fingerprint}[/yellow]  "
        f"{sev_badge}  [dim]{len(match.cves)} CVE[/dim]"
    )

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold dim",
        expand=False,
        padding=(0, 1),
    )
    table.add_column("CVE ID", style="bold white", width=18)
    table.add_column("Sév.", justify="center", width=12)
    table.add_column("Score", justify="center", width=7)
    table.add_column("Publié", style="dim", width=12)
    table.add_column("Description", style="dim", width=52)

    for cve in match.cves:
        desc = (
            cve.description[:80] + "…" if len(cve.description) > 80 else cve.description
        )
        table.add_row(
            cve.cve_id,
            _SEV_STYLE.get(cve.severity, cve.severity),
            _score_style(cve.score),
            cve.published,
            desc,
        )
    console.print(table)
