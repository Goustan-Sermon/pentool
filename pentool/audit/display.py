"""Affichage Rich des résultats Phase 3 — Audit."""

from __future__ import annotations
from rich.table import Table
from rich.panel import Panel
from rich       import box

from pentool.utils              import console, section, success, warning, info
from pentool.audit.web_fingerprint import WebAppFingerprint
from pentool.audit.misconfig       import MisconfigReport, MisconfigFinding


_SEV_STYLE = {
    "CRITICAL": "[critical] CRITICAL [/critical]",
    "HIGH":     "[high] HIGH [/high]",
    "MEDIUM":   "[medium] MEDIUM [/medium]",
    "LOW":      "[low] LOW [/low]",
    "INFO":     "[info] INFO [/info]",
}


def print_fingerprints(fps: list[WebAppFingerprint]) -> None:
    if not fps:
        info("Aucune application web identifiée.")
        return

    t = Table(box=box.ROUNDED, header_style="bold cyan", border_style="dim", expand=False)
    t.add_column("URL",         style="cyan",        width=38)
    t.add_column("Application", style="bold yellow", width=18)
    t.add_column("Version",     style="magenta",     width=14)
    t.add_column("Confiance",   justify="center",    width=10)
    t.add_column("CVE",         justify="center",    width=6)

    for fp in fps:
        ver     = fp.version or "[dim]inconnue[/dim]"
        conf    = "[success]haute[/success]" if fp.confidence == "high" else "[warning]moyenne[/warning]"
        ncve    = str(len(fp.cves)) if fp.cves else "[dim]—[/dim]"
        t.add_row(fp.url, fp.app_name, ver, conf, ncve)

    console.print(t)


def print_misconfig_report(report: MisconfigReport) -> None:
    if not report.findings:
        success(f"  Aucune misconfiguration détectée sur {report.target}")
        return

    crits = report.critical
    highs = report.high

    if crits:
        console.print(f"\n  [danger]⚠ {len(crits)} finding(s) CRITICAL sur {report.target}[/danger]")

    t = Table(box=box.ROUNDED, header_style="bold cyan", border_style="dim",
              expand=False, show_lines=True)
    t.add_column("Sévérité",    justify="center", width=12)
    t.add_column("Check",       style="white",    width=32)
    t.add_column("Description", style="dim",      width=55)

    for f in report.findings:
        t.add_row(
            _SEV_STYLE.get(f.severity, f.severity),
            f.check_name,
            f.description[:80],
        )

    console.print(t)