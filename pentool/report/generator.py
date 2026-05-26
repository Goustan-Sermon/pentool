"""
Générateur de rapport PDF — Pentool ISEN.

Prend en entrée le dict JSON produit par `pentool scan --output`
et génère un rapport PDF professionnel multi-pages avec :
  - Page de garde
  - Sommaire exécutif + score de risque global
  - Tableau des ports / services détectés
  - Section DNS / sous-domaines
  - Section fuzzing HTTP
  - Section CVE détaillée (une sous-section par service)
  - Recommandations
  - Pied de page sur chaque page
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import Flowable

from pentool.report.styles import SEV_BG, SEV_COLOR, C, build_styles
from pentool.utils import info, success, warning

# ──────────────────────────────────────────────
# Flowable personnalisé : rectangle coloré (badge)
# ──────────────────────────────────────────────


class ColorRect(Flowable):
    """Rectangle plein utilisé comme séparateur ou badge de couleur."""

    def __init__(self, width, height, fill_color, radius=2):
        super().__init__()
        self.width = width
        self.height = height
        self._fill = fill_color
        self._r = radius

    def draw(self):
        self.canv.setFillColor(self._fill)
        self.canv.roundRect(0, 0, self.width, self.height, self._r, fill=1, stroke=0)


# ──────────────────────────────────────────────
# Helpers de mise en forme
# ──────────────────────────────────────────────


def _sev_badge_para(severity: str, styles: dict) -> Paragraph:
    """Retourne un Paragraph coloré pour la sévérité."""
    col = SEV_COLOR.get(severity, C.TEXT_MUTED)
    hex_col = col.hexval() if hasattr(col, "hexval") else "#9E9E9E"
    return Paragraph(
        f'<font color="{hex_col}"><b>{severity}</b></font>',
        styles["table_cell"],
    )


def _score_para(score, styles: dict) -> Paragraph:
    if score is None:
        return Paragraph("—", styles["table_cell"])
    if score >= 9.0:
        col = "#FF3B3B"
    elif score >= 7.0:
        col = "#FF8C00"
    elif score >= 4.0:
        col = "#FFD600"
    else:
        col = "#4CAF50"
    return Paragraph(
        f'<font color="{col}"><b>{score:.1f}</b></font>', styles["table_cell"]
    )


def _trunc(text: str, n: int = 90) -> str:
    return text[:n] + "…" if len(text) > n else text


def _fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024**2:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024**2:.1f} MB"


# ──────────────────────────────────────────────
# Style de tableau générique sombre
# ──────────────────────────────────────────────


def _dark_table_style(header_bg=None) -> TableStyle:
    hbg = header_bg or C.SURFACE_3
    return TableStyle(
        [
            # En-tête
            ("BACKGROUND", (0, 0), (-1, 0), hbg),
            ("TEXTCOLOR", (0, 0), (-1, 0), C.ACCENT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
            ("TOPPADDING", (0, 0), (-1, 0), 4),
            # Corps lignes alternées
            ("BACKGROUND", (0, 1), (-1, -1), C.SURFACE_1),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C.SURFACE_1, C.SURFACE_2]),
            ("TEXTCOLOR", (0, 1), (-1, -1), C.TEXT_PRIMARY),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 3),
            ("TOPPADDING", (0, 1), (-1, -1), 3),
            # Grille
            ("GRID", (0, 0), (-1, -1), 0.3, C.BORDER),
            ("LINEBELOW", (0, 0), (-1, 0), 0.8, C.ACCENT),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]
    )


# ──────────────────────────────────────────────
# Callbacks page (fond + numéro de page)
# ──────────────────────────────────────────────


class _PageTemplate:
    """Callbacks pour fond de page et pied de page."""

    def __init__(self, target: str, scan_date: str):
        self._target = target
        self._scan_date = scan_date

    def on_page(self, canvas, doc):
        canvas.saveState()
        w, h = A4

        # Fond sombre
        canvas.setFillColor(C.PAGE_BG)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)

        # Bande colorée en haut
        canvas.setFillColor(C.SURFACE_1)
        canvas.rect(0, h - 14 * mm, w, 14 * mm, fill=1, stroke=0)
        canvas.setFillColor(C.ACCENT)
        canvas.rect(0, h - 14 * mm, w, 0.8 * mm, fill=1, stroke=0)

        # Logo / nom outil dans l'en-tête
        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(C.ACCENT)
        canvas.drawString(15 * mm, h - 9 * mm, "PENTOOL")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(C.TEXT_MUTED)
        canvas.drawString(40 * mm, h - 9 * mm, f"Cible : {self._target}")
        canvas.drawRightString(w - 15 * mm, h - 9 * mm, f"Scan : {self._scan_date}")

        # Bande colorée en bas
        canvas.setFillColor(C.SURFACE_1)
        canvas.rect(0, 0, w, 10 * mm, fill=1, stroke=0)
        canvas.setFillColor(C.ACCENT)
        canvas.rect(0, 10 * mm, w, 0.5 * mm, fill=1, stroke=0)

        # Numéro de page
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(C.TEXT_MUTED)
        canvas.drawCentredString(w / 2, 3.5 * mm, f"Page {doc.page}")
        canvas.drawString(15 * mm, 3.5 * mm, "CONFIDENTIEL — Usage pédagogique ISEN")
        canvas.drawRightString(w - 15 * mm, 3.5 * mm, "Pentool v0.1.0")

        canvas.restoreState()

    def on_first_page(self, canvas, doc):
        """Page de garde : fond plein sans en-tête/pied standard."""
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(C.PAGE_BG)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)
        canvas.restoreState()


# ──────────────────────────────────────────────
# Générateur principal
# ──────────────────────────────────────────────


class ReportGenerator:
    """
    Génère le rapport PDF depuis le dict JSON de scan.

    Usage :
        gen = ReportGenerator(scan_data)
        gen.build("rapport_pentest.pdf")
    """

    def __init__(self, scan_data: dict) -> None:
        self._data = scan_data
        self._styles = build_styles()
        self._target = scan_data.get("target", "Cible inconnue")
        self._date = datetime.now().strftime("%d/%m/%Y %H:%M")

        # Sous-sections extraites
        self._port_data = scan_data.get("port_scan", {})
        self._dns_data = scan_data.get("dns_enum", {})
        # fuzz peut etre une liste (multi-ports) ou un dict (single)
        _fuzz_raw = scan_data.get("fuzz", [])
        if isinstance(_fuzz_raw, dict):
            _fuzz_raw = [_fuzz_raw] if _fuzz_raw else []
        self._fuzz_data_list: list[dict] = _fuzz_raw
        # Pour compatibilite avec le reste du code : on fusionne en un seul dict
        if self._fuzz_data_list:
            all_results = []
            for fd in self._fuzz_data_list:
                all_results.extend(fd.get("results", []))
            self._fuzz_data = {
                "target_url": self._fuzz_data_list[0].get("target_url", "—"),
                "total_tested": sum(
                    fd.get("total_tested", 0) for fd in self._fuzz_data_list
                ),
                "scan_time": sum(
                    fd.get("scan_time", 0.0) for fd in self._fuzz_data_list
                ),
                "results": all_results,
            }
        else:
            self._fuzz_data = {}

        from urllib.parse import urlparse

        self._cve_data = scan_data.get("cve_matches", [])
        self._audit_data = scan_data.get("audit", {})

        for fp in self._audit_data.get("fingerprints", []):
            cves = fp.get("cves", [])
            if cves:
                url_p = urlparse(fp.get("url", ""))
                port_virtuel = url_p.port or (443 if url_p.scheme == "https" else 80)

                self._cve_data.append(
                    {
                        "port": port_virtuel,
                        "protocol": "tcp",
                        "service_name": "Web App",
                        "service_version": fp.get("version") or "inconnue",
                        "fingerprint": fp.get("app_name", ""),
                        "cves": cves,
                    }
                )

    # ------------------------------------------------------------------
    def build(self, output_path: str | Path) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        tpl = _PageTemplate(self._target, self._date)

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            leftMargin=15 * mm,
            rightMargin=15 * mm,
            topMargin=20 * mm,
            bottomMargin=16 * mm,
            title=f"Rapport Pentest — {self._target}",
            author="Pentool ISEN",
            subject="Rapport de test d'intrusion automatisé",
        )

        story = []
        story += self._cover_page()
        story += self._executive_summary()
        story += self._section_ports()
        if self._dns_data:
            story += self._section_dns()
        if self._fuzz_data:
            story += self._section_fuzz()
        if self._cve_data:
            story += self._section_cve()
        if self._audit_data.get("misconfigs") or self._audit_data.get("fingerprints"):
            story += self._section_audit()
        story += self._section_recommendations()

        doc.build(
            story,
            onFirstPage=tpl.on_first_page,
            onLaterPages=tpl.on_page,
        )

        return output_path

    # ──────────────────────────────────────────
    # PAGE DE GARDE
    # ──────────────────────────────────────────

    def _cover_page(self) -> list:
        S = self._styles
        story = []

        story.append(Spacer(1, 40 * mm))

        # Barre décorative
        story.append(ColorRect(180 * mm, 1.5 * mm, C.ACCENT))
        story.append(Spacer(1, 8 * mm))

        story.append(Paragraph("RAPPORT DE PENTEST", S["cover_title"]))
        story.append(Paragraph("TEST D'INTRUSION AUTOMATISÉ", S["cover_subtitle"]))

        story.append(Spacer(1, 6 * mm))
        story.append(ColorRect(180 * mm, 0.5 * mm, C.SURFACE_3))
        story.append(Spacer(1, 10 * mm))

        # Informations cible
        services = self._port_data.get("services", [])
        open_svcs = [s for s in services if s.get("state") == "open"]
        total_cve = sum(len(m.get("cves", [])) for m in self._cve_data)
        critical = sum(
            sum(1 for c in m.get("cves", []) if c.get("severity") == "CRITICAL")
            for m in self._cve_data
        )

        meta_lines = [
            ("Cible", self._target),
            ("IP détectée", self._port_data.get("ip", "—")),
            ("OS", self._port_data.get("os_name", "—")),
            ("Date du scan", self._date),
            ("Ports ouverts", str(len(open_svcs))),
            ("CVE trouvées", str(total_cve)),
            ("CVE CRITICAL", str(critical)),
        ]

        for label, value in meta_lines:
            line = (
                f'<font color="#00D4AA"><b>{label} :</b></font>  '
                f'<font color="#E8E8E8">{value}</font>'
            )
            story.append(Paragraph(line, S["cover_meta"]))

        story.append(Spacer(1, 10 * mm))
        story.append(ColorRect(180 * mm, 1.5 * mm, C.ACCENT))
        story.append(Spacer(1, 20 * mm))

        story.append(
            Paragraph("Projet ISEN — Réalisé avec Pentool v0.1.0", S["cover_meta"])
        )
        story.append(
            Paragraph(
                '<font color="#FF3B3B"><b>CONFIDENTIEL — Usage pédagogique uniquement</b></font>',
                S["cover_meta"],
            )
        )

        story.append(PageBreak())
        return story

    # ──────────────────────────────────────────
    # SOMMAIRE EXÉCUTIF
    # ──────────────────────────────────────────

    def _executive_summary(self) -> list:
        S = self._styles
        story = []

        story.append(Paragraph("1. Sommaire Exécutif", S["section_title"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=C.BORDER, spaceAfter=4 * mm)
        )

        # Score de risque global (max CVSS trouvé)
        all_scores = [
            c.get("cvss_v3_score") or c.get("cvss_v2_score") or 0
            for m in self._cve_data
            for c in m.get("cves", [])
        ]
        max_score = max(all_scores) if all_scores else 0.0

        if max_score >= 9.0:
            risk_label, risk_col = "CRITIQUE", "#FF3B3B"
        elif max_score >= 7.0:
            risk_label, risk_col = "ÉLEVÉ", "#FF8C00"
        elif max_score >= 4.0:
            risk_label, risk_col = "MODÉRÉ", "#FFD600"
        elif max_score > 0:
            risk_label, risk_col = "FAIBLE", "#4CAF50"
        else:
            risk_label, risk_col = "INCONNU", "#9E9E9E"

        # Compteurs
        services = self._port_data.get("services", [])
        open_svcs = [s for s in services if s.get("state") == "open"]
        total_cve = sum(len(m.get("cves", [])) for m in self._cve_data)
        n_crit = sum(
            sum(1 for c in m.get("cves", []) if c.get("severity") == "CRITICAL")
            for m in self._cve_data
        )
        n_high = sum(
            sum(1 for c in m.get("cves", []) if c.get("severity") == "HIGH")
            for m in self._cve_data
        )
        n_medium = sum(
            sum(1 for c in m.get("cves", []) if c.get("severity") == "MEDIUM")
            for m in self._cve_data
        )
        fuzz_found = len(
            [
                r
                for r in self._fuzz_data.get("results", [])
                if r.get("status_code") in (200, 201, 301, 302, 403)
            ]
        )

        # Tableau de synthèse
        summary_data = [
            [
                Paragraph("Indicateur", S["table_header"]),
                Paragraph("Valeur", S["table_header"]),
                Paragraph("Détail", S["table_header"]),
            ],
            [
                Paragraph("Score de risque global", S["table_cell"]),
                Paragraph(
                    f'<font color="{risk_col}"><b>{max_score:.1f} / 10</b></font>',
                    S["table_cell"],
                ),
                Paragraph(
                    f'<font color="{risk_col}"><b>{risk_label}</b></font>',
                    S["table_cell"],
                ),
            ],
            [
                Paragraph("Ports ouverts", S["table_cell"]),
                Paragraph(str(len(open_svcs)), S["table_cell"]),
                Paragraph(
                    ", ".join(str(s["port"]) for s in open_svcs[:8]), S["table_cell"]
                ),
            ],
            [
                Paragraph("CVE CRITICAL", S["table_cell"]),
                Paragraph(
                    f'<font color="#FF3B3B"><b>{n_crit}</b></font>', S["table_cell"]
                ),
                Paragraph("Score CVSS >= 9.0", S["table_cell"]),
            ],
            [
                Paragraph("CVE HIGH", S["table_cell"]),
                Paragraph(
                    f'<font color="#FF8C00"><b>{n_high}</b></font>', S["table_cell"]
                ),
                Paragraph("Score CVSS 7.0–8.9", S["table_cell"]),
            ],
            [
                Paragraph("CVE MEDIUM", S["table_cell"]),
                Paragraph(
                    f'<font color="#FFD600"><b>{n_medium}</b></font>', S["table_cell"]
                ),
                Paragraph("Score CVSS 4.0–6.9", S["table_cell"]),
            ],
            [
                Paragraph("Répertoires HTTP trouvés", S["table_cell"]),
                Paragraph(str(fuzz_found), S["table_cell"]),
                Paragraph(
                    f"{self._fuzz_data.get('total_tested', 0)} chemins testés",
                    S["table_cell"],
                ),
            ],
        ]

        col_widths = [70 * mm, 35 * mm, 75 * mm]
        t = Table(summary_data, colWidths=col_widths, repeatRows=1)
        t.setStyle(_dark_table_style())
        story.append(t)
        story.append(Spacer(1, 5 * mm))

        # Texte de conclusion exécutive
        if max_score >= 9.0:
            conclusion = (
                "Le système analysé présente un niveau de risque <b>CRITIQUE</b>. "
                "Des vulnérabilités permettant une prise de contrôle complète ont été identifiées. "
                "Une remédiation immédiate est requise avant toute mise en production."
            )
        elif max_score >= 7.0:
            conclusion = (
                "Le système présente un niveau de risque <b>ÉLEVÉ</b>. "
                "Plusieurs vulnérabilités exploitables ont été identifiées. "
                "Une remédiation prioritaire est recommandée."
            )
        elif max_score > 0:
            conclusion = (
                "Le système présente un niveau de risque <b>MODÉRÉ</b>. "
                "Des vulnérabilités nécessitant attention ont été identifiées. "
                "Un plan de remédiation est conseillé."
            )
        else:
            conclusion = "Aucune vulnérabilité CVE n'a pu être corrélée avec les services détectés."

        story.append(Paragraph(conclusion, S["body"]))
        story.append(PageBreak())
        return story

    # ──────────────────────────────────────────
    # SECTION PORTS / SERVICES
    # ──────────────────────────────────────────

    def _section_ports(self) -> list:
        S = self._styles
        story = []

        story.append(Paragraph("2. Services Détectés", S["section_title"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=C.BORDER, spaceAfter=3 * mm)
        )

        # Infos hôte
        ip = self._port_data.get("ip", "—")
        hostname = self._port_data.get("hostname", "") or "—"
        os_name = self._port_data.get("os_name", "—")
        scan_t = self._port_data.get("scan_time", "—")
        scan_args = self._port_data.get("scan_args", "—")

        host_info = (
            f"<b>IP :</b> {ip}   <b>Hostname :</b> {hostname}   "
            f"<b>OS :</b> {os_name}   <b>Durée :</b> {scan_t}s"
        )
        story.append(Paragraph(host_info, S["body_muted"]))
        story.append(
            Paragraph(
                f"<b>Commande nmap :</b> <font name='Courier'>{scan_args}</font>",
                S["body_muted"],
            )
        )
        story.append(Spacer(1, 3 * mm))

        services = self._port_data.get("services", [])
        open_svcs = [s for s in services if s.get("state") == "open"]

        if not open_svcs:
            story.append(Paragraph("Aucun port ouvert détecté.", S["body"]))
            story.append(PageBreak())
            return story

        header = [
            Paragraph("Port", S["table_header"]),
            Paragraph("Proto", S["table_header"]),
            Paragraph("Service", S["table_header"]),
            Paragraph("Produit", S["table_header"]),
            Paragraph("Version", S["table_header"]),
            Paragraph("CPE", S["table_header"]),
        ]
        rows = [header]
        for svc in open_svcs:
            cpe = svc.get("cpe", [])
            cpe_str = cpe[0] if cpe else "—"
            rows.append(
                [
                    Paragraph(str(svc.get("port", "")), S["table_mono"]),
                    Paragraph(svc.get("protocol", ""), S["table_cell"]),
                    Paragraph(svc.get("service", ""), S["table_cell"]),
                    Paragraph(svc.get("product", "") or "—", S["table_cell"]),
                    Paragraph(svc.get("version", "") or "—", S["table_mono"]),
                    Paragraph(_trunc(cpe_str, 40), S["cve_desc"]),
                ]
            )

        col_widths = [16 * mm, 14 * mm, 20 * mm, 38 * mm, 26 * mm, 66 * mm]
        t = Table(rows, colWidths=col_widths, repeatRows=1)
        t.setStyle(_dark_table_style())
        story.append(t)
        story.append(PageBreak())
        return story

    # ──────────────────────────────────────────
    # SECTION DNS
    # ──────────────────────────────────────────

    def _section_dns(self) -> list:
        S = self._styles
        story = []

        story.append(Paragraph("3. Énumération DNS", S["section_title"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=C.BORDER, spaceAfter=3 * mm)
        )

        records = self._dns_data.get("records", [])
        subdomains = self._dns_data.get("subdomains", [])
        whois = self._dns_data.get("whois_data", {})

        # Enregistrements DNS
        if records:
            story.append(Paragraph("3.1 Enregistrements DNS", S["subsection_title"]))
            header = [
                Paragraph("Type", S["table_header"]),
                Paragraph("Valeur", S["table_header"]),
                Paragraph("TTL", S["table_header"]),
            ]
            rows = [header]
            for r in records:
                rows.append(
                    [
                        Paragraph(r.get("rtype", ""), S["table_mono"]),
                        Paragraph(_trunc(r.get("value", ""), 70), S["table_cell"]),
                        Paragraph(str(r.get("ttl", "")), S["body_muted"]),
                    ]
                )
            t = Table(rows, colWidths=[18 * mm, 140 * mm, 22 * mm], repeatRows=1)
            t.setStyle(_dark_table_style())
            story.append(t)
            story.append(Spacer(1, 4 * mm))

        # Sous-domaines
        if subdomains:
            story.append(
                Paragraph(
                    f"3.2 Sous-domaines découverts ({len(subdomains)})",
                    S["subsection_title"],
                )
            )
            header = [
                Paragraph("Sous-domaine", S["table_header"]),
                Paragraph("IP", S["table_header"]),
                Paragraph("CNAME", S["table_header"]),
            ]
            rows = [header]
            for sub in subdomains:
                rows.append(
                    [
                        Paragraph(sub.get("subdomain", ""), S["table_mono"]),
                        Paragraph(sub.get("ip", ""), S["table_cell"]),
                        Paragraph(sub.get("cname", "") or "—", S["body_muted"]),
                    ]
                )
            t = Table(rows, colWidths=[80 * mm, 50 * mm, 50 * mm], repeatRows=1)
            t.setStyle(_dark_table_style())
            story.append(t)
            story.append(Spacer(1, 4 * mm))

        # WHOIS
        if whois:
            story.append(Paragraph("3.3 WHOIS", S["subsection_title"]))
            whois_fields = [
                ("Registrar", "registrar"),
                ("Créé le", "creation_date"),
                ("Expire le", "expiration_date"),
                ("Mis à jour", "updated_date"),
                ("Name Servers", "name_servers"),
                ("Pays", "registrant_country"),
            ]
            rows = [
                [
                    Paragraph("Champ", S["table_header"]),
                    Paragraph("Valeur", S["table_header"]),
                ]
            ]
            for label, key in whois_fields:
                val = whois.get(key)
                if val:
                    val_str = ", ".join(val[:3]) if isinstance(val, list) else str(val)
                    rows.append(
                        [
                            Paragraph(label, S["table_cell"]),
                            Paragraph(_trunc(val_str, 80), S["table_cell"]),
                        ]
                    )
            if len(rows) > 1:
                t = Table(rows, colWidths=[40 * mm, 140 * mm], repeatRows=1)
                t.setStyle(_dark_table_style())
                story.append(t)

        story.append(PageBreak())
        return story

    # ──────────────────────────────────────────
    # SECTION FUZZING
    # ──────────────────────────────────────────

    def _section_fuzz(self) -> list:
        S = self._styles
        story = []
        n = 3 if self._dns_data else 2  # numéro de section dynamique

        story.append(
            Paragraph(f"{n + 1}. Fuzzing de Répertoires HTTP", S["section_title"])
        )
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=C.BORDER, spaceAfter=3 * mm)
        )

        results = self._fuzz_data.get("results", [])
        tested = self._fuzz_data.get("total_tested", 0)
        scan_time = self._fuzz_data.get("scan_time", 0)
        target_url = self._fuzz_data.get("target_url", "—")
        interesting = [
            r
            for r in results
            if r.get("status_code") in (200, 201, 204, 301, 302, 403, 401)
        ]

        story.append(
            Paragraph(
                f"<b>URL cible :</b> {target_url}   "
                f"<b>Chemins testés :</b> {tested}   "
                f"<b>Trouvés :</b> {len(interesting)}   "
                f"<b>Durée :</b> {scan_time:.1f}s",
                S["body_muted"],
            )
        )
        story.append(Spacer(1, 3 * mm))

        if not interesting:
            story.append(
                Paragraph("Aucune ressource accessible découverte.", S["body"])
            )
            story.append(PageBreak())
            return story

        header = [
            Paragraph("Sévérité", S["table_header"]),
            Paragraph("Code HTTP", S["table_header"]),
            Paragraph("Chemin", S["table_header"]),
            Paragraph("Taille", S["table_header"]),
            Paragraph("Type MIME", S["table_header"]),
        ]
        rows = [header]
        for r in interesting:
            sev = r.get("severity", "info").upper()
            code = r.get("status_code", "")
            col = SEV_COLOR.get(sev, C.TEXT_SECONDARY)
            hex_c = col.hexval() if hasattr(col, "hexval") else "#9E9E9E"
            rows.append(
                [
                    Paragraph(
                        f'<font color="{hex_c}"><b>{sev}</b></font>', S["table_cell"]
                    ),
                    Paragraph(str(code), S["table_cell"]),
                    Paragraph(r.get("path", ""), S["table_mono"]),
                    Paragraph(_fmt_size(r.get("content_length", 0)), S["body_muted"]),
                    Paragraph(
                        _trunc(r.get("content_type", "") or "—", 25), S["body_muted"]
                    ),
                ]
            )

        col_widths = [22 * mm, 20 * mm, 80 * mm, 20 * mm, 38 * mm]
        t = Table(rows, colWidths=col_widths, repeatRows=1)
        t.setStyle(_dark_table_style())
        story.append(t)
        story.append(PageBreak())
        return story

    # ──────────────────────────────────────────
    # SECTION CVE
    # ──────────────────────────────────────────

    def _section_cve(self) -> list:
        S = self._styles
        story = []

        # Calcul du numéro de section
        sec = 2
        if self._dns_data:
            sec += 1
        if self._fuzz_data:
            sec += 1
        sec += 1

        story.append(
            Paragraph(f"{sec}. Vulnérabilités CVE Identifiées", S["section_title"])
        )
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=C.BORDER, spaceAfter=3 * mm)
        )

        # Tableau récapitulatif global
        header = [
            Paragraph("Port", S["table_header"]),
            Paragraph("Service", S["table_header"]),
            Paragraph("Version", S["table_header"]),
            Paragraph("# CVE", S["table_header"]),
            Paragraph("CRITICAL", S["table_header"]),
            Paragraph("HIGH", S["table_header"]),
            Paragraph("Score max", S["table_header"]),
        ]
        rows = [header]
        for m in self._cve_data:
            n_crit = sum(
                1 for c in m.get("cves", []) if c.get("severity") == "CRITICAL"
            )
            n_high = sum(1 for c in m.get("cves", []) if c.get("severity") == "HIGH")
            scores = [
                c.get("cvss_v3_score") or c.get("cvss_v2_score") or 0
                for c in m.get("cves", [])
            ]
            max_sc = max(scores) if scores else None
            rows.append(
                [
                    Paragraph(str(m.get("port", "")), S["table_mono"]),
                    Paragraph(m.get("service_name", ""), S["table_cell"]),
                    Paragraph(m.get("service_version", "") or "—", S["table_mono"]),
                    Paragraph(str(len(m.get("cves", []))), S["table_cell"]),
                    Paragraph(
                        f'<font color="#FF3B3B"><b>{n_crit}</b></font>'
                        if n_crit
                        else "0",
                        S["table_cell"],
                    ),
                    Paragraph(
                        f'<font color="#FF8C00"><b>{n_high}</b></font>'
                        if n_high
                        else "0",
                        S["table_cell"],
                    ),
                    _score_para(max_sc, S),
                ]
            )

        col_widths = [16 * mm, 22 * mm, 26 * mm, 16 * mm, 22 * mm, 16 * mm, 22 * mm]
        t = Table(rows, colWidths=col_widths, repeatRows=1)
        t.setStyle(_dark_table_style())
        story.append(t)
        story.append(Spacer(1, 6 * mm))

        # Détail par service
        for m in self._cve_data:
            cves = m.get("cves", [])
            if not cves:
                continue

            # Titre service
            story.append(
                KeepTogether(
                    [
                        Paragraph(
                            f'Port <font name="Courier" color="#00D4AA">:{m.get("port")}/{m.get("protocol", "tcp")}</font>'
                            f"  —  {m.get('fingerprint', '')}",
                            S["subsection_title"],
                        ),
                    ]
                )
            )

            # Tableau CVE du service
            cve_header = [
                Paragraph("CVE ID", S["table_header"]),
                Paragraph("Sévérité", S["table_header"]),
                Paragraph("Score", S["table_header"]),
                Paragraph("Publié", S["table_header"]),
                Paragraph("CWE", S["table_header"]),
                Paragraph("Description", S["table_header"]),
            ]
            cve_rows = [cve_header]
            for c in cves:
                sev = c.get("severity", "UNKNOWN")
                score_v = c.get("score")
                cwe_list = c.get("cwe_ids", [])
                desc = _trunc(c.get("description", ""), 100)
                cve_id = c.get("cve_id", "")

                col = SEV_COLOR.get(sev, C.TEXT_MUTED)
                hex_c = col.hexval() if hasattr(col, "hexval") else "#9E9E9E"

                cve_rows.append(
                    [
                        Paragraph(
                            f'<font color="#00D4AA">{cve_id}</font>', S["table_mono"]
                        ),
                        Paragraph(
                            f'<font color="{hex_c}"><b>{sev}</b></font>',
                            S["table_cell"],
                        ),
                        _score_para(score_v, S),
                        Paragraph(c.get("published", "—"), S["body_muted"]),
                        Paragraph(", ".join(cwe_list[:2]) or "—", S["body_muted"]),
                        Paragraph(desc, S["cve_desc"]),
                    ]
                )

            cve_col_w = [30 * mm, 22 * mm, 16 * mm, 18 * mm, 18 * mm, 76 * mm]
            ct = Table(cve_rows, colWidths=cve_col_w, repeatRows=1)
            ct.setStyle(_dark_table_style())
            story.append(ct)
            story.append(Spacer(1, 4 * mm))

        story.append(PageBreak())
        return story

    # ──────────────────────────────────────────
    # SECTION AUDITS
    # ──────────────────────────────────────────

    def _section_audit(self) -> list:
        S = self._styles
        story = []

        # Calcul du numéro de section dynamique
        sec = 3
        if self._dns_data:
            sec += 1
        if self._fuzz_data:
            sec += 1
        if self._cve_data:
            sec += 1

        story.append(
            Paragraph(f"{sec}. Audit Web & Misconfigurations", S["section_title"])
        )
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=C.BORDER, spaceAfter=3 * mm)
        )

        misconfigs = self._audit_data.get("misconfigs", [])
        if not misconfigs:
            story.append(Paragraph("Aucune misconfiguration détectée.", S["body"]))
            story.append(PageBreak())
            return story

        fingerprints = self._audit_data.get("fingerprints", [])
        if fingerprints:
            story.append(Paragraph("Applications Web Détectées", S["subsection_title"]))
            fp_header = [
                Paragraph("Application", S["table_header"]),
                Paragraph("Version", S["table_header"]),
                Paragraph("Confiance", S["table_header"]),
                Paragraph("Vulnérabilités", S["table_header"]),
            ]
            fp_rows = [fp_header]
            for fp in fingerprints:
                app_name = fp.get("app_name", "")
                version = fp.get("version") or "inconnue"
                conf = fp.get("confidence", "")
                cves_count = len(fp.get("cves", []))

                fp_rows.append(
                    [
                        Paragraph(
                            f'<font color="#00D4AA">{app_name}</font>', S["table_cell"]
                        ),
                        Paragraph(version, S["table_mono"]),
                        Paragraph(conf, S["body_muted"]),
                        Paragraph(f"{cves_count} CVE(s)", S["table_cell"]),
                    ]
                )

            fp_table = Table(
                fp_rows, colWidths=[50 * mm, 30 * mm, 30 * mm, 40 * mm], repeatRows=1
            )
            fp_table.setStyle(_dark_table_style())
            story.append(fp_table)
            story.append(Spacer(1, 6 * mm))

        story.append(
            Paragraph("Misconfigurations HTTP & Réseau", S["subsection_title"])
        )

        for mc in misconfigs:
            target = mc.get("target", "")
            findings = mc.get("findings", [])
            if not findings:
                continue

            story.append(Paragraph(f"<b>Cible :</b> {target}", S["subsection_title"]))

            header = [
                Paragraph("Sévérité", S["table_header"]),
                Paragraph("Vérification", S["table_header"]),
                Paragraph("Description", S["table_header"]),
            ]
            rows = [header]

            for f in findings:
                sev = f.get("severity", "INFO")
                col = SEV_COLOR.get(sev, C.TEXT_MUTED)
                hex_c = col.hexval() if hasattr(col, "hexval") else "#9E9E9E"

                rows.append(
                    [
                        Paragraph(
                            f'<font color="{hex_c}"><b>{sev}</b></font>',
                            S["table_cell"],
                        ),
                        Paragraph(f.get("check_name", ""), S["table_cell"]),
                        Paragraph(
                            _trunc(f.get("description", ""), 120), S["body_muted"]
                        ),
                    ]
                )

            t = Table(rows, colWidths=[20 * mm, 50 * mm, 100 * mm], repeatRows=1)
            t.setStyle(_dark_table_style())
            story.append(t)
            story.append(Spacer(1, 5 * mm))

        story.append(PageBreak())
        return story

    # ──────────────────────────────────────────
    # SECTION RECOMMANDATIONS
    # ──────────────────────────────────────────

    def _section_recommendations(self) -> list:
        S = self._styles
        story = []

        # Numéro de section dynamique
        sec = 3
        if self._dns_data:
            sec += 1
        if self._fuzz_data:
            sec += 1
        if self._cve_data:
            sec += 1

        story.append(Paragraph(f"{sec}. Recommandations", S["section_title"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=C.BORDER, spaceAfter=3 * mm)
        )

        recs = self._build_recommendations()

        for level, title, detail in recs:
            col = SEV_COLOR.get(level, C.TEXT_MUTED)
            hc = col.hexval() if hasattr(col, "hexval") else "#9E9E9E"
            story.append(
                KeepTogether(
                    [
                        Paragraph(
                            f'<font color="{hc}">[{level}]</font>  <b>{title}</b>',
                            S["subsection_title"],
                        ),
                        Paragraph(detail, S["body"]),
                        Spacer(1, 2 * mm),
                    ]
                )
            )

        # Disclaimer
        story.append(Spacer(1, 8 * mm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=C.BORDER))
        story.append(Spacer(1, 3 * mm))
        story.append(
            Paragraph(
                "Ce rapport a été généré automatiquement par Pentool dans le cadre d'un projet "
                "pédagogique ISEN. Les résultats doivent être vérifiés manuellement avant toute "
                "action en environnement de production. L'outil ne garantit pas l'exhaustivité "
                "des vulnérabilités détectées.",
                S["body_muted"],
            )
        )
        return story

    def _build_recommendations(self) -> list[tuple[str, str, str]]:
        """Génère des recommandations contextuelles basées sur les résultats."""
        recs = []
        services = {
            s.get("service", "")
            for s in self._port_data.get("services", [])
            if s.get("state") == "open"
        }
        open_ports = [
            s.get("port")
            for s in self._port_data.get("services", [])
            if s.get("state") == "open"
        ]

        # CVE critiques
        for m in self._cve_data:
            for c in m.get("cves", []):
                if c.get("severity") == "CRITICAL":
                    recs.append(
                        (
                            "CRITICAL",
                            f"Corriger {c.get('cve_id')} sur le port {m.get('port')}",
                            f"{_trunc(c.get('description', ''), 160)} "
                            f"— Mettre à jour {m.get('fingerprint', '')} vers la dernière version stable. "
                            f"Consulter {c.get('nvd_url', 'https://nvd.nist.gov')} pour les correctifs disponibles.",
                        )
                    )
                    break  # une rec par service suffit

        # Ports inutiles
        risky = {21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC"}
        for port, name in risky.items():
            if port in open_ports:
                recs.append(
                    (
                        "HIGH",
                        f"Désactiver ou restreindre {name} (port {port})",
                        f"Le service {name} expose des données en clair ou présente un historique "
                        f"de vulnérabilités. Remplacer par un protocole sécurisé (SSH, RDP over VPN) "
                        f"ou restreindre via firewall aux seules IP autorisées.",
                    )
                )

        # Fichiers sensibles trouvés
        critical_paths = [
            r.get("path", "")
            for r in self._fuzz_data.get("results", [])
            if r.get("severity") in ("critical", "high") and r.get("status_code") == 200
        ]
        if critical_paths:
            recs.append(
                (
                    "CRITICAL",
                    "Supprimer les fichiers sensibles exposés",
                    f"Les chemins suivants sont accessibles publiquement : "
                    f"{', '.join(critical_paths[:5])}. "
                    f"Supprimer ou restreindre l'accès via la configuration du serveur web (.htaccess, nginx.conf).",
                )
            )

        # Recommandations génériques toujours présentes
        recs += [
            (
                "MEDIUM",
                "Mettre en place un pare-feu applicatif (WAF)",
                "Un WAF permettrait de filtrer les requêtes malveillantes et de limiter "
                "la surface d'attaque exposée. Envisager ModSecurity (Apache/Nginx) ou Cloudflare WAF.",
            ),
            (
                "MEDIUM",
                "Implémenter une politique de mises à jour régulières",
                "Maintenir tous les services à jour avec les derniers correctifs de sécurité. "
                "Automatiser avec un gestionnaire de paquets ou un outil comme Ansible.",
            ),
            (
                "LOW",
                "Activer la journalisation et la surveillance",
                "Centraliser les logs (ELK, Graylog) et mettre en place des alertes sur les "
                "comportements anormaux (tentatives de brute-force, scans de ports).",
            ),
            (
                "LOW",
                "Réaliser des audits de sécurité réguliers",
                "Planifier des tests d'intrusion périodiques (trimestriels ou semestriels) "
                "pour identifier les nouvelles vulnérabilités introduites par les mises à jour.",
            ),
        ]

        for mc in self._audit_data.get("misconfigs", []):
            for finding in mc.get("findings", []):
                recs.append(
                    (
                        finding.get("severity", "LOW"),
                        finding.get("check_name", "Misconfiguration"),
                        f"{finding.get('description', '')} Solution suggérée : {finding.get('remediation', '')}",
                    )
                )

        return recs


# ──────────────────────────────────────────────
# Fonction de haut niveau
# ──────────────────────────────────────────────


def generate_pdf(scan_data: dict, output_path: str | Path) -> Path:
    """
    Point d'entrée simplifié pour générer un rapport PDF.

    Args:
        scan_data:   dict JSON produit par pentool scan
        output_path: chemin du fichier PDF à créer

    Returns:
        Path du fichier PDF créé
    """
    gen = ReportGenerator(scan_data)
    return gen.build(output_path)
