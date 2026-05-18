"""
Styles ReportLab centralisés pour le rapport PDF Pentool.
"""

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units  import mm
from reportlab.lib.enums  import TA_LEFT, TA_CENTER, TA_RIGHT


# ── Palette de couleurs ────────────────────────────────────────────────
class C:
    # Fond de page
    PAGE_BG       = colors.HexColor("#0F1117")
    # Accents
    ACCENT        = colors.HexColor("#00D4AA")      # teal cyan
    ACCENT_DIM    = colors.HexColor("#0A8C72")
    # Sévérités
    CRITICAL      = colors.HexColor("#FF3B3B")
    HIGH          = colors.HexColor("#FF8C00")
    MEDIUM        = colors.HexColor("#FFD600")
    LOW           = colors.HexColor("#4CAF50")
    INFO          = colors.HexColor("#2196F3")
    # Textes
    TEXT_PRIMARY   = colors.HexColor("#E8E8E8")
    TEXT_SECONDARY = colors.HexColor("#9E9E9E")
    TEXT_MUTED     = colors.HexColor("#5A5A6A")
    # Surfaces
    SURFACE_1     = colors.HexColor("#1A1D27")
    SURFACE_2     = colors.HexColor("#22263A")
    SURFACE_3     = colors.HexColor("#2C3150")
    # Bordures
    BORDER        = colors.HexColor("#2E3250")
    BORDER_LIGHT  = colors.HexColor("#3E4470")
    # Blanc pur
    WHITE         = colors.white
    BLACK         = colors.black


SEV_COLOR = {
    "CRITICAL": C.CRITICAL,
    "HIGH":     C.HIGH,
    "MEDIUM":   C.MEDIUM,
    "LOW":      C.LOW,
    "NONE":     C.TEXT_MUTED,
    "UNKNOWN":  C.TEXT_MUTED,
}

SEV_BG = {
    "CRITICAL": colors.HexColor("#3D0000"),
    "HIGH":     colors.HexColor("#3D1A00"),
    "MEDIUM":   colors.HexColor("#3D3000"),
    "LOW":      colors.HexColor("#003D0A"),
    "NONE":     C.SURFACE_2,
    "UNKNOWN":  C.SURFACE_2,
}


def build_styles() -> dict:
    """Construit et retourne le dictionnaire de styles ReportLab."""
    base = getSampleStyleSheet()

    styles: dict = {}

    # Titre de page de garde
    styles["cover_title"] = ParagraphStyle(
        "cover_title",
        fontName="Helvetica-Bold",
        fontSize=32,
        leading=38,
        textColor=C.ACCENT,
        alignment=TA_CENTER,
        spaceAfter=6 * mm,
    )

    # Sous-titre de page de garde
    styles["cover_subtitle"] = ParagraphStyle(
        "cover_subtitle",
        fontName="Helvetica",
        fontSize=14,
        leading=18,
        textColor=C.TEXT_SECONDARY,
        alignment=TA_CENTER,
        spaceAfter=4 * mm,
    )

    # Méta de page de garde (date, cible, etc.)
    styles["cover_meta"] = ParagraphStyle(
        "cover_meta",
        fontName="Helvetica",
        fontSize=11,
        leading=16,
        textColor=C.TEXT_MUTED,
        alignment=TA_CENTER,
        spaceAfter=2 * mm,
    )

    # Titre de section (h1)
    styles["section_title"] = ParagraphStyle(
        "section_title",
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=C.ACCENT,
        spaceBefore=8 * mm,
        spaceAfter=4 * mm,
        borderPad=0,
    )

    # Titre de sous-section (h2)
    styles["subsection_title"] = ParagraphStyle(
        "subsection_title",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=C.TEXT_PRIMARY,
        spaceBefore=5 * mm,
        spaceAfter=2 * mm,
    )

    # Corps de texte normal
    styles["body"] = ParagraphStyle(
        "body",
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=C.TEXT_PRIMARY,
        spaceAfter=2 * mm,
    )

    # Corps de texte secondaire (muted)
    styles["body_muted"] = ParagraphStyle(
        "body_muted",
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=C.TEXT_SECONDARY,
        spaceAfter=1 * mm,
    )

    # En-tête de tableau
    styles["table_header"] = ParagraphStyle(
        "table_header",
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=C.ACCENT,
        alignment=TA_LEFT,
    )

    # Cellule de tableau normale
    styles["table_cell"] = ParagraphStyle(
        "table_cell",
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=C.TEXT_PRIMARY,
    )

    # Cellule monospace (code, CVE ID, version)
    styles["table_mono"] = ParagraphStyle(
        "table_mono",
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=C.ACCENT,
    )

    # Description CVE (texte long dans tableau)
    styles["cve_desc"] = ParagraphStyle(
        "cve_desc",
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=C.TEXT_SECONDARY,
    )

    # Score de risque global (grand chiffre)
    styles["risk_score"] = ParagraphStyle(
        "risk_score",
        fontName="Helvetica-Bold",
        fontSize=42,
        leading=48,
        textColor=C.CRITICAL,
        alignment=TA_CENTER,
    )

    styles["risk_label"] = ParagraphStyle(
        "risk_label",
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=C.TEXT_SECONDARY,
        alignment=TA_CENTER,
    )

    # Bullet de liste
    styles["bullet"] = ParagraphStyle(
        "bullet",
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=C.TEXT_PRIMARY,
        leftIndent=10,
        spaceAfter=1 * mm,
        bulletIndent=0,
    )

    # URL / lien
    styles["url"] = ParagraphStyle(
        "url",
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=C.INFO,
    )

    return styles