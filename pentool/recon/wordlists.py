"""
Gestion des wordlists — intégration SecLists et wordlists embarquées.

Priorité de résolution :
  1. Chemin absolu fourni par l'utilisateur
  2. SecLists installé sur le système (/usr/share/seclists)
  3. Wordlists embarquées (toujours disponibles, pas de dépendance externe)
"""

from __future__ import annotations

from pathlib import Path
from typing  import Optional

from pentool.utils import info, warning


# ──────────────────────────────────────────────
# Chemins SecLists sur le système
# ──────────────────────────────────────────────

SECLISTS_ROOTS = [
    Path("/usr/share/seclists"),
    Path("/usr/share/SecLists"),
    Path("/opt/seclists"),
    Path("/opt/SecLists"),
    Path(Path.home() / "SecLists"),
    Path(Path.home() / "seclists"),
]


def _seclists_root() -> Optional[Path]:
    """Retourne le répertoire SecLists s'il existe, sinon None."""
    for p in SECLISTS_ROOTS:
        if p.exists():
            return p
    return None


# ──────────────────────────────────────────────
# Catalogue des wordlists SecLists utiles
# ──────────────────────────────────────────────

# Format : (clé, chemin relatif dans SecLists, description)
SECLISTS_CATALOG: list[tuple[str, str, str]] = [
    # ── Dir / Web fuzzing ─────────────────────────────────────────────
    ("web_common",
     "Discovery/Web-Content/common.txt",
     "Répertoires et fichiers web courants (~4 700 entrées)"),

    ("web_medium",
     "Discovery/Web-Content/directory-list-2.3-medium.txt",
     "Répertoires web — liste medium (~220 000 entrées)"),

    ("web_small",
     "Discovery/Web-Content/directory-list-2.3-small.txt",
     "Répertoires web — liste small (~87 000 entrées)"),

    ("web_big",
     "Discovery/Web-Content/big.txt",
     "Répertoires web — grande liste (~20 000 entrées)"),

    ("web_raft_dirs",
     "Discovery/Web-Content/raft-medium-directories.txt",
     "Répertoires RAFT medium (~30 000 entrées)"),

    ("web_raft_files",
     "Discovery/Web-Content/raft-medium-files.txt",
     "Fichiers RAFT medium (~17 000 entrées)"),

    ("api_endpoints",
     "Discovery/Web-Content/api/api-endpoints.txt",
     "Endpoints API REST courants"),

    ("api_objects",
     "Discovery/Web-Content/api/objects.txt",
     "Objets API courants"),

    # ── DNS / Vhosts ──────────────────────────────────────────────────
    ("dns_subdomains_1k",
     "Discovery/DNS/subdomains-top1million-5000.txt",
     "Sous-domaines top 5 000 (DNS + vhost)"),

    ("dns_subdomains_20k",
     "Discovery/DNS/subdomains-top1million-20000.txt",
     "Sous-domaines top 20 000"),

    ("dns_subdomains_110k",
     "Discovery/DNS/subdomains-top1million-110000.txt",
     "Sous-domaines top 110 000 (complet)"),

    ("dns_fierce",
     "Discovery/DNS/fierce-hostlist.txt",
     "Sous-domaines — liste Fierce (~2 300 entrées)"),

    # ── Mots de passe ─────────────────────────────────────────────────
    ("passwords_top100",
     "Passwords/Common-Credentials/10-million-password-list-top-100.txt",
     "Top 100 mots de passe les plus courants"),

    ("passwords_top1k",
     "Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
     "Top 1 000 mots de passe"),

    ("passwords_rockyou_1k",
     "Passwords/Leaked-Databases/rockyou-10.txt",
     "RockYou — top 10 000"),

    # ── Usernames ─────────────────────────────────────────────────────
    ("usernames_top",
     "Usernames/top-usernames-shortlist.txt",
     "Top usernames courants (~17 entrées)"),

    ("usernames_unix",
     "Usernames/unix-passwords.txt",
     "Usernames Unix courants"),

    # ── Fuzzing de paramètres / IDOR ──────────────────────────────────
    ("params_burp",
     "Discovery/Web-Content/burp-parameter-names.txt",
     "Noms de paramètres HTTP courants (~6 000)"),

    ("params_raft",
     "Discovery/Web-Content/raft-medium-words.txt",
     "Mots courants pour fuzzing de paramètres (~63 000)"),
]


# ──────────────────────────────────────────────
# Résolution d'une wordlist
# ──────────────────────────────────────────────

def resolve_wordlist(
    key_or_path: Optional[str],
    fallback: list[str],
    category:   str = "web",
) -> list[str]:
    """
    Résout une wordlist depuis :
      - Un chemin absolu fourni
      - Une clé SecLists (ex: "web_common")
      - Un fallback embarqué

    Args:
        key_or_path: clé SecLists, chemin absolu, ou None
        fallback:    wordlist embarquée à utiliser si rien d'autre
        category:    pour le message d'info

    Returns:
        Liste de strings prête à l'emploi
    """
    if key_or_path is None:
        root = _seclists_root()
        if root:
            # Choisir automatiquement une wordlist appropriée
            auto = _auto_select(category, root)
            if auto:
                return auto
        return fallback

    # Chemin absolu
    p = Path(key_or_path)
    if p.exists() and p.is_file():
        words = [l.strip() for l in p.read_text(errors="replace").splitlines()
                 if l.strip() and not l.startswith("#")]
        info(f"Wordlist : {p} ({len(words)} entrées)")
        return words

    # Clé du catalogue SecLists
    root = _seclists_root()
    if root:
        for key, rel_path, desc in SECLISTS_CATALOG:
            if key == key_or_path:
                full = root / rel_path
                if full.exists():
                    words = [l.strip() for l in full.read_text(errors="replace").splitlines()
                             if l.strip() and not l.startswith("#")]
                    info(f"SecLists [{key}] : {full.name} ({len(words)} entrées)")
                    return words
                else:
                    warning(f"SecLists trouvé mais fichier manquant : {full}")

    warning(f"Wordlist '{key_or_path}' introuvable — utilisation de la liste embarquée.")
    return fallback


def _auto_select(category: str, root: Path) -> Optional[list[str]]:
    """Sélectionne automatiquement la meilleure wordlist selon la catégorie."""
    category_map = {
        "web":   ["web_common", "web_big", "web_small"],
        "dns":   ["dns_subdomains_1k", "dns_fierce"],
        "vhost": ["dns_subdomains_1k", "dns_fierce"],
        "param": ["params_burp"],
    }
    keys = category_map.get(category, [])
    for key in keys:
        for k, rel, _ in SECLISTS_CATALOG:
            if k == key:
                full = root / rel
                if full.exists():
                    words = [l.strip() for l in full.read_text(errors="replace").splitlines()
                             if l.strip() and not l.startswith("#")]
                    info(f"SecLists auto [{key}] : {full.name} ({len(words)} entrées)")
                    return words
    return None


def list_available() -> list[dict]:
    """Retourne la liste des wordlists disponibles (SecLists + embarquées)."""
    root    = _seclists_root()
    results = []

    for key, rel_path, desc in SECLISTS_CATALOG:
        available = False
        path_str  = rel_path
        if root:
            full = root / rel_path
            if full.exists():
                available = True
                path_str  = str(full)

        results.append({
            "key":       key,
            "path":      path_str,
            "desc":      desc,
            "available": available,
            "source":    "seclists" if available else "embarquée (fallback)",
        })

    return results


def seclists_installed() -> bool:
    """Retourne True si SecLists est installé sur le système."""
    return _seclists_root() is not None