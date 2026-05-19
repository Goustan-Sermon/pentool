"""
Shell interactif Pentool — questionnaire guidé avec flèches, espace, entrée.

Utilise `questionary` si disponible, sinon fallback sur `rich.prompt`.
Lance `pentool scan` avec les options choisies à la fin.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Optional

from pentool.utils import console, section, info, warning


# ──────────────────────────────────────────────
# Détection de questionary
# ──────────────────────────────────────────────

def _has_questionary() -> bool:
    try:
        import questionary  # noqa
        return True
    except ImportError:
        return False


# ──────────────────────────────────────────────
# Questions du wizard
# ──────────────────────────────────────────────

PROFILES = [
    ("fast",     "Fast     — top 100 ports, T4  (rapide, ~30s)"),
    ("standard", "Standard — top 1000 ports, T3 (normal, ~2min) ← défaut"),
    ("full",     "Full     — tous les 65535 ports (~20min)"),
    ("stealth",  "Stealth  — SYN scan, T2 (discret)"),
    ("udp",      "UDP      — top 50 ports UDP"),
]

WORDLIST_CHOICES = [
    ("builtin",          "Intégrée — ~100 chemins courants (toujours disponible)"),
    ("web_common",       "SecLists — common.txt           (~4 700 entrées)"),
    ("web_big",          "SecLists — big.txt              (~20 000 entrées)"),
    ("web_medium",       "SecLists — medium               (~220 000 entrées)"),
    ("web_raft_dirs",    "SecLists — raft-medium-dirs     (~30 000 entrées)"),
    ("web_raft_files",   "SecLists — raft-medium-files    (~17 000 entrées)"),
]

VHOST_WORDLIST_CHOICES = [
    ("builtin",          "Intégrée — ~90 sous-domaines (toujours disponible)"),
    ("dns_subdomains_1k","SecLists — subdomains 5 000    (recommandé HTB)"),
    ("dns_subdomains_20k","SecLists — subdomains 20 000"),
    ("dns_fierce",       "SecLists — fierce-hostlist     (~2 300 entrées)"),
]


# ──────────────────────────────────────────────
# Wizard avec questionary
# ──────────────────────────────────────────────

def _run_questionary() -> Optional[list[str]]:
    """Wizard interactif avec questionary (flèches, espace, entrée)."""
    import questionary
    from questionary import Style

    custom_style = Style([
        ("qmark",        "fg:#00D4AA bold"),
        ("question",     "bold"),
        ("answer",       "fg:#00D4AA bold"),
        ("pointer",      "fg:#00D4AA bold"),
        ("highlighted",  "fg:#00D4AA bold"),
        ("selected",     "fg:#00D4AA"),
        ("separator",    "fg:#555555"),
        ("instruction",  "fg:#888888"),
    ])

    console.print()
    console.print("[bold cyan]╔══════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║   PENTOOL — Assistant de configuration   ║[/bold cyan]")
    console.print("[bold cyan]║   Flèches ↑↓ • Espace = sélect • Entrée ║[/bold cyan]")
    console.print("[bold cyan]╚══════════════════════════════════════════╝[/bold cyan]")
    console.print()

    # 1. Cible
    target = questionary.text(
        "Cible (IP ou domaine) :",
        style=custom_style,
    ).ask()
    if not target:
        return None

    # 2. Domaine (vhost)
    domain = questionary.text(
        "Domaine de base pour vhost fuzzing (laisser vide pour ignorer) :",
        style=custom_style,
    ).ask()

    # 3. Profil nmap
    profile_choice = questionary.select(
        "Profil de scan nmap :",
        choices=[questionary.Choice(label, value=val) for val, label in PROFILES],
        default="standard",
        style=custom_style,
    ).ask()

    # 4. Modules actifs
    modules = questionary.checkbox(
        "Modules à activer :",
        choices=[
            questionary.Choice("DNS + WHOIS + sous-domaines",  value="dns",   checked=True),
            questionary.Choice("Fuzzing HTTP de répertoires",   value="fuzz",  checked=True),
            questionary.Choice("VHost fuzzing",                 value="vhost", checked=True),
            questionary.Choice("Param fuzzing (endpoints API)", value="param", checked=True),
            questionary.Choice("Corrélation CVE via NVD",       value="cve",   checked=True),
            questionary.Choice("Audit (fingerprint + misconfig)", value="audit", checked=True),
            questionary.Choice("Rapport PDF automatique",       value="pdf",   checked=True),
        ],
        style=custom_style,
    ).ask()
    if modules is None:
        return None

    # 5. Wordlist fuzzing
    from pentool.recon.wordlists import seclists_installed, list_available
    if "fuzz" in modules:
        avail = {e["key"] for e in list_available() if e["available"]}
        fuzz_choices = [
            questionary.Choice(label, value=val, disabled="(SecLists non installé)" if val != "builtin" and val not in avail else None)
            for val, label in WORDLIST_CHOICES
        ]
        fuzz_wordlist = questionary.select(
            "Wordlist pour le fuzzing HTTP :",
            choices=fuzz_choices,
            style=custom_style,
        ).ask()
    else:
        fuzz_wordlist = None

    # 6. Fuzzing récursif
    recursive = False
    if "fuzz" in modules:
        recursive = questionary.confirm(
            "Activer le fuzzing récursif (plonge dans les sous-répertoires) ?",
            default=False,
            style=custom_style,
        ).ask()

    # 7. VHost wordlist
    if "vhost" in modules and domain:
        avail = {e["key"] for e in list_available() if e["available"]}
        vhost_choices = [
            questionary.Choice(label, value=val, disabled="(SecLists non installé)" if val != "builtin" and val not in avail else None)
            for val, label in VHOST_WORDLIST_CHOICES
        ]
        vhost_wordlist = questionary.select(
            "Wordlist pour le VHost fuzzing :",
            choices=vhost_choices,
            style=custom_style,
        ).ask()
    else:
        vhost_wordlist = None

    # 8. Clé API NVD
    api_key = ""
    if "cve" in modules:
        has_key = questionary.confirm(
            "Avez-vous une clé API NVD (accélère la corrélation CVE) ?",
            default=False,
            style=custom_style,
        ).ask()
        if has_key:
            api_key = questionary.text(
                "Clé API NVD :",
                style=custom_style,
            ).ask() or ""

    # 9. Fichier de sortie
    output = questionary.text(
        "Fichier de sortie JSON+PDF (ex: rapport.json — laisser vide pour ne pas sauvegarder) :",
        default="rapport.json",
        style=custom_style,
    ).ask()

    # 10. Threads
    threads = questionary.text(
        "Nombre de threads pour le fuzzing :",
        default="10",
        style=custom_style,
    ).ask() or "10"

    # ── Construction de la commande ──────────────────────────────────
    return _build_command(
        target=target,
        domain=domain or "",
        profile=profile_choice or "standard",
        modules=modules or [],
        api_key=api_key,
        output=output or "",
        threads=threads,
        recursive=recursive,
    )


# ──────────────────────────────────────────────
# Wizard fallback Rich (sans questionary)
# ──────────────────────────────────────────────

def _run_rich_fallback() -> Optional[list[str]]:
    """Wizard simplifié avec rich.prompt quand questionary n'est pas disponible."""
    from rich.prompt import Prompt, Confirm
    from rich.table  import Table
    from rich        import box

    console.print()
    console.print("[bold cyan]PENTOOL — Assistant de configuration[/bold cyan]")
    console.print("[dim](questionary non installé — mode texte simple)[/dim]")
    console.print()

    # Afficher les profils disponibles
    t = Table(box=box.SIMPLE, show_header=False)
    t.add_column(style="bold yellow")
    t.add_column(style="dim")
    for val, label in PROFILES:
        t.add_row(val, label)
    console.print(t)

    target  = Prompt.ask("[bold]Cible[/bold] (IP ou domaine)")
    if not target:
        return None

    domain  = Prompt.ask("[bold]Domaine vhost[/bold] (vide pour ignorer)", default="")
    profile = Prompt.ask("[bold]Profil[/bold]", choices=[v for v, _ in PROFILES], default="standard")
    output  = Prompt.ask("[bold]Fichier de sortie[/bold]", default="rapport.json")

    # Options booléennes avec Y/N
    use_dns   = Confirm.ask("DNS + WHOIS + sous-domaines ?", default=True)
    use_fuzz  = Confirm.ask("Fuzzing HTTP ?",                default=True)
    use_vhost = Confirm.ask("VHost fuzzing ?",               default=bool(domain))
    use_param = Confirm.ask("Param fuzzing API ?",           default=True)
    use_cve   = Confirm.ask("Corrélation CVE ?",             default=True)
    use_audit = Confirm.ask("Audit fingerprint + misconfig ?",default=True)
    use_pdf   = Confirm.ask("Générer le PDF ?",              default=True)

    modules = []
    if use_dns:   modules.append("dns")
    if use_fuzz:  modules.append("fuzz")
    if use_vhost: modules.append("vhost")
    if use_param: modules.append("param")
    if use_cve:   modules.append("cve")
    if use_audit: modules.append("audit")
    if use_pdf:   modules.append("pdf")

    return _build_command(
        target=target, domain=domain, profile=profile,
        modules=modules, api_key="",
        output=output, threads="10", recursive=False,
    )


# ──────────────────────────────────────────────
# Construction de la commande finale
# ──────────────────────────────────────────────

def _build_command(
    target: str, domain: str, profile: str,
    modules: list[str], api_key: str,
    output: str, threads: str, recursive: bool,
) -> list[str]:
    """Construit la liste d'arguments pour pentool scan."""
    cmd: list[str] = ["pentool", "scan", target, "--profile", profile]

    if domain:
        cmd += ["--domain", domain]
    if "dns"   not in modules: cmd.append("--no-dns")
    if "fuzz"  not in modules: cmd.append("--no-fuzz")
    if "vhost" not in modules: cmd.append("--no-vhost")
    if "param" not in modules: cmd.append("--no-param")
    if "cve"   not in modules: cmd.append("--no-cve")
    if "audit" not in modules: cmd.append("--no-audit")
    if "pdf"   not in modules: cmd.append("--no-pdf")
    # Note: les wordlists SecLists se passent via --wordlist dans les commandes
    # standalone (pentool fuzz / pentool vhost), pas dans pentool scan
    if recursive:
        cmd.append("--fuzz-recursive")
    if api_key:
        cmd += ["--api-key", api_key]
    if threads != "10":
        cmd += ["--fuzz-threads", threads]
    if output:
        cmd += ["--output", output]

    return cmd


# ──────────────────────────────────────────────
# Point d'entrée
# ──────────────────────────────────────────────

def run_interactive() -> None:
    """Lance le wizard interactif puis exécute la commande construite."""
    if _has_questionary():
        cmd = _run_questionary()
    else:
        info("Conseil : [bold]pip install questionary[/bold] pour le mode interactif complet.")
        cmd = _run_rich_fallback()

    if not cmd:
        warning("Wizard annulé.")
        return

    console.print()
    section("Commande générée")
    info(f"  [bold green]{' '.join(cmd)}[/bold green]")
    console.print()

    # Confirmation avant exécution
    try:
        from rich.prompt import Confirm
        if not Confirm.ask("Lancer cette commande ?", default=True):
            info("Annulé. Vous pouvez copier et lancer la commande manuellement.")
            return
    except KeyboardInterrupt:
        return

    # Exécution
    console.print()
    try:
        subprocess.run(cmd, check=False)
    except FileNotFoundError:
        # Si pentool n'est pas dans le PATH (ex: lancement depuis le venv direct)
        cmd[0] = sys.executable.replace("python", "pentool").replace(
            "/python3", "/../bin/pentool"
        )
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        pass