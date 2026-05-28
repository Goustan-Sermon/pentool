# Pentool — Outil de test d'intrusion automatisé
**Projet de fin d'études — ISEN | v0.2.0**

Pentool est un outil CLI de pentest automatisé écrit en Python. Il enchaîne désormais quatre grandes phases :
1. **Reconnaissance** (ports, énumération DNS, fuzzing HTTP de répertoires, fuzzing de Virtual Hosts, et fuzzing de paramètres API/IDOR).
2. **Corrélation CVE** via l'API NVD.
3. **Audit** (Fingerprinting d'applications web et détection de misconfigurations).
4. **Génération de rapport PDF** de qualité professionnelle à l'issue de l'analyse.

> ⚠️ **Usage légal uniquement.** N'utiliser que sur des systèmes dont vous êtes propriétaire ou pour lesquels vous disposez d'une autorisation écrite explicite.

---

## Table des matières

1. [Prérequis système](#1-prérequis-système)
2. [Installation](#2-installation)
3. [Structure du projet](#3-structure-du-projet)
4. [Vue d'ensemble des commandes](#4-vue-densemble-des-commandes)
5. [Commande `scan` — Scan complet et Mode Interactif](#5-commande-scan--scan-complet-et-mode-interactif)
6. [Commande `ports` — Scan de ports](#6-commande-ports--scan-de-ports)
7. [Commande `dns` — Énumération DNS](#7-commande-dns--énumération-dns)
8. [Commande `fuzz` — Fuzzing HTTP](#8-commande-fuzz--fuzzing-http)
9. [Commande `vhost` — Virtual Host Fuzzing](#9-commande-vhost--virtual-host-fuzzing)
10. [Commande `param` — Fuzzing de paramètres et IDOR](#10-commande-param--fuzzing-de-paramètres-et-idor)
11. [Commande `cve` — Corrélation CVE](#11-commande-cve--corrélation-cve)
12. [Commande `report` — Génération PDF](#12-commande-report--génération-pdf)
13. [Fichiers de sortie JSON](#13-fichiers-de-sortie-json)
14. [Clé API NVD (optionnelle)](#14-clé-api-nvd-optionnelle)
15. [Dépannage](#15-dépannage)

---

## 1. Prérequis système

| Dépendance | Version minimale | Vérification |
|---|---|---|
| Python | 3.10+ | `python3 --version` |
| nmap | 7.x | `nmap --version` |
| pip | 22+ | `pip --version` |

**Installer nmap selon votre OS :**

```bash
# Debian / Ubuntu / Kali
sudo apt install nmap

# macOS (Homebrew)
brew install nmap

# Windows
# Télécharger l'installeur sur [https://nmap.org/download.html](https://nmap.org/download.html)

```

> Sur Linux, certains types de scan nmap (SYN stealth, détection OS) nécessitent les droits **root**. Lancez `sudo pentool scan ...` ou utilisez le profil `fast` qui fonctionne sans root.

---

## 2. Installation

### Cloner / copier le projet

```bash
# Depuis votre dossier de travail
cd ~/projets
# Copiez le dossier pentool/ ici, puis :
cd pentool

```

### Créer un environnement virtuel (recommandé)

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# ou
.venv\Scripts\activate           # Windows PowerShell

```

### Installer les dépendances et le package

```bash
pip install -e .

```

La commande `pip install -e .` lit `pyproject.toml` et installe toutes les dépendances requises :
`typer[all]`, `rich`, `python-nmap`, `dnspython`, `python-whois`, `requests`, `reportlab`, `ipaddress`, et `InquirerPy`.

### Vérifier l'installation

```bash
pentool info

```

---

## 3. Structure du projet

```text
pentool
├── pentool
│   ├── audit                 ← Phase 3 : Audit web (Fingerprinting & Misconfig)
│   │   ├── display.py
│   │   ├── misconfig.py
│   │   └── web_fingerprint.py
│   ├── cli.py                ← Point d'entrée de toutes les commandes CLI
│   ├── cve                   ← Phase 2 : Corrélation CVE
│   │   ├── cache.py
│   │   ├── correlator.py
│   │   ├── display.py
│   │   ├── models.py
│   │   └── nvd_client.py
│   ├── recon                 ← Phase 1 : Reconnaissance
│   │   ├── dir_fuzzer.py
│   │   ├── display.py
│   │   ├── dns_enum.py
│   │   ├── param_fuzzer.py
│   │   ├── port_scanner.py
│   │   ├── vhost_fuzzer.py
│   │   └── wordlists.py
│   ├── report                ← Phase 4 : Génération de rapports PDF
│   │   ├── generator.py
│   │   └── styles.py
│   └── utils                 ← Utilitaires partagés
│       └── logger.py
└── pyproject.toml            ← Configuration du package et des dépendances
```



---

## 4. Vue d'ensemble des commandes

```text
pentool [COMMANDE] [OPTIONS] [ARGUMENTS]

Commandes disponibles :
  scan    Scan complet (ports + DNS + fuzz + CVE + audit + PDF auto)
  ports   Scan de ports uniquement
  dns     Énumération DNS/WHOIS
  fuzz    Fuzzing de répertoires HTTP
  vhost   Virtual Host fuzzing
  param   Parameter fuzzing / IDOR
  cve     Corrélation CVE depuis un JSON de scan
  report  Génère le rapport PDF depuis un JSON existant
  info    Profils et version

```

---

## 5. Commande `scan` — Scan complet et Mode Interactif

C'est la commande principale. Elle permet d'enchaîner toutes les phases automatiquement ou d'être lancée via l'assistant interactif.

### 🪄 Le Mode Interactif

Utilisez l'option `--interactive` ou `-i` pour lancer l'assistant guidé (nécessite le module `InquirerPy`). L'assistant vous guidera pour :

* Spécifier la cible.
* Sélectionner le profil nmap (`standard`, `fast`, `full`, `stealth`, `udp`).
* Cocher/décocher les phases à exécuter (DNS, Fuzzing répertoires, Fuzzing VHost, Fuzzing API, CVE, Audit).
* Spécifier des options de domaine, et des fichiers de sortie.

```bash
pentool scan --interactive

```

### Syntaxe CLI standard

```bash
pentool scan <TARGET> [OPTIONS]

```

### Toutes les options

| Option | Défaut | Description |
| --- | --- | --- |
| `--interactive`, `-i` | `false` | Lance l'assistant de configuration interactif. |
| `--profile`, `-p` | `standard` | Profil nmap : `fast`, `standard`, `full`, `stealth`, `udp`. |
| `--domain`, `-d` | *(aucun)* | Domaine de base pour le fuzzing de Virtual Hosts. |
| `--no-dns` | `false` | Désactive l'énumération DNS. |
| `--no-whois` | `false` | Désactive la recherche WHOIS. |
| `--no-subdomains` | `false` | Désactive la recherche de sous-domaines. |
| `--no-fuzz` | `false` | Désactive le fuzzing HTTP de répertoires. |
| `--no-vhost` | `false` | Désactive le fuzzing de Virtual Hosts. |
| `--no-param` | `false` | Désactive le fuzzing automatique de paramètres (IDOR). |
| `--no-cve` | `false` | Désactive la corrélation CVE. |
| `--no-audit` | `false` | Désactive la Phase 3 d'audit (fingerprinting & misconfigurations). |
| `--no-pdf` | `false` | Désactive la génération du rapport PDF automatique. |
| `--fuzz-threads` | `10` | Nombre de threads pour le fuzzing. |
| `--api-key` | *(env)* | Clé API NVD (ou variable `NVD_API_KEY`). |
| `--output`, `-o` | *(aucun)* | Chemin du fichier JSON de sortie (et déclenche la création du PDF). |

---

## 6. Commande `ports` — Scan de ports

Uniquement le scan nmap, sans exécution des autres phases.

```bash
pentool ports 192.168.1.42 --profile fast
pentool ports 192.168.1.42 --ports 22,80,443,8080 --output ports.json

```

---

## 7. Commande `dns` — Énumération DNS

Résout les enregistrements DNS, récupère les infos WHOIS et tente de découvrir des sous-domaines courants.

```bash
pentool dns example.com --no-whois

```

---

## 8. Commande `fuzz` — Fuzzing HTTP

Envoie des requêtes HTTP à une série de chemins courants pour découvrir des fichiers et répertoires cachés.

```bash
pentool fuzz [http://192.168.1.42](http://192.168.1.42) --threads 20 --output fuzz.json

```

---

## 9. Commande `vhost` — Virtual Host Fuzzing

Découvre les sous-domaines cachés non présents en DNS en modifiant l'en-tête `Host`. Idéal pour trouver des applications isolées dans des environnements de type HackTheBox.

```bash
# Exemple de fuzzing VHost avec le domaine monitorsfour.htb
pentool vhost 10.129.59.40 --domain monitorsfour.htb

```

| Option | Description |
| --- | --- |
| `--domain`, `-d` | Domaine de base (requis). |
| `--port`, `-p` | Spécifier le port (défaut 80). |
| `--https` | Forcer l'utilisation du HTTPS. |
| `--wordlist`, `-w` | Utiliser une wordlist personnalisée. |

---

## 10. Commande `param` — Fuzzing de paramètres et IDOR

Permet de découvrir les paramètres acceptés par un endpoint API, de fuzzer leurs valeurs, ou de tester des vulnérabilités de type IDOR avec des plages numériques automatiques.

**Mode 1 — Découverte automatique :**

```bash
pentool param [http://monitorsfour.htb/user](http://monitorsfour.htb/user)

```

**Mode 2 — Fuzzing avec wordlist :**

```bash
pentool param [http://monitorsfour.htb/user](http://monitorsfour.htb/user) --param token --wordlist tokens.txt

```

**Mode 3 — Plage numérique (IDOR) :**

```bash
pentool param [http://monitorsfour.htb/user](http://monitorsfour.htb/user) --param id --start 0 --end 500

```

---

## 11. Commande `cve` — Corrélation CVE

Prend en entrée le fichier JSON produit par le scan, interroge l'API NVD pour chaque service détecté, et affiche les vulnérabilités associées avec leur score CVSS.

```bash
pentool cve rapport.json --min-score 7.0 --api-key VOTRE_CLE

```

---

## 12. Commande `report` — Génération PDF

Génère un rapport PDF standalone d'allure professionnelle à partir d'un fichier JSON de scan préexistant. Pratique si vous avez désactivé la génération PDF lors du scan initial.

```bash
pentool report rapport.json --output rapport_final.pdf

```

---

## 13. Fichiers de sortie JSON

Presque toutes les commandes acceptent `--output fichier.json`. Ces fichiers servent à :

* **Rejouer la Phase 2** (`pentool cve`) sans refaire le scan.
* **Générer le rapport PDF** via `pentool report`.
* **Archiver** les résultats.

---

## 14. Clé API NVD (optionnelle)

Sans clé API, NVD autorise **5 requêtes / 30 secondes**.
Avec une clé API gratuite : **50 requêtes / 30 secondes**.

**Option A — variable d'environnement (recommandé) :**

```bash
export NVD_API_KEY="votre-cle-ici"
pentool scan 192.168.1.42 --output rapport.json

```

**Option B — argument CLI :**

```bash
pentool scan 192.168.1.42 --api-key "votre-cle-ici" --output rapport.json

```

---

## 15. Dépannage

### `pentool: command not found`

Vérifiez que votre environnement virtuel est actif (`source .venv/bin/activate`), puis réinstallez avec `pip install -e .`.

### nmap n'est pas installé ou n'est pas dans le PATH

Assurez-vous d'avoir installé `nmap` sur votre machine physique (`sudo apt install nmap` / `brew install nmap`).

### Scan de ports vide / hôte "down"

Si vous obtenez un résultat vide, c'est probablement car nmap n'a pas les droits nécessaires pour utiliser les paquets SYN bruts. Essayez avec le privilège root (`sudo pentool ...`) ou utilisez le profil de scan `fast`.

### `ModuleNotFoundError` pour `InquirerPy`

Si le mode interactif échoue au démarrage, exécutez `pip install InquirerPy`.

---

*Projet ISEN — Réalisation d'un outil de test d'intrusion automatisé*
*Pentool v0.2.0 — Python 3.10+ — Licence MIT*
