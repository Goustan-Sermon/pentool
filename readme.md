# Pentool — Outil de test d'intrusion automatisé
**Projet de fin d'études — ISEN | v0.1.0**

Pentool est un outil CLI de pentest automatisé écrit en Python. Il enchaîne quatre phases : reconnaissance réseau, énumération DNS, fuzzing HTTP et corrélation de vulnérabilités CVE via l'API NVD, puis génère un rapport PDF professionnel.

> ⚠️ **Usage légal uniquement.** N'utiliser que sur des systèmes dont vous êtes propriétaire ou pour lesquels vous disposez d'une autorisation écrite explicite.

---

## Table des matières

1. [Prérequis système](#1-prérequis-système)
2. [Installation](#2-installation)
3. [Structure du projet](#3-structure-du-projet)
4. [Vue d'ensemble des commandes](#4-vue-densemble-des-commandes)
5. [Commande `scan` — Scan complet](#5-commande-scan--scan-complet)
6. [Commande `ports` — Scan de ports](#6-commande-ports--scan-de-ports)
7. [Commande `dns` — Énumération DNS](#7-commande-dns--énumération-dns)
8. [Commande `fuzz` — Fuzzing HTTP](#8-commande-fuzz--fuzzing-http)
9. [Commande `cve` — Corrélation CVE](#9-commande-cve--corrélation-cve)
10. [Commande `info` — Infos et profils](#10-commande-info--infos-et-profils)
11. [Fichiers de sortie JSON](#11-fichiers-de-sortie-json)
12. [Clé API NVD (optionnelle)](#12-clé-api-nvd-optionnelle)
14. [Dépannage](#13-dépannage)
15. [Architecture du code](#14-architecture-du-code)

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
# Télécharger l'installeur sur https://nmap.org/download.html
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

La commande `pip install -e .` lit `pyproject.toml` et installe toutes les dépendances :

| Package Python | Rôle |
|---|---|
| `typer[all]` | Framework CLI (parsing des arguments) |
| `rich` | Affichage coloré dans le terminal |
| `python-nmap` | Interface Python vers nmap |
| `dnspython` | Résolution DNS (A, MX, NS, TXT…) |
| `python-whois` | Requêtes WHOIS |
| `requests` | Appels HTTP (fuzzing + API NVD) |

### Vérifier l'installation

```bash
pentool info
```

Vous devez voir la bannière ASCII et le tableau des profils de scan. Si la commande `pentool` n'est pas trouvée, vérifiez que votre environnement virtuel est bien activé.

---

## 3. Structure du projet

```
pentool/
├── pyproject.toml              ← configuration du package et des dépendances
└── pentool/                    ← package Python principal
    ├── __init__.py             ← version (0.1.0)
    ├── cli.py                  ← point d'entrée de toutes les commandes
    │
    ├── recon/                  ← Phase 1 : Reconnaissance
    │   ├── __init__.py
    │   ├── port_scanner.py     ← scan nmap (ports, services, OS, CPE)
    │   ├── dns_enum.py         ← DNS, WHOIS, sous-domaines
    │   ├── dir_fuzzer.py       ← fuzzing HTTP de répertoires cachés
    │   └── display.py          ← affichage Rich des résultats recon
    │
    ├── cve/                    ← Phase 2 : Corrélation CVE
    │   ├── __init__.py
    │   ├── models.py           ← dataclasses CVEEntry, ServiceCVEMatch
    │   ├── nvd_client.py       ← client API NVD 2.0
    │   ├── cache.py            ← cache SQLite (~/.pentool/cve_cache.db)
    │   ├── correlator.py       ← corrélation services → CVE
    │   └── display.py          ← affichage Rich des CVE
    │
    └── utils/
        ├── __init__.py
        └── logger.py           ← console Rich partagée
```

---

## 4. Vue d'ensemble des commandes

```
pentool [COMMANDE] [OPTIONS] [ARGUMENTS]

Commandes disponibles :
  scan    Scan complet (ports + DNS + fuzzing + CVE)   ← commande principale
  ports   Scan de ports et services uniquement
  dns     Énumération DNS, WHOIS, sous-domaines
  fuzz    Fuzzing de répertoires et fichiers HTTP
  cve     Corrélation CVE depuis un fichier JSON
  info    Affiche la version et les profils de scan
```

Pour afficher l'aide d'une commande :

```bash
pentool scan --help
pentool fuzz --help
# etc.
```

---

## 5. Commande `scan` — Scan complet

C'est la **commande principale**. Elle enchaîne toutes les phases dans l'ordre :
1. Scan de ports (nmap)
2. Énumération DNS + WHOIS + sous-domaines
3. Fuzzing HTTP (si port 80/443 ouvert)
4. Corrélation CVE via NVD

### Syntaxe

```bash
pentool scan <TARGET> [OPTIONS]
```

### Exemples

```bash
# Scan complet d'une IP (Metasploitable 2 en local)
pentool scan 192.168.1.42

# Scan complet d'un domaine
pentool scan example.com

# Scan complet avec sauvegarde du rapport JSON
pentool scan 192.168.1.42 --output rapport.json

# Scan rapide (top 100 ports, idéal pour la démo)
pentool scan 192.168.1.42 --profile fast --output rapport.json

# Scan complet sans CVE (plus rapide, sans réseau)
pentool scan 192.168.1.42 --no-cve --output rapport.json

# Scan complet avec clé API NVD (moins de throttling)
pentool scan 192.168.1.42 --api-key VOTRE_CLE --output rapport.json
```

### Toutes les options

| Option | Défaut | Description |
|---|---|---|
| `--profile`, `-p` | `standard` | Profil nmap : `fast`, `standard`, `full`, `stealth`, `udp` |
| `--no-dns` | `false` | Désactive l'énumération DNS |
| `--no-whois` | `false` | Désactive la recherche WHOIS |
| `--no-subdomains` | `false` | Désactive la recherche de sous-domaines |
| `--no-fuzz` | `false` | Désactive le fuzzing HTTP |
| `--no-cve` | `false` | Désactive la corrélation CVE |
| `--fuzz-threads` | `10` | Nombre de threads pour le fuzzing |
| `--api-key` | _(env)_ | Clé API NVD (ou variable `NVD_API_KEY`) |
| `--output`, `-o` | _(aucun)_ | Chemin du fichier JSON de sortie |

### Profils de scan nmap

| Profil | Description | Cas d'usage |
|---|---|---|
| `fast` | Top 100 ports, T4 | Démo rapide, réseau lent |
| `standard` | Top 1000 ports, T3 | Usage normal (défaut) |
| `full` | Tous les 65535 ports | Audit exhaustif |
| `stealth` | SYN scan, T2 | Réseau surveillé |
| `udp` | Top 50 ports UDP | Services DNS, SNMP, NTP |

> `full` peut prendre 20–40 minutes.

---

## 6. Commande `ports` — Scan de ports

Uniquement le scan nmap, sans DNS ni CVE.

### Syntaxe

```bash
pentool ports <TARGET> [OPTIONS]
```

### Exemples

```bash
# Scan standard d'une IP
pentool ports 192.168.1.42

# Scan rapide avec profil fast
pentool ports 192.168.1.42 --profile fast

# Scanner uniquement certains ports
pentool ports 192.168.1.42 --ports 22,80,443,8080

# Scanner une plage de ports
pentool ports 192.168.1.42 --ports 1-1024

# Sauvegarder les résultats en JSON
pentool ports 192.168.1.42 --output ports.json

# Ajouter des arguments nmap manuellement
pentool ports 192.168.1.42 --extra "--version-intensity 9"
```

### Toutes les options

| Option | Défaut | Description |
|---|---|---|
| `--profile`, `-p` | `standard` | Profil de scan nmap |
| `--ports`, `-P` | _(tous)_ | Ports spécifiques (ex: `22,80` ou `1-1024`) |
| `--extra`, `-e` | _(aucun)_ | Arguments nmap supplémentaires |
| `--output`, `-o` | _(aucun)_ | Fichier JSON de sortie |

### Ce que la commande affiche

- **Tableau de l'hôte** : IP, hostname, état (up/down), OS détecté, durée du scan
- **Tableau des services** : port, protocole, état, service, produit, version, infos extras
- **Empreintes CVE** : liste des `produit version` prêts à être envoyés en Phase 2

**Exemple de sortie :**

```
╭─ Hôte ────────────────────────────────────────╮
│ Cible      : 192.168.1.42                     │
│ IP         : 192.168.1.42                     │
│ État       :  up                              │
│ OS         : Linux 2.6.x (95% accuracy)       │
│ Durée scan : 12.34s                           │
╰───────────────────────────────────────────────╯

╭───────────────────────────────────────────────────────────╮
│ Port  │ Proto │ État        │ Service │ Produit  │ Version│
│    21 │ tcp   │ ● open      │ ftp     │ vsftpd   │ 2.3.4  │
│    22 │ tcp   │ ● open      │ ssh     │ OpenSSH  │ 4.7p1  │
│    80 │ tcp   │ ● open      │ http    │ Apache   │ 2.2.8  │
│  3306 │ tcp   │ ● open      │ mysql   │ MySQL    │ 5.0.51 │
╰───────────────────────────────────────────────────────────╯
```

---

## 7. Commande `dns` — Énumération DNS

Résout les enregistrements DNS, récupère les infos WHOIS et tente de découvrir des sous-domaines courants.

### Syntaxe

```bash
pentool dns <TARGET> [OPTIONS]
```

### Exemples

```bash
# Énumération complète d'un domaine
pentool dns example.com

# Sans WHOIS
pentool dns example.com --no-whois

# Sans recherche de sous-domaines (plus rapide)
pentool dns example.com --no-subdomains

# Sur une IP (reverse DNS uniquement)
pentool dns 8.8.8.8

# Sauvegarder
pentool dns example.com --output dns.json
```

### Toutes les options

| Option | Défaut | Description |
|---|---|---|
| `--no-whois` | `false` | Désactive la recherche WHOIS |
| `--no-subdomains` | `false` | Désactive l'énumération des sous-domaines |
| `--output`, `-o` | _(aucun)_ | Fichier JSON de sortie |

### Ce que la commande affiche

- **Enregistrements DNS** : A, AAAA, MX, NS, TXT, CNAME, SOA, SRV
- **PTR** (reverse DNS si la cible est une IP)
- **Sous-domaines découverts** : testés à partir d'une wordlist de ~60 préfixes courants (`www`, `mail`, `admin`, `api`, `dev`, `git`, `vpn`…)
- **WHOIS** : registrar, dates de création/expiration, name servers

> La recherche de sous-domaines ne fait que de la résolution DNS (pas de brute-force réseau). Elle est donc rapide et discrète.

---

## 8. Commande `fuzz` — Fuzzing HTTP

Envoie des requêtes HTTP à une série de chemins courants pour découvrir des fichiers et répertoires cachés (pages d'admin, fichiers de configuration, backups, etc.).

### Syntaxe

```bash
pentool fuzz <URL> [OPTIONS]
```

> L'URL doit inclure le schéma : `http://192.168.1.42` ou `https://example.com`

### Exemples

```bash
# Fuzzing avec la wordlist intégrée
pentool fuzz http://192.168.1.42

# Sur un port non standard
pentool fuzz http://192.168.1.42:8080

# Avec une wordlist custom (un chemin par ligne)
pentool fuzz http://192.168.1.42 --wordlist ma_wordlist.txt

# Avec plus de threads (plus rapide, mais plus bruyant)
pentool fuzz http://192.168.1.42 --threads 20

# Timeout plus long (serveur lent)
pentool fuzz http://192.168.1.42 --timeout 10

# Sauvegarder les résultats
pentool fuzz http://192.168.1.42 --output fuzz.json
```

### Toutes les options

| Option | Défaut | Description |
|---|---|---|
| `--threads`, `-t` | `10` | Threads parallèles |
| `--timeout` | `5.0` | Timeout HTTP par requête (secondes) |
| `--wordlist`, `-w` | _(intégrée)_ | Fichier de wordlist custom |
| `--output`, `-o` | _(aucun)_ | Fichier JSON de sortie |

### Wordlist intégrée

La wordlist intégrée couvre ~70 chemins courants répartis en catégories :

| Catégorie | Exemples |
|---|---|
| Admin / panneau | `admin`, `wp-admin`, `phpmyadmin`, `cpanel`, `dashboard` |
| Fichiers sensibles | `.env`, `.git/config`, `config.php`, `backup.zip`, `dump.sql` |
| API / dev | `api/v1`, `graphql`, `swagger-ui`, `api-docs` |
| Auth | `login`, `oauth`, `sso`, `forgot-password` |
| Monitoring | `health`, `actuator/env`, `server-status`, `metrics` |
| Logs | `logs`, `error.log`, `access.log`, `debug` |
| Misc | `robots.txt`, `.well-known/security.txt`, `composer.json` |

### Niveaux de sévérité

| Sévérité | Condition | Exemple |
|---|---|---|
| `CRITICAL` | Code 200 + fichier sensible | `.env` accessible, `dump.sql` |
| `HIGH` | Code 200 + interface admin | `/admin`, `/phpmyadmin` |
| `MEDIUM` | Code 200 autre | `/api/v1`, `/docs` |
| `INFO` | Code 301/302/403 | Redirection ou accès refusé |

### Wordlist custom

Format : un chemin par ligne, sans `/` initial.

```
admin
admin/users
backup
config.bak
.htpasswd
secret/api
```

---

## 9. Commande `cve` — Corrélation CVE

Prend en entrée le fichier JSON produit par `pentool scan` ou `pentool ports`, interroge l'API NVD pour chaque service détecté, et affiche les vulnérabilités associées avec leur score CVSS.

### Syntaxe

```bash
pentool cve <SCAN_JSON> [OPTIONS]
```

> Vous devez d'abord avoir généré un fichier JSON avec `pentool scan --output rapport.json` ou `pentool ports --output ports.json`.

### Exemples

```bash
# Corrélation depuis un scan complet
pentool cve rapport.json

# Depuis un scan de ports uniquement
pentool cve ports.json

# Ne garder que les CVE de score >= 7.0 (HIGH et CRITICAL)
pentool cve rapport.json --min-score 7.0

# Limiter à 5 CVE par service (plus lisible)
pentool cve rapport.json --max-cves 5

# Sans cache (force une nouvelle requête NVD)
pentool cve rapport.json --no-cache

# Avec clé API NVD (moins de throttling)
pentool cve rapport.json --api-key VOTRE_CLE

# Sauvegarder les résultats CVE
pentool cve rapport.json --output cve_results.json
```

### Toutes les options

| Option | Défaut | Description |
|---|---|---|
| `--api-key` | _(env)_ | Clé API NVD (ou `NVD_API_KEY`) |
| `--min-score`, `-s` | `0.0` | Score CVSS minimum (0.0–10.0) |
| `--max-cves` | `10` | Nombre maximum de CVE par service |
| `--no-cache` | `false` | Désactive le cache SQLite local |
| `--output`, `-o` | _(aucun)_ | Fichier JSON de sortie |

### Comment fonctionne la corrélation CVE

Pour chaque service ouvert avec une version détectée, le correlateur applique 3 stratégies en cascade :

1. **CPE exact** — si nmap a fourni un CPE (ex: `cpe:/a:apache:http_server:2.4.49`), interroge directement l'API NVD avec ce CPE.
2. **Fingerprint produit+version** — recherche par mot-clé `"Apache httpd 2.4.49"`.
3. **Nom de service seul** — fallback si rien n'a été trouvé (ex: `"vsftpd"`).

### Cache SQLite

Les résultats NVD sont mis en cache localement dans `~/.pentool/cve_cache.db` avec une durée de vie de **7 jours**. Cela évite de ré-interroger l'API pour les mêmes services et respecte le rate-limit NVD.

### Ce que la commande affiche

```
Phase 2 — Corrélation CVE
╭─ Résumé CVE ──────────────────────────────────╮
│ Services analysés : 4                         │
│ CVE trouvées      : 12                        │
│ CRITICAL          : 3                         │
│ HIGH              : 5                         │
╰───────────────────────────────────────────────╯

:21/tcp  vsftpd 2.3.4  [CRITICAL]  2 CVE
  CVE-2011-2523   CRITICAL  10.0   2011-07-08   Backdoor dans vsftpd 2.3.4…
  CVE-2011-0762   MEDIUM     4.0   2011-03-02   Déni de service via STAT…

:80/tcp  Apache httpd 2.4.49  [CRITICAL]  3 CVE
  CVE-2021-41773  CRITICAL   9.8   2021-10-05   Path traversal et RCE…
  CVE-2021-42013  CRITICAL   9.8   2021-10-07   Variante de CVE-2021-41773…
```

---

## 10. Commande `info` — Infos et profils

Affiche la version de l'outil et le tableau de tous les profils de scan disponibles avec leurs arguments nmap.

```bash
pentool info
```

---

## 11. Fichiers de sortie JSON

Presque toutes les commandes acceptent `--output fichier.json`. Ces fichiers servent à :
- **Rejouer la Phase 2** (`pentool cve`) sans refaire le scan
- **Générer le rapport PDF** (Phase 4)
- **Archiver** les résultats

### Structure du JSON produit par `pentool scan`

```json
{
  "target": "192.168.1.42",

  "port_scan": {
    "target": "192.168.1.42",
    "ip": "192.168.1.42",
    "hostname": "",
    "state": "up",
    "os_name": "Linux 2.6.x (95% accuracy)",
    "scan_args": "nmap -sV -sC -T3 -O 192.168.1.42",
    "scan_time": "14.23",
    "services": [
      {
        "port": 21,
        "protocol": "tcp",
        "state": "open",
        "service": "ftp",
        "product": "vsftpd",
        "version": "2.3.4",
        "extrainfo": "",
        "cpe": ["cpe:/a:vsftpd:vsftpd:2.3.4"]
      }
    ]
  },

  "dns_enum": {
    "target": "192.168.1.42",
    "records": [...],
    "subdomains": [...],
    "whois_data": {...}
  },

  "fuzz": {
    "target_url": "http://192.168.1.42/",
    "total_tested": 70,
    "found_count": 5,
    "results": [
      {
        "url": "http://192.168.1.42/admin",
        "path": "admin",
        "status_code": 200,
        "content_length": 1234,
        "severity": "high"
      }
    ]
  },

  "cve_matches": [
    {
      "service_name": "ftp",
      "service_version": "2.3.4",
      "port": 21,
      "fingerprint": "vsftpd 2.3.4",
      "max_score": 10.0,
      "cves": [
        {
          "cve_id": "CVE-2011-2523",
          "cvss_v3_score": 9.8,
          "cvss_v3_severity": "CRITICAL",
          "description": "...",
          "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"
        }
      ]
    }
  ]
}
```

---

## 12. Clé API NVD (optionnelle)

Sans clé API, NVD autorise **5 requêtes / 30 secondes**. L'outil attend automatiquement entre chaque requête (~6.5s), donc un scan avec 4 services prend environ 30 secondes côté CVE.

Avec une clé API gratuite : **50 requêtes / 30 secondes** (délai réduit à ~1.5s).

### Obtenir une clé gratuite

1. Aller sur [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
2. Remplir le formulaire (email professionnel ou scolaire)
3. Vérifier votre email — la clé arrive en quelques minutes

### Utiliser la clé

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

## 13. Dépannage

### pentool: command not found

```bash
# Vérifier que l'environnement virtuel est activé
source .venv/bin/activate

# Réinstaller
pip install -e .
```

### nmap n'est pas installé ou n'est pas dans le PATH

```bash
# Vérifier
which nmap
nmap --version

# Installer (Linux)
sudo apt install nmap
```

### Scan de ports vide / hôte "down"

```bash
# Sans root, nmap ne peut pas envoyer de paquets SYN bruts
# Solution 1 : lancer avec sudo
sudo pentool ports 192.168.1.42

# Solution 2 : utiliser le profil fast (moins besoin de root)
pentool ports 192.168.1.42 --profile fast
```

### CVE : "rate limit atteint"

NVD limite les requêtes sans clé API. Solutions :

```bash
# Attendre 30 secondes et relancer (le cache reprend là où ça s'est arrêté)
pentool cve rapport.json

# Ou obtenir une clé API gratuite (voir section 12)
export NVD_API_KEY="votre-cle"
pentool cve rapport.json
```

### Fuzzing : aucun résultat

```bash
# Vérifier que le port HTTP est bien ouvert
pentool ports 192.168.1.42 --ports 80,443,8080

# Vérifier que l'URL est correcte (avec http://)
pentool fuzz http://192.168.1.42

# Tester manuellement
curl -I http://192.168.1.42
```

### Erreur `ModuleNotFoundError`

```bash
# Réinstaller toutes les dépendances
pip install -e . --force-reinstall
```

---

## 15. Architecture du code

### Flow de données

```
pentool scan 192.168.1.42 --output rapport.json
         │
         ├── recon/port_scanner.py  →  HostResult (services, OS, CPE)
         │         │
         ├── recon/dns_enum.py      →  DNSEnumResult (records, subdomains, WHOIS)
         │
         ├── recon/dir_fuzzer.py    →  FuzzScanResult (chemins HTTP trouvés)
         │
         ├── cve/correlator.py      →  [ServiceCVEMatch, ...]
         │         ├── cve/nvd_client.py  (requêtes API NVD)
         │         └── cve/cache.py       (SQLite ~/.pentool/cve_cache.db)
         │
         └── rapport.json           →  (Phase 4) → rapport_pentest.pdf
```

### Ajouter une wordlist externe

Pour utiliser une wordlist connue comme **SecLists** ou **dirb** :

```bash
# Exemple avec la wordlist dirb commune
pentool fuzz http://192.168.1.42 \
  --wordlist /usr/share/dirb/wordlists/common.txt
```

### Variables d'environnement supportées

| Variable | Description |
|---|---|
| `NVD_API_KEY` | Clé API NVD (évite de la passer en argument) |

---

*Projet ISEN — Réalisation d'un outil de test d'intrusion automatisé*
*Pentool v0.1.0 — Python 3.10+ — Licence MIT*