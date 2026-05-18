"""
Cache SQLite local pour les résultats NVD.

Évite de ré-interroger l'API pour les mêmes services/versions
et respecte le rate-limit NVD. Durée de vie par défaut : 7 jours.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

from pentool.cve.models import CVEEntry


DEFAULT_DB_PATH = Path.home() / ".pentool" / "cve_cache.db"
DEFAULT_TTL     = 7 * 24 * 3600   # 7 jours en secondes


class CVECache:
    """Cache persistant SQLite pour les CVEEntry."""

    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        ttl:     int  = DEFAULT_TTL,
    ) -> None:
        self._db_path = db_path
        self._ttl     = ttl
        self._init_db()

    # ──────────────────────────────────────────────
    # Initialisation
    # ──────────────────────────────────────────────

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cache_key   TEXT PRIMARY KEY,
                    payload     TEXT NOT NULL,
                    cached_at   REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cached_at ON cve_cache(cached_at)
            """)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=10)

    # ──────────────────────────────────────────────
    # Lecture / écriture
    # ──────────────────────────────────────────────

    def get(self, key: str) -> Optional[list[CVEEntry]]:
        """
        Retourne les CVE en cache pour une clé donnée,
        ou None si absent / expiré.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload, cached_at FROM cve_cache WHERE cache_key = ?",
                (key,)
            ).fetchone()

        if not row:
            return None

        payload, cached_at = row
        if time.time() - cached_at > self._ttl:
            self.delete(key)
            return None

        try:
            raw_list = json.loads(payload)
            return [self._dict_to_cve(d) for d in raw_list]
        except (json.JSONDecodeError, KeyError):
            return None

    def set(self, key: str, cves: list[CVEEntry]) -> None:
        """Stocke une liste de CVEEntry sous une clé."""
        payload = json.dumps([c.to_dict() for c in cves], ensure_ascii=False, default=str)
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO cve_cache (cache_key, payload, cached_at)
                VALUES (?, ?, ?)
            """, (key, payload, time.time()))

    def delete(self, key: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM cve_cache WHERE cache_key = ?", (key,))

    def purge_expired(self) -> int:
        """Supprime les entrées expirées. Retourne le nombre supprimé."""
        cutoff = time.time() - self._ttl
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM cve_cache WHERE cached_at < ?", (cutoff,))
            return cur.rowcount

    def stats(self) -> dict:
        """Statistiques du cache."""
        with self._connect() as conn:
            total   = conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
            expired = conn.execute(
                "SELECT COUNT(*) FROM cve_cache WHERE cached_at < ?",
                (time.time() - self._ttl,)
            ).fetchone()[0]
        return {
            "total_entries": total,
            "expired":       expired,
            "valid":         total - expired,
            "db_path":       str(self._db_path),
            "ttl_days":      self._ttl // 86400,
        }

    # ──────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────

    @staticmethod
    def make_key(fingerprint: str) -> str:
        """Normalise une empreinte en clé de cache."""
        return fingerprint.strip().lower().replace(" ", "_")

    @staticmethod
    def _dict_to_cve(d: dict) -> CVEEntry:
        return CVEEntry(
            cve_id=d.get("cve_id", ""),
            description=d.get("description", ""),
            published=d.get("published", ""),
            modified=d.get("modified", ""),
            cvss_v3_score=d.get("cvss_v3_score"),
            cvss_v3_severity=d.get("cvss_v3_severity", "UNKNOWN"),
            cvss_v3_vector=d.get("cvss_v3_vector", ""),
            cvss_v2_score=d.get("cvss_v2_score"),
            cvss_v2_severity=d.get("cvss_v2_severity", ""),
            references=d.get("references", []),
            cpe_list=d.get("cpe_list", []),
            cwe_ids=d.get("cwe_ids", []),
            matched_service=d.get("matched_service", ""),
            matched_port=d.get("matched_port", 0),
        )