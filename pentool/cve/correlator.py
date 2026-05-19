"""
Corrélateur Services → CVE.

Prend en entrée un HostResult (Phase 1) et retourne
pour chaque service ouvert la liste des CVE associées,
en interrogeant l'API NVD avec cache SQLite.
"""

from __future__ import annotations

from typing import Optional

from pentool.cve.models    import CVEEntry, ServiceCVEMatch
from pentool.cve.nvd_client import NVDClient
from pentool.cve.cache      import CVECache
from pentool.recon.port_scanner import HostResult, ServiceInfo
from pentool.utils import info, warning, success, console


class CVECorrelator:
    """
    Orchestre la recherche CVE pour tous les services d'un hôte.

    Stratégie de recherche (par ordre de précision) :
      1. CPE exact si disponible      → search_by_cpe()
      2. Fingerprint produit+version  → search_by_keyword()
      3. Nom de service seul          → search_by_keyword() (fallback)
    """

    def __init__(
        self,
        api_key:     Optional[str] = None,
        max_cves:    int           = 10,
        use_cache:   bool          = True,
        min_score:   float         = 0.0,   # filtrer par score CVSS minimum
    ) -> None:
        self._client    = NVDClient(api_key=api_key, max_results=max_cves)
        self._cache     = CVECache() if use_cache else None
        self._max_cves  = max_cves
        self._min_score = min_score

    # ──────────────────────────────────────────────
    # Point d'entrée principal
    # ──────────────────────────────────────────────

    def correlate(self, host: HostResult) -> list[ServiceCVEMatch]:
        """
        Corrèle tous les ports ouverts avec les CVE NVD.

        Args:
            host: résultat du scan Phase 1

        Returns:
            Liste de ServiceCVEMatch triée par score max décroissant
        """
        open_services = [s for s in host.open_ports if s.product or s.version]

        if not open_services:
            warning("Aucun service avec version détectée — corrélation CVE impossible.")
            return []

        info(f"Corrélation CVE pour [bold]{len(open_services)}[/bold] service(s) avec version…")

        matches: list[ServiceCVEMatch] = []

        for svc in open_services:
            with console.status(
                f"[cyan]CVE → :{svc.port} {svc.fingerprint}[/cyan]", spinner="dots"
            ):
                cves = self._lookup_service(svc)

            # Filtrage par score minimum
            if self._min_score > 0:
                cves = [c for c in cves if (c.score or 0) >= self._min_score]

            # Tri par sévérité puis score
            cves.sort(key=lambda c: (c.severity_order, -(c.score or 0)))
            cves = cves[:self._max_cves]

            # Annotation du contexte de détection
            for c in cves:
                c.matched_service = svc.fingerprint
                c.matched_port    = svc.port

            match = ServiceCVEMatch(
                service_name=svc.service,
                service_version=svc.version,
                port=svc.port,
                protocol=svc.protocol,
                fingerprint=svc.fingerprint,
                cves=cves,
            )
            matches.append(match)

            _emoji = "🔴" if match.critical_count else ("🟠" if match.high_count else "🟡")
            info(
                f"  {_emoji} :{svc.port} [cyan]{svc.fingerprint}[/cyan] "
                f"→ [bold]{len(cves)}[/bold] CVE"
                + (f" (max CVSS {match.max_score})" if match.max_score else "")
            )

        # Tri global : services les plus dangereux en premier
        matches.sort(key=lambda m: (-(m.max_score or 0), -m.critical_count))

        total_cves = sum(len(m.cves) for m in matches)
        critical   = sum(m.critical_count for m in matches)
        high_      = sum(m.high_count    for m in matches)
        success(
            f"Corrélation terminée : [bold]{total_cves}[/bold] CVE trouvées "
            f"([danger]{critical}[/danger] CRITICAL, [warning]{high_}[/warning] HIGH)"
        )

        return matches

    # ──────────────────────────────────────────────
    # Lookup d'un service (cache + API)
    # ──────────────────────────────────────────────

    def _lookup_service(self, svc: ServiceInfo) -> list[CVEEntry]:
        """Cherche les CVE pour un ServiceInfo, avec cache."""
        cache_key = CVECache.make_key(svc.fingerprint) if self._cache else None

        # 1. Cache hit ?
        if self._cache and cache_key:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        # 2. Recherche API
        cves: list[CVEEntry] = []

        # Stratégie A : CPE exact
        if svc.cpe:
            for cpe_str in svc.cpe[:2]:
                cpes_found = self._client.search_by_cpe(cpe_str)
                cves.extend(cpes_found)

        # Stratégie B : fingerprint produit+version
        if svc.fingerprint and len(cves) < 5:
            kw_found = self._client.search_by_keyword(svc.fingerprint)
            # Déduplication
            existing_ids = {c.cve_id for c in cves}
            cves.extend(c for c in kw_found if c.cve_id not in existing_ids)

        # Stratégie C : fallback nom de service
        # UNIQUEMENT si le service est un nom reconnu (pas "gws", "tcpwrapped"...)
        _SKIP_FALLBACK = {
            "unknown", "", "tcpwrapped", "gws", "gen-serv", "ms-wbt-server",
            "microsoft-ds", "netbios-ssn", "msrpc", "epmap",
        }
        if not cves and svc.service and svc.service not in _SKIP_FALLBACK:
            fallback = self._client.search_by_keyword(svc.service)
            relevant = []
            svc_lower = svc.service.lower()
            for c in fallback:
                desc_lower = c.description.lower()
                cpe_str    = " ".join(c.cpe_list).lower()
                if svc_lower in desc_lower or svc_lower in cpe_str:
                    relevant.append(c)
            cves.extend(relevant)

        # Filtre de pertinence : le produit doit apparaître dans la CVE
        if cves and (svc.product or svc.version):
            product_lower = (svc.product or "").lower().split()[0]
            if product_lower and len(product_lower) > 3:
                filtered = [
                    c for c in cves
                    if product_lower in c.description.lower()
                    or product_lower in " ".join(c.cpe_list).lower()
                ]
                if filtered or not svc.cpe:
                    cves = filtered

        # Filtre de pertinence global : si on a un produit/version connu,
        # on vérifie que les CVE correspondent vraiment au produit
        if cves and (svc.product or svc.version):
            product_lower = (svc.product or "").lower().split()[0]  # ex: "apache"
            if product_lower and len(product_lower) > 3:
                filtered = []
                for c in cves:
                    desc_lower = c.description.lower()
                    cpe_str    = " ".join(c.cpe_list).lower()
                    # La CVE doit mentionner le produit OU avoir un CPE correspondant
                    if product_lower in desc_lower or product_lower in cpe_str:
                        filtered.append(c)
                # Si le filtre est trop agressif (0 résultat sur des CVE trouvées par CPE),
                # on garde quand même les CVE trouvées par CPE exact (stratégie A)
                if filtered or not svc.cpe:
                    cves = filtered

        # Mise en cache
        if self._cache and cache_key and cves:
            self._cache.set(cache_key, cves)

        return cves