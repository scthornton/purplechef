"""MITRE ATT&CK technique resolver — maps technique IDs to executable abilities.

Resolution order:
1. Caldera abilities (preferred — server-side execution)
2. Atomic Red Team tests (fallback — WinRM-based)
3. Manual (no automated execution available)
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from chef_pantry.models.technique import MitreTechnique, ResolvedTechnique

if TYPE_CHECKING:
    from chef_pantry.clients.caldera import CalderaClient

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Common technique metadata (subset — extended at runtime via Caldera API)
_KNOWN_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1003": ("OS Credential Dumping", "credential-access"),
    "T1003.001": ("LSASS Memory", "credential-access"),
    "T1003.002": ("Security Account Manager", "credential-access"),
    "T1003.004": ("LSA Secrets", "credential-access"),
    "T1018": ("Remote System Discovery", "discovery"),
    "T1053": ("Scheduled Task/Job", "execution"),
    "T1053.005": ("Scheduled Task", "execution"),
    "T1059.001": ("PowerShell", "execution"),
    "T1085": ("Rundll32", "defense-evasion"),
    "T1078.004": ("Cloud Accounts", "defense-evasion"),
    "T1110.002": ("Password Cracking", "credential-access"),
    "T1550.002": ("Pass the Hash", "lateral-movement"),
    "T1552.002": ("Credentials in Registry", "credential-access"),
    "T1566.001": ("Spearphishing Attachment", "initial-access"),
}


class MitreResolver:
    """Resolves MITRE technique IDs to executable attack specifications."""

    def __init__(self, caldera_client: CalderaClient | None = None) -> None:
        self._caldera = caldera_client
        self._ability_cache: dict[str, list[dict]] | None = None

    @staticmethod
    def validate_technique_id(technique_id: str) -> bool:
        return bool(_TECHNIQUE_RE.match(technique_id))

    @staticmethod
    def build_technique(technique_id: str) -> MitreTechnique:
        """Build a MitreTechnique from a known ID or minimal info."""
        if not _TECHNIQUE_RE.match(technique_id):
            raise ValueError(f"Invalid MITRE technique ID: {technique_id}")
        if technique_id in _KNOWN_TECHNIQUES:
            name, tactic = _KNOWN_TECHNIQUES[technique_id]
        else:
            name = f"Unknown ({technique_id})"
            tactic = "unknown"
        return MitreTechnique(id=technique_id, name=name, tactic=tactic)

    async def _ensure_ability_cache(self) -> dict[str, list[dict]]:
        if self._ability_cache is not None:
            return self._ability_cache
        if self._caldera is None:
            self._ability_cache = {}
            return self._ability_cache
        abilities = await self._caldera.list_abilities()
        cache: dict[str, list[dict]] = {}
        for ability in abilities:
            tid = ability.get("technique_id", "")
            if tid:
                cache.setdefault(tid, []).append(ability)
        self._ability_cache = cache
        return self._ability_cache

    async def resolve(self, technique_id: str) -> ResolvedTechnique:
        """Resolve a technique ID to an executable specification.

        Tries Caldera first, then falls back to Atomic Red Team notation,
        then marks as manual.
        """
        technique = self.build_technique(technique_id)
        cache = await self._ensure_ability_cache()

        # Try Caldera
        caldera_abilities = cache.get(technique_id, [])
        if caldera_abilities:
            best = caldera_abilities[0]
            return ResolvedTechnique(
                technique=technique,
                caldera_ability_id=best["ability_id"],
                resolution_source="caldera",
            )

        # Fallback: Atomic Red Team (default test 1)
        return ResolvedTechnique(
            technique=technique,
            atomic_test_numbers=[1],
            resolution_source="atomic",
        )

    async def resolve_many(self, technique_ids: list[str]) -> list[ResolvedTechnique]:
        return [await self.resolve(tid) for tid in technique_ids]

    def invalidate_cache(self) -> None:
        self._ability_cache = None
