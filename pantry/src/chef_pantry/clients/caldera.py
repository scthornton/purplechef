"""Caldera REST API client with dry-run safety and audit logging."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import httpx

from chef_pantry.errors import CalderaError, DryRunBlockedError


class CalderaClient:
    """Async client for the MITRE Caldera REST API.

    Safety features:
    - Dry-run mode (default): logs intended actions without executing
    - Group allowlist: operations only target approved agent groups
    - Audit logging: every API call is recorded
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        allowed_groups: list[str] | None = None,
        dry_run: bool = True,
        audit_logger: Any | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._allowed_groups = set(allowed_groups or [])
        self._dry_run = dry_run
        self._audit = audit_logger
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={"KEY": self._api_key, "Accept": "application/json"},
            timeout=30.0,
        )

    @property
    def dry_run(self) -> bool:
        return self._dry_run

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            resp = await self._client.request(method, path, **kwargs)
            resp.raise_for_status()
            return resp.json() if resp.content else None
        except httpx.HTTPStatusError as exc:
            raise CalderaError(
                status_code=exc.response.status_code,
                message=f"{method} {path}: {exc.response.text[:200]}",
            ) from exc
        except httpx.RequestError as exc:
            raise CalderaError(status_code=0, message=str(exc)) from exc

    def _audit_log(self, action: str, target: str | None = None, **detail: Any) -> None:
        if self._audit:
            self._audit.log(
                event_type="caldera_api",
                actor="caldera_client",
                action=action,
                target=target,
                detail=detail if detail else None,
                dry_run=self._dry_run,
            )

    def _check_group(self, group: str) -> None:
        if self._allowed_groups and group not in self._allowed_groups:
            raise CalderaError(
                status_code=403,
                message=f"Group '{group}' not in allowlist: {sorted(self._allowed_groups)}",
            )

    # --- Abilities ---

    async def list_abilities(self) -> list[dict[str, Any]]:
        self._audit_log("list_abilities")
        return await self._request("GET", "/api/v2/abilities")

    async def get_ability(self, ability_id: str) -> dict[str, Any]:
        self._audit_log("get_ability", target=ability_id)
        return await self._request("GET", f"/api/v2/abilities/{ability_id}")

    async def find_ability_by_technique(self, technique_id: str) -> list[dict[str, Any]]:
        """Find all abilities matching a MITRE technique ID."""
        self._audit_log("find_ability_by_technique", target=technique_id)
        abilities = await self.list_abilities()
        return [a for a in abilities if a.get("technique_id") == technique_id]

    # --- Adversaries ---

    async def list_adversaries(self) -> list[dict[str, Any]]:
        self._audit_log("list_adversaries")
        return await self._request("GET", "/api/v2/adversaries")

    async def create_adversary(
        self, name: str, description: str, ability_ids: list[str]
    ) -> dict[str, Any]:
        self._audit_log("create_adversary", target=name, abilities=ability_ids)
        if self._dry_run:
            raise DryRunBlockedError(action=f"create_adversary: Would create adversary '{name}'")
        payload = {
            "name": name,
            "description": description,
            "atomic_ordering": ability_ids,
        }
        return await self._request("POST", "/api/v2/adversaries", json=payload)

    # --- Operations ---

    async def create_operation(
        self,
        name: str,
        adversary_id: str,
        group: str,
        *,
        planner: str = "atomic",
    ) -> dict[str, Any]:
        self._check_group(group)
        self._audit_log("create_operation", target=name, adversary=adversary_id, group=group)
        if self._dry_run:
            raise DryRunBlockedError(
                action=f"create_operation: Would run adversary '{adversary_id}' against group '{group}'"
            )
        payload = {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "group": group,
            "planner": {"id": planner},
            "auto_close": True,
            "state": "running",
        }
        return await self._request("POST", "/api/v2/operations", json=payload)

    async def get_operation(self, operation_id: str) -> dict[str, Any]:
        self._audit_log("get_operation", target=operation_id)
        return await self._request("GET", f"/api/v2/operations/{operation_id}")

    async def poll_operation(
        self, operation_id: str, *, interval: int = 10, timeout: int = 300
    ) -> dict[str, Any]:
        """Poll an operation until it completes or times out."""
        deadline = datetime.now(UTC).timestamp() + timeout
        while datetime.now(UTC).timestamp() < deadline:
            op = await self.get_operation(operation_id)
            state = op.get("state", "unknown")
            if state in ("finished", "cleanup"):
                return op
            await asyncio.sleep(interval)
        raise CalderaError(
            status_code=0,
            message=f"Operation {operation_id} timed out after {timeout}s",
        )

    async def get_operation_results(self, operation_id: str) -> list[dict[str, Any]]:
        """Get the chain (executed steps) from an operation."""
        op = await self.get_operation(operation_id)
        return op.get("chain", [])

    # --- Agents ---

    async def list_agents(self) -> list[dict[str, Any]]:
        self._audit_log("list_agents")
        return await self._request("GET", "/api/v2/agents")

    async def get_agents_in_group(self, group: str) -> list[dict[str, Any]]:
        agents = await self.list_agents()
        return [a for a in agents if a.get("group") == group]

    # --- Lifecycle ---

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> CalderaClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()
