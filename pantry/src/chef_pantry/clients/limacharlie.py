"""LimaCharlie REST API client for detection queries."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

import httpx

from chef_pantry.errors import LimaCharlieError


_TECHNIQUE_TAG_RE = re.compile(r"\bt\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


class LimaCharlieClient:
    """Async client for LimaCharlie detection and response API."""

    BASE_URL = "https://api.limacharlie.io"

    def __init__(self, oid: str, api_key: str, *, audit_logger: Any | None = None) -> None:
        self._oid = oid
        self._audit = audit_logger
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=30.0,
        )

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            resp = await self._client.request(method, path, **kwargs)
            resp.raise_for_status()
            return resp.json() if resp.content else None
        except httpx.HTTPStatusError as exc:
            raise LimaCharlieError(
                status_code=exc.response.status_code,
                message=f"{method} {path}: {exc.response.text[:200]}",
            ) from exc
        except httpx.RequestError as exc:
            raise LimaCharlieError(status_code=0, message=str(exc)) from exc

    def _audit_log(self, action: str, **detail: Any) -> None:
        if self._audit:
            self._audit.log(
                event_type="limacharlie_api",
                actor="limacharlie_client",
                action=action,
                detail=detail if detail else None,
            )

    async def get_detections(
        self,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Fetch recent detections within a time window."""
        params: dict[str, Any] = {"limit": limit}
        if start:
            params["start"] = int(start.timestamp())
        if end:
            params["end"] = int(end.timestamp())
        self._audit_log("get_detections", **params)
        data = await self._request("GET", f"/v1/detects/{self._oid}", params=params)
        return data.get("detects", []) if data else []

    async def find_detections_for_technique(
        self,
        technique_id: str,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Find detections matching a MITRE technique ID by tag."""
        detections = await self.get_detections(start=start, end=end)
        normalized = technique_id.lower().replace(".", "")
        matches = []
        for det in detections:
            detect_data = det.get("detect", {})
            tags = detect_data.get("detect_mtd", {}).get("tags", [])
            for tag in tags:
                tag_match = _TECHNIQUE_TAG_RE.search(tag)
                if tag_match and tag_match.group().lower().replace(".", "") == normalized:
                    matches.append(det)
                    break
        return matches

    async def list_rules(self) -> dict[str, Any]:
        """List all D&R rules in the organization."""
        self._audit_log("list_rules")
        return await self._request("GET", f"/v1/rules/{self._oid}")

    async def create_rule(self, name: str, detect: dict, respond: list) -> dict[str, Any]:
        """Deploy a D&R rule."""
        self._audit_log("create_rule", name=name)
        payload = {"name": name, "detect": detect, "respond": respond}
        return await self._request("POST", f"/v1/rules/{self._oid}", json=payload)

    async def delete_rule(self, name: str) -> None:
        """Remove a D&R rule."""
        self._audit_log("delete_rule", name=name)
        await self._request("DELETE", f"/v1/rules/{self._oid}/{name}")

    @staticmethod
    def extract_technique_tags(detection: dict[str, Any]) -> list[str]:
        """Extract MITRE technique IDs from a detection's tags."""
        tags = detection.get("detect", {}).get("detect_mtd", {}).get("tags", [])
        found = []
        for tag in tags:
            match = _TECHNIQUE_TAG_RE.search(tag)
            if match:
                found.append(match.group().upper())
        return found

    @staticmethod
    def detection_timestamp(detection: dict[str, Any]) -> datetime:
        """Extract timestamp from a detection event."""
        ts = detection.get("detect", {}).get("routing", {}).get("event_time", 0)
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts / 1_000_000 if ts > 1e12 else ts, tz=timezone.utc)
        return datetime.now(timezone.utc)

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> LimaCharlieClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()
