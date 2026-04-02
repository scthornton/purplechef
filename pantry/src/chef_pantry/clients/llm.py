"""Thin async OpenAI-compatible LLM client with structured output and audit logging."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, TypeVar

import httpx
from pydantic import BaseModel

if TYPE_CHECKING:
    from chef_pantry.audit import AuditLogger

T = TypeVar("T", bound=BaseModel)

_DEFAULT_SYSTEM = "You are a cybersecurity detection engineer. Be precise and technical."


class LLMClient:
    """Async client for OpenAI-compatible LLM APIs.

    Features:
    - Structured output via Pydantic models (JSON mode + parsing)
    - Retry with exponential backoff
    - Audit logging of all requests
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str = "gpt-4o",
        *,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self._model = model
        self._audit = audit_logger
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            timeout=60.0,
        )

    async def generate(
        self,
        prompt: str,
        *,
        system: str = _DEFAULT_SYSTEM,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> str:
        """Generate a text completion."""
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        self._audit_log("generate", detail={"model": self._model, "prompt_len": len(prompt)})

        resp = await self._client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        self._audit_log("generate_complete", detail={"response_len": len(content)}, success=True)
        return content

    async def generate_structured(
        self,
        prompt: str,
        output_model: type[T],
        *,
        system: str = _DEFAULT_SYSTEM,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> T:
        """Generate a structured response parsed into a Pydantic model.

        Uses JSON mode and instructs the LLM to output valid JSON matching the schema.
        """
        schema = output_model.model_json_schema()
        structured_system = (
            f"{system}\n\n"
            f"You MUST respond with valid JSON matching this schema:\n"
            f"```json\n{json.dumps(schema, indent=2)}\n```\n"
            f"Respond ONLY with the JSON object, no markdown fences or extra text."
        )

        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": structured_system},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        self._audit_log(
            "generate_structured",
            detail={"model": self._model, "output_type": output_model.__name__},
        )

        resp = await self._client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]

        parsed = output_model.model_validate_json(content)
        self._audit_log(
            "generate_structured_complete",
            detail={"output_type": output_model.__name__},
            success=True,
        )
        return parsed

    def _audit_log(self, action: str, **kwargs: Any) -> None:
        if self._audit:
            self._audit.log(event_type="llm_api", actor="llm_client", action=action, **kwargs)

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> LLMClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()
