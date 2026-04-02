"""Webhook notification after recipe runs.

Sends structured payloads to external endpoints (Slack, PagerDuty,
generic webhooks) summarising coverage results from a PurpleChef run.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

import httpx
from chef_pantry.models.evidence import CoverageResult
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class WebhookConfig(BaseModel):
    """Configuration for an outbound webhook."""

    url: str
    method: Literal["POST"] = "POST"
    headers: dict[str, str] = {}
    include_evidence: bool = False


class WebhookPayload(BaseModel):
    """Canonical payload sent to webhook endpoints."""

    recipe_name: str
    run_id: str
    timestamp: str
    status: Literal["success", "partial", "failure"]
    coverage_percentage: float
    detected_count: int
    missed_count: int
    total_count: int
    techniques_missed: list[str]
    report_url: str | None = None
    evidence_chains: list[dict[str, Any]] | None = None


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def _determine_status(result: CoverageResult) -> Literal["success", "partial", "failure"]:
    pct = result.coverage_percentage
    if pct >= 100.0:
        return "success"
    if pct > 0.0:
        return "partial"
    return "failure"


def _build_payload(
    config: WebhookConfig,
    result: CoverageResult,
    *,
    report_url: str | None = None,
) -> WebhookPayload:
    missed_techniques = [
        chain.technique.id for chain in result.evidence_chains if chain.status == "missed"
    ]

    evidence: list[dict[str, Any]] | None = None
    if config.include_evidence:
        evidence = [chain.model_dump(mode="json") for chain in result.evidence_chains]

    return WebhookPayload(
        recipe_name=result.recipe_name,
        run_id=result.run_id,
        timestamp=result.timestamp.isoformat(),
        status=_determine_status(result),
        coverage_percentage=result.coverage_percentage,
        detected_count=result.detected_count,
        missed_count=result.missed_count,
        total_count=result.total_count,
        techniques_missed=missed_techniques,
        report_url=report_url,
        evidence_chains=evidence,
    )


# ---------------------------------------------------------------------------
# Webhook sender
# ---------------------------------------------------------------------------


def _redact_url(url: str) -> str:
    """Redact webhook URL to avoid leaking secrets in logs."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or "unknown"
    return f"{parsed.scheme}://{host}/***"


async def send_webhook(
    config: WebhookConfig,
    result: CoverageResult,
    *,
    report_url: str | None = None,
) -> bool:
    """Build a payload from *result* and POST it to the webhook URL.

    Returns ``True`` on a 2xx response, ``False`` otherwise.
    """
    payload = _build_payload(config, result, report_url=report_url)
    redacted = _redact_url(config.url)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method=config.method,
                url=config.url,
                json=payload.model_dump(mode="json", exclude_none=True),
                headers=config.headers,
            )
        if 200 <= response.status_code < 300:
            logger.info("Webhook delivered to %s (status %d)", redacted, response.status_code)
            return True
        logger.warning(
            "Webhook to %s returned non-2xx status %d: %s",
            redacted,
            response.status_code,
            response.text[:500],
        )
        return False
    except httpx.HTTPError as exc:
        logger.error("Webhook delivery failed for %s: %s", redacted, exc)
        return False


# ---------------------------------------------------------------------------
# Slack Block Kit payload
# ---------------------------------------------------------------------------


def _color_for_coverage(pct: float) -> str:
    if pct >= 100.0:
        return "#2eb886"  # green
    if pct > 50.0:
        return "#daa038"  # yellow
    return "#a30200"  # red


def build_slack_payload(result: CoverageResult) -> dict[str, Any]:
    """Format a ``CoverageResult`` as a Slack Block Kit message.

    Returns a dict suitable for posting to a Slack Incoming Webhook or
    the ``chat.postMessage`` API.
    """
    pct = result.coverage_percentage
    color = _color_for_coverage(pct)

    missed_techniques = [
        chain.technique.id for chain in result.evidence_chains if chain.status == "missed"
    ]

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "PurpleChef Coverage Report",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Recipe:*\n{result.recipe_name}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Coverage:*\n{pct:.1f}%",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Detected:*\n{result.detected_count}/{result.total_count}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Status:*\n{_determine_status(result).upper()}",
                },
            ],
        },
    ]

    if missed_techniques:
        technique_list = ", ".join(missed_techniques)
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":red_circle: *Missed Techniques:*\n{technique_list}",
                },
            }
        )

    return {
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
            }
        ],
    }
