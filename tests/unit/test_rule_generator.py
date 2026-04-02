"""Unit tests for chef_detection.rule_generator."""

from __future__ import annotations

import pytest
from chef_detection.rule_generator import generate_rule
from chef_detection.rule_validator import validate_sigma
from chef_detection.sigma_templates import list_templates

# ---------------------------------------------------------------------------
# Template-based generation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_rule_with_template_technique_returns_template_source() -> None:
    rule, source = await generate_rule("T1003.001")
    assert source == "template"
    assert isinstance(rule, dict)
    assert rule["title"]


@pytest.mark.asyncio
async def test_generate_rule_template_sets_author() -> None:
    rule, _ = await generate_rule("T1003.001", author="TestAuthor")
    assert rule["author"] == "TestAuthor"


# ---------------------------------------------------------------------------
# No template and no LLM raises ValueError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_rule_without_template_and_no_llm_raises() -> None:
    with pytest.raises(ValueError, match="No Sigma template"):
        await generate_rule("T9999.999")


# ---------------------------------------------------------------------------
# Template-generated rules pass validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("technique_id", list_templates())
async def test_template_generated_rules_pass_validation(technique_id: str) -> None:
    rule, source = await generate_rule(technique_id)
    assert source == "template"
    result = validate_sigma(rule)
    assert result.is_valid is True, f"{technique_id} failed: {result.errors}"
