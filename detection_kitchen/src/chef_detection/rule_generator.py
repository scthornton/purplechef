"""Rule generator -- template-first with LLM fallback.

Tries deterministic Sigma templates first for speed and reproducibility.
Falls back to LLM-based generation when no template exists, producing
structured output via the chef_pantry LLMClient.
"""

from __future__ import annotations

import textwrap
from datetime import date

# TYPE_CHECKING avoids circular imports; LLMClient only needed at runtime
# when the caller actually passes one in.
from typing import TYPE_CHECKING, Any, Literal

# Re-use the resolver for technique metadata lookups.
from chef_pantry.mitre.resolver import MitreResolver
from pydantic import BaseModel, Field

from chef_detection import sigma_templates
from chef_detection.sigma_templates import render_sigma_yaml

if TYPE_CHECKING:
    from chef_pantry.clients.llm import LLMClient


# ---------------------------------------------------------------------------
# Pydantic model for LLM structured output
# ---------------------------------------------------------------------------


class SigmaRuleDraft(BaseModel):
    """Schema the LLM must conform to when generating a Sigma rule."""

    title: str = Field(..., description="Short descriptive title for the Sigma rule")
    description: str = Field(..., description="Detailed description of what the rule detects")
    level: Literal["informational", "low", "medium", "high", "critical"] = Field(
        ..., description="Severity level of the detection"
    )
    logsource: dict[str, Any] = Field(
        ..., description="Sigma logsource definition (category, product, service)"
    )
    detection: dict[str, Any] = Field(
        ..., description="Sigma detection logic with selection(s) and condition"
    )
    falsepositives: list[str] = Field(
        default_factory=list,
        description="Known false-positive scenarios",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tags in attack.tXXXX format",
    )


# ---------------------------------------------------------------------------
# LLM prompt builder
# ---------------------------------------------------------------------------

_FEW_SHOT_EXAMPLE = textwrap.dedent("""\
    Example of a well-formed Sigma rule (JSON representation):
    {
      "title": "Suspicious LSASS Access",
      "description": "Detects process access to lsass.exe with rights used by credential dumpers.",
      "level": "high",
      "logsource": {
        "category": "process_access",
        "product": "windows"
      },
      "detection": {
        "selection": {
          "TargetImage|endswith": "\\\\lsass.exe",
          "GrantedAccess|contains": ["0x1010", "0x1038"]
        },
        "condition": "selection"
      },
      "falsepositives": ["Legitimate security tools"],
      "tags": ["attack.credential_access", "attack.t1003_001"]
    }
""")


def _build_llm_prompt(technique_id: str, technique_name: str, tactic: str) -> str:
    """Build a detailed prompt for LLM-based Sigma rule generation."""
    return textwrap.dedent(f"""\
        You are an expert detection engineer. Generate a Sigma detection rule for
        the following MITRE ATT&CK technique.

        Technique ID: {technique_id}
        Technique Name: {technique_name}
        Tactic: {tactic}

        Requirements:
        - Use standard Sigma field names (Image, CommandLine, ParentImage,
          TargetImage, SourceImage, GrantedAccess, EventID, etc.)
        - Choose the most appropriate logsource. Common sources include:
          * Sysmon (category: process_creation, process_access, file_event, etc.)
          * Windows Security logs (product: windows, service: security)
          * Windows PowerShell logs (product: windows, service: powershell)
        - Include at least one selection and a condition in the detection block.
        - Add relevant false-positive notes.
        - Use attack.{{tactic}} and attack.{{technique_id}} tag format (lowercase,
          dots replaced with underscores).
        - Set an appropriate severity level.

        {_FEW_SHOT_EXAMPLE}

        Generate the Sigma rule for {technique_id} ({technique_name}).
        Respond ONLY with the JSON object matching the required schema.
    """)


# ---------------------------------------------------------------------------
# Core generator
# ---------------------------------------------------------------------------


async def generate_rule(
    technique_id: str,
    *,
    llm_client: LLMClient | None = None,
    author: str = "PurpleChef",
) -> tuple[dict[str, Any], str]:
    """Generate a Sigma rule for the given MITRE ATT&CK technique.

    Returns
    -------
    tuple[dict, str]
        (sigma_rule_dict, source) where *source* is ``"template"`` when a
        deterministic template was used, or ``"llm"`` when the rule was
        generated via the LLM client.

    Raises
    ------
    ValueError
        If no template exists and no ``llm_client`` was provided.
    """
    # 1. Try deterministic template first.
    template_fn = sigma_templates.get_template(technique_id)
    if template_fn is not None:
        rule = template_fn(technique_id, author)
        return rule, "template"

    # 2. Fallback to LLM generation.
    if llm_client is None:
        raise ValueError(
            f"No Sigma template for {technique_id} and no LLM client provided. "
            f"Available templates: {sigma_templates.list_templates()}"
        )

    # Resolve technique metadata for the prompt.
    technique = MitreResolver.build_technique(technique_id)
    prompt = _build_llm_prompt(technique.id, technique.name, technique.tactic)

    draft: SigmaRuleDraft = await llm_client.generate_structured(
        prompt,
        output_model=SigmaRuleDraft,
    )

    # Convert the structured draft into the full Sigma rule dict.
    today = date.today().isoformat()
    rule: dict[str, Any] = {
        "title": draft.title,
        "id": f"purplechef-{technique_id.lower().replace('.', '-')}-llm",
        "status": "experimental",
        "description": draft.description,
        "author": author,
        "date": today,
        "references": [
            f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        ],
        "tags": draft.tags,
        "logsource": draft.logsource,
        "detection": draft.detection,
        "falsepositives": draft.falsepositives,
        "level": draft.level,
    }

    return rule, "llm"


async def generate_rule_yaml(
    technique_id: str,
    *,
    llm_client: LLMClient | None = None,
    author: str = "PurpleChef",
) -> tuple[str, str]:
    """Convenience wrapper that returns rendered YAML instead of a dict."""
    rule_dict, source = await generate_rule(
        technique_id,
        llm_client=llm_client,
        author=author,
    )
    return render_sigma_yaml(rule_dict), source
