"""MITRE ATT&CK Navigator layer import -- generates recipe stubs for uncovered techniques.

Loads Navigator JSON layers, identifies coverage gaps, and produces
recipe YAML stubs (plus Sigma rules when templates exist) so operators
can quickly scaffold detection validation for missing coverage.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml
from chef_detection.sigma_templates import get_template, has_template, render_sigma_yaml
from chef_pantry.mitre.resolver import MitreResolver
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class NavigatorAnalysis(BaseModel):
    """Summary of technique coverage derived from a Navigator layer."""

    total_techniques: int
    covered: int
    uncovered: int
    gap_technique_ids: list[str]


# ---------------------------------------------------------------------------
# Layer loading & validation
# ---------------------------------------------------------------------------


def load_navigator_layer(path: Path) -> dict:
    """Load and validate a MITRE ATT&CK Navigator JSON layer.

    Raises ``ValueError`` when the file is missing required Navigator
    fields or cannot be parsed as JSON.
    """
    raw = path.read_text(encoding="utf-8")
    try:
        layer: dict = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in Navigator layer: {path}") from exc

    # Minimal structural validation
    if "techniques" not in layer:
        raise ValueError(f"Navigator layer is missing 'techniques' key: {path}")
    if not isinstance(layer["techniques"], list):
        raise ValueError(f"'techniques' must be a list in Navigator layer: {path}")

    return layer


# ---------------------------------------------------------------------------
# Coverage extraction
# ---------------------------------------------------------------------------


def extract_uncovered_techniques(
    layer: dict,
    *,
    score_threshold: int = 50,
) -> list[str]:
    """Return technique IDs with a score below *score_threshold*.

    A technique is considered uncovered when:
    - Its ``score`` is ``0`` or below the threshold.
    - It has no ``score`` key at all (treated as 0 / uncovered).
    """
    uncovered: list[str] = []
    for entry in layer.get("techniques", []):
        technique_id: str | None = entry.get("techniqueID")
        if not technique_id:
            continue
        score: int = entry.get("score", 0)
        if score < score_threshold:
            uncovered.append(technique_id)

    return sorted(set(uncovered))


# ---------------------------------------------------------------------------
# Recipe stub generation
# ---------------------------------------------------------------------------

_RECIPE_STUB_TEMPLATE: dict[str, Any] = {
    "version": "1.0",
    "metadata": {
        "author": "PurpleChef (auto-generated)",
        "mitre_techniques": [],
        "mitre_tactics": [],
        "difficulty": "intermediate",
        "estimated_time": "15m",
        "tags": ["auto-generated", "coverage-gap"],
    },
    "mise_en_place": {
        "terraform_module": None,
        "ansible_roles": [],
        "prerequisites": {},
    },
    "attack": {
        "method": "manual",
    },
    "validate": {
        "detection_source": "manual",
        "wait_seconds": 120,
        "expected_rules": [],
        "sigma_rules": [],
    },
    "report": {
        "format": ["json", "html"],
        "evidence_required": True,
    },
    "advise": {
        "generate_sigma": True,
        "generate_kql": False,
    },
}


def _build_recipe_stub(technique_id: str, *, sigma_rel_path: str | None = None) -> dict[str, Any]:
    """Build a single recipe stub dict for a technique ID."""
    technique = MitreResolver.build_technique(technique_id)

    stub = json.loads(json.dumps(_RECIPE_STUB_TEMPLATE))  # deep copy
    safe = technique_id.lower().replace(".", "-")
    stub["name"] = f"coverage-gap-{safe}"
    stub["description"] = (
        f"Auto-generated recipe stub to cover {technique.name} ({technique_id}). "
        "Fill in attack and detection details before running."
    )
    stub["metadata"]["mitre_techniques"] = [technique_id]
    stub["metadata"]["mitre_tactics"] = [technique.tactic]
    if sigma_rel_path:
        stub["validate"]["sigma_rules"] = [{"path": sigma_rel_path}]
    return stub


def generate_recipe_stubs(
    technique_ids: list[str],
    output_dir: Path,
) -> list[Path]:
    """Create recipe YAML stubs (and optional Sigma rules) for each technique.

    Returns a list of all file paths that were created.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []

    for tid in technique_ids:
        safe_name = tid.lower().replace(".", "-")
        recipe_dir = output_dir / f"coverage-gap-{safe_name}"
        recipe_dir.mkdir(parents=True, exist_ok=True)

        # --- sigma rule first (if template exists) so we can reference it ---
        sigma_rel_path: str | None = None
        if has_template(tid):
            template_fn = get_template(tid)
            if template_fn is not None:
                sigma_dict = template_fn(tid)
                sigma_dir = recipe_dir / "sigma-rules"
                sigma_dir.mkdir(exist_ok=True)
                sigma_filename = f"{safe_name}.yml"
                sigma_path = sigma_dir / sigma_filename
                sigma_path.write_text(render_sigma_yaml(sigma_dict), encoding="utf-8")
                created.append(sigma_path)
                sigma_rel_path = f"sigma-rules/{sigma_filename}"
                logger.info("Created Sigma rule: %s", sigma_path)

        # --- recipe.yml (discoverable by discover_recipes) ---
        recipe_path = recipe_dir / "recipe.yml"
        stub = _build_recipe_stub(tid, sigma_rel_path=sigma_rel_path)
        recipe_path.write_text(
            yaml.dump(stub, default_flow_style=False, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        created.append(recipe_path)
        logger.info("Created recipe stub: %s", recipe_path)

    return created


# ---------------------------------------------------------------------------
# Coverage analysis
# ---------------------------------------------------------------------------


def analyze_coverage(
    layer: dict,
    *,
    score_threshold: int = 50,
) -> NavigatorAnalysis:
    """Analyze a Navigator layer and return a coverage summary."""
    seen_ids: set[str] = set()
    for entry in layer.get("techniques", []):
        tid = entry.get("techniqueID")
        if tid:
            seen_ids.add(tid)

    total = len(seen_ids)
    gap_ids = extract_uncovered_techniques(layer, score_threshold=score_threshold)
    uncovered = len(gap_ids)
    covered = total - uncovered

    return NavigatorAnalysis(
        total_techniques=total,
        covered=covered,
        uncovered=uncovered,
        gap_technique_ids=gap_ids,
    )
