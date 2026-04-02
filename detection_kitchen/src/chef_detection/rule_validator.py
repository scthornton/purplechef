"""Sigma rule validator.

Validates Sigma rules for structural correctness, required fields,
and convention compliance before they are written to disk or deployed.
"""

from __future__ import annotations

import re
from typing import Any

import yaml
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Validation result model
# ---------------------------------------------------------------------------


class ValidationResult(BaseModel):
    """Outcome of validating a single Sigma rule."""

    is_valid: bool = True
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)
        self.is_valid = False

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
_VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
_ATTACK_TAG_RE = re.compile(r"^attack\.[a-z0-9_]+$")
_REQUIRED_TOP_LEVEL = {"title", "logsource", "detection"}


# ---------------------------------------------------------------------------
# Core validation
# ---------------------------------------------------------------------------


def validate_sigma(rule: dict[str, Any]) -> ValidationResult:
    """Validate a Sigma rule dict for correctness.

    Checks performed:
    - Required top-level fields: title, logsource, detection
    - logsource contains at least ``category`` or ``product``
    - detection contains at least one selection and a ``condition``
    - level is one of the valid Sigma severity levels
    - Tags follow the ``attack.tXXXX`` / ``attack.<tactic>`` pattern
    - No empty strings in required fields
    """
    result = ValidationResult()

    if not isinstance(rule, dict):
        result.add_error("Rule must be a dict/mapping")
        return result

    # --- Required top-level fields ---
    for field in _REQUIRED_TOP_LEVEL:
        if field not in rule:
            result.add_error(f"Missing required field: '{field}'")
        elif isinstance(rule[field], str) and not rule[field].strip():
            result.add_error(f"Required field '{field}' must not be empty")

    # Early exit if critical fields are missing.
    if not result.is_valid:
        return result

    # --- Title ---
    if not isinstance(rule["title"], str) or not rule["title"].strip():
        result.add_error("Field 'title' must be a non-empty string")

    # --- Logsource validation ---
    logsource = rule["logsource"]
    if not isinstance(logsource, dict):
        result.add_error("Field 'logsource' must be a mapping")
    else:
        if "category" not in logsource and "product" not in logsource:
            result.add_error("Field 'logsource' must contain at least 'category' or 'product'")
        for key in ("category", "product", "service"):
            val = logsource.get(key)
            if val is not None and (not isinstance(val, str) or not val.strip()):
                result.add_error(f"logsource.{key} must be a non-empty string if present")

    # --- Detection validation ---
    detection = rule["detection"]
    if not isinstance(detection, dict):
        result.add_error("Field 'detection' must be a mapping")
    else:
        if "condition" not in detection:
            result.add_error("detection must contain a 'condition' key")
        elif not isinstance(detection["condition"], str) or not detection["condition"].strip():
            result.add_error("detection.condition must be a non-empty string")

        # Must have at least one selection (any key other than 'condition').
        selection_keys = [k for k in detection if k != "condition"]
        if not selection_keys:
            result.add_error(
                "detection must contain at least one selection (a key other than 'condition')"
            )

    # --- Level validation ---
    level = rule.get("level")
    if level is not None:
        if not isinstance(level, str) or level.lower() not in _VALID_LEVELS:
            result.add_error(
                f"Invalid level '{level}'. Must be one of: {', '.join(sorted(_VALID_LEVELS))}"
            )
    else:
        result.add_warning("Field 'level' is missing (recommended)")

    # --- Status validation ---
    status = rule.get("status")
    if status is not None and (
        not isinstance(status, str) or status.lower() not in _VALID_STATUSES
    ):
        result.add_warning(
            f"Non-standard status '{status}'. Expected one of: {', '.join(sorted(_VALID_STATUSES))}"
        )

    # --- Tag validation ---
    tags = rule.get("tags")
    if tags is not None:
        if not isinstance(tags, list):
            result.add_error("Field 'tags' must be a list")
        else:
            for tag in tags:
                if not isinstance(tag, str):
                    result.add_error(f"Each tag must be a string, got: {type(tag).__name__}")
                elif not _ATTACK_TAG_RE.match(tag):
                    result.add_warning(
                        f"Tag '{tag}' does not match expected pattern 'attack.<identifier>'"
                    )
    else:
        result.add_warning("Field 'tags' is missing (recommended for MITRE mapping)")

    # --- Falsepositives ---
    fps = rule.get("falsepositives")
    if fps is not None:
        if not isinstance(fps, list):
            result.add_warning("Field 'falsepositives' should be a list of strings")
        else:
            for fp in fps:
                if not isinstance(fp, str) or not fp.strip():
                    result.add_warning("Each false-positive entry should be a non-empty string")

    # --- Description ---
    desc = rule.get("description")
    if desc is None:
        result.add_warning("Field 'description' is missing (recommended)")
    elif isinstance(desc, str) and not desc.strip():
        result.add_warning("Field 'description' is empty")

    return result


def validate_sigma_yaml(yaml_str: str) -> ValidationResult:
    """Parse a YAML string and validate it as a Sigma rule.

    If the YAML is malformed, returns a result with a parse error.
    """
    result = ValidationResult()

    try:
        data = yaml.safe_load(yaml_str)
    except yaml.YAMLError as exc:
        result.add_error(f"YAML parse error: {exc}")
        return result

    if not isinstance(data, dict):
        result.add_error("YAML did not parse to a mapping; got " + type(data).__name__)
        return result

    return validate_sigma(data)
