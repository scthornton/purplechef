"""Unit tests for chef_detection.rule_validator."""

from __future__ import annotations

import yaml
from chef_detection.rule_validator import validate_sigma, validate_sigma_yaml


def _make_valid_rule() -> dict:
    """Return a minimal valid Sigma rule dict."""
    return {
        "title": "Test Rule",
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection": {
                "Image|endswith": "\\cmd.exe",
            },
            "condition": "selection",
        },
        "level": "medium",
        "tags": ["attack.execution", "attack.t1059_001"],
    }


# ---------------------------------------------------------------------------
# Valid rule
# ---------------------------------------------------------------------------


def test_valid_rule_passes() -> None:
    result = validate_sigma(_make_valid_rule())
    assert result.is_valid is True
    assert result.errors == []


# ---------------------------------------------------------------------------
# Missing required fields
# ---------------------------------------------------------------------------


def test_missing_title_fails() -> None:
    rule = _make_valid_rule()
    del rule["title"]
    result = validate_sigma(rule)
    assert result.is_valid is False
    assert any("title" in e.lower() for e in result.errors)


def test_missing_logsource_fails() -> None:
    rule = _make_valid_rule()
    del rule["logsource"]
    result = validate_sigma(rule)
    assert result.is_valid is False
    assert any("logsource" in e.lower() for e in result.errors)


def test_missing_detection_fails() -> None:
    rule = _make_valid_rule()
    del rule["detection"]
    result = validate_sigma(rule)
    assert result.is_valid is False
    assert any("detection" in e.lower() for e in result.errors)


# ---------------------------------------------------------------------------
# Detection validation
# ---------------------------------------------------------------------------


def test_empty_detection_condition_fails() -> None:
    rule = _make_valid_rule()
    rule["detection"]["condition"] = ""
    result = validate_sigma(rule)
    assert result.is_valid is False
    assert any("condition" in e.lower() for e in result.errors)


# ---------------------------------------------------------------------------
# Level validation
# ---------------------------------------------------------------------------


def test_invalid_level_fails() -> None:
    rule = _make_valid_rule()
    rule["level"] = "super-critical"
    result = validate_sigma(rule)
    assert result.is_valid is False
    assert any("level" in e.lower() for e in result.errors)


def test_missing_level_produces_warning_not_error() -> None:
    rule = _make_valid_rule()
    del rule["level"]
    result = validate_sigma(rule)
    assert result.is_valid is True
    assert any("level" in w.lower() for w in result.warnings)


# ---------------------------------------------------------------------------
# Tag validation
# ---------------------------------------------------------------------------


def test_valid_tags_pass() -> None:
    rule = _make_valid_rule()
    rule["tags"] = ["attack.t1003_001", "attack.credential_access"]
    result = validate_sigma(rule)
    assert result.is_valid is True
    # No tag-related warnings expected for well-formed tags
    tag_warnings = [w for w in result.warnings if "tag" in w.lower()]
    assert tag_warnings == []


# ---------------------------------------------------------------------------
# validate_sigma_yaml
# ---------------------------------------------------------------------------


def test_validate_sigma_yaml_with_valid_string() -> None:
    rule = _make_valid_rule()
    yaml_str = yaml.dump(rule, default_flow_style=False)
    result = validate_sigma_yaml(yaml_str)
    assert result.is_valid is True
    assert result.errors == []


def test_validate_sigma_yaml_with_invalid_yaml() -> None:
    bad_yaml = "title: [unterminated\nlogsource:"
    result = validate_sigma_yaml(bad_yaml)
    assert result.is_valid is False
    assert any("yaml" in e.lower() or "parse" in e.lower() for e in result.errors)


def test_validate_sigma_yaml_with_non_mapping() -> None:
    result = validate_sigma_yaml("- item1\n- item2\n")
    assert result.is_valid is False
    assert any("mapping" in e.lower() for e in result.errors)
