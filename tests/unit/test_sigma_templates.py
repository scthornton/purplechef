"""Unit tests for chef_detection.sigma_templates."""

from __future__ import annotations

import yaml
from chef_detection.sigma_templates import (
    get_template,
    has_template,
    list_templates,
    render_sigma_yaml,
)

# ---------------------------------------------------------------------------
# has_template
# ---------------------------------------------------------------------------


def test_has_template_returns_true_for_t1003_001() -> None:
    assert has_template("T1003.001") is True


def test_has_template_returns_true_for_t1059_001() -> None:
    assert has_template("T1059.001") is True


def test_has_template_returns_false_for_unknown_technique() -> None:
    assert has_template("T9999.999") is False


# ---------------------------------------------------------------------------
# list_templates
# ---------------------------------------------------------------------------


def test_list_templates_returns_all_seven() -> None:
    templates = list_templates()
    assert len(templates) == 7


def test_list_templates_is_sorted() -> None:
    templates = list_templates()
    assert templates == sorted(templates)


# ---------------------------------------------------------------------------
# get_template
# ---------------------------------------------------------------------------


def test_get_template_returns_callable_for_known_technique() -> None:
    fn = get_template("T1003.001")
    assert fn is not None
    assert callable(fn)


def test_get_template_returns_none_for_unknown_technique() -> None:
    assert get_template("T9999.999") is None


# ---------------------------------------------------------------------------
# Template output structure
# ---------------------------------------------------------------------------

_REQUIRED_SIGMA_FIELDS = {"title", "logsource", "detection", "tags"}


def test_template_output_has_required_sigma_fields() -> None:
    for technique_id in list_templates():
        fn = get_template(technique_id)
        assert fn is not None
        rule = fn(technique_id)
        missing = _REQUIRED_SIGMA_FIELDS - rule.keys()
        assert not missing, f"{technique_id} missing fields: {missing}"


def test_template_output_logsource_is_dict() -> None:
    fn = get_template("T1003.001")
    assert fn is not None
    rule = fn("T1003.001")
    assert isinstance(rule["logsource"], dict)


def test_template_output_detection_has_condition() -> None:
    fn = get_template("T1003.001")
    assert fn is not None
    rule = fn("T1003.001")
    assert "condition" in rule["detection"]


def test_template_output_tags_are_list_of_strings() -> None:
    fn = get_template("T1059.001")
    assert fn is not None
    rule = fn("T1059.001")
    assert isinstance(rule["tags"], list)
    for tag in rule["tags"]:
        assert isinstance(tag, str)


# ---------------------------------------------------------------------------
# render_sigma_yaml
# ---------------------------------------------------------------------------


def test_render_sigma_yaml_produces_valid_yaml() -> None:
    fn = get_template("T1003.001")
    assert fn is not None
    rule = fn("T1003.001")
    yaml_str = render_sigma_yaml(rule)
    assert isinstance(yaml_str, str)
    parsed = yaml.safe_load(yaml_str)
    assert isinstance(parsed, dict)
    assert parsed["title"] == rule["title"]


def test_render_sigma_yaml_preserves_detection_condition() -> None:
    fn = get_template("T1550.002")
    assert fn is not None
    rule = fn("T1550.002")
    yaml_str = render_sigma_yaml(rule)
    parsed = yaml.safe_load(yaml_str)
    assert parsed["detection"]["condition"] == rule["detection"]["condition"]
