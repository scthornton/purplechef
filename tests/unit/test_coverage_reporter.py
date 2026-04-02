"""Unit tests for chef_detection.coverage_reporter."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from chef_detection.coverage_reporter import (
    generate_html_report,
    generate_navigator_json,
    save_report,
)
from chef_pantry.models.evidence import (
    CoverageResult,
    DetectionMatch,
    EvidenceChain,
)
from chef_pantry.models.technique import MitreTechnique

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2025, 6, 15, 12, 0, 0, tzinfo=UTC)


def _make_technique(tid: str, name: str, tactic: str) -> MitreTechnique:
    return MitreTechnique(id=tid, name=name, tactic=tactic)


def _make_chain(
    tid: str,
    name: str,
    tactic: str,
    *,
    detected: bool = True,
) -> EvidenceChain:
    technique = _make_technique(tid, name, tactic)
    detections = []
    if detected:
        detections.append(
            DetectionMatch(
                rule_name=f"rule-{tid}",
                source="sentinel",
                timestamp=_NOW,
                alert_id=f"alert-{tid}",
                confidence=0.95,
            )
        )
    return EvidenceChain(
        technique=technique,
        emulation_id=f"emu-{tid}",
        execution_start=_NOW,
        execution_end=_NOW,
        detection_window_start=_NOW,
        detection_window_end=_NOW,
        detections=detections,
        status="detected" if detected else "missed",
    )


def _make_coverage_result() -> CoverageResult:
    return CoverageResult(
        recipe_name="Test Recipe",
        run_id="test-run-001",
        timestamp=_NOW,
        evidence_chains=[
            _make_chain("T1003.001", "LSASS Memory", "credential_access", detected=True),
            _make_chain("T1059.001", "PowerShell", "execution", detected=True),
            _make_chain("T1018", "Remote Discovery", "discovery", detected=False),
        ],
    )


# ---------------------------------------------------------------------------
# generate_navigator_json
# ---------------------------------------------------------------------------


def test_navigator_json_has_required_top_level_keys() -> None:
    result = _make_coverage_result()
    layer = generate_navigator_json(result)
    assert "name" in layer
    assert "versions" in layer
    assert "domain" in layer
    assert "techniques" in layer
    assert "gradient" in layer


def test_navigator_json_domain_is_enterprise_attack() -> None:
    result = _make_coverage_result()
    layer = generate_navigator_json(result)
    assert layer["domain"] == "enterprise-attack"


def test_navigator_json_technique_count_matches() -> None:
    result = _make_coverage_result()
    layer = generate_navigator_json(result)
    assert len(layer["techniques"]) == 3


def test_navigator_json_detected_technique_has_score_100() -> None:
    result = _make_coverage_result()
    layer = generate_navigator_json(result)
    t1003 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1003.001")
    assert t1003["score"] == 100


def test_navigator_json_missed_technique_has_score_0() -> None:
    result = _make_coverage_result()
    layer = generate_navigator_json(result)
    t1018 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1018")
    assert t1018["score"] == 0


def test_navigator_json_is_valid_json_serializable() -> None:
    result = _make_coverage_result()
    layer = generate_navigator_json(result)
    serialized = json.dumps(layer, default=str)
    parsed = json.loads(serialized)
    assert parsed["name"] == layer["name"]


# ---------------------------------------------------------------------------
# generate_html_report
# ---------------------------------------------------------------------------


def test_html_report_contains_purplechef() -> None:
    result = _make_coverage_result()
    html = generate_html_report(result)
    assert "PurpleChef" in html


def test_html_report_contains_technique_ids() -> None:
    result = _make_coverage_result()
    html = generate_html_report(result)
    assert "T1003.001" in html
    assert "T1059.001" in html
    assert "T1018" in html


def test_html_report_contains_recipe_name() -> None:
    result = _make_coverage_result()
    html = generate_html_report(result)
    assert "Test Recipe" in html


def test_html_report_is_valid_html_structure() -> None:
    result = _make_coverage_result()
    html = generate_html_report(result)
    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html


# ---------------------------------------------------------------------------
# save_report
# ---------------------------------------------------------------------------


def test_save_report_creates_json_file(tmp_path: Path) -> None:
    result = _make_coverage_result()
    paths = save_report(result, tmp_path, ["json"])
    assert len(paths) == 1
    assert paths[0].exists()
    assert paths[0].suffix == ".json"
    data = json.loads(paths[0].read_text())
    assert data["recipe_name"] == "Test Recipe"


def test_save_report_creates_html_file(tmp_path: Path) -> None:
    result = _make_coverage_result()
    paths = save_report(result, tmp_path, ["html"])
    assert len(paths) == 1
    assert paths[0].exists()
    assert paths[0].suffix == ".html"
    content = paths[0].read_text()
    assert "PurpleChef" in content


def test_save_report_creates_navigator_file(tmp_path: Path) -> None:
    result = _make_coverage_result()
    paths = save_report(result, tmp_path, ["navigator"])
    assert len(paths) == 1
    assert paths[0].exists()
    layer = json.loads(paths[0].read_text())
    assert layer["domain"] == "enterprise-attack"


def test_save_report_creates_all_formats(tmp_path: Path) -> None:
    result = _make_coverage_result()
    paths = save_report(result, tmp_path, ["json", "html", "navigator"])
    assert len(paths) == 3
    for p in paths:
        assert p.exists()


def test_save_report_creates_output_dir(tmp_path: Path) -> None:
    nested = tmp_path / "deep" / "nested" / "dir"
    result = _make_coverage_result()
    paths = save_report(result, nested, ["json"])
    assert len(paths) == 1
    assert nested.exists()
