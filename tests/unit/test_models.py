"""Unit tests for Chef Pantry Pydantic models."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError as PydanticValidationError

from chef_pantry.models.evidence import CoverageResult, DetectionMatch, EvidenceChain
from chef_pantry.models.recipe import AttackSpec, Recipe
from chef_pantry.models.technique import MitreTechnique, ResolvedTechnique


# ---------------------------------------------------------------------------
# MitreTechnique
# ---------------------------------------------------------------------------


class TestMitreTechnique:
    def test_create_with_all_fields(self, sample_technique: MitreTechnique) -> None:
        assert sample_technique.id == "T1003.001"
        assert sample_technique.name == "LSASS Memory"
        assert sample_technique.tactic == "credential-access"
        assert sample_technique.description == "Dump credentials from LSASS process memory."

    def test_create_without_description(self, sample_technique_no_sub: MitreTechnique) -> None:
        assert sample_technique_no_sub.description is None

    def test_url_for_subtechnique(self, sample_technique: MitreTechnique) -> None:
        assert sample_technique.url == "https://attack.mitre.org/techniques/T1003/001/"

    def test_url_for_top_level_technique(self, sample_technique_no_sub: MitreTechnique) -> None:
        assert sample_technique_no_sub.url == "https://attack.mitre.org/techniques/T1018/"

    def test_frozen_model_rejects_mutation(self, sample_technique: MitreTechnique) -> None:
        with pytest.raises(PydanticValidationError):
            sample_technique.name = "Changed"


# ---------------------------------------------------------------------------
# ResolvedTechnique
# ---------------------------------------------------------------------------


class TestResolvedTechnique:
    def test_caldera_source(self, sample_technique: MitreTechnique) -> None:
        rt = ResolvedTechnique(
            technique=sample_technique,
            caldera_ability_id="abc-123",
            resolution_source="caldera",
        )
        assert rt.caldera_ability_id == "abc-123"
        assert rt.atomic_test_numbers is None
        assert rt.resolution_source == "caldera"

    def test_atomic_source(self, sample_technique: MitreTechnique) -> None:
        rt = ResolvedTechnique(
            technique=sample_technique,
            atomic_test_numbers=[1, 2],
            resolution_source="atomic",
        )
        assert rt.caldera_ability_id is None
        assert rt.atomic_test_numbers == [1, 2]
        assert rt.resolution_source == "atomic"

    def test_manual_source(self, sample_technique: MitreTechnique) -> None:
        rt = ResolvedTechnique(
            technique=sample_technique,
            resolution_source="manual",
        )
        assert rt.resolution_source == "manual"

    def test_invalid_resolution_source(self, sample_technique: MitreTechnique) -> None:
        with pytest.raises(PydanticValidationError):
            ResolvedTechnique(
                technique=sample_technique,
                resolution_source="unknown",
            )


# ---------------------------------------------------------------------------
# EvidenceChain
# ---------------------------------------------------------------------------


def _make_evidence_chain(
    status: str,
    detections: list[DetectionMatch] | None = None,
    technique: MitreTechnique | None = None,
) -> EvidenceChain:
    now = datetime.now(timezone.utc)
    tech = technique or MitreTechnique(
        id="T1018", name="Remote System Discovery", tactic="discovery"
    )
    return EvidenceChain(
        technique=tech,
        emulation_id="op-001",
        execution_start=now - timedelta(minutes=5),
        execution_end=now - timedelta(minutes=3),
        detection_window_start=now - timedelta(minutes=3),
        detection_window_end=now,
        detections=detections or [],
        status=status,
    )


class TestEvidenceChain:
    def test_is_detected_true(self) -> None:
        chain = _make_evidence_chain("detected")
        assert chain.is_detected is True

    def test_is_detected_false_when_missed(self) -> None:
        chain = _make_evidence_chain("missed")
        assert chain.is_detected is False

    def test_is_detected_false_when_partial(self) -> None:
        chain = _make_evidence_chain("partial")
        assert chain.is_detected is False

    def test_is_detected_false_when_error(self) -> None:
        chain = _make_evidence_chain("error")
        assert chain.is_detected is False

    def test_detection_count_zero(self) -> None:
        chain = _make_evidence_chain("missed")
        assert chain.detection_count == 0

    def test_detection_count_with_detections(self) -> None:
        now = datetime.now(timezone.utc)
        det = DetectionMatch(
            rule_name="lsass_access",
            source="limacharlie",
            timestamp=now,
            alert_id="alert-1",
            confidence=0.95,
        )
        chain = _make_evidence_chain("detected", detections=[det])
        assert chain.detection_count == 1

    def test_invalid_status_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            _make_evidence_chain("unknown_status")


# ---------------------------------------------------------------------------
# CoverageResult
# ---------------------------------------------------------------------------


class TestCoverageResult:
    def _make_result(self, statuses: list[str]) -> CoverageResult:
        chains = [_make_evidence_chain(s) for s in statuses]
        return CoverageResult(
            recipe_name="test-recipe",
            run_id="run-001",
            timestamp=datetime.now(timezone.utc),
            evidence_chains=chains,
        )

    def test_empty_result(self) -> None:
        result = self._make_result([])
        assert result.total_count == 0
        assert result.detected_count == 0
        assert result.missed_count == 0
        assert result.coverage_percentage == 0.0

    def test_all_detected(self) -> None:
        result = self._make_result(["detected", "detected", "detected"])
        assert result.total_count == 3
        assert result.detected_count == 3
        assert result.missed_count == 0
        assert result.coverage_percentage == 100.0

    def test_all_missed(self) -> None:
        result = self._make_result(["missed", "missed"])
        assert result.total_count == 2
        assert result.detected_count == 0
        assert result.missed_count == 2
        assert result.coverage_percentage == 0.0

    def test_mixed_statuses(self) -> None:
        result = self._make_result(["detected", "missed", "partial", "detected"])
        assert result.total_count == 4
        assert result.detected_count == 2
        assert result.missed_count == 1
        assert result.coverage_percentage == 50.0

    def test_partial_and_error_not_counted_as_detected(self) -> None:
        result = self._make_result(["partial", "error"])
        assert result.detected_count == 0
        assert result.missed_count == 0


# ---------------------------------------------------------------------------
# Recipe model_validate
# ---------------------------------------------------------------------------


class TestRecipe:
    def test_valid_recipe_from_dict(self, sample_recipe_dict: dict) -> None:
        recipe = Recipe.model_validate(sample_recipe_dict)
        assert recipe.name == "cred-dump-test"
        assert recipe.version == "1.0"
        assert recipe.metadata.author == "scott"
        assert recipe.metadata.difficulty == "intermediate"
        assert recipe.attack.method == "caldera"
        assert recipe.attack.caldera is not None
        assert recipe.attack.caldera.adversary_name == "cred-dumper"

    def test_missing_required_field_raises(self, sample_recipe_dict: dict) -> None:
        del sample_recipe_dict["name"]
        with pytest.raises(PydanticValidationError):
            Recipe.model_validate(sample_recipe_dict)

    def test_invalid_difficulty_raises(self, sample_recipe_dict: dict) -> None:
        sample_recipe_dict["metadata"]["difficulty"] = "expert"
        with pytest.raises(PydanticValidationError):
            Recipe.model_validate(sample_recipe_dict)

    def test_defaults_applied(self, sample_recipe_dict: dict) -> None:
        del sample_recipe_dict["report"]
        del sample_recipe_dict["advise"]
        recipe = Recipe.model_validate(sample_recipe_dict)
        assert recipe.report.format == ["json", "html"]
        assert recipe.advise.generate_sigma is True
        assert recipe.advise.generate_kql is False


# ---------------------------------------------------------------------------
# AttackSpec validator
# ---------------------------------------------------------------------------


class TestAttackSpec:
    def test_caldera_method_requires_caldera_spec(self) -> None:
        with pytest.raises(PydanticValidationError, match="caldera spec required"):
            AttackSpec(method="caldera", caldera=None, atomic=None)

    def test_atomic_method_requires_atomic_spec(self) -> None:
        with pytest.raises(PydanticValidationError, match="atomic spec required"):
            AttackSpec(method="atomic", caldera=None, atomic=None)

    def test_manual_method_needs_no_spec(self) -> None:
        spec = AttackSpec(method="manual")
        assert spec.caldera is None
        assert spec.atomic is None

    def test_caldera_method_with_caldera_spec_passes(self) -> None:
        from chef_pantry.models.emulation import CalderaAbilitySpec, CalderaAttackSpec

        caldera_spec = CalderaAttackSpec(
            adversary_name="test",
            abilities=[CalderaAbilitySpec(technique_id="T1003.001")],
            group="lab",
        )
        spec = AttackSpec(method="caldera", caldera=caldera_spec)
        assert spec.caldera.adversary_name == "test"
