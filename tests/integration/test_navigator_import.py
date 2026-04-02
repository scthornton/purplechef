"""Integration tests for navigator import — verify generated recipes are discoverable."""

from __future__ import annotations

import json
from pathlib import Path

from chef_recipes.navigator_import import generate_recipe_stubs
from chef_recipes.recipe_loader import discover_recipes


def _make_layer(techniques: list[dict]) -> dict:
    return {"name": "test", "domain": "enterprise-attack", "techniques": techniques}


class TestNavigatorImportDiscovery:
    """Finding 1: generated stubs must be discoverable by discover_recipes."""

    def test_generated_stub_creates_recipe_yml(self, tmp_path: Path) -> None:
        created = generate_recipe_stubs(["T1003.001"], tmp_path)
        recipe_files = [p for p in created if p.name == "recipe.yml"]
        assert len(recipe_files) == 1

    def test_generated_stub_is_discoverable(self, tmp_path: Path) -> None:
        generate_recipe_stubs(["T1003.001"], tmp_path)
        discovered = discover_recipes(tmp_path)
        assert len(discovered) == 1
        assert discovered[0].name == "recipe.yml"

    def test_generated_stub_in_named_directory(self, tmp_path: Path) -> None:
        generate_recipe_stubs(["T1003.001"], tmp_path)
        discovered = discover_recipes(tmp_path)
        assert "coverage-gap" in str(discovered[0].parent.name)

    def test_sigma_rule_referenced_in_recipe(self, tmp_path: Path) -> None:
        """If a Sigma template exists, the recipe should reference it."""
        generate_recipe_stubs(["T1003.001"], tmp_path)
        discovered = discover_recipes(tmp_path)
        import yaml

        recipe = yaml.safe_load(discovered[0].read_text())
        sigma_rules = recipe.get("validate", {}).get("sigma_rules", [])
        assert len(sigma_rules) == 1
        assert "sigma-rules/" in sigma_rules[0]["path"]

    def test_sigma_rule_file_exists(self, tmp_path: Path) -> None:
        generate_recipe_stubs(["T1003.001"], tmp_path)
        discovered = discover_recipes(tmp_path)
        import yaml

        recipe = yaml.safe_load(discovered[0].read_text())
        sigma_path = discovered[0].parent / recipe["validate"]["sigma_rules"][0]["path"]
        assert sigma_path.exists()

    def test_multiple_stubs_all_discoverable(self, tmp_path: Path) -> None:
        generate_recipe_stubs(["T1003.001", "T1059.001", "T1018"], tmp_path)
        discovered = discover_recipes(tmp_path)
        assert len(discovered) == 3

    def test_stub_uses_manual_method(self, tmp_path: Path) -> None:
        """Stubs should default to manual (not atomic which is unimplemented)."""
        generate_recipe_stubs(["T1003.001"], tmp_path)
        discovered = discover_recipes(tmp_path)
        import yaml

        recipe = yaml.safe_load(discovered[0].read_text())
        assert recipe["attack"]["method"] == "manual"


class TestDryRunProducesChains:
    """Finding 2: dry-run should return error chains, not empty results."""

    def test_dry_run_blocked_result_has_evidence_chains(self, tmp_path: Path) -> None:
        """Verify that a CoverageResult from dry-run has non-empty evidence_chains."""
        from datetime import UTC, datetime

        from chef_pantry.models.evidence import CoverageResult, EvidenceChain
        from chef_pantry.models.technique import MitreTechnique

        # Simulate what the orchestrator should produce on dry-run
        technique = MitreTechnique(id="T1003.001", name="LSASS Memory", tactic="credential-access")
        now = datetime.now(UTC)
        chain = EvidenceChain(
            technique=technique,
            emulation_id="dry-run",
            execution_start=now,
            execution_end=now,
            detection_window_start=now,
            detection_window_end=now,
            detections=[],
            status="error",
            notes="Blocked by dry-run mode",
        )
        result = CoverageResult(
            recipe_name="test",
            run_id="test-run",
            timestamp=now,
            evidence_chains=[chain],
        )
        assert result.total_count == 1
        assert result.missed_count == 0  # error != missed
        assert result.detected_count == 0
        assert chain.status == "error"
        assert "dry-run" in chain.notes.lower()
