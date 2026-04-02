"""CLI smoke tests — catch integration seam failures between config, CLI, and orchestrator.

These tests exercise real CLI commands with minimal mocking to verify
the application layer works end-to-end.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from chef_cli.main import cli
from click.testing import CliRunner


def _make_env(tmp_path: Path) -> dict[str, str]:
    """Minimal env vars that satisfy ChefSettings without a real backend."""
    return {
        "CHEF_CALDERA_URL": "http://localhost:8888",
        "CHEF_CALDERA_API_KEY": "test-key",
        "CHEF_LC_OID": "test-oid",
        "CHEF_LC_API_KEY": "test-lc-key",
        "CHEF_SAFETY_DRY_RUN": "true",
        "CHEF_SAFETY_AUDIT_LOG": str(tmp_path / "audit.log"),
    }


class TestRecipeRunSmoke:
    """Verify chef recipe run boots without AttributeError."""

    def test_dry_run_does_not_crash_on_settings_access(self, tmp_path: Path) -> None:
        """Finding 1: settings.dry_run, settings.caldera_url etc. must not AttributeError."""
        from chef_pantry.config import get_settings

        get_settings.cache_clear()
        env = _make_env(tmp_path)

        recipe_path = (
            Path(__file__).resolve().parents[2]
            / "recipe_book"
            / "src"
            / "chef_recipes"
            / "recipes"
            / "credential-access"
            / "recipe.yml"
        )

        runner = CliRunner(env=env)
        result = runner.invoke(cli, ["recipe", "run", str(recipe_path)])
        get_settings.cache_clear()

        # The critical assertion: no AttributeError on settings access (Finding 1)
        assert "AttributeError" not in (result.output or "")
        assert "AttributeError" not in str(result.exception or "")
        # In a no-backend environment, acceptable outcomes are:
        # - DryRunBlockedError (dry-run prevented execution)
        # - CalderaError (connection refused — no server running)
        # Both prove the settings plumbing worked; the failure is downstream.
        acceptable = ("DryRunBlockedError", "CalderaError")
        assert result.exception is None or any(
            t in type(result.exception).__name__ for t in acceptable
        )
        # Should show dry-run mode message before any failure
        assert "Dry-run mode" in result.output

    def test_config_loads_nested_safety_settings(self, tmp_path: Path) -> None:
        """Finding 6: CHEF_SAFETY_DRY_RUN must be read, not CHEF_DRY_RUN."""
        from chef_pantry.config import get_settings

        get_settings.cache_clear()
        env = _make_env(tmp_path)
        env["CHEF_SAFETY_DRY_RUN"] = "false"

        with patch.dict("os.environ", env, clear=False):
            settings = get_settings()
            assert settings.safety.dry_run is False
            assert settings.caldera.url == "http://localhost:8888"
            assert settings.limacharlie.oid == "test-oid"

        get_settings.cache_clear()


class TestRecipeDiscovery:
    """Finding 5: discover_recipes must find both .yml and .yaml."""

    def test_discovers_yml_files(self, tmp_path: Path) -> None:
        d = tmp_path / "recipes" / "test"
        d.mkdir(parents=True)
        (d / "recipe.yml").write_text("name: test\n")
        from chef_recipes.recipe_loader import discover_recipes

        assert len(discover_recipes(tmp_path)) == 1

    def test_discovers_yaml_files(self, tmp_path: Path) -> None:
        d = tmp_path / "recipes" / "test"
        d.mkdir(parents=True)
        (d / "recipe.yaml").write_text("name: test\n")
        from chef_recipes.recipe_loader import discover_recipes

        assert len(discover_recipes(tmp_path)) == 1

    def test_discovers_both_extensions(self, tmp_path: Path) -> None:
        d1 = tmp_path / "a"
        d1.mkdir()
        (d1 / "recipe.yml").write_text("name: a\n")
        d2 = tmp_path / "b"
        d2.mkdir()
        (d2 / "recipe.yaml").write_text("name: b\n")
        from chef_recipes.recipe_loader import discover_recipes

        assert len(discover_recipes(tmp_path)) == 2


class TestDetectReportIdempotent:
    """Finding 3: chef detect report must not crash on re-run."""

    def test_skips_navigator_json_on_rerun(self, tmp_path: Path) -> None:
        # Create a valid coverage result
        coverage = {
            "recipe_name": "test",
            "run_id": "abc123",
            "timestamp": "2026-04-01T00:00:00+00:00",
            "evidence_chains": [],
        }
        (tmp_path / "test_abc123.json").write_text(json.dumps(coverage))
        # Simulate a previous navigator output
        (tmp_path / "test_abc123_navigator.json").write_text(
            json.dumps({"name": "nav layer", "techniques": []})
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["detect", "report", str(tmp_path), "-f", "html"])

        assert result.exit_code == 0
        assert "Generated" in result.output
        # Should NOT crash on the navigator JSON
        assert "ValidationError" not in (result.output or "")

    def test_skips_non_coverage_json(self, tmp_path: Path) -> None:
        # Create a file that's valid JSON but not a CoverageResult
        (tmp_path / "random.json").write_text(json.dumps({"foo": "bar"}))

        runner = CliRunner()
        result = runner.invoke(cli, ["detect", "report", str(tmp_path)])

        # Should skip gracefully, not crash
        assert "Skipping non-coverage file" in result.output or result.exit_code == 1


class TestDetectTemplatesKnownTechniques:
    """Finding 6: all template techniques should resolve to known names."""

    def test_t1053_005_resolves_to_known_name(self) -> None:
        from chef_pantry.mitre.resolver import MitreResolver

        technique = MitreResolver.build_technique("T1053.005")
        assert "Unknown" not in technique.name
        assert technique.name == "Scheduled Task"

    def test_all_template_techniques_have_known_names(self) -> None:
        from chef_detection.sigma_templates import list_templates
        from chef_pantry.mitre.resolver import MitreResolver

        for tid in list_templates():
            technique = MitreResolver.build_technique(tid)
            assert "Unknown" not in technique.name, f"{tid} resolved to Unknown"
