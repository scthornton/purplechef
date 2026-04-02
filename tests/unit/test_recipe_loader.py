"""Unit tests for recipe_loader: load_recipe and discover_recipes."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from chef_pantry.errors import RecipeError, ValidationError
from chef_recipes.recipe_loader import discover_recipes, load_recipe

# ---------------------------------------------------------------------------
# load_recipe — valid YAML
# ---------------------------------------------------------------------------


class TestLoadRecipeValid:
    def test_loads_valid_recipe(
        self, tmp_path: Path, sample_recipe_dict: dict
    ) -> None:
        recipe_file = tmp_path / "recipe.yml"
        recipe_file.write_text(yaml.dump(sample_recipe_dict), encoding="utf-8")

        recipe = load_recipe(recipe_file)
        assert recipe.name == "cred-dump-test"
        assert recipe.metadata.author == "scott"
        assert recipe.attack.method == "caldera"

    def test_loads_yaml_extension(
        self, tmp_path: Path, sample_recipe_dict: dict
    ) -> None:
        recipe_file = tmp_path / "recipe.yaml"
        recipe_file.write_text(yaml.dump(sample_recipe_dict), encoding="utf-8")

        recipe = load_recipe(recipe_file)
        assert recipe.name == "cred-dump-test"


# ---------------------------------------------------------------------------
# load_recipe — missing file
# ---------------------------------------------------------------------------


class TestLoadRecipeMissingFile:
    def test_missing_file_raises_recipe_error(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.yml"
        with pytest.raises(RecipeError) as exc_info:
            load_recipe(missing)
        assert "not found" in str(exc_info.value).lower() or missing.name in str(exc_info.value)


# ---------------------------------------------------------------------------
# load_recipe — invalid YAML
# ---------------------------------------------------------------------------


class TestLoadRecipeInvalidYaml:
    def test_malformed_yaml_raises_recipe_error(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.yml"
        bad_file.write_text("{{{{not: valid:: yaml", encoding="utf-8")
        with pytest.raises(RecipeError) as exc_info:
            load_recipe(bad_file)
        assert "yaml" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower()

    def test_yaml_list_instead_of_mapping_raises_recipe_error(
        self, tmp_path: Path
    ) -> None:
        list_file = tmp_path / "list.yml"
        list_file.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(RecipeError) as exc_info:
            load_recipe(list_file)
        assert "mapping" in str(exc_info.value).lower() or "recipe" in str(exc_info.value).lower()

    def test_wrong_extension_raises_recipe_error(self, tmp_path: Path) -> None:
        txt_file = tmp_path / "recipe.txt"
        txt_file.write_text("name: test", encoding="utf-8")
        with pytest.raises(RecipeError):
            load_recipe(txt_file)


# ---------------------------------------------------------------------------
# load_recipe — schema violations
# ---------------------------------------------------------------------------


class TestLoadRecipeSchemaViolation:
    def test_missing_required_field_raises_validation_error(
        self, tmp_path: Path, sample_recipe_dict: dict
    ) -> None:
        del sample_recipe_dict["name"]
        recipe_file = tmp_path / "recipe.yml"
        recipe_file.write_text(yaml.dump(sample_recipe_dict), encoding="utf-8")

        with pytest.raises(ValidationError) as exc_info:
            load_recipe(recipe_file)
        assert exc_info.value.field == "recipe"

    def test_invalid_enum_raises_validation_error(
        self, tmp_path: Path, sample_recipe_dict: dict
    ) -> None:
        sample_recipe_dict["metadata"]["difficulty"] = "expert"
        recipe_file = tmp_path / "recipe.yml"
        recipe_file.write_text(yaml.dump(sample_recipe_dict), encoding="utf-8")

        with pytest.raises(ValidationError) as exc_info:
            load_recipe(recipe_file)
        assert "schema validation failed" in str(exc_info.value).lower() or exc_info.value.field == "recipe"

    def test_caldera_method_without_caldera_spec_raises_validation_error(
        self, tmp_path: Path, sample_recipe_dict: dict
    ) -> None:
        sample_recipe_dict["attack"] = {"method": "caldera"}
        recipe_file = tmp_path / "recipe.yml"
        recipe_file.write_text(yaml.dump(sample_recipe_dict), encoding="utf-8")

        with pytest.raises(ValidationError):
            load_recipe(recipe_file)


# ---------------------------------------------------------------------------
# discover_recipes
# ---------------------------------------------------------------------------


class TestDiscoverRecipes:
    def test_finds_recipe_files(self, tmp_recipe_dir: Path) -> None:
        found = discover_recipes(tmp_recipe_dir)
        assert len(found) == 1
        assert found[0].name == "recipe.yml"

    def test_finds_multiple_recipes(self, tmp_path: Path) -> None:
        for sub in ("alpha", "beta", "gamma"):
            d = tmp_path / sub
            d.mkdir()
            (d / "recipe.yml").write_text("name: stub", encoding="utf-8")
        found = discover_recipes(tmp_path)
        assert len(found) == 3

    def test_ignores_non_recipe_files(self, tmp_path: Path) -> None:
        (tmp_path / "notes.yml").write_text("notes: true", encoding="utf-8")
        (tmp_path / "recipe.yml").write_text("name: real", encoding="utf-8")
        found = discover_recipes(tmp_path)
        assert len(found) == 1

    def test_empty_directory_returns_empty(self, tmp_path: Path) -> None:
        found = discover_recipes(tmp_path)
        assert found == []

    def test_nested_recipe_found(self, tmp_path: Path) -> None:
        nested = tmp_path / "deep" / "nested" / "dir"
        nested.mkdir(parents=True)
        (nested / "recipe.yml").write_text("name: deep", encoding="utf-8")
        found = discover_recipes(tmp_path)
        assert len(found) == 1
        assert "deep" in str(found[0])
