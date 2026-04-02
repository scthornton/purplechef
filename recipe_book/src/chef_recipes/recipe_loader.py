"""Load and validate recipe YAML files into Recipe models."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from chef_pantry.errors import RecipeError, ValidationError
from chef_pantry.models.recipe import Recipe
from pydantic import ValidationError as PydanticValidationError


def load_recipe(path: Path) -> Recipe:
    """Load a recipe from a YAML file, validate, and return the model."""
    if not path.exists():
        raise RecipeError(recipe_name=str(path), detail=f"Recipe file not found: {path}")
    if path.suffix not in (".yml", ".yaml"):
        raise RecipeError(recipe_name=str(path), detail="Recipe must be a .yml or .yaml file")

    raw = path.read_text(encoding="utf-8")
    try:
        data: dict[str, Any] = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise RecipeError(recipe_name=str(path), detail=f"Invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise RecipeError(recipe_name=str(path), detail="Recipe must be a YAML mapping")

    try:
        return Recipe.model_validate(data)
    except PydanticValidationError as exc:
        errors = "; ".join(f"{e['loc']}: {e['msg']}" for e in exc.errors())
        raise ValidationError(field="recipe", detail=f"Schema validation failed: {errors}") from exc


def discover_recipes(base_dir: Path) -> list[Path]:
    """Find all recipe.yml files under a directory."""
    return sorted(base_dir.rglob("recipe.yml"))
