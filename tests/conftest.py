"""Shared pytest fixtures for SEC598 Chef test suite."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from chef_pantry.models.technique import MitreTechnique


@pytest.fixture()
def sample_technique() -> MitreTechnique:
    """A canonical MitreTechnique for reuse across tests."""
    return MitreTechnique(
        id="T1003.001",
        name="LSASS Memory",
        tactic="credential-access",
        description="Dump credentials from LSASS process memory.",
    )


@pytest.fixture()
def sample_technique_no_sub() -> MitreTechnique:
    """A top-level technique without a sub-technique."""
    return MitreTechnique(
        id="T1018",
        name="Remote System Discovery",
        tactic="discovery",
    )


@pytest.fixture()
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture()
def sample_recipe_dict() -> dict:
    """Minimal valid recipe dict that passes Recipe.model_validate."""
    return {
        "name": "cred-dump-test",
        "version": "1.0",
        "description": "Validate credential dumping detection coverage.",
        "metadata": {
            "author": "scott",
            "mitre_techniques": ["T1003.001"],
            "mitre_tactics": ["credential-access"],
            "difficulty": "intermediate",
            "estimated_time": "15m",
            "tags": ["credentials", "lsass"],
        },
        "mise_en_place": {
            "terraform_module": None,
            "ansible_roles": [],
            "prerequisites": {},
        },
        "attack": {
            "method": "caldera",
            "caldera": {
                "adversary_name": "cred-dumper",
                "abilities": [
                    {"technique_id": "T1003.001", "ability_id": "auto"},
                ],
                "group": "sec598-lab",
                "timeout": 300,
            },
        },
        "validate": {
            "detection_source": "limacharlie",
            "wait_seconds": 120,
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


@pytest.fixture()
def tmp_recipe_dir(tmp_path: Path, sample_recipe_dict: dict) -> Path:
    """Create a temp directory with a valid recipe.yml file."""
    import yaml

    recipe_dir = tmp_path / "recipes" / "cred-dump"
    recipe_dir.mkdir(parents=True)
    recipe_file = recipe_dir / "recipe.yml"
    recipe_file.write_text(yaml.dump(sample_recipe_dict), encoding="utf-8")
    return tmp_path
