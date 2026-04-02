from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .emulation import AtomicAttackSpec, CalderaAttackSpec, EmulationMethod


class RecipeMetadata(BaseModel):
    author: str
    mitre_techniques: list[str]
    mitre_tactics: list[str]
    difficulty: Literal["beginner", "intermediate", "advanced"]
    estimated_time: str
    tags: list[str] = []


class MiseEnPlace(BaseModel):
    terraform_module: str | None = None
    ansible_roles: list[str] = []
    prerequisites: dict[str, Any] = {}


class AttackSpec(BaseModel):
    method: EmulationMethod
    caldera: CalderaAttackSpec | None = None
    atomic: AtomicAttackSpec | None = None

    @model_validator(mode="after")
    def validate_spec_matches_method(self) -> AttackSpec:
        if self.method == "caldera" and self.caldera is None:
            raise ValueError("caldera spec required when method is 'caldera'")
        if self.method == "atomic" and self.atomic is None:
            raise ValueError("atomic spec required when method is 'atomic'")
        return self


class ValidateSpec(BaseModel):
    detection_source: Literal["limacharlie", "sentinel", "manual"]
    wait_seconds: int = 120
    expected_rules: list[dict[str, Any]] = []
    sigma_rules: list[dict[str, str]] = []


class ReportSpec(BaseModel):
    format: list[Literal["json", "html", "navigator"]] = ["json", "html"]
    evidence_required: bool = True


class AdviseSpec(BaseModel):
    generate_sigma: bool = True
    generate_kql: bool = False


class Recipe(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    version: str = "1.0"
    description: str
    metadata: RecipeMetadata
    mise_en_place: MiseEnPlace
    attack: AttackSpec
    validate_spec: ValidateSpec = Field(alias="validate")
    report: ReportSpec = ReportSpec()
    advise: AdviseSpec = AdviseSpec()
