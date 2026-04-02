from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, computed_field


class MitreTechnique(BaseModel):
    model_config = {"frozen": True}

    id: str
    name: str
    tactic: str
    description: Optional[str] = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def url(self) -> str:
        base = self.id.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{base}/"


class ResolvedTechnique(BaseModel):
    technique: MitreTechnique
    caldera_ability_id: Optional[str] = None
    atomic_test_numbers: Optional[list[int]] = None
    resolution_source: Literal["caldera", "atomic", "manual"]
