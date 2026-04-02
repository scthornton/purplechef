from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel

EmulationMethod = Literal["caldera", "atomic", "manual"]


class CalderaAbilitySpec(BaseModel):
    technique_id: str
    ability_id: str = "auto"
    description: Optional[str] = None


class CalderaAttackSpec(BaseModel):
    adversary_name: str
    abilities: list[CalderaAbilitySpec]
    group: str
    timeout: int = 300


class AtomicAttackSpec(BaseModel):
    technique_id: str
    test_numbers: list[int]


class EmulationRecord(BaseModel):
    method: EmulationMethod
    operation_id: Optional[str] = None
    techniques_attempted: list[str] = []
    techniques_succeeded: list[str] = []
    start_time: datetime
    end_time: Optional[datetime] = None
    status: Literal["pending", "running", "completed", "failed", "dry_run"]
