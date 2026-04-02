from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

from .technique import MitreTechnique


class DetectionMatch(BaseModel):
    rule_name: str
    source: Literal["limacharlie", "sentinel", "splunk", "manual"]
    timestamp: datetime
    alert_id: str
    tags: list[str] = []
    confidence: float = Field(ge=0.0, le=1.0)


class EvidenceChain(BaseModel):
    technique: MitreTechnique
    emulation_id: str
    execution_start: datetime
    execution_end: datetime
    detection_window_start: datetime
    detection_window_end: datetime
    detections: list[DetectionMatch] = []
    status: Literal["detected", "missed", "partial", "error"]
    notes: Optional[str] = None

    @property
    def is_detected(self) -> bool:
        return self.status == "detected"

    @property
    def detection_count(self) -> int:
        return len(self.detections)


class CoverageResult(BaseModel):
    recipe_name: str
    run_id: str
    timestamp: datetime
    evidence_chains: list[EvidenceChain] = []

    @property
    def total_count(self) -> int:
        return len(self.evidence_chains)

    @property
    def detected_count(self) -> int:
        return sum(1 for c in self.evidence_chains if c.is_detected)

    @property
    def missed_count(self) -> int:
        return sum(1 for c in self.evidence_chains if c.status == "missed")

    @property
    def coverage_percentage(self) -> float:
        if self.total_count == 0:
            return 0.0
        return (self.detected_count / self.total_count) * 100.0
