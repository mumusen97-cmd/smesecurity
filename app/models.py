from datetime import datetime
from enum import Enum
from typing import Dict, List

from pydantic import AnyHttpUrl, BaseModel, Field


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    AUDITOR = "auditor"


class ScanRequest(BaseModel):
    target_url: AnyHttpUrl


class RawFinding(BaseModel):
    rule_id: str | None = None
    title: str | None = None
    severity: str | None = None
    confidence: str | None = None
    endpoint: str | None = None


class NormalizedFinding(BaseModel):
    rule_id: str
    title: str
    severity: str
    confidence: str
    endpoint: str
    score: float
    compliance_tags: List[str] = Field(default_factory=list)


class ScanRecord(BaseModel):
    scan_id: str
    target_url: str
    created_at: datetime
    findings: List[NormalizedFinding] = Field(default_factory=list)
    dropped_records: int = 0


class Report(BaseModel):
    scan_id: str
    target_url: str
    summary: Dict[str, int]
    findings: List[NormalizedFinding]
