from datetime import datetime
from enum import Enum
from typing import Any, Dict, List

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
    risk_band: str
    compliance_tags: List[str] = Field(default_factory=list)


class ScanRecord(BaseModel):
    scan_id: str
    target_url: str
    created_at: datetime
    engine: str
    fallback_used: bool = False
    findings: List[NormalizedFinding] = Field(default_factory=list)
    dropped_records: int = 0


class Report(BaseModel):
    scan_id: str
    target_url: str
    summary: Dict[str, int | float]
    findings: List[NormalizedFinding]


class Actor(BaseModel):
    username: str
    role: Role
    auth_method: str


class CredentialRecord(BaseModel):
    credential_id: str
    public_key: str
    sign_count: int
    device_type: str | None = None
    backed_up: bool = False
    transports: List[str] = Field(default_factory=list)


class UserAccount(BaseModel):
    username: str
    display_name: str
    role: Role
    user_id: str
    credentials: List[CredentialRecord] = Field(default_factory=list)


class RegisterOptionsRequest(BaseModel):
    username: str
    display_name: str
    role: Role


class LoginOptionsRequest(BaseModel):
    username: str


class WebAuthnVerificationRequest(BaseModel):
    username: str
    credential: Dict[str, Any]


class AuthResult(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    display_name: str
    role: Role
