from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.models import AuthResult, LoginOptionsRequest, RegisterOptionsRequest, Report, Role, ScanRecord, ScanRequest, WebAuthnVerificationRequest
from app.security import get_current_actor, require_role
from app.services.audit import append_audit, read_audit
from app.services.auth import authentication_options, get_profile, registration_options, verify_authentication, verify_registration
from app.services.pipeline import build_report, build_scan_record
from app.services.zap_client import ZapIntegrationError

app = FastAPI(title="SME Security Assessment Platform MVP", version="0.1.0")

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

SCANS: dict[str, ScanRecord] = {}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/auth/register/options")
def begin_registration(payload: RegisterOptionsRequest) -> dict:
    return registration_options(payload.username, payload.display_name, payload.role)


@app.post("/auth/register/verify", response_model=AuthResult)
def finish_registration(payload: WebAuthnVerificationRequest) -> AuthResult:
    try:
        result = verify_registration(payload.username, payload.credential)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    append_audit(event="passkey_registered", actor_role=result.role.value, details={"username": result.username})
    return result


@app.post("/auth/login/options")
def begin_login(payload: LoginOptionsRequest) -> dict:
    try:
        return authentication_options(payload.username)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/auth/login/verify", response_model=AuthResult)
def finish_login(payload: WebAuthnVerificationRequest) -> AuthResult:
    try:
        result = verify_authentication(payload.username, payload.credential)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    append_audit(event="passkey_login", actor_role=result.role.value, details={"username": result.username})
    return result


@app.get("/me")
def me(actor=Depends(get_current_actor)) -> dict[str, str]:
    return get_profile(actor)


@app.post("/scans", status_code=201)
def create_scan(
    payload: ScanRequest,
    engine: str = "zap",
    fallback_to_simulated: bool = True,
    actor=Depends(get_current_actor),
) -> dict[str, str | int]:
    require_role(actor, {Role.ADMIN, Role.ANALYST})

    try:
        scan = build_scan_record(
            target_url=str(payload.target_url).rstrip("/"),
            engine=engine,
            fallback_to_simulated=fallback_to_simulated,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ZapIntegrationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    SCANS[scan.scan_id] = scan

    append_audit(
        event="scan_created",
        actor_role=actor.role.value,
        details={
            "scan_id": scan.scan_id,
            "target_url": scan.target_url,
            "engine": engine,
            "fallback_to_simulated": str(fallback_to_simulated),
            "username": actor.username,
        },
    )
    return {
        "scan_id": scan.scan_id,
        "engine": scan.engine,
        "fallback_used": scan.fallback_used,
        "total_findings": len(scan.findings),
        "dropped_records": scan.dropped_records,
    }


@app.get("/scans/{scan_id}", response_model=ScanRecord)
def get_scan(scan_id: str, actor=Depends(get_current_actor)) -> ScanRecord:
    require_role(actor, {Role.ADMIN, Role.ANALYST, Role.AUDITOR})
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    append_audit(event="scan_viewed", actor_role=actor.role.value, details={"scan_id": scan_id, "username": actor.username})
    return scan


@app.get("/reports/{scan_id}", response_model=Report)
def get_report(scan_id: str, actor=Depends(get_current_actor)) -> Report:
    require_role(actor, {Role.ADMIN, Role.AUDITOR})
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report = build_report(scan)
    append_audit(event="report_downloaded", actor_role=actor.role.value, details={"scan_id": scan_id, "username": actor.username})
    return report


@app.get("/audit")
def get_audit(actor=Depends(get_current_actor)) -> list[dict]:
    require_role(actor, {Role.ADMIN})
    logs = read_audit()
    append_audit(event="audit_viewed", actor_role=actor.role.value, details={"entries": str(len(logs)), "username": actor.username})
    return logs
