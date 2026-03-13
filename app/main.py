from fastapi import Depends, FastAPI, HTTPException

from app.models import Report, Role, ScanRecord, ScanRequest
from app.security import get_role, require_role
from app.services.audit import append_audit, read_audit
from app.services.pipeline import build_report, build_scan_record
from app.services.zap_client import ZapIntegrationError

app = FastAPI(title="SME Security Assessment Platform MVP", version="0.1.0")

SCANS: dict[str, ScanRecord] = {}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scans", status_code=201)
def create_scan(
    payload: ScanRequest,
    engine: str = "zap",
    fallback_to_simulated: bool = True,
    role: Role = Depends(get_role),
) -> dict[str, str | int]:
    require_role(role, {Role.ADMIN, Role.ANALYST})

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
        actor_role=role.value,
        details={
            "scan_id": scan.scan_id,
            "target_url": scan.target_url,
            "engine": engine,
            "fallback_to_simulated": str(fallback_to_simulated),
        },
    )
    return {
        "scan_id": scan.scan_id,
        "total_findings": len(scan.findings),
        "dropped_records": scan.dropped_records,
    }


@app.get("/scans/{scan_id}", response_model=ScanRecord)
def get_scan(scan_id: str, role: Role = Depends(get_role)) -> ScanRecord:
    require_role(role, {Role.ADMIN, Role.ANALYST, Role.AUDITOR})
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    append_audit(event="scan_viewed", actor_role=role.value, details={"scan_id": scan_id})
    return scan


@app.get("/reports/{scan_id}", response_model=Report)
def get_report(scan_id: str, role: Role = Depends(get_role)) -> Report:
    require_role(role, {Role.ADMIN, Role.AUDITOR})
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report = build_report(scan)
    append_audit(event="report_downloaded", actor_role=role.value, details={"scan_id": scan_id})
    return report


@app.get("/audit")
def get_audit(role: Role = Depends(get_role)) -> list[dict]:
    require_role(role, {Role.ADMIN})
    logs = read_audit()
    append_audit(event="audit_viewed", actor_role=role.value, details={"entries": str(len(logs))})
    return logs
