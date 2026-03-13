from collections import Counter
from datetime import datetime, timezone
from uuid import uuid4

from app.models import NormalizedFinding, RawFinding, Report, ScanRecord
from app.services.compliance import apply_compliance_tags
from app.services.scoring import calculate_score, classify_risk_band
from app.services.zap_client import ZapIntegrationError, run_zap_scan


#normalise zap severity strings to our internal vocabulary
SEVERITY_NORMALIZATION = {
    "info": "LOW",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}

CONFIDENCE_NORMALIZATION = {
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "confirmed": "HIGH",
    "user confirmed": "HIGH",
}


def simulate_zap_findings(target_url: str) -> list[RawFinding]:
    # This simulates scanner output so the MVP can run end-to-end in class demos.
    base = [
        RawFinding(
            rule_id="1001",
            title="SQL Injection",
            severity="high",
            confidence="high",
            endpoint=f"{target_url}/login",
        ),
        RawFinding(
            rule_id="1002",
            title="Cross-Site Scripting",
            severity="medium",
            confidence="medium",
            endpoint=f"{target_url}/search",
        ),
        RawFinding(
            rule_id="1002",
            title="Cross-Site Scripting",
            severity="medium",
            confidence="medium",
            endpoint=f"{target_url}/search",
        ),
        RawFinding(
            rule_id="1003",
            title="Security Misconfiguration",
            severity="low",
            confidence="high",
            endpoint=f"{target_url}/admin",
        ),
    ]

    if "incomplete" in target_url:
        base.append(
            RawFinding(
                rule_id=None,
                title="SQL Injection",
                severity="high",
                confidence="high",
                endpoint=f"{target_url}/bad",
            )
        )
    return base


#cleans the raw findings - drops incomplete ones and removes duplicates
def normalize_and_dedupe(raw_findings: list[RawFinding]) -> tuple[list[NormalizedFinding], int]:
    normalized: list[NormalizedFinding] = []
    dropped = 0
    seen_keys = set()

    for f in raw_findings:
        #skip and count anything that is missing required fields
        mandatory = [f.rule_id, f.title, f.severity, f.confidence, f.endpoint]
        if any(item is None for item in mandatory):
            dropped += 1
            continue

        severity = SEVERITY_NORMALIZATION.get(f.severity.strip().lower(), "LOW")
        confidence = CONFIDENCE_NORMALIZATION.get(f.confidence.strip().lower(), "MEDIUM")
        #same rule at same url seen before means its a duplicate
        dedupe_key = (f.rule_id, f.endpoint)
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)

        score = calculate_score(severity, confidence)
        finding = NormalizedFinding(
            rule_id=f.rule_id,
            title=f.title,
            severity=severity,
            confidence=confidence,
            endpoint=f.endpoint,
            score=score,
            risk_band=classify_risk_band(score),
        )
        normalized.append(apply_compliance_tags(finding))

    return normalized, dropped


def fetch_zap_findings(target_url: str) -> list[RawFinding]:
    return run_zap_scan(target_url)


#main entry point - picks the engine, runs the scan, builds the record
def build_scan_record(target_url: str, engine: str = "zap", fallback_to_simulated: bool = True) -> ScanRecord:
    selected = engine.strip().lower()
    if selected not in {"zap", "simulated"}:
        raise ValueError("engine must be 'zap' or 'simulated'")

    fallback_used = False
    if selected == "simulated":
        raw = simulate_zap_findings(target_url)
    else:
        try:
            raw = fetch_zap_findings(target_url)
        except ZapIntegrationError:
            if not fallback_to_simulated:
                raise
            #zap not reachable so fall back to demo data
            raw = simulate_zap_findings(target_url)
            fallback_used = True

    findings, dropped = normalize_and_dedupe(raw)
    return ScanRecord(
        scan_id=str(uuid4()),
        target_url=target_url,
        created_at=datetime.now(timezone.utc),
        engine=selected,
        fallback_used=fallback_used,
        findings=findings,
        dropped_records=dropped,
    )


#builds the final report with summary stats from the scan findings
def build_report(scan: ScanRecord) -> Report:
    severity_summary = Counter(f.severity for f in scan.findings)
    scores = [f.score for f in scan.findings]
    summary = {
        "total_findings": len(scan.findings),
        "dropped_records": scan.dropped_records,
        "LOW": severity_summary.get("LOW", 0),
        "MEDIUM": severity_summary.get("MEDIUM", 0),
        "HIGH": severity_summary.get("HIGH", 0),
        "CRITICAL": severity_summary.get("CRITICAL", 0),
        "average_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
        "highest_score": max(scores) if scores else 0.0,
    }
    return Report(
        scan_id=scan.scan_id,
        target_url=scan.target_url,
        summary=summary,
        findings=scan.findings,
    )
