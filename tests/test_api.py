from fastapi.testclient import TestClient

from app.main import app
from app.models import RawFinding

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_create_scan_success() -> None:
    response = client.post(
        "/scans?engine=simulated",
        json={"target_url": "https://example.com"},
        headers={"X-Role": "analyst"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["total_findings"] == 3
    assert data["dropped_records"] == 0


def test_create_scan_invalid_url() -> None:
    response = client.post(
        "/scans?engine=simulated",
        json={"target_url": "not-a-valid-url"},
        headers={"X-Role": "analyst"},
    )
    assert response.status_code == 422


def test_create_scan_forbidden_role() -> None:
    response = client.post(
        "/scans?engine=simulated",
        json={"target_url": "https://example.com"},
        headers={"X-Role": "auditor"},
    )
    assert response.status_code == 403


def test_incomplete_data_is_dropped() -> None:
    response = client.post(
        "/scans?engine=simulated",
        json={"target_url": "https://incomplete.example.com"},
        headers={"X-Role": "admin"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["dropped_records"] == 1


def test_report_access_for_auditor() -> None:
    created = client.post(
        "/scans?engine=simulated",
        json={"target_url": "https://example.com"},
        headers={"X-Role": "admin"},
    )
    scan_id = created.json()["scan_id"]

    report = client.get(f"/reports/{scan_id}", headers={"X-Role": "auditor"})
    assert report.status_code == 200
    assert report.json()["summary"]["total_findings"] == 3


def test_report_access_denied_for_analyst() -> None:
    created = client.post(
        "/scans?engine=simulated",
        json={"target_url": "https://example.com"},
        headers={"X-Role": "admin"},
    )
    scan_id = created.json()["scan_id"]

    report = client.get(f"/reports/{scan_id}", headers={"X-Role": "analyst"})
    assert report.status_code == 403


def test_create_scan_using_real_zap_engine_with_mock(monkeypatch) -> None:
    def fake_fetch(_target_url: str) -> list[RawFinding]:
        return [
            RawFinding(
                rule_id="40012",
                title="Cross-Site Scripting",
                severity="high",
                confidence="confirmed",
                endpoint="https://example.com/search",
            )
        ]

    monkeypatch.setattr("app.services.pipeline.fetch_zap_findings", fake_fetch)

    response = client.post(
        "/scans?engine=zap&fallback_to_simulated=false",
        json={"target_url": "https://example.com"},
        headers={"X-Role": "admin"},
    )
    assert response.status_code == 201
    assert response.json()["total_findings"] == 1

