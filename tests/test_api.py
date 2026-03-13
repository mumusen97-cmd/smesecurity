from fastapi.testclient import TestClient

from app.main import app
from app.models import RawFinding, Role
from app.services.auth import issue_access_token

client = TestClient(app)


def auth_headers(role: Role, username: str = "tester") -> dict[str, str]:
    token = issue_access_token(username, role)
    return {"Authorization": f"Bearer {token}"}


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_create_scan_success() -> None:
    response = client.post(
        "/scans?engine=simulated",
        json={"target_url": "https://example.com"},
        headers=auth_headers(Role.ANALYST),
    )
    assert response.status_code == 201
    data = response.json()
    assert data["total_findings"] == 3
    assert data["dropped_records"] == 0
    assert data["engine"] == "simulated"


def test_create_scan_invalid_url() -> None:
    response = client.post(
        "/scans?engine=simulated",
        json={"target_url": "not-a-valid-url"},
        headers=auth_headers(Role.ANALYST),
    )
    assert response.status_code == 422


def test_create_scan_forbidden_role() -> None:
    response = client.post(
        "/scans?engine=simulated",
        json={"target_url": "https://example.com"},
        headers=auth_headers(Role.AUDITOR),
    )
    assert response.status_code == 403


def test_incomplete_data_is_dropped() -> None:
    response = client.post(
        "/scans?engine=simulated",
        json={"target_url": "https://incomplete.example.com"},
        headers=auth_headers(Role.ADMIN),
    )
    assert response.status_code == 201
    data = response.json()
    assert data["dropped_records"] == 1


def test_report_access_for_auditor() -> None:
    created = client.post(
        "/scans?engine=simulated",
        json={"target_url": "https://example.com"},
        headers=auth_headers(Role.ADMIN),
    )
    scan_id = created.json()["scan_id"]

    report = client.get(f"/reports/{scan_id}", headers=auth_headers(Role.AUDITOR))
    assert report.status_code == 200
    assert report.json()["summary"]["total_findings"] == 3
    assert report.json()["summary"]["highest_score"] > 0


def test_report_access_denied_for_analyst() -> None:
    created = client.post(
        "/scans?engine=simulated",
        json={"target_url": "https://example.com"},
        headers=auth_headers(Role.ADMIN),
    )
    scan_id = created.json()["scan_id"]

    report = client.get(f"/reports/{scan_id}", headers=auth_headers(Role.ANALYST))
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
        headers=auth_headers(Role.ADMIN),
    )
    assert response.status_code == 201
    assert response.json()["total_findings"] == 1


def test_me_requires_valid_token() -> None:
    response = client.get("/me", headers=auth_headers(Role.ADMIN, username="owner1"))
    assert response.status_code == 200
    assert response.json()["username"] == "owner1"


def test_index_page_loads() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "SME Security Assessment Platform" in response.text

