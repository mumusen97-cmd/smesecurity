import os
import time
from typing import Any

import httpx

from app.models import RawFinding


class ZapIntegrationError(Exception):
    pass


#read zap url from env so we can change port without editing code
def _zap_base_url() -> str:
    return os.getenv("ZAP_BASE_URL", "http://127.0.0.1:8080").rstrip("/")


def _zap_api_key() -> str:
    return os.getenv("ZAP_API_KEY", "")


def _client_timeout() -> float:
    return float(os.getenv("ZAP_TIMEOUT_SECONDS", "120"))


def _request(client: httpx.Client, path: str, params: dict[str, Any]) -> dict[str, Any]:
    base = _zap_base_url()
    merged = dict(params)
    api_key = _zap_api_key()
    if api_key:
        merged["apikey"] = api_key

    response = client.get(f"{base}{path}", params=merged)
    response.raise_for_status()
    return response.json()


#kicks off a scan phase and polls until it hits 100 percent or times out
def _poll_status(
    client: httpx.Client,
    start_path: str,
    status_path: str,
    start_key: str,
    status_key: str,
    target_url: str,
    timeout_seconds: float,
) -> None:
    start = _request(client, start_path, {"url": target_url})
    scan_id = str(start.get(start_key, ""))
    if not scan_id:
        raise ZapIntegrationError(f"ZAP did not return a valid {start_key}")

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        state = _request(client, status_path, {"scanId": scan_id}).get(status_key)
        if state == "100":
            return
        time.sleep(1)

    raise ZapIntegrationError(f"ZAP scan timed out for target: {target_url}")


#runs a full zap scan - spider first then active scan then fetch alerts
def run_zap_scan(target_url: str) -> list[RawFinding]:
    timeout_seconds = _client_timeout()
    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            #spider crawls links first
            _poll_status(
                client=client,
                start_path="/JSON/spider/action/scan/",
                status_path="/JSON/spider/view/status/",
                start_key="scan",
                status_key="status",
                target_url=target_url,
                timeout_seconds=timeout_seconds,
            )

            #active scan actually tests the vulnerabilities
            _poll_status(
                client=client,
                start_path="/JSON/ascan/action/scan/",
                status_path="/JSON/ascan/view/status/",
                start_key="scan",
                status_key="status",
                target_url=target_url,
                timeout_seconds=timeout_seconds,
            )

            #pull all alerts zap found and convert to our model
            alerts = _request(
                client,
                "/JSON/core/view/alerts/",
                {
                    "baseurl": target_url,
                    "start": 0,
                    "count": 500,
                },
            ).get("alerts", [])

        findings: list[RawFinding] = []
        for alert in alerts:
            findings.append(
                RawFinding(
                    rule_id=alert.get("pluginId"),
                    title=alert.get("name"),
                    severity=alert.get("risk"),
                    confidence=alert.get("confidence"),
                    endpoint=alert.get("url"),
                )
            )
        return findings

    except (httpx.HTTPError, ValueError) as exc:
        raise ZapIntegrationError(f"Unable to execute ZAP scan: {exc}") from exc
