# OWASP-Aligned SME Security Assessment Platform (MVP)

This repository contains a working MVP backend for the MIS5203 project.

## Implemented Technical Work

- URL scan request validation
- OWASP-style finding normalization and deduplication
- Risk scoring engine
- GDPR and PCI-DSS compliance mapping
- JSON report generation
- Role-based access checks (`admin`, `analyst`, `auditor`)
- Audit logging for key actions
- Functional tests for success and failure scenarios

## Quick Start

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Run with Real OWASP ZAP

Start ZAP daemon (example with Docker):

```bash
docker run -u zap -p 8080:8080 -i ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080
```

Optional environment variables:

```bash
set ZAP_BASE_URL=http://127.0.0.1:8080
set ZAP_API_KEY=
set ZAP_TIMEOUT_SECONDS=120
```

Then call scan endpoint with `engine=zap`:

```bash
curl -X POST "http://127.0.0.1:8000/scans?engine=zap&fallback_to_simulated=false" -H "Content-Type: application/json" -H "X-Role: admin" -d "{\"target_url\":\"https://example.com\"}"
```

To run classroom demo mode without a running ZAP daemon, use `engine=simulated`.

## Run Tests

```bash
pytest -q
```

## API Endpoints

- `POST /scans?engine=zap|simulated&fallback_to_simulated=true|false` -> create scan (`admin`, `analyst`)
- `GET /scans/{scan_id}` -> get scan summary (`admin`, `analyst`, `auditor`)
- `GET /reports/{scan_id}` -> get report (`admin`, `auditor`)
- `GET /audit` -> read audit trail (`admin`)

