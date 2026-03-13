# OWASP-Aligned SME Security Assessment Platform (MVP)

This repository contains a working MVP backend for the MIS5203 project.

## Implemented Technical Work

- Browser-based web interface for SME owners, IT staff, and auditors
- Passwordless authentication using WebAuthn/Passkeys
- URL scan request validation
- Real OWASP ZAP API integration with optional fallback demo mode
- OWASP-style finding normalization and deduplication
- Risk scoring engine with numeric score and risk band
- GDPR and PCI-DSS compliance mapping
- JSON report generation
- Token-based role access checks (`admin`, `analyst`, `auditor`)
- Audit logging for key actions
- Functional tests for success and failure scenarios

## Quick Start

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://localhost:8000` in a browser to use the web interface.

## Passkey Setup Notes

- Open the application via `http://localhost:8000` so the default WebAuthn RP ID and origin match.
- Passkeys require a browser and device that support WebAuthn.
- For non-localhost deployment, set `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGIN` to your actual host values.

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
set WEBAUTHN_RP_ID=localhost
set WEBAUTHN_ORIGIN=http://localhost:8000
set APP_SECRET_KEY=change-this-secret-before-production
```

Then call scan endpoint with `engine=zap`:

```bash
curl -X POST "http://127.0.0.1:8000/scans?engine=zap&fallback_to_simulated=false" -H "Content-Type: application/json" -H "X-Role: admin" -d "{\"target_url\":\"https://example.com\"}"
```
To run demo mode without a running ZAP daemon, use `engine=simulated`.

## Run Tests

```bash
pytest -q
```

## API Endpoints

- `GET /` -> web dashboard
- `POST /auth/register/options` -> begin passkey registration
- `POST /auth/register/verify` -> complete passkey registration and receive token
- `POST /auth/login/options` -> begin passkey login
- `POST /auth/login/verify` -> complete passkey login and receive token
- `GET /me` -> inspect current signed-in user
- `POST /scans?engine=zap|simulated&fallback_to_simulated=true|false` -> create scan (`admin`, `analyst`)
- `GET /scans/{scan_id}` -> get scan summary (`admin`, `analyst`, `auditor`)
- `GET /reports/{scan_id}` -> get report (`admin`, `auditor`)
- `GET /audit` -> read audit trail (`admin`)
