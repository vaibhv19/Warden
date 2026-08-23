# Warden — Roadmap & Developer Integration Guide

This guide details the implementation roadmap, architectural definitions, and reproduction instructions for Warden.

---

## 1. Project Prerequisites

To build and run the Warden security suite from a clean environment, ensure you have:
- **Python 3.12+**
- **Docker and Docker Compose v2+**
- **OWASP ZAP** (stable container or local daemon)

---

## 2. Environment Setup & Installation

### Step 1: Virtual Environment Setup
Initialize a clean Python virtual environment:
```bash
python -m venv .venv

# Activate on Windows:
.venv\Scripts\activate

# Activate on Unix/macOS:
source .venv/bin/activate
```

### Step 2: Dependency Installation
Install development, testing, and production dependencies:
```bash
# Install test/development requirements (ruff, pytest, pytest-cov, pytest-mock)
pip install -r requirements-dev.txt

# Install application and production requirements
pip install -r requirements.txt

# Install Warden package in editable mode
pip install -e .
```

### Step 3: Centralized Environment Variables
Copy the env template and customize settings:
```bash
cp .env.example .env
```
Key configuration parameters:
- `WARDEN_ENV`: Environment flag (`dev`, `test`, `prod`).
- `ZAP_BASE_URL`: Base address of the ZAP API (defaults to `http://localhost:8080`).
- `TIMEOUT_SECONDS`: Global HTTP timeout limit.
- `OUTPUT_DIR`: Path where scan reports are exported (defaults to `./reports`).

---

## 3. Roadmaps & Actual Implementations

### Phase 1 — Project Foundation & Architecture
- **Goal:** Initialize domain models and project boundaries.
- **Implemented:**
  - central Settings manager in `src/warden/config.py`.
  - target context configurations (`TargetConfig`, `TargetAuthContext`) in `src/warden/models/target.py`.

### Phase 2 — Target & Scan Infrastructure
- **Goal:** Implement safety checks, reachability audits, and ZAP wrappers.
- **Implemented:**
  - reachability check with HTTP status code validation in `src/warden/target_validator.py`.
  - REST client for ZAP in `src/warden/scanners/zap_client.py`.
  - baseline spider scan orchestration workflow in `src/warden/orchestration/__init__.py`.

### Phase 3 — Automated Vulnerability Scanning
- **Goal:** Execute specialized active vulnerability scanning.
- **Implemented:**
  - SQLi Scanner (`src/warden/scanners/sqli.py`) checking for database error patterns and time delays.
  - XSS Scanner (`src/warden/scanners/xss.py`) verifying unescaped tag reflections.
  - Authentication Scanner (`src/warden/scanners/auth.py`) auditing unprotected paths on baseline crawl endpoints.

### Phase 4 — Broken Access Control Testing
- **Goal:** Implement IDOR and privilege escalation scanners.
- **Implemented:**
  - User A (Attacker) and User B (Resource Owner) double authentication context mapping.
  - Access Control Scanner (`src/warden/scanners/access_control.py`) checking cross-user read/write isolation against templates.

### Phase 5 — Intelligent Input Fuzzing
- **Goal:** Implement boundary, type-mismatch, and crash validation.
- **Implemented:**
  - parameter-based payload generator (malformed JSON, type mismatch, oversized values) in `src/warden/scanners/fuzzing.py`.
  - anomaly detection (catching server-side HTTP 500 unhandled exceptions or connection reset socket timeouts).

### Phase 6 — Security Findings & Reporting Engine
- **Goal:** Consolidate, deduplicate, and export findings.
- **Implemented:**
  - deduplication signature matching: `(name, URL, parameter)`.
  - merges duplicate findings by preserving the highest severity and aggregating evidences.
  - structured JSON and human-readable Markdown report generators in `src/warden/reporting/engine.py`.

### Phase 7 — End-to-End Integration & Test Coverage
- **Goal:** Validate the complete scan pipeline.
- **Implemented:**
  - full integration tests in `tests/test_e2e.py` using a live fuzzed target server.
  - isolation of global database mutable dictionary state between test suites.
  - verified Docker Compose networking configuration.

### Phase 8 — Final Quality Audit & Portfolio Readiness
- **Goal:** Audit code structure, typing, formatting, and Docker execution.
- **Implemented:**
  - Ruff formatting and linting.
  - Docker Compose service verification and container E2E runs.

---

## 4. Controlled Setup & Service Networking

To test Warden locally against a real target application, follow this service order:

1. **Build Container Stack:**
   ```bash
   docker compose build
   ```

2. **Start target-app and ZAP Services:**
   ```bash
   docker compose up -d zap target-app
   ```
   *Note: target-app runs on port `8000` and ZAP daemon runs on port `8080`.*

3. **Run Scan inside Container Network:**
   Because Warden runs inside the private bridge network, specify the target container service name (`target-app`) and ZAP service container name (`zap`) for ZAP communications:
   ```bash
   docker compose run --rm -e ZAP_BASE_URL=http://zap:8080 warden scan --id doc-scan --name "Target Scan" --url http://target-app:8000/ --authorized
   ```

4. **Shutdown Services:**
   ```bash
   docker compose down
   ```

---

## 5. Troubleshooting & Reproducibility Notes

- **Windows IPv6 / localhost Delay:** Local HTTP tests on Windows targeting `localhost` can trigger IPv6 DNS latency timeouts (~2 seconds per request). Integration configurations must utilize direct IP addresses (e.g. `127.0.0.1`) to enforce direct IPv4 socket bindings.
- **Socket Connection Keep-Alive:** The Python standard mock HTTP server defaults to keeping connections alive. Explicitly setting `self.close_connection = True` inside HTTP request handlers ensures connection termination and fast request cycles in automated test environments.
- **Global DB Contamination:** Pytest shares the state of modules imported. When tests execute write actions against fuzzed targets, ensure `tests.target_app.DOCUMENTS` global dictionary values are reset to defaults at the start of integration tests.
