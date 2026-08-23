# Warden — Security & Vulnerability Testing Suite

Warden is a controlled-environment security testing suite designed to automate vulnerability scanning, broken access-control verification, and input fuzzing against authorized targets.

> [!WARNING]
> **Safety Boundary & Authorized Testing Only**
> Warden must only be executed against systems and target environments that you own or have explicit, documented authorization to test. Unauthorized security testing is illegal. Mass scanning and arbitrary discovery are strictly disabled.

---

## Current Project Status
- **Phase 1: Project Foundation & Architecture (COMPLETE)**
- **Phase 2: Target & Scan Infrastructure (COMPLETE)**
  - Implemented syntactic URL checks, network pings, and target reachability check logic.
  - Implemented custom REST integration wrapper for ZAP API connectivity.
  - Developed full ScanOrchestrator to initiate scans, track status, and monitor progress.
  - Developed conversion interface mapping raw ZAP alerts into Warden Finding models.
  - Integrated scan command execution into the Warden CLI.
- **Phase 3: Automated Vulnerability Scanning (COMPLETE)**
  - Implemented evidence-based SQL Injection scanner (Error-based, Time-based, and Boolean-based).
  - Implemented Cross-Site Scripting (XSS) scanner checking for raw unescaped reflection.
  - Implemented Authentication Weakness scanner checking for unprotected endpoints and bypass headers.
- **Phase 4: Broken Access Control Testing (COMPLETE)**
  - Introduced User A/User B test model with separate authenticated contexts.
  - Implemented checks for cross-user read/write access and IDOR-style resource identifier manipulation.
  - Verified successful access control enforcement without false positives.
- **Phase 5: Intelligent Input Fuzzing (COMPLETE)**
  - Implemented parameter-based fuzzing engine for strings and integers.
  - Supported malformed JSON, missing fields, type mismatches, and oversized inputs.
  - Identified unhandled server crashes (HTTP 500) and timeouts as anomalies.
- **Phase 6: Security Findings & Reporting Engine (COMPLETE)**
  - Implemented a unified `ReportEngine` with finding aggregation, severity categorization, and metadata mapping.
  - Developed signature-based deduplication (grouping by name, URL, and parameter).
  - Supported exporting structured JSON and human-readable Markdown security reports.
- **Phase 7: End-to-End Integration & Test Coverage (COMPLETE)**
  - Developed a comprehensive end-to-end integration test (`test_e2e.py`) validating the full multi-scanner security testing pipeline.
  - Resolved global mutable state pollution across the mock application.
  - Validated and configured the Docker Compose infrastructure setup.

---

## Technology Stack
- **Core:** Python 3.12+ (Pydantic, Click, python-dotenv)
- **Quality & Style:** Ruff, Pytest
- **Infrastructure:** Docker, Docker Compose
- **Target Integration:** OWASP ZAP Daemon

---

## Repository Structure
```text
warden/
├── src/
│   └── warden/
│       ├── __init__.py          # Package initializer
│       ├── main.py              # CLI Entry point & scan commands
│       ├── config.py            # Settings manager
│       ├── target_validator.py  # Target reachability & health checks
│       ├── models/
│       │   ├── __init__.py
│       │   ├── target.py        # Target model & safety validation
│       │   └── finding.py       # Finding domain model
│       ├── scanners/
│       │   ├── __init__.py
│       │   ├── base.py          # Abstract Base Scanner interface
│       │   └── zap_client.py    # Custom OWASP ZAP API Client
│       ├── orchestration/
│       │   └── __init__.py      # Scan Orchestrator lifecycle manager
│       └── reporting/
│           └── __init__.py      # Findings Normalizer (ZAP -> Warden)
├── tests/                       # Unit & Integration Tests
├── Dockerfile                   # Warden container config
├── docker-compose.yml           # Multi-container orchestration (Warden + ZAP)
├── pyproject.toml               # Python package metadata and tool configs
├── requirements.txt             # Production dependencies
└── requirements-dev.txt         # Development & testing dependencies
```

---

## Prerequisites
- Python 3.12+
- Docker and Docker Compose v2+

---

## Environment Setup & Configuration

1. **Clone the Repository**
2. **Set up Environment File**
   Warden loads configurations from environment variables. A local template `.env.example` is provided:
   ```bash
   cp .env.example .env
   ```
   Modify `.env` as needed:
   - `WARDEN_ENV`: Run mode (`dev`, `test`, `prod`).
   - `ZAP_BASE_URL`: Base address of the ZAP API.
   - `TIMEOUT_SECONDS`: Global network request timeout.
   - `SCAN_TIMEOUT_SECONDS`: Max time to wait for a spider scan (default: 300).
   - `POLL_INTERVAL_SECONDS`: Interval for polling scan status (default: 2).
   - `OUTPUT_DIR`: Path to write report output.

3. **Install Dependencies**
   It is recommended to run in a virtual environment:
   ```bash
   python -m venv .venv
   # On Windows:
   .venv\Scripts\activate
   # On Unix/macOS:
   source .venv/bin/activate

   pip install -r requirements-dev.txt
   pip install -e .
   ```

---

## How to Run

### Command Line Interface (CLI)

Run settings preview:
```bash
python -m warden.main show-config
# or via entry point
warden show-config
```

Validate target authorization and syntax:
```bash
# Validating an authorized target (Succeeds)
warden validate-target --id "t1" --name "Local Phoenix Test" --url "http://localhost:4000" --authorized

# Validating an unauthorized target (Fails)
warden validate-target --id "t2" --name "External Site" --url "http://example.com"
```

Execute a baseline scan against an authorized target (requires ZAP running):
```bash
# Running baseline scan and saving results
warden scan --id "t-e2e" --name "Local Target" --url "http://localhost:8080/" --authorized
```

### Running Tests
Execute the automated test suite with pytest:
```bash
pytest -v
```

Run static analysis, checks, and formatting:
```bash
ruff check .
ruff format --check .
```

---

## Docker & Container Usage

Warden utilizes Docker Compose to run both the scanning environment and its dependencies (such as OWASP ZAP) in a standardized container network.

### Build Container
Build the Warden container image:
```bash
docker compose build
```

### Validate Docker Compose Configuration
```bash
docker compose config
```

### Run Services
Start the services in the background:
```bash
docker compose up -d
```
This launches the Warden service and an OWASP ZAP stable container running in daemon mode, connected via a private network.

---

## Current Limitations
- **Final Quality Audit:** A final portfolio readiness and code quality audit are scheduled for Phase 8.

