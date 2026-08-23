# Warden — Security & Vulnerability Testing Suite

Warden is a controlled-environment security testing suite designed to automate vulnerability scanning, broken access-control verification, and input fuzzing against authorized targets.

> [!WARNING]
> **Safety Boundary & Authorized Testing Only**
> Warden must only be executed against systems and target environments that you own or have explicit, documented authorization to test. Unauthorized security testing is illegal. Mass scanning and arbitrary discovery are strictly disabled.

---

## Current Project Status
- **Phase 1: Project Foundation & Architecture (COMPLETE)**
  - Repository foundation, package layout, and dependency configurations are established.
  - Safe configuration and target authorization models are validated.
  - Test suites are configured and executing correctly.
  - Containerization foundation via Docker and Docker Compose is established.

---

## Technology Stack
- **Core:** Python 3.12+ (Pydantic, Click, python-dotenv)
- **Quality & Style:** Ruff, Pytest
- **Infrastructure:** Docker, Docker Compose
- **Target Integration (Future):** OWASP ZAP Daemon

---

## Repository Structure
```text
warden/
├── src/
│   └── warden/
│       ├── __init__.py          # Package initializer
│       ├── main.py              # CLI Entry point
│       ├── config.py            # Settings manager
│       ├── models/
│       │   ├── __init__.py
│       │   ├── target.py        # Target model & safety validation
│       │   └── finding.py       # Finding domain model placeholder
│       ├── scanners/
│       │   ├── __init__.py
│       │   └── base.py          # Abstract Base Scanner interface
│       ├── orchestration/       # Scan orchestration placeholder
│       └── reporting/           # Report generation placeholder
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
- **Scanning:** Active vulnerability scanning, SQL injection, XSS, and fuzzing actions are not implemented in Phase 1.
- **Reporting:** Structured security reports and export formats are placeholders.
