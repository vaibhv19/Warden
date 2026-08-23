import hashlib
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Tuple

from warden.models.finding import Finding, Severity
from warden.scanners.base import BaseScanner
from warden.scanners.payloads import AUTH_BYPASS_HEADERS

PROTECTED_PATHS = ["/admin", "/dashboard", "/secure"]


class AuthScanner(BaseScanner):
    """Scanner module for identifying Authentication Weaknesses and Bypass vulnerabilities."""

    @property
    def name(self) -> str:
        return "Authentication Weakness Scanner"

    def _make_request(self, url: str, headers: Dict[str, str]) -> Tuple[int, str]:
        """Helper to make HTTP request with custom headers, returns (status, body)."""
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Warden/0.1.0")
            for k, v in headers.items():
                req.add_header(k, v)

            with urllib.request.urlopen(req, timeout=10) as response:
                body = response.read().decode("utf-8", errors="ignore")
                return response.status, body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            return e.code, body
        except Exception:
            return 0, ""

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        base_url = str(self.target.base_url).rstrip("/")

        for path in PROTECTED_PATHS:
            target_url = f"{base_url}{path}"

            # Scenario 1: Request with missing credentials (no auth header)
            status_no_auth, body_no_auth = self._make_request(target_url, {})

            # If the request succeeds (returns 200 OK) for a path that is universally protected (like /admin or /dashboard),
            # it indicates a potential authentication weakness.
            if path in ["/admin", "/dashboard"] and status_no_auth == 200:
                raw_id = f"{self.target.id}:auth_missing:{path}"
                fid = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:16]

                findings.append(
                    Finding(
                        id=fid,
                        target_id=self.target.id,
                        name="Authentication Bypass (Missing Authentication)",
                        severity=Severity.HIGH,
                        description=(
                            f"The protected endpoint '{path}' is accessible without authentication. "
                            f"A request with no authentication headers unexpectedly returned HTTP 200."
                        ),
                        remediation="Configure the web server or application middleware to enforce authentication checks on all protected routes.",
                        evidence=f"Endpoint: {path}\nStatus: {status_no_auth}\nResponse: {body_no_auth[:150]}",
                        metadata={
                            "tool": "Warden Auth Scanner",
                            "affected_url": target_url,
                            "path": path,
                            "scenario": "missing_credentials",
                        },
                    )
                )
                continue  # skip invalid credentials check if it's already completely unauthenticated

            # Scenario 2: Request with invalid/expired credentials (bypass headers)
            # If the endpoint returned 401/403 previously (which is secure), check if sending malformed/invalid credentials bypasses it.
            if status_no_auth in [401, 403]:
                for headers in AUTH_BYPASS_HEADERS:
                    if not headers:
                        continue  # already checked missing

                    status_invalid, body_invalid = self._make_request(
                        target_url, headers
                    )

                    if status_invalid == 200:
                        raw_id = f"{self.target.id}:auth_bypass:{path}:{list(headers.keys())[0]}"
                        fid = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:16]

                        findings.append(
                            Finding(
                                id=fid,
                                target_id=self.target.id,
                                name="Authentication Bypass (Weak Credential Validation)",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"The protected endpoint '{path}' accepted invalid/malformed credentials. "
                                    f"A request with invalid header '{headers}' unexpectedly returned HTTP 200."
                                ),
                                remediation="Ensure the authentication handler strictly validates credentials/tokens and returns 401 Unauthorized for invalid inputs.",
                                evidence=f"Endpoint: {path}\nInjected Headers: {headers}\nStatus: {status_invalid}",
                                metadata={
                                    "tool": "Warden Auth Scanner",
                                    "affected_url": target_url,
                                    "path": path,
                                    "headers": headers,
                                    "scenario": "invalid_credentials",
                                },
                            )
                        )
                        break

        return findings
