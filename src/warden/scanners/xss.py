import hashlib
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Tuple

from warden.models.finding import Finding, Severity
from warden.scanners.base import BaseScanner
from warden.scanners.payloads import XSS_PAYLOADS


class XssScanner(BaseScanner):
    """Scanner module for identifying Cross-Site Scripting (XSS) vulnerabilities."""

    @property
    def name(self) -> str:
        return "Cross-Site Scripting Scanner"

    def _make_request(self, url: str) -> Tuple[int, str]:
        """Helper to make HTTP request, returns (status, body)."""
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Warden/0.1.0")

            # Add Authorization header if credentials are provided in auth_context
            if self.target.auth_context and self.target.auth_context.credentials:
                for k, v in self.target.auth_context.credentials.items():
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
        crawled_urls: List[str] = []

        if self.zap_client:
            try:
                crawled_urls = self.zap_client.get_crawled_urls()
            except Exception:
                pass

        if not crawled_urls:
            crawled_urls = [str(self.target.base_url)]

        target_base = str(self.target.base_url).rstrip("/")

        for url in crawled_urls:
            # Security boundary: ensure we only scan in-scope URLs
            if not url.startswith(target_base):
                continue

            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)

            if not params:
                continue

            for param_name in params.keys():
                for p in XSS_PAYLOADS:
                    payload_val = p["payload"]

                    # Modify the parameter value with payload
                    modified_params = dict(params)
                    modified_params[param_name] = [payload_val]
                    new_query = urllib.parse.urlencode(modified_params, doseq=True)
                    target_url = urllib.parse.urlunparse(
                        parsed_url._replace(query=new_query)
                    )

                    status, body = self._make_request(target_url)

                    # Check if the payload is reflected raw/unescaped in the response body
                    if payload_val in body:
                        # Generate deterministic ID
                        raw_id = (
                            f"{self.target.id}:xss:{url}:{param_name}:{payload_val}"
                        )
                        fid = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:16]

                        findings.append(
                            Finding(
                                id=fid,
                                target_id=self.target.id,
                                name="Reflected Cross-Site Scripting (XSS)",
                                severity=Severity.HIGH,
                                description=(
                                    f"Vulnerability discovered via parameter '{param_name}' "
                                    f"injecting payload '{payload_val}'. The payload was reflected "
                                    f"unescaped in the server response body, potentially allowing "
                                    f"arbitrary script execution."
                                ),
                                remediation="Perform context-aware output encoding on all user inputs before rendering.",
                                evidence=f"Payload: {payload_val}\nReflection Snippet: {body[body.find(payload_val) - 50 : body.find(payload_val) + 150]}",
                                metadata={
                                    "tool": "Warden XSS Scanner",
                                    "parameter": param_name,
                                    "affected_url": url,
                                    "payload": payload_val,
                                },
                            )
                        )
                        break  # matched, move to next parameter

        return findings
