import hashlib
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Tuple

from warden.models.finding import Finding, Severity
from warden.scanners.base import BaseScanner
from warden.scanners.payloads import SQLI_PAYLOADS

# Common SQL error signatures
SQL_ERROR_SIGNATURES = [
    "sqlite3.operationalerror",
    "sql syntax error",
    "mysql_fetch_array",
    "pg::syntaxerror",
    "postgresql query failed",
    "unclosed quotation mark",
    'near "\'": syntax error',
]


class SqlInjectionScanner(BaseScanner):
    """Scanner module for identifying SQL Injection vulnerabilities."""

    @property
    def name(self) -> str:
        return "SQL Injection Scanner"

    def _make_request(self, url: str) -> Tuple[int, str, float]:
        """Helper to make HTTP request, returns (status, body, duration)."""
        start = time.time()
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Warden/0.1.0")

            # Add Authorization header if credentials are provided in auth_context
            if self.target.auth_context and self.target.auth_context.credentials:
                for k, v in self.target.auth_context.credentials.items():
                    req.add_header(k, v)

            with urllib.request.urlopen(req, timeout=10) as response:
                body = response.read().decode("utf-8", errors="ignore")
                duration = time.time() - start
                return response.status, body, duration
        except urllib.error.HTTPError as e:
            # Error responses (like HTTP 500) can carry SQL syntax error messages
            body = e.read().decode("utf-8", errors="ignore")
            duration = time.time() - start
            return e.code, body, duration
        except Exception:
            return 0, "", 0.0

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
                for p in SQLI_PAYLOADS:
                    payload_type = p["type"]
                    payload_val = p["payload"]

                    # Modify the parameter value with payload
                    modified_params = dict(params)
                    modified_params[param_name] = [payload_val]
                    new_query = urllib.parse.urlencode(modified_params, doseq=True)
                    target_url = urllib.parse.urlunparse(
                        parsed_url._replace(query=new_query)
                    )

                    status, body, duration = self._make_request(target_url)

                    # 1. Error-based SQLi Check
                    if payload_type == "error":
                        body_lower = body.lower()
                        for sig in SQL_ERROR_SIGNATURES:
                            if sig in body_lower:
                                raw_id = (
                                    f"{self.target.id}:sqli_error:{url}:{param_name}"
                                )
                                fid = hashlib.sha256(
                                    raw_id.encode("utf-8")
                                ).hexdigest()[:16]
                                findings.append(
                                    Finding(
                                        id=fid,
                                        target_id=self.target.id,
                                        name="SQL Injection (Error-Based)",
                                        severity=Severity.HIGH,
                                        description=(
                                            f"Vulnerability discovered via parameter '{param_name}' "
                                            f"injecting error payload '{payload_val}'. The response contained "
                                            f"a known database error signature: '{sig}'."
                                        ),
                                        remediation="Sanitize all inputs and use parameterized SQL queries / ORMs.",
                                        evidence=f"Payload: {payload_val}\nMatched Signature: {sig}\nResponse Snippet: {body[:300]}",
                                        metadata={
                                            "tool": "Warden SQLi Scanner",
                                            "parameter": param_name,
                                            "affected_url": url,
                                            "payload": payload_val,
                                            "signature": sig,
                                        },
                                    )
                                )
                                break  # matched, move to next parameter/payload

                    # 2. Time-based SQLi Check
                    elif payload_type == "time":
                        # If query takes more than 4.5 seconds (delay default is 5 seconds), it's highly indicative of time-based SQLi
                        if duration >= 4.5:
                            raw_id = f"{self.target.id}:sqli_time:{url}:{param_name}"
                            fid = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[
                                :16
                            ]
                            findings.append(
                                Finding(
                                    id=fid,
                                    target_id=self.target.id,
                                    name="SQL Injection (Time-Based)",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"Time-based SQL injection detected on parameter '{param_name}' "
                                        f"using sleep payload. Request took {duration:.2f} seconds."
                                    ),
                                    remediation="Use parameterized queries and restrict database user privileges.",
                                    evidence=f"Payload: {payload_val}\nDuration: {duration:.2f}s",
                                    metadata={
                                        "tool": "Warden SQLi Scanner",
                                        "parameter": param_name,
                                        "affected_url": url,
                                        "payload": payload_val,
                                        "duration_seconds": duration,
                                    },
                                )
                            )

                    # 3. Boolean-based SQLi Check
                    elif payload_type == "boolean_true":
                        # Fetch true and false variants to compare length
                        # Find matching false payload
                        false_p = next(
                            (x for x in SQLI_PAYLOADS if x["type"] == "boolean_false"),
                            None,
                        )
                        if false_p:
                            false_params = dict(params)
                            false_params[param_name] = [false_p["payload"]]
                            false_query = urllib.parse.urlencode(
                                false_params, doseq=True
                            )
                            false_url = urllib.parse.urlunparse(
                                parsed_url._replace(query=false_query)
                            )

                            _, false_body, _ = self._make_request(false_url)

                            # Compare response sizes
                            true_len = len(body)
                            false_len = len(false_body)
                            if (
                                false_len > 0
                                and abs(true_len - false_len) / max(true_len, false_len)
                                > 0.3
                            ):
                                raw_id = (
                                    f"{self.target.id}:sqli_boolean:{url}:{param_name}"
                                )
                                fid = hashlib.sha256(
                                    raw_id.encode("utf-8")
                                ).hexdigest()[:16]
                                findings.append(
                                    Finding(
                                        id=fid,
                                        target_id=self.target.id,
                                        name="SQL Injection (Boolean-Based)",
                                        severity=Severity.MEDIUM,
                                        description=(
                                            f"Boolean-based SQL injection suspected on parameter '{param_name}'. "
                                            f"True response length ({true_len}) and False response length ({false_len}) "
                                            f"differ significantly."
                                        ),
                                        remediation="Ensure input validation and parameterize all SQL queries.",
                                        evidence=f"True Length: {true_len}, False Length: {false_len}",
                                        metadata={
                                            "tool": "Warden SQLi Scanner",
                                            "parameter": param_name,
                                            "affected_url": url,
                                            "true_payload": payload_val,
                                            "false_payload": false_p["payload"],
                                        },
                                    )
                                )

        return findings
