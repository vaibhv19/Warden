import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Tuple

from warden.models.finding import Finding, Severity
from warden.scanners.base import BaseScanner


class FuzzingScanner(BaseScanner):
    """Scanner module for intelligent controlled input fuzzing on authorized targets."""

    @property
    def name(self) -> str:
        return "Input Fuzzing Scanner"

    def _make_request(
        self,
        url: str,
        method: str = "POST",
        headers: Dict[str, str] = None,
        data: Any = None,
    ) -> Tuple[int, str]:
        """Helper to make HTTP requests, returns (status, body). Handles timeouts cleanly."""
        if headers is None:
            headers = {}

        try:
            req_data = None
            if data is not None:
                if isinstance(data, (dict, list)):
                    req_data = json.dumps(data).encode("utf-8")
                    if "Content-Type" not in headers:
                        headers["Content-Type"] = "application/json"
                elif isinstance(data, str):
                    req_data = data.encode("utf-8")
                else:
                    req_data = data

            req = urllib.request.Request(url, data=req_data, method=method)
            req.add_header("User-Agent", "Warden/0.1.0")
            req.add_header("Connection", "close")

            # Add authentication headers if context exists
            if self.target.auth_context and self.target.auth_context.credentials:
                for k, v in self.target.auth_context.credentials.items():
                    req.add_header(k, v)

            # Using a short timeout (5 seconds) so we can detect Denial of Service/blocking anomalies
            with urllib.request.urlopen(req, timeout=5) as response:
                body = response.read().decode("utf-8", errors="ignore")
                return response.status, body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            return e.code, body
        except urllib.error.URLError as e:
            # Check for timeout or socket error
            reason = str(e.reason).lower()
            if "timed out" in reason or "timeout" in reason:
                return -1, "Connection Timed Out"
            return -2, f"Connection Failed: {e.reason}"
        except Exception as e:
            return 0, str(e)

    def _generate_fuzz_payloads(self, param_type: str) -> List[Tuple[str, Any]]:
        """Generates bounded and reproducible fuzz cases.

        Returns:
            List[Tuple[case_name, payload_value]]
        """
        cases = []
        if param_type == "string":
            cases.extend(
                [
                    ("oversized", "A" * 10000),  # Safely bounded oversized input
                    ("unexpected_type_int", 99999),  # Send integer instead of string
                    ("unexpected_type_bool", True),  # Send boolean
                    ("unexpected_type_dict", {"k": "v"}),  # Send dict
                    ("boundary_empty", ""),  # Empty string
                    ("boundary_special", "'\"\\//%;()&"),  # Special character injection
                ]
            )
        elif param_type == "int":
            cases.extend(
                [
                    ("oversized", 999999999999999999),  # Oversized integer
                    ("unexpected_type_string", "not_an_int"),  # String type mismatch
                    ("unexpected_type_bool", False),  # Boolean type mismatch
                    ("unexpected_type_list", [1, 2, 3]),  # List type mismatch
                    ("boundary_negative", -1),  # Negative boundary
                    ("boundary_zero", 0),  # Zero boundary
                ]
            )
        return cases

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        fuzzing_targets = self.target.scan_metadata.get("fuzzing_targets", [])
        if not fuzzing_targets:
            return findings

        for target in fuzzing_targets:
            url = target.get("url")
            method = target.get("method", "POST").upper()
            parameters = target.get("parameters", {})

            if not url:
                continue

            for param_name, param_type in parameters.items():
                # Generate base template where all params have standard values
                base_payload = {}
                for k, t in parameters.items():
                    base_payload[k] = "" if t == "string" else 0

                # Generate fuzz cases for current parameter
                fuzz_cases = self._generate_fuzz_payloads(param_type)

                # Test: Malformed raw JSON payload (Invalid structure)
                # E.g. raw unparseable JSON string
                malformed_raw = '{"' + param_name + '": }'  # Syntax error JSON
                status_raw, body_raw = self._make_request(
                    url, method=method, data=malformed_raw
                )
                self._analyze_response(
                    findings,
                    url,
                    method,
                    param_name,
                    "malformed_json_syntax",
                    malformed_raw,
                    status_raw,
                    body_raw,
                )

                # Test: Missing fields (Invalid structure)
                # E.g. omit param_name entirely
                missing_field_payload = {
                    k: v for k, v in base_payload.items() if k != param_name
                }
                status_missing, body_missing = self._make_request(
                    url, method=method, data=missing_field_payload
                )
                self._analyze_response(
                    findings,
                    url,
                    method,
                    param_name,
                    "missing_required_field",
                    missing_field_payload,
                    status_missing,
                    body_missing,
                )

                # Test: Bounded fuzz payloads
                for case_name, payload_val in fuzz_cases:
                    test_payload = dict(base_payload)
                    test_payload[param_name] = payload_val

                    status, body = self._make_request(
                        url, method=method, data=test_payload
                    )

                    self._analyze_response(
                        findings,
                        url,
                        method,
                        param_name,
                        case_name,
                        test_payload,
                        status,
                        body,
                    )

        return findings

    def _analyze_response(
        self,
        findings: List[Finding],
        url: str,
        method: str,
        param_name: str,
        case_name: str,
        payload_data: Any,
        status: int,
        body: str,
    ) -> None:
        """Analyzes response and generates finding if unexpected anomaly occurs."""
        # 1. Check for crash/error status (HTTP 500)
        if status == 500:
            raw_id = f"{self.target.id}:fuzz_anomaly_500:{url}:{param_name}:{case_name}"
            fid = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:16]

            findings.append(
                Finding(
                    id=fid,
                    target_id=self.target.id,
                    name="Input Fuzzing Anomaly (Unhandled Exception)",
                    severity=Severity.HIGH,
                    description=(
                        f"Fuzzing parameter '{param_name}' with case '{case_name}' triggered an unhandled exception "
                        f"(HTTP 500 Server Error) at '{method} {url}'."
                    ),
                    remediation="Implement robust input validation constraints (using schema validators or strong type enforcement) and handle exceptions gracefully to return proper client errors (HTTP 400/422).",
                    evidence=f"Method: {method}\nURL: {url}\nFuzzed Parameter: {param_name}\nCase: {case_name}\nPayload: {payload_data}\nResponse Status: 500\nResponse Body Snippet: {body[:300]}",
                    metadata={
                        "tool": "Warden Fuzzing Scanner",
                        "affected_url": url,
                        "parameter": param_name,
                        "case_name": case_name,
                        "payload": str(payload_data),
                        "status_code": status,
                    },
                )
            )

        # 2. Check for Denial of Service / Connection Timeout (-1)
        elif status == -1:
            raw_id = (
                f"{self.target.id}:fuzz_anomaly_timeout:{url}:{param_name}:{case_name}"
            )
            fid = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:16]

            findings.append(
                Finding(
                    id=fid,
                    target_id=self.target.id,
                    name="Input Fuzzing Anomaly (Potential Denial of Service)",
                    severity=Severity.HIGH,
                    description=(
                        f"Fuzzing parameter '{param_name}' with case '{case_name}' caused the server to hang or time out "
                        f"at '{method} {url}', indicating a potential resource exhaustion or infinite loop vulnerability."
                    ),
                    remediation="Optimize resource management, implement execution timeouts, and limit maximum request payload sizes in the web server/gateway.",
                    evidence=f"Method: {method}\nURL: {url}\nFuzzed Parameter: {param_name}\nCase: {case_name}\nPayload: {payload_data}\nReason: Connection Timed Out",
                    metadata={
                        "tool": "Warden Fuzzing Scanner",
                        "affected_url": url,
                        "parameter": param_name,
                        "case_name": case_name,
                        "payload": str(payload_data),
                        "status_code": status,
                    },
                )
            )
