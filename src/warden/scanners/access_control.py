import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Tuple

from warden.models.finding import Finding, Severity
from warden.scanners.base import BaseScanner


class AccessControlScanner(BaseScanner):
    """Scanner module for identifying Broken Access Control and IDOR vulnerabilities."""

    @property
    def name(self) -> str:
        return "Broken Access Control Scanner"

    def _make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Dict[str, str] = None,
        data: Any = None,
    ) -> Tuple[int, str]:
        """Helper to make HTTP requests with specific headers, methods, and payloads."""
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

    def _get_headers(self, user_context_name: str) -> Dict[str, str]:
        """Get headers for the specified user context ('a' / attacker or 'b' / owner)."""
        headers = {}
        context = None
        if user_context_name == "a":
            context = self.target.auth_context
        elif user_context_name == "b":
            context = self.target.auth_context_b

        if context and context.credentials:
            headers.update(context.credentials)
        return headers

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        # Access control tests are expected to be configured in scan_metadata
        tests = self.target.scan_metadata.get("access_control_tests", [])
        if not tests:
            return findings

        for test in tests:
            test_name = test.get("name", "Unnamed Access Control Test")
            method = test.get("method", "GET").upper()
            url_template = test.get("url_template")
            resource_id_owner = test.get("resource_id_owner")
            action = test.get("action", "read").lower()
            owner_indicator = test.get("owner_indicator", "")

            if not url_template or not resource_id_owner:
                continue

            # Build URL for Owner's (User B) resource
            owner_url = url_template.replace("{resource_id}", str(resource_id_owner))

            headers_owner = self._get_headers("b")
            headers_attacker = self._get_headers("a")

            # 1. Verify owner can access their own resource first (Baseline)
            owner_payload = test.get("owner_payload")
            owner_status, owner_body = self._make_request(
                owner_url, method=method, headers=headers_owner, data=owner_payload
            )

            # Check if baseline request is successful.
            # If the owner cannot access their own resource, the test configuration might be invalid.
            if owner_status not in [200, 201, 204]:
                continue

            # 2. Execute cross-user access attempt using Attacker's (User A) context
            attacker_payload = test.get("attacker_payload")
            attacker_status, attacker_body = self._make_request(
                owner_url,
                method=method,
                headers=headers_attacker,
                data=attacker_payload,
            )

            # 3. Analyze result comparison based on action type
            if action == "read":
                # For read actions, unauthorized success means User A got HTTP 200/201
                # AND the response contains the private indicator of User B's resource.
                if attacker_status in [200, 201]:
                    # Verify presence of the private indicator in Attacker's response
                    if owner_indicator and owner_indicator in attacker_body:
                        raw_id = f"{self.target.id}:access_control_read:{test_name}:{owner_url}"
                        fid = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:16]

                        findings.append(
                            Finding(
                                id=fid,
                                target_id=self.target.id,
                                name="Broken Access Control (Unauthorized Read)",
                                severity=Severity.HIGH,
                                description=(
                                    f"Cross-user resource access succeeded. User A (Attacker) was able to read "
                                    f"User B's private resource via '{method} {owner_url}'."
                                ),
                                remediation="Enforce strict object-level access control checks in the backend middleware or controller, validating that the authenticated session owner matches the resource owner.",
                                evidence=f"Target URL: {owner_url}\nAttacker Status: {attacker_status}\nPrivate Data Exposed: {owner_indicator}",
                                metadata={
                                    "tool": "Warden Access Control Scanner",
                                    "test_name": test_name,
                                    "method": method,
                                    "affected_url": owner_url,
                                    "action": "read",
                                    "resource_id_owner": resource_id_owner,
                                    "attacker_status": attacker_status,
                                },
                            )
                        )

            elif action == "write":
                # For write actions, unauthorized success means User A's modification request
                # returned success status (200/201/204).
                if attacker_status in [200, 201, 204]:
                    # To be absolutely sure, verify if the modification was actually applied.
                    # We can fetch the resource again using User B's context (Owner) and check for Attacker's payload changes.
                    # Or check if User B's resource now matches the modified state.
                    verify_url = url_template.replace(
                        "{resource_id}", str(resource_id_owner)
                    )
                    verify_status, verify_body = self._make_request(
                        verify_url, method="GET", headers=headers_owner
                    )

                    attacker_indicator = test.get("attacker_indicator", "")
                    modification_confirmed = True
                    if attacker_indicator and verify_status == 200:
                        modification_confirmed = attacker_indicator in verify_body

                    if modification_confirmed:
                        raw_id = f"{self.target.id}:access_control_write:{test_name}:{owner_url}"
                        fid = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:16]

                        findings.append(
                            Finding(
                                id=fid,
                                target_id=self.target.id,
                                name="Broken Access Control (Unauthorized Write)",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"Cross-user resource modification succeeded. User A (Attacker) was able to modify "
                                    f"User B's private resource via '{method} {owner_url}'."
                                ),
                                remediation="Implement server-side ownership validation before performing any modification or deletion operations.",
                                evidence=f"Target URL: {owner_url}\nAttacker Status: {attacker_status}\nAttacker Payload: {attacker_payload}",
                                metadata={
                                    "tool": "Warden Access Control Scanner",
                                    "test_name": test_name,
                                    "method": method,
                                    "affected_url": owner_url,
                                    "action": "write",
                                    "resource_id_owner": resource_id_owner,
                                    "attacker_status": attacker_status,
                                },
                            )
                        )

        return findings
