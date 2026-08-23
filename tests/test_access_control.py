import json
import socket
import socketserver
import threading
from unittest.mock import patch

from tests.target_app import VulnerableHandler
from warden.models.target import TargetAuthContext, TargetConfig
from warden.scanners.access_control import AccessControlScanner


def test_access_control_read_vulnerable():
    # Setup Target with User A (attacker) and User B (owner)
    target = TargetConfig(
        id="t-ac-test",
        name="Access Control Test Target",
        base_url="http://example.com/",
        is_authorized=True,
        auth_context=TargetAuthContext(
            auth_type="bearer", credentials={"Authorization": "Bearer user-a-token"}
        ),
        auth_context_b=TargetAuthContext(
            auth_type="bearer", credentials={"Authorization": "Bearer user-b-token"}
        ),
        scan_metadata={
            "access_control_tests": [
                {
                    "name": "Vulnerable Read Document",
                    "method": "GET",
                    "url_template": "http://example.com/api/documents/vulnerable/{resource_id}",
                    "resource_id_owner": "doc-b",
                    "action": "read",
                    "owner_indicator": "Secret Document B",
                }
            ]
        },
    )

    scanner = AccessControlScanner(target)

    def mock_make_request(url, method="GET", headers=None, data=None):
        if "vulnerable" in url:
            # Sells owner's document because it's vulnerable (IDOR)
            return 200, json.dumps(
                {
                    "owner": "user-b",
                    "title": "Secret Document B",
                    "content": "This is User B's private info.",
                }
            )
        return 404, ""

    with patch.object(scanner, "_make_request", side_effect=mock_make_request):
        findings = scanner.run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.name == "Broken Access Control (Unauthorized Read)"
    assert finding.severity == "high"
    assert "Secret Document B" in finding.evidence
    assert finding.metadata["action"] == "read"


def test_access_control_read_secure_no_finding():
    target = TargetConfig(
        id="t-ac-test",
        name="Access Control Test Target",
        base_url="http://example.com/",
        is_authorized=True,
        auth_context=TargetAuthContext(
            auth_type="bearer", credentials={"Authorization": "Bearer user-a-token"}
        ),
        auth_context_b=TargetAuthContext(
            auth_type="bearer", credentials={"Authorization": "Bearer user-b-token"}
        ),
        scan_metadata={
            "access_control_tests": [
                {
                    "name": "Secure Read Document",
                    "method": "GET",
                    "url_template": "http://example.com/api/documents/secure/{resource_id}",
                    "resource_id_owner": "doc-b",
                    "action": "read",
                    "owner_indicator": "Secret Document B",
                }
            ]
        },
    )

    scanner = AccessControlScanner(target)

    def mock_make_request(url, method="GET", headers=None, data=None):
        if headers.get("Authorization") == "Bearer user-b-token":
            return 200, json.dumps(
                {
                    "owner": "user-b",
                    "title": "Secret Document B",
                    "content": "This is User B's private info.",
                }
            )
        elif headers.get("Authorization") == "Bearer user-a-token":
            return 403, "Forbidden"
        return 401, "Unauthorized"

    with patch.object(scanner, "_make_request", side_effect=mock_make_request):
        findings = scanner.run()

    # Access was denied correctly, so there should be no findings
    assert len(findings) == 0


def test_access_control_write_vulnerable():
    target = TargetConfig(
        id="t-ac-test",
        name="Access Control Test Target",
        base_url="http://example.com/",
        is_authorized=True,
        auth_context=TargetAuthContext(
            auth_type="bearer", credentials={"Authorization": "Bearer user-a-token"}
        ),
        auth_context_b=TargetAuthContext(
            auth_type="bearer", credentials={"Authorization": "Bearer user-b-token"}
        ),
        scan_metadata={
            "access_control_tests": [
                {
                    "name": "Vulnerable Write Document",
                    "method": "PUT",
                    "url_template": "http://example.com/api/documents/vulnerable/{resource_id}",
                    "resource_id_owner": "doc-b",
                    "action": "write",
                    "attacker_payload": {"title": "Hacked Title"},
                    "attacker_indicator": "Hacked Title",
                }
            ]
        },
    )

    scanner = AccessControlScanner(target)

    # In vulnerable mode, when User A writes, we update local mock state.
    state = {
        "doc-b": {
            "owner": "user-b",
            "title": "Secret Document B",
            "content": "This is User B's private info.",
        }
    }

    def mock_make_request(url, method="GET", headers=None, data=None):
        doc_id = url.split("/")[-1]
        if method == "GET":
            return 200, json.dumps(state.get(doc_id))
        elif method in ["PUT", "POST"]:
            if isinstance(data, dict):
                state[doc_id].update(data)
            elif isinstance(data, str):
                state[doc_id].update(json.loads(data))
            return 200, json.dumps(state.get(doc_id))
        return 404, ""

    with patch.object(scanner, "_make_request", side_effect=mock_make_request):
        findings = scanner.run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.name == "Broken Access Control (Unauthorized Write)"
    assert finding.severity == "critical"
    assert "Hacked Title" in finding.evidence
    assert finding.metadata["action"] == "write"


def test_access_control_write_secure_no_finding():
    target = TargetConfig(
        id="t-ac-test",
        name="Access Control Test Target",
        base_url="http://example.com/",
        is_authorized=True,
        auth_context=TargetAuthContext(
            auth_type="bearer", credentials={"Authorization": "Bearer user-a-token"}
        ),
        auth_context_b=TargetAuthContext(
            auth_type="bearer", credentials={"Authorization": "Bearer user-b-token"}
        ),
        scan_metadata={
            "access_control_tests": [
                {
                    "name": "Secure Write Document",
                    "method": "PUT",
                    "url_template": "http://example.com/api/documents/secure/{resource_id}",
                    "resource_id_owner": "doc-b",
                    "action": "write",
                    "attacker_payload": {"title": "Hacked Title"},
                    "attacker_indicator": "Hacked Title",
                }
            ]
        },
    )

    scanner = AccessControlScanner(target)

    state = {
        "doc-b": {
            "owner": "user-b",
            "title": "Secret Document B",
            "content": "This is User B's private info.",
        }
    }

    def mock_make_request(url, method="GET", headers=None, data=None):
        doc_id = url.split("/")[-1]
        token = headers.get("Authorization")
        if method == "GET":
            if token == "Bearer user-b-token":
                return 200, json.dumps(state.get(doc_id))
            return 403, "Forbidden"
        elif method in ["PUT", "POST"]:
            if token == "Bearer user-b-token":
                if isinstance(data, dict):
                    state[doc_id].update(data)
                elif isinstance(data, str):
                    state[doc_id].update(json.loads(data))
                return 200, json.dumps(state.get(doc_id))
            return 403, "Forbidden"
        return 404, ""

    with patch.object(scanner, "_make_request", side_effect=mock_make_request):
        findings = scanner.run()

    # Write action was blocked for user A, so no findings
    assert len(findings) == 0


def test_access_control_integration():
    # Find a free port
    s = socket.socket()
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()

    # Start server in background thread
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("", port), VulnerableHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    try:
        # Run scanner targeting this local server
        target = TargetConfig(
            id="t-ac-integration",
            name="Access Control Integration Target",
            base_url=f"http://localhost:{port}/",
            is_authorized=True,
            auth_context=TargetAuthContext(
                auth_type="bearer", credentials={"Authorization": "Bearer user-a-token"}
            ),
            auth_context_b=TargetAuthContext(
                auth_type="bearer", credentials={"Authorization": "Bearer user-b-token"}
            ),
            scan_metadata={
                "access_control_tests": [
                    {
                        "name": "Integration Vulnerable Read",
                        "method": "GET",
                        "url_template": f"http://localhost:{port}/api/documents/vulnerable/{{resource_id}}",
                        "resource_id_owner": "doc-b",
                        "action": "read",
                        "owner_indicator": "Secret Document B",
                    },
                    {
                        "name": "Integration Secure Read",
                        "method": "GET",
                        "url_template": f"http://localhost:{port}/api/documents/secure/{{resource_id}}",
                        "resource_id_owner": "doc-b",
                        "action": "read",
                        "owner_indicator": "Secret Document B",
                    },
                    {
                        "name": "Integration Vulnerable Write",
                        "method": "PUT",
                        "url_template": f"http://localhost:{port}/api/documents/vulnerable/{{resource_id}}",
                        "resource_id_owner": "doc-b",
                        "action": "write",
                        "attacker_payload": {"title": "Integration Hacked Title"},
                        "attacker_indicator": "Integration Hacked Title",
                    },
                ]
            },
        )

        scanner = AccessControlScanner(target)
        findings = scanner.run()

        # Vulnerable read and vulnerable write should succeed (IDOR!), secure read should fail/deny.
        # So we should get exactly 2 findings: Vulnerable Read and Vulnerable Write.
        assert len(findings) == 2
        names = [f.name for f in findings]
        assert "Broken Access Control (Unauthorized Read)" in names
        assert "Broken Access Control (Unauthorized Write)" in names

    finally:
        server.shutdown()
        server.server_close()
        server_thread.join()
