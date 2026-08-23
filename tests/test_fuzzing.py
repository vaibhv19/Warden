import socket
import socketserver
import threading
from unittest.mock import patch

from tests.target_app import VulnerableHandler
from warden.models.target import TargetConfig
from warden.scanners.fuzzing import FuzzingScanner


def test_fuzzing_payload_generator():
    target = TargetConfig(
        id="t-fuzz",
        name="Fuzz Target",
        base_url="http://example.com/",
        is_authorized=True,
    )
    scanner = FuzzingScanner(target)

    str_payloads = scanner._generate_fuzz_payloads("string")
    int_payloads = scanner._generate_fuzz_payloads("int")

    assert len(str_payloads) > 0
    assert any(c[0] == "oversized" and len(c[1]) == 10000 for c in str_payloads)
    assert any(c[0] == "unexpected_type_int" and c[1] == 99999 for c in str_payloads)

    assert len(int_payloads) > 0
    assert any(c[0] == "oversized" and c[1] == 999999999999999999 for c in int_payloads)
    assert any(
        c[0] == "unexpected_type_string" and c[1] == "not_an_int" for c in int_payloads
    )


def test_fuzzing_scanner_secure_endpoint():
    target = TargetConfig(
        id="t-fuzz",
        name="Fuzz Target",
        base_url="http://example.com/",
        is_authorized=True,
        scan_metadata={
            "fuzzing_targets": [
                {
                    "url": "http://example.com/api/fuzz/secure",
                    "method": "POST",
                    "parameters": {"username": "string"},
                }
            ]
        },
    )
    scanner = FuzzingScanner(target)

    # Secure endpoint returns 400 Bad Request for all invalid inputs
    def mock_make_request(url, method="POST", headers=None, data=None):
        return 400, "Bad Request"

    with patch.object(scanner, "_make_request", side_effect=mock_make_request):
        findings = scanner.run()

    # No findings should be generated because the server handled validation errors gracefully (HTTP 400)
    assert len(findings) == 0


def test_fuzzing_scanner_vulnerable_endpoint():
    target = TargetConfig(
        id="t-fuzz",
        name="Fuzz Target",
        base_url="http://example.com/",
        is_authorized=True,
        scan_metadata={
            "fuzzing_targets": [
                {
                    "url": "http://example.com/api/fuzz/vulnerable",
                    "method": "POST",
                    "parameters": {"username": "string"},
                }
            ]
        },
    )
    scanner = FuzzingScanner(target)

    def mock_make_request(url, method="POST", headers=None, data=None):
        # Trigger unhandled exception HTTP 500 when username is integer 99999
        if data and isinstance(data, dict) and data.get("username") == 99999:
            return 500, "Internal Server Error"
        return 200, '{"status": "success"}'

    with patch.object(scanner, "_make_request", side_effect=mock_make_request):
        findings = scanner.run()

    # The unhandled exception (HTTP 500) should generate an anomaly finding
    assert len(findings) > 0
    finding = findings[0]
    assert finding.name == "Input Fuzzing Anomaly (Unhandled Exception)"
    assert finding.severity == "high"
    assert "500" in finding.evidence
    assert finding.metadata["parameter"] == "username"


def test_fuzzing_integration():
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
        # Target configuration for integration test
        target = TargetConfig(
            id="t-fuzz-integration",
            name="Fuzz Integration Target",
            base_url=f"http://127.0.0.1:{port}/",
            is_authorized=True,
            scan_metadata={
                "fuzzing_targets": [
                    {
                        "url": f"http://127.0.0.1:{port}/api/fuzz/secure",
                        "method": "POST",
                        "parameters": {"username": "string", "age": "int"},
                    },
                    {
                        "url": f"http://127.0.0.1:{port}/api/fuzz/vulnerable",
                        "method": "POST",
                        "parameters": {"username": "string", "age": "int"},
                    },
                ]
            },
        )

        scanner = FuzzingScanner(target)
        findings = scanner.run()

        # The secure endpoint should not yield any findings.
        # The vulnerable endpoint should produce findings for:
        # - malformed json syntax
        # - missing field (ValueError)
        # - unexpected string types (AttributeError)
        # - oversized string (OverflowError)
        # - unexpected int types (TypeError)
        assert len(findings) > 0

        # Verify finding details
        finding_names = [f.name for f in findings]
        assert "Input Fuzzing Anomaly (Unhandled Exception)" in finding_names

        # Verify affected URL is the vulnerable one
        for f in findings:
            assert "vulnerable" in f.metadata["affected_url"]
            assert f.severity == "high"

    finally:
        server.shutdown()
        server.server_close()
        server_thread.join()
