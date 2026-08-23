from unittest.mock import patch

import pytest

from warden.models.target import TargetConfig
from warden.scanners.auth import AuthScanner


def test_auth_scanner_missing_auth():
    target = TargetConfig(
        id="t-auth",
        name="Auth Target",
        base_url="http://example.com/",
        is_authorized=True,
    )

    scanner = AuthScanner(target)

    def mock_make_request(url, headers):
        if "/admin" in url:
            # Missing credentials returns 200 OK (vulnerable!)
            return 200, "Admin Console Page Content"
        return 404, ""

    with patch.object(scanner, "_make_request", side_effect=mock_make_request):
        findings = scanner.run()

    assert len(findings) > 0
    finding = findings[0]
    assert finding.name == "Authentication Bypass (Missing Authentication)"
    assert finding.severity == "high"
    assert "/admin" in finding.description


def test_auth_scanner_invalid_auth_bypass():
    target = TargetConfig(
        id="t-auth-bypass",
        name="Auth Bypass Target",
        base_url="http://example.com/",
        is_authorized=True,
    )

    scanner = AuthScanner(target)

    def mock_make_request(url, headers):
        if "/admin" in url:
            if not headers:
                # No headers returns 401 (behaves securely initially)
                return 401, "Unauthorized"
            # Invalid headers returns 200 OK (bypass!)
            return 200, "Admin Console"
        return 404, ""

    with patch.object(scanner, "_make_request", side_effect=mock_make_request):
        findings = scanner.run()

    assert len(findings) > 0
    finding = findings[0]
    assert finding.name == "Authentication Bypass (Weak Credential Validation)"
    assert finding.severity == "critical"


def test_auth_scanner_secure_endpoint():
    target = TargetConfig(
        id="t-auth-secure",
        name="Auth Secure Target",
        base_url="http://example.com/",
        is_authorized=True,
    )

    scanner = AuthScanner(target)

    def mock_make_request(url, headers):
        # Correctly returns 401 for all requests except valid auth (which the scanner doesn't send)
        return 401, "Unauthorized"

    with patch.object(scanner, "_make_request", side_effect=mock_make_request):
        findings = scanner.run()

    # If it returns 401, it is secure, no findings should be reported!
    assert len(findings) == 0


def test_auth_scanner_unauthorized_target():
    # Attempting to scan an unauthorized target should raise ValueError
    with pytest.raises(ValueError, match="Target is not authorized"):
        AuthScanner(
            TargetConfig(
                id="t-unauth",
                name="Unauthorized Target",
                base_url="http://example.com/",
                is_authorized=False,
            )
        )
