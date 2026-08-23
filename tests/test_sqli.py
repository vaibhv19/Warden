from unittest.mock import MagicMock, patch

from warden.models.target import TargetConfig
from warden.scanners.sqli import SqlInjectionScanner


def test_sqli_scanner_error_based():
    target = TargetConfig(
        id="t-sqli",
        name="SQLi Target",
        base_url="http://example.com/",
        is_authorized=True,
    )

    mock_zap = MagicMock()
    mock_zap.get_crawled_urls.return_value = ["http://example.com/users?id=1"]

    scanner = SqlInjectionScanner(target, mock_zap)

    # Mock response containing sqlite OperationalError SQL signature
    mock_body = 'sqlite3.OperationalError: near "\'": syntax error'
    with patch.object(scanner, "_make_request", return_value=(500, mock_body, 0.05)):
        findings = scanner.run()

    assert len(findings) > 0
    finding = findings[0]
    assert finding.name == "SQL Injection (Error-Based)"
    assert finding.target_id == "t-sqli"
    assert "operationalerror" in finding.description.lower()
    assert finding.severity == "high"


def test_sqli_scanner_time_based():
    target = TargetConfig(
        id="t-sqli-time",
        name="SQLi Time Target",
        base_url="http://example.com/",
        is_authorized=True,
    )

    mock_zap = MagicMock()
    mock_zap.get_crawled_urls.return_value = ["http://example.com/users?id=1"]

    scanner = SqlInjectionScanner(target, mock_zap)

    # Mock response with long duration
    with patch.object(
        scanner, "_make_request", return_value=(200, "User Profile", 5.2)
    ):
        findings = scanner.run()

    # Time-based triggers when duration is >= 4.5
    time_findings = [f for f in findings if "Time-Based" in f.name]
    assert len(time_findings) > 0
    assert time_findings[0].name == "SQL Injection (Time-Based)"
    assert time_findings[0].severity == "high"


def test_sqli_scanner_boolean_based():
    target = TargetConfig(
        id="t-sqli-bool",
        name="SQLi Boolean Target",
        base_url="http://example.com/",
        is_authorized=True,
    )

    mock_zap = MagicMock()
    mock_zap.get_crawled_urls.return_value = ["http://example.com/users?id=1"]

    scanner = SqlInjectionScanner(target, mock_zap)

    def mock_make_request(url):
        # If true condition payload, return large body
        if "boolean_true" in url or "1'='1" in url or "1%27%3D%271" in url:
            return 200, "A" * 1000, 0.05
        # If false condition payload, return small body
        elif "boolean_false" in url or "1'='2" in url or "1%27%3D%272" in url:
            return 200, "A" * 10, 0.05
        return 200, "A" * 500, 0.05

    with patch.object(scanner, "_make_request", side_effect=mock_make_request):
        findings = scanner.run()

    bool_findings = [f for f in findings if "Boolean-Based" in f.name]
    assert len(bool_findings) > 0
    assert bool_findings[0].severity == "medium"


def test_sqli_scanner_scope_restriction():
    target = TargetConfig(
        id="t-scope",
        name="Scope Target",
        base_url="http://example.com/",
        is_authorized=True,
    )

    mock_zap = MagicMock()
    # Out of scope url crawled
    mock_zap.get_crawled_urls.return_value = ["http://malicious.com/users?id=1"]

    scanner = SqlInjectionScanner(target, mock_zap)
    with patch.object(scanner, "_make_request") as mock_req:
        findings = scanner.run()
        # Request should never be made to out-of-scope URL
        mock_req.assert_not_called()

    assert len(findings) == 0
