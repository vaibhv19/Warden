from unittest.mock import MagicMock, patch

from warden.models.target import TargetConfig
from warden.scanners.xss import XssScanner


def test_xss_scanner_detected():
    target = TargetConfig(
        id="t-xss",
        name="XSS Target",
        base_url="http://example.com/",
        is_authorized=True,
    )

    mock_zap = MagicMock()
    mock_zap.get_crawled_urls.return_value = ["http://example.com/search?q=test"]

    scanner = XssScanner(target, mock_zap)

    def mock_make_request(url):
        # Return response containing the unescaped script tag payload
        if "script" in url:
            return 200, "<html>You searched for: <script>alert(1)</script></html>"
        return 200, "<html>No reflection</html>"

    with patch.object(scanner, "_make_request", side_effect=mock_make_request):
        findings = scanner.run()

    assert len(findings) > 0
    finding = findings[0]
    assert finding.name == "Reflected Cross-Site Scripting (XSS)"
    assert finding.target_id == "t-xss"
    assert "unescaped" in finding.description
    assert finding.severity == "high"


def test_xss_scanner_safe_reflection():
    target = TargetConfig(
        id="t-xss-safe",
        name="XSS Safe Target",
        base_url="http://example.com/",
        is_authorized=True,
    )

    mock_zap = MagicMock()
    mock_zap.get_crawled_urls.return_value = ["http://example.com/search?q=test"]

    scanner = XssScanner(target, mock_zap)

    def mock_make_request(url):
        # Return safely encoded reflection (e.g. &lt;script&gt; instead of <script>)
        if "<script>alert(1)</script>" in url:
            return (
                200,
                "<html>You searched for: &lt;script&gt;alert(1)&lt;/script&gt;</html>",
            )
        elif "img" in url:
            return (
                200,
                "<html>You searched for: &lt;img src=x onerror=alert(1)&gt;</html>",
            )
        return 200, "<html>Safe</html>"

    with patch.object(scanner, "_make_request", side_effect=mock_make_request):
        findings = scanner.run()

    # The scanner should not flag safely encoded reflection
    assert len(findings) == 0
