from warden.models.finding import Severity
from warden.reporting import map_severity, normalize_zap_alert


def test_map_severity() -> None:
    """Verify mapping of ZAP risk string to Severity enum."""
    assert map_severity("High") == Severity.HIGH
    assert map_severity("Medium") == Severity.MEDIUM
    assert map_severity("Low") == Severity.LOW
    assert map_severity("Informational") == Severity.INFO
    assert map_severity("unknown") == Severity.INFO


def test_normalize_zap_alert() -> None:
    """Verify full conversion from raw alert dict to Finding model."""
    zap_alert = {
        "id": "1001",
        "alert": "SQL Injection",
        "risk": "High",
        "confidence": "Medium",
        "url": "http://target.local/vuln?id=1",
        "param": "id",
        "description": "SQL injection description",
        "solution": "Use parameterized queries",
        "evidence": "union select NULL",
    }

    finding = normalize_zap_alert("target-abc", zap_alert)
    assert finding.target_id == "target-abc"
    assert finding.name == "SQL Injection"
    assert finding.severity == Severity.HIGH
    assert finding.description == "SQL injection description"
    assert finding.remediation == "Use parameterized queries"
    assert finding.evidence == "union select NULL"
    assert finding.metadata["tool"] == "OWASP ZAP"
    assert finding.metadata["zap_id"] == "1001"
    assert finding.metadata["confidence"] == "Medium"
    assert finding.metadata["parameter"] == "id"
    assert finding.metadata["affected_url"] == "http://target.local/vuln?id=1"
