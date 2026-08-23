import hashlib
from typing import Any, Dict

from warden.models.finding import Finding, Severity


def map_severity(zap_risk: str) -> Severity:
    """Maps OWASP ZAP risk labels to Warden Severity levels."""
    zap_risk = zap_risk.lower()
    if "high" in zap_risk:
        return Severity.HIGH
    elif "medium" in zap_risk:
        return Severity.MEDIUM
    elif "low" in zap_risk:
        return Severity.LOW
    else:
        return Severity.INFO


def normalize_zap_alert(target_id: str, zap_alert: Dict[str, Any]) -> Finding:
    """Normalizes an individual raw ZAP alert JSON object into a Warden Finding."""
    alert_name = zap_alert.get("alert", "Unknown Vulnerability")
    zap_risk = zap_alert.get("risk", "Informational")
    description = zap_alert.get("description", "No description provided.")
    remediation = zap_alert.get("solution", "No remediation steps provided.")
    evidence = zap_alert.get("evidence", "")
    affected_url = zap_alert.get("url", "")

    # Generate a deterministic unique ID for the finding within Warden
    raw_id_str = f"{target_id}:{alert_name}:{affected_url}"
    finding_id = hashlib.sha256(raw_id_str.encode("utf-8")).hexdigest()[:16]

    severity = map_severity(zap_risk)

    return Finding(
        id=finding_id,
        target_id=target_id,
        name=alert_name,
        severity=severity,
        description=description,
        remediation=remediation or None,
        evidence=evidence or None,
        metadata={
            "tool": "OWASP ZAP",
            "zap_id": zap_alert.get("id", ""),
            "confidence": zap_alert.get("confidence", ""),
            "parameter": zap_alert.get("param", ""),
            "affected_url": affected_url,
        },
    )
