import json

from warden.models.finding import Finding, Severity
from warden.models.target import TargetConfig
from warden.reporting.engine import ReportEngine


def test_reporting_summary_counts():
    target = TargetConfig(
        id="t-rep",
        name="Reporting Target",
        base_url="http://example.com",
        is_authorized=True,
    )

    findings = [
        Finding(
            id="f1",
            target_id="t-rep",
            name="SQLi",
            severity=Severity.CRITICAL,
            description="SQLi desc",
        ),
        Finding(
            id="f2",
            target_id="t-rep",
            name="XSS",
            severity=Severity.HIGH,
            description="XSS desc",
        ),
        Finding(
            id="f3",
            target_id="t-rep",
            name="Auth",
            severity=Severity.HIGH,
            description="Auth desc",
        ),
        Finding(
            id="f4",
            target_id="t-rep",
            name="CORS",
            severity=Severity.MEDIUM,
            description="CORS desc",
        ),
        Finding(
            id="f5",
            target_id="t-rep",
            name="SSL",
            severity=Severity.LOW,
            description="SSL desc",
        ),
        Finding(
            id="f6",
            target_id="t-rep",
            name="Header",
            severity=Severity.INFO,
            description="Header desc",
        ),
    ]

    engine = ReportEngine(target, findings)
    counts = engine.get_summary_counts(findings)

    assert counts["critical"] == 1
    assert counts["high"] == 2
    assert counts["medium"] == 1
    assert counts["low"] == 1
    assert counts["info"] == 1


def test_reporting_deduplication():
    target = TargetConfig(
        id="t-rep",
        name="Reporting Target",
        base_url="http://example.com",
        is_authorized=True,
    )

    findings = [
        Finding(
            id="f1",
            target_id="t-rep",
            name="SQL Injection",
            severity=Severity.HIGH,
            description="SQL Injection on query param",
            evidence="Payload: ' OR '1'='1",
            metadata={
                "affected_url": "http://example.com/users",
                "parameter": "id",
                "tool": "Warden SQLi Scanner",
            },
        ),
        # Overlapping finding with lower severity but extra details
        Finding(
            id="f2",
            target_id="t-rep",
            name="SQL Injection",
            severity=Severity.MEDIUM,
            description="Database syntax error flagged",
            evidence="Response signature: near syntax error",
            metadata={
                "affected_url": "http://example.com/users",
                "parameter": "id",
                "tool": "OWASP ZAP",
            },
        ),
        # Unique finding (different parameter)
        Finding(
            id="f3",
            target_id="t-rep",
            name="SQL Injection",
            severity=Severity.HIGH,
            description="SQL Injection on search query",
            metadata={
                "affected_url": "http://example.com/search",
                "parameter": "q",
                "tool": "Warden SQLi Scanner",
            },
        ),
    ]

    engine = ReportEngine(target, findings)
    deduped = engine.deduplicate()

    # Total unique findings should be 2 (one on /users?id, one on /search?q)
    assert len(deduped) == 2

    # Check merged finding details
    merged = next(f for f in deduped if f.metadata.get("parameter") == "id")
    assert merged.severity == Severity.HIGH  # Highest severity preserved
    assert "SQL Injection on query param" in merged.description
    assert "Database syntax error flagged" in merged.description
    assert "Payload: ' OR '1'='1" in merged.evidence
    assert "Response signature: near syntax error" in merged.evidence
    assert "f2" in merged.metadata["merged_duplicate_ids"]


def test_report_generation_and_saving(tmp_path):
    target = TargetConfig(
        id="t-rep",
        name="Reporting Target",
        base_url="http://example.com",
        is_authorized=True,
    )

    findings = [
        Finding(
            id="f1",
            target_id="t-rep",
            name="SQL Injection",
            severity=Severity.CRITICAL,
            description="SQL Injection vulnerability",
            evidence="Payload: '",
            remediation="Use parameterized queries",
            metadata={"affected_url": "http://example.com/users", "parameter": "id"},
        )
    ]

    engine = ReportEngine(target, findings)

    # 1. JSON Report validation
    json_report = engine.generate_json_report(findings)
    assert json_report["target"]["id"] == "t-rep"
    assert json_report["summary"]["total_findings"] == 1
    assert json_report["findings"][0]["name"] == "SQL Injection"

    # 2. Markdown Report validation
    md_report = engine.generate_markdown_report(findings)
    assert "# Warden Security Assessment Report" in md_report
    assert "## Executive Summary" in md_report
    assert "SQL Injection" in md_report
    assert "CRITICAL" in md_report
    assert "Use parameterized queries" in md_report

    # 3. File saving validation
    saved = engine.save_reports(tmp_path, "t-rep")

    json_file = saved["json"]
    md_file = saved["markdown"]

    assert json_file.exists()
    assert md_file.exists()

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["target"]["id"] == "t-rep"

    with open(md_file, "r", encoding="utf-8") as f:
        text = f.read()
        assert "# Warden Security Assessment Report" in text
