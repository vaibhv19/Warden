import json
import socket
import socketserver
import threading
from unittest.mock import MagicMock, patch

from tests.target_app import VulnerableHandler
from warden.config import Settings
from warden.models.target import TargetAuthContext, TargetConfig
from warden.orchestration import ScanOrchestrator
from warden.reporting.engine import ReportEngine


def test_complete_warden_workflow_e2e(tmp_path):
    # Reset target app DOCUMENTS to prevent contamination from other tests
    import tests.target_app

    tests.target_app.DOCUMENTS = {
        "doc-a": {
            "owner": "user-a",
            "title": "Secret Document A",
            "content": "This is User A's private info.",
        },
        "doc-b": {
            "owner": "user-b",
            "title": "Secret Document B",
            "content": "This is User B's private info.",
        },
    }

    # 1. Find a free port and start the vulnerable test target app in a background thread
    s = socket.socket()
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()

    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("", port), VulnerableHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    try:
        # 2. Configure target scan settings with access control and fuzzing targets
        target = TargetConfig(
            id="t-e2e",
            name="E2E Target App",
            base_url=f"http://127.0.0.1:{port}/",
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
                        "name": "E2E Vulnerable Read",
                        "method": "GET",
                        "url_template": f"http://127.0.0.1:{port}/api/documents/vulnerable/{{resource_id}}",
                        "resource_id_owner": "doc-b",
                        "action": "read",
                        "owner_indicator": "Secret Document B",
                    }
                ],
                "fuzzing_targets": [
                    {
                        "url": f"http://127.0.0.1:{port}/api/fuzz/vulnerable",
                        "method": "POST",
                        "parameters": {"username": "string"},
                    }
                ],
            },
        )

        settings = Settings(
            WARDEN_ENV="test",
            ZAP_BASE_URL="http://zap-api-test:8080",
            TIMEOUT_SECONDS=2,
            SCAN_TIMEOUT_SECONDS=2,
            POLL_INTERVAL_SECONDS=1,
            OUTPUT_DIR=tmp_path,
        )

        # 3. Mock ZAP API calls to simulate crawling and baseline findings
        mock_zap = MagicMock()
        mock_zap.check_connectivity.return_value = True
        mock_zap.check_readiness.return_value = True
        mock_zap.start_spider.return_value = "scan-e2e-123"
        mock_zap.get_spider_status.return_value = 100
        mock_zap.get_crawled_urls.return_value = [
            f"http://127.0.0.1:{port}/search?q=test",
            f"http://127.0.0.1:{port}/users?id=1",
        ]
        mock_zap.get_alerts.return_value = [
            {
                "alert": "X-Content-Type-Options Header Missing",
                "risk": "Low",
                "description": "The X-Content-Type-Options header was not set.",
                "solution": "Ensure the X-Content-Type-Options header is set to nosniff.",
                "evidence": "",
                "url": f"http://127.0.0.1:{port}/index.html",
                "id": "10021",
                "confidence": "Medium",
                "param": "",
            }
        ]

        # Patch ZapClient class inside orchestration
        with patch("warden.orchestration.ZapClient", return_value=mock_zap):
            # Since ZAP is mocked, we need to mock ZAP client references in custom scanners or let them call mock_zap.
            # Custom scanners SQLi and XSS use _make_request which uses urllib.request directly,
            # so they will hit the live localhost server! Let's mock ZAP get_crawled_urls which they use.

            # Let's perform the baseline scan orchestrator run
            orchestrator = ScanOrchestrator(settings=settings, target=target)
            raw_findings = orchestrator.run_baseline_scan()

            # 4. Assert all customized scanners ran and returned expected findings
            assert len(raw_findings) > 0

            finding_names = [f.name for f in raw_findings]

            # - ZAP passive scanner
            assert "X-Content-Type-Options Header Missing" in finding_names
            # - Auth bypass scanner
            assert "Authentication Bypass (Missing Authentication)" in finding_names
            # - Access control scanner
            assert "Broken Access Control (Unauthorized Read)" in finding_names
            # - Fuzzing scanner
            assert "Input Fuzzing Anomaly (Unhandled Exception)" in finding_names

            # 5. Execute ReportEngine to consolidate and deduplicate findings
            report_engine = ReportEngine(target, raw_findings)
            deduped = report_engine.deduplicate()

            assert len(deduped) <= len(raw_findings)

            # 6. Save Markdown and JSON reports to output directory
            saved_paths = report_engine.save_reports(settings.output_dir, target.id)

            assert saved_paths["json"].exists()
            assert saved_paths["markdown"].exists()

            # 7. Validate report structures
            with open(saved_paths["json"], "r", encoding="utf-8") as f:
                json_data = json.load(f)
                assert json_data["target"]["id"] == "t-e2e"
                assert json_data["summary"]["total_findings"] > 0
                assert len(json_data["findings"]) == len(deduped)

            with open(saved_paths["markdown"], "r", encoding="utf-8") as f:
                md_text = f.read()
                assert "# Warden Security Assessment Report" in md_text
                assert "E2E Target App" in md_text
                assert "Vulnerability Details" in md_text
                assert "Broken Access Control" in md_text
                assert "Input Fuzzing Anomaly" in md_text

    finally:
        # Shutdown live test server cleanly
        server.shutdown()
        server.server_close()
        server_thread.join()
