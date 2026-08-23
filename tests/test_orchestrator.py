from unittest.mock import MagicMock, patch

import pytest

from warden.config import Settings
from warden.models.target import TargetConfig
from warden.orchestration import OrchestratorError, ScanOrchestrator


@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        WARDEN_ENV="test",
        ZAP_BASE_URL="http://localhost:8080",
        TIMEOUT_SECONDS=1,
        SCAN_TIMEOUT_SECONDS=2,
        POLL_INTERVAL_SECONDS=1,
    )


@pytest.fixture
def test_target() -> TargetConfig:
    return TargetConfig(
        id="t-orch",
        name="Orch Target",
        base_url="http://target.local",
        is_authorized=True,
    )


@patch("warden.orchestration.validate_target_config")
@patch("warden.orchestration.check_target_reachability")
@patch("warden.orchestration.ZapClient")
@patch("warden.orchestration.normalize_zap_alert")
def test_orchestrator_success(
    mock_normalize: MagicMock,
    mock_zap_class: MagicMock,
    mock_reachability: MagicMock,
    mock_validate: MagicMock,
    test_settings: Settings,
    test_target: TargetConfig,
) -> None:
    """Verify ScanOrchestrator successfully completes the baseline workflow."""
    mock_zap = MagicMock()
    mock_zap.check_connectivity.return_value = True
    mock_zap.check_readiness.return_value = True
    mock_zap.start_spider.return_value = "scan-123"
    mock_zap.get_spider_status.side_effect = [50, 100]
    mock_zap.get_alerts.return_value = [{"alert": "Test Alert", "risk": "Low"}]
    mock_zap_class.return_value = mock_zap

    mock_normalize.return_value = MagicMock()

    progress_log = []

    def progress_callback(msg: str) -> None:
        progress_log.append(msg)

    orchestrator = ScanOrchestrator(
        settings=test_settings,
        target=test_target,
        progress_callback=progress_callback,
    )

    findings = orchestrator.run_baseline_scan()
    assert len(findings) == 1
    assert any("Initializing scan orchestration" in log for log in progress_log)
    assert any("Spider progress: 100%" in log for log in progress_log)

    mock_validate.assert_called_once_with(test_target)
    mock_reachability.assert_called_once()
    mock_zap.start_spider.assert_called_once_with(str(test_target.base_url))


@patch("warden.orchestration.validate_target_config")
def test_orchestrator_target_validation_failure(
    mock_validate: MagicMock,
    test_settings: Settings,
    test_target: TargetConfig,
) -> None:
    """Verify orchestrator fails early when target config is invalid."""
    mock_validate.side_effect = Exception("Invalid Config Details")

    orchestrator = ScanOrchestrator(
        settings=test_settings,
        target=test_target,
    )

    with pytest.raises(OrchestratorError) as excinfo:
        orchestrator.run_baseline_scan()
    assert "Target validation failed: Invalid Config Details" in str(excinfo.value)


@patch("warden.orchestration.validate_target_config")
@patch("warden.orchestration.check_target_reachability")
@patch("warden.orchestration.ZapClient")
def test_orchestrator_zap_connectivity_failure(
    mock_zap_class: MagicMock,
    mock_reachability: MagicMock,
    mock_validate: MagicMock,
    test_settings: Settings,
    test_target: TargetConfig,
) -> None:
    """Verify orchestrator fails early when ZAP connection fails."""
    mock_zap = MagicMock()
    mock_zap.check_connectivity.return_value = False
    mock_zap_class.return_value = mock_zap

    orchestrator = ScanOrchestrator(
        settings=test_settings,
        target=test_target,
    )

    with pytest.raises(OrchestratorError) as excinfo:
        orchestrator.run_baseline_scan()
    assert "ZAP daemon is not reachable" in str(excinfo.value)


@patch("warden.orchestration.validate_target_config")
@patch("warden.orchestration.check_target_reachability")
@patch("warden.orchestration.ZapClient")
def test_orchestrator_spider_timeout(
    mock_zap_class: MagicMock,
    mock_reachability: MagicMock,
    mock_validate: MagicMock,
    test_settings: Settings,
    test_target: TargetConfig,
) -> None:
    """Verify orchestrator raises timeout error if spider takes too long."""
    mock_zap = MagicMock()
    mock_zap.check_connectivity.return_value = True
    mock_zap.check_readiness.return_value = True
    mock_zap.start_spider.return_value = "scan-123"
    mock_zap.get_spider_status.return_value = 50
    mock_zap_class.return_value = mock_zap

    orchestrator = ScanOrchestrator(
        settings=test_settings,
        target=test_target,
    )

    test_settings.scan_timeout_seconds = 1
    test_settings.poll_interval_seconds = 0.5

    with pytest.raises(OrchestratorError) as excinfo:
        orchestrator.run_baseline_scan()
    assert "Scan timed out after" in str(excinfo.value)
