from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from warden.main import cli


def test_cli_help() -> None:
    """Verify help command displays correctly."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Warden Security & Vulnerability Testing Suite CLI." in result.output


def test_cli_show_config() -> None:
    """Verify show-config command prints parameters."""
    runner = CliRunner()
    result = runner.invoke(cli, ["show-config"])
    assert result.exit_code == 0
    assert "Warden Configuration:" in result.output
    assert "Environment:" in result.output


def test_cli_validate_target_success() -> None:
    """Verify validate-target CLI command succeeds when authorized."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "validate-target",
            "--id",
            "t1",
            "--name",
            "Prod Test",
            "--url",
            "https://prod.local",
            "--authorized",
        ],
    )
    assert result.exit_code == 0
    assert "Target validation: SUCCESS" in result.output
    assert "ID: t1" in result.output
    assert "Authorized: True" in result.output


def test_cli_validate_target_unauthorized() -> None:
    """Verify validate-target CLI command fails when unauthorized."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "validate-target",
            "--id",
            "t2",
            "--name",
            "Unauthorized Test",
            "--url",
            "https://unauthorized.local",
        ],
    )
    assert result.exit_code != 0
    assert "Target validation: FAILED" in result.output
    assert "Target is not authorized" in result.output


@patch("warden.orchestration.ScanOrchestrator")
def test_cli_scan_success(mock_orchestrator_class: MagicMock) -> None:
    """Verify scan CLI command succeeds when authorized."""
    mock_orchestrator = MagicMock()
    mock_orchestrator.run_baseline_scan.return_value = []
    mock_orchestrator_class.return_value = mock_orchestrator

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "--id",
            "t1",
            "--name",
            "Scan Test",
            "--url",
            "https://prod.local",
            "--authorized",
        ],
    )
    assert result.exit_code == 0
    assert "Scan completed successfully" in result.output
    assert "Findings discovered: 0" in result.output
    mock_orchestrator.run_baseline_scan.assert_called_once()


def test_cli_scan_unauthorized() -> None:
    """Verify scan CLI command fails on unauthorized target."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "--id",
            "t2",
            "--name",
            "Scan Unauthorized",
            "--url",
            "https://prod.local",
        ],
    )
    assert result.exit_code != 0
    assert "Scan execution failed" in result.output
    assert "Target is not authorized" in result.output
