import json

import click

from warden.config import get_settings
from warden.models.target import TargetAuthContext, TargetConfig


@click.group()
def cli() -> None:
    """Warden Security & Vulnerability Testing Suite CLI."""
    pass


@cli.command()
def show_config() -> None:
    """Print the current validated application configuration."""
    try:
        settings = get_settings()
        click.echo("Warden Configuration:")
        click.echo(f"  Environment: {settings.warden_env}")
        click.echo(f"  ZAP Base URL: {settings.zap_base_url}")
        click.echo(f"  Timeout (sec): {settings.timeout_seconds}")
        click.echo(f"  Scan Timeout (sec): {settings.scan_timeout_seconds}")
        click.echo(f"  Poll Interval (sec): {settings.poll_interval_seconds}")
        click.echo(f"  Output Directory: {settings.output_dir}")
    except Exception as e:
        click.echo(f"Error loading configuration: {e}", err=True)
        raise click.Abort()


@cli.command()
@click.option(
    "--id", "target_id", required=True, help="Unique identifier for the target"
)
@click.option("--name", required=True, help="Friendly name of the target")
@click.option("--url", required=True, help="Base URL of the target")
@click.option(
    "--authorized", is_flag=True, help="Explicitly authorize this scan target"
)
@click.option(
    "--auth-context-json", help="Optional JSON string containing TargetAuthContext"
)
def validate_target(
    target_id: str, name: str, url: str, authorized: bool, auth_context_json: str
) -> None:
    """Validate a target configuration model and verify its authorization status."""
    try:
        auth_context = None
        if auth_context_json:
            auth_data = json.loads(auth_context_json)
            auth_context = TargetAuthContext(**auth_data)

        target = TargetConfig(
            id=target_id,
            name=name,
            base_url=url,
            is_authorized=authorized,
            auth_context=auth_context,
        )
        click.echo("Target validation: SUCCESS")
        click.echo(f"  ID: {target.id}")
        click.echo(f"  Name: {target.name}")
        click.echo(f"  Base URL: {target.base_url}")
        click.echo(f"  Authorized: {target.is_authorized}")
    except Exception as e:
        click.echo("Target validation: FAILED")
        click.echo(f"  Error: {e}", err=True)
        raise click.Abort()


@cli.command()
@click.option(
    "--id", "target_id", required=True, help="Unique identifier for the target"
)
@click.option("--name", required=True, help="Friendly name of the target")
@click.option("--url", required=True, help="Base URL of the target")
@click.option(
    "--authorized", is_flag=True, help="Explicitly authorize this scan target"
)
@click.option(
    "--auth-context-json", help="Optional JSON string containing TargetAuthContext"
)
def scan(
    target_id: str, name: str, url: str, authorized: bool, auth_context_json: str
) -> None:
    """Execute a controlled baseline security scan against an authorized target."""
    try:
        settings = get_settings()

        auth_context = None
        if auth_context_json:
            auth_data = json.loads(auth_context_json)
            auth_context = TargetAuthContext(**auth_data)

        target = TargetConfig(
            id=target_id,
            name=name,
            base_url=url,
            is_authorized=authorized,
            auth_context=auth_context,
        )

        def log_progress(msg: str) -> None:
            click.echo(f"[*] {msg}")

        click.echo(f"[*] Scanned target endpoint: {target.base_url}")
        click.echo(f"[*] ZAP API endpoint: {settings.zap_base_url}")

        from warden.orchestration import ScanOrchestrator
        from warden.reporting.engine import ReportEngine

        orchestrator = ScanOrchestrator(
            settings=settings, target=target, progress_callback=log_progress
        )

        findings = orchestrator.run_baseline_scan()

        # Run reporting engine
        report_engine = ReportEngine(target, findings)
        deduped_findings = report_engine.deduplicate()

        click.echo("--------------------------------------------------")
        click.echo("[+] Scan completed successfully.")
        click.echo(f"[+] Findings discovered: {len(deduped_findings)}")
        click.echo(f"[+] Total raw findings: {len(findings)}")

        # Save JSON and MD reports
        saved_paths = report_engine.save_reports(settings.output_dir, target_id)

        click.echo(f"[+] Structured JSON report saved to: {saved_paths['json']}")
        click.echo(
            f"[+] Human-readable Markdown report saved to: {saved_paths['markdown']}"
        )

        # Display severity summary breakdown
        summary = report_engine.get_summary_counts(deduped_findings)
        click.echo("[+] Severity breakdown:")
        click.echo(f"    Critical: {summary['critical']}")
        click.echo(f"    High:     {summary['high']}")
        click.echo(f"    Medium:   {summary['medium']}")
        click.echo(f"    Low:      {summary['low']}")
        click.echo(f"    Info:     {summary['info']}")

    except Exception as e:
        click.echo(f"[-] Scan execution failed: {e}", err=True)
        raise click.Abort()


if __name__ == "__main__":
    cli()
