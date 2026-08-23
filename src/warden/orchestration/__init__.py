import time
from typing import Callable, List, Optional

from warden.config import Settings
from warden.models.finding import Finding
from warden.models.target import TargetConfig
from warden.reporting import normalize_zap_alert
from warden.scanners.access_control import AccessControlScanner
from warden.scanners.auth import AuthScanner
from warden.scanners.fuzzing import FuzzingScanner
from warden.scanners.sqli import SqlInjectionScanner
from warden.scanners.xss import XssScanner
from warden.scanners.zap_client import ZapClient
from warden.target_validator import check_target_reachability, validate_target_config


class OrchestratorError(Exception):
    """Exception raised for errors in the orchestration pipeline."""

    pass


class ScanOrchestrator:
    """Orchestrates the Warden Phase 2 scan lifecycle."""

    def __init__(
        self,
        settings: Settings,
        target: TargetConfig,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.settings = settings
        self.target = target
        self.progress_callback = progress_callback
        self.zap = ZapClient(
            base_url=str(self.settings.zap_base_url),
            api_key=self.settings.zap_api_key,
            timeout=self.settings.timeout_seconds,
        )

    def _log(self, message: str) -> None:
        if self.progress_callback:
            self.progress_callback(message)

    def run_baseline_scan(self) -> List[Finding]:
        """Runs a complete baseline passive scan against the target environment."""
        self._log("Initializing scan orchestration...")

        # 1. Target configuration checks
        self._log("Validating target configuration...")
        try:
            validate_target_config(self.target)
        except Exception as e:
            raise OrchestratorError(f"Target validation failed: {e}")

        # 2. Target reachability check
        self._log(f"Verifying reachability for target {self.target.base_url}...")
        try:
            check_target_reachability(
                self.target, timeout=self.settings.timeout_seconds
            )
        except Exception as e:
            raise OrchestratorError(f"Target reachability check failed: {e}")

        # 3. ZAP availability verification
        self._log(f"Verifying connectivity to ZAP at {self.settings.zap_base_url}...")
        if not self.zap.check_connectivity():
            raise OrchestratorError(
                "ZAP daemon is not reachable. Ensure ZAP is "
                "running and configured correctly."
            )

        self._log("Checking ZAP readiness...")
        if not self.zap.check_readiness():
            raise OrchestratorError("ZAP daemon is not ready to perform scans.")

        # 4. Initiate baseline scan (Spider scan)
        target_url = str(self.target.base_url)
        self._log(f"Initiating ZAP spider scan against {target_url}...")
        try:
            scan_id = self.zap.start_spider(target_url)
        except Exception as e:
            raise OrchestratorError(f"Failed to start ZAP spider scan: {e}")

        # 5. Poll spider status until complete or timeout
        self._log(f"Spider scan started with ID: {scan_id}. Monitoring progress...")
        start_time = time.time()
        timeout = self.settings.scan_timeout_seconds
        poll_interval = self.settings.poll_interval_seconds

        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                raise OrchestratorError(
                    f"Scan timed out after {timeout} seconds during spider crawl."
                )

            try:
                progress = self.zap.get_spider_status(scan_id)
            except Exception as e:
                raise OrchestratorError(f"Failed to fetch spider status: {e}")

            self._log(f"Spider progress: {progress}%")
            if progress >= 100:
                break

            time.sleep(poll_interval)

        # 6. Await passive scan completion
        self._log("Waiting for passive scan queue to empty...")
        try:
            self.zap.wait_for_pscan(poll_interval=1, timeout=30)
        except Exception as e:
            self._log(f"Warning: passive scan queue check encountered an issue: {e}")

        # 7. Retrieve alerts and normalize them into Warden Finding models
        self._log("Retrieving findings from ZAP...")
        try:
            zap_alerts = self.zap.get_alerts(base_url=target_url)
        except Exception as e:
            raise OrchestratorError(f"Failed to retrieve alerts from ZAP: {e}")

        self._log(f"Discovered {len(zap_alerts)} raw alerts. Normalizing findings...")
        normalized_findings = []
        for alert in zap_alerts:
            finding = normalize_zap_alert(self.target.id, alert)
            normalized_findings.append(finding)

        self._log(f"Successfully normalized {len(normalized_findings)} findings.")

        # 8. Run Phase 3 Specialized Scanners
        self._log("Running specialized vulnerability testing...")

        try:
            sqli_scanner = SqlInjectionScanner(self.target, self.zap)
            self._log("Running SQL Injection Scanner...")
            sqli_findings = sqli_scanner.run()
            self._log(
                f"SQL Injection Scanner discovered {len(sqli_findings)} findings."
            )
            normalized_findings.extend(sqli_findings)
        except Exception as e:
            self._log(f"Warning: SQL Injection Scanner encountered an issue: {e}")

        try:
            xss_scanner = XssScanner(self.target, self.zap)
            self._log("Running Cross-Site Scripting Scanner...")
            xss_findings = xss_scanner.run()
            self._log(
                f"Cross-Site Scripting Scanner discovered {len(xss_findings)} findings."
            )
            normalized_findings.extend(xss_findings)
        except Exception as e:
            self._log(
                f"Warning: Cross-Site Scripting Scanner encountered an issue: {e}"
            )

        try:
            auth_scanner = AuthScanner(self.target, self.zap)
            self._log("Running Authentication Weakness Scanner...")
            auth_findings = auth_scanner.run()
            self._log(
                f"Authentication Weakness Scanner discovered {len(auth_findings)} findings."
            )
            normalized_findings.extend(auth_findings)
        except Exception as e:
            self._log(
                f"Warning: Authentication Weakness Scanner encountered an issue: {e}"
            )

        try:
            ac_scanner = AccessControlScanner(self.target, self.zap)
            self._log("Running Broken Access Control Scanner...")
            ac_findings = ac_scanner.run()
            self._log(
                f"Broken Access Control Scanner discovered {len(ac_findings)} findings."
            )
            normalized_findings.extend(ac_findings)
        except Exception as e:
            self._log(
                f"Warning: Broken Access Control Scanner encountered an issue: {e}"
            )

        try:
            fuzz_scanner = FuzzingScanner(self.target, self.zap)
            self._log("Running Input Fuzzing Scanner...")
            fuzz_findings = fuzz_scanner.run()
            self._log(
                f"Input Fuzzing Scanner discovered {len(fuzz_findings)} findings."
            )
            normalized_findings.extend(fuzz_findings)
        except Exception as e:
            self._log(f"Warning: Input Fuzzing Scanner encountered an issue: {e}")

        # Deduplicate findings by ID
        unique_findings = {}
        for f in normalized_findings:
            unique_findings[f.id] = f

        self._log(
            f"Successfully completed scan orchestration. Total findings: {len(unique_findings)}."
        )
        return list(unique_findings.values())
