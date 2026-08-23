import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from warden.models.finding import Finding, Severity
from warden.models.target import TargetConfig


class ReportEngine:
    """Consolidates, deduplicates, and formats security scan findings into structured reports."""

    def __init__(self, target: TargetConfig, findings: List[Finding]) -> None:
        self.target = target
        self.findings = findings
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def deduplicate(self) -> List[Finding]:
        """Deduplicates findings based on a signature (name, affected URL, and parameter).

        Merges duplicates by keeping the highest severity and aggregating description/evidence.
        """
        deduped: Dict[Tuple[str, str, str], Finding] = {}

        # Severity rank for comparison
        severity_rank = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }

        for finding in self.findings:
            # Resolve url and parameter from metadata or directly
            affected_url = finding.metadata.get(
                "affected_url", str(self.target.base_url)
            )
            parameter = finding.metadata.get("parameter", "")

            # Signature key
            sig = (finding.name.lower(), affected_url.lower(), parameter.lower())

            if sig not in deduped:
                # Make a copy to avoid mutating original
                deduped[sig] = finding.model_copy(deep=True)
            else:
                existing = deduped[sig]

                # 1. Update severity if new is higher
                if severity_rank[finding.severity] > severity_rank[existing.severity]:
                    existing.severity = finding.severity

                # 2. Append description if different
                if finding.description not in existing.description:
                    existing.description += f" | {finding.description}"

                # 3. Aggregate evidence
                if finding.evidence and existing.evidence:
                    if finding.evidence not in existing.evidence:
                        existing.evidence += (
                            f"\n---\nAdditional Evidence:\n{finding.evidence}"
                        )
                elif finding.evidence:
                    existing.evidence = finding.evidence

                # 4. Merge metadata
                existing.metadata.update(finding.metadata)

                # Add duplicate info to metadata
                existing.metadata["merged_duplicate_ids"] = existing.metadata.get(
                    "merged_duplicate_ids", []
                ) + [finding.id]

        return list(deduped.values())

    def get_summary_counts(self, findings: List[Finding]) -> Dict[str, int]:
        """Calculate counts of findings grouped by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity.value] += 1
        return counts

    def generate_json_report(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generates a structured dictionary representing the scan report."""
        summary = self.get_summary_counts(findings)

        return {
            "report_metadata": {
                "scan_timestamp": self.timestamp,
                "warden_version": "0.1.0",
            },
            "target": {
                "id": self.target.id,
                "name": self.target.name,
                "base_url": str(self.target.base_url),
            },
            "summary": {
                "total_findings": len(findings),
                "severity_counts": summary,
            },
            "findings": [f.model_dump() for f in findings],
        }

    def generate_markdown_report(self, findings: List[Finding]) -> str:
        """Generates a beautiful human-readable markdown report."""
        summary = self.get_summary_counts(findings)

        md = []
        md.append("# Warden Security Assessment Report")
        md.append("")
        md.append("## Executive Summary")
        md.append("")
        md.append("| Target Name | Base URL | Scan Date (UTC) |")
        md.append("|---|---|---|")
        md.append(f"| {self.target.name} | {self.target.base_url} | {self.timestamp} |")
        md.append("")
        md.append("### Severity Breakdown")
        md.append("")
        md.append(f"- **Critical:** {summary['critical']}")
        md.append(f"- **High:** {summary['high']}")
        md.append(f"- **Medium:** {summary['medium']}")
        md.append(f"- **Low:** {summary['low']}")
        md.append(f"- **Info:** {summary['info']}")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## Vulnerability Details")
        md.append("")

        if not findings:
            md.append("No vulnerabilities were discovered during this security scan.")
            return "\n".join(md)

        # Sort findings by severity rank (highest first)
        severity_order = ["critical", "high", "medium", "low", "info"]
        sorted_findings = sorted(
            findings, key=lambda x: severity_order.index(x.severity.value)
        )

        for i, f in enumerate(sorted_findings, start=1):
            sev_label = f.severity.value.upper()
            color_badge = (
                "🔴"
                if sev_label in ["CRITICAL", "HIGH"]
                else "🟡"
                if sev_label == "MEDIUM"
                else "🔵"
            )

            md.append(f"### {i}. {color_badge} {f.name} [{sev_label}]")
            md.append("")
            md.append(f"**Severity:** {sev_label}")

            affected_url = f.metadata.get("affected_url", str(self.target.base_url))
            md.append(f"**Affected URL:** `{affected_url}`")

            if f.metadata.get("parameter"):
                md.append(f"**Vulnerable Parameter:** `{f.metadata['parameter']}`")

            md.append("")
            md.append("**Description:**")
            md.append(f"{f.description}")
            md.append("")

            if f.evidence:
                md.append("**Evidence / Repro Payload:**")
                md.append("```text")
                md.append(f"{f.evidence.strip()}")
                md.append("```")
                md.append("")

            if f.remediation:
                md.append("**Remediation / Fix Recommendation:**")
                md.append(f"{f.remediation}")
                md.append("")

            md.append("**Scanner Source:**")
            md.append(f"*{f.metadata.get('tool', 'Unknown Scanner')}*")
            md.append("")
            md.append("---")
            md.append("")

        return "\n".join(md)

    def save_reports(self, output_dir: Path, target_id: str) -> Dict[str, Path]:
        """Saves both JSON and Markdown reports to the specified directory."""
        output_dir.mkdir(parents=True, exist_ok=True)

        # Deduplicate findings first
        deduped_findings = self.deduplicate()

        json_report = self.generate_json_report(deduped_findings)
        md_report = self.generate_markdown_report(deduped_findings)

        json_path = output_dir / f"report-{target_id}.json"
        md_path = output_dir / f"report-{target_id}.md"

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2)

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_report)

        return {"json": json_path, "markdown": md_path}
