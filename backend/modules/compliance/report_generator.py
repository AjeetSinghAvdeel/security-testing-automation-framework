"""Compliance and reporting helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List


class ReportGenerator:
    """Generate summary artifacts for scans and compliance reviews."""

    def __init__(self) -> None:
        self.name = "Report Generator"
        self.version = "1.0.0"

    def generate_pentest_report(self, test_results: List[Dict]) -> Dict:
        """Generate a lightweight penetration test report payload."""
        return {
            "report_id": f"PENTEST-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "test_count": len(test_results),
            "findings": test_results,
            "summary": self.generate_summary_from_findings(test_results),
            "recommendations": [],
        }

    def generate_compliance_report(self, test_results: List[Dict]) -> Dict:
        """Generate a lightweight compliance report payload."""
        return {
            "report_id": f"COMPLIANCE-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "framework": "NIST & ISO 27001",
            "timestamp": datetime.now().isoformat(),
            "gaps": [],
            "controls_assessed": len(test_results),
            "controls_passed": 0,
        }

    def generate_summary_from_findings(self, results: List[Dict]) -> Dict:
        """Summarize severity counts from a plain findings list."""
        summary = {
            "total_tests": len(results),
            "vulnerabilities_found": len(results),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        for finding in results:
            severity = finding.get("severity", "Low")
            lowered = str(severity).lower()
            if lowered == "critical":
                summary["critical"] += 1
            elif lowered == "high":
                summary["high"] += 1
            elif lowered == "medium":
                summary["medium"] += 1
            else:
                summary["low"] += 1
        return summary

    def generate_summary(self, scan_result: Dict, alerts: List[Dict], compliance_results: List[Dict]) -> Dict:
        """Generate the summary shape expected by the SIEM branch."""
        severity_count = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}

        for finding in scan_result.get("results", []):
            severity = finding.get("severity", "Low")
            if severity in severity_count:
                severity_count[severity] += 1

        return {
            "report_id": f"RPT-{scan_result.get('test_id')}",
            "generated_at": datetime.utcnow().isoformat(),
            "test_id": scan_result.get("test_id"),
            "target": scan_result.get("target"),
            "module": scan_result.get("module"),
            "total_findings": len(scan_result.get("results", [])),
            "severity_breakdown": severity_count,
            "alerts_generated": len(alerts),
            "compliance_summary": compliance_results,
            "findings": scan_result.get("results", []),
        }


class NISTMapper:
    """NIST Framework mapping helper."""

    def __init__(self) -> None:
        self.name = "NIST Mapper"
        self.version = "1.0.0"

    def map_to_nist(self, findings: List[Dict]) -> Dict:
        return {
            "framework": "NIST SP 800-53",
            "mappings": findings,
        }


class ISOMapper:
    """ISO 27001 Framework mapping helper."""

    def __init__(self) -> None:
        self.name = "ISO Mapper"
        self.version = "1.0.0"

    def map_to_iso(self, findings: List[Dict]) -> Dict:
        return {
            "standard": "ISO/IEC 27001:2022",
            "mappings": findings,
        }
