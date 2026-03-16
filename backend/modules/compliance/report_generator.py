from datetime import datetime

class ReportGenerator:
    def generate_summary(self, scan_result, alerts, compliance_results):
        severity_count = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}

        for finding in scan_result.get("results", []):
            sev = finding.get("severity", "Low")
            if sev in severity_count:
                severity_count[sev] += 1

        report = {
            "report_id": f"RPT-{scan_result.get('test_id')}",
            "generated_at": datetime.utcnow().isoformat(),
            "test_id": scan_result.get("test_id"),
            "target": scan_result.get("target"),
            "module": scan_result.get("module"),
            "total_findings": len(scan_result.get("results", [])),
            "severity_breakdown": severity_count,
            "alerts_generated": len(alerts),
            "compliance_summary": compliance_results,
            "findings": scan_result.get("results", [])
        }

        return report