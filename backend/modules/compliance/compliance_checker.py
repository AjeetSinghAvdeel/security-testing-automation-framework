from .frameworks import COMPLIANCE_MAPPINGS

class ComplianceChecker:
    def map_finding(self, finding):
        vuln = finding.get("vulnerability")
        mapping = COMPLIANCE_MAPPINGS.get(
            vuln,
            {"NIST": ["Not Mapped"], "ISO27001": ["Not Mapped"]}
        )

        return {
            "vulnerability": vuln,
            "severity": finding.get("severity"),
            "nist_controls": mapping["NIST"],
            "iso27001_controls": mapping["ISO27001"]
        }

    def check_compliance(self, scan_result):
        compliance_results = []
        for finding in scan_result.get("results", []):
            compliance_results.append(self.map_finding(finding))
        return compliance_results