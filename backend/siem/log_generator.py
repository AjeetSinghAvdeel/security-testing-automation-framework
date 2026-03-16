import json
from datetime import datetime

class LogGenerator:
    def __init__(self):
        self.logs = []

    def generate_cef_log(self, test_id, target, module, finding):
        severity_map = {
            "Low": 3,
            "Medium": 5,
            "High": 8,
            "Critical": 10
        }

        cef_log = {
            "timestamp": datetime.utcnow().isoformat(),
            "format": "CEF",
            "deviceVendor": "PBLFramework",
            "deviceProduct": "SecurityTestingFramework",
            "deviceVersion": "1.0",
            "signature": finding.get("vulnerability", "Unknown"),
            "name": finding.get("description", "No description"),
            "severity": severity_map.get(finding.get("severity", "Low"), 3),
            "extension": {
                "test_id": test_id,
                "target": target,
                "module": module,
                "endpoint": finding.get("endpoint", ""),
                "evidence": finding.get("evidence", "")
            }
        }

        self.logs.append(cef_log)
        return cef_log

    def generate_logs_from_results(self, scan_result):
        generated = []
        for finding in scan_result.get("results", []):
            generated.append(
                self.generate_cef_log(
                    scan_result.get("test_id"),
                    scan_result.get("target"),
                    scan_result.get("module"),
                    finding
                )
            )
        return generated

    def get_log_statistics(self):
        return {
            "total_logs": len(self.logs),
            "formats": ["CEF"]
        }