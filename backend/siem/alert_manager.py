from datetime import datetime

class AlertManager:
    def __init__(self):
        self.alerts = []

    def create_alert(self, test_id, finding):
        alert = {
            "alert_id": f"ALERT-{len(self.alerts)+1:03d}",
            "test_id": test_id,
            "vulnerability": finding.get("vulnerability"),
            "severity": finding.get("severity"),
            "endpoint": finding.get("endpoint", ""),
            "status": "Open",
            "timestamp": datetime.utcnow().isoformat()
        }
        self.alerts.append(alert)
        return alert

    def generate_alerts(self, scan_result):
        generated = []
        for finding in scan_result.get("results", []):
            if finding.get("severity") in ["High", "Critical"]:
                generated.append(self.create_alert(scan_result.get("test_id"), finding))
        return generated

    def get_alerts(self):
        return self.alerts