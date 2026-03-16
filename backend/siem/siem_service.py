from .log_generator import LogGenerator
from .alert_manager import AlertManager
from backend.modules.compliance.compliance_checker import ComplianceChecker
from backend.modules.compliance.report_generator import ReportGenerator

class SIEMService:
    def __init__(self):
        self.log_generator = LogGenerator()
        self.alert_manager = AlertManager()
        self.compliance_checker = ComplianceChecker()
        self.report_generator = ReportGenerator()

    def process_results(self, scan_result):
        logs = self.log_generator.generate_logs_from_results(scan_result)
        alerts = self.alert_manager.generate_alerts(scan_result)
        compliance = self.compliance_checker.check_compliance(scan_result)
        report = self.report_generator.generate_summary(scan_result, alerts, compliance)

        return {
            "logs": logs,
            "alerts": alerts,
            "compliance": compliance,
            "report": report
        }