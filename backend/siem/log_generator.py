"""
Log Generator - Creates standardized logs for SIEM integration
"""

import json
import logging
from datetime import datetime
from typing import Dict, List
import uuid
import socket
import os
logger = logging.getLogger(__name__)


class LogGenerator:
    """Generates and stores logs for SIEM integration"""

    def __init__(self):
        self.hostname = socket.gethostname()
        self.log_queue: List[Dict] = []

    # ============================================================
    # MAIN ENTRY POINT (CALLED FROM ENGINE)
    # ============================================================

    def generate_security_log(self, processed_results: Dict):
        """
        Generate and store SIEM logs from processed test results
        """

        logs = []

        # Main execution log
        main_log = self.create_test_log(processed_results)
        logs.append(main_log)

        # Finding logs
        for finding in processed_results.get("findings", []):
            finding_log = self.create_finding_log(processed_results, finding)
            logs.append(finding_log)

            # High severity alerts
            if finding.get("severity") in ["Critical", "High"]:
                alert_log = self.create_alert_log(processed_results, finding)
                logs.append(alert_log)

        # Store logs
        self.send_to_siem(logs)

    # ============================================================
    # LOG BUILDERS
    # ============================================================

    def create_test_log(self, results: Dict) -> Dict:
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "security_test",
            "timestamp": datetime.utcnow().isoformat(),
            "host": self.hostname,
            "module": results.get("module"),
            "target": results.get("target"),
            "summary": results.get("summary"),
            "risk_score": results.get("summary", {}).get("overall_risk", 0),
            "tags": ["security_test"]
        }

    def create_finding_log(self, results: Dict, finding: Dict) -> Dict:
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "vulnerability_finding",
            "timestamp": datetime.utcnow().isoformat(),
            "host": self.hostname,
            "module": results.get("module"),
            "target": results.get("target"),
            "finding_type": finding.get("type"),
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "evidence": finding.get("evidence"),
            "remediation": finding.get("remediation"),
            "tags": ["vulnerability"]
        }

    def create_alert_log(self, results: Dict, finding: Dict) -> Dict:
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "security_alert",
            "timestamp": datetime.utcnow().isoformat(),
            "host": self.hostname,
            "module": results.get("module"),
            "target": results.get("target"),
            "alert_type": "high_risk_vulnerability",
            "severity": finding.get("severity"),
            "risk_score": results.get("summary", {}).get("overall_risk", 0),
            "tags": ["alert", "high_risk"]
        }

    # ============================================================
    # STORAGE
    # ============================================================

    def send_to_siem(self, logs: List[Dict]):
        logger.info(f"[SIEM] Storing {len(logs)} logs")
        self.log_queue.extend(logs)

        # Optional: Write to file
        for log in logs:
            self.write_to_file(log)

    def write_to_file(self, log: Dict):
        try:
            os.makedirs("logs", exist_ok=True)
            log_file = f"logs/siem_logs_{datetime.now().strftime('%Y%m%d')}.json"
            with open(log_file, "a") as f:
                f.write(json.dumps(log) + "\n")
        except Exception as e:
            logger.error(f"[SIEM] File write failed: {str(e)}")

    # ============================================================
    # STATS
    # ============================================================

    def get_log_statistics(self) -> Dict:
        return {
            "total_logs": len(self.log_queue),
            "queued_logs": len(self.log_queue),
            "last_log_time": datetime.utcnow().isoformat()
        }


# Singleton instance
log_generator = LogGenerator()