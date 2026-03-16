"""Log generation utilities for SIEM integration."""

from __future__ import annotations

from datetime import datetime
import json
import logging
import os
import socket
from typing import Dict, List
import uuid

logger = logging.getLogger(__name__)


class LogGenerator:
    """Generate structured logs and CEF summaries from scan results."""

    def __init__(self) -> None:
        self.hostname = socket.gethostname()
        self.log_queue: List[Dict] = []
        self.logs: List[Dict] = []

    def generate_security_log(self, processed_results: Dict) -> List[Dict]:
        """Generate verbose SIEM logs from processed test results."""
        logs = []

        main_log = self.create_test_log(processed_results)
        logs.append(main_log)

        for finding in processed_results.get("findings", []):
            finding_log = self.create_finding_log(processed_results, finding)
            logs.append(finding_log)

            if finding.get("severity") in ["Critical", "High"]:
                logs.append(self.create_alert_log(processed_results, finding))

        self.send_to_siem(logs)
        return logs

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
            "tags": ["security_test"],
        }

    def create_finding_log(self, results: Dict, finding: Dict) -> Dict:
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "vulnerability_finding",
            "timestamp": datetime.utcnow().isoformat(),
            "host": self.hostname,
            "module": results.get("module"),
            "target": results.get("target"),
            "finding_type": finding.get("type") or finding.get("vulnerability"),
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "evidence": finding.get("evidence") or finding.get("description"),
            "remediation": finding.get("remediation"),
            "tags": ["vulnerability"],
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
            "tags": ["alert", "high_risk"],
        }

    def generate_cef_log(self, test_id: str, target: str, module: str, finding: Dict) -> Dict:
        """Generate the simplified CEF-style record used by the SIEM branch."""
        severity_map = {
            "Low": 3,
            "Medium": 5,
            "High": 8,
            "Critical": 10,
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
                "evidence": finding.get("evidence", ""),
            },
        }

        self.logs.append(cef_log)
        return cef_log

    def generate_logs_from_results(self, scan_result: Dict) -> List[Dict]:
        """Generate the simplified logs expected by the SIEM service."""
        generated = []
        for finding in scan_result.get("results", []):
            generated.append(
                self.generate_cef_log(
                    scan_result.get("test_id"),
                    scan_result.get("target"),
                    scan_result.get("module", "multi_module"),
                    finding,
                )
            )
        return generated

    def send_to_siem(self, logs: List[Dict]) -> None:
        logger.info("[SIEM] Storing %s logs", len(logs))
        self.log_queue.extend(logs)

        for log in logs:
            self.write_to_file(log)

    def write_to_file(self, log: Dict) -> None:
        try:
            os.makedirs("logs", exist_ok=True)
            log_file = f"logs/siem_logs_{datetime.now().strftime('%Y%m%d')}.json"
            with open(log_file, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(log) + "\n")
        except Exception as exc:
            logger.error("[SIEM] File write failed: %s", exc)

    def get_log_statistics(self) -> Dict:
        return {
            "total_logs": len(self.log_queue) + len(self.logs),
            "queued_logs": len(self.log_queue),
            "formats": ["CEF"],
            "last_log_time": datetime.utcnow().isoformat(),
        }


log_generator = LogGenerator()
