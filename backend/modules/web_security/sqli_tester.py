"""
Web Security Module - SQL Injection Tester
"""

import logging
import time
import requests
from typing import Dict

logger = logging.getLogger(__name__)

class SQLITester:
    """Safe SQL Injection detection module (response anomaly based)"""
    
    def __init__(self):
        self.name = "SQL Injection Tester"
        self.version = "2.0.0"
        self.mitre_id = "T1190"
        self.severity = "High"
        self.test_payloads = [
            {"name": "Basic quote test", "payload": "'"},
            {"name": "Union test", "payload": "' UNION SELECT NULL--"},
            {"name": "Boolean test", "payload": "' OR '1'='1"}
        ]

    async def execute(self, config: Dict) -> Dict:
        """
        Execute SQL injection detection (safe validation mode)
        """
        target = config.get("target", {})
        url = target.get("url")

        logger.info(f"[SQLI] Starting SQL injection detection on {url}")

        results = {
            "module": "sqli",
            "target": url,
            "tests": [],
            "vulnerabilities": [],
            "timestamp": time.time()
        }

        if not url:
            results["error"] = "No target URL provided"
            return results

        try:
            # Baseline request
            baseline_response = requests.get(url, timeout=5)
            baseline_length = len(baseline_response.text)

            for payload in self.test_payloads:
                test_url = f"{url}?id={payload['payload']}"

                try:
                    response = requests.get(test_url, timeout=5)

                    response_length = len(response.text)
                    length_diff = abs(response_length - baseline_length)

                    sql_error_patterns = [
                        "sql syntax",
                        "mysql_fetch",
                        "ora-",
                        "syntax error",
                        "warning: mysql",
                        "unclosed quotation mark",
                        "odbc",
                        "pdoexception"
                    ]

                    error_detected = any(
                        pattern in response.text.lower()
                        for pattern in sql_error_patterns
                    )

                    vulnerable = False
                    confidence = 0.2
                    evidence = None

                    if error_detected:
                        vulnerable = True
                        confidence = 0.9
                        evidence = "SQL error message detected in response"

                    elif length_diff > 150:
                        vulnerable = True
                        confidence = 0.6
                        evidence = f"Significant response length difference detected ({length_diff} bytes)"

                    test_result = {
                        "parameter": "id",
                        "payload": payload["payload"],
                        "vulnerable": vulnerable,
                        "confidence": confidence,
                        "evidence": evidence,
                        "mitre_id": self.mitre_id
                    }

                    results["tests"].append(test_result)

                    if vulnerable:
                        results["vulnerabilities"].append(test_result)

                except Exception as request_error:
                    logger.warning(f"[SQLI] Request failed: {str(request_error)}")

            return results

        except Exception as e:
            logger.error(f"[SQLI] Execution failed: {str(e)}")
            results["error"] = str(e)
            return results

    def get_metadata(self) -> Dict:
        return {
            "name": self.name,
            "version": self.version,
            "mitre_id": self.mitre_id,
            "severity": self.severity
        }