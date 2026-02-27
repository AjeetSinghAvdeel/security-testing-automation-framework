"""
Web Security Module - XSS Tester
"""

import logging
import time
import requests
from typing import Dict

logger = logging.getLogger(__name__)

class XSSTester:
    """Safe XSS detection module (reflection-based validation)"""

    def __init__(self):
        self.name = "XSS Tester"
        self.version = "2.0.0"
        self.mitre_id = "T1059.007"
        self.severity = "Medium"
        self.test_payloads = [
            {"name": "Basic script", "payload": "<script>alert(1)</script>"},
            {"name": "Image tag", "payload": "<img src=x onerror=alert(1)>"},
            {"name": "Div event", "payload": "<div onmouseover='alert(1)'>test</div>"}
        ]

    async def execute(self, config: Dict) -> Dict:
        """
        Execute XSS reflection detection (safe mode)
        """
        target = config.get("target", {})
        url = target.get("url")

        logger.info(f"[XSS] Starting XSS detection on {url}")

        results = {
            "module": "xss",
            "target": url,
            "tests": [],
            "vulnerabilities": [],
            "timestamp": time.time()
        }

        if not url:
            results["error"] = "No target URL provided"
            return results

        for payload in self.test_payloads:
            try:
                test_url = f"{url}?q={payload['payload']}"
                response = requests.get(test_url, timeout=5)

                reflected = payload["payload"] in response.text

                vulnerable = False
                confidence = 0.2
                evidence = None

                if reflected:
                    vulnerable = True
                    confidence = 0.8
                    evidence = "Payload reflected without encoding in response"

                test_result = {
                    "input_point": "q",
                    "payload": payload["payload"],
                    "vulnerable": vulnerable,
                    "confidence": confidence,
                    "evidence": evidence,
                    "mitre_id": self.mitre_id
                }

                results["tests"].append(test_result)

                if vulnerable:
                    results["vulnerabilities"].append(test_result)

            except Exception as e:
                logger.warning(f"[XSS] Request failed: {str(e)}")

        return results

    def get_metadata(self) -> Dict:
        return {
            "name": self.name,
            "version": self.version,
            "mitre_id": self.mitre_id,
            "severity": self.severity
        }


class AuthBypassTester:
    """
    Authentication Bypass validation (safe configuration check)
    """

    def __init__(self):
        self.name = "Auth Bypass Tester"
        self.version = "1.1.0"
        self.mitre_id = "T1110"
        self.severity = "Critical"

    async def execute(self, config: Dict) -> Dict:
        """
        Performs simple authorization validation:
        Checks if restricted endpoint is accessible without token.
        """

        target = config.get("target", {})
        url = target.get("url")

        results = {
            "module": "auth",
            "target": url,
            "tests": [],
            "vulnerabilities": [],
            "timestamp": time.time()
        }

        if not url:
            results["error"] = "No target URL provided"
            return results

        try:
            response = requests.get(url, timeout=5)

            vulnerable = False
            confidence = 0.3
            evidence = None

            # If 200 OK returned for supposed protected endpoint
            if response.status_code == 200:
                vulnerable = True
                confidence = 0.7
                evidence = "Endpoint accessible without authentication"

            test_result = {
                "test": "auth_bypass_check",
                "vulnerable": vulnerable,
                "confidence": confidence,
                "evidence": evidence,
                "mitre_id": self.mitre_id
            }

            results["tests"].append(test_result)

            if vulnerable:
                results["vulnerabilities"].append(test_result)

        except Exception as e:
            results["error"] = str(e)

        return results