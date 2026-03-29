"""Web Security Module - XSS and auth-bypass testers."""

from __future__ import annotations

import logging
import time
from typing import Dict, List
from urllib.parse import urlencode, urljoin

import requests

from backend.modules.local_lab import JuiceShopLab

logger = logging.getLogger(__name__)


class XSSTester:
    """Active reflected-XSS probe for local labs."""

    def __init__(self):
        self.name = "XSS Tester"
        self.version = "2.1.0"
        self.mitre_id = "T1059.007"
        self.severity = "Medium"
        self.test_payloads = [
            {"name": "Basic script", "payload": "<script>alert(1)</script>"},
            {"name": "Image tag", "payload": "<img src=x onerror=alert(1)>"},
            {"name": "Div event", "payload": "<div onmouseover='alert(1)'>test</div>"},
        ]
        self.paths = ["/", "/search", "/products", "/feedback"]
        self.parameters = ["q", "search", "query", "name", "message"]

    async def execute(self, config: Dict) -> Dict:
        target = config.get("target", {})
        url = target.get("url")
        attack_type = config.get("attack_type")

        logger.info("[XSS] Starting XSS detection on %s", url)

        results = {
            "module": "xss",
            "target": url,
            "tests": [],
            "vulnerabilities": [],
            "actions": [],
            "timestamp": time.time(),
        }

        if not url:
            results["error"] = "No target URL provided"
            return results

        session = requests.Session()
        juice_shop = JuiceShopLab(url)

        if juice_shop.is_match():
            for payload in self.test_payloads:
                probe = juice_shop.search(payload["payload"])
                results["actions"].append(probe["action"])
                response = probe["response"]
                if response is None:
                    continue

                reflected = payload["payload"] in response.text
                test_result = {
                    "input_point": "q",
                    "payload": payload["payload"],
                    "endpoint": probe["action"]["endpoint"],
                    "method": "GET",
                    "vulnerable": reflected,
                    "confidence": 0.88 if reflected else 0.2,
                    "evidence": "Payload reflected without encoding in Juice Shop search response" if reflected else None,
                    "mitre_id": self.mitre_id,
                    "severity": self.severity,
                    "type": "Reflected XSS",
                }
                results["tests"].append(test_result)

                if reflected:
                    results["vulnerabilities"].append(test_result)
                    return results

        for path in self.paths:
            endpoint = urljoin(f"{url.rstrip('/')}/", path.lstrip("/"))
            for payload in self.test_payloads:
                for parameter in self.parameters:
                    test_url = f"{endpoint}?{urlencode({parameter: payload['payload']})}"
                    try:
                        response = session.get(test_url, timeout=5)
                    except Exception as exc:
                        logger.warning("[XSS] Request failed: %s", exc)
                        continue

                    reflected = payload["payload"] in response.text
                    test_result = {
                        "input_point": parameter,
                        "payload": payload["payload"],
                        "endpoint": endpoint,
                        "method": "GET",
                        "vulnerable": reflected,
                        "confidence": 0.85 if reflected else 0.2,
                        "evidence": "Payload reflected without encoding in response" if reflected else None,
                        "mitre_id": self.mitre_id,
                    }

                    results["tests"].append(test_result)

                    if reflected:
                        results["vulnerabilities"].append(test_result)
                        return results

        return results

    def get_metadata(self) -> Dict:
        return {
            "name": self.name,
            "version": self.version,
            "mitre_id": self.mitre_id,
            "severity": self.severity,
        }


class AuthBypassTester:
    """Authorization bypass probe for common protected local-lab endpoints."""

    def __init__(self):
        self.name = "Auth Bypass Tester"
        self.version = "1.2.0"
        self.mitre_id = "T1110"
        self.severity = "Critical"
        self.paths = ["/admin", "/admin/dashboard", "/api/admin", "/dashboard", "/profile"]

    async def execute(self, config: Dict) -> Dict:
        target = config.get("target", {})
        url = target.get("url")
        attack_type = config.get("attack_type")

        results = {
            "module": "auth",
            "target": url,
            "tests": [],
            "vulnerabilities": [],
            "actions": [],
            "timestamp": time.time(),
        }

        if not url:
            results["error"] = "No target URL provided"
            return results

        session = requests.Session()
        juice_shop = JuiceShopLab(url)

        if juice_shop.is_match():
            results["actions"].extend(juice_shop.check_admin_endpoints())
            for action in results["actions"]:
                if attack_type == "application_configuration" and "application-configuration" not in action["endpoint"]:
                    continue
                if attack_type == "admin_section" and "application-configuration" in action["endpoint"]:
                    continue
                vulnerable = action.get("outcome") == "authorized"
                test_result = {
                    "test": "auth_bypass_check",
                    "endpoint": action["endpoint"],
                    "method": action["method"],
                    "vulnerable": vulnerable,
                    "confidence": 0.8 if vulnerable else 0.25,
                    "evidence": "Protected endpoint accessible without authentication" if vulnerable else None,
                    "mitre_id": self.mitre_id,
                    "severity": self.severity,
                    "type": "Application Configuration"
                    if attack_type == "application_configuration"
                    else "Admin Section",
                }
                results["tests"].append(test_result)
                if vulnerable:
                    results["vulnerabilities"].append(test_result)
            return results

        for path in self.paths:
            endpoint = urljoin(f"{url.rstrip('/')}/", path.lstrip("/"))
            try:
                response = session.get(endpoint, timeout=5, allow_redirects=False)
            except Exception as exc:
                results["tests"].append(
                    {
                        "endpoint": endpoint,
                        "vulnerable": False,
                        "evidence": str(exc),
                        "mitre_id": self.mitre_id,
                    }
                )
                continue

            vulnerable = response.status_code == 200
            test_result = {
                "test": "auth_bypass_check",
                "endpoint": endpoint,
                "method": "GET",
                "vulnerable": vulnerable,
                "confidence": 0.75 if vulnerable else 0.25,
                "evidence": "Protected endpoint accessible without authentication" if vulnerable else None,
                "mitre_id": self.mitre_id,
            }

            results["tests"].append(test_result)
            if vulnerable:
                results["vulnerabilities"].append(test_result)

        return results


class ObservabilityTester:
    """Probe public observability endpoints on local labs."""

    def __init__(self):
        self.name = "Observability Tester"
        self.version = "1.0.0"
        self.mitre_id = "T1046"
        self.severity = "Medium"

    async def execute(self, config: Dict) -> Dict:
        target = config.get("target", {})
        url = target.get("url")
        results = {
            "module": "observability",
            "target": url,
            "tests": [],
            "vulnerabilities": [],
            "actions": [],
            "timestamp": time.time(),
        }

        if not url:
            results["error"] = "No target URL provided"
            return results

        juice_shop = JuiceShopLab(url)
        if juice_shop.is_match():
            probe = juice_shop.metrics()
            results["actions"].append(probe["action"])
            response = probe["response"]
            if response is not None and response.status_code == 200 and "process_cpu_user_seconds_total" in response.text:
                finding = {
                    "test": "exposed_metrics",
                    "endpoint": probe["action"]["endpoint"],
                    "method": "GET",
                    "vulnerable": True,
                    "confidence": 0.9,
                    "evidence": "Prometheus metrics were accessible without authentication.",
                    "mitre_id": self.mitre_id,
                    "severity": self.severity,
                    "type": "Exposed Metrics",
                }
                results["tests"].append(finding)
                results["vulnerabilities"].append(finding)

        return results
