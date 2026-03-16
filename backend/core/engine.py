"""
Core scan engine for running registered security modules.
"""

from __future__ import annotations

from datetime import datetime
import threading
from typing import Any, Dict, List
import uuid

from backend.blockchain.blockchain_auditor import blockchain_auditor
from backend.siem.siem_service import SIEMService


class ScanEngine:
    """Registers modules and executes them through a common run(target) API."""

    def __init__(self) -> None:
        self.modules: List[Any] = []
        self.tests: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._store = None
        self._siem_service = SIEMService()

    def register_module(self, module: Any) -> None:
        if module not in self.modules:
            self.modules.append(module)

    def clear_modules(self) -> None:
        self.modules = []

    def set_store(self, store: Any) -> None:
        self._store = store

    def run_scan(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for module in self.modules:
            module_name = getattr(module, "__name__", str(module)).split(".")[-1]
            try:
                result = module.run(target)
            except Exception as exc:
                error_finding = self._normalize_finding(
                    {
                        "type": "Module Execution Error",
                        "severity": "Low",
                        "description": str(exc),
                    },
                    module_name=module_name,
                    target=target,
                )
                if error_finding:
                    findings.append(error_finding)
                continue

            if not result:
                continue

            findings.extend(
                self._extract_findings(result=result, module_name=module_name, target=target)
            )

        return findings

    def create_test(self, target: str, modules: List[Any], user: Dict[str, Any]) -> Dict[str, Any]:
        test_id = f"test-{uuid.uuid4().hex[:8]}"

        self.clear_modules()
        for module in modules:
            self.register_module(module)

        record = {
            "test_id": test_id,
            "target": target,
            "status": "running",
            "results": [],
            "result_count": 0,
            "created_at": datetime.utcnow().isoformat(),
            "completed_at": None,
            "error": None,
            "user_id": user["uid"],
            "user_name": user.get("name"),
            "user_email": user.get("email"),
        }
        with self._lock:
            self.tests[test_id] = record

        self._persist(record)

        worker = threading.Thread(
            target=self._execute_test,
            args=(test_id, target),
            daemon=True,
        )
        worker.start()
        return dict(record)

    def get_test(self, test_id: str) -> Dict[str, Any] | None:
        with self._lock:
            record = self.tests.get(test_id)
        if record is not None:
            return dict(record)

        return None

    def get_test_status(self, test_id: str) -> Dict[str, Any] | None:
        test = self.get_test(test_id)
        if not test:
            return None
        return {
            "test_id": test["test_id"],
            "status": test["status"],
            "target": test["target"],
            "result_count": test["result_count"],
        }

    def get_all_tests(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(test) for test in self.tests.values()]

    def _execute_test(self, test_id: str, target: str) -> None:
        try:
            findings = self.run_scan(target)
            with self._lock:
                record = self.tests[test_id]
                record["status"] = "completed"
                record["results"] = findings
                record["result_count"] = len(findings)
                record["completed_at"] = datetime.utcnow().isoformat()
                record["module"] = "multi_module"
                evidence_hash = blockchain_auditor.hash_evidence(record)
                tx_hash = blockchain_auditor.store_hash(
                    evidence_hash=evidence_hash,
                    attack_type="SECURITY_SCAN",
                    target_info=target,
                    severity=self._severity_score(findings),
                )
                record["evidence_hash"] = evidence_hash
                record["blockchain_tx"] = tx_hash
            self._attach_siem_outputs(test_id)
        except Exception as exc:
            with self._lock:
                record = self.tests[test_id]
                record["status"] = "failed"
                record["error"] = str(exc)
                record["completed_at"] = datetime.utcnow().isoformat()
        self._persist(self.tests[test_id])

    def _persist(self, record: Dict[str, Any]) -> None:
        if self._store is None:
            return
        worker = threading.Thread(
            target=self._persist_record,
            args=(dict(record),),
            daemon=True,
        )
        worker.start()

    def _persist_record(self, record: Dict[str, Any]) -> None:
        try:
            self._store.save_test(record)
        except Exception:
            pass

    def _attach_siem_outputs(self, test_id: str) -> None:
        """Attach SIEM/compliance artifacts without affecting scan success."""
        with self._lock:
            record = dict(self.tests[test_id])

        try:
            siem_payload = self._siem_service.process_results(record)
        except Exception as exc:
            siem_payload = {"error": str(exc)}

        with self._lock:
            current = self.tests[test_id]
            current["siem"] = siem_payload

        self._persist(self.tests[test_id])

    def _extract_findings(
        self, result: Any, module_name: str, target: str
    ) -> List[Dict[str, Any]]:
        if isinstance(result, list):
            raw_findings = result
            result_module = module_name
            result_target = target
        elif isinstance(result, dict):
            result_module = result.get("module", module_name)
            result_target = result.get("target", target)
            raw_findings = []

            for key in ("results", "findings", "vulnerabilities"):
                if isinstance(result.get(key), list):
                    raw_findings = result[key]
                    break

            if not raw_findings:
                raw_findings = [result]
        else:
            return []

        normalized: List[Dict[str, Any]] = []
        for item in raw_findings:
            finding = self._normalize_finding(
                item=item,
                module_name=result_module,
                target=result_target,
            )
            if finding:
                normalized.append(finding)

        return normalized

    def _normalize_finding(
        self, item: Any, module_name: str, target: str
    ) -> Dict[str, Any] | None:
        if not isinstance(item, dict):
            return None

        if item.get("vulnerable") is False:
            return None

        severity = self._normalize_severity(item.get("severity"))
        if severity == "Info":
            return None

        vulnerability = (
            item.get("vulnerability")
            or item.get("type")
            or item.get("name")
            or item.get("test")
        )
        if not vulnerability:
            return None

        finding: Dict[str, Any] = {
            "module": item.get("module", module_name),
            "target": item.get("target", target),
            "severity": severity,
            "vulnerability": vulnerability,
        }

        description = item.get("description") or item.get("evidence") or item.get("error")
        if description:
            finding["description"] = description

        if "confidence" in item:
            finding["confidence"] = item["confidence"]

        if "risk_score" in item:
            finding["risk_score"] = item["risk_score"]

        return finding

    def _normalize_severity(self, severity: Any) -> str:
        if not severity:
            return "Low"

        normalized = str(severity).strip().title()
        if normalized == "Error":
            return "Low"
        return normalized

    def _severity_score(self, findings: List[Dict[str, Any]]) -> int:
        severity_map = {
            "Critical": 10,
            "High": 8,
            "Medium": 5,
            "Low": 3,
        }
        return max((severity_map.get(finding.get("severity"), 1) for finding in findings), default=1)


engine = ScanEngine()
