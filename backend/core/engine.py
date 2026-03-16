"""
Core scan engine for running registered security modules.
"""

from __future__ import annotations

from typing import Any, Dict, List
import uuid


class ScanEngine:
    """Registers modules and executes them through a common run(target) API."""

    def __init__(self) -> None:
        self.modules: List[Any] = []
        self.tests: Dict[str, Dict[str, Any]] = {}

    def register_module(self, module: Any) -> None:
        if module not in self.modules:
            self.modules.append(module)

    def clear_modules(self) -> None:
        self.modules = []

    def run_scan(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for module in self.modules:
            try:
                result = module.run(target)
            except Exception as exc:
                findings.append(
                    {
                        "module": getattr(module, "__name__", str(module)).split(".")[-1],
                        "error": str(exc),
                    }
                )
                continue

            if not result:
                continue

            if isinstance(result, list):
                findings.extend(item for item in result if item)
            else:
                findings.append(result)

        return findings

    def create_test(self, target: str, modules: List[Any]) -> Dict[str, Any]:
        test_id = f"test-{uuid.uuid4().hex[:8]}"

        self.clear_modules()
        for module in modules:
            self.register_module(module)

        findings = self.run_scan(target)
        record = {
            "test_id": test_id,
            "target": target,
            "status": "completed",
            "results": findings,
            "result_count": len(findings),
        }
        self.tests[test_id] = record
        return record

    def get_test(self, test_id: str) -> Dict[str, Any] | None:
        return self.tests.get(test_id)

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
        return list(self.tests.values())


engine = ScanEngine()
