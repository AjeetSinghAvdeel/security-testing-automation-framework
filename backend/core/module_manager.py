"""
Dynamic module loader for framework security modules.
"""

from __future__ import annotations

import importlib
from typing import Any, Dict, List


class ModuleManager:
    def __init__(self) -> None:
        self.module_map = {
            "web_security": [
                "modules.web_security.web_scanner",
                "backend.modules.web_security.web_scanner",
            ],
            "iam_security": [
                "modules.iam_security.iam_scanner",
                "backend.modules.iam_security.iam_scanner",
            ],
            "iot_security": [
                "modules.iot_security.iot_scanner",
                "backend.modules.iot_security.iot_scanner",
            ],
        }

    def _import_first_available(self, import_paths: List[str]) -> Any | None:
        for import_path in import_paths:
            try:
                return importlib.import_module(import_path)
            except ModuleNotFoundError:
                continue
        return None

    def load_modules(self) -> List[Any]:
        loaded_modules: List[Any] = []
        for import_paths in self.module_map.values():
            module = self._import_first_available(import_paths)
            if module is not None:
                loaded_modules.append(module)
        return loaded_modules

    def get_loaded_modules(self) -> List[Dict[str, Any]]:
        modules: List[Dict[str, Any]] = []
        for name, import_paths in self.module_map.items():
            module = self._import_first_available(import_paths)
            modules.append(
                {
                    "name": name,
                    "path": import_paths[0],
                    "loaded": module is not None,
                }
            )
        return modules


module_manager = ModuleManager()
