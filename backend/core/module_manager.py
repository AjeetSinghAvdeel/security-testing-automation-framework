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
        self.profile_map = {
            "full_assessment": ["web_security", "iam_security", "iot_security"],
            "web_inputs": ["web_security"],
            "credential_stuffing": ["iam_security"],
            "password_strength": ["iam_security"],
            "exposed_credentials": ["iam_security"],
            "login_mc_safesearch": ["iam_security"],
            "bruteforce": ["iam_security"],
            "login_admin_sqli": ["web_security"],
            "union_search_injection": ["web_security"],
            "reflected_xss": ["web_security"],
            "admin_section": ["iam_security"],
            "view_basket": ["iam_security"],
            "application_configuration": ["web_security"],
            "empty_user_registration": ["iam_security"],
            "exposed_metrics": ["web_security"],
            "session_authz": ["iam_security"],
            "iot_protocols": ["iot_security"],
        }

    def _import_first_available(self, import_paths: List[str]) -> Any | None:
        for import_path in import_paths:
            try:
                return importlib.import_module(import_path)
            except ModuleNotFoundError:
                continue
        return None

    def load_modules(self, profile: str = "full_assessment") -> List[Any]:
        loaded_modules: List[Any] = []
        module_names = self.profile_map.get(profile, self.profile_map["full_assessment"])
        for module_name in module_names:
            import_paths = self.module_map.get(module_name, [])
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
