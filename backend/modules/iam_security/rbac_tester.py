from __future__ import annotations

from typing import Dict, List

import requests

from backend.modules.local_lab import JuiceShopLab


ADMIN_ENDPOINTS = [
    "/admin",
    "/admin/dashboard",
    "/admin/users",
    "/admin/settings",
]


def test_rbac(target, scan_options=None):
    """
    Test access to sensitive admin endpoints and Juice Shop basket tampering paths.
    """

    results: List[Dict] = []
    actions: List[Dict] = []
    scan_options = scan_options or {}
    attack_type = scan_options.get("attack_type")
    juice_shop = JuiceShopLab(target)

    if juice_shop.is_match():
        if attack_type == "view_basket":
            auth_result, action = juice_shop.login("admin@juice-sh.op", "admin123")
            actions.append(action)
            if auth_result and auth_result.get("basket_id"):
                current_basket_id = int(auth_result["basket_id"])
                tampered_basket_id = 1 if current_basket_id != 1 else 2
                probe = juice_shop.read_basket(auth_result["token"], tampered_basket_id)
                actions.append(probe["action"])
                response = probe["response"]
                if response is not None and response.status_code == 200:
                    results.append(
                        {
                            "type": "View Basket",
                            "severity": "High",
                            "risk_score": 8.1,
                            "endpoint": probe["action"]["endpoint"],
                            "description": "Authenticated session accessed another basket by changing the basket id.",
                        }
                    )
            return {"findings": results, "actions": actions}

        actions.extend(juice_shop.check_admin_endpoints())
        for action in actions:
            if action.get("outcome") == "authorized":
                results.append(
                    {
                        "type": "Admin Section",
                        "severity": "High",
                        "risk_score": 7.4,
                        "endpoint": action["endpoint"],
                        "description": "Admin-oriented endpoint was reachable without an additional authorization barrier.",
                    }
                )
        return {"findings": results, "actions": actions}

    for endpoint in ADMIN_ENDPOINTS:
        try:
            response = requests.get(target + endpoint, timeout=3)
            if response.status_code == 200:
                results.append(
                    {
                        "type": "RBAC Misconfiguration",
                        "severity": "High",
                        "risk_score": 7.0,
                        "endpoint": endpoint,
                        "description": "Admin endpoint accessible without authorization",
                    }
                )

        except Exception:
            pass

    return {"findings": results, "actions": actions}
