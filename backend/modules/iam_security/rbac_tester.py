import requests

ADMIN_ENDPOINTS = [
    "/admin",
    "/admin/dashboard",
    "/admin/users",
    "/admin/settings"
]


def test_rbac(target):
    """
    Test access to sensitive admin endpoints
    """

    results = []

    for endpoint in ADMIN_ENDPOINTS:

        try:
            response = requests.get(target + endpoint, timeout=3)

            if response.status_code == 200:
                results.append({
                    "type": "RBAC Misconfiguration",
                    "severity": "High",
                    "risk_score": 7.0,
                    "endpoint": endpoint,
                    "description": "Admin endpoint accessible without authorization"
                })

        except Exception:
            pass

    return results