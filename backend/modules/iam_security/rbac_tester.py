import requests

ADMIN_ENDPOINTS = [
    "/admin",
    "/admin/dashboard",
    "/admin/users",
    "/admin/settings"
]


def test_rbac(target):

    results = []

    for endpoint in ADMIN_ENDPOINTS:

        try:
            r = requests.get(target + endpoint, timeout=3)

            if r.status_code == 200:
                results.append({
                    "type": "RBAC Misconfiguration",
                    "severity": "High",
                    "endpoint": endpoint
                })

        except Exception:
            pass

    return results