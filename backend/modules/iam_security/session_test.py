import requests


def test_session(target):
    """
    Check security flags on session cookies
    """

    findings = []

    try:
        response = requests.get(target)

        for cookie in response.cookies:

            if not cookie.secure:
                findings.append({
                    "type": "Insecure Cookie",
                    "severity": "Medium",
                    "risk_score": 4.5,
                    "cookie": cookie.name,
                    "description": "Session cookie not marked Secure"
                })

            if not cookie.has_nonstandard_attr("HttpOnly"):
                findings.append({
                    "type": "Missing HttpOnly Cookie Flag",
                    "severity": "Low",
                    "risk_score": 3.0,
                    "cookie": cookie.name,
                    "description": "Cookie missing HttpOnly protection"
                })

    except Exception:
        pass

    return findings