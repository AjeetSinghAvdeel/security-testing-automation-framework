import requests

def test_session(target):

    findings = []

    try:
        r = requests.get(target)

        for cookie in r.cookies:

            if not cookie.secure:
                findings.append({
                    "type": "Insecure Cookie",
                    "severity": "Medium",
                    "cookie": cookie.name
                })

            if not cookie.has_nonstandard_attr("HttpOnly"):
                findings.append({
                    "type": "Missing HttpOnly Cookie Flag",
                    "severity": "Low",
                    "cookie": cookie.name
                })

    except Exception:
        pass

    return findings