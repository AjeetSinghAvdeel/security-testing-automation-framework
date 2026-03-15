import requests


def test_session(target):

    findings = []

    try:
        r = requests.get(target)

        for cookie in r.cookies:

            if not cookie.secure:
                findings.append({
                    "type": "Insecure Session Cookie",
                    "severity": "Medium",
                    "cookie": cookie.name
                })

    except Exception:
        pass

    return findings