import requests
import time

USERNAMES = ["admin", "test"]
PASSWORDS = ["admin", "password", "123456"]


def test_credentials(target):

    results = []
    attempts = 0

    for user in USERNAMES:
        for password in PASSWORDS:

            attempts += 1

            try:
                r = requests.post(
                    f"{target}/login",
                    json={"username": user, "password": password},
                    timeout=3
                )

                if r.status_code == 200:
                    results.append({
                        "type": "Credential Stuffing",
                        "severity": "High",
                        "username": user,
                        "password": password
                    })

            except Exception:
                pass

            time.sleep(0.3)

    if attempts > 5:
        results.append({
            "type": "Rate Limit Missing",
            "severity": "Medium",
            "description": "Login endpoint does not appear to rate limit requests"
        })

    return results