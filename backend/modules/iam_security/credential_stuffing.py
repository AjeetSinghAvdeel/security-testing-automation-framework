import requests

USERNAMES = ["admin", "user", "test"]
PASSWORDS = ["admin", "password", "123456", "admin123"]


def test_credentials(target):

    results = []

    for user in USERNAMES:
        for password in PASSWORDS:

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

    return results