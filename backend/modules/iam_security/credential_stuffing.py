import requests
import time

USERNAMES = ["admin", "user", "test"]
PASSWORDS = ["admin", "password", "123456", "admin123"]


def test_credentials(target):
    """
    Attempt common credential combinations
    """

    results = []

    for username in USERNAMES:
        for password in PASSWORDS:

            try:
                response = requests.post(
                    f"{target}/login",
                    json={
                        "username": username,
                        "password": password
                    },
                    timeout=3
                )

                if response.status_code == 200:
                    results.append({
                        "type": "Credential Stuffing",
                        "severity": "High",
                        "risk_score": 8.0,
                        "username": username,
                        "password": password,
                        "description": "Application accepted common credential"
                    })

            except Exception:
                pass

            time.sleep(0.3)

    return results


def test_bruteforce_protection(target):
    """
    Detect if login endpoint blocks repeated attempts
    """

    results = []
    blocked = False

    try:
        for _ in range(10):

            response = requests.post(
                f"{target}/login",
                json={
                    "username": "admin",
                    "password": "wrongpassword"
                },
                timeout=3
            )

            if response.status_code == 429:
                blocked = True

        if not blocked:
            results.append({
                "type": "Missing Brute-force Protection",
                "severity": "High",
                "risk_score": 7.5,
                "description": "Login endpoint does not rate-limit repeated attempts"
            })

    except Exception:
        pass

    return results


def test_password_policy(target):
    """
    Check if system accepts extremely weak passwords
    """

    results = []

    try:
        response = requests.post(
            f"{target}/register",
            json={
                "username": "weaktestuser",
                "password": "123"
            },
            timeout=3
        )

        if response.status_code == 200:
            results.append({
                "type": "Weak Password Policy",
                "severity": "Medium",
                "risk_score": 5.5,
                "description": "Application accepted a very weak password"
            })

    except Exception:
        pass

    return results