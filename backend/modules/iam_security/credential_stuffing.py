from __future__ import annotations

import time
from typing import Dict, Iterable, List, Tuple
from urllib.parse import urljoin

import requests

from backend.modules.local_lab import JuiceShopLab


USERNAMES = ["admin", "user", "test", "demo"]
PASSWORDS = ["admin", "password", "123456", "admin123", "demo123"]
JUICE_SHOP_CREDENTIALS = [
    ("admin@juice-sh.op", "admin123"),
    ("demo@juice-sh.op", "demo123"),
    ("jim@juice-sh.op", "ncc-1701"),
    ("bjoern@juice-sh.op", "Juice-Shop"),
]

LOGIN_PATHS = [
    "/login",
    "/api/login",
    "/user/login",
    "/authenticate",
    "/rest/user/login",
    "/session/login",
]

REGISTER_PATHS = [
    "/register",
    "/signup",
    "/api/register",
    "/api/signup",
    "/rest/user/signup",
]

LOGIN_FIELD_SETS = [
    ("username", "password"),
    ("email", "password"),
    ("login", "password"),
]

REGISTER_FIELD_SETS = [
    ("username", "password"),
    ("email", "password"),
]


def _base_url(target: str) -> str:
    return target.rstrip("/")


def _candidate_endpoints(target: str, paths: Iterable[str]) -> List[str]:
    base = _base_url(target)
    return [urljoin(f"{base}/", path.lstrip("/")) for path in paths]


def _submit_variants(
    session: requests.Session,
    endpoint: str,
    user_field: str,
    password_field: str,
    username: str,
    password: str,
    timeout: int = 3,
) -> List[Tuple[str, requests.Response]]:
    payload = {
        user_field: username,
        password_field: password,
    }
    responses: List[Tuple[str, requests.Response]] = []

    try:
        responses.append(("json", session.post(endpoint, json=payload, timeout=timeout, allow_redirects=False)))
    except Exception:
        pass

    try:
        responses.append(("form", session.post(endpoint, data=payload, timeout=timeout, allow_redirects=False)))
    except Exception:
        pass

    return responses


def _successful_auth(response: requests.Response) -> bool:
    body = response.text.lower()
    failure_markers = [
        "invalid",
        "incorrect",
        "unauthorized",
        "forbidden",
        "login failed",
        "wrong password",
    ]
    if any(marker in body for marker in failure_markers):
        return False

    return response.status_code in {200, 201, 202, 204, 302}


def _registration_accepted(response: requests.Response) -> bool:
    body = response.text.lower()
    rejection_markers = [
        "weak password",
        "password too short",
        "password must",
        "invalid password",
    ]
    if any(marker in body for marker in rejection_markers):
        return False

    return response.status_code in {200, 201, 202, 204, 302}


def test_credentials(target: str, attack_type: str | None = None) -> Dict[str, List[Dict]]:
    """Attempt common credential combinations against likely login endpoints."""
    results: List[Dict] = []
    actions: List[Dict] = []
    session = requests.Session()
    juice_shop = JuiceShopLab(target)

    if juice_shop.is_match():
        credentials_by_attack = {
            "password_strength": [("admin@juice-sh.op", "admin123")],
            "exposed_credentials": [("testing@juice-sh.op", "IamUsedForTesting")],
            "login_mc_safesearch": [("mc.safesearch@juice-sh.op", "Mr. N00dles")],
        }
        selected_credentials = credentials_by_attack.get(attack_type, JUICE_SHOP_CREDENTIALS)

        for username, password in selected_credentials:
            auth_result, action = juice_shop.login(username, password)
            actions.append(action)
            if auth_result:
                actions.extend(
                    juice_shop.verify_session(
                        auth_result["token"],
                        auth_result.get("basket_id"),
                    )
                )
                results.append(
                    {
                        "type": {
                            "password_strength": "Password Strength",
                            "exposed_credentials": "Exposed Credentials",
                            "login_mc_safesearch": "Login MC SafeSearch",
                        }.get(attack_type, "Credential Stuffing"),
                        "severity": "High",
                        "risk_score": 8.0,
                        "endpoint": action["endpoint"],
                        "method": "POST",
                        "username": username,
                        "description": f"Juice Shop accepted the credential pair for {auth_result['email']}.",
                    }
                )
                break

        return {"findings": results, "actions": actions}

    for endpoint in _candidate_endpoints(target, LOGIN_PATHS):
        for username in USERNAMES:
            for password in PASSWORDS:
                for user_field, password_field in LOGIN_FIELD_SETS:
                    for mode, response in _submit_variants(
                        session,
                        endpoint,
                        user_field,
                        password_field,
                        username,
                        password,
                    ):
                        if _successful_auth(response):
                            results.append(
                                {
                                    "type": "Credential Stuffing",
                                    "severity": "High",
                                    "risk_score": 8.0,
                                    "endpoint": endpoint,
                                    "method": "POST",
                                    "mode": mode,
                                    "username": username,
                                    "description": "Application accepted common credential",
                                }
                            )
                            actions.append(
                                {
                                    "action": "login_attempt",
                                    "endpoint": endpoint,
                                    "method": "POST",
                                    "outcome": "authenticated",
                                    "summary": f"Authenticated against {endpoint} as {username}.",
                                    "status_code": response.status_code,
                                }
                            )
                            return {"findings": results, "actions": actions}
                time.sleep(0.15)

    return {"findings": results, "actions": actions}


def test_bruteforce_protection(target: str, attack_type: str | None = None) -> Dict[str, List[Dict]]:
    """Detect missing lockout or rate limiting on repeated login attempts."""
    results: List[Dict] = []
    actions: List[Dict] = []
    session = requests.Session()
    juice_shop = JuiceShopLab(target)

    if juice_shop.is_match():
        blocked = False
        successful_login = None
        passwords = ["admin", "password", "123456", "admin123"]

        for password in passwords:
            auth_result, action = juice_shop.login("admin@juice-sh.op", password)
            actions.append(action)
            if action.get("status_code") in {403, 423, 429}:
                blocked = True
                break
            if auth_result:
                successful_login = auth_result
                break
            time.sleep(0.15)

        if not blocked:
            results.append(
                {
                    "type": "Missing Brute-force Protection",
                    "severity": "High",
                    "risk_score": 7.8,
                    "endpoint": action.get("endpoint") if actions else "/rest/user/login",
                    "description": "Repeated Juice Shop login attempts were not rate-limited or locked out.",
                }
            )

        if successful_login:
            actions.extend(
                juice_shop.verify_session(
                    successful_login["token"],
                    successful_login.get("basket_id"),
                )
            )
            results.append(
                {
                    "type": "Brute-force Login Success",
                    "severity": "High",
                    "risk_score": 8.4,
                    "endpoint": actions[-1]["endpoint"] if actions else "/rest/user/login",
                    "description": "Repeated password guessing led to an authenticated Juice Shop session.",
                }
            )

        return {"findings": results, "actions": actions}

    for endpoint in _candidate_endpoints(target, LOGIN_PATHS):
        blocked = False
        attempts = 0

        for user_field, password_field in LOGIN_FIELD_SETS:
            for _ in range(8):
                responses = _submit_variants(
                    session,
                    endpoint,
                    user_field,
                    password_field,
                    "admin",
                    "wrongpassword",
                )
                attempts += len(responses)
                for _, response in responses:
                    if response.status_code in {403, 423, 429}:
                        blocked = True
                        break
                if blocked:
                    break
                time.sleep(0.1)
            if blocked:
                break

        if attempts and not blocked:
            results.append(
                {
                    "type": "Missing Brute-force Protection",
                    "severity": "High",
                    "risk_score": 7.5,
                    "endpoint": endpoint,
                    "description": "Login endpoint did not rate-limit repeated failed attempts",
                }
            )
            return {"findings": results, "actions": actions}

    return {"findings": results, "actions": actions}


def test_password_policy(target: str, attack_type: str | None = None) -> Dict[str, List[Dict]]:
    """Check whether likely registration endpoints accept very weak passwords."""
    results: List[Dict] = []
    actions: List[Dict] = []
    session = requests.Session()

    for endpoint in _candidate_endpoints(target, REGISTER_PATHS):
        for user_field, password_field in REGISTER_FIELD_SETS:
            username_value = (
                f"weak-{int(time.time())}@local.lab"
                if user_field == "email"
                else f"weaktestuser{int(time.time())}"
            )

            for mode, response in _submit_variants(
                session,
                endpoint,
                user_field,
                password_field,
                username_value,
                "123",
            ):
                if _registration_accepted(response):
                    results.append(
                        {
                            "type": "Weak Password Policy",
                            "severity": "Medium",
                            "risk_score": 5.5,
                            "endpoint": endpoint,
                            "method": "POST",
                            "mode": mode,
                            "description": "Application accepted a very weak password",
                        }
                    )
                    actions.append(
                        {
                            "action": "registration_attempt",
                            "endpoint": endpoint,
                            "method": "POST",
                            "outcome": "accepted",
                            "summary": "Registration endpoint accepted a weak password.",
                            "status_code": response.status_code,
                        }
                    )
                    return {"findings": results, "actions": actions}

    return {"findings": results, "actions": actions}


def test_registration_validation(target: str, attack_type: str | None = None) -> Dict[str, List[Dict]]:
    results: List[Dict] = []
    actions: List[Dict] = []
    juice_shop = JuiceShopLab(target)

    if not juice_shop.is_match():
        return {"findings": results, "actions": actions}

    if attack_type == "empty_user_registration":
        probe = juice_shop.register_user(" ", " ")
        actions.append(probe["action"])
        response = probe["response"]
        if response is not None and response.status_code in {200, 201}:
            results.append(
                {
                    "type": "Empty User Registration",
                    "severity": "High",
                    "risk_score": 7.2,
                    "endpoint": probe["action"]["endpoint"],
                    "method": "POST",
                    "description": "Juice Shop accepted a registration with blank email and password fields.",
                }
            )

    return {"findings": results, "actions": actions}
