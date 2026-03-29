from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urljoin

import requests


JUICE_SHOP_MARKERS = ("owasp juice shop", "juice shop")
JUICE_SHOP_LOGIN_PATH = "/rest/user/login"
JUICE_SHOP_WHOAMI_PATH = "/rest/user/whoami"
JUICE_SHOP_SEARCH_PATH = "/rest/products/search"
JUICE_SHOP_ADMIN_PATHS = [
    "/rest/admin/application-configuration",
    "/api/Users",
]
JUICE_SHOP_USERS_PATH = "/api/Users"
JUICE_SHOP_METRICS_PATH = "/metrics"


def normalize_target(target: str) -> str:
    return target if "://" in target else f"http://{target}"


def action_record(
    *,
    action: str,
    endpoint: str,
    method: str,
    outcome: str,
    summary: str,
    status_code: int | None = None,
    details: str | None = None,
) -> Dict[str, Any]:
    record = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "endpoint": endpoint,
        "method": method,
        "outcome": outcome,
        "summary": summary,
    }
    if status_code is not None:
        record["status_code"] = status_code
    if details:
        record["details"] = details
    return record


class JuiceShopLab:
    def __init__(self, target: str, timeout: int = 4) -> None:
        self.base_url = normalize_target(target).rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def is_match(self) -> bool:
        try:
            response = self.session.get(f"{self.base_url}/", timeout=self.timeout)
        except Exception:
            return False

        body = response.text.lower()
        return any(marker in body for marker in JUICE_SHOP_MARKERS)

    def login(self, email: str, password: str) -> Tuple[Dict[str, Any] | None, Dict[str, Any]]:
        endpoint = urljoin(f"{self.base_url}/", JUICE_SHOP_LOGIN_PATH.lstrip("/"))
        payload = {"email": email, "password": password}

        try:
            response = self.session.post(endpoint, json=payload, timeout=self.timeout)
        except Exception as exc:
            return None, action_record(
                action="login_attempt",
                endpoint=endpoint,
                method="POST",
                outcome="request_failed",
                summary=f"Login request for {email} could not be completed.",
                details=str(exc),
            )

        data = {}
        try:
            data = response.json()
        except Exception:
            data = {}

        auth = data.get("authentication") or {}
        token = auth.get("token")
        basket_id = auth.get("bid")
        if token:
            return {
                "token": token,
                "basket_id": basket_id,
                "email": auth.get("umail") or email,
                "status_code": response.status_code,
            }, action_record(
                action="login_attempt",
                endpoint=endpoint,
                method="POST",
                outcome="authenticated",
                status_code=response.status_code,
                summary=f"Authenticated against Juice Shop as {auth.get('umail') or email}.",
            )

        return None, action_record(
            action="login_attempt",
            endpoint=endpoint,
            method="POST",
            outcome="rejected",
            status_code=response.status_code,
            summary=f"Login was rejected for {email}.",
            details=(response.text[:180] or "").strip() or None,
        )

    def register_user(self, email: str, password: str, extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
        endpoint = urljoin(f"{self.base_url}/", JUICE_SHOP_USERS_PATH.lstrip("/"))
        payload = {"email": email, "password": password}
        if extra:
            payload.update(extra)

        try:
            response = self.session.post(endpoint, json=payload, timeout=self.timeout)
        except Exception as exc:
            return {
                "response": None,
                "action": action_record(
                    action="registration_attempt",
                    endpoint=endpoint,
                    method="POST",
                    outcome="request_failed",
                    summary=f"Registration request for {email!r} could not be completed.",
                    details=str(exc),
                ),
            }

        outcome = "accepted" if response.status_code in {200, 201} else "rejected"
        return {
            "response": response,
            "action": action_record(
                action="registration_attempt",
                endpoint=endpoint,
                method="POST",
                outcome=outcome,
                status_code=response.status_code,
                summary=f"Submitted a Juice Shop registration attempt for {email!r}.",
            ),
        }

    def verify_session(self, token: str, basket_id: Any = None) -> List[Dict[str, Any]]:
        headers = {"Authorization": f"Bearer {token}"}
        actions: List[Dict[str, Any]] = []

        whoami_endpoint = urljoin(f"{self.base_url}/", JUICE_SHOP_WHOAMI_PATH.lstrip("/"))
        try:
            whoami = self.session.get(whoami_endpoint, headers=headers, timeout=self.timeout)
            actions.append(
                action_record(
                    action="session_validation",
                    endpoint=whoami_endpoint,
                    method="GET",
                    outcome="authorized" if whoami.status_code == 200 else "denied",
                    status_code=whoami.status_code,
                    summary="Validated authenticated session against the user profile endpoint."
                    if whoami.status_code == 200
                    else "Authenticated session could not access the user profile endpoint.",
                )
            )
        except Exception as exc:
            actions.append(
                action_record(
                    action="session_validation",
                    endpoint=whoami_endpoint,
                    method="GET",
                    outcome="request_failed",
                    summary="Could not validate the authenticated session.",
                    details=str(exc),
                )
            )

        if basket_id:
            basket_endpoint = urljoin(f"{self.base_url}/", f"/rest/basket/{basket_id}".lstrip("/"))
            try:
                basket = self.session.get(basket_endpoint, headers=headers, timeout=self.timeout)
                actions.append(
                    action_record(
                        action="authenticated_feature_access",
                        endpoint=basket_endpoint,
                        method="GET",
                        outcome="authorized" if basket.status_code == 200 else "denied",
                        status_code=basket.status_code,
                        summary="Accessed the authenticated basket endpoint."
                        if basket.status_code == 200
                        else "Authenticated basket access was denied.",
                    )
                )
            except Exception as exc:
                actions.append(
                    action_record(
                        action="authenticated_feature_access",
                        endpoint=basket_endpoint,
                        method="GET",
                        outcome="request_failed",
                        summary="Could not open the authenticated basket endpoint.",
                        details=str(exc),
                    )
                )

        return actions

    def search(self, payload: str) -> Dict[str, Any]:
        endpoint = urljoin(f"{self.base_url}/", JUICE_SHOP_SEARCH_PATH.lstrip("/"))
        try:
            response = self.session.get(endpoint, params={"q": payload}, timeout=self.timeout)
        except Exception as exc:
            return {
                "response": None,
                "action": action_record(
                    action="search_probe",
                    endpoint=endpoint,
                    method="GET",
                    outcome="request_failed",
                    summary="Search probe could not be completed.",
                    details=str(exc),
                ),
            }

        return {
            "response": response,
            "action": action_record(
                action="search_probe",
                endpoint=f"{endpoint}?q={payload}",
                method="GET",
                outcome="completed",
                status_code=response.status_code,
                summary=f"Sent a search probe with payload: {payload}",
            ),
        }

    def metrics(self) -> Dict[str, Any]:
        endpoint = urljoin(f"{self.base_url}/", JUICE_SHOP_METRICS_PATH.lstrip("/"))
        try:
            response = self.session.get(endpoint, timeout=self.timeout)
        except Exception as exc:
            return {
                "response": None,
                "action": action_record(
                    action="metrics_probe",
                    endpoint=endpoint,
                    method="GET",
                    outcome="request_failed",
                    summary="Metrics endpoint could not be reached.",
                    details=str(exc),
                ),
            }

        return {
            "response": response,
            "action": action_record(
                action="metrics_probe",
                endpoint=endpoint,
                method="GET",
                outcome="authorized" if response.status_code == 200 else "denied",
                status_code=response.status_code,
                summary="Requested the Juice Shop metrics endpoint.",
            ),
        }

    def check_admin_endpoints(self, token: str | None = None) -> List[Dict[str, Any]]:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        actions: List[Dict[str, Any]] = []
        for path in JUICE_SHOP_ADMIN_PATHS:
            endpoint = urljoin(f"{self.base_url}/", path.lstrip("/"))
            try:
                response = self.session.get(endpoint, headers=headers, timeout=self.timeout)
                actions.append(
                    action_record(
                        action="admin_probe",
                        endpoint=endpoint,
                        method="GET",
                        outcome="authorized" if response.status_code == 200 else "denied",
                        status_code=response.status_code,
                        summary="Admin-oriented endpoint responded successfully."
                        if response.status_code == 200
                        else "Admin-oriented endpoint denied access.",
                    )
                )
            except Exception as exc:
                actions.append(
                    action_record(
                        action="admin_probe",
                        endpoint=endpoint,
                        method="GET",
                        outcome="request_failed",
                        summary="Admin-oriented endpoint could not be reached.",
                        details=str(exc),
                    )
                )
        return actions

    def read_basket(self, token: str, basket_id: Any) -> Dict[str, Any]:
        endpoint = urljoin(f"{self.base_url}/", f"/rest/basket/{basket_id}".lstrip("/"))
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = self.session.get(endpoint, headers=headers, timeout=self.timeout)
        except Exception as exc:
            return {
                "response": None,
                "action": action_record(
                    action="basket_probe",
                    endpoint=endpoint,
                    method="GET",
                    outcome="request_failed",
                    summary=f"Basket probe for basket {basket_id} could not be completed.",
                    details=str(exc),
                ),
            }

        return {
            "response": response,
            "action": action_record(
                action="basket_probe",
                endpoint=endpoint,
                method="GET",
                outcome="authorized" if response.status_code == 200 else "denied",
                status_code=response.status_code,
                summary=f"Requested basket {basket_id} with an authenticated session.",
            ),
        }


def summarize_actions(actions: Iterable[Dict[str, Any]]) -> str:
    total = 0
    authenticated = 0
    blocked = 0
    for action in actions:
        total += 1
        if action.get("outcome") == "authenticated":
            authenticated += 1
        if action.get("outcome") == "denied":
            blocked += 1

    fragments = [f"{total} actions performed"]
    if authenticated:
        fragments.append(f"{authenticated} authenticated sessions established")
    if blocked:
        fragments.append(f"{blocked} access checks denied")
    return ", ".join(fragments)
