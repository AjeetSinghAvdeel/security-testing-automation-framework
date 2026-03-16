"""
Firebase-backed storage for scan records.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
import threading

try:
    import firebase_admin
    from firebase_admin import auth, credentials, firestore
except Exception:  # pragma: no cover - dependency may be absent in some environments
    firebase_admin = None
    auth = None
    credentials = None
    firestore = None


class FirebaseStore:
    def __init__(self) -> None:
        self._client = None
        self._lock = threading.Lock()
        self._init_error: str | None = None
        self._key_path = Path(__file__).resolve().parent / "firebase_key.json"

    @property
    def enabled(self) -> bool:
        return self.client is not None

    @property
    def client(self):
        if self._client is not None:
            return self._client

        with self._lock:
            if self._client is not None:
                return self._client

            if firebase_admin is None or credentials is None or firestore is None:
                self._init_error = "firebase-admin dependency not installed"
                return None

            if not self._key_path.exists():
                self._init_error = f"missing service account file: {self._key_path.name}"
                return None

            try:
                app = firebase_admin.get_app()
            except ValueError:
                app = firebase_admin.initialize_app(
                    credentials.Certificate(str(self._key_path))
                )

            try:
                self._client = firestore.client(app=app)
            except Exception as exc:
                self._init_error = str(exc)
                self._client = None

        return self._client

    @property
    def init_error(self) -> str | None:
        _ = self.client
        return self._init_error

    def verify_token(self, token: str) -> Dict[str, Any] | None:
        client = self.client
        if client is None or auth is None:
            return None

        try:
            decoded = auth.verify_id_token(token)
            return {
                "uid": decoded.get("uid"),
                "email": decoded.get("email"),
                "name": decoded.get("name") or decoded.get("email") or "User",
                "picture": decoded.get("picture"),
            }
        except Exception:
            return None

    def save_test(self, test: Dict[str, Any]) -> None:
        client = self.client
        if client is None:
            return

        payload = dict(test)
        payload["updated_at"] = datetime.utcnow().isoformat()
        client.collection("scans").document(test["test_id"]).set(payload)

    def get_test(self, user_id: str, test_id: str) -> Dict[str, Any] | None:
        client = self.client
        if client is None:
            return None

        document = client.collection("scans").document(test_id).get()
        if not document.exists:
            return None
        payload = document.to_dict()
        if payload.get("user_id") != user_id:
            return None
        return payload

    def list_tests(self, user_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        client = self.client
        if client is None:
            return []

        query = client.collection("scans").where("user_id", "==", user_id)
        tests = [document.to_dict() for document in query.stream()]
        tests.sort(key=lambda item: item.get("created_at") or "", reverse=True)
        return tests[:limit]

    def get_stats(self, user_id: str) -> Dict[str, int]:
        tests = self.list_tests(user_id=user_id, limit=100)
        findings = [finding for test in tests for finding in test.get("results", [])]

        stats = {
            "totalTests": len(tests),
            "totalVulnerabilities": len(
                [finding for finding in findings if finding.get("vulnerability")]
            ),
            "criticalCount": 0,
            "highCount": 0,
            "mediumCount": 0,
            "lowCount": 0,
        }

        for finding in findings:
            severity = finding.get("severity")
            if severity == "Critical":
                stats["criticalCount"] += 1
            elif severity == "High":
                stats["highCount"] += 1
            elif severity == "Medium":
                stats["mediumCount"] += 1
            elif severity == "Low":
                stats["lowCount"] += 1

        return stats


firebase_store = FirebaseStore()
