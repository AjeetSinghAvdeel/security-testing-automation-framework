"""
Flask API for the core scan engine and dashboard.
"""

from __future__ import annotations

from functools import wraps

from flask import Flask, jsonify, request
from flask_cors import CORS

from backend.core.engine import engine
from backend.core.module_manager import module_manager
from backend.core.safety_checker import validate_target
from backend.blockchain.blockchain_auditor import blockchain_auditor
from backend.firebase_store import firebase_store


app = Flask(__name__)
CORS(app)
engine.set_store(firebase_store)

ATTACK_PROFILES = {
    "full_assessment": {
        "modules": ["web_security", "iam_security", "iot_security"],
        "tests": [],
        "attack_type": "full_assessment",
    },
    "credential_stuffing": {
        "modules": ["iam_security"],
        "tests": ["credential_stuffing"],
        "attack_type": "credential_stuffing",
    },
    "password_strength": {
        "modules": ["iam_security"],
        "tests": ["credential_stuffing"],
        "attack_type": "password_strength",
    },
    "exposed_credentials": {
        "modules": ["iam_security"],
        "tests": ["credential_stuffing"],
        "attack_type": "exposed_credentials",
    },
    "login_mc_safesearch": {
        "modules": ["iam_security"],
        "tests": ["credential_stuffing"],
        "attack_type": "login_mc_safesearch",
    },
    "bruteforce": {
        "modules": ["iam_security"],
        "tests": ["bruteforce"],
        "attack_type": "bruteforce",
    },
    "login_admin_sqli": {
        "modules": ["web_security"],
        "tests": ["sqli"],
        "attack_type": "login_admin_sqli",
    },
    "union_search_injection": {
        "modules": ["web_security"],
        "tests": ["sqli"],
        "attack_type": "union_search_injection",
    },
    "reflected_xss": {
        "modules": ["web_security"],
        "tests": ["xss"],
        "attack_type": "reflected_xss",
    },
    "admin_section": {
        "modules": ["iam_security"],
        "tests": ["rbac"],
        "attack_type": "admin_section",
    },
    "view_basket": {
        "modules": ["iam_security"],
        "tests": ["rbac"],
        "attack_type": "view_basket",
    },
    "application_configuration": {
        "modules": ["web_security"],
        "tests": ["auth_bypass"],
        "attack_type": "application_configuration",
    },
    "empty_user_registration": {
        "modules": ["iam_security"],
        "tests": ["registration_validation"],
        "attack_type": "empty_user_registration",
    },
    "exposed_metrics": {
        "modules": ["web_security"],
        "tests": ["observability"],
        "attack_type": "exposed_metrics",
    },
    "session_authz": {
        "modules": ["iam_security"],
        "tests": ["rbac", "session"],
        "attack_type": "session_authz",
    },
    "web_inputs": {
        "modules": ["web_security"],
        "tests": ["sqli", "xss", "auth_bypass", "observability"],
        "attack_type": "web_inputs",
    },
    "iot_protocols": {
        "modules": ["iot_security"],
        "tests": [],
        "attack_type": "iot_protocols",
    },
}


def require_user(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(" ", 1)[1].strip()
        user = firebase_store.verify_token(token) if firebase_store.enabled else None
        if not user:
            return jsonify({"error": "Invalid or expired token"}), 401

        return handler(user, *args, **kwargs)

    return wrapped


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify(
        {
            "status": "ok",
            "modules": module_manager.get_loaded_modules(),
            "firebase": {
                "enabled": firebase_store.enabled,
                "error": firebase_store.init_error,
            },
            "blockchain": blockchain_auditor.get_statistics(),
        }
    )


@app.route("/api/tests/run", methods=["POST"])
@require_user
def run_test(user):
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()
    attack_profile = (payload.get("attackProfile") or "full_assessment").strip()
    profile_config = ATTACK_PROFILES.get(attack_profile)

    if not target:
        return jsonify({"error": "Target is required"}), 400

    if profile_config is None:
        return jsonify({"error": "Unknown attack profile"}), 400

    if not validate_target(target):
        return jsonify({"error": "Unsafe target blocked by safety checker"}), 400

    modules = module_manager.load_modules(profile=attack_profile)
    test = engine.create_test(
        target,
        modules,
        user,
        scan_options={
            "attack_profile": attack_profile,
            "tests": profile_config["tests"],
            "attack_type": profile_config["attack_type"],
            "jwt_token": (payload.get("jwtToken") or "").strip() or None,
        },
    )
    return jsonify(test), 202


@app.route("/api/tests", methods=["GET"])
@require_user
def list_tests(user):
    tests = firebase_store.list_tests(user_id=user["uid"], limit=25) if firebase_store.enabled else [
        test for test in engine.get_all_tests() if test.get("user_id") == user["uid"]
    ]
    return jsonify({"tests": tests})


@app.route("/api/tests/status/<test_id>", methods=["GET"])
@require_user
def get_test_status(user, test_id: str):
    test = engine.get_test_status(test_id)
    if test and engine.get_test(test_id) and engine.get_test(test_id).get("user_id") != user["uid"]:
        test = None
    if not test:
        stored_test = firebase_store.get_test(user["uid"], test_id) if firebase_store.enabled else None
        if stored_test:
            test = {
                "test_id": stored_test["test_id"],
                "status": stored_test["status"],
                "target": stored_test["target"],
                "result_count": stored_test.get("result_count", 0),
            }
    if not test:
        return jsonify({"error": "Test not found"}), 404
    return jsonify(test)


@app.route("/api/tests/<test_id>", methods=["GET"])
@require_user
def get_test(user, test_id: str):
    test = engine.get_test(test_id)
    if test and test.get("user_id") != user["uid"]:
        test = None
    if not test and firebase_store.enabled:
        test = firebase_store.get_test(user["uid"], test_id)
    if not test:
        return jsonify({"error": "Test not found"}), 404
    return jsonify(test)


@app.route("/api/modules", methods=["GET"])
def get_modules():
    return jsonify({"modules": module_manager.get_loaded_modules()})


@app.route("/api/dashboard/stats", methods=["GET"])
@require_user
def get_dashboard_stats(user):
    if firebase_store.enabled:
        stats = firebase_store.get_stats(user_id=user["uid"])
        stats["blockchainRecords"] = len(blockchain_auditor.evidence_records)
        stats["blockchainConnected"] = blockchain_auditor.connected
        return jsonify(stats)

    tests = [test for test in engine.get_all_tests() if test.get("user_id") == user["uid"]]
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
        "blockchainRecords": len(blockchain_auditor.evidence_records),
        "blockchainConnected": blockchain_auditor.connected,
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
    return jsonify(stats)


@app.route("/api/blockchain/status", methods=["GET"])
@require_user
def get_blockchain_status(_user):
    return jsonify(blockchain_auditor.get_statistics())


@app.route("/api/blockchain/records", methods=["GET"])
@require_user
def get_blockchain_records(user):
    user_tests = (
        firebase_store.list_tests(user_id=user["uid"], limit=100)
        if firebase_store.enabled
        else [test for test in engine.get_all_tests() if test.get("user_id") == user["uid"]]
    )
    allowed_hashes = {test.get("evidence_hash") for test in user_tests}
    records = [
        record for record in blockchain_auditor.evidence_records if record.get("hash") in allowed_hashes
    ]
    return jsonify({"records": records})


@app.route("/api/auth/session", methods=["GET"])
@require_user
def get_session(user):
    return jsonify({"user": user})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
