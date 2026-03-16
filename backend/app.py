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

    if not target:
        return jsonify({"error": "Target is required"}), 400

    if not validate_target(target):
        return jsonify({"error": "Unsafe target blocked by safety checker"}), 400

    modules = module_manager.load_modules()
    test = engine.create_test(target, modules, user)
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
