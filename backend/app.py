"""
Flask API for the core scan engine and dashboard.
"""

from __future__ import annotations

from flask import Flask, jsonify, request
from flask_cors import CORS

from backend.core.engine import engine
from backend.core.module_manager import module_manager
from backend.core.safety_checker import validate_target
from backend.firebase_store import firebase_store


app = Flask(__name__)
CORS(app)
engine.set_store(firebase_store)


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
        }
    )


@app.route("/api/tests/run", methods=["POST"])
def run_test():
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()

    if not target:
        return jsonify({"error": "Target is required"}), 400

    if not validate_target(target):
        return jsonify({"error": "Unsafe target blocked by safety checker"}), 400

    modules = module_manager.load_modules()
    test = engine.create_test(target, modules)
    return jsonify(test), 202


@app.route("/api/tests", methods=["GET"])
def list_tests():
    tests = firebase_store.list_tests(limit=25) if firebase_store.enabled else engine.get_all_tests()
    return jsonify({"tests": tests})


@app.route("/api/tests/status/<test_id>", methods=["GET"])
def get_test_status(test_id: str):
    test = engine.get_test_status(test_id)
    if not test:
        stored_test = firebase_store.get_test(test_id) if firebase_store.enabled else None
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
def get_test(test_id: str):
    test = engine.get_test(test_id)
    if not test:
        return jsonify({"error": "Test not found"}), 404
    return jsonify(test)


@app.route("/api/modules", methods=["GET"])
def get_modules():
    return jsonify({"modules": module_manager.get_loaded_modules()})


@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    if firebase_store.enabled:
        return jsonify(firebase_store.get_stats())

    tests = engine.get_all_tests()
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
    return jsonify(stats)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
