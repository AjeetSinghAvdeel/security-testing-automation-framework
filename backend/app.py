"""
Flask API for the core scan engine and dashboard.
"""

from __future__ import annotations

from flask import Flask, jsonify, request
from flask_cors import CORS

from backend.core.engine import engine
from backend.core.module_manager import module_manager
from backend.core.safety_checker import validate_target


app = Flask(__name__)
CORS(app)


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
    return jsonify(test), 201


@app.route("/api/tests/status/<test_id>", methods=["GET"])
def get_test_status(test_id: str):
    test = engine.get_test_status(test_id)
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
    tests = engine.get_all_tests()
    findings = [finding for test in tests for finding in test.get("results", [])]

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        severity = finding.get("severity")
        if severity in severity_counts:
            severity_counts[severity] += 1

    return jsonify(
        {
            "totalTests": len(tests),
            "totalVulnerabilities": len(
                [finding for finding in findings if finding.get("vulnerability")]
            ),
            "criticalCount": severity_counts["Critical"],
            "highCount": severity_counts["High"],
            "mediumCount": severity_counts["Medium"],
            "lowCount": severity_counts["Low"],
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
