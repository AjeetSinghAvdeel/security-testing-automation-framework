"""
Flask Application - IoT & Web Security Testing Framework
"""

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import logging
from datetime import datetime
from functools import wraps
import jwt

# Import core modules
from backend.core.engine import engine
from backend.core.safety_checker import safety_checker
from backend.core.module_manager import module_manager
from backend.blockchain.blockchain_auditor import blockchain_auditor
from backend.siem.log_generator import log_generator

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')

CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================
# AUTH
# =============================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return f(*args, **kwargs)

        try:
            if token.startswith('Bearer '):
                token = token[7:]
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'error': 'Invalid token'}), 401

        return f(*args, **kwargs)
    return decorated


# =============================
# HEALTH
# =============================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'blockchain': blockchain_auditor.get_statistics(),
        'siem': {
            'total_logs': len(log_generator.log_queue)
        }
    })


# =============================
# DASHBOARD
# =============================

@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def get_dashboard_stats():

    all_tests = engine.get_all_tests()

    total_vulns = 0
    critical = 0
    high = 0
    medium = 0
    low = 0

    for test in all_tests:
        results = test.get("results", {})
        findings = results.get("findings", [])

        for vuln in findings:
            total_vulns += 1
            severity = vuln.get("severity")

            if severity == "Critical":
                critical += 1
            elif severity == "High":
                high += 1
            elif severity == "Medium":
                medium += 1
            elif severity == "Low":
                low += 1

    stats = {
        'totalTests': len(all_tests),
        'totalVulnerabilities': total_vulns,
        'criticalCount': critical,
        'blockchainRecords': len(blockchain_auditor.evidence_records),
        'siemAlerts': len(log_generator.log_queue),
        'riskDistribution': {
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low
        }
    }

    return jsonify(stats)


# =============================
# TEST ENDPOINTS
# =============================

@app.route('/api/tests/run', methods=['POST'])
@token_required
def run_test():

    data = request.get_json()

    if not data.get('module') or not data.get('test') or not data.get('target'):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        test_id = engine.schedule_test({
            'module': data.get('module'),
            'test': data.get('test'),
            'target': data.get('target'),
            'intensity': data.get('intensity', 'medium'),
            'blockchain': data.get('blockchain', True),
            'siem': data.get('siem', True)
        })

        socketio.emit('test_scheduled', {'test_id': test_id})

        return jsonify({
            'test_id': test_id,
            'status': 'running'
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/tests', methods=['GET'])
@token_required
def list_tests():
    return jsonify({
        'tests': engine.get_all_tests(),
        'total': len(engine.get_all_tests())
    })


@app.route('/api/tests/<test_id>', methods=['GET'])
@token_required
def get_test_results(test_id):
    test = engine.get_test_status(test_id)
    if not test:
        return jsonify({'error': 'Test not found'}), 404
    return jsonify(test)


# =============================
# SIEM
# =============================

@app.route('/api/siem/alerts', methods=['GET'])
@token_required
def get_siem_alerts():

    alerts = log_generator.log_queue

    critical = sum(1 for log in alerts if log.get("severity") == "Critical")
    high = sum(1 for log in alerts if log.get("severity") == "High")
    medium = sum(1 for log in alerts if log.get("severity") == "Medium")
    low = sum(1 for log in alerts if log.get("severity") == "Low")

    return jsonify({
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'logs': alerts,
        'total': len(alerts)
    })


# =============================
# BLOCKCHAIN
# =============================

@app.route('/api/blockchain/status', methods=['GET'])
@token_required
def get_blockchain_status():
    return jsonify(blockchain_auditor.get_statistics())


@app.route('/api/blockchain/records', methods=['GET'])
@token_required
def get_blockchain_records():
    return jsonify(blockchain_auditor.evidence_records)


@app.route('/api/blockchain/verify/<hash_value>', methods=['GET'])
@token_required
def verify_blockchain_hash(hash_value):

    exists = any(
        record["hash"] == hash_value
        for record in blockchain_auditor.evidence_records
    )

    return jsonify({
        'hash': hash_value,
        'exists': exists,
        'verified': exists
    })


# =============================
# MAIN
# =============================

if __name__ == '__main__':
    os.makedirs('logs', exist_ok=True)
    os.makedirs('reports/generated', exist_ok=True)

    logger.info("Starting IoT & Web Security Testing Framework")

    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)