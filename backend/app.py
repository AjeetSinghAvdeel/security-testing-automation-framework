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
from backend.core.result_processor import result_processor
from backend.blockchain.blockchain_auditor import blockchain_auditor
from backend.siem.log_generator import log_generator

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')

# Enable CORS
CORS(app)

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===== Authentication =====

def token_required(f):
    """Decorator to require authentication token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            # For demo purposes, allow without token
            return f(*args, **kwargs)
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

# ===== Health Check =====

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0',
        'blockchain': blockchain_auditor.get_statistics(),
        'siem': log_generator.get_log_statistics()
    })

# ===== Dashboard Endpoints =====

@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def get_dashboard_stats():
    """Get dashboard statistics"""
    all_tests = engine.get_all_tests()
    
    stats = {
        'totalTests': len(all_tests),
        'totalVulnerabilities': sum(
            len(test.get('results', {}).get('vulnerabilities', []))
            for test in all_tests
        ),
        'criticalCount': sum(
            1 for test in all_tests
            for vuln in test.get('results', {}).get('vulnerabilities', [])
            if vuln.get('severity') == 'Critical'
        ),
        'blockchainRecords': 0,
        'siemAlerts': 0,
        'riskDistribution': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
    }
    
    return jsonify(stats)

@app.route('/api/tests/recent', methods=['GET'])
@token_required
def get_recent_tests():
    """Get recent tests"""
    all_tests = engine.get_all_tests()
    
    recent = []
    for test in all_tests[-10:]:
        recent.append({
            'test_id': test.get('test_id'),
            'module': test.get('config', {}).get('module'),
            'target': test.get('config', {}).get('target', {}).get('url'),
            'findings': len(test.get('results', {}).get('vulnerabilities', [])),
            'status': test.get('status'),
            'severity': 'Medium',
            'timestamp': test.get('created_at')
        })
    
    return jsonify(recent)

# ===== Module Endpoints =====

@app.route('/api/modules', methods=['GET'])
@token_required
def list_modules():
    """List available modules"""
    modules = module_manager.list_modules()
    
    return jsonify({
        'modules': modules,
        'total': len(modules)
    })

@app.route('/api/modules/<module_name>', methods=['GET'])
@token_required
def get_module_info(module_name):
    """Get module information"""
    info = module_manager.get_module_info(module_name)
    capabilities = module_manager.get_module_capabilities(module_name)
    
    return jsonify({
        'module': info,
        'capabilities': capabilities
    })

# ===== Test Endpoints =====

@app.route('/api/tests/run', methods=['POST'])
@token_required
def run_test():
    """Run a security test"""
    data = request.get_json()
    
    # Validate input
    if not data.get('module') or not data.get('target'):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        # Schedule test
        test_id = engine.schedule_test({
            'module': data.get('module'),
            'test': data.get('test'),
            'target': data.get('target'),
            'intensity': data.get('intensity', 'medium'),
            'blockchain': data.get('blockchain', True),
            'siem': data.get('siem', True)
        })
        
        # Emit WebSocket event
        socketio.emit('test_scheduled', {'test_id': test_id})
        
        logger.info(f"Test {test_id} scheduled")
        
        return jsonify({
            'test_id': test_id,
            'status': 'queued',
            'estimated_time': 30
        }), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/tests/status/<test_id>', methods=['GET'])
@token_required
def get_test_status(test_id):
    """Get test status"""
    status = engine.get_test_status(test_id)
    
    if not status:
        return jsonify({'error': 'Test not found'}), 404
    
    return jsonify(status)

@app.route('/api/tests/<test_id>', methods=['GET'])
@token_required
def get_test_results(test_id):
    """Get test results"""
    test = engine.get_test_status(test_id)
    
    if not test:
        return jsonify({'error': 'Test not found'}), 404
    
    return jsonify(test)

@app.route('/api/tests', methods=['GET'])
@token_required
def list_tests():
    """List all tests"""
    tests = engine.get_all_tests()
    
    return jsonify({
        'tests': tests,
        'total': len(tests)
    })

# ===== SIEM Endpoints =====

@app.route('/api/siem/alerts', methods=['GET'])
@token_required
def get_siem_alerts():
    """Get SIEM alerts"""
    limit = request.args.get('limit', default=100, type=int)
    severity = request.args.get('severity')
    
    # Return simulated alert data
    return jsonify({
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'logs': [],
        'total': 0
    })

@app.route('/api/siem/logs', methods=['GET'])
@token_required
def get_siem_logs():
    """Get SIEM logs"""
    limit = request.args.get('limit', default=100, type=int)
    
    return jsonify({
        'logs': log_generator.log_queue[-limit:],
        'total': len(log_generator.log_queue),
        'page': 1
    })

# ===== Blockchain Endpoints =====

@app.route('/api/blockchain/status', methods=['GET'])
@token_required
def get_blockchain_status():
    """Get blockchain status"""
    stats = blockchain_auditor.get_statistics()
    
    return jsonify(stats)

@app.route('/api/blockchain/records', methods=['GET'])
@token_required
def get_blockchain_records():
    """Get blockchain records"""
    limit = request.args.get('limit', default=100, type=int)
    
    # Return empty records for now
    return jsonify([])

@app.route('/api/blockchain/verify/<hash_value>', methods=['GET'])
@token_required
def verify_blockchain_hash(hash_value):
    """Verify evidence on blockchain"""
    # Simulated verification
    return jsonify({
        'hash': hash_value,
        'exists': False,
        'verified': False
    })

# ===== Report Endpoints =====

@app.route('/api/reports/generate/<report_type>', methods=['POST'])
@token_required
def generate_report(report_type):
    """Generate security report"""
    try:
        # Get recent tests
        tests = engine.get_all_tests()
        
        if report_type == 'pentest':
            filename = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        elif report_type == 'compliance':
            filename = f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        elif report_type == 'blockchain':
            filename = f"blockchain_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        else:
            return jsonify({'error': 'Invalid report type'}), 400
        
        report_path = f"reports/generated/{filename}"
        
        # Create simple text report for now
        with open(report_path, 'w') as f:
            f.write(f"Security Report - {report_type}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Total Tests: {len(tests)}\n")
        
        return send_file(report_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ===== Configuration Endpoints =====

@app.route('/api/config/safety', methods=['GET'])
@token_required
def get_safety_config():
    """Get safety configuration"""
    return jsonify(safety_checker.get_safety_report())

# ===== WebSocket Events =====

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {'data': 'Connected to server'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('subscribe_test')
def handle_subscribe_test(data):
    """Subscribe to test updates"""
    test_id = data.get('test_id')
    logger.info(f"Subscribed to test: {test_id}")
    emit('subscribed', {'test_id': test_id})

# ===== Error Handlers =====

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

@app.before_request
def log_request():
    """Log incoming requests"""
    logger.debug(f"{request.method} {request.path}")

# ===== Main =====

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('reports/generated', exist_ok=True)
    
    # Run the application
    logger.info("Starting IoT & Web Security Testing Framework")
    
    # Use socketio.run() for SocketIO support
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
