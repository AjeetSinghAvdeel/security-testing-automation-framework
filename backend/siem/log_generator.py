"""
Log Generator - Creates standardized logs for SIEM integration
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List
import uuid
import socket

logger = logging.getLogger(__name__)

class LogGenerator:
    """Generates and sends logs to SIEM systems"""
    
    def __init__(self):
        self.log_format = "cef"  # Common Event Format
        self.es = None
        self.hostname = socket.gethostname()
        self.log_queue = []
        
    def generate_logs(self, test_results: Dict) -> List[Dict]:
        """
        Generate SIEM-compatible logs from test results
        """
        logs = []
        
        # Create main test log
        main_log = self.create_test_log(test_results)
        logs.append(main_log)
        
        # Create detailed finding logs
        for finding in test_results.get('vulnerabilities', []):
            finding_log = self.create_finding_log(test_results, finding)
            logs.append(finding_log)
        
        # Create alert logs for critical findings
        for finding in test_results.get('vulnerabilities', []):
            if finding.get('severity') in ['Critical', 'High']:
                alert_log = self.create_alert_log(test_results, finding)
                logs.append(alert_log)
        
        return logs
    
    def create_test_log(self, test_results: Dict) -> Dict:
        """Create main test execution log"""
        log_entry = {
            'event_id': str(uuid.uuid4()),
            'event_type': 'security_test',
            'timestamp': datetime.utcnow().isoformat(),
            'host': self.hostname,
            'source': 'security_testing_framework',
            'module': test_results.get('module', 'unknown'),
            'target': test_results.get('target', 'unknown'),
            'status': 'completed',
            'summary': test_results.get('summary', {}),
            'risk_level': test_results.get('summary', {}).get('risk_level', 'Low'),
            'mitre_id': test_results.get('summary', {}).get('mitre_mapping', ''),
            'tags': ['security_test', 'automated_scan']
        }
        
        # Add blockchain info if available
        if 'blockchain' in test_results:
            log_entry['blockchain_hash'] = test_results['blockchain'].get('evidence_hash')
            log_entry['blockchain_tx'] = test_results['blockchain'].get('transaction_hash')
        
        return log_entry
    
    def create_finding_log(self, test_results: Dict, finding: Dict) -> Dict:
        """Create detailed finding log"""
        log_entry = {
            'event_id': str(uuid.uuid4()),
            'event_type': 'vulnerability_finding',
            'timestamp': datetime.utcnow().isoformat(),
            'host': self.hostname,
            'source': 'security_testing_framework',
            'module': test_results.get('module', 'unknown'),
            'target': test_results.get('target', 'unknown'),
            'finding_type': finding.get('test', finding.get('payload', 'unknown')),
            'parameter': finding.get('parameter', finding.get('input_point', 'unknown')),
            'severity': self.map_severity(finding.get('confidence', 0.5)),
            'confidence': finding.get('confidence', 0.5),
            'evidence': finding.get('evidence', ''),
            'remediation': self.get_remediation(finding),
            'tags': ['vulnerability', 'finding']
        }
        
        return log_entry
    
    def create_alert_log(self, test_results: Dict, finding: Dict) -> Dict:
        """Create alert log for critical findings"""
        log_entry = {
            'event_id': str(uuid.uuid4()),
            'event_type': 'security_alert',
            'timestamp': datetime.utcnow().isoformat(),
            'host': self.hostname,
            'source': 'security_testing_framework',
            'alert_type': 'high_risk_vulnerability',
            'module': test_results.get('module', 'unknown'),
            'target': test_results.get('target', 'unknown'),
            'finding': finding.get('test', finding.get('payload', 'unknown')),
            'severity': 'High',
            'risk_score': self.calculate_risk_score(finding),
            'tags': ['alert', 'high_risk']
        }
        
        return log_entry
    
    def map_severity(self, confidence: float) -> str:
        """Map confidence to severity level"""
        if confidence >= 0.8:
            return "Critical"
        elif confidence >= 0.6:
            return "High"
        elif confidence >= 0.4:
            return "Medium"
        elif confidence >= 0.2:
            return "Low"
        else:
            return "Info"
    
    def calculate_risk_score(self, finding: Dict) -> float:
        """Calculate risk score (0-10)"""
        base_score = finding.get('confidence', 0.5) * 10
        return min(round(base_score, 1), 10.0)
    
    def get_remediation(self, finding: Dict) -> str:
        """Get remediation advice"""
        finding_type = finding.get('test', '').lower()
        
        remediations = {
            'sql': 'Implement parameterized queries and input validation',
            'xss': 'Implement output encoding and Content-Security-Policy',
            'jwt': 'Validate JWT signatures and implement proper expiration',
            'auth': 'Implement multi-factor authentication and rate limiting',
            'mqtt': 'Enable MQTT authentication and TLS encryption',
            'default': 'Review and fix the identified vulnerability'
        }
        
        for key, remediation in remediations.items():
            if key in finding_type:
                return remediation
        
        return remediations['default']
    
    def send_to_siem(self, logs: List[Dict]):
        """Send logs to SIEM (simulated)"""
        logger.info(f"Processing {len(logs)} logs for SIEM")
        self.log_queue.extend(logs)
    
    def write_to_file(self, log: Dict):
        """Write log to file as backup"""
        try:
            log_file = f"logs/siem_logs_{datetime.now().strftime('%Y%m%d')}.json"
            
            with open(log_file, 'a') as f:
                f.write(json.dumps(log) + '\n')
                
        except Exception as e:
            logger.error(f"Error writing log to file: {str(e)}")
    
    def get_log_statistics(self) -> Dict:
        """Get log statistics"""
        return {
            'total_logs_generated': len(self.log_queue),
            'queued_logs': len(self.log_queue),
            'elasticsearch_connected': False,
            'last_log_time': datetime.now().isoformat()
        }

# Singleton instance
log_generator = LogGenerator()
