"""
Result Processor - Processes and formats test results
"""

import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)

class ResultProcessor:
    """Processes security testing results"""
    
    def __init__(self):
        self.severity_levels = {
            'Critical': 9.0,
            'High': 7.0,
            'Medium': 5.0,
            'Low': 3.0,
            'Info': 1.0
        }
    
    def process(self, raw_results: Dict) -> Dict:
        """
        Process raw test results into standardized format
        """
        processed = {
            'test_id': raw_results.get('test_id'),
            'module': raw_results.get('module'),
            'target': raw_results.get('target'),
            'timestamp': datetime.now().isoformat(),
            'summary': self.generate_summary(raw_results),
            'findings': self.process_findings(raw_results.get('vulnerabilities', [])),
            'metadata': self.extract_metadata(raw_results)
        }
        
        return processed
    
    def generate_summary(self, results: Dict) -> Dict:
        """Generate test summary"""
        vulns = results.get('vulnerabilities', [])
        
        summary = {
            'total_tests': results.get('total_tests', 0),
            'vulnerabilities_found': len(vulns),
            'critical_count': sum(1 for v in vulns if v.get('severity') == 'Critical'),
            'high_count': sum(1 for v in vulns if v.get('severity') == 'High'),
            'medium_count': sum(1 for v in vulns if v.get('severity') == 'Medium'),
            'low_count': sum(1 for v in vulns if v.get('severity') == 'Low'),
            'overall_risk': self.calculate_risk_score(vulns)
        }
        
        return summary
    
    def process_findings(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Process vulnerability findings"""
        processed_findings = []
        
        for vuln in vulnerabilities:
            finding = {
                'type': vuln.get('payload', vuln.get('test')),
                'severity': self.determine_severity(vuln),
                'confidence': vuln.get('confidence', 0.5),
                'target': vuln.get('parameter', vuln.get('input_point')),
                'evidence': vuln.get('evidence'),
                'mitre_id': vuln.get('mitre_id'),
                'remediation': self.get_remediation(vuln)
            }
            processed_findings.append(finding)
        
        return processed_findings
    
    def determine_severity(self, vuln: Dict) -> str:
        """Determine severity level from confidence"""
        confidence = vuln.get('confidence', 0)
        
        if confidence >= 0.8:
            return 'Critical'
        elif confidence >= 0.6:
            return 'High'
        elif confidence >= 0.4:
            return 'Medium'
        elif confidence >= 0.2:
            return 'Low'
        else:
            return 'Info'
    
    def calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score"""
        if not vulnerabilities:
            return 0.0
        
        severity_scores = [
            self.severity_levels.get(v.get('severity', 'Low'), 0)
            for v in vulnerabilities
        ]
        
        # Average severity multiplied by vulnerability count
        avg_severity = sum(severity_scores) / len(severity_scores) if severity_scores else 0
        risk_score = min(avg_severity * (len(vulnerabilities) / 5), 10.0)
        
        return round(risk_score, 2)
    
    def extract_metadata(self, results: Dict) -> Dict:
        """Extract test metadata"""
        return {
            'duration': results.get('duration'),
            'module_version': results.get('module_version'),
            'tester': results.get('tester'),
            'notes': results.get('notes', '')
        }
    
    def get_remediation(self, vuln: Dict) -> str:
        """Get remediation advice"""
        vuln_type = str(vuln.get('test', '')).lower()
        
        remediations = {
            'sqli': 'Implement parameterized queries and input validation',
            'xss': 'Implement output encoding and Content-Security-Policy',
            'jwt': 'Validate JWT signatures and implement proper expiration',
            'auth': 'Implement multi-factor authentication and rate limiting',
            'mqtt': 'Enable MQTT authentication and TLS encryption',
            'credential': 'Implement account lockout and rate limiting',
            'default': 'Review and fix the identified vulnerability'
        }
        
        for key, remediation in remediations.items():
            if key in vuln_type:
                return remediation
        
        return remediations['default']

# Singleton instance
result_processor = ResultProcessor()
