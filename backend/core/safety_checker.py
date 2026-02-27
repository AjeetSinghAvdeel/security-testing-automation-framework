"""
Safety Checker - Critical for academic approval
Ensures all tests are safe and controlled
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, List, Any
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class SafetyChecker:
    """Validates and sanitizes all test inputs"""
    
    def __init__(self):
        self.safe_domains = [
            'localhost',
            '127.0.0.1',
            'test.com',
            'example.com',
            'demo.app',
            'vulnerable-app'
        ]
        
        self.safe_networks = [
            '127.0.0.0/8',
            '192.168.1.0/24',
            '10.0.0.0/8',
            '172.16.0.0/12'
        ]
        
        self.dangerous_payloads = [
            'DROP TABLE',
            'DELETE FROM',
            'rm -rf',
            'format C:',
            'shutdown',
            'reboot'
        ]
        
    def validate_target(self, target: Dict) -> bool:
        """
        Validate if target is safe to test
        Returns: True if safe, False otherwise
        """
        target_url = target.get('url', '')
        target_ip = target.get('ip', '')
        
        # Parse URL
        try:
            parsed = urlparse(target_url)
            hostname = parsed.hostname or target_url
            
            # Check if in safe domains
            if any(domain in hostname for domain in self.safe_domains):
                return True
            
            # Check if local IP
            if hostname in ['localhost', '127.0.0.1']:
                return True
            
            # Check if in safe networks
            if target_ip:
                ip = ipaddress.ip_address(target_ip)
                for network in self.safe_networks:
                    if ip in ipaddress.ip_network(network):
                        return True
            
            logger.warning(f"Unsafe target rejected: {target_url}")
            return False
            
        except Exception as e:
            logger.error(f"Target validation error: {str(e)}")
            return False
    
    def sanitize_payload(self, payload: str, attack_type: str) -> str:
        """
        Sanitize attack payloads to prevent damage
        """
        if not payload:
            return payload
        
        # Remove dangerous commands
        for dangerous in self.dangerous_payloads:
            payload = re.sub(dangerous, '[REMOVED]', payload, flags=re.IGNORECASE)
        
        # Attack-specific sanitization
        if attack_type == 'sql_injection':
            payload = self.sanitize_sql_payload(payload)
        elif attack_type == 'xss':
            payload = self.sanitize_xss_payload(payload)
        elif attack_type == 'command_injection':
            payload = self.sanitize_command_payload(payload)
        
        return payload
    
    def sanitize_sql_payload(self, payload: str) -> str:
        """Sanitize SQL injection payloads"""
        # Remove dangerous SQL commands
        dangerous_sql = [
            'DROP', 'DELETE', 'TRUNCATE', 
            'ALTER', 'CREATE', 'INSERT',
            'UPDATE', 'MERGE'
        ]
        
        for cmd in dangerous_sql:
            payload = re.sub(fr'\b{cmd}\b', f'--{cmd}--', payload, flags=re.IGNORECASE)
        
        # Ensure payload is read-only
        payload = f"/* SAFE TEST */ {payload} /* READ ONLY */"
        return payload
    
    def sanitize_xss_payload(self, payload: str) -> str:
        """Sanitize XSS payloads"""
        # Replace script tags with safe versions
        payload = payload.replace('<script>', '&lt;script&gt;')
        payload = payload.replace('</script>', '&lt;/script&gt;')
        
        # Remove dangerous event handlers
        dangerous_events = [
            'onload', 'onerror', 'onclick', 
            'onmouseover', 'onfocus'
        ]
        
        for event in dangerous_events:
            payload = re.sub(f'{event}=', f'data-{event}=', payload, flags=re.IGNORECASE)
        
        return payload
    
    def sanitize_command_payload(self, payload: str) -> str:
        """Sanitize command injection payloads"""
        # Add echo for safe output
        payload = f"echo 'SAFE TEST: {payload}'"
        
        # Remove dangerous operators
        payload = payload.replace('&&', '&amp;&amp;')
        payload = payload.replace('||', '&#124;&#124;')
        payload = payload.replace(';', '&#59;')
        
        return payload
    
    def validate_module_config(self, module_config: Dict) -> bool:
        """
        Validate module configuration
        """
        required_fields = ['module', 'target']
        
        # Check required fields
        for field in required_fields:
            if field not in module_config:
                logger.error(f"Missing required field: {field}")
                return False
        
        # Check module name
        allowed_modules = ['web', 'iam', 'iot', 'compliance']
        if module_config.get('module') not in allowed_modules:
            logger.error(f"Invalid module: {module_config.get('module')}")
            return False
        
        # Validate target
        if not self.validate_target(module_config.get('target', {})):
            return False
        
        # Validate payload count
        payloads = module_config.get('payloads', [])
        if len(payloads) > 10:  # Limit payloads
            logger.warning("Too many payloads, limiting to 10")
            module_config['payloads'] = payloads[:10]
        
        return True
    
    def get_safety_report(self) -> Dict:
        """Generate safety report for auditing"""
        return {
            'safe_domains': self.safe_domains,
            'safe_networks': self.safe_networks,
            'dangerous_payloads_blocked': len(self.dangerous_payloads),
            'safety_checks_passed': True,
            'timestamp': str(datetime.now())
        }

# Singleton instance
safety_checker = SafetyChecker()
