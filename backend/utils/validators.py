"""Input Validators"""

import re
from typing import Dict, Any, Tuple, List

class Validator:
    """Input validation class"""
    
    @staticmethod
    def validate_test_config(config: Dict) -> Tuple[bool, str]:
        """Validate test configuration"""
        required_fields = ['module', 'target']
        
        for field in required_fields:
            if field not in config:
                return False, f"Missing required field: {field}"
        
        # Validate module
        valid_modules = ['web', 'iam', 'iot', 'compliance']
        if config.get('module') not in valid_modules:
            return False, f"Invalid module: {config.get('module')}"
        
        # Validate target
        if not Validator.validate_target(config.get('target', {})):
            return False, "Invalid or unsafe target"
        
        return True, "Valid"
    
    @staticmethod
    def validate_target(target: Dict) -> bool:
        """Validate target URL/IP"""
        url = target.get('url', '')
        ip = target.get('ip', '')
        
        safe_domains = ['localhost', '127.0.0.1', 'test.com', 'example.com', 'demo.app']
        
        if url:
            for domain in safe_domains:
                if domain in url.lower():
                    return True
        
        if ip:
            return Validator.validate_ipv4(ip)
        
        return False
    
    @staticmethod
    def validate_ipv4(ip: str) -> bool:
        """Validate IPv4 address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        
        safe_ranges = [
            '127',      # localhost
            '192.168',  # private
            '10',       # private
            '172.16'    # private
        ]
        
        return any(ip.startswith(range) for range in safe_ranges)
    
    @staticmethod
    def validate_payload(payload: str) -> Tuple[bool, str]:
        """Validate payload safety"""
        dangerous_patterns = [
            r'DROP\s+TABLE',
            r'DELETE\s+FROM',
            r'rm\s+-rf',
            r'format\s+C:',
            r'shutdown',
            r'reboot',
            r'eval\s*\(',
            r'exec\s*\('
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return False, f"Dangerous pattern detected: {pattern}"
        
        return True, "Safe"
    
    @staticmethod
    def validate_json(data: Any) -> Tuple[bool, str]:
        """Validate JSON data"""
        import json
        try:
            if isinstance(data, str):
                json.loads(data)
            elif isinstance(data, dict):
                json.dumps(data)
            return True, "Valid JSON"
        except Exception as e:
            return False, f"Invalid JSON: {str(e)}"
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, List[str]]:
        """Validate password strength"""
        issues = []
        
        if len(password) < 8:
            issues.append("Password must be at least 8 characters")
        
        if not any(c.isupper() for c in password):
            issues.append("Password must contain uppercase letter")
        
        if not any(c.islower() for c in password):
            issues.append("Password must contain lowercase letter")
        
        if not any(c.isdigit() for c in password):
            issues.append("Password must contain digit")
        
        return len(issues) == 0, issues
    
    @staticmethod
    def sanitize_input(data: str, max_length: int = 1000) -> str:
        """Sanitize user input"""
        # Remove null bytes
        data = data.replace('\x00', '')
        # Trim to max length
        data = data[:max_length]
        # Remove control characters
        data = ''.join(c for c in data if ord(c) >= 32 or c in '\n\r\t')
        return data
