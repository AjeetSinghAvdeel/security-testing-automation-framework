"""Utility Functions and Constants"""

import re
import string
from typing import Any, List, Dict

# Security Constants
SAFE_DOMAINS = [
    'localhost',
    '127.0.0.1',
    'test.com',
    'example.com',
    'demo.app',
    'vulnerable-app',
    '192.168',
    '10.0',
    '172.16'
]

DANGEROUS_PATTERNS = [
    r'DROP\s+TABLE',
    r'DELETE\s+FROM',
    r'rm\s+-rf',
    r'format\s+C:',
    r'shutdown',
    r'reboot'
]

SEVERITY_SCORES = {
    'Critical': 9.0,
    'High': 7.0,
    'Medium': 5.0,
    'Low': 3.0,
    'Info': 1.0
}

# Validators
def is_safe_url(url: str) -> bool:
    """Check if URL is safe to test"""
    for domain in SAFE_DOMAINS:
        if domain in url.lower():
            return True
    return False

def is_safe_payload(payload: str) -> bool:
    """Check if payload is safe"""
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            return False
    return True

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_ipv4(ip: str) -> bool:
    """Validate IPv4 address"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

# Helpers
def sanitize_string(s: str, max_length: int = 1000) -> str:
    """Sanitize string input"""
    # Remove null bytes
    s = s.replace('\x00', '')
    # Trim to max length
    s = s[:max_length]
    return s

def calculate_hash_strength(password: str) -> int:
    """Calculate password strength (0-100)"""
    score = 0
    
    if len(password) >= 8:
        score += 20
    if len(password) >= 12:
        score += 10
    if any(c.isupper() for c in password):
        score += 20
    if any(c.islower() for c in password):
        score += 20
    if any(c.isdigit() for c in password):
        score += 15
    if any(c in string.punctuation for c in password):
        score += 15
    
    return min(score, 100)

def format_timestamp(timestamp: int) -> str:
    """Format Unix timestamp"""
    from datetime import datetime
    return datetime.fromtimestamp(timestamp).isoformat()

def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Merge two dictionaries"""
    result = dict1.copy()
    result.update(dict2)
    return result

def flatten_dict(d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
    """Flatten nested dictionary"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

# Logging
def format_log_message(message: str, **kwargs) -> str:
    """Format log message with context"""
    if kwargs:
        context = ', '.join([f"{k}={v}" for k, v in kwargs.items()])
        return f"{message} [{context}]"
    return message
