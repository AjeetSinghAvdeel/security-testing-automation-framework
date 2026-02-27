"""Application Constants"""

# Environment
ENVIRONMENT = {
    'DEVELOPMENT': 'development',
    'PRODUCTION': 'production',
    'TESTING': 'testing'
}

# Test Status
TEST_STATUS = {
    'QUEUED': 'queued',
    'RUNNING': 'running',
    'COMPLETED': 'completed',
    'FAILED': 'failed',
    'STOPPED': 'stopped'
}

# Severity Levels
SEVERITY = {
    'CRITICAL': 'Critical',
    'HIGH': 'High',
    'MEDIUM': 'Medium',
    'LOW': 'Low',
    'INFO': 'Info'
}

SEVERITY_SCORES = {
    'Critical': 9.0,
    'High': 7.0,
    'Medium': 5.0,
    'Low': 3.0,
    'Info': 1.0
}

# Security Modules
MODULES = {
    'WEB': 'web',
    'IAM': 'iam',
    'IOT': 'iot',
    'COMPLIANCE': 'compliance'
}

# Web Security Tests
WEB_TESTS = {
    'SQLI': 'sqli',
    'XSS': 'xss',
    'AUTH_BYPASS': 'auth',
    'CSRF': 'csrf',
    'INSECURE_DESERIALIZATION': 'insecure_deser'
}

# IAM Tests
IAM_TESTS = {
    'CREDENTIAL_STUFFING': 'credential',
    'JWT': 'jwt',
    'RBAC': 'rbac',
    'MFA_BYPASS': 'mfa',
    'SESSION_HIJACKING': 'session'
}

# IoT Tests
IOT_TESTS = {
    'MQTT': 'mqtt',
    'DEVICE_SPOOFING': 'spoofing',
    'COAP': 'coap',
    'FIRMWARE_ANALYSIS': 'firmware',
    'WEAK_CRYPTO': 'weak_crypto'
}

# MITRE ATT&CK Techniques
MITRE_TECHNIQUES = {
    'T1190': 'Exploit Public-Facing Application',
    'T1110': 'Brute Force',
    'T1110.001': 'Password Guessing',
    'T1110.004': 'Credential Stuffing',
    'T1078': 'Valid Accounts',
    'T1200': 'Exploitation of Remote Services',
    'T1059.007': 'JavaScript'
}

# Framework Mappings
FRAMEWORKS = {
    'NIST': 'NIST SP 800-53',
    'ISO': 'ISO/IEC 27001:2022',
    'PCI-DSS': 'PCI DSS v3.2.1',
    'CIS': 'CIS Controls'
}

# NIST Security Functions
NIST_FUNCTIONS = {
    'IDENTIFY': 'Identify',
    'PROTECT': 'Protect',
    'DETECT': 'Detect',
    'RESPOND': 'Respond',
    'RECOVER': 'Recover'
}

# Response Codes
HTTP_STATUS = {
    'OK': 200,
    'CREATED': 201,
    'BAD_REQUEST': 400,
    'UNAUTHORIZED': 401,
    'FORBIDDEN': 403,
    'NOT_FOUND': 404,
    'INTERNAL_ERROR': 500,
    'SERVICE_UNAVAILABLE': 503
}

# Error Messages
ERROR_MESSAGES = {
    'INVALID_TARGET': 'Invalid or unsafe target',
    'INVALID_CONFIG': 'Invalid configuration',
    'TEST_NOT_FOUND': 'Test not found',
    'MODULE_NOT_FOUND': 'Module not found',
    'BLOCKCHAIN_ERROR': 'Blockchain error',
    'SIEM_ERROR': 'SIEM error',
    'AUTH_FAILED': 'Authentication failed',
    'PERMISSION_DENIED': 'Permission denied'
}

# Success Messages
SUCCESS_MESSAGES = {
    'TEST_STARTED': 'Test started successfully',
    'TEST_COMPLETED': 'Test completed successfully',
    'REPORT_GENERATED': 'Report generated successfully',
    'EVIDENCE_STORED': 'Evidence stored on blockchain',
    'LOGS_SENT': 'Logs sent to SIEM'
}

# Timeouts (in seconds)
TIMEOUTS = {
    'QUICK_TEST': 30,
    'STANDARD_TEST': 300,
    'DEEP_TEST': 900,
    'HTTP_REQUEST': 30,
    'BLOCKCHAIN_TX': 60
}

# Limits
LIMITS = {
    'MAX_PAYLOADS': 10,
    'MAX_CONCURRENT_TESTS': 5,
    'MAX_LOG_SIZE': 10000,
    'MAX_REPORT_SIZE': 50000000  # 50 MB
}
