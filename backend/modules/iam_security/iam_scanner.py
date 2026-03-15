from .credential_stuffing import test_credentials
from .jwt_analyzer import analyze_jwt
from .rbac_tester import test_rbac
from .session_test import test_session
from datetime import datetime


def run(target, token=None):

    findings = []

    findings.extend(test_credentials(target))
    findings.extend(test_rbac(target))
    findings.extend(test_session(target))

    if token:
        findings.extend(analyze_jwt(token))

    return {
        "module": "iam_security",
        "timestamp": datetime.utcnow().isoformat(),
        "vulnerabilities": findings
    }