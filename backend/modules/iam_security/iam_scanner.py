from datetime import datetime

from .credential_stuffing import (
    test_credentials,
    test_bruteforce_protection,
    test_password_policy
)

from .jwt_analyzer import analyze_jwt
from .rbac_tester import test_rbac
from .session_test import test_session


def run(target, token=None):
    """
    Main IAM security scanner entry point
    """

    findings = []

    # Authentication checks
    findings.extend(test_credentials(target))
    findings.extend(test_bruteforce_protection(target))
    findings.extend(test_password_policy(target))

    # Authorization checks
    findings.extend(test_rbac(target))

    # Session checks
    findings.extend(test_session(target))

    # Token checks
    if token:
        findings.extend(analyze_jwt(token))

    return {
        "module": "iam_security",
        "timestamp": datetime.utcnow().isoformat(),
        "vulnerabilities": findings
    }