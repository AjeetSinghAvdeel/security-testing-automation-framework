from datetime import datetime

from .credential_stuffing import (
    test_credentials,
    test_bruteforce_protection,
    test_password_policy,
    test_registration_validation,
)

from .jwt_analyzer import analyze_jwt
from .rbac_tester import test_rbac
from .session_test import test_session


def run(target, token=None, scan_options=None):
    """
    Main IAM security scanner entry point
    """

    findings = []
    actions = []
    scan_options = scan_options or {}
    selected_tests = set(scan_options.get("tests", []))
    attack_type = scan_options.get("attack_type")

    if not selected_tests or "credential_stuffing" in selected_tests:
        output = test_credentials(target, attack_type=attack_type)
        findings.extend(_collect_findings(output))
        actions.extend(_collect_actions(output))

    if not selected_tests or "bruteforce" in selected_tests:
        output = test_bruteforce_protection(target, attack_type=attack_type)
        findings.extend(_collect_findings(output))
        actions.extend(_collect_actions(output))

    if not selected_tests or "password_policy" in selected_tests:
        output = test_password_policy(target, attack_type=attack_type)
        findings.extend(_collect_findings(output))
        actions.extend(_collect_actions(output))

    if not selected_tests or "registration_validation" in selected_tests:
        output = test_registration_validation(target, attack_type=attack_type)
        findings.extend(_collect_findings(output))
        actions.extend(_collect_actions(output))

    if not selected_tests or "rbac" in selected_tests:
        output = test_rbac(target, scan_options=scan_options)
        findings.extend(_collect_findings(output))
        actions.extend(_collect_actions(output))

    if not selected_tests or "session" in selected_tests:
        output = test_session(target)
        findings.extend(_collect_findings(output))
        actions.extend(_collect_actions(output))

    # Token checks
    if token and (not selected_tests or "jwt" in selected_tests):
        output = analyze_jwt(token)
        findings.extend(_collect_findings(output))
        actions.extend(_collect_actions(output))

    return {
        "module": "iam_security",
        "timestamp": datetime.utcnow().isoformat(),
        "vulnerabilities": findings,
        "actions": actions,
    }


def _collect_findings(output):
    if isinstance(output, dict):
        return output.get("findings", [])
    return output or []


def _collect_actions(output):
    if isinstance(output, dict):
        return output.get("actions", [])
    return []
