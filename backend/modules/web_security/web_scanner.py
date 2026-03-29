import asyncio

from .sqli_tester import SQLITester
from .xss_tester import AuthBypassTester, ObservabilityTester, XSSTester


def run(target, intensity="medium", scan_options=None):
    """
    Web security scanning module
    Runs all web vulnerability tests
    """

    url_target = target if "://" in target else f"http://{target}"
    scan_options = scan_options or {}
    config = {
        "target": {
            "url": url_target,
        },
        "intensity": intensity,
        "attack_type": scan_options.get("attack_type"),
    }
    findings = []
    actions = []
    selected_tests = set(scan_options.get("tests", []))
    all_testers = {
        "sqli": SQLITester(),
        "xss": XSSTester(),
        "auth_bypass": AuthBypassTester(),
        "observability": ObservabilityTester(),
    }
    testers = (
        [tester for key, tester in all_testers.items() if key in selected_tests]
        if selected_tests
        else list(all_testers.values())
    )

    for tester in testers:
        try:
            result = asyncio.run(tester.execute(config))
            findings.extend(result.get("vulnerabilities", []))
            actions.extend(result.get("actions", []))
        except Exception as exc:
            findings.append(
                {
                    "type": tester.name,
                    "severity": "Low",
                    "description": str(exc),
                }
            )

    return {
        "module": "web_security",
        "target": url_target,
        "findings": findings,
        "actions": actions,
    }
