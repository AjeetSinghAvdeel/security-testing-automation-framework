import asyncio

from .sqli_tester import SQLITester
from .xss_tester import AuthBypassTester, XSSTester


def run(target, intensity="medium"):
    """
    Web security scanning module
    Runs all web vulnerability tests
    """

    url_target = target if "://" in target else f"http://{target}"
    config = {
        "target": {
            "url": url_target,
        },
        "intensity": intensity,
    }
    findings = []
    testers = [SQLITester(), XSSTester(), AuthBypassTester()]

    for tester in testers:
        try:
            result = asyncio.run(tester.execute(config))
            findings.extend(result.get("vulnerabilities", []))
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
    }
