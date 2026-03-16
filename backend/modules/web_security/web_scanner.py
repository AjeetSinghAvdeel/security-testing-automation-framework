from .sqli_tester import test_sql_injection
from .xss_tester import test_xss


def run(target, intensity="medium"):
    """
    Web security scanning module
    Runs all web vulnerability tests
    """

    findings = []

    try:
        # SQL Injection tests
        sqli_results = test_sql_injection(target)
        findings.extend(sqli_results)

    except Exception as e:
        findings.append({
            "type": "SQL Injection",
            "severity": "Error",
            "description": str(e)
        })

    try:
        # XSS tests
        xss_results = test_xss(target)
        findings.extend(xss_results)

    except Exception as e:
        findings.append({
            "type": "XSS",
            "severity": "Error",
            "description": str(e)
        })

    return {
        "module": "web_security",
        "target": target,
        "findings": findings
    }