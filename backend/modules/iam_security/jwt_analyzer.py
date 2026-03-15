import jwt
from datetime import datetime


def analyze_jwt(token):
    """
    Analyze JWT token security
    """

    findings = []

    try:
        header = jwt.get_unverified_header(token)

        if header.get("alg") == "none":
            findings.append({
                "type": "JWT None Algorithm",
                "severity": "Critical",
                "risk_score": 9.5,
                "description": "JWT token uses insecure 'none' algorithm"
            })

        payload = jwt.decode(token, options={"verify_signature": False})

        if "exp" in payload:
            expiry_time = datetime.fromtimestamp(payload["exp"])

            if expiry_time < datetime.utcnow():
                findings.append({
                    "type": "Expired JWT Token",
                    "severity": "Medium",
                    "risk_score": 5.0,
                    "description": "JWT token has expired"
                })

        findings.append({
            "type": "JWT Payload Decoded",
            "severity": "Info",
            "payload": payload
        })

    except Exception:
        pass

    return findings