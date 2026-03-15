import jwt
from datetime import datetime

def analyze_jwt(token):

    findings = []

    try:
        header = jwt.get_unverified_header(token)

        if header.get("alg") == "none":
            findings.append({
                "type": "JWT None Algorithm",
                "severity": "Critical",
                "description": "Token uses insecure 'none' algorithm"
            })

        payload = jwt.decode(token, options={"verify_signature": False})

        if "exp" in payload:
            expiry = datetime.fromtimestamp(payload["exp"])
            if expiry < datetime.utcnow():
                findings.append({
                    "type": "Expired JWT Token",
                    "severity": "Medium",
                    "description": "Token has already expired"
                })

        findings.append({
            "type": "JWT Payload Decoded",
            "severity": "Info",
            "payload": payload
        })

    except Exception:
        pass

    return findings