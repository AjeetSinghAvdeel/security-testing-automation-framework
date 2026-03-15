import jwt


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

        findings.append({
            "type": "JWT Payload Decoded",
            "severity": "Info",
            "payload": payload
        })

    except Exception:
        pass

    return findings