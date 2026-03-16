"""
CoAP exposure tester.
"""

from __future__ import annotations

import socket
from typing import Dict


def run(target: str) -> Dict[str, str] | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        try:
            sock.connect((target, 5683))
        except OSError:
            return None

        return {
            "module": "iot_security",
            "target": target,
            "vulnerability": "Open CoAP Service",
            "severity": "High",
        }
