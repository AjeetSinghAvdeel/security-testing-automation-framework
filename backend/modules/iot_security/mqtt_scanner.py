"""
MQTT scanner for safe broker exposure checks.
"""

from __future__ import annotations

import socket
from typing import Dict


def run(target: str) -> Dict[str, str] | None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        if sock.connect_ex((target, 1883)) == 0:
            return {
                "module": "iot_security",
                "target": target,
                "vulnerability": "Open MQTT Broker",
                "severity": "High",
            }
    return None
