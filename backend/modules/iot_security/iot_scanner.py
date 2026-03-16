"""
IoT security module controller.
"""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlparse

from backend.modules.iot_security import coap_tester, device_spoof, mqtt_scanner


def run(target: str) -> List[Dict[str, str]]:
    if "://" in target:
        host = urlparse(target).hostname or target
    else:
        host = target

    results: List[Dict[str, str]] = []

    for scanner in (mqtt_scanner, device_spoof, coap_tester):
        result = scanner.run(host)
        if result:
            results.append(result)

    return results
