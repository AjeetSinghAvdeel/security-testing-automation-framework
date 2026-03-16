"""
IoT security module controller.
"""

from __future__ import annotations

from typing import Dict, List

from backend.modules.iot_security import coap_tester, device_spoof, mqtt_scanner


def run(target: str) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []

    for scanner in (mqtt_scanner, device_spoof, coap_tester):
        result = scanner.run(target)
        if result:
            results.append(result)

    return results
