"""
Target validation helpers for safe local-network testing.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

SAFE_HOSTNAMES = {
    "localhost",
    "backend",
    "frontend",
    "mosquitto",
    "host.docker.internal",
}


def _extract_host(target: str) -> str:
    value = (target or "").strip()
    if not value:
        return ""

    if "://" not in value:
        parsed = urlparse(f"//{value}")
    else:
        parsed = urlparse(value)

    return (parsed.hostname or value.split("/")[0]).strip("[]")


def validate_target(target: str) -> bool:
    host = _extract_host(target)
    if not host:
        return False

    if host in SAFE_HOSTNAMES:
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    private_networks = (
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    return any(ip in network for network in private_networks)
