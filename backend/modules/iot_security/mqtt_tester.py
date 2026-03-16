"""
Compatibility wrapper for the new IoT scanner modules.
"""

from backend.modules.iot_security.coap_tester import run as run_coap
from backend.modules.iot_security.device_spoof import run as run_device_spoof
from backend.modules.iot_security.mqtt_scanner import run as run_mqtt

__all__ = ["run_mqtt", "run_device_spoof", "run_coap"]
