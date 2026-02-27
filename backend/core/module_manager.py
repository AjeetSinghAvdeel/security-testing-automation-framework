"""
Module Manager - Loads and manages security testing modules
"""

import importlib
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class ModuleManager:

    def __init__(self):
        self.module_configs = {
            'web': {
                'classes': {
                    'sqli': {
                        'path': 'backend.modules.web_security.sqli_tester',
                        'class': 'SQLITester'
                    },
                    'xss': {
                        'path': 'backend.modules.web_security.xss_tester',
                        'class': 'XSSTester'
                    },
                    'auth': {
                        'path': 'backend.modules.web_security.xss_tester',
                        'class': 'AuthBypassTester'
                    }
                }
            },
            'iot': {
                'classes': {
                    'mqtt': {
                        'path': 'backend.modules.iot_security.mqtt_tester',
                        'class': 'MQTTTester'
                    },
                    'spoofing': {
                        'path': 'backend.modules.iot_security.mqtt_tester',
                        'class': 'DeviceSpoofingTester'
                    },
                    'coap': {
                        'path': 'backend.modules.iot_security.mqtt_tester',
                        'class': 'CoAPTester'
                    }
                }
            }
        }

    def get_module(self, module_group: str, test_name: str):

        if module_group not in self.module_configs:
            raise ValueError(f"Invalid module group: {module_group}")

        module_info = self.module_configs[module_group]["classes"].get(test_name)

        if not module_info:
            raise ValueError(f"Invalid test type: {test_name}")

        module_path = module_info["path"]
        class_name = module_info["class"]

        try:
            module = importlib.import_module(module_path)
            cls = getattr(module, class_name)
            return cls()
        except Exception as e:
            raise Exception(f"Failed loading {class_name}: {str(e)}")

    def list_modules(self) -> List[Dict]:
        return [
            {
                "group": group,
                "tests": list(config["classes"].keys())
            }
            for group, config in self.module_configs.items()
        ]


module_manager = ModuleManager()