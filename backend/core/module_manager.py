"""
Module Manager - Loads and manages security testing modules
"""

import importlib
import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)

class ModuleManager:
    """Manages all security testing modules"""
    
    def __init__(self):
        self.modules = {}
        self.module_metadata = {}
        self.load_modules()
        
    def load_modules(self):
        """Dynamically load all modules"""
        module_configs = {
            'web': {
                'path': 'backend.modules.web_security',
                'classes': {
                    'sqli': 'SQLITester',
                    'xss': 'XSSTester',
                    'auth': 'AuthBypassTester'
                },
                'description': 'Web application security testing',
                'version': '1.0.0'
            },
            'iam': {
                'path': 'backend.modules.iam_security',
                'classes': {
                    'credential': 'CredentialStuffingTester',
                    'jwt': 'JWTTester',
                    'rbac': 'RBACTester'
                },
                'description': 'Identity and access management testing',
                'version': '1.0.0'
            },
            'iot': {
                'path': 'backend.modules.iot_security',
                'classes': {
                    'mqtt': 'MQTTTester',
                    'spoofing': 'DeviceSpoofingTester',
                    'coap': 'CoAPTester'
                },
                'description': 'IoT device security testing',
                'version': '1.0.0'
            },
            'compliance': {
                'path': 'backend.modules.compliance',
                'classes': {
                    'nist': 'NISTMapper',
                    'iso': 'ISOMapper',
                    'report': 'ReportGenerator'
                },
                'description': 'Compliance and reporting',
                'version': '1.0.0'
            }
        }
        
        for module_name, config in module_configs.items():
            self.module_metadata[module_name] = {
                'name': module_name,
                'description': config['description'],
                'version': config['version'],
                'classes': config['classes'],
                'loaded': False,
                'error': None
            }
            
            logger.info(f"Registered module: {module_name}")
    
    def get_module(self, module_name: str, class_name: str = None):
        """
        Get a specific module or class
        """
        if module_name not in self.module_metadata:
            raise ValueError(f"Module {module_name} not found")
        
        return module_name
    
    def list_modules(self) -> List[Dict]:
        """List all available modules"""
        return [
            {
                'name': name,
                'description': meta.get('description', ''),
                'version': meta.get('version', ''),
                'loaded': meta.get('loaded', False),
                'classes': list(meta.get('classes', {}).values()),
                'error': meta.get('error', None)
            }
            for name, meta in self.module_metadata.items()
        ]
    
    def get_module_info(self, module_name: str) -> Dict:
        """Get detailed module information"""
        return self.module_metadata.get(module_name, {})
    
    def get_module_capabilities(self, module_name: str) -> List[str]:
        """Get capabilities of a module"""
        capabilities = {
            'web': ['sqli', 'xss', 'auth_bypass', 'csrf', 'session_hijacking'],
            'iam': ['credential_stuffing', 'jwt_testing', 'rbac_testing', 'token_replay'],
            'iot': ['mqtt_testing', 'device_spoofing', 'coap_testing', 'firmware_analysis'],
            'compliance': ['nist_mapping', 'iso_mapping', 'report_generation', 'gap_analysis']
        }
        return capabilities.get(module_name, [])

# Singleton instance
module_manager = ModuleManager()
