"""
Core Engine - Orchestrates all framework operations
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List
from threading import Thread
from queue import Queue
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityTestingEngine:
    """Main orchestration engine for security testing"""
    
    def __init__(self):
        self.active_tests = {}
        self.test_queue = Queue()
        self.results_cache = {}
        
        # Load configuration
        self.load_configuration()
        
    def load_configuration(self):
        """Load engine configuration"""
        self.config = {
            'max_concurrent_tests': 5,
            'test_timeout': 300,  # seconds
            'safe_mode': True,
            'target_validation': True,
            'log_level': 'INFO',
            'blockchain_enabled': True,
            'siem_integration': True
        }
        logger.info("Engine configuration loaded")
        
    def validate_target(self, target: Dict) -> bool:
        """Validate target before testing"""
        target_url = target.get('url', '')
        safe_domains = ['localhost', '127.0.0.1', 'test.com', 'example.com', 'demo.app', 'vulnerable-app']
        
        try:
            for domain in safe_domains:
                if domain in target_url:
                    return True
            logger.warning(f"Unsafe target rejected: {target_url}")
            return False
        except Exception as e:
            logger.error(f"Target validation error: {str(e)}")
            return False
    
    def schedule_test(self, test_config: Dict) -> str:
        """Schedule a new security test"""
        test_id = self.generate_test_id()
        
        # Validate target safety
        if not self.validate_target(test_config.get('target', {})):
            raise ValueError("Invalid or unsafe target")
        
        # Create test record
        test_record = {
            'test_id': test_id,
            'config': test_config,
            'status': 'queued',
            'created_at': datetime.now().isoformat(),
            'started_at': None,
            'completed_at': None,
            'results': None,
            'error': None
        }
        
        # Add to queue
        self.test_queue.put(test_id)
        self.active_tests[test_id] = test_record
        
        logger.info(f"Test {test_id} scheduled: {test_config.get('module')}")
        return test_id
    
    def generate_test_id(self) -> str:
        """Generate unique test ID"""
        import uuid
        return f"TEST-{uuid.uuid4().hex[:8].upper()}"
    
    def get_test_status(self, test_id: str) -> Dict:
        """Get status of a test"""
        return self.active_tests.get(test_id, {})
    
    def get_all_tests(self) -> List[Dict]:
        """Get all tests"""
        return list(self.active_tests.values())
    
    def stop_test(self, test_id: str):
        """Stop a running test"""
        if test_id in self.active_tests:
            self.active_tests[test_id]['status'] = 'stopped'
            logger.info(f"Test {test_id} stopped")
            return True
        return False

# Singleton instance
engine = SecurityTestingEngine()
