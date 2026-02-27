"""
System tests for IoT & Web Security Testing Framework
"""

import unittest
import logging
from backend.core.engine import SecurityTestingEngine
from backend.blockchain.blockchain_auditor import BlockchainAuditor
from backend.siem.log_generator import LogGenerator

logging.basicConfig(level=logging.INFO)

class TestSecurityFramework(unittest.TestCase):
    """Main test suite for the framework"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.engine = SecurityTestingEngine()
        cls.blockchain = BlockchainAuditor()
        cls.logger = LogGenerator()
    
    def test_engine_initialization(self):
        """Test core engine initialization"""
        self.assertIsNotNone(self.engine)
        logging.info("✓ Core engine initialized")
    
    def test_safety_validation(self):
        """Test target validation"""
        valid_target = {'url': 'http://localhost:8080'}
        self.assertTrue(self.engine.validate_target(valid_target))
        
        invalid_target = {'url': 'http://evil.com'}
        self.assertFalse(self.engine.validate_target(invalid_target))
        logging.info("✓ Safety validation working")
    
    def test_module_loading(self):
        """Test module loading"""
        modules = self.engine.module_manager.list_modules()
        self.assertTrue(len(modules) > 0)
        logging.info("✓ Modules loaded")
    
    def test_blockchain_hashing(self):
        """Test blockchain hashing"""
        test_data = {'test': 'test', 'result': 'pass'}
        hash_val = self.blockchain.hash_evidence(test_data)
        self.assertEqual(len(hash_val), 64)
        logging.info("✓ Blockchain hashing working")
    
    def test_log_generation(self):
        """Test log generation"""
        test_results = {
            'module': 'test',
            'target': 'localhost',
            'vulnerabilities': []
        }
        logs = self.logger.generate_logs(test_results)
        self.assertTrue(len(logs) > 0)
        logging.info("✓ Log generation working")

if __name__ == '__main__':
    unittest.main(verbosity=2)
