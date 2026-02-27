"""
Core Engine - Orchestrates all framework operations
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List
import uuid
import threading

from backend.core.module_manager import module_manager
from backend.core.result_processor import result_processor
from backend.blockchain.blockchain_auditor import blockchain_auditor
from backend.siem.log_generator import log_generator

logger = logging.getLogger(__name__)

class SecurityTestingEngine:

    def __init__(self):
        self.active_tests = {}
        self.lock = threading.Lock()

    # =============================
    # TEST SCHEDULING
    # =============================

    def schedule_test(self, test_config: Dict) -> str:

        test_id = f"TEST-{uuid.uuid4().hex[:8].upper()}"

        test_record = {
            'test_id': test_id,
            'config': test_config,
            'status': 'running',
            'created_at': datetime.now().isoformat(),
            'started_at': datetime.now().isoformat(),
            'completed_at': None,
            'results': None,
            'error': None
        }

        self.active_tests[test_id] = test_record

        # Run test in background thread
        thread = threading.Thread(
            target=self._execute_test,
            args=(test_id, test_config)
        )
        thread.start()

        return test_id

    # =============================
    # EXECUTION PIPELINE
    # =============================

    def _execute_test(self, test_id: str, config: Dict):

        try:
            module_group = config.get("module")
            test_name = config.get("test")

            module_instance = module_manager.get_module(module_group, test_name)

            raw_results = asyncio.run(
                module_instance.execute(config)
            )

            raw_results["test_id"] = test_id
            raw_results["total_tests"] = len(raw_results.get("tests", []))

            processed_results = result_processor.process(raw_results)

            # Blockchain integration
            if config.get("blockchain", True):
                evidence_hash = blockchain_auditor.hash_evidence(processed_results)

                tx_hash = blockchain_auditor.store_hash(
                    evidence_hash,
                    attack_type=test_name,
                    target_info=str(config.get("target"))
                )

                processed_results["blockchain_tx"] = tx_hash

            # SIEM integration
            if config.get("siem", True):
                log_generator.generate_security_log(processed_results)

            with self.lock:
                self.active_tests[test_id]["status"] = "completed"
                self.active_tests[test_id]["completed_at"] = datetime.now().isoformat()
                self.active_tests[test_id]["results"] = processed_results

        except Exception as e:
            logger.error(f"Test execution failed: {str(e)}")

            with self.lock:
                self.active_tests[test_id]["status"] = "failed"
                self.active_tests[test_id]["error"] = str(e)

    # =============================
    # STATUS METHODS
    # =============================

    def get_test_status(self, test_id: str) -> Dict:
        return self.active_tests.get(test_id)

    def get_all_tests(self) -> List[Dict]:
        return list(self.active_tests.values())

engine = SecurityTestingEngine()