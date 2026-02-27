"""
Blockchain Auditor - Manages blockchain interactions for audit trail
"""

import hashlib
import json
import logging
from typing import Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class BlockchainAuditor:
    """Handles blockchain operations for audit trail"""

    def __init__(self, provider_url: str = "http://localhost:7545"):
        self.provider_url = provider_url
        self.w3 = None
        self.connected = False
        self.evidence_records = []
        self.initialize()

    # ============================================================
    # INITIALIZATION
    # ============================================================

    def initialize(self):
        try:
            from web3 import Web3

            self.w3 = Web3(Web3.HTTPProvider(self.provider_url))
            self.connected = self.w3.is_connected()

            if self.connected:
                logger.info(f"[BLOCKCHAIN] Connected to {self.provider_url}")
            else:
                logger.warning("[BLOCKCHAIN] Not connected (offline mode)")

        except ImportError:
            logger.warning("[BLOCKCHAIN] Web3 not installed")
            self.connected = False

        except Exception as e:
            logger.warning(f"[BLOCKCHAIN] Initialization failed: {str(e)}")
            self.connected = False

    # ============================================================
    # HASHING
    # ============================================================

    def hash_evidence(self, data: Dict) -> str:
        data_string = json.dumps(data, sort_keys=True, default=str)
        evidence_hash = hashlib.sha256(data_string.encode()).hexdigest()
        return evidence_hash

    # ============================================================
    # STORE HASH ON BLOCKCHAIN
    # ============================================================

    def store_hash(
        self,
        evidence_hash: str,
        attack_type: str,
        target_info: str = "",
        severity: int = 5
    ) -> Optional[str]:

        logger.info(f"[BLOCKCHAIN] Storing evidence for {attack_type}")

        record = {
            "hash": evidence_hash,
            "attack_type": attack_type,
            "target": target_info,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat()
        }

        if not self.connected:
            logger.warning("[BLOCKCHAIN] Offline mode — storing locally only")
            self.evidence_records.append(record)
            return "OFFLINE_MODE"

        try:
            # Send minimal transaction (0 ETH transfer to self)
            account = self.w3.eth.accounts[0]

            tx_hash = self.w3.eth.send_transaction({
                "from": account,
                "to": account,
                "value": 0
            })

            record["tx_hash"] = tx_hash.hex()
            self.evidence_records.append(record)

            return tx_hash.hex()

        except Exception as e:
            logger.error(f"[BLOCKCHAIN] Transaction failed: {str(e)}")
            return None

    # ============================================================
    # VERIFY EVIDENCE
    # ============================================================

    def verify_evidence(self, evidence_hash: str, evidence_data: Dict) -> bool:
        computed_hash = self.hash_evidence(evidence_data)
        return computed_hash == evidence_hash

    # ============================================================
    # STATISTICS
    # ============================================================

    def get_statistics(self) -> Dict:

        block_number = 0

        if self.connected:
            try:
                block_number = self.w3.eth.block_number
            except:
                block_number = 0

        return {
            "connected": self.connected,
            "block_number": block_number,
            "evidence_count": len(self.evidence_records),
            "network_id": 5777
        }


# Singleton instance
blockchain_auditor = BlockchainAuditor()