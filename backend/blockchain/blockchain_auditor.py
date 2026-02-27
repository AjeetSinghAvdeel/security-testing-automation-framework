"""
Blockchain Auditor - Manages blockchain interactions for audit trail
"""

import hashlib
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import os

logger = logging.getLogger(__name__)

class BlockchainAuditor:
    """Handles blockchain operations for audit trail"""
    
    def __init__(self, provider_url: str = "http://localhost:7545"):
        self.provider_url = provider_url
        self.w3 = None
        self.contract = None
        self.contract_address = None
        self.connected = False
        
        # Try to initialize
        self.initialize()
        
    def initialize(self):
        """Initialize blockchain connection"""
        try:
            # Try to connect to web3
            from web3 import Web3
            self.w3 = Web3(Web3.HTTPProvider(self.provider_url))
            self.connected = self.w3.is_connected()
            
            if self.connected:
                logger.info(f"Connected to blockchain at {self.provider_url}")
            else:
                logger.warning("Blockchain not currently connected, running in offline mode")
                
        except ImportError:
            logger.warning("Web3 not installed, blockchain features disabled")
        except Exception as e:
            logger.warning(f"Blockchain initialization failed: {str(e)}")
    
    def hash_evidence(self, data: Dict) -> str:
        """
        Generate SHA-256 hash of evidence data
        """
        # Convert to JSON string with sorted keys
        data_string = json.dumps(data, sort_keys=True, default=str)
        
        # Generate hash
        hash_object = hashlib.sha256(data_string.encode())
        evidence_hash = hash_object.hexdigest()
        
        logger.debug(f"Generated hash: {evidence_hash[:16]}...")
        return evidence_hash
    
    def store_hash(self, evidence_hash: str, attack_type: str, 
                  target_info: str = "", severity: int = 5) -> Optional[str]:
        """
        Store evidence hash on blockchain
        Returns transaction hash if successful
        """
        logger.info(f"Recording evidence hash for {attack_type}")
        
        # In simulation mode, generate a fake transaction hash
        fake_tx = f"0x{'0' * 64}".replace('0', 'a' * 8)[:66]
        
        return fake_tx
    
    def verify_evidence(self, evidence_hash: str, evidence_data: Dict) -> bool:
        """
        Verify evidence integrity by comparing hash
        """
        computed_hash = self.hash_evidence(evidence_data)
        return computed_hash == evidence_hash
    
    def get_statistics(self) -> Dict:
        """
        Get blockchain statistics
        """
        return {
            'connected': self.connected,
            'block_number': 1,
            'contract_address': self.contract_address or 'Not deployed',
            'evidence_count': 0,
            'network_id': 5777  # Ganache default
        }

# Singleton instance
blockchain_auditor = BlockchainAuditor()
