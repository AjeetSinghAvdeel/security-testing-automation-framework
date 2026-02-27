// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AttackAudit
 * @dev Store hashes of security test results on blockchain for tamper-proof audit trail
 */
contract AttackAudit {
    
    // Struct to store evidence details
    struct Evidence {
        string evidenceHash;      // SHA-256 hash of test results
        uint256 timestamp;        // When the evidence was recorded
        string attackType;        // Type of attack/test performed
        address testedBy;         // Who performed the test
        string targetInfo;        // Target information (hashed for privacy)
        uint256 severity;         // Severity score (1-10)
        bool verified;            // Verification status
    }
    
    // Mapping from evidence ID to Evidence
    mapping(uint256 => Evidence) public evidences;
    
    // Mapping from hash to boolean (to prevent duplicates)
    mapping(string => bool) public hashExists;
    
    // Array of all evidence IDs
    uint256[] public evidenceIds;
    
    // Counter for total evidences
    uint256 public evidenceCount;
    
    // Events
    event EvidenceAdded(uint256 indexed id, string evidenceHash, string attackType, address indexed tester);
    event EvidenceVerified(uint256 indexed id, bool status);
    
    /**
     * @dev Add new evidence to blockchain
     */
    function addEvidence(
        string memory _evidenceHash,
        string memory _attackType,
        string memory _targetInfo,
        uint256 _severity
    ) public returns (uint256) {
        
        uint256 evidenceId = evidenceCount;
        
        evidences[evidenceId] = Evidence({
            evidenceHash: _evidenceHash,
            timestamp: block.timestamp,
            attackType: _attackType,
            testedBy: msg.sender,
            targetInfo: _targetInfo,
            severity: _severity,
            verified: false
        });
        
        evidenceIds.push(evidenceId);
        hashExists[_evidenceHash] = true;
        evidenceCount++;
        
        emit EvidenceAdded(evidenceId, _evidenceHash, _attackType, msg.sender);
        
        return evidenceId;
    }
    
    /**
     * @dev Get evidence details
     */
    function getEvidence(uint256 _id) public view returns (
        string memory evidenceHash,
        uint256 timestamp,
        string memory attackType,
        address testedBy,
        string memory targetInfo,
        uint256 severity,
        bool verified
    ) {
        require(_id < evidenceCount, "Evidence does not exist");
        
        Evidence memory e = evidences[_id];
        return (
            e.evidenceHash,
            e.timestamp,
            e.attackType,
            e.testedBy,
            e.targetInfo,
            e.severity,
            e.verified
        );
    }
    
    /**
     * @dev Get evidence count
     */
    function getEvidenceCount() public view returns (uint256) {
        return evidenceCount;
    }
    
    /**
     * @dev Verify if hash exists
     */
    function verifyHash(string memory _hash) public view returns (bool) {
        return hashExists[_hash];
    }
}
