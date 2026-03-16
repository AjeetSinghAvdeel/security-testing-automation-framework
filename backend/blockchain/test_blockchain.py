from blockchain_auditor import blockchain_auditor

print("Blockchain connected:", blockchain_auditor.connected)

data = {
    "attack": "SQL Injection",
    "target": "localhost",
    "severity": "high"
}

# Generate hash
evidence_hash = blockchain_auditor.hash_evidence(data)
print("Generated Hash:", evidence_hash)

# Store evidence
tx = blockchain_auditor.store_hash(
    evidence_hash,
    attack_type="SQL_INJECTION",
    target_info="localhost",
    severity=8
)

print("Transaction:", tx)

# Verify evidence
verified = blockchain_auditor.verify_evidence(evidence_hash, data)
print("Evidence verified:", verified)

# Show stats
print("Blockchain stats:", blockchain_auditor.get_statistics())