import hashlib
import json

def generate_hash(data):
    """
    Generate SHA256 hash for scan results
    """

    json_data = json.dumps(data, sort_keys=True)

    hash_value = hashlib.sha256(json_data.encode()).hexdigest()

    return hash_value