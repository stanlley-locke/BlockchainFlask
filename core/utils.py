"""
Helper utilities for hashing, formatting, and shard calculations
"""
import hashlib
import json
import time
import random
import string
import base64
from .config import SHARD_COUNT

def calculate_hash(data):
    """Calculate SHA-256 hash of data"""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    elif not isinstance(data, str):
        data = str(data)
    return hashlib.sha256(data.encode()).hexdigest()

def calculate_merkle_root(transactions):
    """Calculate merkle root of transactions"""
    if not transactions:
        return "0"
    
    tx_hashes = [calculate_hash(tx) for tx in transactions]
    
    while len(tx_hashes) > 1:
        if len(tx_hashes) % 2 == 1:
            tx_hashes.append(tx_hashes[-1])
        
        next_level = []
        for i in range(0, len(tx_hashes), 2):
            combined = tx_hashes[i] + tx_hashes[i + 1]
            next_level.append(calculate_hash(combined))
        
        tx_hashes = next_level
    
    return tx_hashes[0]

def generate_random_string(length=32):
    """Generate random string for various purposes"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def calculate_shard_id(address):
    """Calculate shard ID based on address"""
    return int(calculate_hash(address), 16) % SHARD_COUNT

def format_balance(balance):
    """Format balance for display"""
    return f"{balance:.8f}"

def format_timestamp(timestamp):
    """Format timestamp for display"""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

def validate_address(address):
    """Validate blockchain address format"""
    if not address or len(address) < 32:
        return False
    
    # Check if address is valid base64
    try:
        base64.b64decode(address)
        return True
    except:
        return False

def validate_transaction_amount(amount):
    """Validate transaction amount"""
    try:
        amount = float(amount)
        return amount > 0 and amount <= 1000000000  # Max 1 billion
    except:
        return False

def calculate_transaction_fee(amount, fee_percent=0.01):
    """Calculate transaction fee"""
    return amount * fee_percent

def is_valid_hash(hash_str):
    """Check if string is a valid hash"""
    if not hash_str or len(hash_str) != 64:
        return False
    
    try:
        int(hash_str, 16)
        return True
    except ValueError:
        return False

def difficulty_to_target(difficulty):
    """Convert difficulty to target hash"""
    return "0" * difficulty + "f" * (64 - difficulty)

def meets_difficulty(block_hash, difficulty):
    """Check if block hash meets difficulty requirement"""
    target = difficulty_to_target(difficulty)
    return block_hash < target

def adjust_difficulty(blocks, target_time=60):
    """Adjust mining difficulty based on block times"""
    if len(blocks) < 2:
        return blocks[-1].get('difficulty', 4)
    
    # Calculate average time between last few blocks
    recent_blocks = blocks[-5:] if len(blocks) >= 5 else blocks
    time_taken = recent_blocks[-1]['timestamp'] - recent_blocks[0]['timestamp']
    expected_time = target_time * (len(recent_blocks) - 1)
    
    current_difficulty = blocks[-1].get('difficulty', 4)
    
    if time_taken < expected_time * 0.8:
        # Blocks are being mined too fast, increase difficulty
        return min(current_difficulty + 1, 10)
    elif time_taken > expected_time * 1.2:
        # Blocks are being mined too slow, decrease difficulty
        return max(current_difficulty - 1, 1)
    
    return current_difficulty

def validate_block_structure(block):
    """Validate block structure"""
    required_fields = ['block_index', 'previous_hash', 'timestamp', 'merkle_root', 'nonce', 'hash', 'difficulty']
    
    for field in required_fields:
        if field not in block:
            return False, f"Missing field: {field}"
    
    # Validate types
    if not isinstance(block['block_index'], int):
        return False, "block_index must be integer"
    
    if not isinstance(block['timestamp'], (int, float)):
        return False, "timestamp must be number"
    
    if not isinstance(block['nonce'], int):
        return False, "nonce must be integer"
    
    if not isinstance(block['difficulty'], int):
        return False, "difficulty must be integer"
    
    # Validate hash format
    if not is_valid_hash(block['hash']):
        return False, "Invalid hash format"
    
    return True, "Valid block structure"

def compress_data(data):
    """Compress data for storage or transmission"""
    import zlib
    if isinstance(data, dict):
        data = json.dumps(data)
    return zlib.compress(data.encode())

def decompress_data(compressed_data):
    """Decompress data"""
    import zlib
    return zlib.decompress(compressed_data).decode()
