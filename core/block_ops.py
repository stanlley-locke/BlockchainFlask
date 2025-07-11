"""
Mining, block validation, difficulty adjustment, and chain operations
"""
import time
import threading
import logging
from .crypto import crypto_manager
from .database import execute_query
from .utils import calculate_hash, calculate_merkle_root, meets_difficulty, adjust_difficulty
from .config import INITIAL_MINING_REWARD, HALVING_INTERVAL, DIFFICULTY_ADJUSTMENT_INTERVAL

class BlockOperations:
    """Manages blockchain operations"""
    
    def __init__(self):
        self.crypto = crypto_manager
        self.blockchain = []
        self.mining_threads = {}
        self.load_blockchain()
    
    def load_blockchain(self):
        """Load blockchain from database"""
        try:
            blocks = execute_query(
                "SELECT block_index, previous_hash, timestamp, merkle_root, nonce, hash, difficulty, validator, vote_count "
                "FROM blocks ORDER BY block_index ASC",
                fetch=True
            )
            
            self.blockchain = [
                {
                    'block_index': block[0],
                    'previous_hash': block[1],
                    'timestamp': block[2],
                    'merkle_root': block[3],
                    'nonce': block[4],
                    'hash': block[5],
                    'difficulty': block[6],
                    'validator': block[7],
                    'vote_count': block[8] or 0
                }
                for block in blocks
            ]
            
            logging.info(f"Loaded {len(self.blockchain)} blocks from database")
            
        except Exception as e:
            logging.error(f"Failed to load blockchain: {e}")
            self.blockchain = []
    
    def get_latest_block(self):
        """Get the latest block in the chain"""
        return self.blockchain[-1] if self.blockchain else None
    
    def get_block_by_index(self, index):
        """Get block by index"""
        try:
            for block in self.blockchain:
                if block['block_index'] == index:
                    return block
            return None
        except Exception as e:
            logging.error(f"Failed to get block by index: {e}")
            return None
    
    def get_block_by_hash(self, block_hash):
        """Get block by hash"""
        try:
            for block in self.blockchain:
                if block['hash'] == block_hash:
                    return block
            return None
        except Exception as e:
            logging.error(f"Failed to get block by hash: {e}")
            return None
    
    def calculate_mining_reward(self, block_index):
        """Calculate mining reward based on halving schedule"""
        halvings = block_index // HALVING_INTERVAL
        reward = INITIAL_MINING_REWARD
        
        for _ in range(halvings):
            reward /= 2
        
        return max(reward, 0.01)  # Minimum reward
    
    def create_genesis_block(self):
        """Create the genesis block"""
        try:
            genesis_block = {
                'block_index': 0,
                'previous_hash': '0',
                'timestamp': time.time(),
                'transactions': [],
                'merkle_root': '0',
                'nonce': 0,
                'hash': 'GENESIS_HASH',
                'difficulty': 4,
                'validator': 'NETWORK',
                'vote_count': 0
            }
            
            self.blockchain.append(genesis_block)
            
            # Store in database
            execute_query(
                "INSERT INTO blocks (block_index, previous_hash, timestamp, merkle_root, nonce, hash, difficulty, validator, vote_count) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    genesis_block['block_index'],
                    genesis_block['previous_hash'],
                    genesis_block['timestamp'],
                    genesis_block['merkle_root'],
                    genesis_block['nonce'],
                    genesis_block['hash'],
                    genesis_block['difficulty'],
                    genesis_block['validator'],
                    genesis_block['vote_count']
                )
            )
            
            logging.info("Created genesis block")
            return genesis_block
            
        except Exception as e:
            logging.error(f"Failed to create genesis block: {e}")
            return None
    
    def validate_block(self, block):
        """Validate a block"""
        try:
            # Check if block exists
            if not block:
                return False, "Block is empty"
            
            # Validate block structure
            required_fields = ['block_index', 'previous_hash', 'timestamp', 'merkle_root', 'nonce', 'hash', 'difficulty']
            for field in required_fields:
                if field not in block:
                    return False, f"Missing field: {field}"
            
            # Check if block index is correct
            latest_block = self.get_latest_block()
            if latest_block and block['block_index'] != latest_block['block_index'] + 1:
                return False, "Invalid block index"
            
            # Check previous hash
            if latest_block and block['previous_hash'] != latest_block['hash']:
                return False, "Invalid previous hash"
            
            # Validate block hash
            calculated_hash = self.calculate_block_hash(block)
            if block['hash'] != calculated_hash:
                return False, "Invalid block hash"
            
            # Check proof of work
            if not meets_difficulty(block['hash'], block['difficulty']):
                return False, "Block doesn't meet difficulty requirement"
            
            return True, "Valid block"
            
        except Exception as e:
            logging.error(f"Failed to validate block: {e}")
            return False, str(e)
    
    def calculate_block_hash(self, block):
        """Calculate block hash"""
        try:
            # Create block string for hashing
            block_string = f"{block['block_index']}{block['previous_hash']}{block['timestamp']}{block['merkle_root']}{block['nonce']}{block['difficulty']}"
            return calculate_hash(block_string)
        except Exception as e:
            logging.error(f"Failed to calculate block hash: {e}")
            return None
    
    def mine_block(self, transactions, miner_address):
        """Mine a new block"""
        try:
            latest_block = self.get_latest_block()
            if not latest_block:
                return None, "No latest block found"
            
            # Create new block
            new_block = {
                'block_index': latest_block['block_index'] + 1,
                'previous_hash': latest_block['hash'],
                'timestamp': time.time(),
                'transactions': transactions,
                'merkle_root': calculate_merkle_root(transactions),
                'nonce': 0,
                'difficulty': adjust_difficulty(self.blockchain),
                'validator': miner_address,
                'vote_count': 0
            }
            
            # Mine block (find valid nonce)
            while True:
                block_hash = self.calculate_block_hash(new_block)
                if meets_difficulty(block_hash, new_block['difficulty']):
                    new_block['hash'] = block_hash
                    break
                new_block['nonce'] += 1
                
                # Check if mining should stop
                if new_block['nonce'] % 10000 == 0:
                    logging.info(f"Mining block {new_block['block_index']}, nonce: {new_block['nonce']}")
            
            # Validate block
            is_valid, error = self.validate_block(new_block)
            if not is_valid:
                return None, error
            
            # Add block to chain
            self.blockchain.append(new_block)
            
            # Store in database
            execute_query(
                "INSERT INTO blocks (block_index, previous_hash, timestamp, merkle_root, nonce, hash, difficulty, validator, vote_count) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    new_block['block_index'],
                    new_block['previous_hash'],
                    new_block['timestamp'],
                    new_block['merkle_root'],
                    new_block['nonce'],
                    new_block['hash'],
                    new_block['difficulty'],
                    new_block['validator'],
                    new_block['vote_count']
                )
            )
            
            logging.info(f"Mined block {new_block['block_index']} with hash {new_block['hash']}")
            return new_block, None
            
        except Exception as e:
            logging.error(f"Failed to mine block: {e}")
            return None, str(e)
    
    def start_mining(self, miner_address, transaction_manager):
        """Start mining in a separate thread"""
        def mining_loop():
            while True:
                try:
                    # Get pending transactions
                    pending_transactions = transaction_manager.get_pending_transactions(limit=10)
                    
                    # Add mining reward transaction
                    reward = self.calculate_mining_reward(len(self.blockchain))
                    coinbase_tx = transaction_manager.create_coinbase_transaction(miner_address, reward)
                    
                    if coinbase_tx:
                        pending_transactions.insert(0, coinbase_tx)
                    
                    # Mine block
                    block, error = self.mine_block(pending_transactions, miner_address)
                    
                    if block:
                        # Process transactions
                        transaction_manager.process_transactions(pending_transactions)
                        logging.info(f"Successfully mined block {block['block_index']}")
                        
                        # Wait before mining next block
                        time.sleep(60)  # TARGET_BLOCK_TIME
                    else:
                        logging.error(f"Failed to mine block: {error}")
                        time.sleep(10)
                        
                except Exception as e:
                    logging.error(f"Mining error: {e}")
                    time.sleep(10)
        
        # Start mining thread
        mining_thread = threading.Thread(target=mining_loop, daemon=True)
        mining_thread.start()
        self.mining_threads[miner_address] = mining_thread
        
        logging.info(f"Started mining for {miner_address}")
    
    def stop_mining(self, miner_address):
        """Stop mining for a specific address"""
        if miner_address in self.mining_threads:
            # Note: This is a simple implementation. In production, you'd need proper thread management
            del self.mining_threads[miner_address]
            logging.info(f"Stopped mining for {miner_address}")
    
    def get_blockchain_stats(self):
        """Get blockchain statistics"""
        try:
            if not self.blockchain:
                return {
                    'total_blocks': 0,
                    'total_transactions': 0,
                    'current_difficulty': 4,
                    'latest_block_time': None,
                    'hash_rate': 0
                }
            
            total_blocks = len(self.blockchain)
            latest_block = self.blockchain[-1]
            
            # Count total transactions
            total_transactions = execute_query(
                "SELECT COUNT(*) FROM transactions",
                fetch=True
            )[0][0]
            
            # Calculate hash rate (simplified)
            if total_blocks > 1:
                time_diff = latest_block['timestamp'] - self.blockchain[-2]['timestamp']
                hash_rate = latest_block['difficulty'] / time_diff if time_diff > 0 else 0
            else:
                hash_rate = 0
            
            return {
                'total_blocks': total_blocks,
                'total_transactions': total_transactions,
                'current_difficulty': latest_block['difficulty'],
                'latest_block_time': latest_block['timestamp'],
                'hash_rate': hash_rate
            }
            
        except Exception as e:
            logging.error(f"Failed to get blockchain stats: {e}")
            return {}
    
    def get_chain_validation_result(self):
        """Validate the entire blockchain"""
        try:
            if not self.blockchain:
                return False, "Blockchain is empty"
            
            # Check genesis block
            if self.blockchain[0]['block_index'] != 0:
                return False, "Invalid genesis block"
            
            # Validate each block
            for i in range(1, len(self.blockchain)):
                current_block = self.blockchain[i]
                previous_block = self.blockchain[i-1]
                
                # Check block index
                if current_block['block_index'] != previous_block['block_index'] + 1:
                    return False, f"Invalid block index at block {i}"
                
                # Check previous hash
                if current_block['previous_hash'] != previous_block['hash']:
                    return False, f"Invalid previous hash at block {i}"
                
                # Validate block hash
                calculated_hash = self.calculate_block_hash(current_block)
                if current_block['hash'] != calculated_hash:
                    return False, f"Invalid block hash at block {i}"
                
                # Check proof of work
                if not meets_difficulty(current_block['hash'], current_block['difficulty']):
                    return False, f"Block {i} doesn't meet difficulty requirement"
            
            return True, "Blockchain is valid"
            
        except Exception as e:
            logging.error(f"Failed to validate blockchain: {e}")
            return False, str(e)

# Global block operations instance
block_operations = BlockOperations()
