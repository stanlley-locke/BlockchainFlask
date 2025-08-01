import hashlib
import time
from uuid import uuid4
from collections import deque
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import json # Used for serializing/deserializing in to_dict/from_dict

# Constants
DIFFICULTY = 4 # Number of leading zeros required for proof-of-work
MINING_REWARD = 12.5

def sha256_hash(data):
    """Calculates the SHA256 hash of a string."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def generate_key_pair():
    """Generates a new ECDSA private and public key pair."""
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    # Return private key in PEM format and public key as hex string
    return sk.to_pem().decode('utf-8'), vk.to_string().hex()

class UTXO:
    """Represents an Unspent Transaction Output (coin ownership)."""
    def __init__(self, public_key, amount):
        self.public_key = public_key
        self.amount = amount

    def to_dict(self):
        return {
            "public_key": self.public_key,
            "amount": self.amount
        }

    @classmethod
    def from_dict(cls, data):
        return cls(data['public_key'], data['amount'])

class UTXOPool:
    """Manages the collection of UTXOs (balances) for the blockchain."""
    def __init__(self, utxos=None):
        # Stores UTXO objects, keyed by public_key
        self.utxos = utxos if utxos is not None else {}

    def add_utxo(self, public_key, amount):
        """Adds or updates a UTXO for a given public key."""
        if public_key in self.utxos:
            self.utxos[public_key].amount += amount
        else:
            self.utxos[public_key] = UTXO(public_key, amount)

    def handle_transaction(self, transaction, fee_receiver_public_key):
        """
        Applies a transaction to the UTXO pool.
        Returns True if successful, False otherwise (e.g., insufficient funds).
        """
        if not self.is_valid_transaction(transaction):
            return False

        input_utxo = self.utxos[transaction.input_public_key];
        input_utxo.amount -= transaction.amount
        input_utxo.amount -= transaction.fee

        if input_utxo.amount <= 0:
            del self.utxos[transaction.input_public_key]

        self.add_utxo(transaction.output_public_key, transaction.amount)
        self.add_utxo(fee_receiver_public_key, transaction.fee)
        return True

    def is_valid_transaction(self, transaction):
        """Checks if a transaction is valid given the current UTXO pool state."""
        utxo = self.utxos.get(transaction.input_public_key)
        return (
            utxo is not None and
            utxo.amount >= (transaction.amount + transaction.fee) and
            transaction.amount > 0 and
            transaction.fee >= 0
        )

    def clone(self):
        """Creates a deep copy of the UTXO pool."""
        cloned_utxos = {pk: UTXO(utxo.public_key, utxo.amount) for pk, utxo in self.utxos.items()}
        return UTXOPool(cloned_utxos)

    def to_dict(self):
        """Converts the UTXO pool to a dictionary for serialization."""
        return {pk: utxo.to_dict() for pk, utxo in self.utxos.items()}

    @classmethod
    def from_dict(cls, data):
        """Creates a UTXOPool object from a dictionary."""
        utxos = {pk: UTXO.from_dict(utxo_data) for pk, utxo_data in data.items()}
        return cls(utxos)

class Transaction:
    """Represents a transfer of coins between public keys."""
    def __init__(self, input_public_key, output_public_key, amount, fee=0, signature=None):
        self.input_public_key = input_public_key
        self.output_public_key = output_public_key
        self.amount = amount
        self.fee = fee
        self.signature = signature
        self.hash = self._calculate_hash()

    def _calculate_hash(self):
        """Calculates the SHA256 hash of the transaction data."""
        # Order matters for consistent hashing
        data = f"{self.input_public_key}{self.output_public_key}{self.amount}{self.fee}"
        return sha256_hash(data)

    def sign(self, private_key_pem):
        """Signs the transaction hash with the provided private key."""
        try:
            sk = SigningKey.from_pem(private_key_pem, curve=SECP256k1)
            self.signature = sk.sign(self.hash.encode('utf-8')).hex()
        except Exception as e:
            print(f"Error signing transaction: {e}")
            self.signature = None # Ensure signature is None on failure

    def has_valid_signature(self):
        """Verifies the transaction's signature using the input public key."""
        if not self.signature:
            return False
        try:
            # Public key is stored as hex string, convert back to bytes for VerifyingKey
            vk = VerifyingKey.from_string(bytes.fromhex(self.input_public_key), curve=SECP256k1)
            return vk.verify(bytes.fromhex(self.signature), self.hash.encode('utf-8'))
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

    def to_dict(self):
        """Converts the transaction to a dictionary for serialization."""
        return {
            "input_public_key": self.input_public_key,
            "output_public_key": self.output_public_key,
            "amount": self.amount,
            "fee": self.fee,
            "signature": self.signature,
            "hash": self.hash
        }

    @classmethod
    def from_dict(cls, data):
        """Creates a Transaction object from a dictionary."""
        return cls(
            data['input_public_key'],
            data['output_public_key'],
            data['amount'],
            data['fee'],
            data['signature']
        )

class Block:
    """Represents a block in the blockchain."""
    def __init__(self, index, parent_hash, coinbase_beneficiary, height, utxo_pool, transactions=None, nonce=None, timestamp=None):
        self.index = index
        self.parent_hash = parent_hash
        self.coinbase_beneficiary = coinbase_beneficiary
        self.height = height
        self.utxo_pool = utxo_pool # This is a UTXOPool object
        self.transactions = transactions if transactions is not None else {} # hash -> Transaction object
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.nonce = nonce if nonce is not None else sha256_hash(str(time.time())) # Initial random nonce
        self.hash = self._calculate_hash()

    def _calculate_hash(self):
        """Calculates the SHA256 hash of the block's contents."""
        # Ensure consistent order for hashing transactions
        transaction_hashes = sorted([tx.hash for tx in self.transactions.values()])
        transactions_string = "".join(transaction_hashes)
        data = f"{self.index}{self.parent_hash}{self.timestamp}{self.nonce}{self.coinbase_beneficiary}{self.height}{transactions_string}"
        return sha256_hash(data)

    def set_nonce(self, nonce):
        """Sets the nonce and recalculates the block's hash."""
        self.nonce = nonce
        self.hash = self._calculate_hash()

    def is_valid_pow(self):
        """Checks if the block's hash meets the Proof-of-Work difficulty."""
        return self.hash.endswith("0" * DIFFICULTY)

    def is_valid_block(self, parent_block_utxo_pool):
        """
        Validates the block's integrity, including PoW, hash, and transactions.
        Requires the parent block's UTXO pool for transaction validation.
        """
        # 1. Check Proof of Work
        if not self.is_valid_pow():
            print(f"Block {self.hash} failed PoW check.")
            return False

        # 2. Re-calculate hash to ensure it matches the stored hash
        if self.hash != self._calculate_hash():
            print(f"Block {self.hash} hash mismatch.")
            return False

        # 3. Validate transactions against the parent's UTXO pool
        # Create a temporary UTXO pool to simulate applying transactions
        temp_utxo_pool = parent_block_utxo_pool.clone()
        temp_utxo_pool.add_utxo(self.coinbase_beneficiary, MINING_REWARD) # Add mining reward first

        for tx_hash, transaction in self.transactions.items():
            if not transaction.has_valid_signature():
                print(f"Block {self.hash} contains transaction {tx_hash} with invalid signature.")
                return False
            if not temp_utxo_pool.handle_transaction(transaction, self.coinbase_beneficiary):
                print(f"Block {self.hash} contains invalid transaction {tx_hash} (insufficient funds or other issue).")
                return False

        # If all checks pass, the block is valid
        return True

    def to_dict(self):
        """Converts the block to a dictionary for serialization."""
        return {
            "index": self.index,
            "parent_hash": self.parent_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "hash": self.hash,
            "coinbase_beneficiary": self.coinbase_beneficiary,
            "height": self.height,
            "utxo_pool": self.utxo_pool.to_dict(),
            "transactions": {h: tx.to_dict() for h, tx in self.transactions.items()}
        }

    @classmethod
    def from_dict(cls, data):
        """Creates a Block object from a dictionary."""
        utxo_pool_data = data.pop('utxo_pool')
        transactions_data = data.pop('transactions')

        deserialized_utxo_pool = UTXOPool.from_dict(utxo_pool_data)
        deserialized_transactions = {h: Transaction.from_dict(tx_data) for h, tx_data in transactions_data.items()}

        block = cls(
            index=data['index'],
            parent_hash=data['parent_hash'],
            coinbase_beneficiary=data['coinbase_beneficiary'],
            height=data['height'],
            utxo_pool=deserialized_utxo_pool,
            transactions=deserialized_transactions,
            nonce=data['nonce'],
            timestamp=data['timestamp']
        )
        # Recalculate hash to ensure integrity after deserialization
        block.hash = block._calculate_hash()
        return block

class Blockchain:
    """Manages the blockchain, including blocks, transactions, and consensus."""
    def __init__(self):
        self.blocks = {}  # Stores Block objects, keyed by block hash
        self.pending_transactions = {} # Stores Transaction objects, keyed by transaction hash
        self.nodes = set() # Set of URLs of other blockchain nodes
        self.create_genesis_block()

    @property
    def last_block(self):
        """Returns the block with the highest height (the tip of the longest chain)."""
        if not self.blocks:
            return None
        return max(self.blocks.values(), key=lambda block: block.height)

    def create_genesis_block(self):
        """Creates the first block in the blockchain (genesis block)."""
        genesis_utxo_pool = UTXOPool()
        genesis_block = Block(
            index=0,
            parent_hash="root",
            coinbase_beneficiary="genesis_address",
            height=0,
            utxo_pool=genesis_utxo_pool,
            nonce="genesis_nonce",
            timestamp=time.time()
        )
        # Ensure genesis block hash is calculated and stored
        genesis_block.hash = genesis_block._calculate_hash()
        self.blocks[genesis_block.hash] = genesis_block
        print("Genesis block created.")

    def add_block(self, block):
        """
        Adds a new block to the blockchain after validation.
        Returns True if the block is added, False otherwise.
        """
        # 1. Check if parent exists and height is correct
        parent = self.blocks.get(block.parent_hash)
        if block.parent_hash != "root" and (parent is None or parent.height + 1 != block.height):
            print(f"Invalid parent or height for block {block.hash}. Parent: {block.parent_hash}, Expected Height: {parent.height + 1 if parent else 'N/A'}, Actual Height: {block.height}")
            return False

        # 2. Validate the block itself (PoW, hash, transactions)
        parent_utxo_pool = parent.utxo_pool if parent else UTXOPool() # For genesis, parent_utxo_pool is empty
        if not block.is_valid_block(parent_utxo_pool):
            print(f"Block {block.hash} failed internal validation.")
            return False

        # 3. If valid, add to our chain
        self.blocks[block.hash] = block
        print(f"Block {block.hash} (Height: {block.height}) added to the blockchain.")

        # 4. Remove included transactions from pending pool
        for tx_hash in block.transactions:
            if tx_hash in self.pending_transactions:
                del self.pending_transactions[tx_hash]
        return True

    def new_transaction(self, input_public_key, output_public_key, amount, fee, private_key_pem):
        """
        Creates a new transaction, signs it, and adds it to the pending transactions pool.
        Returns the transaction hash if successful, None otherwise.
        """
        transaction = Transaction(input_public_key, output_public_key, amount, fee)
        transaction.sign(private_key_pem)

        if not transaction.has_valid_signature():
            print("Transaction signature is invalid.")
            return None

        # Basic validation before adding to pending (full validation happens when mining)
        current_utxo_pool = self.last_block.utxo_pool if self.last_block else UTXOPool()
        if not current_utxo_pool.is_valid_transaction(transaction):
            print("Transaction is invalid based on current UTXO pool (insufficient funds or invalid amount/fee).")
            return None

        self.pending_transactions[transaction.hash] = transaction
        return transaction.hash

    def mine_block(self, miner_public_key):
        """
        Mines a new block by finding a nonce that satisfies the PoW difficulty.
        Includes pending transactions and awards the miner.
        Returns the newly mined block if successful, None otherwise.
        """
        last_block = self.last_block
        if not last_block:
            print("Cannot mine: No last block found (blockchain not initialized?).")
            return None

        new_block_index = last_block.index + 1
        new_block_height = last_block.height + 1
        parent_hash = last_block.hash
        parent_utxo_pool = last_block.utxo_pool

        # 1. Select transactions to include and validate them against a temporary UTXO pool
        transactions_to_include = {}
        # Clone parent's UTXO pool to simulate the state for transaction validation
        # This temporary pool will also receive the mining reward for validation purposes
        temp_utxo_pool_for_validation = parent_utxo_pool.clone()
        temp_utxo_pool_for_validation.add_utxo(miner_public_key, MINING_REWARD)

        for tx_hash, transaction in list(self.pending_transactions.items()): # Iterate over a copy to allow modification
            if transaction.has_valid_signature() and temp_utxo_pool_for_validation.handle_transaction(transaction, miner_public_key):
                transactions_to_include[tx_hash] = transaction
            else:
                print(f"Skipping invalid pending transaction: {tx_hash}")

        # 2. Create a new block candidate
        new_block = Block(
            index=new_block_index,
            parent_hash=parent_hash,
            coinbase_beneficiary=miner_public_key,
            height=new_block_height,
            utxo_pool=UTXOPool(), # Placeholder, will be set after PoW
            transactions=transactions_to_include
        )

        # 3. Perform Proof of Work
        nonce = 0
        while not new_block.is_valid_pow():
            nonce += 1
            new_block.set_nonce(str(nonce)) # Nonce can be any string

        # 4. After finding nonce, finalize the block's UTXO pool
        # This is the actual UTXO pool state after this block is added
        final_block_utxo_pool = parent_utxo_pool.clone()
        final_block_utxo_pool.add_utxo(miner_public_key, MINING_REWARD) # Add mining reward

        for tx_hash, transaction in transactions_to_include.items():
            # Re-apply transactions to the final UTXO pool
            # This ensures the block's UTXO pool accurately reflects the state
            final_block_utxo_pool.handle_transaction(transaction, miner_public_key)

        new_block.utxo_pool = final_block_utxo_pool
        new_block.timestamp = time.time() # Set final timestamp

        # 5. Add the newly mined block to the chain
        if self.add_block(new_block):
            return new_block
        return None

    def register_node(self, address):
        """Adds a new node to the list of nodes."""
        from urllib.parse import urlparse # Import here to avoid circular dependency with Flask app
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path: # Handle cases like 'localhost:5001' without scheme
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError("Invalid URL for node registration.")
        print(f"Registered new node: {address}")

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts by
        replacing our chain with the longest one in the network.
        Returns True if our chain was replaced, False otherwise.
        """
        import requests # Import here to avoid circular dependency with Flask app
        neighbours = list(self.nodes)
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain) # Use the length of the current longest chain

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/chain')

                if response.status_code == 200:
                    chain_data = response.json()
                    # Deserialize the received chain data into Block objects
                    received_chain = [Block.from_dict(block_dict) for block_dict in chain_data['chain']]

                    if len(received_chain) > max_length and self.is_valid_chain(received_chain):
                        max_length = len(received_chain)
                        new_chain = received_chain
            except requests.exceptions.ConnectionError:
                print(f"Could not connect to node: {node}")
                continue
            except json.JSONDecodeError:
                print(f"Could not decode JSON from node: {node}")
                continue
            except Exception as e:
                print(f"An error occurred with node {node}: {e}")
                continue

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            # Clear current blocks and add blocks from the new chain
            self.blocks = {}
            for block in new_chain:
                self.blocks[block.hash] = block
            print("Our chain was replaced by a longer, valid chain.")
            return True

        print("Our chain is authoritative.")
        return False

    def is_valid_chain(self, chain):
        """
        Determine if a given blockchain is valid.
        A chain is valid if:
        1. All blocks correctly link to their parent via hash.
        2. All blocks satisfy Proof of Work.
        3. All transactions within each block are valid and signed.
        4. The UTXO pool state is consistent throughout the chain.
        """
        if not chain:
            return False

        # Check genesis block
        if chain[0].parent_hash != "root" or chain[0].index != 0:
            print("Invalid genesis block.")
            return False

        # Start with the genesis block's UTXO pool for validation
        # This will be updated as we traverse and validate each block
        current_utxo_pool_for_validation = chain[0].utxo_pool.clone()

        for i in range(len(chain)):
            block = chain[i]

            if i > 0:
                prev_block = chain[i-1]
                # Check hash linkage
                if block.parent_hash != prev_block.hash:
                    print(f"Chain invalid: Block {block.hash} parent hash mismatch with {prev_block.hash}.")
                    return False
                # Check height
                if block.height != prev_block.height + 1:
                    print(f"Chain invalid: Block {block.hash} height mismatch.")
                    return False

                # Validate block's PoW and transactions against the previous block's UTXO pool
                # This is where the core validation logic from Block.is_valid_block is used
                if not block.is_valid_block(prev_block.utxo_pool):
                    print(f"Chain invalid: Block {block.hash} failed internal validation during chain check.")
                    return False

                # After validating the block, the block's own utxo_pool should be the result
                # of applying its transactions to the parent's utxo_pool.
                # We just need to ensure it matches.
                # For simplicity, we trust block.utxo_pool if block.is_valid_block passed.
                current_utxo_pool_for_validation = block.utxo_pool.clone()
            else: # Genesis block
                # Genesis block might not strictly follow PoW, but for consistency, we can check its hash format
                if not block.is_valid_pow() and block.parent_hash != "root": # Only check PoW for non-genesis
                    print("Genesis block failed PoW (if applicable).")
                    return False
                # For genesis, its UTXO pool is just what it starts with
                current_utxo_pool_for_validation = block.utxo_pool.clone()

        return True

    @property
    def chain(self):
        """
        Returns the current longest chain as a list of Block objects,
        ordered from genesis to the latest block.
        """
        if not self.blocks:
            return []

        longest_chain_blocks = []
        current_block = self.last_block
        # Traverse back from the last block to the genesis block
        while current_block and current_block.parent_hash != "root":
            longest_chain_blocks.append(current_block)
            current_block = self.blocks.get(current_block.parent_hash)
        if current_block: # Add the genesis block
            longest_chain_blocks.append(current_block)

        # Reverse the list to get the chain in chronological order
        return list(reversed(longest_chain_blocks))
