"""
Configuration constants and system-wide settings
"""
import os

# ============== BLOCKCHAIN CONFIGURATION ==============
P2P_PORT = 5001
RPC_PORT = 5001
TARGET_VERSION = "4.0.0"
TARGET_NAME = "COINIUM BLOCKCHAIN"
TARGET_DESCRIPTION = "Advanced blockchain with smart contracts, privacy features, and governance"
TARGET_AUTHOR = "Stanlley Locke"
TARGET_LICENSE = "MIT License"
TARGET_BLOCKCHAIN_NAME = "COINIUM BLOCKCHAIN"
TARGET_BLOCK_TIME = 60  # seconds
DIFFICULTY_ADJUSTMENT_INTERVAL = 5  # blocks
FEE_PERCENT = 0.01  # 1% transaction fee
MAX_SUPPLY = 21010724  # Total coins
HALVING_INTERVAL = 100  # Blocks
INITIAL_MINING_REWARD = 50
SHARD_COUNT = 4  # Number of shards
DIFFICULTY = 4  # Initial difficulty
MIN_STAKE = 1000  # Minimum coins to stake
MEMPOOL_KEY_ROTATION_INTERVAL = 3600  # 1 hour
SYNC_INTERVAL = 300  # 5 minutes for periodic sync
SNAPSHOT_INTERVAL = 100  # Blocks between snapshots

# ============== DATABASE CONFIGURATION ==============
DATABASE_VERSION = 1
DATABASE_FILE = "blockchain.db"

# ============== SECURITY CONFIGURATION ==============
SECRET_KEY = os.environ.get('SESSION_SECRET', 'default-secret-key-change-in-production')
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'default-encryption-key')

# ============== NETWORK CONFIGURATION ==============
BOOTSTRAP_NODES = [("seed1.coinium.com", 5000), ("seed2.coinium.com", 5000)]
MIN_PEER_SCORE = 30
MAX_PEERS = 50
GOSSIP_FANOUT = 3
RATE_LIMIT_WINDOW = 60  # seconds
MAX_MESSAGES_PER_MINUTE = 100

# ============== SSL CONFIGURATION ==============
SSL_CERT = "cert.pem"
SSL_KEY = "key.pem"
CA_CERT = "cacert.pem"
CA_KEY = "cakey.pem"

# ============== LOGGING CONFIGURATION ==============
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
LOG_FILE = "blockchain.log"
