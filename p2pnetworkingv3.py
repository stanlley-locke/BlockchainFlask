import socket
import threading
import json
import ssl
import time
import logging
import sqlite3
import miniupnpc
import stun
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import os
import base64
import datetime
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
import select
from collections import defaultdict
import secrets
import heapq
import pytz
import requests
from queue import PriorityQueue, Queue
from dataclasses import dataclass, field
from enum import Enum
import aiortc
import asyncio

# Initialize colorama for colored output
from colorama import Fore, Style, init
init(autoreset=True)

# Enhanced logging with colors
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, Fore.WHITE)
        message = super().format(record)
        return f"{color}{message}{Style.RESET_ALL}"

for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

# Disable propagation
logger = logging.getLogger("p2pnet")
logger.propagate = False
logger.setLevel(logging.INFO)

# File-only handler
logfile = "p2p_network.log"
fh = logging.FileHandler(logfile)
fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(module)s - %(message)s'))
logger.addHandler(fh)


# Database setup for persistent peer storage
PEER_DB = sqlite3.connect("peer_store.db", check_same_thread=False)
PEER_DB_CURSOR = PEER_DB.cursor()
PEER_DB_CURSOR.execute('''CREATE TABLE IF NOT EXISTS peers (
                          ip TEXT,
                          port INTEGER,
                          score REAL,
                          latency REAL,
                          last_seen TIMESTAMP,
                          PRIMARY KEY (ip, port)
                       )''')
PEER_DB_CURSOR.execute('''CREATE TABLE IF NOT EXISTS revoked_certs (
                          serial TEXT PRIMARY KEY,
                          revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                       )''')
PEER_DB.commit()

# Global state with thread locks
PEERS = set()
PEER_SCORES = {}
BLOCK_VOTES = {}
VALIDATORS = set()
PEER_LATENCIES = {}
RATE_LIMITS = defaultdict(lambda: defaultdict(int))
PEER_LOCK = threading.Lock()
CONN = sqlite3.connect("blockchain.db", check_same_thread=False)
C = CONN.cursor()

# Message priority levels
class MessagePriority(Enum):
    BLOCK = 0
    VOTE = 1
    TX = 2
    PEER_LIST = 3
    OTHER = 4

# Configuration
MIN_STAKE = 1000
P2P_PORT = 5000
RPC_PORT = 6000
SSL_CERT = "cert.pem"
SSL_KEY = "key.pem"
CA_CERT = "cacert.pem"
CA_KEY = "cakey.pem"
BOOTSTRAP_NODES = [("seed1.coinium.com", 5000), ("seed2.coinium.com", 5000)]
MIN_PEER_SCORE = 30
MAX_PEERS = 50
BLOCK_PROPAGATION_DELAY = 2  # seconds
GOSSIP_FANOUT = 3
SCORE_DECAY_INTERVAL = 3600  # 1 hour
SCORE_DECAY_FACTOR = 0.95
RATE_LIMIT_WINDOW = 60  # seconds
MAX_MESSAGES_PER_MINUTE = 100
FORK_ALERT_THRESHOLD = 3
TOKEN_BUCKET_CAPACITY = 100
TOKEN_BUCKET_RATE = 10  # tokens per second
TURN_SERVER = "turn.coinium.com"
TURN_USER = "coinium"
TURN_PASSWORD = "securepassword"
MEMPOOL_KEY_ROTATION_INTERVAL = 3600  # 1 hour
MEMPOOL_KEYS = {}
CURRENT_MEMPOOL_KEY_ID = 0
VECTOR_CLOCKS = {}
MESSAGE_SEEN_CACHE = set()
MESSAGE_TTL = 10
ANTI_ENTROPY_INTERVAL = 300  # 5 minutes

# Priority queue for message handling
message_queue = PriorityQueue()

def store_peer_data():
    """Store peer data in persistent database"""
    with PEER_LOCK:
        for peer in PEERS:
            ip, port = peer
            score = PEER_SCORES.get(peer, 100)
            latency = PEER_LATENCIES.get(peer, 0)
            last_seen = datetime.datetime.now(pytz.utc).isoformat()

            PEER_DB_CURSOR.execute('''INSERT OR REPLACE INTO peers
                                    (ip, port, score, latency, last_seen)
                                    VALUES (?, ?, ?, ?, ?)''',
                                    (ip, port, score, latency, last_seen))
        PEER_DB.commit()
        logger.info("Persisted peer data to database")

def load_peer_data():
    """Load peer data from persistent database"""
    PEER_DB_CURSOR.execute("SELECT ip, port, score, latency FROM peers")
    rows = PEER_DB_CURSOR.fetchall()
    with PEER_LOCK:
        for row in rows:
            ip, port, score, latency = row
            peer = (ip, port)
            PEERS.add(peer)
            PEER_SCORES[peer] = score
            PEER_LATENCIES[peer] = latency
        logger.info(f"Loaded {len(rows)} peers from database")

def setup_nat_traversal():
    """Configure NAT traversal using UPnP, STUN, and TURN fallback"""
    public_ip = None
    public_port = P2P_PORT

    # UPnP port forwarding
    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200
        upnp.discover()
        upnp.selectigd()
        upnp.addportmapping(P2P_PORT, 'TCP', upnp.lanaddr, P2P_PORT, 'Coinium', '')
        logger.info(f"UPnP port forwarding enabled: {upnp.lanaddr}:{P2P_PORT}")
    except Exception as e:
        logger.error(f"UPnP failed: {e}")

    # STUN for public IP discovery
    try:
        nat_type, public_ip, public_port = stun.get_ip_info()
        if public_ip and public_port:
            logger.info(f"Public IP discovered via STUN: {public_ip}:{public_port}")
        else:
            logger.warning("STUN did not return public IP/port")
    except Exception as e:
        logger.error(f"STUN failed: {e}")

    # TURN fallback configuration
    if not public_ip:
        logger.info("Attempting TURN server fallback")
        try:
            turn_client = aiortc.rtcicetransport.IceTransport(TURN_SERVER)
            turn_client.set_credentials(TURN_USER, TURN_PASSWORD)
            turn_client.gather_candidates()

            # Wait for candidate gathering
            time.sleep(2)

            if turn_client.candidates:
                public_ip = turn_client.candidates[0].address
                public_port = turn_client.candidates[0].port
                logger.info(f"TURN fallback address: {public_ip}:{public_port}")
        except Exception as e:
            logger.error(f"TURN setup failed: {e}")

    return public_ip, public_port

def create_ssl_context(server_side=False, require_mtls=False):
    """Create SSL context with appropriate settings"""
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH if not server_side else ssl.Purpose.CLIENT_AUTH
    )

    if server_side:
        context.load_cert_chain(certfile=SSL_CERT, keyfile=SSL_KEY)
        if require_mtls:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(CA_CERT)
    else:
        context.load_verify_locations(CA_CERT)

    return context

def token_bucket_check(peer_ip):
    """Token bucket rate limiting implementation"""
    now = time.time()
    bucket_key = f"bucket_{peer_ip}"

    # Initialize bucket if not exists
    if bucket_key not in RATE_LIMITS:
        RATE_LIMITS[bucket_key] = {
            'tokens': TOKEN_BUCKET_CAPACITY,
            'last_check': now
        }

    # Calculate time elapsed and add tokens
    elapsed = now - RATE_LIMITS[bucket_key]['last_check']
    tokens_to_add = elapsed * TOKEN_BUCKET_RATE
    RATE_LIMITS[bucket_key]['tokens'] = min(
        TOKEN_BUCKET_CAPACITY,
        RATE_LIMITS[bucket_key]['tokens'] + tokens_to_add
    )
    RATE_LIMITS[bucket_key]['last_check'] = now

    # Check if tokens available
    if RATE_LIMITS[bucket_key]['tokens'] >= 1:
        RATE_LIMITS[bucket_key]['tokens'] -= 1
        return True
    return False

def send_message(peer, message, use_ssl=True, timeout=5):
    """Send message to a peer with SSL encryption and token bucket"""
    ip, port = peer
    start_time = time.time()

    # Apply token bucket rate limiting
    if not token_bucket_check(ip):
        logger.warning(f"Rate limited peer {ip}:{port}")
        return False

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if use_ssl:
            context = create_ssl_context(server_side=False)
            ssock = context.wrap_socket(sock, server_hostname=ip)
            ssock.connect((ip, port))
            ssock.sendall(json.dumps(message).encode())
            ssock.close()
        else:
            sock.connect((ip, port))
            sock.sendall(json.dumps(message).encode())
            sock.close()

        latency = time.time() - start_time
        with PEER_LOCK:
            PEER_LATENCIES[peer] = latency
            update_peer_score(peer, 1)  # Reward for successful communication
        logger.info(f"Sent message to {ip}:{port} in {latency:.4f}s")
        return True
    except Exception as e:
        logger.error(f"Failed to send message to {peer}: {e}")
        with PEER_LOCK:
            update_peer_score(peer, -3)  # Penalize for failure
        return False

def generate_message_id(message):
    """Create unique message ID for deduplication"""
    message_str = json.dumps(message, sort_keys=True)
    return hashlib.sha256(message_str.encode()).hexdigest()

def gossip_message(message, origin_peer=None, ttl=5, priority=MessagePriority.OTHER):
    global MESSAGE_SEEN_CACHE
    """Gossip-style message propagation with deduplication and prioritization"""
    # Generate message ID for deduplication
    message_id = generate_message_id(message)

    # Check if we've seen this message recently
    if message_id in MESSAGE_SEEN_CACHE:
        return
    MESSAGE_SEEN_CACHE.add(message_id)

    # Clean old messages from cache
    if len(MESSAGE_SEEN_CACHE) > 10000:
        #global MESSAGE_SEEN_CACHE
        MESSAGE_SEEN_CACHE = set()

    # Add metadata to message
    message['ttl'] = ttl - 1
    message['origin'] = origin_peer
    message['message_id'] = message_id
    message['vector_clock'] = VECTOR_CLOCKS.get(os.urandom(16).hex(), 0)

    # Add to priority queue instead of sending immediately
    message_queue.put((priority.value, time.time(), message_id, message))
    logger.debug(f"Queued message {message_id[:8]} at priority {priority.name}")

def process_message_queue():
    """Process messages from the priority queue"""
    while True:
        if not message_queue.empty():
            priority, timestamp, msg_id, message = message_queue.get()
            ttl = message.get('ttl', 0)

            # Skip expired messages
            if ttl <= 0:
                continue

            with PEER_LOCK:
                # Adjust fanout based on network size
                dynamic_fanout = min(GOSSIP_FANOUT + len(PEERS)//10, MAX_PEERS)
                all_peers = list(PEERS)
                origin_peer = message.get('origin')

                if origin_peer in all_peers:
                    all_peers.remove(origin_peer)

                if len(all_peers) <= dynamic_fanout:
                    targets = all_peers
                else:
                    targets = random.sample(all_peers, dynamic_fanout)

            # Send to selected peers
            for peer in targets:
                threading.Thread(target=send_message, args=(peer, message)).start()

            logger.debug(f"Propagated message {msg_id[:8]} to {len(targets)} peers")

        time.sleep(0.1)  # Prevent busy waiting

def start_message_processor():
    """Start message queue processor thread"""
    threading.Thread(target=process_message_queue, daemon=True).start()

def add_peer(ip, port):
    """Add a new peer to the network"""
    peer = (ip, port)
    with PEER_LOCK:
        if peer not in PEERS and len(PEERS) < MAX_PEERS:
            PEERS.add(peer)
            PEER_SCORES[peer] = 100  # Initial score
            PEER_LATENCIES[peer] = 0
            logger.info(f"Added peer: {ip}:{port}")
            return True
    return False

def remove_peer(ip, port):
    """Remove a peer from the network"""
    peer = (ip, port)
    with PEER_LOCK:
        if peer in PEERS:
            PEERS.remove(peer)
            if peer in PEER_SCORES:
                del PEER_SCORES[peer]
            if peer in PEER_LATENCIES:
                del PEER_LATENCIES[peer]
            logger.info(f"Removed peer: {ip}:{port}")
            return True
    return False

def update_peer_score(peer, delta):
    """Update a peer's reputation score"""
    if peer not in PEER_SCORES:
        PEER_SCORES[peer] = 100
    PEER_SCORES[peer] = max(0, min(200, PEER_SCORES[peer] + delta))

    # Auto-blacklist low scoring peers
    if PEER_SCORES[peer] < MIN_PEER_SCORE:
        remove_peer(*peer)
        logger.warning(f"Blacklisted peer {peer} for low score")

def decay_peer_scores():
    """Periodically decay peer scores"""
    while True:
        time.sleep(SCORE_DECAY_INTERVAL)
        with PEER_LOCK:
            for peer in list(PEER_SCORES.keys()):
                PEER_SCORES[peer] = max(0, PEER_SCORES[peer] * SCORE_DECAY_FACTOR)
            logger.info("Decayed peer scores")
        store_peer_data()

def start_score_decay():
    """Start score decay thread"""
    threading.Thread(target=decay_peer_scores, daemon=True).start()

def list_peers():
    """List all active peers"""
    with PEER_LOCK:
        return list(PEERS)

def broadcast_peer_list():
    """Broadcast the current peer list to all peers"""
    peer_list = list_peers()
    message = {"type": "PEER_LIST", "data": peer_list}
    gossip_message(message, priority=MessagePriority.PEER_LIST)

def generate_ssl_cert():
    """Generate a self-signed SSL certificate for secure communication"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from datetime import timedelta

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Coinium Network"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"coinum.network"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"coinum.network")]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    with open(SSL_CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(SSL_KEY, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    logger.info("Generated self-signed SSL certificate")

def is_health_check_running():
    """Check if health check thread is running"""
    global health_check_thread
    return health_check_thread and health_check_thread.is_alive()

def stop_reputation_exchange():
    """Stop the reputation exchange thread"""
    global reputation_exchange_thread
    if reputation_exchange_thread and reputation_exchange_thread.is_alive():
        reputation_exchange_thread.join(timeout=1)
        logger.info("Reputation exchange thread stopped")
    else:
        logger.warning("Reputation exchange thread was not running")

def is_reputation_exchange_running():
    """Check if reputation exchange thread is running"""
    global reputation_exchange_thread
    return reputation_exchange_thread and reputation_exchange_thread.is_alive()

def stop_score_decay():
    """Stop the score decay thread"""
    global score_decay_thread
    if score_decay_thread and score_decay_thread.is_alive():
        score_decay_thread.join(timeout=1)
        logger.info("Score decay thread stopped")
    else:
        logger.warning("Score decay thread was not running")

def is_score_decay_running():
    """Check if score decay thread is running"""
    global score_decay_thread
    return score_decay_thread and score_decay_thread.is_alive()

def stop_anti_entropy():
    """Stop the anti-entropy thread"""
    global anti_entropy_thread
    if anti_entropy_thread and anti_entropy_thread.is_alive():
        anti_entropy_thread.join(timeout=1)
        logger.info("Anti-entropy thread stopped")
    else:
        logger.warning("Anti-entropy thread was not running")

def is_anti_entropy_running():
    """Check if anti-entropy thread is running"""
    global anti_entropy_thread
    return anti_entropy_thread and anti_entropy_thread.is_alive()

def stop_message_processor():
    """Stop the message processor thread"""
    global message_processor_thread
    if message_processor_thread and message_processor_thread.is_alive():
        message_processor_thread.join(timeout=1)
        logger.info("Message processor thread stopped")
    else:
        logger.warning("Message processor thread was not running")

def is_message_processor_running():
    """Check if message processor thread is running"""
    global message_processor_thread
    return message_processor_thread and message_processor_thread.is_alive()

def set_gossip_fanout(fanout):
    """Set the dynamic gossip fanout based on network size"""
    global GOSSIP_FANOUT
    if fanout < 1:
        logger.warning("Fanout must be at least 1, setting to 1")
        GOSSIP_FANOUT = 1
    else:
        GOSSIP_FANOUT = fanout
    logger.info(f"Set gossip fanout to {GOSSIP_FANOUT}")

def get_gossip_fanout():
    """Get the current gossip fanout setting"""
    global GOSSIP_FANOUT
    return GOSSIP_FANOUT


def stop_health_check():
    """Stop the health check thread"""
    global health_check_thread
    if health_check_thread and health_check_thread.is_alive():
        health_check_thread.join(timeout=1)
        logger.info("Health check thread stopped")
    else:
        logger.warning("Health check thread was not running")


def get_metrics():
    """Get current network metrics"""
    with PEER_LOCK:
        metrics = {
            "total_peers": len(PEERS),
            "peer_scores": PEER_SCORES,
            "peer_latencies": PEER_LATENCIES,
            "block_votes": {k: len(v) for k, v in BLOCK_VOTES.items()},
            "validators": list(VALIDATORS)
        }
    return metrics

def exchange_reputation():
    """Exchange peer reputation summaries with other peers"""
    with PEER_LOCK:
        reputation_data = {
            f"{peer[0]}:{peer[1]}": score for peer, score in PEER_SCORES.items()
        }

    message = {"type": "REPUTATION_REPORT", "data": reputation_data}
    gossip_message(message, priority=MessagePriority.OTHER)

    logger.info("Exchanged reputation data with peers")

def start_reputation_exchange():
    """Periodically exchange reputation data"""
    while True:
        time.sleep(1800)  # Every 30 minutes
        exchange_reputation()

def save_peers(filename='peers.json'):
    """Save current peers to a JSON file"""
    with open(filename, 'w') as f:
        json.dump(list(PEERS), f)

def load_peers(filename='peers.json'):
    """Load peers from a JSON file"""
    global PEERS
    try:
        with open(filename, 'r') as f:
            PEERS = set(tuple(peer) for peer in json.load(f))
        logger.info(f"Loaded {len(PEERS)} peers from {filename}.")
    except FileNotFoundError:
        logger.warning("No peers file found, starting with an empty peer list.")
    except json.JSONDecodeError:
        logger.error("Error decoding peers file, starting with an empty peer list.")
        PEERS = set()

def ping_peers(timeout=2):
    """Check connectivity to all peers"""
    responsive_peers = []
    for peer in list_peers():
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(peer)
            sock.close()
            latency = time.time() - start_time

            with PEER_LOCK:
                PEER_LATENCIES[peer] = latency
                update_peer_score(peer, 1)
            responsive_peers.append(peer)
        except:
            with PEER_LOCK:
                update_peer_score(peer, -3)
    return responsive_peers

def start_health_check():
    """Periodically check peer health"""
    while True:
        time.sleep(60)  # Every minute
        logger.info("Starting health check...")
        responsive = ping_peers()
        logger.info(f"Health check complete. Responsive peers: {len(responsive)}/{len(PEERS)}")
        store_peer_data()

def validate_block_signature(block):
    """Validate block signature using validator's public key"""
    try:
        validator = block.get("validator")
        signature = block.get("signature")
        if not validator or not signature:
            return False

        # Fetch validator's public key
        C.execute("SELECT public_key FROM wallets WHERE wallet_address = ?", (validator,))
        result = C.fetchone()
        if not result:
            return False

        public_key = serialization.load_der_public_key(
            bytes.fromhex(result[0]),
            backend=default_backend()
        )

        # Create a copy of block without signature for verification
        block_copy = block.copy()
        block_copy.pop("signature", None)

        # Verify signature
        public_key.verify(
            bytes.fromhex(signature),
            json.dumps(block_copy, sort_keys=True).encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        logger.error(f"Block signature validation failed: {e}")
        return False

def handle_block_vote(block_hash, voter):
    """Process vote for a block"""
    if voter not in VALIDATORS:
        logger.warning(f"Non-validator attempted to vote: {voter}")
        return False

    if block_hash not in BLOCK_VOTES:
        BLOCK_VOTES[block_hash] = set()

    if voter not in BLOCK_VOTES[block_hash]:
        BLOCK_VOTES[block_hash].add(voter)
        logger.info(f"Vote received for block {block_hash[:8]}... (Total: {len(BLOCK_VOTES[block_hash])})")

        # Check if supermajority reached
        if len(BLOCK_VOTES[block_hash]) > len(VALIDATORS) * 2 / 3:
            logger.info(f"Block {block_hash[:8]}... achieved consensus!")
            return True
    return False

def get_validators():
    """Fetch current validators from database"""
    with PEER_LOCK:
        VALIDATORS.clear()
        C.execute("SELECT wallet_address FROM wallets WHERE staked >= ?", (MIN_STAKE,))
        for row in C.fetchall():
            VALIDATORS.add(row[0])
        return VALIDATORS

def refresh_validators():
    """Periodically refresh validator list"""
    while True:
        time.sleep(300)  # Every 5 minutes
        get_validators()
        logger.info("Refreshed validator list")

def detect_partitions(blockchain):
    """Detect network partitions by comparing chain lengths"""
    chain_lengths = []

    # Gather chain lengths from peers
    for peer in list_peers():
        try:
            response = send_message(peer, {"type": "CHAIN_LENGTH_REQUEST"})
            if response and 'length' in response:
                chain_lengths.append(response['length'])
        except:
            continue

    # Check for significant divergence
    our_length = len(blockchain)
    divergent_peers = [l for l in chain_lengths if abs(l - our_length) > FORK_ALERT_THRESHOLD]

    if divergent_peers:
        logger.error(f"NETWORK PARTITION DETECTED! Our chain: {our_length}, Divergent peers: {divergent_peers}")
        # Trigger reconciliation process
        threading.Thread(target=reconcile_partition, args=(blockchain, divergent_peers)).start()
        return True

    return False

def reconcile_partition(blockchain, divergent_peers):
    """Reconcile network partition by syncing with longest chain"""
    logger.warning("Starting partition reconciliation...")

    # Find peer with longest chain
    longest_peer = None
    max_length = len(blockchain)

    for peer in list_peers():
        try:
            response = send_message(peer, {"type": "CHAIN_LENGTH_REQUEST"})
            if response and response['length'] > max_length:
                max_length = response['length']
                longest_peer = peer
        except:
            continue

    if not longest_peer:
        logger.error("No longer chain found for reconciliation")
        return

    logger.info(f"Syncing with peer {longest_peer} (chain length: {max_length})")

    # Fetch entire chain from peer
    try:
        response = send_message(longest_peer, {"type": "CHAIN_REQUEST"})
        if response and 'chain' in response:
            new_chain = response['chain']

            # Validate the new chain
            if validate_chain(new_chain):
                # Replace our chain
                blockchain.clear()
                blockchain.extend(new_chain)
                logger.info(f"Reconciled chain to height {len(blockchain)}")
            else:
                logger.error("Received invalid chain during reconciliation")
        else:
            logger.error("Failed to fetch chain during reconciliation")
    except Exception as e:
        logger.error(f"Reconciliation failed: {e}")

def validate_chain(chain):
    """Validate entire blockchain (placeholder implementation)"""
    # In a real implementation, this would validate PoW, signatures, and linkages
    return True

def rotate_mempool_key():
    """Rotate symmetric key for encrypted mempool"""
    global CURRENT_MEMPOOL_KEY_ID, MEMPOOL_KEYS

    # Generate new key
    key_id = CURRENT_MEMPOOL_KEY_ID + 1
    key = secrets.token_bytes(32)
    MEMPOOL_KEYS[key_id] = {
        'key': key,
        'created_at': datetime.datetime.utcnow()
    }
    CURRENT_MEMPOOL_KEY_ID = key_id

    # Broadcast new key to network
    broadcast_key(key_id)

    logger.info(f"Rotated mempool encryption key to ID {key_id}")

def initialize_mempool_key():
    key = secrets.token_bytes(32)
    MEMPOOL_KEYS[CURRENT_MEMPOOL_KEY_ID] = {
        'key': key,
        'created_at': datetime.datetime.utcnow()
    }
    logger.info("Initialized mempool encryption key (ID 0)")

def broadcast_key(key_id):
    """Broadcast new mempool key to validators"""
    if key_id not in MEMPOOL_KEYS:
        return

    key_data = MEMPOOL_KEYS[key_id]
    message = {
        "type": "MEMPOOL_KEY",
        "key_id": key_id,
        "key": base64.b64encode(key_data['key']).decode(),
        "created_at": key_data['created_at'].isoformat()
    }

    # Only send to validators
    for validator in VALIDATORS:
        # In real implementation, we'd look up validator's address
        threading.Thread(target=send_message, args=((validator, P2P_PORT), message)).start()

def encrypt_transaction(tx):
    """Encrypt transaction for private mempool"""
    if not MEMPOOL_KEYS:
        return tx  # Fallback to plaintext if no keys

    # Use latest key
    key_data = MEMPOOL_KEYS[CURRENT_MEMPOOL_KEY_ID]
    key = key_data['key']

    # Serialize transaction
    tx_str = json.dumps(tx)
    tx_bytes = tx_str.encode()

    # Generate IV
    iv = os.urandom(16)

    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(tx_bytes) + encryptor.finalize()

    return {
        "encrypted": True,
        "key_id": CURRENT_MEMPOOL_KEY_ID,
        "iv": base64.b64encode(iv).decode(),
        "tag": base64.b64encode(encryptor.tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def decrypt_transaction(enc_tx):
    """Decrypt transaction from private mempool"""
    if not enc_tx.get("encrypted"):
        return enc_tx

    key_id = enc_tx.get("key_id")
    if key_id not in MEMPOOL_KEYS:
        raise ValueError("Decryption key not available")

    key_data = MEMPOOL_KEYS[key_id]
    key = key_data['key']

    # Decode components
    iv = base64.b64decode(enc_tx["iv"])
    tag = base64.b64decode(enc_tx["tag"])
    ciphertext = base64.b64decode(enc_tx["ciphertext"])

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    tx_bytes = decryptor.update(ciphertext) + decryptor.finalize()

    return json.loads(tx_bytes.decode())

def handle_client(conn, addr, blockchain, pending_transactions, use_ssl=False):
    """Handle incoming client connections"""
    ip, port = addr
    try:
        # Apply token bucket rate limiting
        if not token_bucket_check(ip):
            conn.close()
            return

        data = conn.recv(65536)  # 64KB max
        if not data:
            return

        message = json.loads(data.decode())
        msg_type = message.get("type")

        # Check for duplicate messages
        message_id = generate_message_id(message)
        if message_id in MESSAGE_SEEN_CACHE:
            return
        MESSAGE_SEEN_CACHE.add(message_id)

        # Handle message based on type
        if msg_type == "NEW_TRANSACTION":
            tx = message["data"]
            if tx.get("encrypted"):
                try:
                    tx = decrypt_transaction(tx)
                except Exception as e:
                    logger.error(f"Transaction decryption failed: {e}")
                    return

            if tx not in pending_transactions:
                pending_transactions.append(tx)
                logger.info(f"Received new transaction from {addr}")

                # Encrypt before re-gossiping
                if MEMPOOL_KEYS:
                    tx = encrypt_transaction(tx)

                # Re-gossip to other peers
                gossip_message({
                    "type": "NEW_TRANSACTION",
                    "data": tx
                }, origin_peer=addr, priority=MessagePriority.TX)

        elif msg_type == "NEW_BLOCK":
            block = message["data"]
            if validate_block_signature(block) and block not in blockchain:
                blockchain.append(block)
                logger.info(f"Valid block received from {addr}: {block['hash'][:8]}...")
                # Re-gossip to other peers
                gossip_message({
                    "type": "NEW_BLOCK",
                    "data": block
                }, origin_peer=addr, priority=MessagePriority.BLOCK)

                # Automatically vote for valid blocks
                if addr[0] in VALIDATORS:  # Only validators vote
                    vote_msg = {
                        "type": "BLOCK_VOTE",
                        "block_hash": block["hash"],
                        "voter": addr[0]
                    }
                    gossip_message(vote_msg, priority=MessagePriority.VOTE)

        elif msg_type in ["SNAPSHOT_REQUEST", "SYNC_REQUEST", "SYNC_DATA", "SYNC_COMPLETE"]:
            handle_sync_message(message, addr)

        elif msg_type == "BLOCK_VOTE":
            block_hash = message["block_hash"]
            voter = message["voter"]
            if handle_block_vote(block_hash, voter):
                # Consensus reached, process block
                logger.info(f"Consensus reached for block {block_hash[:8]}...")

        elif msg_type == "PEER_LIST":
            new_peers = message["data"]
            for peer in new_peers:
                if peer not in PEERS:
                    add_peer(peer[0], peer[1])

        elif msg_type == "PING":
            # Respond to ping
            conn.sendall(json.dumps({"type": "PONG"}).encode())

        elif msg_type == "PONG":
            # Handle pong response
            with PEER_LOCK:
                update_peer_score(addr, 1)

        elif msg_type == "VALIDATOR_LIST":
            # Update validator set
            new_validators = set(message["data"])
            with PEER_LOCK:
                VALIDATORS.update(new_validators)

        elif msg_type == "REPUTATION_REPORT":
            # Update peer scores based on reputation report
            reputation_data = message["data"]
            with PEER_LOCK:
                for peer_addr, score in reputation_data.items():
                    ip, port = peer_addr.split(":")
                    peer = (ip, int(port))
                    if peer in PEER_SCORES:
                        # Weighted average of scores
                        PEER_SCORES[peer] = (PEER_SCORES[peer] + score) / 2

        elif msg_type == "CHAIN_LENGTH_REQUEST":
            # Respond with our chain length
            conn.sendall(json.dumps({
                "type": "CHAIN_LENGTH_RESPONSE",
                "length": len(blockchain)
            }).encode())

        elif msg_type == "CHAIN_REQUEST":
            # Send entire chain
            conn.sendall(json.dumps({
                "type": "CHAIN_RESPONSE",
                "chain": blockchain
            }).encode())

        elif msg_type == "MEMPOOL_KEY":
            # Store new mempool key
            key_id = message["key_id"]
            key = base64.b64decode(message["key"])
            created_at = datetime.datetime.fromisoformat(message["created_at"])

            MEMPOOL_KEYS[key_id] = {
                'key': key,
                'created_at': created_at
            }
            logger.info(f"Received new mempool key ID {key_id}")

        else:
            logger.warning(f"Unknown message type from {addr}: {msg_type}")

    except Exception as e:
        logger.error(f"Error handling client {addr}: {e}")
        with PEER_LOCK:
            update_peer_score(addr, -5)
    finally:
        conn.close()

def start_server(port, blockchain, pending_transactions, use_ssl=True, require_mtls=False):
    """Start the P2P server"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(10)
    logger.info(f"P2P server listening on port {port} (SSL: {use_ssl}, mTLS: {require_mtls})...")

    # Configure SSL if enabled
    ssl_context = None
    if use_ssl:
        ssl_context = create_ssl_context(server_side=True, require_mtls=require_mtls)

    while True:
        try:
            client, addr = server.accept()
            if use_ssl:
                try:
                    client = ssl_context.wrap_socket(client, server_side=True)
                    # mTLS verification
                    if require_mtls:
                        cert = client.getpeercert()
                        if not cert or 'subject' not in cert:
                            raise ssl.SSLError("No client certificate provided")
                except ssl.SSLError as e:
                    logger.error(f"SSL handshake failed with {addr}: {e}")
                    client.close()
                    continue

            threading.Thread(
                target=handle_client,
                args=(client, addr, blockchain, pending_transactions, use_ssl),
                daemon=True
            ).start()
        except Exception as e:
            logger.error(f"Server error: {e}")

class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler for serving metrics"""
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            with PEER_LOCK:
                metrics = {
                    "peers": len(PEERS),
                    "peer_scores": {f"{ip}:{port}": score for (ip, port), score in PEER_SCORES.items()},
                    "average_latency": sum(PEER_LATENCIES.values()) / len(PEER_LATENCIES) if PEER_LATENCIES else 0,
                    "validators": list(VALIDATORS),
                    "pending_transactions": len(pending_transactions),
                    "blockchain_length": len(blockchain),
                    "mempool_key_id": CURRENT_MEMPOOL_KEY_ID,
                    "message_queue_size": message_queue.qsize()
                }

            self.wfile.write(json.dumps(metrics).encode())
        else:
            self.send_response(404)
            self.end_headers()

def start_metrics_server(port):
    """Start HTTP server for metrics"""
    server = HTTPServer(('0.0.0.0', port), MetricsHandler)
    logger.info(f"Metrics server running on port {port}")
    server.serve_forever()

def bootstrap_network():
    """Connect to bootstrap nodes"""
    for node in BOOTSTRAP_NODES:
        add_peer(node[0], node[1])
        send_message(node, {"type": "PEER_REQUEST"})

    # Request validator list
    gossip_message({"type": "VALIDATOR_REQUEST"})

def run_anti_entropy():
    """Periodic anti-entropy to synchronize state"""
    while True:
        time.sleep(ANTI_ENTROPY_INTERVAL)
        logger.info("Running anti-entropy round")

        # Exchange vector clocks with random peers
        with PEER_LOCK:
            if not PEERS:
                continue
            target_peer = random.choice(list(PEERS))

        try:
            response = send_message(target_peer, {
                "type": "VECTOR_CLOCKS",
                "clocks": VECTOR_CLOCKS
            })

            if response and response.get("type") == "VECTOR_CLOCKS_RESPONSE":
                # Merge vector clocks
                for key, value in response["clocks"].items():
                    if key not in VECTOR_CLOCKS or VECTOR_CLOCKS[key] < value:
                        VECTOR_CLOCKS[key] = value
        except Exception as e:
            logger.error(f"Anti-entropy failed: {e}")

def start_anti_entropy():
    """Start anti-entropy thread"""
    threading.Thread(target=run_anti_entropy, daemon=True).start()

def start_network_services(blockchain, pending_transactions, require_mtls=False):
    """Start all network services"""
    # Load persistent peer data
    load_peer_data()

    # Start P2P server
    threading.Thread(
        target=start_server,
        args=(P2P_PORT, blockchain, pending_transactions, True, require_mtls),
        daemon=True
    ).start()

    # Start metrics server
    threading.Thread(
        target=start_metrics_server,
        args=(RPC_PORT,),
        daemon=True
    ).start()

    # Start health checking
    threading.Thread(
        target=start_health_check,
        daemon=True
    ).start()

    # Start reputation exchange
    threading.Thread(
        target=start_reputation_exchange,
        daemon=True
    ).start()

    # Start validator refresh
    threading.Thread(
        target=refresh_validators,
        daemon=True
    ).start()

    # Start score decay
    threading.Thread(
        target=start_score_decay,
        daemon=True
    ).start()

    # Start message processor
    threading.Thread(
        target=start_message_processor,
        daemon=True
    ).start()

    # Start anti-entropy
    threading.Thread(
        target=start_anti_entropy,
        daemon=True
    ).start()

    # Start mempool key rotation
    threading.Thread(
        target=rotate_mempool_key,
        daemon=True
    ).start()

    # Bootstrap network
    bootstrap_network()

def create_ca():
    """Create Certificate Authority if not exists"""
    if os.path.exists(CA_CERT) and os.path.exists(CA_KEY):
        return

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Generate CA private key
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    # Create self-signed CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Coinium CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Coinium Network"),
    ])

    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365*10)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())

    # Save CA certificate
    with open(CA_CERT, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    # Save CA private key
    with open(CA_KEY, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"coinium-secure"),
        ))

    logger.info("Generated new Certificate Authority")

def sign_certificate(csr_pem):
    """Sign a certificate signing request"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    # Load CA
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=b"coinium-secure",
            backend=default_backend()
        )

    # Parse CSR
    csr = x509.load_pem_x509_csr(csr_pem)

    # Validate CSR subject
    subject = csr.subject
    common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    # Create certificate
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())

    return cert.public_bytes(serialization.Encoding.PEM)

def revoke_certificate(serial):
    """Revoke a certificate"""
    serial_hex = serial.hex()
    PEER_DB_CURSOR.execute("INSERT OR IGNORE INTO revoked_certs (serial) VALUES (?)", (serial_hex,))
    PEER_DB.commit()
    logger.warning(f"Revoked certificate: {serial_hex}")

def is_cert_revoked(serial):
    """Check if certificate is revoked"""
    serial_hex = serial.hex()
    PEER_DB_CURSOR.execute("SELECT 1 FROM revoked_certs WHERE serial = ?", (serial_hex,))
    return PEER_DB_CURSOR.fetchone() is not None

# Initialize network
create_ca()
public_ip, public_port = setup_nat_traversal()

if public_ip:
    add_peer(public_ip, public_port)

#get_validators()  # Load initial validators

# Example usage (to be called from main application)
if __name__ == "__main__":
    # Placeholder for blockchain and transactions
    blockchain = []
    pending_transactions = []

    # Start network services with mTLS enabled
    start_network_services(blockchain, pending_transactions, require_mtls=True)

    # Keep main thread alive
    while True:
        # Periodic partition detection
        detect_partitions(blockchain)
        time.sleep(60)