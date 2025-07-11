"""
Database connection, schema, queries, and sync logic
"""
import sqlite3
import threading
import time
import json
import zlib
import hashlib
import logging
from .config import DATABASE_FILE, DATABASE_VERSION

# Database lock for thread safety
db_lock = threading.Lock()
conn = None

def init_database():
    """Initialize the database with all required tables"""
    global conn
    
    conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
    c = conn.cursor()
    
    # Create wallets table
    c.execute('''
        CREATE TABLE IF NOT EXISTS wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wallet_address TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            encrypted_private_key TEXT NOT NULL,
            seed_phrase TEXT NOT NULL,
            balance REAL DEFAULT 0.0,
            staked REAL DEFAULT 0.0,
            last_online REAL DEFAULT 0.0
        )
    ''')
    
    # Create transactions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tx_hash TEXT UNIQUE NOT NULL,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            amount REAL NOT NULL,
            fee REAL NOT NULL DEFAULT 0,
            timestamp REAL NOT NULL,
            signature TEXT,
            is_coinbase INTEGER DEFAULT 0,
            shard_id INTEGER
        )
    ''')
    
    # Create blocks table
    c.execute('''
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_index INTEGER UNIQUE NOT NULL,
            previous_hash TEXT NOT NULL,
            timestamp REAL NOT NULL,
            merkle_root TEXT NOT NULL,
            nonce INTEGER NOT NULL,
            hash TEXT UNIQUE NOT NULL,
            difficulty INTEGER NOT NULL,
            validator TEXT,
            vote_count INTEGER DEFAULT 0
        )
    ''')
    
    # Create UTXOs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS utxos (
            tx_id TEXT NOT NULL,
            output_index INTEGER NOT NULL,
            recipient TEXT NOT NULL,
            amount REAL NOT NULL,
            spent INTEGER DEFAULT 0,
            PRIMARY KEY (tx_id, output_index)
        )
    ''')
    
    # Create contracts table
    c.execute('''
        CREATE TABLE IF NOT EXISTS contracts (
            address TEXT PRIMARY KEY,
            code TEXT NOT NULL,
            creator TEXT NOT NULL,
            balance REAL DEFAULT 0.0,
            storage TEXT
        )
    ''')
    
    # Create NFTs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS nfts (
            id TEXT PRIMARY KEY,
            creator TEXT NOT NULL,
            owner TEXT NOT NULL,
            metadata_uri TEXT NOT NULL,
            created_at REAL NOT NULL
        )
    ''')
    
    # Create proposals table
    c.execute('''
        CREATE TABLE IF NOT EXISTS proposals (
            id TEXT PRIMARY KEY,
            creator TEXT NOT NULL,
            description TEXT NOT NULL,
            options TEXT NOT NULL,
            votes TEXT NOT NULL,
            start_time REAL NOT NULL,
            end_time REAL NOT NULL,
            executed INTEGER DEFAULT 0
        )
    ''')
    
    # Create payment channels table
    c.execute('''
        CREATE TABLE IF NOT EXISTS payment_channels (
            id TEXT PRIMARY KEY,
            party1 TEXT NOT NULL,
            party2 TEXT NOT NULL,
            deposit1 REAL NOT NULL,
            deposit2 REAL NOT NULL,
            balance1 REAL NOT NULL,
            balance2 REAL NOT NULL,
            state_version INTEGER DEFAULT 0,
            closing_tx_id TEXT,
            closed INTEGER DEFAULT 0
        )
    ''')
    
    # Create burned coins table
    c.execute('''
        CREATE TABLE IF NOT EXISTS burned_coins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wallet_address TEXT NOT NULL,
            amount REAL NOT NULL,
            timestamp REAL NOT NULL
        )
    ''')
    
    conn.commit()
    logging.info("Database initialized successfully")
    return conn

def get_db_connection():
    """Get the database connection"""
    global conn
    if conn is None:
        conn = init_database()
    return conn

def execute_query(query, params=None, fetch=False):
    """Execute a database query with thread safety"""
    with db_lock:
        c = get_db_connection().cursor()
        if params:
            c.execute(query, params)
        else:
            c.execute(query)
        
        if fetch:
            return c.fetchall()
        else:
            conn.commit()
            return c.lastrowid

def create_database_snapshot():
    """Create a compressed snapshot of the entire database"""
    snapshot = {
        "version": DATABASE_VERSION,
        "timestamp": time.time(),
        "wallets": [],
        "transactions": [],
        "blocks": [],
        "utxos": [],
        "contracts": [],
        "nfts": [],
        "proposals": [],
        "channels": [],
        "burned": []
    }
    
    # Query all tables
    c = get_db_connection().cursor()
    
    c.execute("SELECT * FROM wallets")
    snapshot["wallets"] = c.fetchall()
    
    c.execute("SELECT * FROM transactions")
    snapshot["transactions"] = c.fetchall()
    
    c.execute("SELECT * FROM blocks")
    snapshot["blocks"] = c.fetchall()
    
    c.execute("SELECT * FROM utxos")
    snapshot["utxos"] = c.fetchall()
    
    c.execute("SELECT * FROM contracts")
    snapshot["contracts"] = c.fetchall()
    
    c.execute("SELECT * FROM nfts")
    snapshot["nfts"] = c.fetchall()
    
    c.execute("SELECT * FROM proposals")
    snapshot["proposals"] = c.fetchall()
    
    c.execute("SELECT * FROM payment_channels")
    snapshot["channels"] = c.fetchall()
    
    c.execute("SELECT * FROM burned_coins")
    snapshot["burned"] = c.fetchall()
    
    # Compress snapshot
    json_data = json.dumps(snapshot).encode()
    compressed = zlib.compress(json_data)
    
    # Calculate checksum
    checksum = hashlib.sha256(json_data).hexdigest()
    
    return compressed, checksum

def apply_database_snapshot(snapshot_data, checksum):
    """Apply a database snapshot after validation"""
    try:
        # Decompress and validate
        decompressed = zlib.decompress(snapshot_data)
        if hashlib.sha256(decompressed).hexdigest() != checksum:
            logging.error("Snapshot checksum mismatch")
            return False
        
        snapshot = json.loads(decompressed)
        
        # Validate version
        if snapshot.get("version") != DATABASE_VERSION:
            logging.error(f"Database version mismatch: {snapshot.get('version')} vs {DATABASE_VERSION}")
            return False
        
        # Clear existing data
        with db_lock:
            c = get_db_connection().cursor()
            c.execute("DELETE FROM wallets")
            c.execute("DELETE FROM transactions")
            c.execute("DELETE FROM blocks")
            c.execute("DELETE FROM utxos")
            c.execute("DELETE FROM contracts")
            c.execute("DELETE FROM nfts")
            c.execute("DELETE FROM proposals")
            c.execute("DELETE FROM payment_channels")
            c.execute("DELETE FROM burned_coins")
            
            # Apply data from snapshot
            for table, data in snapshot.items():
                if table in ["version", "timestamp"]:
                    continue
                    
                for row in data:
                    if table == "wallets":
                        c.execute(
                            "INSERT INTO wallets (wallet_address, public_key, encrypted_private_key, seed_phrase, balance, staked, last_online) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)",
                            row[1:]  # Skip ID
                        )
                    elif table == "transactions":
                        c.execute(
                            "INSERT INTO transactions (tx_hash, sender, recipient, amount, fee, timestamp, signature, is_coinbase, shard_id) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            row[1:]  # Skip ID
                        )
                    elif table == "blocks":
                        c.execute(
                            "INSERT INTO blocks (block_index, previous_hash, timestamp, merkle_root, nonce, hash, difficulty, validator, vote_count) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            row[1:]  # Skip ID
                        )
                    # Add other tables as needed
            
            conn.commit()
            logging.info("Database snapshot applied successfully")
            return True
            
    except Exception as e:
        logging.error(f"Failed to apply database snapshot: {e}")
        return False
