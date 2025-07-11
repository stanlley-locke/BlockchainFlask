"""
Peer discovery, NAT traversal, and peer list management
"""
import socket
import threading
import time
import logging
import sqlite3
import miniupnpc
import stun
from collections import defaultdict
from core.config import P2P_PORT, BOOTSTRAP_NODES, MAX_PEERS

class NodeManager:
    """Manages peer connections and discovery"""
    
    def __init__(self):
        self.peers = set()
        self.peer_lock = threading.Lock()
        self.peer_db = sqlite3.connect("peer_store.db", check_same_thread=False)
        self.init_peer_db()
        self.public_ip = None
        self.public_port = P2P_PORT
        
    def init_peer_db(self):
        """Initialize peer database"""
        cursor = self.peer_db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS peers (
                ip TEXT,
                port INTEGER,
                last_seen TIMESTAMP,
                PRIMARY KEY (ip, port)
            )
        ''')
        self.peer_db.commit()
    
    def setup_nat_traversal(self):
        """Configure NAT traversal using UPnP and STUN"""
        self.public_ip = None
        self.public_port = P2P_PORT
        
        # Try UPnP first
        try:
            upnp = miniupnpc.UPnP()
            upnp.discoverdelay = 200
            upnp.discover()
            upnp.selectigd()
            upnp.addportmapping(P2P_PORT, 'TCP', upnp.lanaddr, P2P_PORT, 'Coinium', '')
            logging.info(f"UPnP port forwarding enabled: {upnp.lanaddr}:{P2P_PORT}")
        except Exception as e:
            logging.error(f"UPnP failed: {e}")
        
        # Use STUN for public IP discovery
        try:
            nat_type, public_ip, public_port = stun.get_ip_info()
            if public_ip and public_port:
                self.public_ip = public_ip
                self.public_port = public_port
                logging.info(f"Public IP discovered via STUN: {public_ip}:{public_port}")
        except Exception as e:
            logging.error(f"STUN failed: {e}")
        
        return self.public_ip, self.public_port
    
    def add_peer(self, ip, port):
        """Add a new peer"""
        peer = (ip, port)
        with self.peer_lock:
            if peer not in self.peers and len(self.peers) < MAX_PEERS:
                self.peers.add(peer)
                
                # Store in database
                cursor = self.peer_db.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO peers (ip, port, last_seen) VALUES (?, ?, datetime('now'))",
                    (ip, port)
                )
                self.peer_db.commit()
                
                logging.info(f"Added peer: {ip}:{port}")
                return True
        return False
    
    def remove_peer(self, ip, port):
        """Remove a peer"""
        peer = (ip, port)
        with self.peer_lock:
            if peer in self.peers:
                self.peers.remove(peer)
                
                # Remove from database
                cursor = self.peer_db.cursor()
                cursor.execute("DELETE FROM peers WHERE ip = ? AND port = ?", (ip, port))
                self.peer_db.commit()
                
                logging.info(f"Removed peer: {ip}:{port}")
                return True
        return False
    
    def get_peers(self):
        """Get list of current peers"""
        with self.peer_lock:
            return list(self.peers)
    
    def load_peers(self):
        """Load peers from database"""
        cursor = self.peer_db.cursor()
        cursor.execute("SELECT ip, port FROM peers")
        rows = cursor.fetchall()
        
        with self.peer_lock:
            for ip, port in rows:
                peer = (ip, port)
                self.peers.add(peer)
        
        logging.info(f"Loaded {len(rows)} peers from database")
    
    def save_peers(self):
        """Save current peers to database"""
        cursor = self.peer_db.cursor()
        with self.peer_lock:
            for ip, port in self.peers:
                cursor.execute(
                    "INSERT OR REPLACE INTO peers (ip, port, last_seen) VALUES (?, ?, datetime('now'))",
                    (ip, port)
                )
        self.peer_db.commit()
        logging.info("Saved peers to database")
    
    def discover_peers(self):
        """Discover peers from bootstrap nodes"""
        for ip, port in BOOTSTRAP_NODES:
            try:
                # Try to connect to bootstrap node
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    self.add_peer(ip, port)
                    logging.info(f"Connected to bootstrap node: {ip}:{port}")
                
                sock.close()
                
            except Exception as e:
                logging.error(f"Failed to connect to bootstrap node {ip}:{port}: {e}")
    
    def ping_peers(self):
        """Ping all peers to check connectivity"""
        peers_to_remove = []
        
        with self.peer_lock:
            peers_copy = list(self.peers)
        
        for ip, port in peers_copy:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                
                if result != 0:
                    peers_to_remove.append((ip, port))
                
                sock.close()
                
            except Exception as e:
                logging.error(f"Failed to ping peer {ip}:{port}: {e}")
                peers_to_remove.append((ip, port))
        
        # Remove unresponsive peers
        for ip, port in peers_to_remove:
            self.remove_peer(ip, port)
        
        if peers_to_remove:
            logging.info(f"Removed {len(peers_to_remove)} unresponsive peers")
    
    def start_peer_discovery(self):
        """Start peer discovery in background"""
        def discovery_loop():
            while True:
                try:
                    self.discover_peers()
                    self.ping_peers()
                    time.sleep(300)  # Run every 5 minutes
                except Exception as e:
                    logging.error(f"Peer discovery error: {e}")
                    time.sleep(60)
        
        discovery_thread = threading.Thread(target=discovery_loop, daemon=True)
        discovery_thread.start()
        logging.info("Started peer discovery service")
    
    def get_node_info(self):
        """Get information about this node"""
        return {
            'public_ip': self.public_ip,
            'public_port': self.public_port,
            'peer_count': len(self.peers),
            'peers': self.get_peers()
        }

# Global node manager instance
node_manager = NodeManager()
