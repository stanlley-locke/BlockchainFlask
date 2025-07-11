"""
Gossip protocol, anti-entropy, and message queue management
"""
import json
import threading
import time
import logging
import hashlib
import random
from queue import PriorityQueue
from enum import Enum
from collections import defaultdict

class MessagePriority(Enum):
    BLOCK = 0
    VOTE = 1
    TRANSACTION = 2
    PEER_LIST = 3
    OTHER = 4

class MessageManager:
    """Manages message propagation and gossip protocol"""
    
    def __init__(self, node_manager):
        self.node_manager = node_manager
        self.message_queue = PriorityQueue()
        self.message_cache = set()
        self.message_stats = defaultdict(int)
        self.gossip_fanout = 3
        self.ttl_default = 5
        self.processing = False
        
    def generate_message_id(self, message):
        """Generate unique message ID"""
        message_str = json.dumps(message, sort_keys=True)
        return hashlib.sha256(message_str.encode()).hexdigest()
    
    def add_message(self, message, priority=MessagePriority.OTHER, ttl=None):
        """Add message to gossip queue"""
        try:
            message_id = self.generate_message_id(message)
            
            # Check if message already processed
            if message_id in self.message_cache:
                return False
            
            # Add to cache
            self.message_cache.add(message_id)
            
            # Clean cache if too large
            if len(self.message_cache) > 10000:
                self.message_cache.clear()
            
            # Add metadata
            message['message_id'] = message_id
            message['ttl'] = ttl or self.ttl_default
            message['timestamp'] = time.time()
            
            # Add to queue
            self.message_queue.put((priority.value, time.time(), message))
            self.message_stats['queued'] += 1
            
            logging.debug(f"Added message {message_id[:8]} to queue")
            return True
            
        except Exception as e:
            logging.error(f"Failed to add message: {e}")
            return False
    
    def process_message_queue(self):
        """Process messages from queue"""
        while self.processing:
            try:
                if not self.message_queue.empty():
                    priority, timestamp, message = self.message_queue.get()
                    
                    # Check TTL
                    if message.get('ttl', 0) <= 0:
                        continue
                    
                    # Decrease TTL
                    message['ttl'] -= 1
                    
                    # Get peers for gossip
                    peers = self.node_manager.get_peers()
                    if not peers:
                        continue
                    
                    # Select random peers for gossip
                    num_peers = min(self.gossip_fanout, len(peers))
                    selected_peers = random.sample(peers, num_peers)
                    
                    # Send to selected peers
                    for peer in selected_peers:
                        self.send_message_to_peer(peer, message)
                    
                    self.message_stats['propagated'] += 1
                    
                time.sleep(0.1)  # Prevent busy waiting
                
            except Exception as e:
                logging.error(f"Message processing error: {e}")
                time.sleep(1)
    
    def send_message_to_peer(self, peer, message):
        """Send message to specific peer"""
        try:
            import socket
            
            ip, port = peer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            sock.connect((ip, port))
            sock.sendall(json.dumps(message).encode())
            sock.close()
            
            self.message_stats['sent'] += 1
            logging.debug(f"Sent message to {ip}:{port}")
            
        except Exception as e:
            logging.error(f"Failed to send message to {peer}: {e}")
            self.message_stats['failed'] += 1
    
    def broadcast_message(self, message, priority=MessagePriority.OTHER):
        """Broadcast message to all peers"""
        try:
            peers = self.node_manager.get_peers()
            
            for peer in peers:
                threading.Thread(
                    target=self.send_message_to_peer,
                    args=(peer, message),
                    daemon=True
                ).start()
            
            self.message_stats['broadcast'] += 1
            logging.info(f"Broadcast message to {len(peers)} peers")
            
        except Exception as e:
            logging.error(f"Failed to broadcast message: {e}")
    
    def start_message_processor(self):
        """Start message processing"""
        if not self.processing:
            self.processing = True
            threading.Thread(target=self.process_message_queue, daemon=True).start()
            logging.info("Started message processor")
    
    def stop_message_processor(self):
        """Stop message processing"""
        self.processing = False
        logging.info("Stopped message processor")
    
    def get_message_stats(self):
        """Get message statistics"""
        return dict(self.message_stats)
    
    def set_gossip_fanout(self, fanout):
        """Set gossip fanout parameter"""
        self.gossip_fanout = max(1, min(fanout, 10))
        logging.info(f"Set gossip fanout to {self.gossip_fanout}")
    
    def anti_entropy_sync(self):
        """Perform anti-entropy synchronization"""
        try:
            peers = self.node_manager.get_peers()
            if not peers:
                return
            
            # Select random peer for sync
            peer = random.choice(peers)
            
            # Request state from peer
            sync_request = {
                'type': 'sync_request',
                'node_id': self.node_manager.public_ip,
                'timestamp': time.time()
            }
            
            self.send_message_to_peer(peer, sync_request)
            logging.debug(f"Initiated anti-entropy sync with {peer}")
            
        except Exception as e:
            logging.error(f"Anti-entropy sync error: {e}")
    
    def start_anti_entropy(self, interval=300):
        """Start anti-entropy process"""
        def anti_entropy_loop():
            while True:
                try:
                    self.anti_entropy_sync()
                    time.sleep(interval)
                except Exception as e:
                    logging.error(f"Anti-entropy loop error: {e}")
                    time.sleep(60)
        
        threading.Thread(target=anti_entropy_loop, daemon=True).start()
        logging.info("Started anti-entropy service")

# Global message manager instance
message_manager = None

def get_message_manager(node_manager):
    """Get message manager instance"""
    global message_manager
    if message_manager is None:
        message_manager = MessageManager(node_manager)
    return message_manager
