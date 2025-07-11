"""
Network manager to start/stop all network services
"""
import logging
import time
from .nodes import node_manager
from .messaging import get_message_manager
from .health import get_health_manager
from .reputation import get_reputation_manager
from .mempool_keys import mempool_key_manager
from .ssl_utils import ssl_manager

class NetworkManager:
    """Manages all network services"""
    
    def __init__(self):
        self.node_manager = node_manager
        self.message_manager = get_message_manager(self.node_manager)
        self.health_manager = get_health_manager(self.node_manager)
        self.reputation_manager = get_reputation_manager(self.node_manager)
        self.mempool_key_manager = mempool_key_manager
        self.ssl_manager = ssl_manager
        self.services_running = False
        
    def start_all_services(self):
        """Start all network services"""
        try:
            logging.info("Starting network services...")
            
            # Setup SSL certificates
            self.ssl_manager.generate_ssl_certificate()
            
            # Initialize mempool keys
            self.mempool_key_manager.initialize_keys()
            
            # Setup NAT traversal
            self.node_manager.setup_nat_traversal()
            
            # Load existing peers
            self.node_manager.load_peers()
            
            # Start peer discovery
            self.node_manager.start_peer_discovery()
            
            # Start message processing
            self.message_manager.start_message_processor()
            
            # Start health monitoring
            self.health_manager.start_health_check()
            
            # Start reputation services
            self.reputation_manager.start_score_decay()
            self.reputation_manager.start_reputation_exchange()
            
            # Start key rotation
            self.mempool_key_manager.start_key_rotation()
            
            # Start anti-entropy
            self.message_manager.start_anti_entropy()
            
            self.services_running = True
            logging.info("All network services started successfully")
            
        except Exception as e:
            logging.error(f"Failed to start network services: {e}")
            self.stop_all_services()
    
    def stop_all_services(self):
        """Stop all network services"""
        try:
            logging.info("Stopping network services...")
            
            # Stop message processing
            self.message_manager.stop_message_processor()
            
            # Stop health monitoring
            self.health_manager.stop_health_check()
            
            # Stop reputation services
            self.reputation_manager.stop_score_decay()
            
            # Stop key rotation
            self.mempool_key_manager.stop_key_rotation()
            
            # Save peers
            self.node_manager.save_peers()
            
            self.services_running = False
            logging.info("All network services stopped")
            
        except Exception as e:
            logging.error(f"Failed to stop network services: {e}")
    
    def get_network_status(self):
        """Get comprehensive network status"""
        try:
            node_info = self.node_manager.get_node_info()
            health_stats = self.health_manager.get_network_stats()
            reputation_stats = self.reputation_manager.get_reputation_stats()
            message_stats = self.message_manager.get_message_stats()
            key_info = self.mempool_key_manager.get_key_info()
            
            return {
                'services_running': self.services_running,
                'node_info': node_info,
                'health_stats': health_stats,
                'reputation_stats': reputation_stats,
                'message_stats': message_stats,
                'key_info': key_info,
                'timestamp': time.time()
            }
            
        except Exception as e:
            logging.error(f"Failed to get network status: {e}")
            return {'error': str(e)}
    
    def broadcast_message(self, message, priority=None):
        """Broadcast message to network"""
        return self.message_manager.broadcast_message(message, priority)
    
    def add_peer(self, ip, port):
        """Add peer to network"""
        return self.node_manager.add_peer(ip, port)
    
    def remove_peer(self, ip, port):
        """Remove peer from network"""
        return self.node_manager.remove_peer(ip, port)
    
    def get_peers(self):
        """Get list of peers"""
        return self.node_manager.get_peers()
    
    def ping_all_peers(self):
        """Ping all peers"""
        return self.health_manager.check_all_peers()

# Global network manager instance
network_manager = NetworkManager()
