"""
Health check, latency scoring, and ping management
"""
import time
import threading
import logging
import socket
from collections import defaultdict

class HealthManager:
    """Manages network health and peer monitoring"""
    
    def __init__(self, node_manager):
        self.node_manager = node_manager
        self.peer_latencies = defaultdict(float)
        self.peer_health = defaultdict(dict)
        self.health_check_active = False
        self.ping_interval = 30
        
    def ping_peer(self, peer):
        """Ping a peer and measure latency"""
        try:
            ip, port = peer
            start_time = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            result = sock.connect_ex((ip, port))
            latency = time.time() - start_time
            
            sock.close()
            
            if result == 0:
                self.peer_latencies[peer] = latency
                self.peer_health[peer]['status'] = 'healthy'
                self.peer_health[peer]['last_ping'] = time.time()
                return True, latency
            else:
                self.peer_health[peer]['status'] = 'unhealthy'
                return False, None
                
        except Exception as e:
            logging.error(f"Failed to ping peer {peer}: {e}")
            self.peer_health[peer]['status'] = 'error'
            return False, None
    
    def check_all_peers(self):
        """Check health of all peers"""
        peers = self.node_manager.get_peers()
        healthy_count = 0
        
        for peer in peers:
            is_healthy, latency = self.ping_peer(peer)
            if is_healthy:
                healthy_count += 1
                logging.debug(f"Peer {peer} is healthy (latency: {latency:.3f}s)")
            else:
                logging.warning(f"Peer {peer} is unhealthy")
        
        health_ratio = healthy_count / len(peers) if peers else 0
        logging.info(f"Network health: {healthy_count}/{len(peers)} peers healthy ({health_ratio:.1%})")
        
        return health_ratio
    
    def get_peer_latency(self, peer):
        """Get latency for a specific peer"""
        return self.peer_latencies.get(peer, 0)
    
    def get_peer_health(self, peer):
        """Get health status for a specific peer"""
        return self.peer_health.get(peer, {'status': 'unknown'})
    
    def get_fastest_peers(self, count=5):
        """Get peers with lowest latency"""
        if not self.peer_latencies:
            return []
        
        sorted_peers = sorted(
            self.peer_latencies.items(),
            key=lambda x: x[1]
        )
        
        return [peer for peer, latency in sorted_peers[:count]]
    
    def get_network_stats(self):
        """Get network statistics"""
        peers = self.node_manager.get_peers()
        
        if not peers:
            return {
                'total_peers': 0,
                'healthy_peers': 0,
                'average_latency': 0,
                'min_latency': 0,
                'max_latency': 0
            }
        
        healthy_peers = sum(
            1 for peer in peers
            if self.peer_health.get(peer, {}).get('status') == 'healthy'
        )
        
        latencies = list(self.peer_latencies.values())
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        min_latency = min(latencies) if latencies else 0
        max_latency = max(latencies) if latencies else 0
        
        return {
            'total_peers': len(peers),
            'healthy_peers': healthy_peers,
            'average_latency': avg_latency,
            'min_latency': min_latency,
            'max_latency': max_latency
        }
    
    def start_health_check(self):
        """Start health check service"""
        def health_check_loop():
            while self.health_check_active:
                try:
                    self.check_all_peers()
                    time.sleep(self.ping_interval)
                except Exception as e:
                    logging.error(f"Health check error: {e}")
                    time.sleep(10)
        
        if not self.health_check_active:
            self.health_check_active = True
            threading.Thread(target=health_check_loop, daemon=True).start()
            logging.info("Started health check service")
    
    def stop_health_check(self):
        """Stop health check service"""
        self.health_check_active = False
        logging.info("Stopped health check service")
    
    def is_health_check_running(self):
        """Check if health check is running"""
        return self.health_check_active
    
    def remove_unhealthy_peers(self, threshold=0.5):
        """Remove peers that are consistently unhealthy"""
        current_time = time.time()
        peers_to_remove = []
        
        for peer, health in self.peer_health.items():
            if health.get('status') == 'unhealthy':
                last_ping = health.get('last_ping', 0)
                if current_time - last_ping > threshold * 3600:  # threshold in hours
                    peers_to_remove.append(peer)
        
        for peer in peers_to_remove:
            ip, port = peer
            self.node_manager.remove_peer(ip, port)
            if peer in self.peer_latencies:
                del self.peer_latencies[peer]
            if peer in self.peer_health:
                del self.peer_health[peer]
        
        if peers_to_remove:
            logging.info(f"Removed {len(peers_to_remove)} unhealthy peers")

# Global health manager instance
health_manager = None

def get_health_manager(node_manager):
    """Get health manager instance"""
    global health_manager
    if health_manager is None:
        health_manager = HealthManager(node_manager)
    return health_manager
