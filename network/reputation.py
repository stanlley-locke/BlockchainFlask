"""
Reputation scoring, score decay, and validator updates
"""
import time
import threading
import logging
from collections import defaultdict
from core.database import execute_query

class ReputationManager:
    """Manages peer reputation and scoring"""
    
    def __init__(self, node_manager):
        self.node_manager = node_manager
        self.peer_scores = defaultdict(lambda: 100)  # Default score
        self.score_decay_active = False
        self.decay_interval = 3600  # 1 hour
        self.decay_factor = 0.95
        self.min_score = 0
        self.max_score = 1000
        
    def update_peer_score(self, peer, delta):
        """Update peer reputation score"""
        try:
            current_score = self.peer_scores[peer]
            new_score = max(self.min_score, min(self.max_score, current_score + delta))
            
            self.peer_scores[peer] = new_score
            
            logging.debug(f"Updated peer {peer} score: {current_score} -> {new_score} (delta: {delta})")
            
            # Remove peer if score is too low
            if new_score < 30:
                ip, port = peer
                self.node_manager.remove_peer(ip, port)
                logging.warning(f"Removed low-reputation peer {peer} (score: {new_score})")
            
        except Exception as e:
            logging.error(f"Failed to update peer score: {e}")
    
    def get_peer_score(self, peer):
        """Get peer reputation score"""
        return self.peer_scores.get(peer, 100)
    
    def get_top_peers(self, count=10):
        """Get peers with highest reputation"""
        if not self.peer_scores:
            return []
        
        sorted_peers = sorted(
            self.peer_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [peer for peer, score in sorted_peers[:count]]
    
    def decay_scores(self):
        """Apply score decay to all peers"""
        try:
            for peer in list(self.peer_scores.keys()):
                current_score = self.peer_scores[peer]
                new_score = max(self.min_score, current_score * self.decay_factor)
                self.peer_scores[peer] = new_score
            
            logging.info(f"Applied score decay to {len(self.peer_scores)} peers")
            
        except Exception as e:
            logging.error(f"Failed to decay scores: {e}")
    
    def start_score_decay(self):
        """Start score decay service"""
        def decay_loop():
            while self.score_decay_active:
                try:
                    self.decay_scores()
                    time.sleep(self.decay_interval)
                except Exception as e:
                    logging.error(f"Score decay error: {e}")
                    time.sleep(60)
        
        if not self.score_decay_active:
            self.score_decay_active = True
            threading.Thread(target=decay_loop, daemon=True).start()
            logging.info("Started score decay service")
    
    def stop_score_decay(self):
        """Stop score decay service"""
        self.score_decay_active = False
        logging.info("Stopped score decay service")
    
    def is_score_decay_running(self):
        """Check if score decay is running"""
        return self.score_decay_active
    
    def handle_message_success(self, peer):
        """Handle successful message from peer"""
        self.update_peer_score(peer, 1)
    
    def handle_message_failure(self, peer):
        """Handle failed message from peer"""
        self.update_peer_score(peer, -3)
    
    def handle_invalid_block(self, peer):
        """Handle invalid block from peer"""
        self.update_peer_score(peer, -10)
    
    def handle_valid_block(self, peer):
        """Handle valid block from peer"""
        self.update_peer_score(peer, 5)
    
    def get_validators(self, min_stake=1000):
        """Get validator addresses from high-reputation peers"""
        try:
            # Get wallets with sufficient stake
            validators = execute_query(
                "SELECT wallet_address, staked FROM wallets WHERE staked >= ? ORDER BY staked DESC",
                (min_stake,),
                fetch=True
            )
            
            # Filter by peer reputation
            high_rep_validators = []
            for validator in validators:
                address = validator[0]
                
                # Check if address corresponds to a high-reputation peer
                # This is a simplified check - in practice, you'd need a mapping
                peer_found = False
                for peer in self.peer_scores:
                    if self.peer_scores[peer] > 80:  # High reputation threshold
                        high_rep_validators.append({
                            'address': address,
                            'stake': validator[1],
                            'reputation': self.peer_scores[peer]
                        })
                        peer_found = True
                        break
                
                if not peer_found and validator[1] >= min_stake:
                    # Include validator even if peer not found, but with lower priority
                    high_rep_validators.append({
                        'address': address,
                        'stake': validator[1],
                        'reputation': 50  # Default reputation
                    })
            
            return high_rep_validators
            
        except Exception as e:
            logging.error(f"Failed to get validators: {e}")
            return []
    
    def exchange_reputation(self, peer):
        """Exchange reputation data with peer"""
        try:
            # Create reputation message
            reputation_data = {
                'type': 'reputation_exchange',
                'scores': dict(self.peer_scores),
                'timestamp': time.time()
            }
            
            # Send to peer (implementation depends on messaging system)
            logging.debug(f"Exchanged reputation data with {peer}")
            
        except Exception as e:
            logging.error(f"Failed to exchange reputation with {peer}: {e}")
    
    def start_reputation_exchange(self, interval=1800):
        """Start reputation exchange service"""
        def exchange_loop():
            while True:
                try:
                    peers = self.node_manager.get_peers()
                    if peers:
                        # Select random peer for reputation exchange
                        import random
                        peer = random.choice(peers)
                        self.exchange_reputation(peer)
                    
                    time.sleep(interval)
                except Exception as e:
                    logging.error(f"Reputation exchange error: {e}")
                    time.sleep(60)
        
        threading.Thread(target=exchange_loop, daemon=True).start()
        logging.info("Started reputation exchange service")
    
    def get_reputation_stats(self):
        """Get reputation statistics"""
        if not self.peer_scores:
            return {
                'total_peers': 0,
                'average_score': 0,
                'min_score': 0,
                'max_score': 0,
                'high_reputation_peers': 0
            }
        
        scores = list(self.peer_scores.values())
        high_rep_count = sum(1 for score in scores if score > 80)
        
        return {
            'total_peers': len(self.peer_scores),
            'average_score': sum(scores) / len(scores),
            'min_score': min(scores),
            'max_score': max(scores),
            'high_reputation_peers': high_rep_count
        }

# Global reputation manager instance
reputation_manager = None

def get_reputation_manager(node_manager):
    """Get reputation manager instance"""
    global reputation_manager
    if reputation_manager is None:
        reputation_manager = ReputationManager(node_manager)
    return reputation_manager
