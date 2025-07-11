"""
Mempool key rotation and encryption
"""
import os
import time
import threading
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

class MempoolKeyManager:
    """Manages mempool encryption keys and rotation"""
    
    def __init__(self):
        self.keys = {}
        self.current_key_id = 0
        self.rotation_interval = 3600  # 1 hour
        self.rotation_active = False
        self.key_lock = threading.Lock()
        
    def generate_key(self, password=None):
        """Generate encryption key"""
        try:
            if password:
                # Derive key from password
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            else:
                # Generate random key
                key = Fernet.generate_key()
            
            return key
            
        except Exception as e:
            logging.error(f"Failed to generate key: {e}")
            return None
    
    def add_key(self, key_id, key):
        """Add encryption key"""
        with self.key_lock:
            self.keys[key_id] = key
            logging.info(f"Added mempool key: {key_id}")
    
    def get_key(self, key_id):
        """Get encryption key by ID"""
        with self.key_lock:
            return self.keys.get(key_id)
    
    def get_current_key(self):
        """Get current encryption key"""
        return self.get_key(self.current_key_id)
    
    def rotate_key(self):
        """Rotate to new encryption key"""
        try:
            with self.key_lock:
                # Generate new key
                new_key_id = self.current_key_id + 1
                new_key = self.generate_key()
                
                if new_key:
                    self.keys[new_key_id] = new_key
                    self.current_key_id = new_key_id
                    
                    # Keep only last 3 keys
                    if len(self.keys) > 3:
                        old_key_id = min(self.keys.keys())
                        del self.keys[old_key_id]
                    
                    logging.info(f"Rotated to new mempool key: {new_key_id}")
                    return new_key_id
                
        except Exception as e:
            logging.error(f"Failed to rotate key: {e}")
        
        return None
    
    def encrypt_mempool_data(self, data, key_id=None):
        """Encrypt mempool data"""
        try:
            if key_id is None:
                key_id = self.current_key_id
            
            key = self.get_key(key_id)
            if not key:
                return None
            
            f = Fernet(key)
            
            if isinstance(data, str):
                data = data.encode()
            
            encrypted = f.encrypt(data)
            return base64.b64encode(encrypted).decode()
            
        except Exception as e:
            logging.error(f"Failed to encrypt mempool data: {e}")
            return None
    
    def decrypt_mempool_data(self, encrypted_data, key_id):
        """Decrypt mempool data"""
        try:
            key = self.get_key(key_id)
            if not key:
                return None
            
            f = Fernet(key)
            
            encrypted_bytes = base64.b64decode(encrypted_data)
            decrypted = f.decrypt(encrypted_bytes)
            
            return decrypted.decode()
            
        except Exception as e:
            logging.error(f"Failed to decrypt mempool data: {e}")
            return None
    
    def start_key_rotation(self):
        """Start automatic key rotation"""
        def rotation_loop():
            while self.rotation_active:
                try:
                    time.sleep(self.rotation_interval)
                    self.rotate_key()
                except Exception as e:
                    logging.error(f"Key rotation error: {e}")
                    time.sleep(60)
        
        if not self.rotation_active:
            self.rotation_active = True
            threading.Thread(target=rotation_loop, daemon=True).start()
            logging.info("Started mempool key rotation")
    
    def stop_key_rotation(self):
        """Stop automatic key rotation"""
        self.rotation_active = False
        logging.info("Stopped mempool key rotation")
    
    def is_key_rotation_running(self):
        """Check if key rotation is running"""
        return self.rotation_active
    
    def initialize_keys(self):
        """Initialize with first key"""
        try:
            initial_key = self.generate_key()
            if initial_key:
                self.add_key(0, initial_key)
                self.current_key_id = 0
                logging.info("Initialized mempool keys")
                return True
            return False
            
        except Exception as e:
            logging.error(f"Failed to initialize keys: {e}")
            return False
    
    def get_key_info(self):
        """Get key information"""
        with self.key_lock:
            return {
                'current_key_id': self.current_key_id,
                'total_keys': len(self.keys),
                'key_ids': list(self.keys.keys()),
                'rotation_active': self.rotation_active
            }

# Global mempool key manager instance
mempool_key_manager = MempoolKeyManager()
