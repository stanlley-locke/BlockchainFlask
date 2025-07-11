"""
Cryptographic functions for key generation, encryption, and signing
"""
import hashlib
import base64
import os
import secrets
import base58
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging

class CryptoManager:
    """Manages all cryptographic operations"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_key_pair(self):
        """Generate Ed25519 key pair"""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def generate_address(self, public_key):
        """Generate blockchain address from public key"""
        # Hash the public key
        hash_obj = hashlib.sha256(public_key).digest()
        ripemd = hashlib.new('ripemd160')
        ripemd.update(hash_obj)
        
        # Add version byte and checksum
        versioned = b'\x00' + ripemd.digest()
        checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
        
        # Encode as base58
        address = base58.b58encode(versioned + checksum).decode()
        return address
    
    def sign_message(self, private_key_pem, message):
        """Sign a message with private key"""
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=self.backend
            )
            
            if isinstance(message, str):
                message = message.encode()
            
            signature = private_key.sign(message)
            return base64.b64encode(signature).decode()
        except Exception as e:
            logging.error(f"Failed to sign message: {e}")
            return None
    
    def verify_signature(self, public_key_pem, message, signature):
        """Verify message signature"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=self.backend
            )
            
            if isinstance(message, str):
                message = message.encode()
            
            signature_bytes = base64.b64decode(signature)
            public_key.verify(signature_bytes, message)
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            logging.error(f"Failed to verify signature: {e}")
            return False
    
    def encrypt_private_key(self, private_key_pem, password):
        """Encrypt private key with password"""
        try:
            # Derive key from password
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=self.backend
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Encrypt private key
            f = Fernet(key)
            encrypted = f.encrypt(private_key_pem)
            
            # Return salt + encrypted data
            return base64.b64encode(salt + encrypted).decode()
        except Exception as e:
            logging.error(f"Failed to encrypt private key: {e}")
            return None
    
    def decrypt_private_key(self, encrypted_data, password):
        """Decrypt private key with password"""
        try:
            # Decode and extract salt
            data = base64.b64decode(encrypted_data)
            salt = data[:16]
            encrypted = data[16:]
            
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=self.backend
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Decrypt private key
            f = Fernet(key)
            private_key_pem = f.decrypt(encrypted)
            
            return private_key_pem
        except Exception as e:
            logging.error(f"Failed to decrypt private key: {e}")
            return None
    
    def generate_seed_phrase(self, length=12):
        """Generate mnemonic seed phrase"""
        # Simple word list (in production, use BIP39 wordlist)
        words = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
            "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
            "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
            "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
            "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
            "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
            "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
            "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
            "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
            "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
            "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "article",
            "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
            "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
            "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
            "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis"
        ]
        
        selected_words = [secrets.choice(words) for _ in range(length)]
        return " ".join(selected_words)
    
    def hash_password(self, password):
        """Hash password for storage"""
        salt = os.urandom(32)
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return base64.b64encode(salt + pwdhash).decode()
    
    def verify_password(self, stored_hash, password):
        """Verify password against stored hash"""
        try:
            decoded = base64.b64decode(stored_hash)
            salt = decoded[:32]
            stored_pwdhash = decoded[32:]
            
            pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            return pwdhash == stored_pwdhash
        except Exception as e:
            logging.error(f"Failed to verify password: {e}")
            return False
    
    def generate_transaction_hash(self, transaction):
        """Generate hash for transaction"""
        # Create canonical string representation
        tx_string = f"{transaction['sender']}{transaction['recipient']}{transaction['amount']}{transaction['timestamp']}"
        return hashlib.sha256(tx_string.encode()).hexdigest()
    
    def encrypt_data(self, data, key):
        """Encrypt data with AES"""
        try:
            # Generate random IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key[:32]),  # Use first 32 bytes as key
                modes.CBC(iv),
                backend=self.backend
            )
            
            # Pad data to block size
            if isinstance(data, str):
                data = data.encode()
            
            padding_length = 16 - (len(data) % 16)
            padded_data = data + bytes([padding_length] * padding_length)
            
            # Encrypt
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Return IV + ciphertext
            return base64.b64encode(iv + ciphertext).decode()
        except Exception as e:
            logging.error(f"Failed to encrypt data: {e}")
            return None
    
    def decrypt_data(self, encrypted_data, key):
        """Decrypt data with AES"""
        try:
            # Decode and extract IV
            data = base64.b64decode(encrypted_data)
            iv = data[:16]
            ciphertext = data[16:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key[:32]),  # Use first 32 bytes as key
                modes.CBC(iv),
                backend=self.backend
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            padding_length = padded_data[-1]
            data = padded_data[:-padding_length]
            
            return data.decode()
        except Exception as e:
            logging.error(f"Failed to decrypt data: {e}")
            return None

# Global crypto manager instance
crypto_manager = CryptoManager()
