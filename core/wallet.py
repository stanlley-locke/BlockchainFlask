"""
Wallet creation, recovery, balance management, and staking
"""
import time
import logging
from .crypto import crypto_manager
from .database import execute_query
from .utils import validate_address, format_balance

class WalletManager:
    """Manages wallet operations"""
    
    def __init__(self):
        self.crypto = crypto_manager
    
    def create_wallet(self, password=None):
        """Create new wallet with optional password encryption"""
        try:
            # Generate key pair
            private_key, public_key = self.crypto.generate_key_pair()
            
            # Generate address
            address = self.crypto.generate_address(public_key)
            
            # Generate seed phrase
            seed_phrase = self.crypto.generate_seed_phrase()
            
            # Encrypt private key if password provided
            if password:
                encrypted_private_key = self.crypto.encrypt_private_key(private_key, password)
            else:
                encrypted_private_key = private_key.decode()
            
            # Store wallet in database
            execute_query(
                "INSERT INTO wallets (wallet_address, public_key, encrypted_private_key, seed_phrase, balance, staked, last_online) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (address, public_key.decode(), encrypted_private_key, seed_phrase, 0.0, 0.0, time.time())
            )
            
            logging.info(f"Created wallet: {address}")
            
            return {
                'address': address,
                'public_key': public_key.decode(),
                'private_key': private_key.decode() if not password else None,
                'seed_phrase': seed_phrase,
                'balance': 0.0,
                'staked': 0.0
            }
            
        except Exception as e:
            logging.error(f"Failed to create wallet: {e}")
            return None
    
    def recover_wallet(self, seed_phrase, password=None):
        """Recover wallet from seed phrase"""
        try:
            # Check if wallet exists
            wallet = execute_query(
                "SELECT * FROM wallets WHERE seed_phrase = ?",
                (seed_phrase,),
                fetch=True
            )
            
            if not wallet:
                return None
            
            wallet_data = wallet[0]
            
            # Decrypt private key if password provided
            private_key = None
            if password:
                private_key = self.crypto.decrypt_private_key(wallet_data[3], password)
            
            return {
                'address': wallet_data[1],
                'public_key': wallet_data[2],
                'private_key': private_key.decode() if private_key else None,
                'seed_phrase': wallet_data[4],
                'balance': wallet_data[5],
                'staked': wallet_data[6]
            }
            
        except Exception as e:
            logging.error(f"Failed to recover wallet: {e}")
            return None
    
    def get_wallet_balance(self, address):
        """Get wallet balance"""
        try:
            if not validate_address(address):
                return None
            
            wallet = execute_query(
                "SELECT balance, staked FROM wallets WHERE wallet_address = ?",
                (address,),
                fetch=True
            )
            
            if wallet:
                return {
                    'balance': wallet[0][0],
                    'staked': wallet[0][1],
                    'total': wallet[0][0] + wallet[0][1]
                }
            
            return None
            
        except Exception as e:
            logging.error(f"Failed to get wallet balance: {e}")
            return None
    
    def update_wallet_balance(self, address, new_balance):
        """Update wallet balance"""
        try:
            if not validate_address(address):
                return False
            
            execute_query(
                "UPDATE wallets SET balance = ?, last_online = ? WHERE wallet_address = ?",
                (new_balance, time.time(), address)
            )
            
            logging.info(f"Updated balance for {address}: {format_balance(new_balance)}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to update wallet balance: {e}")
            return False
    
    def stake_coins(self, address, amount):
        """Stake coins for validation"""
        try:
            if not validate_address(address):
                return False
            
            # Get current balance
            balance_info = self.get_wallet_balance(address)
            if not balance_info or balance_info['balance'] < amount:
                return False
            
            # Update balance and staked amounts
            new_balance = balance_info['balance'] - amount
            new_staked = balance_info['staked'] + amount
            
            execute_query(
                "UPDATE wallets SET balance = ?, staked = ? WHERE wallet_address = ?",
                (new_balance, new_staked, address)
            )
            
            logging.info(f"Staked {format_balance(amount)} coins for {address}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to stake coins: {e}")
            return False
    
    def unstake_coins(self, address, amount):
        """Unstake coins"""
        try:
            if not validate_address(address):
                return False
            
            # Get current balance
            balance_info = self.get_wallet_balance(address)
            if not balance_info or balance_info['staked'] < amount:
                return False
            
            # Update balance and staked amounts
            new_balance = balance_info['balance'] + amount
            new_staked = balance_info['staked'] - amount
            
            execute_query(
                "UPDATE wallets SET balance = ?, staked = ? WHERE wallet_address = ?",
                (new_balance, new_staked, address)
            )
            
            logging.info(f"Unstaked {format_balance(amount)} coins for {address}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to unstake coins: {e}")
            return False
    
    def get_wallet_transactions(self, address):
        """Get transaction history for wallet"""
        try:
            if not validate_address(address):
                return []
            
            transactions = execute_query(
                "SELECT * FROM transactions WHERE sender = ? OR recipient = ? ORDER BY timestamp DESC",
                (address, address),
                fetch=True
            )
            
            return [
                {
                    'tx_hash': tx[1],
                    'sender': tx[2],
                    'recipient': tx[3],
                    'amount': tx[4],
                    'fee': tx[5],
                    'timestamp': tx[6],
                    'is_coinbase': bool(tx[8])
                }
                for tx in transactions
            ]
            
        except Exception as e:
            logging.error(f"Failed to get wallet transactions: {e}")
            return []
    
    def get_all_wallets(self):
        """Get all wallets"""
        try:
            wallets = execute_query(
                "SELECT wallet_address, balance, staked, last_online FROM wallets ORDER BY balance DESC",
                fetch=True
            )
            
            return [
                {
                    'address': wallet[0],
                    'balance': wallet[1],
                    'staked': wallet[2],
                    'last_online': wallet[3]
                }
                for wallet in wallets
            ]
            
        except Exception as e:
            logging.error(f"Failed to get all wallets: {e}")
            return []
    
    def delete_wallet(self, address):
        """Delete wallet (use with caution)"""
        try:
            if not validate_address(address):
                return False
            
            execute_query(
                "DELETE FROM wallets WHERE wallet_address = ?",
                (address,)
            )
            
            logging.info(f"Deleted wallet: {address}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to delete wallet: {e}")
            return False
    
    def get_validator_wallets(self, min_stake=1000):
        """Get wallets eligible for validation"""
        try:
            validators = execute_query(
                "SELECT wallet_address, staked FROM wallets WHERE staked >= ? ORDER BY staked DESC",
                (min_stake,),
                fetch=True
            )
            
            return [
                {
                    'address': validator[0],
                    'staked': validator[1]
                }
                for validator in validators
            ]
            
        except Exception as e:
            logging.error(f"Failed to get validator wallets: {e}")
            return []

# Global wallet manager instance
wallet_manager = WalletManager()
