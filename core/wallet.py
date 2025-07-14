"""
Wallet creation, recovery, balance management, and staking
"""
import time
import logging
import sqlite3
from datetime import datetime
from colorama import Fore, Style
from .crypto import crypto_manager
from .utils import validate_address, format_balance
import os

class WalletManager:
    """Manages wallet operations"""
    
    def __init__(self, db_path='blockchain.db'):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.crypto = crypto_manager

    def create_wallet(self, password=None):
        """Create new wallet with optional password encryption"""
        try:
            private_key, public_key = self.crypto.generate_key_pair()
            address = self.crypto.generate_address(public_key)
            seed_phrase = self.crypto.generate_seed_phrase()

            encrypted_private_key = self.crypto.encrypt_private_key(private_key, password) if password else private_key.decode()

            self.cursor.execute("""
                INSERT INTO wallets (wallet_address, public_key, encrypted_private_key, seed_phrase, balance, staked, last_online)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (address, public_key.decode(), encrypted_private_key, seed_phrase, 0.0, 0.0, time.time()))
            self.conn.commit()

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
            self.cursor.execute("SELECT * FROM wallets WHERE seed_phrase = ?", (seed_phrase,))
            wallet = self.cursor.fetchone()
            if not wallet:
                return None

            private_key = self.crypto.decrypt_private_key(wallet[3], password) if password else None

            return {
                'address': wallet[1],
                'public_key': wallet[2],
                'private_key': private_key.decode() if private_key else None,
                'seed_phrase': wallet[4],
                'balance': wallet[5],
                'staked': wallet[6]
            }

        except Exception as e:
            logging.error(f"Failed to recover wallet: {e}")
            return None

    def get_wallet_balance(self, address):
        """Get wallet balance"""
        try:
            self.cursor.execute("SELECT balance, staked FROM wallets WHERE wallet_address = ?", (address,))
            row = self.cursor.fetchone()
            if row:
                return {
                    'balance': row[0],
                    'staked': row[1],
                    'total': row[0] + row[1]
                }
            return None

        except Exception as e:
            logging.error(f"Failed to get wallet balance: {e}")
            return None

    def update_wallet_balance(self, address, new_balance):
        """Update wallet balance"""
        try:

            self.cursor.execute(
                "UPDATE wallets SET balance = ?, last_online = ? WHERE wallet_address = ?",
                (new_balance, time.time(), address)
            )
            self.conn.commit()
            logging.info(f"Updated balance for {address}: {format_balance(new_balance)}")
            return True

        except Exception as e:
            logging.error(f"Failed to update wallet balance: {e}")
            return False

    def stake_coins(self, address, amount):
        """Stake coins for validation"""
        try:

            balance_info = self.get_wallet_balance(address)
            if not balance_info or balance_info['balance'] < amount:
                return False

            new_balance = balance_info['balance'] - amount
            new_staked = balance_info['staked'] + amount

            self.cursor.execute(
                "UPDATE wallets SET balance = ?, staked = ? WHERE wallet_address = ?",
                (new_balance, new_staked, address)
            )
            self.conn.commit()

            logging.info(f"Staked {format_balance(amount)} coins for {address}")
            return True

        except Exception as e:
            logging.error(f"Failed to stake coins: {e}")
            return False

    def unstake_coins(self, address, amount):
        """Unstake coins"""
        try:

            balance_info = self.get_wallet_balance(address)
            if not balance_info or balance_info['staked'] < amount:
                return False

            new_balance = balance_info['balance'] + amount
            new_staked = balance_info['staked'] - amount

            self.cursor.execute(
                "UPDATE wallets SET balance = ?, staked = ? WHERE wallet_address = ?",
                (new_balance, new_staked, address)
            )
            self.conn.commit()

            logging.info(f"Unstaked {format_balance(amount)} coins for {address}")
            return True

        except Exception as e:
            logging.error(f"Failed to unstake coins: {e}")
            return False

    def get_wallet_transactions(self, address):
        """Get transaction history for wallet"""
        try:

            self.cursor.execute(
                "SELECT * FROM transactions WHERE sender = ? OR recipient = ? ORDER BY timestamp DESC",
                (address, address)
            )
            transactions = self.cursor.fetchall()

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
            self.cursor.execute(
                "SELECT wallet_address, balance, staked, last_online FROM wallets ORDER BY balance DESC"
            )
            wallets = self.cursor.fetchall()

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

            self.cursor.execute("DELETE FROM wallets WHERE wallet_address = ?", (address,))
            self.conn.commit()

            logging.info(f"Deleted wallet: {address}")
            return True

        except Exception as e:
            logging.error(f"Failed to delete wallet: {e}")
            return False

    def get_validator_wallets(self, min_stake=1000):
        """Get wallets eligible for validation"""
        try:
            self.cursor.execute(
                "SELECT wallet_address, staked FROM wallets WHERE staked >= ? ORDER BY staked DESC",
                (min_stake,)
            )
            validators = self.cursor.fetchall()

            return [
                {
                    'address': v[0],
                    'staked': v[1]
                }
                for v in validators
            ]

        except Exception as e:
            logging.error(f"Failed to get validator wallets: {e}")
            return []

    def fund_wallet(self, address, amount):
        """Fund a wallet with specified amount"""
        try:
            self.cursor.execute("SELECT balance FROM wallets WHERE wallet_address = ?", (address,))
            if self.cursor.fetchone():
                self.cursor.execute(
                    "UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?",
                    (amount, address)
                )
                self.conn.commit()
                logging.info(f"Funded {address} with {amount} coins")
                return True
            else:
                logging.error(f"Wallet {address} does not exist")
                return False
        except sqlite3.Error as e:
            logging.error(f"Failed to fund wallet {address}: {e}")
            return False

    def load_wallet(self, address):
        """Load wallet details by address"""
        try:
            self.cursor.execute("SELECT * FROM wallets WHERE wallet_address = ?", (address,))
            wallet = self.cursor.fetchone()
            if wallet:
                return {
                    'address': wallet[1],
                    'public_key': wallet[2],
                    'encrypted_private_key': wallet[3],
                    'seed_phrase': wallet[4],
                    'balance': wallet[5],
                    'staked': wallet[6],
                    'last_online': wallet[7]
                }
            return None
        except Exception as e:
            logging.error(f"Failed to load wallet {address}: {e}")
            return None


    def close(self):
        """Close the database connection"""
        self.conn.close()

    def decrypt_private_key(self, encrypted_data, password):
        """Decrypt private key from structured JSON"""
        try:
            data = json.loads(encrypted_data)
            salt = base64.b64decode(data['salt'])
            ciphertext = base64.b64decode(data['ciphertext'])

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=self.backend
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            fernet = Fernet(key)
            return fernet.decrypt(ciphertext)
        except Exception as e:
            logging.error(f"Failed to decrypt private key: {e}")
            return None


# Global wallet manager instance
wallet_manager = WalletManager()
