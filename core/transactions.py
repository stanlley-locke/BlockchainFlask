"""
Transaction creation, mempool encryption, and validation
"""
import time
import json
import logging
from .crypto import crypto_manager
from .database import execute_query
from .utils import validate_address, validate_transaction_amount, calculate_transaction_fee
from .config import FEE_PERCENT

class TransactionManager:
    """Manages transaction operations"""

    def __init__(self):
        self.crypto = crypto_manager
        self.pending_transactions = []
        self.mempool_key = None

    def create_transaction(self, sender, recipient, amount, password, fee=None):
        """Create and sign a new transaction"""
        try:
            # Validate inputs
            if not validate_transaction_amount(amount):
                return None, "Invalid transaction amount"

            # Get encrypted private key from DB
            sender_wallet = execute_query(
                "SELECT encrypted_private_key FROM wallets WHERE wallet_address = ?",
                (sender,),
                fetch=True
            )

            if not sender_wallet:
                return None, "Sender wallet not found"

            encrypted_private_key = sender_wallet[0][0]

            # Decrypt private key using password
            private_key = self.crypto.decrypt_private_key(encrypted_private_key, password)
            if not private_key:
                return None, "Failed to decrypt private key"

            # Calculate fee if not provided
            if fee is None:
                fee = calculate_transaction_fee(amount, FEE_PERCENT)

            # Create transaction
            transaction = {
                'sender': sender,
                'recipient': recipient,
                'amount': float(amount),
                'fee': float(fee),
                'timestamp': time.time(),
                'is_coinbase': False
            }

            # Generate transaction hash
            tx_hash = self.crypto.generate_transaction_hash(transaction)
            transaction['tx_hash'] = tx_hash

            # Sign transaction
            signature = self.crypto.sign_message(private_key, tx_hash)
            if not signature:
                return None, "Failed to sign transaction"

            transaction['signature'] = signature

            # Validate transaction
            is_valid, error = self.validate_transaction(transaction)
            if not is_valid:
                return None, error

            logging.info(f"Created transaction: {tx_hash}")
            return transaction, None

        except Exception as e:
            logging.error(f"Failed to create transaction: {e}")
            return None, str(e)

    def create_coinbase_transaction(self, recipient, amount):
        """Create coinbase transaction for mining rewards"""
        try:
            transaction = {
                'sender': 'COINBASE',
                'recipient': recipient,
                'amount': float(amount),
                'fee': 0.0,
                'timestamp': time.time(),
                'is_coinbase': True,
                'signature': None
            }

            tx_hash = self.crypto.generate_transaction_hash(transaction)
            transaction['tx_hash'] = tx_hash

            return transaction

        except Exception as e:
            logging.error(f"Failed to create coinbase transaction: {e}")
            return None

    def validate_transaction(self, transaction):
        """Validate transaction"""
        try:
            required_fields = ['sender', 'recipient', 'amount', 'fee', 'timestamp', 'tx_hash']
            for field in required_fields:
                if field not in transaction:
                    return False, f"Missing field: {field}"

            if transaction.get('is_coinbase', False):
                return True, "Valid coinbase transaction"

            if 'signature' not in transaction:
                return False, "Missing signature"

            sender_data = execute_query(
                "SELECT public_key FROM wallets WHERE wallet_address = ?",
                (transaction['sender'],),
                fetch=True
            )

            if not sender_data:
                return False, "Sender wallet not found"

            public_key = sender_data[0][0].encode()

            is_valid = self.crypto.verify_signature(
                public_key,
                transaction['tx_hash'],
                transaction['signature']
            )

            if not is_valid:
                return False, "Invalid signature"

            balance_info = execute_query(
                "SELECT balance FROM wallets WHERE wallet_address = ?",
                (transaction['sender'],),
                fetch=True
            )

            if balance_info:
                balance = balance_info[0][0]
                total_cost = transaction['amount'] + transaction['fee']

                if balance < total_cost:
                    return False, "Insufficient balance"

            return True, "Valid transaction"

        except Exception as e:
            logging.error(f"Failed to validate transaction: {e}")
            return False, str(e)

    def add_to_mempool(self, transaction):
        """Add transaction to mempool"""
        try:
            is_valid, error = self.validate_transaction(transaction)
            if not is_valid:
                return False, error

            existing = execute_query(
                "SELECT id FROM transactions WHERE tx_hash = ?",
                (transaction['tx_hash'],),
                fetch=True
            )

            if existing:
                return False, "Transaction already exists"

            self.pending_transactions.append(transaction)

            execute_query(
                "INSERT INTO transactions (tx_hash, sender, recipient, amount, fee, timestamp, signature, is_coinbase) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    transaction['tx_hash'],
                    transaction['sender'],
                    transaction['recipient'],
                    transaction['amount'],
                    transaction['fee'],
                    transaction['timestamp'],
                    transaction.get('signature'),
                    int(transaction.get('is_coinbase', False))
                )
            )

            logging.info(f"Added transaction to mempool: {transaction['tx_hash']}")
            return True, "Transaction added to mempool"

        except Exception as e:
            logging.error(f"Failed to add transaction to mempool: {e}")
            return False, str(e)

    def get_pending_transactions(self, limit=None):
        """Get pending transactions for block creation"""
        try:
            query = """
                SELECT tx_hash, sender, recipient, amount, fee, timestamp, signature, is_coinbase
                FROM transactions
                WHERE tx_hash NOT IN (
                    SELECT DISTINCT tx_hash FROM blocks b
                    JOIN transactions t ON b.merkle_root LIKE '%' || t.tx_hash || '%'
                )
                ORDER BY fee DESC, timestamp ASC
            """

            if limit:
                query += f" LIMIT {limit}"

            transactions = execute_query(query, fetch=True)

            return [
                {
                    'tx_hash': tx[0],
                    'sender': tx[1],
                    'recipient': tx[2],
                    'amount': tx[3],
                    'fee': tx[4],
                    'timestamp': tx[5],
                    'signature': tx[6],
                    'is_coinbase': bool(tx[7])
                }
                for tx in transactions
            ]

        except Exception as e:
            logging.error(f"Failed to get pending transactions: {e}")
            return []

    def process_transactions(self, transactions):
        """Process transactions and update balances"""
        try:
            for transaction in transactions:
                if transaction.get('is_coinbase', False):
                    execute_query(
                        "UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?",
                        (transaction['amount'], transaction['recipient'])
                    )
                else:
                    execute_query(
                        "UPDATE wallets SET balance = balance - ? WHERE wallet_address = ?",
                        (transaction['amount'] + transaction['fee'], transaction['sender'])
                    )

                    execute_query(
                        "UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?",
                        (transaction['amount'], transaction['recipient'])
                    )

                self.pending_transactions = [
                    tx for tx in self.pending_transactions
                    if tx['tx_hash'] != transaction['tx_hash']
                ]

            logging.info(f"Processed {len(transactions)} transactions")
            return True

        except Exception as e:
            logging.error(f"Failed to process transactions: {e}")
            return False

    def get_transaction_by_hash(self, tx_hash):
        """Get transaction by hash"""
        try:
            transaction = execute_query(
                "SELECT * FROM transactions WHERE tx_hash = ?",
                (tx_hash,),
                fetch=True
            )

            if transaction:
                tx = transaction[0]
                return {
                    'tx_hash': tx[1],
                    'sender': tx[2],
                    'recipient': tx[3],
                    'amount': tx[4],
                    'fee': tx[5],
                    'timestamp': tx[6],
                    'signature': tx[7],
                    'is_coinbase': bool(tx[8])
                }

            return None

        except Exception as e:
            logging.error(f"Failed to get transaction: {e}")
            return None

    def get_transaction_pool_stats(self):
        """Get mempool statistics"""
        try:
            pending_count = len(self.pending_transactions)
            total_fees = sum(tx['fee'] for tx in self.pending_transactions)

            return {
                'pending_count': pending_count,
                'total_fees': total_fees,
                'average_fee': total_fees / pending_count if pending_count > 0 else 0
            }

        except Exception as e:
            logging.error(f"Failed to get mempool stats: {e}")
            return {'pending_count': 0, 'total_fees': 0, 'average_fee': 0}


# Global transaction manager instance
transaction_manager = TransactionManager()
