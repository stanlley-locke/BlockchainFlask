"""
Flask routes for blockchain application
"""
import json
import logging
from flask import render_template, request, jsonify, session, redirect, url_for
from flask_socketio import emit
from . import app, socketio
from core.wallet import wallet_manager
from core.transactions import transaction_manager
from core.block_ops import block_operations
from core.database import get_db_connection, execute_query
from network.network_manager import network_manager

# Home page
@app.route('/')
def index():
    """Main dashboard page"""
    try:
        # Get blockchain stats
        blockchain_stats = block_operations.get_blockchain_stats()
        
        # Get network status
        network_status = network_manager.get_network_status()
        
        # Get recent transactions
        recent_transactions = execute_query(
            "SELECT tx_hash, sender, recipient, amount, timestamp FROM transactions ORDER BY timestamp DESC LIMIT 10",
            fetch=True
        )
        
        return render_template('index.html', 
                             blockchain_stats=blockchain_stats,
                             network_status=network_status,
                             recent_transactions=recent_transactions)
    except Exception as e:
        logging.error(f"Error loading dashboard: {e}")
        return render_template('index.html', error=str(e))

@app.route('/admin')
def admin():
    """Admin dashboard page"""
    try:
        # Get comprehensive system stats
        blockchain_stats = block_operations.get_blockchain_stats()
        network_status = network_manager.get_network_status()
        
        # Get all wallets
        wallets = wallet_manager.get_all_wallets()
        
        # Get validator info
        validators = wallet_manager.get_validator_wallets()
        
        return render_template('admin.html',
                             blockchain_stats=blockchain_stats,
                             network_status=network_status,
                             wallets=wallets,
                             validators=validators)
    except Exception as e:
        logging.error(f"Error loading admin dashboard: {e}")
        return render_template('admin.html', error=str(e))

# Wallet Management Routes
@app.route('/api/wallet/create', methods=['POST'])
def create_wallet():
    """Create new wallet"""
    try:
        data = request.get_json()
        password = data.get('password')
        
        wallet = wallet_manager.create_wallet(password)
        if wallet:
            return jsonify({
                'success': True,
                'wallet': wallet
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to create wallet'
            }), 400
    except Exception as e:
        logging.error(f"Error creating wallet: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/wallet/recover', methods=['POST'])
def recover_wallet():
    """Recover wallet from seed phrase"""
    try:
        data = request.get_json()
        seed_phrase = data.get('seed_phrase')
        password = data.get('password')
        
        wallet = wallet_manager.recover_wallet(seed_phrase, password)
        if wallet:
            return jsonify({
                'success': True,
                'wallet': wallet
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to recover wallet'
            }), 400
    except Exception as e:
        logging.error(f"Error recovering wallet: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/wallet/balance/<address>')
def get_wallet_balance(address):
    """Get wallet balance"""
    try:
        balance = wallet_manager.get_wallet_balance(address)
        if balance is not None:
            return jsonify({
                'success': True,
                'balance': balance
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Wallet not found'
            }), 404
    except Exception as e:
        logging.error(f"Error getting wallet balance: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/wallet/transactions/<address>')
def get_wallet_transactions(address):
    """Get wallet transaction history"""
    try:
        transactions = wallet_manager.get_wallet_transactions(address)
        return jsonify({
            'success': True,
            'transactions': transactions
        })
    except Exception as e:
        logging.error(f"Error getting wallet transactions: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/wallet/stake', methods=['POST'])
def stake_coins():
    """Stake coins for validation"""
    try:
        data = request.get_json()
        address = data.get('address')
        amount = data.get('amount')
        
        success = wallet_manager.stake_coins(address, amount)
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to stake coins'
            }), 400
    except Exception as e:
        logging.error(f"Error staking coins: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/wallet/unstake', methods=['POST'])
def unstake_coins():
    """Unstake coins"""
    try:
        data = request.get_json()
        address = data.get('address')
        amount = data.get('amount')
        
        success = wallet_manager.unstake_coins(address, amount)
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to unstake coins'
            }), 400
    except Exception as e:
        logging.error(f"Error unstaking coins: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Transaction Routes
@app.route('/api/transaction/create', methods=['POST'])
def create_transaction():
    """Create new transaction"""
    try:
        data = request.get_json()
        sender = data.get('sender')
        recipient = data.get('recipient')
        amount = data.get('amount')
        private_key = data.get('private_key')
        
        transaction, error = transaction_manager.create_transaction(
            sender, recipient, amount, private_key.encode()
        )
        
        if transaction:
            # Add to mempool
            success, msg = transaction_manager.add_to_mempool(transaction)
            if success:
                # Broadcast transaction
                network_manager.broadcast_message({
                    'type': 'new_transaction',
                    'transaction': transaction
                })
                
                return jsonify({
                    'success': True,
                    'transaction': transaction
                })
            else:
                return jsonify({
                    'success': False,
                    'error': msg
                }), 400
        else:
            return jsonify({
                'success': False,
                'error': error
            }), 400
    except Exception as e:
        logging.error(f"Error creating transaction: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/transaction/<tx_hash>')
def get_transaction(tx_hash):
    """Get transaction by hash"""
    try:
        transaction = transaction_manager.get_transaction_by_hash(tx_hash)
        if transaction:
            return jsonify({
                'success': True,
                'transaction': transaction
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Transaction not found'
            }), 404
    except Exception as e:
        logging.error(f"Error getting transaction: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/mempool/stats')
def get_mempool_stats():
    """Get mempool statistics"""
    try:
        stats = transaction_manager.get_transaction_pool_stats()
        return jsonify({
            'success': True,
            'stats': stats
        })
    except Exception as e:
        logging.error(f"Error getting mempool stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Mining Routes
@app.route('/api/mining/start', methods=['POST'])
def start_mining():
    """Start mining"""
    try:
        data = request.get_json()
        miner_address = data.get('miner_address')
        
        block_operations.start_mining(miner_address, transaction_manager)
        
        return jsonify({
            'success': True,
            'message': f'Mining started for {miner_address}'
        })
    except Exception as e:
        logging.error(f"Error starting mining: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/mining/stop', methods=['POST'])
def stop_mining():
    """Stop mining"""
    try:
        data = request.get_json()
        miner_address = data.get('miner_address')
        
        block_operations.stop_mining(miner_address)
        
        return jsonify({
            'success': True,
            'message': f'Mining stopped for {miner_address}'
        })
    except Exception as e:
        logging.error(f"Error stopping mining: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Blockchain Routes
@app.route('/api/blockchain/stats')
def get_blockchain_stats():
    """Get blockchain statistics"""
    try:
        stats = block_operations.get_blockchain_stats()
        return jsonify({
            'success': True,
            'stats': stats
        })
    except Exception as e:
        logging.error(f"Error getting blockchain stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/blockchain/validate')
def validate_blockchain():
    """Validate entire blockchain"""
    try:
        is_valid, message = block_operations.get_chain_validation_result()
        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': message
        })
    except Exception as e:
        logging.error(f"Error validating blockchain: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/block/<int:block_index>')
def get_block(block_index):
    """Get block by index"""
    try:
        block = block_operations.get_block_by_index(block_index)
        if block:
            return jsonify({
                'success': True,
                'block': block
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Block not found'
            }), 404
    except Exception as e:
        logging.error(f"Error getting block: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/blocks/latest')
def get_latest_block():
    """Get latest block"""
    try:
        block = block_operations.get_latest_block()
        if block:
            return jsonify({
                'success': True,
                'block': block
            })
        else:
            return jsonify({
                'success': False,
                'error': 'No blocks found'
            }), 404
    except Exception as e:
        logging.error(f"Error getting latest block: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Network Routes
@app.route('/api/network/status')
def get_network_status():
    """Get network status"""
    try:
        status = network_manager.get_network_status()
        return jsonify({
            'success': True,
            'status': status
        })
    except Exception as e:
        logging.error(f"Error getting network status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/network/peers')
def get_peers():
    """Get peer list"""
    try:
        peers = network_manager.get_peers()
        return jsonify({
            'success': True,
            'peers': peers
        })
    except Exception as e:
        logging.error(f"Error getting peers: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/network/peer/add', methods=['POST'])
def add_peer():
    """Add peer to network"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        port = data.get('port', 5000)
        
        success = network_manager.add_peer(ip, port)
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to add peer'
            }), 400
    except Exception as e:
        logging.error(f"Error adding peer: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/network/peer/remove', methods=['POST'])
def remove_peer():
    """Remove peer from network"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        port = data.get('port', 5000)
        
        success = network_manager.remove_peer(ip, port)
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to remove peer'
            }), 400
    except Exception as e:
        logging.error(f"Error removing peer: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Smart Contract Routes
@app.route('/api/contracts', methods=['GET'])
def get_contracts():
    """Get all smart contracts"""
    try:
        contracts = execute_query(
            "SELECT address, creator, balance FROM contracts",
            fetch=True
        )
        
        contract_list = [
            {
                'address': contract[0],
                'creator': contract[1],
                'balance': contract[2]
            }
            for contract in contracts
        ]
        
        return jsonify({
            'success': True,
            'contracts': contract_list
        })
    except Exception as e:
        logging.error(f"Error getting contracts: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# NFT Routes
@app.route('/api/nfts', methods=['GET'])
def get_nfts():
    """Get all NFTs"""
    try:
        nfts = execute_query(
            "SELECT id, creator, owner, metadata_uri, created_at FROM nfts",
            fetch=True
        )
        
        nft_list = [
            {
                'id': nft[0],
                'creator': nft[1],
                'owner': nft[2],
                'metadata_uri': nft[3],
                'created_at': nft[4]
            }
            for nft in nfts
        ]
        
        return jsonify({
            'success': True,
            'nfts': nft_list
        })
    except Exception as e:
        logging.error(f"Error getting NFTs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Governance Routes
@app.route('/api/proposals', methods=['GET'])
def get_proposals():
    """Get all governance proposals"""
    try:
        proposals = execute_query(
            "SELECT id, creator, description, options, votes, start_time, end_time, executed FROM proposals",
            fetch=True
        )
        
        proposal_list = [
            {
                'id': proposal[0],
                'creator': proposal[1],
                'description': proposal[2],
                'options': json.loads(proposal[3]),
                'votes': json.loads(proposal[4]),
                'start_time': proposal[5],
                'end_time': proposal[6],
                'executed': bool(proposal[7])
            }
            for proposal in proposals
        ]
        
        return jsonify({
            'success': True,
            'proposals': proposal_list
        })
    except Exception as e:
        logging.error(f"Error getting proposals: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

