#!/usr/bin/env python3
"""
Coinium Blockchain Network - CLI Interface
Main entry point for command-line operations
"""

import os
import sys
import json
import time
import logging
import argparse
from datetime import datetime
import traceback
# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cli.log"),
        #logging.StreamHandler()
    ]
)

# Import core modules
from core.database import init_database
from core.wallet import wallet_manager
from core.transactions import transaction_manager
from core.block_ops import block_operations
from core.crypto import crypto_manager
from network.network_manager import network_manager

# Import Flask app
from app import create_app

def display_banner():
    """Display the application banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                    COINIUM BLOCKCHAIN NETWORK                 ║
    ║                         Version 4.0.0                        ║
    ║                    Advanced Blockchain Platform               ║
    ║                                                               ║
    ║    Features: Smart Contracts, NFTs, Governance, P2P Network  ║
    ║    Author: Stanlley Locke                                     ║
    ║    License: MIT License                                       ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def initialize_system():
    """Initialize the blockchain system"""
    print("Initializing Coinium Blockchain Network...")
    
    # Initialize database
    print("Setting up database...")
    init_database()
    
    # Initialize genesis block if needed
    if len(block_operations.blockchain) == 0:
        print("Creating genesis block...")
        block_operations.create_genesis_block()
    
    # Start network services
    print("Starting network services...")
    network_manager.start_all_services()
    
    print("System initialized successfully!")

def wallet_commands(args):
    """Handle wallet-related commands"""
    if args.wallet_action == 'create':
        password = input("Enter password for wallet encryption (leave empty for no encryption): ")
        if not password:
            password = None
        
        wallet = wallet_manager.create_wallet(password)
        if wallet:
            print(f"\n✓ Wallet created successfully!")
            print(f"Address: {wallet['address']}")
            print(f"Seed Phrase: {wallet['seed_phrase']}")
            print(f"Balance: {wallet['balance']} COIN")
            if not password:
                print(f"Private Key: {wallet['private_key']}")
            print("\n⚠️  Keep your seed phrase and private key secure!")
        else:
            print("❌ Failed to create wallet")
    
    elif args.wallet_action == 'recover':
        seed_phrase = input("Enter seed phrase: ")
        password = input("Enter password (if wallet was encrypted): ")
        if not password:
            password = None
        
        wallet = wallet_manager.recover_wallet(seed_phrase, password)
        if wallet:
            print(f"\n✓ Wallet recovered successfully!")
            print(f"Address: {wallet['address']}")
            print(f"Balance: {wallet['balance']} COIN")
            print(f"Staked: {wallet['staked']} COIN")
        else:
            print("❌ Failed to recover wallet")
    
    elif args.wallet_action == 'balance':
        address = input("Enter wallet address: ").strip()
        balance = wallet_manager.get_wallet_balance(address)
        if balance:
            print(f"\n💰 Wallet Balance for {address[:16]}...")
            print(f"Available: {balance['balance']:.8f} COIN")
            print(f"Staked: {balance['staked']:.8f} COIN")
            print(f"Total: {balance['total']:.8f} COIN")
        else:
            print("❌ Wallet not found")
    
    elif args.wallet_action == 'list':
        wallets = wallet_manager.get_all_wallets()
        if wallets:
            print(f"\n📋 All Wallets ({len(wallets)} total):")
            print("-" * 80)
            for i, wallet in enumerate(wallets, 1):
                print(f"{i:2d}. {wallet['address'][:16]}... | Balance: {wallet['balance']:.8f} | Staked: {wallet['staked']:.8f}")
        else:
            print("No wallets found")
    
    elif args.wallet_action == 'stake':
        address = input("Enter wallet address: ").strip()
        amount = float(input("Enter amount to stake: "))
        
        success = wallet_manager.stake_coins(address, amount)
        if success:
            print(f"✓ Successfully staked {amount:.8f} COIN")
        else:
            print("❌ Failed to stake coins")
    
    elif args.wallet_action == 'unstake':
        address = input("Enter wallet address: ").strip()
        amount = float(input("Enter amount to unstake: "))
        
        success = wallet_manager.unstake_coins(address, amount)
        if success:
            print(f"✓ Successfully unstaked {amount:.8f} COIN")
        else:
            print("❌ Failed to unstake coins")

    elif args.wallet_action == 'fund':
        address = input("Enter wallet address to fund: ")
        amount = float(input("Enter amount to fund: "))
        
        success = wallet_manager.fund_wallet(address, amount)
        if success:
            print(f"✓ Successfully funded {amount:.8f} COIN to {address[:16]}...")
        else:
            print("❌ Failed to fund wallet")   
    else:
        print("❌ Invalid wallet action specified")


def transaction_commands(args):
    """Handle transaction-related commands"""
    if args.transaction_action == 'send':
        sender = input("Enter sender address: ").strip()
        recipient = input("Enter recipient address: ").strip()
        amount = float(input("Enter amount: "))
        password = input("Enter wallet password: ")

        transaction, error = transaction_manager.create_transaction(
            sender, recipient, amount, password
        )

        if transaction:
            success, msg = transaction_manager.add_to_mempool(transaction)
            if success:
                print(f"✓ Transaction sent successfully!")
                print(f"Transaction Hash: {transaction['tx_hash']}")
                print(f"Amount: {amount:.8f} COIN")
                print(f"Fee: {transaction['fee']:.8f} COIN")

                # Broadcast transaction to the network
                network_manager.broadcast_message({
                    'type': 'new_transaction',
                    'transaction': transaction
                })
            else:
                print(f"❌ Failed to add transaction to mempool: {msg}")
        else:
            print(f"❌ Failed to create transaction: {error}")
    
    elif args.transaction_action == 'history':
        address = input("Enter wallet address: ").strip()
        transactions = wallet_manager.get_wallet_transactions(address)

        if transactions:
            print(f"\n📋 Transaction History for {address[:16]}...")
            print("-" * 100)
            for i, tx in enumerate(transactions, 1):
                tx_type = "Received" if tx['recipient'] == address else "Sent"
                print(f"{i:2d}. {tx_type} | {tx['amount']:.8f} COIN | {datetime.fromtimestamp(tx['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"    Hash: {tx['tx_hash']}")
                print(f"    {'From' if tx_type == 'Received' else 'To'}: {tx['sender' if tx_type == 'Received' else 'recipient'][:16]}...")
        else:
            print("No transactions found")

    elif args.transaction_action == 'status':
        tx_hash = input("Enter transaction hash: ")
        transaction = transaction_manager.get_transaction_by_hash(tx_hash)

        if transaction:
            print(f"\n📄 Transaction Details:")
            print(f"Hash: {transaction['tx_hash']}")
            print(f"From: {transaction['sender']}")
            print(f"To: {transaction['recipient']}")
            print(f"Amount: {transaction['amount']:.8f} COIN")
            print(f"Fee: {transaction['fee']:.8f} COIN")
            print(f"Time: {datetime.fromtimestamp(transaction['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Type: {'Coinbase' if transaction['is_coinbase'] else 'Regular'}")
        else:
            print("❌ Transaction not found")


def mining_commands(args):
    """Handle mining-related commands"""
    if args.mining_action == 'start':
        miner_address = input("Enter miner wallet address: ")
        
        # Validate address
        if not wallet_manager.get_wallet_balance(miner_address):
            print("❌ Invalid miner address")
            return
        
        print(f"🔨 Starting mining for {miner_address[:16]}...")
        block_operations.start_mining(miner_address, transaction_manager)
        print("✓ Mining started successfully!")
        print("Press Ctrl+C to stop mining...")
        
        try:
            while True:
                time.sleep(60)
                stats = block_operations.get_blockchain_stats()
                print(f"⛏️  Mining... | Blocks: {stats['total_blocks']} | Difficulty: {stats['current_difficulty']}")
        except KeyboardInterrupt:
            print("\n🛑 Stopping mining...")
            block_operations.stop_mining(miner_address)
            print("✓ Mining stopped")
    
    elif args.mining_action == 'stop':
        miner_address = input("Enter miner wallet address: ")
        block_operations.stop_mining(miner_address)
        print("✓ Mining stopped")

def blockchain_commands(args):
    """Handle blockchain-related commands"""
    if args.blockchain_action == 'stats':
        stats = block_operations.get_blockchain_stats()
        print(f"\n📊 Blockchain Statistics:")
        print(f"Total Blocks: {stats['total_blocks']}")
        print(f"Total Transactions: {stats['total_transactions']}")
        print(f"Current Difficulty: {stats['current_difficulty']}")
        print(f"Hash Rate: {stats['hash_rate']:.2f} H/s")
        if stats['latest_block_time']:
            print(f"Latest Block: {datetime.fromtimestamp(stats['latest_block_time']).strftime('%Y-%m-%d %H:%M:%S')}")
    
    elif args.blockchain_action == 'validate':
        print("🔍 Validating blockchain...")
        is_valid, message = block_operations.get_chain_validation_result()
        if is_valid:
            print(f"✓ {message}")
        else:
            print(f"❌ {message}")
    
    elif args.blockchain_action == 'block':
        block_index = int(input("Enter block index: "))
        block = block_operations.get_block_by_index(block_index)
        
        if block:
            print(f"\n📦 Block #{block['block_index']}:")
            print(f"Hash: {block['hash']}")
            print(f"Previous Hash: {block['previous_hash']}")
            print(f"Timestamp: {datetime.fromtimestamp(block['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Nonce: {block['nonce']}")
            print(f"Difficulty: {block['difficulty']}")
            print(f"Validator: {block.get('validator', 'N/A')}")
            print(f"Merkle Root: {block['merkle_root']}")
        else:
            print("❌ Block not found")
    
    elif args.blockchain_action == 'latest':
        block = block_operations.get_latest_block()
        if block:
            print(f"\n📦 Latest Block #{block['block_index']}:")
            print(f"Hash: {block['hash']}")
            print(f"Timestamp: {datetime.fromtimestamp(block['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Nonce: {block['nonce']}")
            print(f"Difficulty: {block['difficulty']}")
        else:
            print("❌ No blocks found")

def network_commands(args):
    """Handle network-related commands"""
    if args.network_action == 'status':
        status = network_manager.get_network_status()
        print(f"\n🌐 Network Status:")
        print(f"Services Running: {'✓' if status['services_running'] else '❌'}")
        print(f"Connected Peers: {status['node_info']['peer_count']}")
        print(f"Public IP: {status['node_info']['public_ip'] or 'Unknown'}")
        print(f"Public Port: {status['node_info']['public_port']}")
        print(f"Healthy Peers: {status['health_stats']['healthy_peers']}")
        print(f"Average Latency: {status['health_stats']['average_latency']:.3f}s")
        print(f"Network Health: {status['health_stats']['healthy_peers']}/{status['health_stats']['total_peers']}")
    
    elif args.network_action == 'peers':
        peers = network_manager.get_peers()
        if peers:
            print(f"\n👥 Connected Peers ({len(peers)} total):")
            for i, peer in enumerate(peers, 1):
                print(f"{i:2d}. {peer[0]}:{peer[1]}")
        else:
            print("No peers connected")
    
    elif args.network_action == 'add-peer':
        ip = input("Enter peer IP address: ")
        port = int(input("Enter peer port (default 5000): ") or "5000")
        
        success = network_manager.add_peer(ip, port)
        if success:
            print(f"✓ Peer {ip}:{port} added successfully")
        else:
            print(f"❌ Failed to add peer {ip}:{port}")
    
    elif args.network_action == 'ping':
        print("🏓 Pinging all peers...")
        health_ratio = network_manager.ping_all_peers()
        print(f"✓ Ping completed. Network health: {health_ratio:.1%}")

def run_web_interface():
    """Run the Flask web interface"""
    print("🚀 Starting Coinium Web Interface...")
    
    # Initialize system
    initialize_system()
    
    # Create Flask app
    app, socketio = create_app()
    
    print("✓ Web interface started successfully!")
    print("🌐 Access the dashboard at: http://localhost:5000")
    print("🔧 Access the admin panel at: http://localhost:5000/admin")
    print("Press Ctrl+C to stop the server...")
    
    try:
        # Run the Flask app with Socket.IO
        socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down web interface...")
        network_manager.stop_all_services()
        print("✓ Web interface stopped")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Coinium Blockchain Network CLI')
    parser.add_argument('--version', action='version', version='Coinium Blockchain Network 4.0.0')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Web interface command
    web_parser = subparsers.add_parser('web', help='Start web interface')
    
    # Wallet commands
    wallet_parser = subparsers.add_parser('wallet', help='Wallet management')
    wallet_parser.add_argument('wallet_action', choices=['create', 'recover', 'balance', 'list', 'stake', 'unstake'])
    
    # Transaction commands
    tx_parser = subparsers.add_parser('transaction', help='Transaction management')
    tx_parser.add_argument('transaction_action', choices=['send', 'history', 'status'])
    
    # Mining commands
    mining_parser = subparsers.add_parser('mining', help='Mining operations')
    mining_parser.add_argument('mining_action', choices=['start', 'stop'])
    
    # Blockchain commands
    blockchain_parser = subparsers.add_parser('blockchain', help='Blockchain operations')
    blockchain_parser.add_argument('blockchain_action', choices=['stats', 'validate', 'block', 'latest'])
    
    # Network commands
    network_parser = subparsers.add_parser('network', help='Network management')
    network_parser.add_argument('network_action', choices=['status', 'peers', 'add-peer', 'ping'])
    
    # Parse arguments
    args = parser.parse_args()
    
    # Display banner
    display_banner()
    
    # Handle commands
    if args.command == 'web':
        run_web_interface()
    elif args.command == 'wallet':
        initialize_system()
        wallet_commands(args)
    elif args.command == 'transaction':
        initialize_system()
        transaction_commands(args)
    elif args.command == 'mining':
        initialize_system()
        mining_commands(args)
    elif args.command == 'blockchain':
        initialize_system()
        blockchain_commands(args)
    elif args.command == 'network':
        initialize_system()
        network_commands(args)
    else:
        # Interactive mode
        print("🎯 Starting interactive mode...")
        initialize_system()
        
        while True:
            try:
                print("\n" + "="*60)
                print("COINIUM BLOCKCHAIN NETWORK - INTERACTIVE MODE")
                print("="*60)
                print("1. Wallet Management")
                print("2. Transaction Management")
                print("3. Mining Operations")
                print("4. Blockchain Operations")
                print("5. Network Management")
                print("6. Start Web Interface")
                print("7. Exit")
                print("-"*60)
                
                choice = input("Enter your choice (1-7): ").strip()
                
                if choice == '1':
                    print("\n📱 Wallet Management:")
                    print("1. Create Wallet")
                    print("2. Recover Wallet")
                    print("3. Check Balance")
                    print("4. List Wallets")
                    print("5. Stake Coins")
                    print("6. Unstake Coins")
                    print("7. fund wallet ")
                    
                    wallet_choice = input("Enter choice (1-7: ").strip()
                    actions = ['create', 'recover', 'balance', 'list', 'stake', 'unstake', 'fund']
                    if wallet_choice in ['1', '2', '3', '4', '5', '6', '7']:
                        args = argparse.Namespace(wallet_action=actions[int(wallet_choice)-1])
                        wallet_commands(args)
                
                elif choice == '2':
                    print("\n💸 Transaction Management:")
                    print("1. Send Transaction")
                    print("2. Transaction History")
                    print("3. Transaction Status")
                    
                    tx_choice = input("Enter choice (1-3): ").strip()
                    actions = ['send', 'history', 'status']
                    if tx_choice in ['1', '2', '3']:
                        args = argparse.Namespace(transaction_action=actions[int(tx_choice)-1])
                        transaction_commands(args)
                
                elif choice == '3':
                    print("\n⛏️ Mining Operations:")
                    print("1. Start Mining")
                    print("2. Stop Mining")
                    
                    mining_choice = input("Enter choice (1-2): ").strip()
                    actions = ['start', 'stop']
                    if mining_choice in ['1', '2']:
                        args = argparse.Namespace(mining_action=actions[int(mining_choice)-1])
                        mining_commands(args)
                
                elif choice == '4':
                    print("\n⛓️ Blockchain Operations:")
                    print("1. Show Statistics")
                    print("2. Validate Blockchain")
                    print("3. Get Block")
                    print("4. Latest Block")
                    
                    blockchain_choice = input("Enter choice (1-4): ").strip()
                    actions = ['stats', 'validate', 'block', 'latest']
                    if blockchain_choice in ['1', '2', '3', '4']:
                        args = argparse.Namespace(blockchain_action=actions[int(blockchain_choice)-1])
                        blockchain_commands(args)
                
                elif choice == '5':
                    print("\n🌐 Network Management:")
                    print("1. Network Status")
                    print("2. List Peers")
                    print("3. Add Peer")
                    print("4. Ping All Peers")
                    
                    network_choice = input("Enter choice (1-4): ").strip()
                    actions = ['status', 'peers', 'add-peer', 'ping']
                    if network_choice in ['1', '2', '3', '4']:
                        args = argparse.Namespace(network_action=actions[int(network_choice)-1])
                        network_commands(args)
                
                elif choice == '6':
                    run_web_interface()
                    break
                
                elif choice == '7':
                    print("\n👋 Goodbye!")
                    break
                
                else:
                    print("❌ Invalid choice. Please try again.")
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ An error occurred: {e}")
                logging.error(f"CLI error: {e}")

if __name__ == "__main__":
    main()
