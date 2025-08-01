from flask import Flask, jsonify, request
from flask import render_template  # Import render_template for HTML rendering
from flask_cors import CORS # Import CORS
from urllib.parse import urlparse
import requests
import os
from uuid import uuid4
import json # For pretty printing JSON responses and handling requests

# Import the blockchain core components
from blockchain_app import Blockchain, generate_key_pair, DIFFICULTY, MINING_REWARD, sha256_hash, Block, Transaction, UTXO, UTXOPool

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/mine', methods=['GET'])
def mine():
    """
    Mines a new block.
    Requires a 'miner_public_key' query parameter to assign the mining reward.
    """
    miner_public_key = request.args.get('miner_public_key')
    if not miner_public_key:
        return jsonify({"message": "Please provide a 'miner_public_key' query parameter."}), 400

    new_block = blockchain.mine_block(miner_public_key)

    if new_block:
        response = {
            'message': 'New Block Forged',
            'index': new_block.index,
            'transactions': [tx.to_dict() for tx in new_block.transactions.values()],
            'nonce': new_block.nonce,
            'hash': new_block.hash,
            'parent_hash': new_block.parent_hash,
            'height': new_block.height,
            'coinbase_beneficiary': new_block.coinbase_beneficiary,
            'utxo_pool': new_block.utxo_pool.to_dict()
        }
        return jsonify(response), 200
    else:
        return jsonify({"message": "Could not mine a new block. Check server logs for details."}), 500

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    """
    Creates a new transaction and adds it to the pending transactions pool.
    Requires input_public_key, output_public_key, amount, fee, and private_key_pem in the request body.
    """
    values = request.get_json()
    required = ['input_public_key', 'output_public_key', 'amount', 'fee', 'private_key_pem']
    if not all(k in values for k in required):
        return jsonify({'message': 'Missing values', 'required_fields': required}), 400

    input_pk = values['input_public_key']
    output_pk = values['output_public_key']
    amount = values['amount']
    fee = values.get('fee', 0)
    private_key_pem = values['private_key_pem']

    transaction_hash = blockchain.new_transaction(input_pk, output_pk, amount, fee, private_key_pem)

    if transaction_hash:
        response = {'message': f'Transaction {transaction_hash} will be added to the next mined block.'}
        return jsonify(response), 201
    else:
        return jsonify({"message": "Failed to create transaction. Check inputs, balance, or signature."}), 400

@app.route('/chain', methods=['GET'])
def full_chain():
    """Returns the full blockchain (longest chain) and its length."""
    response = {
        'chain': [block.to_dict() for block in blockchain.chain],
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    """
    Registers new nodes with this blockchain instance.
    Requires a list of node URLs in the request body.
    """
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return jsonify({"message": "Error: Please supply a valid list of nodes"}), 400

    for node in nodes:
        try:
            blockchain.register_node(node)
        except ValueError as e:
            print(f"Failed to register node {node}: {e}")
            return jsonify({"message": f"Error registering node {node}: {e}"}), 400

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    """
    Resolves conflicts by replacing the current chain with the longest valid chain
    found among registered nodes.
    """
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced by a longer, valid chain.',
            'new_chain': [block.to_dict() for block in blockchain.chain]
        }
    else:
        response = {
            'message': 'Our chain is authoritative (it is the longest or no longer valid chain was found).',
            'chain': [block.to_dict() for block in blockchain.chain]
        }
    return jsonify(response), 200

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    """Generates a new private/public key pair for a wallet."""
    private_key, public_key = generate_key_pair()
    response = {
        'message': 'New wallet generated',
        'private_key_pem': private_key,
        'public_key_hex': public_key
    }
    return jsonify(response), 200

@app.route('/utxos/<public_key>', methods=['GET'])
def get_utxos(public_key):
    """Returns the balance (sum of UTXOs) for a given public key."""
    last_block = blockchain.last_block
    if not last_block:
        return jsonify({"message": "Blockchain not initialized. Mine the genesis block first."}), 500

    utxo_pool = last_block.utxo_pool
    balance_utxo = utxo_pool.utxos.get(public_key)
    balance = balance_utxo.amount if balance_utxo else 0

    response = {
        'public_key': public_key,
        'balance': balance
    }
    return jsonify(response), 200

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Run a simple Python Flask Blockchain node.")
    parser.add_argument('-p', '--port', default=5000, type=int, help='Port to listen on')
    args = parser.parse_args()
    app.run(host='0.0.0.0', port=args.port, debug=True) # debug=True for development
