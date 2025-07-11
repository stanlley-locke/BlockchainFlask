"""
Socket.IO event handlers for real-time updates
"""
import logging
from flask_socketio import emit, join_room, leave_room, disconnect
from . import socketio
from network.network_manager import network_manager
from core.block_ops import block_operations
from core.transactions import transaction_manager

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logging.info(f"Client connected: {request.sid}")
    emit('connected', {'status': 'Connected to Coinium Network'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logging.info(f"Client disconnected: {request.sid}")

@socketio.on('join_room')
def handle_join_room(data):
    """Handle client joining a room"""
    room = data.get('room')
    join_room(room)
    emit('status', {'message': f'Joined room: {room}'})

@socketio.on('leave_room')
def handle_leave_room(data):
    """Handle client leaving a room"""
    room = data.get('room')
    leave_room(room)
    emit('status', {'message': f'Left room: {room}'})

@socketio.on('get_blockchain_stats')
def handle_get_blockchain_stats():
    """Send blockchain statistics to client"""
    try:
        stats = block_operations.get_blockchain_stats()
        emit('blockchain_stats', {
            'success': True,
            'stats': stats
        })
    except Exception as e:
        logging.error(f"Error getting blockchain stats: {e}")
        emit('blockchain_stats', {
            'success': False,
            'error': str(e)
        })

@socketio.on('get_network_status')
def handle_get_network_status():
    """Send network status to client"""
    try:
        status = network_manager.get_network_status()
        emit('network_status', {
            'success': True,
            'status': status
        })
    except Exception as e:
        logging.error(f"Error getting network status: {e}")
        emit('network_status', {
            'success': False,
            'error': str(e)
        })

@socketio.on('get_mempool_stats')
def handle_get_mempool_stats():
    """Send mempool statistics to client"""
    try:
        stats = transaction_manager.get_transaction_pool_stats()
        emit('mempool_stats', {
            'success': True,
            'stats': stats
        })
    except Exception as e:
        logging.error(f"Error getting mempool stats: {e}")
        emit('mempool_stats', {
            'success': False,
            'error': str(e)
        })

@socketio.on('subscribe_updates')
def handle_subscribe_updates():
    """Subscribe to real-time updates"""
    join_room('updates')
    emit('status', {'message': 'Subscribed to real-time updates'})

@socketio.on('unsubscribe_updates')
def handle_unsubscribe_updates():
    """Unsubscribe from real-time updates"""
    leave_room('updates')
    emit('status', {'message': 'Unsubscribed from real-time updates'})

# Functions to broadcast updates to clients
def broadcast_new_block(block):
    """Broadcast new block to all connected clients"""
    socketio.emit('new_block', {
        'block': block,
        'timestamp': block.get('timestamp')
    }, room='updates')

def broadcast_new_transaction(transaction):
    """Broadcast new transaction to all connected clients"""
    socketio.emit('new_transaction', {
        'transaction': transaction,
        'timestamp': transaction.get('timestamp')
    }, room='updates')

def broadcast_network_update(update):
    """Broadcast network update to all connected clients"""
    socketio.emit('network_update', {
        'update': update,
        'timestamp': update.get('timestamp')
    }, room='updates')

def broadcast_mining_update(update):
    """Broadcast mining update to all connected clients"""
    socketio.emit('mining_update', {
        'update': update,
        'timestamp': update.get('timestamp')
    }, room='updates')

def broadcast_peer_update(peer_data):
    """Broadcast peer update to all connected clients"""
    socketio.emit('peer_update', {
        'peer_data': peer_data,
        'timestamp': peer_data.get('timestamp')
    }, room='updates')

