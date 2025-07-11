"""
Flask app initialization and Socket.IO setup
"""
import os
import logging
from flask import Flask
from flask_socketio import SocketIO

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key-change-in-production")

# Initialize Socket.IO
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

# Import routes and socket events
from . import routes
from . import socketio_events

def create_app():
    """Create and configure the Flask app"""
    # Initialize database
    from core.database import init_database
    init_database()
    
    # Start network services
    from network.network_manager import network_manager
    network_manager.start_all_services()
    
    return app, socketio
