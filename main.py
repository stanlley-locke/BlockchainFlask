"""
Coinium Blockchain Network - Main Entry Point
This is the main entry point for the Flask web application
"""

import os
import sys
import logging

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Import the Flask app
from app import create_app

# Create the app and socketio instances at module level
app, socketio = create_app()

def main():
    """Main entry point for the web application"""
    try:
        # Get port from environment or use default
        port = int(os.environ.get('PORT', 5000))
        
        # Start the application
        print(f"🚀 Starting Coinium Blockchain Network on port {port}...")
        print(f"🌐 Dashboard: http://localhost:{port}/")
        print(f"🔧 Admin Panel: http://localhost:{port}/admin")
        
        # Run with Socket.IO support
        socketio.run(
            app,
            host='0.0.0.0',
            port=port,
            debug=True,
            allow_unsafe_werkzeug=True
        )
        
    except Exception as e:
        logging.error(f"Failed to start application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
