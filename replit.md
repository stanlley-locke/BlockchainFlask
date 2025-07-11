# Coinium Blockchain Network

## Overview

Coinium is a comprehensive blockchain network implementation featuring smart contracts, NFTs, governance, and a P2P network. It's built with Python/Flask for the web interface and includes a complete blockchain infrastructure with mining, staking, and transaction management capabilities.

## User Preferences

```
Preferred communication style: Simple, everyday language.
```

## System Architecture

### Technology Stack
- **Backend**: Python 3.x with Flask web framework
- **Database**: SQLite for local storage
- **Frontend**: HTML/CSS/JavaScript with Bootstrap 5 (dark theme)
- **Real-time Communication**: Socket.IO for live updates
- **Networking**: Custom P2P network implementation
- **Cryptography**: Ed25519 for key generation and signing

### Application Structure
The system follows a modular architecture with clear separation of concerns:

```
coinium/
├── app/                    # Flask web application
├── core/                   # Core blockchain functionality
├── network/                # P2P networking system
├── attached_assets/        # Legacy blockchain implementations
├── cli.py                  # Command-line interface
└── main.py                 # Main web application entry point
```

## Key Components

### Core Blockchain (core/)
- **Database Layer**: SQLite-based storage for blockchain data, wallets, and transactions
- **Cryptography**: Ed25519 key pairs, address generation, and message signing
- **Wallet Management**: Wallet creation, balance tracking, and staking functionality
- **Transaction System**: Transaction creation, validation, and mempool management
- **Block Operations**: Mining, block validation, and difficulty adjustment
- **Utilities**: Hash calculations, merkle trees, and shard management

### P2P Network (network/)
- **Node Management**: Peer discovery, NAT traversal using UPnP/STUN
- **Messaging**: Gossip protocol implementation with priority queues
- **Health Monitoring**: Peer latency tracking and health checks
- **Reputation System**: Peer scoring and reputation management
- **SSL/TLS**: Certificate generation and secure communications
- **Mempool Encryption**: Key rotation and encrypted transaction pools

### Web Interface (app/)
- **Flask Routes**: Dashboard, admin panel, and API endpoints
- **Socket.IO Events**: Real-time updates for blockchain stats and network status
- **Templates**: Responsive HTML templates with Bootstrap 5 dark theme
- **Static Assets**: CSS styling and JavaScript for frontend functionality

## Data Flow

### Transaction Flow
1. User creates transaction through web interface or CLI
2. Transaction signed with Ed25519 private key
3. Added to encrypted mempool with current rotation key
4. Gossip protocol propagates transaction to network peers
5. Miners include transaction in next block
6. Block validation and consensus through proof-of-stake/proof-of-work hybrid

### Network Communication
1. P2P network discovers peers via bootstrap nodes and UPnP
2. SSL/TLS certificates ensure secure peer communication
3. Gossip protocol with priority queues manages message propagation
4. Health monitoring tracks peer latency and reputation
5. Anti-entropy mechanisms ensure network consistency

### Real-time Updates
1. Socket.IO connects web clients to Flask server
2. Blockchain events trigger real-time notifications
3. Network status updates push to connected clients
4. Admin dashboard receives comprehensive system metrics

## External Dependencies

### Core Libraries
- **Flask**: Web framework and API server
- **Flask-SocketIO**: Real-time bidirectional communication
- **cryptography**: Ed25519 keys, SSL certificates, encryption
- **sqlite3**: Database storage and queries
- **miniupnpc**: UPnP NAT traversal for P2P networking
- **pystun**: STUN protocol for NAT detection

### Frontend Dependencies
- **Bootstrap 5**: UI framework with dark theme
- **Font Awesome**: Icon library
- **Socket.IO client**: Real-time communication
- **Chart.js**: Data visualization (implied by admin dashboard)

### Optional Dependencies
- **aiortc**: WebRTC support for advanced P2P features
- **colorama**: Terminal color output for CLI

## Deployment Strategy

### Local Development
- Single-file execution with `python main.py`
- SQLite database for easy setup
- Built-in Flask development server
- Socket.IO with CORS enabled for development

### Production Considerations
- Environment variables for security (SESSION_SECRET, ENCRYPTION_KEY)
- SSL certificate generation for P2P network security
- Database backup and recovery mechanisms
- Horizontal scaling through shard management
- Load balancing for web interface

### Network Deployment
- Bootstrap nodes for peer discovery
- UPnP/STUN for NAT traversal
- SSL/TLS for encrypted peer communication
- Reputation system for network security
- Health monitoring for network stability

The system is designed to be self-contained with minimal external dependencies while providing enterprise-grade blockchain functionality including smart contracts, NFTs, and governance features.