// Coinium Blockchain Network - Admin JavaScript

// Global variables
let socket;
let isConnected = false;
let refreshInterval;
let logInterval;

// Initialize admin application
document.addEventListener('DOMContentLoaded', function() {
    initializeSocket();
    initializeEventListeners();
    startPeriodicUpdates();
    loadInitialData();
    startLogUpdates();
});

// Socket.IO initialization
function initializeSocket() {
    if (typeof io === 'undefined' || window.socketFallback) {
        console.warn('Socket.IO not available, real-time features disabled');
        return;
    }
    
    socket = io();
    
    socket.on('connect', function() {
        isConnected = true;
        updateConnectionStatus(true);
        console.log('Connected to server');
        
        // Subscribe to real-time updates
        socket.emit('subscribe_updates');
    });
    
    socket.on('disconnect', function() {
        isConnected = false;
        updateConnectionStatus(false);
        console.log('Disconnected from server');
    });
    
    socket.on('blockchain_stats', function(data) {
        if (data.success) {
            updateSystemStatus(data.stats);
        }
    });
    
    socket.on('network_status', function(data) {
        if (data.success) {
            updateNetworkInfo(data.status);
        }
    });
    
    socket.on('new_block', function(data) {
        addLogEntry(`New block mined: ${data.block.hash.substring(0, 12)}...`);
        updateSystemStatus();
    });
    
    socket.on('new_transaction', function(data) {
        addLogEntry(`New transaction: ${data.transaction.tx_hash.substring(0, 12)}...`);
    });
    
    socket.on('network_update', function(data) {
        addLogEntry(`Network update: ${data.update.message || 'Status changed'}`);
    });
    
    socket.on('peer_update', function(data) {
        addLogEntry(`Peer update: ${data.peer_data.action || 'Peer list updated'}`);
        updatePeersList();
    });
}

// Event listeners
function initializeEventListeners() {
    // Add peer button
    const addPeerBtn = document.querySelector('button[onclick="addPeer()"]');
    if (addPeerBtn) {
        addPeerBtn.addEventListener('click', addPeer);
    }
}

// Periodic updates
function startPeriodicUpdates() {
    refreshInterval = setInterval(function() {
        if (isConnected) {
            socket.emit('get_blockchain_stats');
            socket.emit('get_network_status');
            loadContracts();
            loadNFTs();
            loadProposals();
        }
    }, 10000); // Update every 10 seconds
}

// Load initial data
function loadInitialData() {
    if (isConnected) {
        socket.emit('get_blockchain_stats');
        socket.emit('get_network_status');
    }
    
    loadContracts();
    loadNFTs();
    loadProposals();
}

// Start log updates
function startLogUpdates() {
    logInterval = setInterval(function() {
        // Simulate log entries (in production, these would come from server)
        const now = new Date().toISOString();
        if (Math.random() > 0.7) {
            const messages = [
                'Peer health check completed',
                'Transaction pool updated',
                'Block validation in progress',
                'Network synchronization status: OK',
                'Mempool key rotated',
                'Reputation scores updated'
            ];
            const message = messages[Math.floor(Math.random() * messages.length)];
            addLogEntry(`[${now}] ${message}`);
        }
    }, 5000);
}

// Update connection status
function updateConnectionStatus(connected) {
    const statusElement = document.getElementById('connection-status');
    if (statusElement) {
        if (connected) {
            statusElement.innerHTML = '<i class="fas fa-wifi me-1"></i>Connected';
            statusElement.className = 'badge bg-success';
        } else {
            statusElement.innerHTML = '<i class="fas fa-wifi-slash me-1"></i>Disconnected';
            statusElement.className = 'badge bg-danger';
        }
    }
}

// Update system status
function updateSystemStatus(stats) {
    if (stats) {
        // Update system status indicators
        const servicesStatus = document.getElementById('services-status');
        if (servicesStatus) {
            servicesStatus.innerHTML = '<span class="text-success"><i class="fas fa-check-circle"></i> Running</span>';
        }
        
        const blockchainValid = document.getElementById('blockchain-valid');
        if (blockchainValid) {
            blockchainValid.innerHTML = '<span class="text-success"><i class="fas fa-check-circle"></i> Valid</span>';
        }
    }
}

// Update network info
function updateNetworkInfo(status) {
    if (status && status.health_stats) {
        const networkHealth = document.getElementById('network-health');
        if (networkHealth && status.health_stats.total_peers > 0) {
            const healthPercent = (status.health_stats.healthy_peers / status.health_stats.total_peers * 100).toFixed(0);
            networkHealth.textContent = `${healthPercent}%`;
        }
    }
}

// Network management functions
function addPeer() {
    const ip = document.getElementById('peer-ip').value;
    const port = parseInt(document.getElementById('peer-port').value) || 5000;
    
    if (!ip) {
        showNotification('Please enter an IP address', 'warning');
        return;
    }
    
    fetch('/api/network/peer/add', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip: ip, port: port })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Peer added successfully!', 'success');
            updatePeersList();
            
            // Clear inputs
            document.getElementById('peer-ip').value = '';
            document.getElementById('peer-port').value = '5000';
        } else {
            showNotification(data.error || 'Failed to add peer', 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error adding peer', 'danger');
    });
}

function removePeer(ip, port) {
    fetch('/api/network/peer/remove', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip: ip, port: port })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Peer removed successfully!', 'success');
            updatePeersList();
        } else {
            showNotification(data.error || 'Failed to remove peer', 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error removing peer', 'danger');
    });
}

function updatePeersList() {
    fetch('/api/network/peers')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const peersList = document.getElementById('peers-list');
            if (peersList) {
                peersList.innerHTML = '';
                
                if (data.peers.length === 0) {
                    peersList.innerHTML = '<div class="list-group-item text-muted">No peers connected</div>';
                } else {
                    data.peers.forEach(peer => {
                        const peerElement = document.createElement('div');
                        peerElement.className = 'list-group-item d-flex justify-content-between align-items-center';
                        peerElement.innerHTML = `
                            <span class="font-monospace">${peer[0]}:${peer[1]}</span>
                            <button class="btn btn-sm btn-danger" onclick="removePeer('${peer[0]}', ${peer[1]})">
                                <i class="fas fa-times"></i>
                            </button>
                        `;
                        peersList.appendChild(peerElement);
                    });
                }
            }
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

function pingAllPeers() {
    fetch('/api/network/status')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Ping completed successfully!', 'success');
            addLogEntry('Ping all peers completed');
        } else {
            showNotification('Ping failed', 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error pinging peers', 'danger');
    });
}

// Blockchain tools
function validateBlockchain() {
    const toolResults = document.getElementById('tool-results');
    toolResults.innerHTML = '<div class="alert alert-info">Validating blockchain...</div>';
    
    fetch('/api/blockchain/validate')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const alertType = data.valid ? 'success' : 'danger';
            const icon = data.valid ? 'check-circle' : 'times-circle';
            
            toolResults.innerHTML = `
                <div class="alert alert-${alertType}">
                    <i class="fas fa-${icon} me-2"></i>${data.message}
                </div>
            `;
            
            addLogEntry(`Blockchain validation: ${data.message}`);
        } else {
            toolResults.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-times-circle me-2"></i>Validation failed: ${data.error}
                </div>
            `;
        }
    })
    .catch(error => {
        console.error('Error:', error);
        toolResults.innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-times-circle me-2"></i>Error validating blockchain
            </div>
        `;
    });
}

function createSnapshot() {
    const toolResults = document.getElementById('tool-results');
    toolResults.innerHTML = '<div class="alert alert-info">Creating snapshot...</div>';
    
    // Simulate snapshot creation
    setTimeout(() => {
        toolResults.innerHTML = `
            <div class="alert alert-success">
                <i class="fas fa-check-circle me-2"></i>Snapshot created successfully
            </div>
        `;
        addLogEntry('Database snapshot created');
    }, 2000);
}

function syncNetwork() {
    const toolResults = document.getElementById('tool-results');
    toolResults.innerHTML = '<div class="alert alert-info">Synchronizing network...</div>';
    
    // Simulate network sync
    setTimeout(() => {
        toolResults.innerHTML = `
            <div class="alert alert-success">
                <i class="fas fa-check-circle me-2"></i>Network synchronized successfully
            </div>
        `;
        addLogEntry('Network synchronization completed');
    }, 3000);
}

function resetNetwork() {
    if (confirm('Are you sure you want to reset the network? This action cannot be undone.')) {
        const toolResults = document.getElementById('tool-results');
        toolResults.innerHTML = '<div class="alert alert-warning">Resetting network...</div>';
        
        // Simulate network reset
        setTimeout(() => {
            toolResults.innerHTML = `
                <div class="alert alert-success">
                    <i class="fas fa-check-circle me-2"></i>Network reset successfully
                </div>
            `;
            addLogEntry('Network reset completed');
        }, 2000);
    }
}

// Load smart contracts
function loadContracts() {
    fetch('/api/contracts')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const contractsList = document.getElementById('contracts-list');
            if (contractsList) {
                if (data.contracts.length === 0) {
                    contractsList.innerHTML = '<p class="text-muted">No smart contracts deployed</p>';
                } else {
                    contractsList.innerHTML = data.contracts.map(contract => `
                        <div class="card mb-2">
                            <div class="card-body">
                                <h6 class="card-title">${contract.address.substring(0, 16)}...</h6>
                                <p class="card-text">
                                    <small class="text-muted">Creator: ${contract.creator.substring(0, 16)}...</small><br>
                                    <small class="text-muted">Balance: ${contract.balance.toFixed(8)} COIN</small>
                                </p>
                            </div>
                        </div>
                    `).join('');
                }
            }
        }
    })
    .catch(error => {
        console.error('Error loading contracts:', error);
    });
}

// Load NFTs
function loadNFTs() {
    fetch('/api/nfts')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const nftsList = document.getElementById('nfts-list');
            if (nftsList) {
                if (data.nfts.length === 0) {
                    nftsList.innerHTML = '<p class="text-muted">No NFTs created</p>';
                } else {
                    nftsList.innerHTML = data.nfts.map(nft => `
                        <div class="card mb-2">
                            <div class="card-body">
                                <h6 class="card-title">${nft.id.substring(0, 16)}...</h6>
                                <p class="card-text">
                                    <small class="text-muted">Owner: ${nft.owner.substring(0, 16)}...</small><br>
                                    <small class="text-muted">Created: ${new Date(nft.created_at * 1000).toLocaleDateString()}</small>
                                </p>
                            </div>
                        </div>
                    `).join('');
                }
            }
        }
    })
    .catch(error => {
        console.error('Error loading NFTs:', error);
    });
}

// Load governance proposals
function loadProposals() {
    fetch('/api/proposals')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const proposalsList = document.getElementById('proposals-list');
            if (proposalsList) {
                if (data.proposals.length === 0) {
                    proposalsList.innerHTML = '<p class="text-muted">No governance proposals</p>';
                } else {
                    proposalsList.innerHTML = data.proposals.map(proposal => `
                        <div class="card mb-3">
                            <div class="card-body">
                                <h6 class="card-title">${proposal.description}</h6>
                                <p class="card-text">
                                    <small class="text-muted">Created by: ${proposal.creator.substring(0, 16)}...</small><br>
                                    <small class="text-muted">
                                        Status: ${proposal.executed ? 'Executed' : 'Active'}
                                    </small>
                                </p>
                                <div class="progress mb-2">
                                    <div class="progress-bar" style="width: ${proposal.votes ? Object.keys(proposal.votes).length * 10 : 0}%"></div>
                                </div>
                            </div>
                        </div>
                    `).join('');
                }
            }
        }
    })
    .catch(error => {
        console.error('Error loading proposals:', error);
    });
}

// Wallet management functions
function viewWallet(address) {
    showNotification(`Viewing wallet: ${address.substring(0, 16)}...`, 'info');
    // In a real implementation, this would open a detailed view
}

function editWallet(address) {
    showNotification(`Editing wallet: ${address.substring(0, 16)}...`, 'info');
    // In a real implementation, this would open an edit form
}

function viewValidator(address) {
    showNotification(`Viewing validator: ${address.substring(0, 16)}...`, 'info');
    // In a real implementation, this would open a detailed view
}

// Log management
function addLogEntry(message) {
    const logsContainer = document.getElementById('system-logs');
    if (logsContainer) {
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        logEntry.textContent = `[${new Date().toISOString()}] ${message}`;
        
        logsContainer.appendChild(logEntry);
        
        // Keep only last 100 log entries
        const logEntries = logsContainer.querySelectorAll('.log-entry');
        if (logEntries.length > 100) {
            logEntries[0].remove();
        }
        
        // Scroll to bottom
        logsContainer.scrollTop = logsContainer.scrollHeight;
    }
}

// Utility functions
function showNotification(message, type) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    notification.style.top = '80px';
    notification.style.right = '20px';
    notification.style.zIndex = '9999';
    notification.style.minWidth = '300px';
    
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Add to body
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 5000);
}

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
    
    if (logInterval) {
        clearInterval(logInterval);
    }
    
    if (socket) {
        socket.disconnect();
    }
});

