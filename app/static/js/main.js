// Coinium Blockchain Network - Main JavaScript

// Global variables
let socket;
let isConnected = false;
let currentWallet = null;
let updateInterval;

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeSocket();
    initializeEventListeners();
    startPeriodicUpdates();
    loadInitialData();
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
            updateBlockchainStats(data.stats);
        }
    });
    
    socket.on('network_status', function(data) {
        if (data.success) {
            updateNetworkStatus(data.status);
        }
    });
    
    socket.on('mempool_stats', function(data) {
        if (data.success) {
            updateMempoolStats(data.stats);
        }
    });
    
    socket.on('new_block', function(data) {
        showNotification('New block mined!', 'success');
        updateBlockchainStats();
    });
    
    socket.on('new_transaction', function(data) {
        showNotification('New transaction received!', 'info');
        updateTransactionTable();
    });
    
    socket.on('network_update', function(data) {
        updateNetworkStatus(data.update);
    });
}

// Event listeners
function initializeEventListeners() {
    // Transaction form
    const transactionForm = document.getElementById('transaction-form');
    if (transactionForm) {
        transactionForm.addEventListener('submit', handleTransactionSubmit);
    }
    
    // Wallet creation form
    const createWalletForm = document.getElementById('create-wallet-form');
    if (createWalletForm) {
        createWalletForm.addEventListener('submit', handleCreateWalletSubmit);
    }
    
    // Wallet recovery form
    const recoverWalletForm = document.getElementById('recover-wallet-form');
    if (recoverWalletForm) {
        recoverWalletForm.addEventListener('submit', handleRecoverWalletSubmit);
    }
}

// Periodic updates
function startPeriodicUpdates() {
    updateInterval = setInterval(function() {
        if (isConnected) {
            socket.emit('get_blockchain_stats');
            socket.emit('get_network_status');
            socket.emit('get_mempool_stats');
        }
    }, 5000); // Update every 5 seconds
}

// Load initial data
function loadInitialData() {
    if (isConnected) {
        socket.emit('get_blockchain_stats');
        socket.emit('get_network_status');
        socket.emit('get_mempool_stats');
    }
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

// Update blockchain statistics
function updateBlockchainStats(stats) {
    if (stats) {
        document.getElementById('total-blocks').textContent = stats.total_blocks || 0;
        document.getElementById('total-transactions').textContent = stats.total_transactions || 0;
        document.getElementById('difficulty').textContent = stats.current_difficulty || 4;
        document.getElementById('hash-rate').textContent = (stats.hash_rate || 0).toFixed(2) + ' H/s';
    }
}

// Update network status
function updateNetworkStatus(status) {
    if (status && status.node_info) {
        document.getElementById('peer-count').textContent = status.node_info.peer_count || 0;
    }
    
    if (status && status.health_stats) {
        document.getElementById('healthy-peers').textContent = status.health_stats.healthy_peers || 0;
        const avgLatency = status.health_stats.average_latency || 0;
        document.getElementById('avg-latency').textContent = (avgLatency * 1000).toFixed(0) + 'ms';
    }
}

// Update mempool statistics
function updateMempoolStats(stats) {
    if (stats) {
        document.getElementById('mempool-size').textContent = stats.pending_count || 0;
    }
}

// Wallet functions
function createWallet() {
    const modal = new bootstrap.Modal(document.getElementById('createWalletModal'));
    modal.show();
}

function recoverWallet() {
    const modal = new bootstrap.Modal(document.getElementById('recoverWalletModal'));
    modal.show();
}

function submitCreateWallet() {
    const password = document.getElementById('wallet-password').value;
    
    fetch('/api/wallet/create', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ password: password })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Wallet created successfully!', 'success');
            displayWalletInfo(data.wallet);
            
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('createWalletModal'));
            modal.hide();
        } else {
            showNotification(data.error || 'Failed to create wallet', 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error creating wallet', 'danger');
    });
}

function submitRecoverWallet() {
    const seedPhrase = document.getElementById('seed-phrase').value;
    const password = document.getElementById('recover-password').value;
    
    fetch('/api/wallet/recover', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
            seed_phrase: seedPhrase,
            password: password 
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Wallet recovered successfully!', 'success');
            displayWalletInfo(data.wallet);
            
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('recoverWalletModal'));
            modal.hide();
        } else {
            showNotification(data.error || 'Failed to recover wallet', 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error recovering wallet', 'danger');
    });
}

function displayWalletInfo(wallet) {
    // Display wallet information
    const walletInfo = document.getElementById('wallet-info');
    if (walletInfo) {
        walletInfo.classList.remove('d-none');
        document.getElementById('wallet-balance').textContent = (wallet.balance || 0).toFixed(8);
        document.getElementById('wallet-staked').textContent = (wallet.staked || 0).toFixed(8);
        
        // Set wallet address in input
        document.getElementById('wallet-address').value = wallet.address;
        
        // Store current wallet
        currentWallet = wallet;
    }
}

function checkBalance() {
    const address = document.getElementById('wallet-address').value;
    
    if (!address) {
        showNotification('Please enter a wallet address', 'warning');
        return;
    }
    
    fetch(`/api/wallet/balance/${address}`)
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            document.getElementById('wallet-balance').textContent = data.balance.balance.toFixed(8);
            document.getElementById('wallet-staked').textContent = data.balance.staked.toFixed(8);
            document.getElementById('wallet-info').classList.remove('d-none');
        } else {
            showNotification(data.error || 'Wallet not found', 'warning');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error checking balance', 'danger');
    });
}

// Transaction functions
function handleTransactionSubmit(event) {
    event.preventDefault();
    
    const sender = document.getElementById('tx-sender').value;
    const recipient = document.getElementById('tx-recipient').value;
    const amount = parseFloat(document.getElementById('tx-amount').value);
    const privateKey = document.getElementById('tx-private-key').value;
    
    if (!sender || !recipient || !amount || !privateKey) {
        showNotification('Please fill in all fields', 'warning');
        return;
    }
    
    // Show loading state
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Sending...';
    submitBtn.disabled = true;
    
    fetch('/api/transaction/create', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            sender: sender,
            recipient: recipient,
            amount: amount,
            private_key: privateKey
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Transaction sent successfully!', 'success');
            
            // Clear form
            document.getElementById('transaction-form').reset();
            
            // Update transaction table
            updateTransactionTable();
        } else {
            showNotification(data.error || 'Failed to send transaction', 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error sending transaction', 'danger');
    })
    .finally(() => {
        // Restore button state
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    });
}

// Mining functions
function startMining() {
    const minerAddress = document.getElementById('miner-address').value;
    
    if (!minerAddress) {
        showNotification('Please enter a miner address', 'warning');
        return;
    }
    
    fetch('/api/mining/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ miner_address: minerAddress })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Mining started successfully!', 'success');
            updateMiningStatus('Mining...', 'success');
        } else {
            showNotification(data.error || 'Failed to start mining', 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error starting mining', 'danger');
    });
}

function stopMining() {
    const minerAddress = document.getElementById('miner-address').value;
    
    if (!minerAddress) {
        showNotification('Please enter a miner address', 'warning');
        return;
    }
    
    fetch('/api/mining/stop', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ miner_address: minerAddress })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Mining stopped successfully!', 'info');
            updateMiningStatus('Idle', 'secondary');
        } else {
            showNotification(data.error || 'Failed to stop mining', 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error stopping mining', 'danger');
    });
}

function updateMiningStatus(status, type) {
    const statusElement = document.getElementById('mining-status');
    const statusText = document.getElementById('mining-status-text');
    
    if (statusElement && statusText) {
        statusText.textContent = status;
        statusElement.className = `mt-3 alert alert-${type}`;
        statusElement.classList.remove('d-none');
    }
}

// Fund wallet for testing
function fundWallet() {
    const address = document.getElementById('wallet-address').value;
    if (!address) {
        showNotification('Please enter a wallet address first', 'warning');
        return;
    }

    const amount = prompt('Enter amount to fund (default: 1000):', '1000');
    if (!amount || isNaN(amount) || parseFloat(amount) <= 0) {
        showNotification('Invalid amount', 'warning');
        return;
    }

    fetch('/api/wallet/fund', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            address: address,
            amount: parseFloat(amount)
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification(`Successfully funded ${amount} coins to wallet!`, 'success');
            // Auto-refresh balance
            checkBalance();
        } else {
            showNotification(data.error || 'Failed to fund wallet', 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error funding wallet', 'danger');
    });
}

// Update transaction table
function updateTransactionTable() {
    // This would typically fetch recent transactions and update the table
    // For now, we'll just refresh the page data
    if (isConnected) {
        location.reload();
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

function formatTimestamp(timestamp) {
    return new Date(timestamp * 1000).toLocaleString();
}

function formatBalance(balance) {
    return parseFloat(balance).toFixed(8);
}

function formatHash(hash) {
    return hash.substring(0, 12) + '...';
}

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (updateInterval) {
        clearInterval(updateInterval);
    }
    
    if (socket) {
        socket.disconnect();
    }
});

