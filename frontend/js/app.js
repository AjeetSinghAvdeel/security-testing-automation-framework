// Main Application JavaScript

// Global variables
let socket = null;
let currentTestId = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeWebSocket();
    loadDashboard();
    setupEventListeners();
    startAutoRefresh();
});

// WebSocket connection
function initializeWebSocket() {
    socket = io('http://localhost:5000', {
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        reconnectionAttempts: 5
    });
    
    socket.on('connect', function() {
        console.log('Connected to server');
        updateConnectionStatus(true);
    });
    
    socket.on('test_update', function(data) {
        handleTestUpdate(data);
    });
    
    socket.on('disconnect', function() {
        console.log('Disconnected from server');
        updateConnectionStatus(false);
    });
}

// Load dashboard data
function loadDashboard() {
    fetch('/api/dashboard/stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('total-tests').textContent = data.totalTests || 0;
            document.getElementById('total-vulns').textContent = data.totalVulnerabilities || 0;
            document.getElementById('critical-count').textContent = data.criticalCount || 0;
            document.getElementById('blockchain-records').textContent = data.blockchainRecords || 0;
            document.getElementById('siem-alerts').textContent = data.siemAlerts || 0;
        })
        .catch(error => console.error('Error loading dashboard:', error));
    
    loadRecentTests();
}

// Load recent tests
function loadRecentTests() {
    fetch('/api/tests/recent')
        .then(response => response.json())
        .then(tests => {
            const tbody = document.getElementById('tests-tbody');
            tbody.innerHTML = '';
            
            tests.slice(0, 10).forEach(test => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td><code class="small">${test.test_id}</code></td>
                    <td>${test.module || 'N/A'}</td>
                    <td>${test.target || 'N/A'}</td>
                    <td><span class="badge bg-info">${test.findings || 0}</span></td>
                    <td><span class="badge bg-${getStatusBadgeColor(test.status)}">${test.status}</span></td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" onclick="viewTestDetails('${test.test_id}')">
                            <i class="bi bi-eye"></i>
                        </button>
                    </td>
                `;
                tbody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading tests:', error));
}

// Run security module test
function runModule(module, test) {
    // Get configuration
    const target = document.getElementById('target-input').value || 'http://localhost:8080';
    const intensity = document.getElementById('intensity-select').value;
    const useBlockchain = document.getElementById('blockchain-check').checked;
    const useSIEM = document.getElementById('siem-check').checked;
    
    // Show loading modal
    const modal = new bootstrap.Modal(document.getElementById('loading-modal'));
    modal.show();
    
    // Update loading message
    document.getElementById('loading-message').textContent = 
        `Running ${module} ${test} test on ${target}...`;
    
    // Prepare request
    const requestData = {
        module: module,
        test: test,
        target: {
            url: target
        },
        intensity: intensity,
        blockchain: useBlockchain,
        siem: useSIEM
    };
    
    // Send test request
    fetch('/api/tests/run', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestData)
    })
    .then(response => response.json())
    .then(data => {
        currentTestId = data.test_id;
        monitorTestProgress(data.test_id);
        showAlert(`Test ${data.test_id} started!`, 'success');
    })
    .catch(error => {
        console.error('Error running test:', error);
        modal.hide();
        showAlert('Error running test: ' + error.message, 'danger');
    });
}

// Monitor test progress
function monitorTestProgress(testId) {
    const checkInterval = setInterval(() => {
        fetch(`/api/tests/status/${testId}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'completed' || data.status === 'failed') {
                    clearInterval(checkInterval);
                    handleTestComplete(data);
                } else {
                    document.getElementById('loading-message').textContent = 
                        `Test in progress... Status: ${data.status}`;
                }
            })
            .catch(error => console.error('Error checking status:', error));
    }, 2000);
}

// Handle test completion
function handleTestComplete(data) {
    // Hide loading modal
    const modal = bootstrap.Modal.getInstance(document.getElementById('loading-modal'));
    if (modal) modal.hide();
    
    if (data.status === 'completed') {
        showAlert('Test completed successfully!', 'success');
        loadDashboard(); // Refresh dashboard
    } else {
        showAlert(`Test failed: ${data.error}`, 'danger');
    }
}

// Utility functions

function showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 end-0 m-3`;
    alertDiv.style.zIndex = '9999';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.body.appendChild(alertDiv);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

function updateConnectionStatus(connected) {
    const statusElement = document.getElementById('connection-status');
    if (connected) {
        statusElement.className = 'badge bg-success';
        statusElement.textContent = 'Connected';
    } else {
        statusElement.className = 'badge bg-danger';
        statusElement.textContent = 'Disconnected';
    }
}

function getStatusBadgeColor(status) {
    const colors = {
        'completed': 'success',
        'running': 'primary',
        'queued': 'secondary',
        'failed': 'danger',
        'stopped': 'warning'
    };
    return colors[status] || 'secondary';
}

function viewTestDetails(testId) {
    fetch(`/api/tests/${testId}`)
        .then(response => response.json())
        .then(data => {
            console.log('Test details:', data);
            showAlert('Test ID: ' + testId, 'info');
        })
        .catch(error => console.error('Error fetching test details:', error));
}

function startAutoRefresh() {
    // Refresh dashboard every 30 seconds
    setInterval(() => {
        loadDashboard();
    }, 30000);
}

function setupEventListeners() {
    // Handle form submit (if needed)
    const form = document.getElementById('test-config-form');
    if (form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
        });
    }
}

function handleTestUpdate(data) {
    console.log('Test update:', data);
    loadDashboard();
}
