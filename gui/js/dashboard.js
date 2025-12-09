// FlockBack Live Dashboard - Real-time AI Camera Detection
// Developed by NSM Barii

const DATA_PATH = 'data/live.json';
const REFRESH_INTERVAL = 2000; // Update every 2 seconds

// State management
let lastData = null;
let updateInterval = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    console.log('FlockBack Dashboard Initialized');
    startLiveUpdates();
});

// Start live data updates
function startLiveUpdates() {
    fetchData(); // Initial fetch
    updateInterval = setInterval(fetchData, REFRESH_INTERVAL);
}

// Fetch data from live.json
async function fetchData() {
    try {
        const response = await fetch(DATA_PATH);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        // Only update if data has changed
        if (JSON.stringify(data) !== JSON.stringify(lastData)) {
            lastData = data;
            updateDashboard(data);
            updateTimestamp();
        }

    } catch (error) {
        console.error('Error fetching data:', error);
        handleError(error);
    }
}

// Update dashboard with new data
function updateDashboard(data) {
    const bleDevices = data.ble || [];
    const wifiDevices = data.wifi || [];

    // Update stats
    updateStats(bleDevices.length, wifiDevices.length);

    // Update tables
    updateBLETable(bleDevices);
    updateWiFiTable(wifiDevices);
}

// Update statistics cards
function updateStats(bleCount, wifiCount) {
    const total = bleCount + wifiCount;

    document.getElementById('bleCount').textContent = bleCount;
    document.getElementById('wifiCount').textContent = wifiCount;
    document.getElementById('totalCount').textContent = total;
    document.getElementById('bleBadge').textContent = bleCount;
    document.getElementById('wifiBadge').textContent = wifiCount;

    // Add animation effect
    animateStatCard('bleCount');
    animateStatCard('wifiCount');
    animateStatCard('totalCount');
}

// Animate stat number change
function animateStatCard(elementId) {
    const element = document.getElementById(elementId);
    element.style.transform = 'scale(1.1)';
    element.style.color = 'var(--accent-green)';

    setTimeout(() => {
        element.style.transform = 'scale(1)';
        element.style.color = 'var(--text-primary)';
    }, 300);
}

// Update BLE detection table
function updateBLETable(devices) {
    const tbody = document.getElementById('bleTableBody');

    if (devices.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-state">
                <td colspan="4">
                    <div class="empty-message">
                        <span class="empty-icon">🔍</span>
                        <p>No BLE cameras detected yet...</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = devices.map(device => {
        const mac = device.mac || 'Unknown';
        const name = device.local_name || 'Unnamed Device';
        const rssi = device.rssi || 0;
        const services = device.services || [];

        const signalClass = getSignalClass(rssi);
        const servicesHTML = formatServices(services);

        return `
            <tr>
                <td><code>${escapeHtml(mac)}</code></td>
                <td><strong>${escapeHtml(name)}</strong></td>
                <td class="${signalClass}">${rssi} dBm</td>
                <td>${servicesHTML}</td>
            </tr>
        `;
    }).join('');
}

// Update WiFi detection table
function updateWiFiTable(devices) {
    const tbody = document.getElementById('wifiTableBody');

    if (devices.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-state">
                <td colspan="5">
                    <div class="empty-message">
                        <span class="empty-icon">🔍</span>
                        <p>No WiFi cameras detected yet...</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = devices.map(device => {
        const ssid = device.ssid || 'Hidden Network';
        const channel = device.channel || 'N/A';
        const frequency = device.frequency || 'N/A';
        const rssi = device.rssi || 0;
        const encryption = device.encryption || 'Unknown';

        const signalClass = getSignalClass(rssi);

        return `
            <tr>
                <td><strong>${escapeHtml(ssid)}</strong></td>
                <td>${channel}</td>
                <td>${frequency}</td>
                <td class="${signalClass}">${rssi} dBm</td>
                <td>${escapeHtml(encryption)}</td>
            </tr>
        `;
    }).join('');
}

// Format BLE service UUIDs
function formatServices(services) {
    if (!services || services.length === 0) {
        return '<span style="color: var(--text-secondary);">None</span>';
    }

    // Show first 2 services, then "+" for more
    const displayServices = services.slice(0, 2);
    const remaining = services.length - 2;

    let html = displayServices.map(uuid =>
        `<span class="service-badge" title="${uuid}">${shortenUUID(uuid)}</span>`
    ).join(' ');

    if (remaining > 0) {
        html += ` <span class="service-badge" title="Click to see all">+${remaining} more</span>`;
    }

    return html;
}

// Shorten UUID for display
function shortenUUID(uuid) {
    if (!uuid) return 'Unknown';

    // Check if it's a standard UUID format
    if (uuid.includes('-')) {
        const parts = uuid.split('-');
        return parts[0]; // Return first segment
    }

    return uuid.substring(0, 8) + '...';
}

// Get signal strength CSS class
function getSignalClass(rssi) {
    if (rssi >= -50) return 'signal-strong';
    if (rssi >= -70) return 'signal-medium';
    return 'signal-weak';
}

// Update last update timestamp
function updateTimestamp() {
    const now = new Date();
    const timeString = now.toLocaleTimeString();
    document.getElementById('lastUpdate').textContent = timeString;
}

// Handle errors
function handleError(error) {
    console.error('Dashboard Error:', error);

    // You could add a notification banner here
    // For now, just log to console
}

// Utility: Escape HTML to prevent XSS
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (updateInterval) {
        clearInterval(updateInterval);
    }
});

// Export for debugging (optional)
window.FlockBackDebug = {
    fetchData,
    lastData: () => lastData,
    forceUpdate: () => fetchData()
};
