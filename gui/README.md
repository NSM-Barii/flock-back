# FlockBack Web Dashboard

A sleek, real-time web interface for monitoring AI camera detections from FlockBack.

## 🚀 Quick Start

### Option 1: Python HTTP Server (Recommended)
```bash
cd /Users/jabarilucien/Documents/nsm_tools/flock-back/gui
python3 -m http.server 8000
```

Then open your browser to: **http://localhost:8000**

### Option 2: Direct File Access
Simply open `index.html` in your browser (some features may be limited due to CORS).

## 📊 Features

- **Real-time Detection**: Updates every 2 seconds
- **BLE Monitoring**: Bluetooth camera detections with MAC, name, signal, and UUIDs
- **WiFi Monitoring**: Wireless camera detections with SSID, channel, frequency, and signal
- **Live Stats**: Total counts for BLE, WiFi, and combined threats
- **Modern UI**: Dark cybersecurity-themed design
- **Signal Strength**: Color-coded signal indicators (strong/medium/weak)
- **Responsive**: Works on desktop, tablet, and mobile

## 🎨 Design

- **Dark Theme**: Easy on the eyes during long scanning sessions
- **Glowing Accents**: Neon-inspired highlights and animations
- **Clean Layout**: Organized stats and detection tables
- **Live Indicators**: Pulsing status dot shows active scanning

## 📁 Structure

```
gui/
├── index.html           # Main dashboard
├── css/
│   └── style.css       # All styling
├── js/
│   └── dashboard.js    # Live data fetching & updates
└── README.md           # This file
```

## 🔧 Configuration

Edit `dashboard.js` line 5 to change data source:
```javascript
const DATA_PATH = '../../../.data/flock-back/war_drives/live.json';
```

Change refresh rate on line 6:
```javascript
const REFRESH_INTERVAL = 2000; // milliseconds
```

## 📝 Data Format

The dashboard reads from `live.json`:
```json
{
  "ble": [
    {
      "mac": "XX:XX:XX:XX:XX:XX",
      "local_name": "FS Ext Battery",
      "rssi": -45,
      "services": ["0000180a-..."]
    }
  ],
  "wifi": [
    {
      "ssid": "flock",
      "channel": 6,
      "frequency": "2.4 GHz",
      "rssi": -60,
      "encryption": null
    }
  ]
}
```

## 🐛 Debugging

Open browser console (F12) to check:
- `FlockBackDebug.lastData()` - View current data
- `FlockBackDebug.forceUpdate()` - Manually refresh

## 💡 Tips

- Keep the scanner running to see live updates
- Signal strength: Green (-50 to 0), Yellow (-70 to -50), Red (below -70)
- Works best with Chrome/Firefox/Safari
- Dashboard auto-refreshes while scanner writes to `live.json`

---

**Developed by NSM Barii** | [GitHub](https://github.com/NSM-Barii/flock-back)
