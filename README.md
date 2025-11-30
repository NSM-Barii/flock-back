# FlockBack — Wireless Scanner for AI-Powered LPR Cameras

FlockBack is a lightweight Python tool for detecting **AI-powered license plate reader (LPR) cameras** such as Flock Safety, Raven, Penguin, PigVision, and similar vendors.

It uses **BLE + Wi-Fi signature scanning** to identify the hidden wireless components many LPR systems rely on, allowing you to detect cameras *before you can visually see them*. Ideal for wardriving, privacy research, auditing, and mapping surveillance deployments.

The project is **actively in development**, and contributors are welcome — especially for new **OUI entries, MAC prefixes, BLE UUIDs, and vendor signatures**.

---

## Features
- 🚨 Passive BLE scanning using **Bleak** (built on top of BlueZ)
- 📡 Optional Wi-Fi scanning using **Scapy** in monitor mode
- 🛰️ Optional GPS support for mapping detections
- 🔎 Matches BLE names, UUIDs, MAC prefixes, SSIDs, and OUIs
- ⚙️ Auto-recovering sniffers designed for long-duration wardriving
- 🎯 BLE-only mode when no arguments are passed
- 🧩 Modular signature files for easy expansion
- 🤝 Open to community contributions

---

## Usage

### Help Menu
```bash
python3 FlockBack.py -h
```

---

### BLE-Only Mode (default)
Run with no arguments:
```bash
python3 FlockBack.py
```
This launches BLE scanning only (no Wi-Fi required).

---

### BLE + Wi-Fi Mode
```bash
python3 FlockBack.py -i wlan0
```

**Flags:**

| Flag | Description |
|------|-------------|
| `-h` | Show help menu |
| `-i` | Pass a Wi-Fi interface (must be in monitor mode) |

Example:
```bash
python3 FlockBack.py -i wlan1
```

---

## Requirements
- Linux recommended  
- Python **3.10+**
- Bluetooth adapter  
- Wi-Fi adapter with monitor mode (optional)
- BlueZ (required for BLE scanning)
- Python libraries: Bleak, Scapy, gps3 (optional for GPS)

If BlueZ dependencies are missing, check:

```
setup_ble.txt
```

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/NSM-Barii/FlockBack
cd FlockBack
```

### 2. Create and activate a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python dependencies
```bash
pip install -r requirements.txt
```

---

## Project Status
FlockBack is **in active development**.  
Expect updates, signature expansions, and new features as the project grows.

Contributions are encouraged — especially:
- New MAC prefixes  
- New OUIs  
- BLE UUID sets  
- Additional LPR vendor fingerprints  
- Performance improvements  
- General code enhancements  

Submit PRs or open issues anytime.

---

## Contributing
Want to help expand detection accuracy or add new vendor signatures?

Open a pull request or issue with:
- BLE UUID dumps  
- Wi-Fi SSID patterns  
- MAC prefix observations  
- Vendor information  
- Captures from wardriving sessions  

Every contribution matters.

---

## Disclaimer
This tool is for **educational and research purposes only**.  
Do not use it to evade surveillance, tamper with infrastructure, or engage in unlawful activity.  
Use responsibly.
