# FlockBack — AI Camera Detection Toolkit (BLE + Wi-Fi)
<img width="1536" height="1024" alt="a961a9c5-7d97-4373-a757-49fd88c69ace" src="https://github.com/user-attachments/assets/0a58884d-210f-42b4-be74-9c82834f8b40" />




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

```bash
# BLE-only mode (default)
python3 flock-back.py

# BLE + Wi-Fi mode
python3 flock-back.py -i wlan0

# Verbose mode (shows all non-AI cameras detected)
python3 flock-back.py -v

# Full scan with verbose output
python3 flock-back.py -i wlan0 -v
```

**Flags:**

| Flag | Description |
|------|-------------|
| `-h` | Show help menu |
| `-i` | Wi-Fi interface in monitor mode |
| `-v` | Verbose mode (show all detected devices) |

---

## Requirements
- Linux (recommended)
- Python **3.10+**
- Bluetooth adapter
- Wi-Fi adapter with monitor mode (optional)
- BlueZ for BLE scanning

---

## Installation

### 1. Install BlueZ (BLE Support)
```bash
sudo apt update
sudo apt install bluez bluez-tools bluez-firmware
```

### 2. Enable and start Bluetooth service
```bash
sudo systemctl enable bluetooth
sudo systemctl start bluetooth
```

### 3. Check Bluetooth service status
```bash
systemctl status bluetooth
```

> **Note:** If you experience Bluetooth issues, refer to `setup/setup_ble.txt` for additional troubleshooting steps.

### 4. Clone the repository
```bash
git clone https://github.com/NSM-Barii/flock-back
cd flock-back
```

### 5. Navigate to flock_off and create a virtual environment
```bash
cd flock_off
python3 -m venv venv
source venv/bin/activate
```

### 6. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 7. Run the program
```bash
# BLE-only mode
python3 flock-back.py

# BLE + Wi-Fi mode
python3 flock-back.py -i wlan0
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
