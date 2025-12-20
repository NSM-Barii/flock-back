# FlockBack — AI Camera Detection Toolkit (BLE + Wi-Fi)
![Flock-Back Banner](https://github.com/user-attachments/assets/81829f0c-b241-4099-addd-c09e106f187a)




FlockBack is a lightweight Python tool for detecting **AI-powered license plate reader (LPR) cameras** such as Flock Safety, Raven, Penguin, PigVision, and similar vendors.

It uses **BLE + Wi-Fi signature scanning** to identify the hidden wireless components many LPR systems rely on, allowing you to detect cameras *before you can visually see them*. Ideal for wardriving, privacy research, auditing, and mapping surveillance deployments.

The project is **actively in development**, and contributors are welcome — especially for new **OUI entries, MAC prefixes, BLE UUIDs, and vendor signatures**.

---

## Features
- **Passive BLE scanning** via Bleak (BlueZ)
- **Wi-Fi monitor mode** scanning via Scapy (optional)
- **Signature matching**: BLE names, UUIDs, MAC prefixes, SSIDs, OUIs
- **Auto-recovering sniffers** for long-duration wardriving
- **GPS support** (coming soon)

---

## Usage

```bash
# BLE-only mode (default)
sudo venv/bin/python main.py

# BLE + Wi-Fi mode
sudo venv/bin/python main.py -i wlan0

# Verbose mode (shows all non-AI cameras detected)
sudo venv/bin/python main.py -v

# Full scan with verbose output
sudo venv/bin/python main.py -i wlan0 -v
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

### 5. Navigate to src and create a virtual environment
```bash
cd src
python3 -m venv venv
source venv/bin/activate
```

### 6. Install Python dependencies
```bash
pip install -r ../requirements.txt
```

### 7. Run the program
```bash
# BLE-only mode
sudo venv/bin/python main.py

# BLE + Wi-Fi mode
sudo venv/bin/python main.py -i wlan0
```

---

## Contributing
FlockBack is **in active development** and contributions are welcome.

**What we need:**
- MAC prefixes & OUIs
- BLE UUIDs & service dumps
- Wi-Fi SSID patterns
- Vendor fingerprints
- Performance improvements
- Code enhancements

Submit PRs or open issues with any wardriving captures, observations, or improvements.

---

## Disclaimer
This tool is for **educational and research purposes only**.  
Do not use it to evade surveillance, tamper with infrastructure, or engage in unlawful activity.  
Use responsibly.
