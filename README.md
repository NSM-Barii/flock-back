# FlockBack — AI Camera Detection Toolkit
![Flock-Back Banner](https://github.com/user-attachments/assets/81829f0c-b241-4099-addd-c09e106f187a)

Lightweight Python tool for detecting **AI-powered license plate reader (LPR) cameras** (Flock Safety, Raven, Penguin, PigVision, etc.) using **BLE + Wi-Fi signature scanning**. Detect surveillance cameras before you can visually see them.

**Features:**
- Passive BLE + Wi-Fi monitor mode scanning
- Signature matching: BLE UUIDs, MAC prefixes, SSIDs, OUIs
- Auto-recovering sniffers for long wardriving sessions
- Real-time web dashboard

---

## Bluetooth Setup (Linux)

**Install BlueZ before running:**
```bash
sudo apt update && sudo apt install bluez bluez-tools bluez-firmware -y
sudo systemctl enable bluetooth && sudo systemctl start bluetooth
systemctl status bluetooth
```

> **Troubleshooting:** See `setup/setup_ble.txt` for additional Bluetooth configuration help.

---

## Quick Start

**Requirements:** Linux, Python 3.10+, Bluetooth adapter

**One-line install:**
```bash
git clone https://github.com/NSM-Barii/flock-back && cd flock-back/src && python3 -m venv venv && source venv/bin/activate && pip install -r ../requirements.txt
```

**Run:**
```bash
# BLE-only mode
sudo venv/bin/python main.py

# BLE + Wi-Fi mode (requires monitor mode adapter)
sudo venv/bin/python main.py -i wlan0

# Verbose mode (show all devices)
sudo venv/bin/python main.py -v
```

---

## Contributing

Contributions welcome! We need:
- MAC prefixes, OUIs, BLE UUIDs, SSID patterns
- Vendor fingerprints and wardriving captures
- Performance improvements and code enhancements

Submit PRs or open issues with your findings.

---

## Disclaimer
**Educational and research purposes only.** Use responsibly and legally.
