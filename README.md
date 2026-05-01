# FlockBack — AI Camera Detection Toolkit
![Flock-Back Banner](https://github.com/user-attachments/assets/81829f0c-b241-4099-addd-c09e106f187a)

Lightweight Python tool for detecting **AI-powered license plate reader (LPR) cameras** (Flock Safety, Raven, Penguin, PigVision, etc.) using **BLE + Wi-Fi signature scanning**. Detect surveillance cameras before you can visually see them.

**Features:**
- Passive BLE + Wi-Fi monitor mode scanning with signature matching
- Probe request and beacon capture with channel hopping, frame count, and sequence logging
- All finds saved to `flocks.json`, packet mode hits to `packets.json`

---

## Dependencies

**Python 3.10+**, and the following system packages:

**BlueZ (Bluetooth):**
```bash
sudo apt update && sudo apt install bluez bluez-tools bluez-firmware -y
sudo systemctl enable bluetooth && sudo systemctl start bluetooth
systemctl status bluetooth
```

**tshark (Wi-Fi packet capture):**
```bash
sudo apt install tshark -y
```
> During install, select **Yes** when asked to allow non-superusers to capture packets, or run with `sudo`.

**Python packages:**
```bash
pip install -r requirements.txt
```

> **Troubleshooting Bluetooth:** See `setup/setup_ble.txt` for additional configuration help.

---

## Quick Start

**Install:**
```bash
git clone https://github.com/NSM-Barii/flock-back
cd flock-back/src
python3 -m venv venv
source venv/bin/activate
pip install -r ../requirements.txt
```

**Run:**
```bash
# BLE-only mode
sudo venv/bin/python main.py

# BLE + Wi-Fi mode (requires monitor mode adapter)
sudo venv/bin/python main.py -i wlan1

# Verbose mode (show all devices)
sudo venv/bin/python main.py -i wlan1 -v

# Packet mode (continuous logging of repeat Flock hits)
sudo venv/bin/python main.py -i wlan1 -p
```

---

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i` | Monitor-mode WiFi interface | None |
| `-b` | Bluetooth adapter | `hci0` |
| `-p` | Packet mode — keep printing/saving repeat Flock hits | Off |
| `-v` | Verbose — show non-Flock devices | Off |
| `-g` | GPS serial port — **not implemented yet, do not use** | None |
| `-bs` | BLE scan window in seconds | `5` |
| `-delay` | Channel hop dwell time in seconds | `0.125` |
| `-hops` | Custom channel list (e.g. `-hops 1 6 11`) | See below |
| `-preset` | Channel preset: `2.4`, `5`, or `all` | `all` |
| `-h` | Help menu | — |

**Default hop list:** `1 6 11 36 40 44 48 149 153 157 161`

**Presets:**
- `2.4` — channels 1-11 (2.4GHz only, recommended for wardriving)
- `5` — 5GHz only (36, 40, 44, 48, 149, 153, 157, 161)
- `all` — default list

---

## Output

Finds are saved to `database/flocks.json` (newline-delimited JSON):
```json
{"time_stamp": "05/01/2026  -  03:58:25", "type": "ble", "rssi": -86, "mac": "58:8E:81:FC:F5:51", "local_name": "FS Ext Battery", "manufacturer": false, "uuids": false}
{"time_stamp": "05/01/2026  -  04:15:59", "type": "wifi", "rssi": -84, "mac": "d8:f3:bc:7d:c1:a9", "ssid": "<MISSING>", "vendor": "Liteon Technology Corporation", "frequency": "5745", "encryption": "unknown", "channel": "149", "subtype": "0x0004", "seq": "1195", "frame_count": 2}
```

Packet mode repeat hits are saved to `database/packets.json` in the same format.

---

## Research

Probe request discovery by:

Signatures by:

Program: GitHub.com/nsm-barii/flock-back

---

This program, originally created in December of last year, was made to find the ever growing threat of Flock cameras appearing in America.

Originally it was made and based primarily off of finding these Flock cameras by wardriving and sniffing mainly with BLE and comparing the BLE packets against a list of BLE names.

This method is no longer fully viable — while some Flock cameras still advertise via BLE, a large majority have turned off BLE advertisements and instead reveal themselves by sending out probe requests using WiFi.

This is presumably an update that some Flock cameras have gone through. The ones with this update only send out probe requests with a missing SSID (which is obfuscation) to connect to a hidden network that isn't broadcasting its SSID. This hidden network is likely an access point that a Flock employee would broadcast near the camera when trying to connect to it — further research will need to be done to confirm this.

Furthermore, the Republican candidate for Florida, James Fishback, is running on the promise of banning Flock cameras. If something like this were to happen in one state, as with dominoes, it could happen in others as well.

I found out that the first camera I showed in my original video no longer advertised BLE packets, which I found strange as it used to (visible in my first video on Flock cameras). I then made the assumption that perhaps they were advertising themselves via probe requests using WiFi. While looking into this, **@jakeswiz** was also doing research on it around the same time and figured it out and made a video — show him some love as I'm grateful for the work he has done as well.

As time progresses I will be doing more research into Flock cameras and trying to figure out more about how they work.

---

## Contributing

Contributions welcome! We need:
- MAC prefixes, OUIs, BLE UUIDs, SSID patterns
- Vendor fingerprints and wardriving captures
- Performance improvements and code enhancements

Submit PRs or open issues with your findings.

---

## Disclaimer
**This program was made for educational, ethical, and legal purposes only.** Use responsibly and in accordance with local laws.
