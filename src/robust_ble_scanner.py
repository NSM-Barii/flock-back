import asyncio
import subprocess
import time
from bleak import BleakScanner
from rich.console import Console

console = Console()


async def ble_scan(timeout=5, passive=False):
    scanner = None
    try:
        mode = "passive" if passive else "active"
        devices = await BleakScanner.discover(timeout=timeout, return_adv=True, scanning_mode=mode)
        return devices
    except Exception as e:
        console.print(f"[bold red]BLE Error:[bold yellow] {e}")
        return None


def reset_bt():
    try:
        subprocess.run(["sudo", "bluetoothctl", "power", "off"], capture_output=True, timeout=5)
        time.sleep(2)
        subprocess.run(["sudo", "bluetoothctl", "power", "on"], capture_output=True, timeout=5)
        time.sleep(3)
        console.print("[bold green][+] BT reset")
    except:
        pass


def main():
    scans = 0
    last_reset = time.time()
    errors = 0

    while True:
        scans += 1
        console.print(f"\n[bold cyan]Scan #{scans}")

        devices = asyncio.run(ble_scan(timeout=5, passive=False))

        if devices:
            console.print(f"[bold green]Found {len(devices)} devices")
            errors = 0

            for mac, (device, adv) in devices.items():
                console.print(f"  {mac} - {adv.local_name} - {adv.rssi}dBm")

        else:
            errors += 1
            console.print(f"[bold red]Scan failed - errors: {errors}")

            if errors >= 3:
                reset_bt()
                errors = 0

        if time.time() - last_reset > 120:
            reset_bt()
            last_reset = time.time()

        time.sleep(5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Stopped")
