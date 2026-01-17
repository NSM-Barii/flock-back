"""
Simplified Robust BLE Scanner - Fixes error.txt issues
Key fixes: Fresh scanner instances + proper cleanup + adapter resets
"""

import asyncio
import subprocess
import time
from bleak import BleakScanner

console = None  # Will be set from flock_finder


async def discover_safe(timeout=5):
    """
    Safe BLE discovery that prevents DBus errors
    Creates fresh scanner instance and ensures cleanup
    """
    scanner = None
    try:
        scanner = BleakScanner(return_adv=True)
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()
        return await scanner.get_discovered_devices_and_advertisement_data()

    except Exception as e:
        if console:
            console.print(f"[bold red]BLE Error:[bold yellow] {e}")
        return None

    finally:
        # Cleanup scanner resources
        if scanner:
            try:
                await scanner.stop()
            except:
                pass
        await asyncio.sleep(0.5)  # Let resources release


def reset_adapter():
    """Reset BT adapter when errors occur"""
    try:
        subprocess.run(["sudo", "bluetoothctl", "power", "off"], capture_output=True, timeout=5)
        time.sleep(2)
        subprocess.run(["sudo", "bluetoothctl", "power", "on"], capture_output=True, timeout=5)
        time.sleep(3)
        if console:
            console.print("[bold green][+] Adapter reset")
    except:
        pass


# Usage example - replace your _discover() and exception handling with this pattern
